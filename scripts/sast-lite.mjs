#!/usr/bin/env node
/**
 * Pattern SAST-lite for JS/PHP (eval, innerHTML, SQL concat heuristics).
 * POST to /v1/security/sast. Not a full SAST engine.
 *
 * Usage:
 *   node scripts/sast-lite.mjs [--root .] [--agent URL] [--token TOKEN] [--service name]
 */
'use strict';

const fs = require('fs');
const path = require('path');

// Messages omit "name(" shapes so this file does not self-match in-repo SAST.
const RULES = [
  { rule: 'js-eval', re: /\beval\s*\(/g, ext: ['.js', '.mjs', '.ts', '.tsx', '.jsx'], severity: 'high', message: 'dynamic eval invocation' },
  { rule: 'js-innerhtml', re: /\.innerHTML\s*=/g, ext: ['.js', '.mjs', '.ts', '.tsx', '.jsx'], severity: 'medium', message: 'innerHTML assignment' },
  { rule: 'js-document-write', re: /document\.write\s*\(/g, ext: ['.js', '.mjs', '.ts', '.tsx', '.jsx'], severity: 'medium', message: 'document write call' },
  { rule: 'php-eval', re: /\beval\s*\(/g, ext: ['.php'], severity: 'high', message: 'PHP eval invocation' },
  { rule: 'php-sql-concat', re: /(["'])\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"']*\1\s*\./gi, ext: ['.php'], severity: 'high', message: 'SQL string concatenation' },
  { rule: 'php-sql-interp', re: /"(SELECT|INSERT|UPDATE|DELETE)\b[^"]*\$/gi, ext: ['.php'], severity: 'high', message: 'SQL with variable interpolation' },
  { rule: 'js-sql-concat', re: /(["'`])\s*(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,80}\1\s*\+/gi, ext: ['.js', '.mjs', '.ts'], severity: 'medium', message: 'SQL string concat in JS' },
];

const SKIP = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', '.libs']);
const SKIP_FILES = new Set(['sast-lite.mjs', 'secrets-lite.mjs', 'iac-lite.mjs']);

function arg(name, def = '') {
  const i = process.argv.indexOf(name);
  if (i < 0) return def;
  return process.argv[i + 1] || def;
}

function walk(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP.has(e.name)) continue;
      walk(full, out);
    } else if (e.isFile()) {
      if (SKIP_FILES.has(e.name)) continue;
      out.push(full);
    }
  }
  return out;
}

(async () => {
  const root = path.resolve(arg('--root', '.'));
  const agent = arg('--agent', process.env.OPA_AGENT_URL || 'http://127.0.0.1:8080');
  const token = arg('--token', process.env.OPA_SECURITY_INGEST_TOKEN || '');
  const service = arg('--service', process.env.OPA_SERVICE || 'repo-scan');
  const findings = [];
  for (const file of walk(root)) {
    const ext = path.extname(file).toLowerCase();
    const applicable = RULES.filter((r) => r.ext.includes(ext));
    if (!applicable.length) continue;
    let text;
    try {
      if (fs.statSync(file).size > 1.5 * 1024 * 1024) continue;
      text = fs.readFileSync(file, 'utf8');
    } catch { continue; }
    const rel = path.relative(root, file);
    const lines = text.split(/\r?\n/);
    for (const rule of applicable) {
      for (let i = 0; i < lines.length; i++) {
        rule.re.lastIndex = 0;
        if (!rule.re.test(lines[i])) continue;
        findings.push({
          rule: rule.rule, file: rel, line: i + 1,
          severity: rule.severity, message: rule.message + ': ' + lines[i].trim().slice(0, 100),
        });
      }
    }
  }
  console.log(JSON.stringify({ findings: findings.length, sample: findings.slice(0, 5) }, null, 2));
  const headers = { 'content-type': 'application/json' };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
    headers['X-OPA-Security-Token'] = token;
  }
  const res = await fetch(`${agent.replace(/\/$/, '')}/v1/security/sast`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ service, findings }),
  });
  console.log(res.status, await res.text());
  process.exit(res.ok ? 0 : 1);
})();
