#!/usr/bin/env node
/**
 * Wave 30 — ripgrep-style secret scan of cwd; POST findings to /v1/security/secrets.
 *
 * Usage:
 *   node scripts/secret-scan.mjs [--root .] [--agent URL] [--token TOKEN] [--service name]
 */
'use strict';

const fs = require('fs');
const path = require('path');

const PATTERNS = [
  { rule: 'aws-access-key', re: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { rule: 'aws-secret-key', re: /aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"][A-Za-z0-9/+=]{30,}['"]/gi, severity: 'critical' },
  { rule: 'private-key', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical' },
  { rule: 'github-pat', re: /ghp_[A-Za-z0-9]{36}/g, severity: 'high' },
  { rule: 'slack-token', re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, severity: 'high' },
  { rule: 'generic-api-key', re: /(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi, severity: 'medium' },
];

const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', '.libs', 'autom4te.cache']);
const TEXT_EXT = new Set(['.js', '.mjs', '.ts', '.tsx', '.jsx', '.py', '.go', '.php', '.yml', '.yaml', '.json', '.env', '.tf', '.sh', '.c', '.h', '.md', '.txt', '.ini', '.conf']);

function arg(name, def = '') {
  const i = process.argv.indexOf(name);
  if (i < 0) return def;
  return process.argv[i + 1] || def;
}

function walk(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name.startsWith('.') && e.name !== '.env') {
      if (SKIP_DIRS.has(e.name)) continue;
    }
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(full, out);
    } else if (e.isFile()) {
      const ext = path.extname(e.name).toLowerCase();
      if (!TEXT_EXT.has(ext) && e.name !== '.env' && !e.name.endsWith('.env.example')) continue;
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
    let text;
    try {
      const st = fs.statSync(file);
      if (st.size > 2 * 1024 * 1024) continue;
      text = fs.readFileSync(file, 'utf8');
    } catch { continue; }
    const rel = path.relative(root, file);
    const lines = text.split(/\r?\n/);
    for (const { rule, re, severity } of PATTERNS) {
      // Reset lastIndex for global regexes
      re.lastIndex = 0;
      for (let i = 0; i < lines.length; i++) {
        re.lastIndex = 0;
        if (!re.test(lines[i])) continue;
        const snippet = lines[i].slice(0, 120).replace(/[A-Za-z0-9/+=_-]{12,}/g, '***');
        findings.push({ rule, file: rel, line: i + 1, severity, snippet, detector: 'secret-scan.mjs' });
      }
    }
  }
  console.log(JSON.stringify({ findings: findings.length, sample: findings.slice(0, 5) }, null, 2));
  if (!findings.length) process.exit(0);
  const headers = { 'content-type': 'application/json' };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
    headers['X-OPA-Security-Token'] = token;
  }
  const res = await fetch(`${agent.replace(/\/$/, '')}/v1/security/secrets`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ service, findings }),
  });
  const body = await res.text();
  console.log(res.status, body);
  process.exit(res.ok ? 0 : 1);
})();
