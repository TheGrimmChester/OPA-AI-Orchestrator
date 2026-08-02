#!/usr/bin/env node
/**
 * AppSec — heuristic IaC/container stub: Dockerfile FROM + terraform resource blocks.
 * POST to /v1/security/iac (kind=dockerfile|terraform|container). Not a full IaC scanner.
 *
 * Usage:
 *   node scripts/iac-scan-stub.mjs [--root .] [--agent URL] [--token TOKEN] [--service name]
 */
'use strict';

const fs = require('fs');
const path = require('path');

const SKIP = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', '.terraform']);

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
    } else if (e.isFile()) out.push(full);
  }
  return out;
}

function scanDockerfile(rel, text, findings) {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*FROM\s+(\S+)/i);
    if (!m) continue;
    const image = m[1];
    let severity = 'low';
    let message = `FROM ${image}`;
    if (image === 'latest' || /:latest$/i.test(image) || image.indexOf(':') < 0) {
      severity = 'medium';
      message = `Unpinned / latest base image: ${image}`;
    }
    if (/^FROM\s+.*as\s+/i.test(lines[i]) === false && /scratch/i.test(image) === false) {
      findings.push({ kind: 'dockerfile', rule: 'docker-from', file: rel, severity, message });
    } else {
      findings.push({ kind: 'dockerfile', rule: 'docker-from', file: rel, severity, message });
    }
    if (/:latest$/i.test(image) || image.indexOf(':') < 0) {
      findings.push({
        kind: 'container', rule: 'container-unpinned-tag', file: rel,
        severity: 'medium', message: `Container image tag not pinned: ${image}`,
      });
    }
  }
}

function scanTerraform(rel, text, findings) {
  const re = /resource\s+"([^"]+)"\s+"([^"]+)"/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const type = m[1];
    const name = m[2];
    findings.push({
      kind: 'terraform', rule: 'tf-resource', file: rel,
      severity: 'info', message: `resource "${type}" "${name}"`,
    });
    if (/aws_security_group|aws_s3_bucket|google_storage_bucket|azurerm_storage_account/.test(type)) {
      findings.push({
        kind: 'terraform', rule: 'tf-sensitive-resource', file: rel,
        severity: 'low', message: `Review sensitive resource ${type}.${name} (stub — not policy-as-code)`,
      });
    }
  }
}

(async () => {
  const root = path.resolve(arg('--root', '.'));
  const agent = arg('--agent', process.env.OPA_AGENT_URL || 'http://127.0.0.1:8080');
  const token = arg('--token', process.env.OPA_SECURITY_INGEST_TOKEN || '');
  const service = arg('--service', process.env.OPA_SERVICE || 'repo-scan');
  const findings = [];
  for (const file of walk(root)) {
    const base = path.basename(file);
    const rel = path.relative(root, file);
    let text;
    try {
      if (fs.statSync(file).size > 2 * 1024 * 1024) continue;
      text = fs.readFileSync(file, 'utf8');
    } catch { continue; }
    if (/^Dockerfile/i.test(base) || /\.dockerfile$/i.test(base)) {
      scanDockerfile(rel, text, findings);
    } else if (/\.tf$/i.test(base)) {
      scanTerraform(rel, text, findings);
    }
  }
  // Normalize severity "info" → "low" for ingest
  for (const f of findings) {
    if (f.severity === 'info') f.severity = 'low';
  }
  console.log(JSON.stringify({ findings: findings.length, sample: findings.slice(0, 8) }, null, 2));
  const headers = { 'content-type': 'application/json' };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
    headers['X-OPA-Security-Token'] = token;
  }
  const res = await fetch(`${agent.replace(/\/$/, '')}/v1/security/iac`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ service, findings }),
  });
  console.log(res.status, await res.text());
  process.exit(res.ok ? 0 : 1);
})();
