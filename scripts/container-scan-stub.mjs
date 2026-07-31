#!/usr/bin/env node
/**
 * Wave 30 — container/image scan stub (not Trivy/Grype).
 * Emits JSON for POST /v1/security/containers.
 *
 * Usage:
 *   node scripts/container-scan-stub.mjs [image-ref]
 *   OPA_AGENT_URL=… OPA_SECURITY_INGEST_TOKEN=… node scripts/container-scan-stub.mjs myapp:latest --post
 */
'use strict';
const image = process.argv.find((a) => !a.startsWith('-') && !a.endsWith('.mjs')) || process.env.OPA_IMAGE || 'app:local';
const findings = [];
// Heuristic stubs — replace with real scanner output in CI.
if (/:latest$/i.test(image) || image.indexOf(':') < 0) {
  findings.push({
    rule: 'floating_tag',
    severity: 'medium',
    message: 'Image tag is floating (:latest or untagged)',
    package: image,
  });
}
if (/root|admin/i.test(image)) {
  findings.push({
    rule: 'suspicious_name',
    severity: 'low',
    message: 'Image name suggests privileged role',
    package: image,
  });
}
const body = {
  service: process.env.OPA_SERVICE || 'repo',
  image,
  findings,
  honesty: 'Heuristic stub — not a full container CVE engine',
};
if (process.argv.includes('--post')) {
  const agent = (process.env.OPA_AGENT_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
  const headers = { 'Content-Type': 'application/json' };
  const tok = process.env.OPA_SECURITY_INGEST_TOKEN || '';
  if (tok) {
    headers['X-OPA-Security-Token'] = tok;
    headers.Authorization = 'Bearer ' + tok;
  }
  fetch(agent + '/v1/security/containers', { method: 'POST', headers, body: JSON.stringify(body) })
    .then(async (r) => {
      const t = await r.text();
      process.stdout.write(t + '\n');
      if (!r.ok) process.exit(1);
    })
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
} else {
  process.stdout.write(JSON.stringify(body));
}
