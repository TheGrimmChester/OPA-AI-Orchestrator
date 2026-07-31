#!/usr/bin/env node
/** Convert npm audit --json into simplified SBOM POST /v1/sbom body. */
'use strict';
const fs = require('fs');
const raw = fs.readFileSync(0, 'utf8');
let audit;
try { audit = JSON.parse(raw); } catch (e) { console.error('bad json'); process.exit(1); }
const pkgs = [];
const vulns = audit.vulnerabilities || {};
for (const [name, v] of Object.entries(vulns)) {
  const via = Array.isArray(v.via) ? v.via : [];
  const ver = (v.range || v.version || '*').replace(/^[\^=~<> ]+/, '') || '0.0.0';
  pkgs.push({ name, version: ver, ecosystem: 'npm' });
}
const body = {
  service: process.env.OPA_SERVICE || 'app',
  packages: pkgs,
};
process.stdout.write(JSON.stringify(body));
