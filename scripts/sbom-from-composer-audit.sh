#!/usr/bin/env bash
# Wave 30 — adapt composer audit JSON into OPA POST /v1/sbom.
# Usage:
#   composer audit --format=json | ./scripts/sbom-from-composer-audit.sh my-php-svc | curl -X POST "$OPA/v1/sbom" -d @-
set -euo pipefail
SERVICE="${1:-${OPA_SERVICE:-php-app}}"
RELEASE="${OPA_RELEASE:-}"
python3 - "$SERVICE" "$RELEASE" <<'PY'
import json, sys
service, release = sys.argv[1], sys.argv[2]
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception as e:
    print("invalid json:", e, file=sys.stderr)
    sys.exit(1)

packages = []
seen = set()
# composer audit --format=json: {"advisories": {"pkg/name": [...]}, ...} or list
advisories = data.get("advisories") or data.get("abandoned") or {}
if isinstance(advisories, dict):
    for name, items in advisories.items():
        ver = "0.0.0"
        if isinstance(items, list) and items:
            ver = str(items[0].get("affectedVersions") or items[0].get("version") or ver)
        key = f"{name}@{ver}"
        if key in seen:
            continue
        seen.add(key)
        packages.append({"name": name, "version": ver, "purl": f"pkg:composer/{name}@{ver}"})
# installed packages from composer show --format=json style
installed = data.get("installed") or []
if isinstance(installed, list):
    for p in installed:
        name = p.get("name")
        ver = p.get("version") or "0.0.0"
        if not name:
            continue
        key = f"{name}@{ver}"
        if key in seen:
            continue
        seen.add(key)
        packages.append({"name": name, "version": ver, "purl": f"pkg:composer/{name}@{ver}"})

print(json.dumps({"service": service, "release": release, "ecosystem": "composer", "packages": packages, "source": "composer-audit"}, indent=2))
PY
