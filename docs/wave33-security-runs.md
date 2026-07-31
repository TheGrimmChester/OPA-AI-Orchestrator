# Security runs (Wave 33)

First-class scan lifecycle — create a run from the Dashboard or API, Agent executes embedded lite/stub scanners against `OPA_SECURITY_WORKSPACE`, and findings are stamped with `security_run_id`.

## API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/api/security/profiles` | viewer | Service→tool profiles + scanner honesty |
| GET\|POST | `/api/security/runs` | viewer | List / create (+ dispatch) |
| GET | `/api/security/runs/{id}` | viewer | Status + summary |
| GET | `/api/security/runs/{id}/findings` | viewer | Secrets/SAST/IaC for this run |

Create body:

```json
{
  "service": "node-smoke",
  "profile": "auto|php|node|container|iac|full",
  "scanners": ["secrets", "sast", "iac", "container", "sbom"],
  "target_path": "",
  "image": "app:latest",
  "dispatch": true
}
```

`target_path` must resolve under `OPA_SECURITY_WORKSPACE` (default `/workspace`). Path traversal outside the mount is rejected.

Existing CI ingest (`POST /v1/security/*`) accepts optional `security_run_id` / `run_id` and remains token-gated via `OPA_SECURITY_INGEST_TOKEN`. List APIs accept `?security_run_id=`.

## Profiles → scanners

| Profile | Default scanners |
|---------|------------------|
| `php` / `node` | secrets, sast, sbom |
| `container` | container, iac |
| `iac` | iac, secrets |
| `full` | secrets, sast, iac, container, sbom |
| `auto` | detect from files under workspace |

IAST is **runtime-only** and is never dispatched from a scan run.

## Honesty

| Scanner | Mode |
|---------|------|
| secrets | **gitleaks** when `gitleaks` is on PATH / `OPA_GITLEAKS_BIN`; else embedded regex lite (`secret-scan.mjs` parity). Opt id stays `secrets` (`gitleaks` is an alias). Findings use `detector=gitleaks` or `embedded-secret-scan`. |
| sast | lite (pattern heuristics) |
| iac | stub (Dockerfile FROM + TF resources) |
| container | stub (floating tag heuristics — not Trivy/Grype) |
| sbom | lite (`package.json` / `composer.json` → inventory) |

Gitleaks invocation (when available):

```bash
gitleaks detect --source <workspace> --no-git --no-banner \
  --report-format json --report-path <tmp> --exit-code 0 --timeout 120
```

Default gitleaks rules only — no custom packs yet.

## Stack

```yaml
OPA_SECURITY_WORKSPACE: "/workspace"
volumes:
  - ./harness/fixtures/security-workspace:/workspace:ro
```
