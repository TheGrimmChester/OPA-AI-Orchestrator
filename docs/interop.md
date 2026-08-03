# Interop

ORA may call OSA for findings / `security_run_id` linkage and AppSec gate status when `PEER_OSA_URL` is set. Empty peer URLs disable those features (`peer_unavailable`).

| Variable | Purpose |
|----------|---------|
| `PEER_OSA_URL` | OSA API base URL (required for AppSec runs from review jobs) |
| `PEER_OPA_URL` | Optional OPA hub deep links |
| `PEER_OPL_URL` | Optional OPL base URL |
| `OPEN_SERVICE_JWT_SECRET` | Service JWT mint/validate secret |
| `JWT_SECRET` | User JWT validation |
| `ORA_PUBLIC_URL` | Public URL for this product |

## Service JWT

Caller mints with `Open-Auth-Go` / `Open-Client-Go` peer helpers:

- `iss=ora-api`, `aud=osa-api`
- scopes: `runs:write`, `findings:read`, `health:read`

## Review vs AppSec gate

| Concern | Product | Mechanism |
|---------|---------|-----------|
| Review check-run / inline review comments | **ORA** | Repo Watch / review runner |
| AppSec CI gate (secrets/SAST/IaC severity) | **OSA** | `GET\|POST /api/security/gate` via peer |

Browser clients never hold `OPEN_SERVICE_JWT_SECRET`. Dashboards call only `ora-api`.
