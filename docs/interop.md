# Interop

ORA may call OSA for findings / `security_run_id` linkage and AppSec gate status when `PEER_OSA_URL` is set. Empty peer URLs disable those features (`peer_unavailable`).

| Variable | Purpose |
|----------|---------|
| `PEER_OSA_URL` | OSA API base URL (required for AppSec runs from review jobs) |
| `PEER_OPA_URL` | Optional OPA hub deep links; when set (and `AUTH_MODE` unset) enables co-deployed user auth |
| `PEER_OPL_URL` | Optional OPL base URL |
| `OPEN_SERVICE_JWT_SECRET` | Service JWT mint/validate secret |
| `JWT_SECRET` | User JWT secret |
| `AUTH_MODE` | `standalone` (local `/api/auth/login`) or `codeployed` (hub-issued tokens) |
| `CLICKHOUSE_DB` | ClickHouse database for this product (default `ora`) |
| `ORA_PUBLIC_URL` | Public URL for this product |

## User auth modes

| Mode | Behavior |
|------|----------|
| **Standalone** | `ora-api` issues JWTs (`POST /api/auth/login`, `GET /api/auth/status`). Lab admin: `admin`/`admin`. |
| **Co-deployed** | Share `JWT_SECRET` with **OPA-Hub**; hub issues tokens; `ora-api` validates only. Local login returns `503`. |

## Service JWT

Caller mints with `Open-Auth-Go` / `Open-Client-Go` peer helpers:

- `iss=ora-api`, `aud=osa-api` — scopes: `runs:write`, `findings:read`, `health:read`
- `iss=opm-api`, `aud=ora-api` — scopes: `connectors:read`, `scm:clone`, `health:read`
- `iss=osa-api`, `aud=ora-api` — scopes: `connectors:read`, `scm:clone`, `health:read`

OPM and OSA discover GitHub repos via `GET /api/connectors` and `GET /api/connectors/{id}/repos` (user JWT or service JWT with `connectors:read`). Ephemeral clones use `POST /api/peer/scm/clone-credentials` (service JWT + `scm:clone` only). GitHub App/PAT secrets never leave ORA.

## Review vs AppSec gate

| Concern | Product | Mechanism |
|---------|---------|-----------|
| Review check-run / inline review comments | **ORA** | Repo Watch / review runner |
| AppSec CI gate (secrets/SAST/IaC severity) | **OSA** | `GET\|POST /api/security/gate` via peer |

Browser clients never hold `OPEN_SERVICE_JWT_SECRET`. Dashboards call only `ora-api`.
