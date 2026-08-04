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

User JWTs and standalone `/api/auth/*` come from **Open-Auth-Go** (`Gate`); this repo keeps thin wiring in `auth_wire.go`.

| Mode | Behavior |
|------|----------|
| **Standalone** | `ora-api` issues JWTs (`POST /api/auth/login`, `GET /api/auth/status`). Lab admin: `admin`/`admin`. |
| **Co-deployed** | Share `JWT_SECRET` with **OPA-Hub**; hub issues tokens; `ora-api` validates only. Local login returns `503`. |

## Tenant headers

When `OPA_AUTH_REQUIRED=1`, send **`X-Organization-ID`** and **`X-Project-ID`** on control-plane calls so ClickHouse scopes match the dashboard tenant picker. Open-Tenant treats missing headers as a no-access filter on scoped queries (empty result), not as “all tenants”.

Some SCM admin lists (for example connectors / jobs with honesty text for tenant All) may still return broader rows when headers are omitted — prefer always sending headers so scripts match the UI.

```bash
TOKEN=$(curl -sf -X POST http://127.0.0.1:18080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq -r .token)

curl -sf "http://127.0.0.1:8091/api/scm/jobs?limit=5" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Organization-ID: default-org" \
  -H "X-Project-ID: default-project" | jq '{honesty, n:(.jobs|length)}'

curl -sf http://127.0.0.1:8091/api/connectors \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Organization-ID: default-org" \
  -H "X-Project-ID: default-project" | jq '.connectors | length'
```

From the LAN use `192.168.100.101` instead of `127.0.0.1`. Family overview: [OPA-Stack interop](https://github.com/TheGrimmChester/OPA-Stack/blob/main/docs/interop.md#tenant-headers-required-when-auth-is-on). Sibling products (OSA security runs, OPL perf scenarios/runs) return empty lists without these headers — see that doc.

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
