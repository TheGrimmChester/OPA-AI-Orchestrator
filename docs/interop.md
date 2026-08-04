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

When `OPA_AUTH_REQUIRED=1`, send **`X-Organization-ID`** and **`X-Project-ID`** on control-plane calls so ClickHouse scopes match the dashboard tenant picker. Omitting them (or sending `"all"`) scopes to **`default-org` / `default-project`** — the same write tenant used for INSERT (Open-Tenant-Go ≥ 0.2.2). Prefer always sending concrete headers so scripts match the UI. Hub JWTs with `project_ids` are allowlisted via Open-Auth-Go `EnforceProjectACL` (non-member → **403**; `admin` unrestricted).

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

From the LAN use `192.168.100.101` instead of `127.0.0.1`. Family overview: [OPA-Stack interop](https://github.com/TheGrimmChester/OPA-Stack/blob/main/docs/interop.md#tenant-headers-required-when-auth-is-on). Sibling products (OSA security runs, OPL perf scenarios/runs) follow the same WriteTenant-aligned defaults — see that doc.

## Service JWT

Caller mints with `Open-Auth-Go` / `Open-Client-Go` peer helpers:

- `iss=ora-api`, `aud=osa-api` — scopes: `runs:write`, `findings:read`, `health:read`
- `iss=opm-api`, `aud=ora-api` — scopes: `connectors:read`, `scm:clone`, `scm:pm`, `health:read`
- `iss=osa-api`, `aud=ora-api` — scopes: `connectors:read`, `scm:clone`, `health:read`

OPM and OSA discover GitHub repos via `GET /api/connectors` and `GET /api/connectors/{id}/repos` (user JWT or service JWT with `connectors:read`). Ephemeral clones use `POST /api/peer/scm/clone-credentials` (service JWT + `scm:clone` only). Milestone list/upsert and Projects v2 list/item sync use `POST /api/peer/scm/milestones/*` and `POST /api/peer/scm/projects/*` (service JWT + `scm:pm`). GitHub App/PAT secrets never leave ORA.

### Issues peer surface (`scm:pm`)

Used by OPM to keep a task and a GitHub Issue in step. All three take `connector_id` and `repo_full_name`.

| Endpoint | Body | Returns |
|----------|------|---------|
| `POST /api/peer/scm/issues/get` | `number` | `issue` (number, title, body, state, html_url, labels, milestone, milestone_title, assignees, updated_at) |
| `POST /api/peer/scm/issues/create` | `title`, `body`, `labels`, `milestone` | `issue` |
| `POST /api/peer/scm/issues/update` | `number`, `title`, `body`, `state`, `milestone`, `labels` | `applied` (fields sent), `issue` |

`update` treats a blank `title`/`body`/`state` as "leave unchanged" so a caller can patch one field. `milestone` is `>0` set, `<0` clear, `0` leave unchanged.

Failures are machine-readable rather than a generic `502`, so the caller can report the cause:

| `status` | HTTP | Meaning |
|----------|------|---------|
| `missing_issues_permission` | 403 | The installation lacks Issues write. Body carries `missing` and `granted`. Write calls pre-flight the installation permission probe, so this is returned before GitHub is contacted. |
| `issue_not_found` | 404 | The issue was deleted, transferred, or is invisible to this connector. |
| `upstream_error` | 502 | Anything else; `error` carries GitHub's own status and body. |

**GitHub permissions for `scm:pm`:** Issues write covers milestones and the Issues surface above. Organization projects write is needed for Projects v2 only (optional — without it milestone and Issues routes still work; projects list returns `missing_organization_projects`).

**Projects v2 `sync-item` covers create and status only.** `POST /api/peer/scm/projects/sync-item` creates a
draft item when no `item_id` is supplied (`github_projects.go:274-292`) and can set the Status single-select
from a column hint (`githubSetProjectV2ItemStatus`). It does **not** update the title or body of an item that
already exists: `githubUpdateProjectV2DraftIssue` (`github_projects.go:294-302`) returns `nil` without calling
the API — updating a draft issue needs the draft's content id, which callers do not have — and the caller
discards its return value (`peer_scm_pm.go:268`). A rename therefore comes back `{"ok": true}` while the board
is unchanged, with no `status_note` to hint at it. Callers should not treat a successful `sync-item` as
confirmation that the item's title matches.

## Review vs AppSec gate

| Concern | Product | Mechanism |
|---------|---------|-----------|
| Review check-run / inline review comments | **ORA** | Repo Watch / review runner |
| AppSec CI gate (secrets/SAST/IaC severity) | **OSA** | `GET\|POST /api/security/gate` via peer |

Browser clients never hold `OPEN_SERVICE_JWT_SECRET`. Dashboards call only `ora-api`.
