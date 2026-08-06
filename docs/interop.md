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
- `iss=opm-api`, `aud=ora-api` — scopes: `connectors:read`, `scm:clone`, `scm:pm`, `scm:pr`, `health:read`
- `iss=osa-api`, `aud=ora-api` — scopes: `connectors:read`, `scm:clone`, `health:read`

OPM and OSA discover GitHub repos via `GET /api/connectors` and `GET /api/connectors/{id}/repos` (user JWT or service JWT with `connectors:read`). Ephemeral clones use `POST /api/peer/scm/clone-credentials` (service JWT + `scm:clone` only). Milestone list/upsert and Projects v2 list/item sync use `POST /api/peer/scm/milestones/*` and `POST /api/peer/scm/projects/*` (service JWT + `scm:pm`). GitHub App/PAT secrets never leave ORA.

**Install bind:** `GET /api/connectors/github/install-url` signs Open tenant into GitHub `state` (organization accounts only); callback creates an `active` connector under that org. Orphans (`pending_claim`) are invisible to list/get/peers until claimed; redirect once with `claim_token`; claim with `POST /api/connectors/{id}/claim` `{ "claim_token": "..." }` — not by matching GitHub `account_login` to an Open org name. Peer SCM resolve fail-closed: `status=active` + non-empty matching `org_id`.

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

### Projects v2 peer surface (`scm:pm`)

| Endpoint | Body | Returns |
|----------|------|---------|
| `POST /api/peer/scm/projects/list` | `owner` or `repo_full_name` | `projects` (id, title, number, url) |
| `POST /api/peer/scm/projects/items/upsert` | `project_id`, `item_id` (optional), `title`, `body`, `status_hint` | `item_id`, `title_synced`, `title_status`, `title_note`, `status_synced`, `status_note` |
| `POST /api/peer/scm/projects/items/status` | `project_id`, `item_id`, `status_hint` | `status_synced`, `status` |

`items/upsert` creates a draft item when no `item_id` is supplied, and **does now refresh the title and body of
an item that already exists.** Projects v2 has no mutation that renames a board item directly:
`updateProjectV2DraftIssue` takes the draft's own content id, so `githubUpdateProjectV2DraftIssue` first resolves
the `PVTI_…` item id to its backing `DraftIssue.id` (`ProjectV2Item.content` is a `DraftIssue | Issue |
PullRequest` union) and then mutates. A blank `title` or `body` means "leave that field unchanged".

The outcome is always reported — the caller must not assume a rename landed:

| `title_status` | `title_synced` | Meaning |
|----------------|----------------|---------|
| `ok` | `true` | GitHub confirmed the draft was updated, or the item was just created with this title. |
| `nothing_to_sync` | `false` | Neither title nor body was supplied. |
| `title_sync_unsupported` | `false` | The card is backed by a real Issue or PR. Its title lives on the issue and **cannot** be changed through Projects v2 — use the Issues surface above instead. |
| `item_not_found` | `false` | The project item, or its draft content, is gone. |
| `missing_organization_projects` | `false` | The installation lacks organization projects write. |
| `upstream_error` | `false` | Anything else GitHub returned; `title_note` carries the detail. |

Hard failures (the item could not be created, or the installation cannot use Projects v2 at all) are real
non-2xx responses carrying `status`, mirroring the Issues contract: `403 missing_organization_projects`,
`404 item_not_found`, `422 title_sync_unsupported`, `502 upstream_error`.

**GitHub permissions for `scm:pm`:** Issues write covers milestones and the Issues surface above.

Projects v2 additionally requires **Organization permissions › Projects: Read and write**
(`organization_projects: write`) on the GitHub App installation. This is *not* granted by the current
installation, so every Projects v2 route — list, `items/upsert`, `items/status` — pre-flights the installation
permission probe and refuses with `403 missing_organization_projects` (carrying `missing`, `granted`, and a
`note` naming the permission) before contacting GitHub. Until that permission is granted and the installation
permissions re-accepted, the whole Projects v2 path is unreachable in practice; milestone and Issues routes are
unaffected. PAT connectors cannot be probed and instead surface GitHub's own answer, classified into the same
statuses. A deployment with the permission granted is required to prove the live update end to end.

### Code delivery peer surface (`scm:pr`)

`scm:pr` is the **only** scope that can write code. It is separate from `scm:pm`
on purpose: a peer that syncs issues, milestones and Projects must not be able to
obtain a write-capable git credential or open a pull request. Both routes are
POST-only writes — there is no read variant under this scope.

| Route | Purpose |
|-------|---------|
| `POST /api/peer/scm/push-credentials` | Short-lived **Contents-write** installation token + `clone_url` for one delivery push. Returns `expires_at` and the granted `permissions`. Not persisted by ORA, not logged. |
| `POST /api/peer/scm/pull-requests/create` | Opens a pull request (`title`, `body`, `head`, `base`, `draft`). Returns `pull_request { number, html_url, state, head_ref, base_ref, draft }`. |

An already-open pull request for the same `head` is resolved and returned with
`already_existed: true`, so re-delivering a branch converges instead of failing.

Failures are machine-readable so the caller reports the concrete cause:

| `status` | HTTP | Meaning |
|----------|------|---------|
| `missing_contents_permission` | 403 | Installation cannot push (or the connector is not authorized for writes) |
| `missing_pull_requests_permission` | 403 | Installation cannot open pull requests |
| `head_branch_not_found` | 422 | The head branch does not exist on the remote |
| `no_commits_between` | 422 | Head carries nothing base does not already have |
| `repo_not_found` | 404 | The connector cannot see the repository |
| `upstream_error` | 502 | Anything else GitHub returned |

403 responses include the installation's `granted` / `missing` permission sets.
Write calls pre-flight the installation permission probe, so a missing permission
is reported as such rather than surfacing as a GitHub 502.

**GitHub permissions for `scm:pr`:** **Contents: Read and write** and
**Metadata: Read** for the push credential; **Pull requests: Read and write**
(plus Contents write, Metadata read) to open the pull request. **`workflows` is
never requested**, so a delivery cannot modify `.github/workflows/`. PAT
connectors are refused for writes unless `OPA_AGENTS_ALLOW_PAT_WRITE=1`.

## Review vs AppSec gate

| Concern | Product | Mechanism |
|---------|---------|-----------|
| Review check-run / inline review comments | **ORA** | Repo Watch / review runner |
| AppSec CI gate (secrets/SAST/IaC severity) | **OSA** | `GET\|POST /api/security/gate` via peer |

Browser clients never hold `OPEN_SERVICE_JWT_SECRET`. Dashboards call only `ora-api`.
