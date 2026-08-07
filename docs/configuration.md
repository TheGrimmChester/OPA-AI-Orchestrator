# Configuration

| Variable | Description |
|----------|-------------|
| `HTTP_ADDR` / `LISTEN_ADDR` | HTTP listen address (smoke default `:8091`) |
| `JWT_SECRET` | User JWT secret (issue in standalone; validate in co-deployed) |
| `AUTH_MODE` | `standalone` or `codeployed` (default: standalone when `PEER_OPA_URL` empty) |
| `AUTH_ADMIN_USER` / `AUTH_ADMIN_PASSWORD` | Lab admin seed for standalone login (default `admin`/`admin`) |
| `OPEN_SERVICE_JWT_SECRET` | Service JWT mint/validate secret |
| `CLICKHOUSE_URL` | ClickHouse HTTP endpoint |
| `CLICKHOUSE_DB` | Product database (default `ora`). Alias: `CLICKHOUSE_DATABASE` |
| `PEER_OSA_URL` | OSA base URL (AppSec runs + gate + SCM checker fan-out target) |
| `PEER_OAM_URL` | OAM base URL (connector directory sync via `POST /api/internal/connectors/sync`; dashboard project switcher via `GET /api/oam/projects?product=ora`). When set, browser connector/credential writes are refused (`credentials_home_oam`); OAM peers writes via `/api/internal/connectors/*`. `POST /api/scm/ai-review` and `POST /api/scm/opa-review/stack` fail-closed when a concrete `X-Project-ID` is absent from OAM `?product=ora` (skip when unset or project empty/`all`). |
| `OAM_DASHBOARD_URL` | Preferred base for post-install / claim browser redirects (`/connectors`). Falls back to `OPA_DASHBOARD_URL` for one release. |
| `PEER_OPL_URL` | OPL base URL (SCM checker fan-out) |
| `PEER_OPM_URL` | OPM base URL (SCM checker fan-out) |
| `PEER_OPA_URL` | Optional OPA hub base URL (also selects co-deployed auth when set) |
| `ORA_PUBLIC_URL` | Public URL for this product |
| `OPA_GITHUB_APP_ID` | GitHub App id |
| `OPA_GITHUB_APP_SLUG` | GitHub App slug for install URLs and reviewer login. Fallback `ora`; set to the **installed** App slug in production (do not force-rename a live App). |
| `OPA_GITHUB_APP_PRIVATE_KEY` | GitHub App PEM |
| `OPA_GITHUB_WEBHOOK_SECRET` | Webhook HMAC secret |
| `OPA_GITHUB_INSTALL_STATE_SECRET` | Dedicated HMAC for signed install `state` (≥16). Prefer over `JWT_SECRET`. When set, only this key verifies callback state (set `OPA_GITHUB_INSTALL_STATE_ACCEPT_LEGACY=1` temporarily to also accept older `OPEN_SERVICE`/`JWT` tokens). |
| `OPA_GITHUB_GRAPHQL_URL` | GitHub GraphQL endpoint used by the Projects v2 surface (default `https://api.github.com/graphql`). Override for a GitHub Enterprise host or a test stub. |
| `ORA_RUNNER_TAG` | Runner image tag (`smoke` or `nas`) |
| `ORCHESTRATOR_LISTEN_ADDR` | Orchestrator health listen (default `:8096`) |
| `OPA_GATE_WAIT_TIMEOUT_SEC` | How long the AppSec Gate waits for the OSA security run to finish before reporting `scan_incomplete` (default `600`) |
| `OPA_GATE_RUN_APPEAR_TIMEOUT_SEC` | How long the gate waits for the security run to exist at all before reporting `scan_incomplete` (default `90`). A run that never appears is a broken hand-off, so this is shorter than the scan budget. |
| `OPA_CHECKUP_MODULE_SRC` | Host directory holding sibling module checkouts, used to resolve `go.mod` filesystem `replace` targets in Checkup. Accepts a `:`-separated list. Falls back to `FAMILY_ROOT`, then `OPA_FAMILY_SRC`. See [Job isolation](job-isolation.md#checkup-workspace). |

## Security cache and job sandbox

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | empty | Dedicated `redis-ora` instance for security caches (install-permission probe, webhook dedup, job-token allowlist mirror). Memory-only when unset. |
| `ORA_SEC_L1_CACHE` | `20000` | L1 max entries for security cache |
| `ORA_SEC_KEY_PREFIX` | `ora:sec:` | Redis key prefix |
| `OPA_JOB_SANDBOX` | `off` | Set `docker` on NAS for container-isolated agent/scan jobs |
| `OPA_JOB_EGRESS_PROXY` | on when sandbox=docker | Set `0` for break-glass unrestricted egress |
| `OPA_JOB_ALLOW_HOST_EXEC` | off | Break-glass host exec when docker unavailable |

Job boxes never receive `REDIS_URL` or platform secrets — see [Job isolation](job-isolation.md).
