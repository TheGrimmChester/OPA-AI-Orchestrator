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
| `PEER_OSA_URL` | OSA base URL (AppSec runs + gate) |
| `PEER_OPA_URL` | Optional OPA hub base URL (also selects co-deployed auth when set) |
| `ORA_PUBLIC_URL` | Public URL for this product |
| `ORA_RUNNER_TAG` | Runner image tag (`smoke` or `nas`) |
| `ORCHESTRATOR_LISTEN_ADDR` | Orchestrator health listen (default `:8096`) |
