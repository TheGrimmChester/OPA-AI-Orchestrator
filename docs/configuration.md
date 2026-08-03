# Configuration

| Variable | Description |
|----------|-------------|
| `HTTP_ADDR` / `LISTEN_ADDR` | HTTP listen address (smoke default `:8091`) |
| `JWT_SECRET` | User JWT validation secret |
| `OPEN_SERVICE_JWT_SECRET` | Service JWT mint/validate secret |
| `CLICKHOUSE_URL` | ClickHouse HTTP endpoint |
| `PEER_OSA_URL` | OSA base URL (AppSec runs + gate) |
| `PEER_OPA_URL` | Optional OPA hub base URL |
| `ORA_PUBLIC_URL` | Public URL for this product |
| `ORA_RUNNER_TAG` | Runner image tag (`smoke` or `nas`) |
| `ORCHESTRATOR_LISTEN_ADDR` | Orchestrator health listen (default `:8096`) |
