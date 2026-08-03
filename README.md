# ORA-API

Go API for **Open Review Agent** — Repo Watch, SCM connectors, automated code review, review check-runs, coding agents, and roadmaps.

| Port (smoke) | Service |
|---|---|
| **8091** | `ora-api` |
| 8080 | `opa-hub` / `opa-agent` (observability) |
| 8092 | `opl-api` |
| 8093 | `osa-api` |

**Shared when co-deployed:** ClickHouse (`CLICKHOUSE_URL`), user JWT (`JWT_SECRET`).

**Not here:** AppSec findings / vulns / IAST / AppSec CI gate (**OSA**), load tests (**OPL**), APM ingest (**OPA**).

## Documentation

See [docs/index.md](docs/index.md).

## Build

```bash
go build -o ora-api .
```

Image tags: `ora-api:smoke` (laptop) · `ora-api:nas` (production / NAS only).
