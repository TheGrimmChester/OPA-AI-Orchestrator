# OPA AI Orchestrator

Owns Repo Watch / SCM / OPA Review and Security runs (profiles + scan orchestration).

| Port (smoke) | Service |
|---|---|
| **8091** | This service |
| 8080 | OPA-Agent (APM / remaining APIs) |
| 8092 | OPA-Perf-Lab |

**Shared:** ClickHouse (`CLICKHOUSE_URL`), JWT (`JWT_SECRET` — same secret as Agent).

**Not here:** Perf Lab (`/api/perf/*`), APM ingest, vulns/IAST list APIs (Agent Vulnerability / IAST and AppSec surfaces).

Dashboard routes `/api/scm/*`, `/api/connectors/*`, `/api/security/runs*`, `/api/security/profiles` here (via `VITE_ORCHESTRATOR_URL` or nginx path proxy).
