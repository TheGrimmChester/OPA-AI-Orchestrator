# OPA AI Orchestrator

Owns Wave 34 (Repo Watch / SCM / OPA Review) and Wave 33 security **runs** (profiles + scan orchestration).

| Port (smoke) | Service |
|---|---|
| **8091** | This service |
| 8080 | OPA-Agent (APM / remaining APIs) |
| 8092 | OPA-Perf-Lab |

**Shared:** ClickHouse (`CLICKHOUSE_URL`), JWT (`JWT_SECRET` — same secret as Agent).

**Not here:** Perf Lab (`/api/perf/*`), APM ingest, vulns/IAST list APIs (Agent Wave 19/30).

Dashboard routes `/api/scm/*`, `/api/connectors/*`, `/api/security/runs*`, `/api/security/profiles` here (via `VITE_ORCHESTRATOR_URL` or nginx path proxy).
