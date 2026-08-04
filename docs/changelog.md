# Changelog

## Unreleased

- Docs: tenant headers (`X-Organization-ID` / `X-Project-ID`) required when auth is on; NAS curl examples in interop.
- Bootstrap ORA ClickHouse product tables (connectors, SCM jobs/stacks/webhooks, review contexts, secrets, AI reviews, agent prefs) in `CLICKHOUSE_DB` at startup so co-deployed `opa.*` → `ora.*` rewrite and writer INSERTs no longer hit an empty database.
- Auth via Open-Auth-Go `Gate` (delete local `auth.go` / `auth_local.go` duplicates).
- Product branding: Open Review Agent (`ora-api` / `ORA-API`).
