# Changelog

## Unreleased

- Peer SCM: Issues surface for task ↔ issue sync (`POST /api/peer/scm/issues/{get,create,update}`, scope `scm:pm`). Failures are machine-readable — `missing_issues_permission` (403, with the granted/missing permission set), `issue_not_found` (404), `upstream_error` (502) — so callers report the concrete cause instead of a generic upstream failure. Write calls pre-flight the installation permission probe. GitHub App/PAT secrets stay in ORA.
- Issues helpers: `githubUpdateIssue` (title/body/state/milestone/labels, per-field patch semantics) and assignee/milestone-title decoding on `githubGetIssue`.
- Auth: adopt Open-Auth-Go per-user project ACLs (`project_ids` / `EnforceProjectACL` on Gate middleware). Restricted JWTs get **403** on non-member `X-Project-ID`; role `admin` stays unrestricted. No second membership store — hub-minted claims only.
- Scope: under auth, missing/`all` tenant headers collapse to `default-org`/`default-project` for in-memory lists (connectors, jobs, webhooks, review contexts) — matching Open-Tenant-Go v0.2.2 `WriteTenant` / `ScopePredicate`. User-scoped credentials no longer cross orgs.
- Bump `open-tenant-go` to v0.2.2 so auth-enforced list scope matches `WriteTenant` defaults.
- Docs: tenant headers (`X-Organization-ID` / `X-Project-ID`) scope to `default-org` / `default-project` when omitted under auth; NAS curl examples in interop.
- Bootstrap ORA ClickHouse product tables (connectors, SCM jobs/stacks/webhooks, review contexts, secrets, AI reviews, agent prefs) in `CLICKHOUSE_DB` at startup so co-deployed `opa.*` → `ora.*` rewrite and writer INSERTs no longer hit an empty database.
- Auth via Open-Auth-Go `Gate` (delete local `auth.go` / `auth_local.go` duplicates).
- Product branding: Open Review Agent (`ora-api` / `ORA-API`).
