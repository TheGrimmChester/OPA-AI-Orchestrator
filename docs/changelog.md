# Changelog

## Unreleased

- Peer SCM: **code delivery surface** under the new narrow scope `scm:pr` — `POST /api/peer/scm/push-credentials` mints a short-lived Contents-write installation token for one delivery push, and `POST /api/peer/scm/pull-requests/create` opens the pull request. `scm:pr` is separate from `scm:pm` so an issues/milestones peer can never write code; both routes are POST-only writes. Failures are machine-readable — `missing_contents_permission` / `missing_pull_requests_permission` (403, with the granted/missing permission set), `head_branch_not_found` and `no_commits_between` (422), `repo_not_found` (404), `upstream_error` (502). An already-open pull request for the same head is returned with `already_existed: true`. Write calls pre-flight the installation permission probe. Requires **Contents: Read and write** and **Pull requests: Read and write**; `workflows` is never requested. GitHub App/PAT secrets stay in ORA.
- Checks: `OPA AppSec Gate` and `OPA Checkup` distinguish "could not evaluate" from "policy violation". An unreachable security service, a security run that never started, or a run that did not finish within `OPA_GATE_WAIT_TIMEOUT_SEC` now reports **neutral** with the cause, instead of `failure`. Verdict reasons: `peer_not_configured`, `peer_unavailable`, `scan_not_started`, `scan_incomplete`.
- Gate: wait for the OSA security run to reach a terminal state before reading findings. The gate previously evaluated immediately after creating the run, completing in under a second against an empty findings set.
- Checkup: resolve `go.mod` filesystem `replace` targets into the job layout and bind them read-only, so services that pin sibling module directories compile in their isolated checkout. Unresolvable replacements report **neutral** (`status=blocked`) with the module names and `OPA_CHECKUP_MODULE_SRC` guidance — no step runs, so no failure is claimed.
- Checkup: clear `primary/.opa-checkup/` step captures before each run so a retry on a reused layout cannot report a previous attempt's output.
- Checkup: failed checks name the failing step in the check title and include a head-and-tail excerpt of that step's output in the summary.
- Config: add `OPA_GATE_WAIT_TIMEOUT_SEC`, `OPA_GATE_RUN_APPEAR_TIMEOUT_SEC` and `OPA_CHECKUP_MODULE_SRC`.

- Peer SCM: Issues surface for task ↔ issue sync (`POST /api/peer/scm/issues/{get,create,update}`, scope `scm:pm`). Failures are machine-readable — `missing_issues_permission` (403, with the granted/missing permission set), `issue_not_found` (404), `upstream_error` (502) — so callers report the concrete cause instead of a generic upstream failure. Write calls pre-flight the installation permission probe. GitHub App/PAT secrets stay in ORA.
- Issues helpers: `githubUpdateIssue` (title/body/state/milestone/labels, per-field patch semantics) and assignee/milestone-title decoding on `githubGetIssue`.

- Auth: adopt Open-Auth-Go per-user project ACLs (`project_ids` / `EnforceProjectACL` on Gate middleware). Restricted JWTs get **403** on non-member `X-Project-ID`; role `admin` stays unrestricted. No second membership store — hub-minted claims only.
- Scope: under auth, missing/`all` tenant headers collapse to `default-org`/`default-project` for in-memory lists (connectors, jobs, webhooks, review contexts) — matching Open-Tenant-Go v0.2.2 `WriteTenant` / `ScopePredicate`. User-scoped credentials no longer cross orgs.
- Bump `open-tenant-go` to v0.2.2 so auth-enforced list scope matches `WriteTenant` defaults.
- Docs: tenant headers (`X-Organization-ID` / `X-Project-ID`) scope to `default-org` / `default-project` when omitted under auth; NAS curl examples in interop.
- Bootstrap ORA ClickHouse product tables (connectors, SCM jobs/stacks/webhooks, review contexts, secrets, AI reviews, agent prefs) in `CLICKHOUSE_DB` at startup so co-deployed `opa.*` → `ora.*` rewrite and writer INSERTs no longer hit an empty database.
- Auth via Open-Auth-Go `Gate` (delete local `auth.go` / `auth_local.go` duplicates).
- Product branding: Open Review Agent (`ora-api` / `ORA-API`).
