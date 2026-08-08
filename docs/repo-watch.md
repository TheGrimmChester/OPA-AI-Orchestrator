# Repo Watch (ORA)

GitHub Repo Watch + AI PR checks

## Today (no GitHub App yet)

```bash
# Tenant-wide gate
curl -fsS -H "X-OPA-Security-Token: $OPA_SECURITY_INGEST_TOKEN" \
  -X POST "$OPA_AGENT_URL/v1/security/pr-check"

# Scoped to a security run
curl -fsS -H "X-OPA-Security-Token: $OPA_SECURITY_INGEST_TOKEN" \
  -H 'Content-Type: application/json' \
  -X POST "$OPA_AGENT_URL/v1/security/pr-check" \
  -d '{"security_run_id":"srun-…"}'
```

Harness: `OPA-stack/harness/appsec-pr-check.sh`

## Connect GitHub

Family platform overview (checker fan-out, OAM tenancy, peer contract): [OPA-Stack interop — SCM checker platform](https://github.com/TheGrimmChester/OPA-Stack/blob/main/docs/interop.md#scm-checker-platform).

ORA supports **two webhook ingress modes**. Both feed the same unified pipeline (tenant resolve → SCM envelope → parallel peer fan-out → GitHub status publish).

**Enablement (when `PEER_OAM_URL` is set):** Account Manager owns review enablement. Enable product **ora** on an OAM directory project, bind `external_key` (`owner/repo`) and `connector_ids`. ORA auto-ensures a runtime watched row on webhook/install — do **not** rely on a Watch UI or browser `PUT …/watched` (that path returns **404** under peer OAM). Solo lab without `PEER_OAM_URL` may still use local watched rows / App auto-watch.

Register connectors from **OAM Dashboard**; every connector requires `organization_id` + `project_id`.

| Mode | When to use | Webhook URL | Credential |
|------|-------------|-------------|------------|
| **GitHub App** | Production; Check Runs + installation APIs | `{ORA_PUBLIC_URL}/v1/scm/github/webhook` | App installation (OAM-scoped) |
| **Repository hooks** | No App; PAT-only orgs | `{ORA_PUBLIC_URL}/v1/scm/github/webhook/{connector_id}` | PAT with `admin:repo_hook` (or fine-grained hook scope) |

Repository-hook mode: under peer OAM, enablement comes from the OAM project bind (ORA ensures runtime watched rows). Without `PEER_OAM_URL`, `PUT /api/connectors/{id}/watched` may still create hooks. Per-repo encrypted secret on `watched_repos` (`webhook_mode`: `app` | `repo`).

### Account binding (Open tenant, not GitHub login)

GitHub App installs bind to an **Open** org or personal tenant from the **signed-in Open session**, not from the GitHub install target (`account_login`).

| Path | How tenancy is set |
|------|--------------------|
| **Happy path (preferred)** | Dashboard **Connect GitHub App** → `GET /api/connectors/github/install-url` mints a short-lived signed `state` JWT (`org` / `proj` / `user`) from the signed-in Open session (organization account → org bind; personal account → `user_id` / empty org) → GitHub callback → connector `status=active` under that Open tenant |
| **Orphan / marketplace** | Install without valid `state` → connector `status=pending_claim` + one-time `claim_token` in the dashboard redirect → org admin **`POST /api/connectors/{id}/claim`** with `{ "claim_token": "..." }` |

Do **not** infer Open tenancy from GitHub `account_login` name equality, and do **not** fall back to `default-org` for unscoped installs. `OPA_GITHUB_APP_CLIENT_ID` is optional install-flow OAuth only — not Open↔GitHub user linking.

### Production — GitHub App

1. Create a GitHub App with:
   - **Contents:** read (clone) and **write** (autofix land / issue implement)
   - **Metadata:** read
   - **Pull requests:** read/write
   - **Checks:** write
   - **Issues:** read/write (**required** for AI Issues, milestones, and PR conversation comments)
   - **Organization projects:** read/write — **optional**, for Projects v2 peer (`scm:pm`)
2. Events: `pull_request`, `push`, `installation`, `installation_repositories`, **`issues`**, **`issue_comment`**, **`label`**. Optionally `projects_v2_item` when Projects v2 is on.
3. Webhook URL: `$ORA_PUBLIC_URL/v1/scm/github/webhook` (legacy alias: `$OPA_PUBLIC_URL/v1/scm/github/webhook`)
4. Dashboard: `GET /api/connectors/{id}/permissions` probes installation grants and lists missing keys (Issues write, etc.).
5. AI Issues: see [ai-issues-roadmap.md](ai-issues-roadmap.md). Only Issues labelled `AI` (configurable) are auto-processed.
4. Agent env:

| Env | Purpose |
|-----|---------|
| `OPA_GITHUB_APP_ID` | App id |
| `OPA_GITHUB_APP_SLUG` | GitHub App slug (`https://github.com/apps/<slug>`). Used as the reviewer login for Apps. Code fallback is `ora`; **production must set the installed App’s real slug** (NAS currently uses `opa-ai-orchestrator` via compose `.env`). |
| `OPA_GITHUB_APP_CLIENT_ID` / `CLIENT_SECRET` | OAuth (optional) |
| `OPA_GITHUB_APP_PRIVATE_KEY` | PEM (use `\n` for newlines in env) |
| `OPA_GITHUB_WEBHOOK_SECRET` | HMAC |
| `OPA_PUBLIC_URL` | Agent public base |
| `OAM_DASHBOARD_URL` | Preferred redirect after install / claim (`/connectors`). Falls back to `OPA_DASHBOARD_URL`. |
| `OPA_DASHBOARD_URL` | Fallback redirect base (one release); also used for job Check Run links |
| `OPA_SCM_STATE_DIR` | Durable SCM job + OPA Review stack JSON (default `$OPA_SECURITY_WORKSPACE/scm-state`). Survives Agent restart when the workspace (or this dir) is volume-mounted. Dual-written with ClickHouse `opa.scm_jobs` / `opa.scm_review_stacks`. |
| `OPA_REVIEW_TMP` | OPA Review + context-gen checkout root (default `/tmp/opa-review`) |
| `CURSOR_API_KEY` | **Unused for tenant jobs** (formerly a process-wide fallback). Set review-runner / model-provider keys via Account settings (`opa.scm_secrets` scopes). Still injected into the child review-runner process after scoped resolution. |
| `OPA_CURSOR_AGENT_BIN` | Path to review-runner binary (image default `/usr/local/bin/agent`) |
| `OPA_CURSOR_MODEL` | default `auto` |
| `SKIP_CURSOR_AI` | `1` to skip automated review. Default `0` in compose — with a scoped user/org API key, OPA Review runs |
| `OPA_CURSOR_AGENT_FORCE` | `1` to pass `--force` to the review runner (default off; `--trust` alone for headless) |
| `OPA_AI_REVIEW_MAX_UNITS` | Cap independent review units per PR (default 10, max 12) |
| `OPA_GITLEAKS_CONFIG` | Path to gitleaks.toml (image default `/etc/opa/gitleaks.toml` allowlists UI `key:` FPs) |
| `JWT_SECRET` / `OPA_CONNECTOR_SECRET` | AES-256-GCM key material for persisting PAT + review-runner API key in ClickHouse across Agent restarts (`OPA_CONNECTOR_SECRET` preferred; smoke uses compose `JWT_SECRET`). Ephemeral JWT fallbacks are refused for secret encryption. |
| `OPA_SCM_MOCK_GITHUB` | `1` mock checkout + Check Run ids for smoke/fake tokens (compose). **Real `ghp_` / `github_pat_` PATs still call GitHub** for repo listing and checkout. |
| `OPA_SCAN_WORKTREE_ENFORCE` | Default `1`. SCM / repo-linked security scans must use an isolated checkout under `OPA_REVIEW_TMP/{id}` (never shared `/workspace` root). Set `0` only for legacy local path scans. |
| `OPA_SCM_CRON` | `1` for 6h full scans |
| `OPA_SCM_ALLOW_UNSIGNED` | `1` only when webhook secret unset (local) |
| `OPA_AUTH_REQUIRED` | `1` auth-wraps mutating `/api/connectors/`, `/api/scm/jobs/`, `/api/scm/contexts/` (GET stays viewer) |

### Worktree layout

```
$OPA_SECURITY_WORKSPACE/
  cache/github/{owner}__{repo}.git   # bare mirror (real credentials; GIT_ASKPASS)

$OPA_REVIEW_TMP/                     # default /tmp/opa-review
  {job_id}/                          # OPA Review / SCM job PR head checkout
  ctxgen-{id}/                       # POST /api/scm/contexts/generate checkout
```

- Repo Watch jobs (webhook / simulate / manual review) always prepare `$OPA_REVIEW_TMP/{job_id}` before gitleaks/SAST/review.
- Context generate clones into `$OPA_REVIEW_TMP/ctxgen-{id}` (default branch or optional PR), runs the review runner with `cwd` = that tree, then deletes the dir.
- Real PAT/App: bare mirror + `git worktree add` via **GIT_ASKPASS** (token never in clone URL). Checkout failure → job `status=error` (no silent shared-fixture scan). Context generate fail-closed the same way with real credentials.
- Mock / fake token: isolated mock git repo under the same `$OPA_REVIEW_TMP/{id}` path.
- Webhooks for repos without an OAM ora-enabled project bind (when `PEER_OAM_URL` set) are skipped with an honest reason — no unconstrained App auto-watch. Solo without peer OAM may still auto-watch installed repos.
- Review runner: `cmd.Dir = checkout`, prompt + `OPA_SCAN_WORKTREE` env point at the full tree; brief instructs **surrounding-code analysis** (callers, neighbors, related tests) — not hunk-only. `--trust` by default (`OPA_CURSOR_AGENT_FORCE=1` adds `--force`). Reviews run **per changed file** (or package group when over `OPA_AI_REVIEW_MAX_UNITS`), then findings are aggregated.
- Gitleaks uses `/etc/opa/gitleaks.toml` (UI `key:` / React prop allowlists) plus an Agent post-filter; AppSec gate default `min_severity=high` ignores medium-only generic-api-key noise. Manual `force_ai` / `ai_only` jobs still run review and report gate+ai together.
- Old `$OPA_REVIEW_TMP/*` (and legacy `worktrees/`/`jobs/`) cleaned after ~24h (`git worktree remove` + delete).
- **Review API key tenancy:** stored in `opa.scm_secrets` with `scope` (`admin`|`org`|`user`) + `organization_id`/`user_id`. Job resolution: **user → org → fail closed**. Admin keys are never inherited. Process env `CURSOR_API_KEY` / `OPA_OPENAI_API_KEY` / `OPA_ANTHROPIC_API_KEY` are **not** used as tenant fallbacks.

Dashboard: **PR Jobs** shows SHA + Worktree path from job summary.

Dashboard: connect GitHub / PAT from **Account Manager**; enable **ora** on the OAM project and bind the repo (`external_key` + connector). ORA ensures runtime watches on the next webhook.

### Repository hooks (no App)

1. Connect a PAT under an OAM org/project (OAM Dashboard → Connectors, or `POST /api/connectors/github/pat`).
2. Set `webhook_mode` to `repo` on the connector (stored in OAM directory via `POST /api/internal/connectors/sync`).
3. Enable **ora** on the OAM project and bind `external_key` / `connector_ids` (Account Manager). Under peer OAM, browser `PUT …/watched` is **404**; ORA ensures runtime rows and registers hooks from that bind.
4. Same peer fan-out as App mode; commit-status fallback when Check Runs are unavailable.

### Local / smoke — PAT or simulate

```bash
# PAT bootstrap
curl -X POST "$AGENT/api/connectors/github/pat" -H 'Content-Type: application/json' \
  -d '{"token":"ghp_…","login":"you","repos":["org/repo"]}'

# Simulate PR job without GitHub
curl -X POST "$AGENT/api/scm/simulate" -H 'Content-Type: application/json' \
  -d '{"repo":"local/smoke","pr":1,"service":"node-smoke"}'
```

## Check Runs

| Name | Meaning |
|------|---------|
| **OPA AppSec Gate** | Scanner findings for this PR/run, evaluated by OSA; fail on severity policy |
| **OPA Checkup** | The repository's own build and test commands, run in an isolated per-job checkout |
| **OPA Review** | Review runner (`agent -p --trust [--force] --model auto`); per-file/package units then aggregate; default non-blocking unless `ai_blocking` on watched repo. **Global PR comment** = narrative résumé (confidence + human priorities); **findings** = inline line comments only. |

**Limitation:** Creating Check Runs generally requires a **GitHub App** with Checks: write. Classic / fine-grained **PATs** often cannot create Check Runs (Agent may mock ids under `OPA_SCM_MOCK_GITHUB` / `OPA_SCM_SKIP_CHECK_RUNS`). PR comments still work when the token has pull-request write.

### Three outcomes, not two

A gate that reports `failure` when it could not reach a verdict is worse than no
gate: reviewers learn to merge past red checks. Both blocking checks therefore
separate "this commit violates policy" from "this check could not run".

| Conclusion | AppSec Gate | Checkup |
|------------|-------------|---------|
| `success` | No findings at or above `min_severity` | Every step met its post-condition |
| `failure` | Blocking findings in this run | A step ran and failed — the title names the step and the summary carries its output |
| `neutral` | The gate could not evaluate | The workspace could not be prepared, so no step ran |

`neutral` conclusions state the cause in the check summary. The AppSec Gate
reports these reasons:

| Reason | Cause | Fix |
|--------|-------|-----|
| `peer_not_configured` | `PEER_OSA_URL` is unset, so no security service owns the verdict | Point `PEER_OSA_URL` at the OSA service |
| `peer_unavailable` | OSA was unreachable, refused the service token, or returned an error | Check OSA health and that `OPEN_SERVICE_JWT_SECRET` matches on both services |
| `scan_not_started` | The security run could not be created on OSA | Same as above; the check summary carries the transport error |
| `scan_incomplete` | Scanners did not finish within `OPA_GATE_WAIT_TIMEOUT_SEC`, or the run never appeared within `OPA_GATE_RUN_APPEAR_TIMEOUT_SEC` | Raise the timeout, or investigate the stalled or missing run |

The gate waits for the security run to reach a terminal state before reading
findings. Without that wait it would report on an empty findings set within a
second of the run starting, which looks like a pass or a failure depending on
timing and is neither.

## Manual OPA Review

```bash
# Queue OPA Review for a selected PR (force=true runs even on drafts)
curl -X POST "$AGENT/api/scm/ai-review" -H 'Content-Type: application/json' \
  -d '{"repo_full_name":"org/repo","pr_number":42,"connector_id":"conn-…","force":true}'

# AI-only re-run from an existing job
curl -X POST "$AGENT/api/scm/jobs/$JOB_ID/ai-review" -H 'Content-Type: application/json' \
  -d '{"force":true,"ai_only":true}'

# List open PRs (mock or GitHub)
curl "$AGENT/api/connectors/$CONN_ID/pulls?repo=org/repo"
```

Dashboard: **Run OPA Review** (repo + PR from project scope) → job appears under **PR Jobs**. **Re-run review** on a job row re-queues review-only.

With `SKIP_CURSOR_AI=1` or no review-runner API key, the job still completes and records `ai.status=skipped` honestly.

## Reviewer contexts (multi-context packs)

| Table | Purpose |
|-------|---------|
| `opa.review_contexts` | Per-repo (or `*` org-level) markdown briefs: title, body, tags, `link_group_id` |
| `opa.watched_repos.link_group_id` | Shared “project link” so OPA Review packs **this repo + linked repos’ contexts** |

APIs:

- `GET /api/scm/contexts` — list; `?for_repo=org/repo` expands primary + linked + org
- `POST /api/scm/contexts` — create
- `GET|PATCH|DELETE /api/scm/contexts/{id}`
- `PUT /api/scm/context-links` — `{ "repo_full_names":["a/b","a/c"], "link_group_id"? }` or `"clear":true`
- `POST /api/scm/contexts/generate` — review runner drafts a senior-engineer reviewer brief from a full checkout under `$OPA_REVIEW_TMP/ctxgen-{id}` (default branch or optional PR); explores architecture/invariants/tests (not README-only). Returns draft; set `save_draft:true` to persist. Fail-closed on checkout with real credentials. Skips honestly when `SKIP_CURSOR_AI=1` or no key.

Prompt pack caps: primary ~8k chars, each linked ~2k (6k budget), org ~3k.

### Design / UI enforcement

When the PR diff touches UI paths (`.jsx`/`.tsx`/`.css`/`components/`/`src/pages/`/`theme/`/…):

1. Review brief sets `ui_files_changed: true` and packs **Design enforcement (from worktree)** — cites findable `src/theme/*`, `components/ui`, CSS variables; never invents a brand system.
2. Contexts tagged `design` / `ui` / `design-system` are **prioritized** in the multi-context pack (including linked repos’ design notes).
3. Findings should use rule `design-enforcement` with file:line when possible.
4. **Generate with AI** on a frontend worktree appends a Design enforcement section and suggests tags `design`,`ui`.

Dashboard: **Repo Watch → Reviewer contexts** → check **Design / UI enforcement context**, edit notes, Save. Tags show in the contexts table.

Dashboard: **Repo Watch → Reviewer contexts** — edit markdown, **Generate with AI**, link watched repos, see which contexts apply before **Run OPA Review**.

## Branch protection

Require these Check Runs on protected branches (after GitHub App is installed):

1. **OPA AppSec Gate** — fail closed on high/critical findings for the PR’s security run
2. **OPA Checkup** — fail closed when the repository's own tests fail
3. **OPA Review** (optional) — default non-blocking; set `ai_blocking` on a watched repo to fail the check when the AI reports findings

Both blocking checks report `neutral` when they could not evaluate, so branch
protection treats an unreachable service or an unprepared runner as "no answer
yet" rather than a merge-blocking violation. Configure required checks to expect
a conclusion, and investigate repeated `neutral` results as infrastructure
faults — they mean the commit was never verified.

### AppSec Gate check outcomes

The check distinguishes three states, so a gate that never ran is never mistaken
for a clean scan:

| Title | Conclusion | Meaning |
| --- | --- | --- |
| `AppSec Gate passed` | success | OSA evaluated the run; no findings at or above `min_severity` |
| `AppSec Gate failed` | failure | OSA evaluated the run; blocking findings present |
| `AppSec Gate could not run — not scanned` | failure | The scan was never dispatched or the gate query failed (`peer_unavailable`, `scan_not_dispatched`). No finding count exists — an empty result here means nothing was scanned |

The gate result carries `evaluated` (bool). `evaluated=false` is reported as
`not_evaluated` in the PR résumé rather than a bare `error`. Results persisted
before `evaluated` existed, and the synthetic `ai_only` result, count as evaluated.

Legacy CI without Repo Watch can still call `harness/appsec-pr-check.sh` (tenant or `SECURITY_RUN_ID`-scoped).

## APIs

- `GET /api/connectors`
- `POST /api/connectors/github/pat`
- `GET /api/connectors/github/install-url` — mints signed install `state` from the current Open session (organization → org bind; personal → user_id / empty org)
- `GET /api/connectors/github/callback` — completes install; orphans redirect to OAM `/connectors?connector=…#claim_token=…` (raw token once in fragment; hash stored). `OAM_DASHBOARD_URL` preferred over `OPA_DASHBOARD_URL`. Older `?claim_token=` links still work in dashboards.
- `POST /api/connectors/github/issue-claim-token` — admin remint `{ "installation_id": "…" }` → one-time `claim_token` + `claim_url` for webhook-provisioned pendings
- `GET|PATCH|DELETE /api/connectors/{id}` — get / edit (login, display_name, replace PAT) / soft-delete + cascade watched (`pending_claim` invisible/immutable)
- `POST /api/connectors/{id}/claim` — `{ "claim_token": "..." }` claims a `pending_claim` connector into the caller's Open org (CAS; wipe nonce; sync OAM)
- `GET /api/connectors/{id}/repos` — installable repos; foreign / pending → **404** (no org leak)
- `GET /api/connectors/{id}/pulls?repo=owner/name` — open PRs
- `GET /api/connectors/{id}/watched` (runtime list). `PUT` → **404** when `PEER_OAM_URL` set (enable via OAM project); internal OAM peer path may still write.
- `GET /api/scm/jobs` — live SCM jobs (`running` → `queued` → `waiting` first; `counts`/`total`; `limit` max 500). **running** = actively processing; **queued** = next to run (slot reserved / ready); **waiting** = backlog until a free slot or prior stack item. Stack drain keeps at most `OPA_REVIEW_STACK_CONCURRENCY` items in `queued`+`running`; extras stay `waiting`. Non-stack manual jobs stay `queued` until a process slot frees. Jobs + stacks persist under `$OPA_SCM_STATE_DIR` (default `$OPA_SECURITY_WORKSPACE/scm-state`) and ClickHouse; on Agent boot, stuck `running` jobs are recovered (`recovered_from_restart`), incomplete stacks resume drain, and **all non-stack `queued` jobs are re-dispatched** up to concurrency (enqueue-time goroutines do not survive recreate). Also `POST /api/scm/jobs/resume` (admin one-shot), `POST /api/scm/jobs/{id}/retry`, `POST /api/scm/jobs/{id}/cancel`, `POST /api/scm/jobs/{id}/ai-review`, `POST /api/scm/opa-review/stacks/{id}/cancel`
- `GET /api/scm/jobs/{id}?view=ops|org|client` — job detail with typed **`evidence`** (schema_version 1): `identity`, `status`, `context`, `chat`, `results`, `posts[]`, `findings`, `auto_fixes`, `artifact_refs`, `sections`. Parent `kind=run` also returns `children_evidence` compact summaries. `view=client` redacts briefs/transcripts to previews.
- `GET /api/scm/jobs/{id}/artifacts/{name}` — durable brief/transcript/post/checkup blobs under `$OPA_SCM_STATE_DIR/jobs/{id}/artifacts/`
- `GET /api/scm/webhooks` — GitHub delivery receipts (`outcome` queued/ignored/skipped/duplicate/ping/error; `counts`/`total`; org visibility like jobs). Dual-written to `$OPA_SCM_STATE_DIR/webhooks/*.json` + `opa.scm_webhooks`. Boot backfills synthetic rows from webhook-origin `scm_jobs` when live receipts were missing.
- `GET /api/scm/webhooks/{id}` — receipt detail (+ related job when visible)
- `POST /api/scm/ai-review` / `POST /api/scm/opa-review` — manual OPA Review enqueue
- `POST /api/scm/opa-review/stack` (alias `/api/scm/ai-review/stack`) — multi repo×PR stack `{items, force?, ai_only?, preview_url?}` → `{stack_id, job_ids}` (absolute max **500**; over 40 soft-advises `"note": "large stack — items wait and run serially"`; extras stay `waiting` until a slot frees)
- `GET /api/scm/opa-review/stacks/{id}` — stack progress (`waiting` | `queued` | `running` | `completed` | `failed`)
- `OPA_REVIEW_STACK_CONCURRENCY` — parallel SCM jobs (default 1, max 4); drain promotes waiting → queued → running as slots free
- Global OPA Review comment = narrative résumé only; line findings are inline; stack waiting semantics as above
- **UI visual MCP (required for UI diffs):** ora-api / ora-orchestrator image must ship Node.js (`node`/`npx`), Playwright Chromium + system libs, and set `OPA_REVIEW_BROWSER_DEPS_OK=1`. CLI already uses `--approve-mcps`. Env:
  - `OPA_REVIEW_BROWSER_MCP` — `1` (default) enables browser MCP for UI-touched PRs; `0` disables
  - `OPA_REVIEW_BROWSER_DEPS_OK` — must be `1` when Chromium/deps are provisioned (image default); otherwise visual MCP is skipped as unmet requirement
  - `OPA_REVIEW_PREVIEW_URL` — optional preview URL for the review runner to open
  - `OPA_REVIEW_MCP_CONFIG` — optional host JSON of `mcpServers` merged into a host-owned overlay under `$OPA_SCM_STATE_DIR/mcp-overlay/.../.cursor/mcp.json` via `prepareOPAReviewMCP` / `writeReviewMCPOverlay` (never the PR worktree). Only allowlisted server names are accepted (currently `browser`); others are dropped.
- `GET|POST /api/scm/contexts`, `GET|PATCH|DELETE /api/scm/contexts/{id}`, `POST /api/scm/contexts/generate`
- `PUT /api/scm/context-links`
- `GET /api/scm/settings`, `POST /api/scm/settings/cursor-key` — `cursor_key_set` only; key AES-GCM in `opa.scm_secrets`
- `POST /v1/scm/github/webhook`
- `POST /api/scm/simulate`
- `POST /api/security/runs` (Security runs workspace scans)
