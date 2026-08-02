# GitHub Repo Watch + AI PR checks (Wave 34)

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

### Production — GitHub App

1. Create a GitHub App with Contents (read), Metadata, Pull requests (read/write), Checks (write).
2. Events: `pull_request`, `push`, `installation`, `installation_repositories`.
3. Webhook URL: `$OPA_PUBLIC_URL/v1/scm/github/webhook`
4. Agent env:

| Env | Purpose |
|-----|---------|
| `OPA_GITHUB_APP_ID` | App id |
| `OPA_GITHUB_APP_SLUG` | apps/… slug |
| `OPA_GITHUB_APP_CLIENT_ID` / `CLIENT_SECRET` | OAuth (optional) |
| `OPA_GITHUB_APP_PRIVATE_KEY` | PEM (use `\n` for newlines in env) |
| `OPA_GITHUB_WEBHOOK_SECRET` | HMAC |
| `OPA_PUBLIC_URL` | Agent public base |
| `OPA_DASHBOARD_URL` | Redirect after install |
| `OPA_SCM_STATE_DIR` | Durable SCM job + OPA Review stack JSON (default `$OPA_SECURITY_WORKSPACE/scm-state`). Survives Agent restart when the workspace (or this dir) is volume-mounted. Dual-written with ClickHouse `opa.scm_jobs` / `opa.scm_review_stacks`. |
| `OPA_REVIEW_TMP` | OPA Review + context-gen checkout root (default `/tmp/opa-review`) |
| `CURSOR_API_KEY` | **Unused for tenant jobs** (formerly a process-wide fallback). Set CLI keys via Account / AI settings (`opa.scm_secrets` scopes). Still injected into the child agent process after scoped resolution. |
| `OPA_CURSOR_AGENT_BIN` | Path to AI agent binary (image default `/usr/local/bin/agent`) |
| `OPA_CURSOR_MODEL` | default `auto` |
| `SKIP_CURSOR_AI` | `1` to skip AI. Default `0` in compose — with a scoped user/org API key, OPA Review runs |
| `OPA_CURSOR_AGENT_FORCE` | `1` to pass `--force` to the AI agent (default off; `--trust` alone for headless) |
| `OPA_AI_REVIEW_MAX_UNITS` | Cap independent review units per PR (default 10, max 12) |
| `OPA_GITLEAKS_CONFIG` | Path to gitleaks.toml (image default `/etc/opa/gitleaks.toml` allowlists UI `key:` FPs) |
| `JWT_SECRET` / `OPA_CONNECTOR_SECRET` | AES-256-GCM key material for persisting PAT + OPA Review API key in ClickHouse across Agent restarts (`OPA_CONNECTOR_SECRET` preferred; smoke uses compose `JWT_SECRET`). Ephemeral JWT fallbacks are refused for secret encryption. |
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

- Repo Watch jobs (webhook / simulate / manual AI review) always prepare `$OPA_REVIEW_TMP/{job_id}` before gitleaks/SAST/AI.
- Context generate clones into `$OPA_REVIEW_TMP/ctxgen-{id}` (default branch or optional PR), runs the agent with `cwd` = that tree, then deletes the dir.
- Real PAT/App: bare mirror + `git worktree add` via **GIT_ASKPASS** (token never in clone URL). Checkout failure → job `status=error` (no silent shared-fixture scan). Context generate fail-closed the same way with real credentials.
- Mock / fake token: isolated mock git repo under the same `$OPA_REVIEW_TMP/{id}` path.
- Webhooks for **unwatched** repos are skipped (no surprise auto-watch).
- AI agent: `cmd.Dir = checkout`, prompt + `OPA_SCAN_WORKTREE` env point at the full tree; brief instructs **surrounding-code analysis** (callers, neighbors, related tests) — not hunk-only. `--trust` by default (`OPA_CURSOR_AGENT_FORCE=1` adds `--force`). Reviews run **per changed file** (or package group when over `OPA_AI_REVIEW_MAX_UNITS`), then findings are aggregated.
- Gitleaks uses `/etc/opa/gitleaks.toml` (UI `key:` / React prop allowlists) plus an Agent post-filter; AppSec gate default `min_severity=high` ignores medium-only generic-api-key noise. Manual `force_ai` / `ai_only` jobs still run AI and report gate+ai together.
- Old `$OPA_REVIEW_TMP/*` (and legacy `worktrees/`/`jobs/`) cleaned after ~24h (`git worktree remove` + delete).
- **OPA Review API key tenancy:** stored in `opa.scm_secrets` with `scope` (`admin`|`org`|`user`) + `organization_id`/`user_id`. Job resolution: **user → org → fail closed**. Admin keys are never inherited. Process env `CURSOR_API_KEY` / `OPA_OPENAI_API_KEY` / `OPA_ANTHROPIC_API_KEY` are **not** used as tenant fallbacks.

Dashboard: **PR Jobs** shows SHA + Worktree path from job summary.

Dashboard: **Security → Repo Watch** → Connect GitHub / PAT bootstrap → select watched repos.

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
| **OPA AppSec Gate** | Lite/stub scanners for this PR/run; fail on severity policy |
| **OPA Review** | AI agent (`agent -p --trust [--force] --model auto`); per-file/package units then aggregate; default non-blocking unless `ai_blocking` on watched repo. **Global PR comment** = narrative résumé (confidence + human priorities); **findings** = inline line comments only. |

**Limitation:** Creating Check Runs generally requires a **GitHub App** with Checks: write. Classic / fine-grained **PATs** often cannot create Check Runs (Agent may mock ids under `OPA_SCM_MOCK_GITHUB` / `OPA_SCM_SKIP_CHECK_RUNS`). PR comments still work when the token has pull-request write.

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

Dashboard: **Security → Repo Watch** → **Run OPA Review** (repo + PR) → job appears under **PR Jobs**. **Re-run AI** on a job row re-queues AI-only.

With `SKIP_CURSOR_AI=1` or no OPA Review API key, the job still completes and records `ai.status=skipped` honestly.

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
- `POST /api/scm/contexts/generate` — AI agent drafts a senior-engineer reviewer brief from a full checkout under `$OPA_REVIEW_TMP/ctxgen-{id}` (default branch or optional PR); explores architecture/invariants/tests (not README-only). Returns draft; set `save_draft:true` to persist. Fail-closed on checkout with real credentials. Skips honestly when `SKIP_CURSOR_AI=1` or no key.

Prompt pack caps: primary ~8k chars, each linked ~2k (6k budget), org ~3k.

### Design / UI enforcement

When the PR diff touches UI paths (`.jsx`/`.tsx`/`.css`/`components/`/`src/pages/`/`theme/`/…):

1. AI brief sets `ui_files_changed: true` and packs **Design enforcement (from worktree)** — cites findable `src/theme/*`, `components/ui`, CSS variables; never invents a brand system.
2. Contexts tagged `design` / `ui` / `design-system` are **prioritized** in the multi-context pack (including linked repos’ design notes).
3. Findings should use rule `design-enforcement` with file:line when possible.
4. **Generate with AI** on a frontend worktree appends a Design enforcement section and suggests tags `design`,`ui`.

Dashboard: **Repo Watch → Reviewer contexts** → check **Design / UI enforcement context**, edit notes, Save. Tags show in the contexts table.

Dashboard: **Repo Watch → Reviewer contexts** — edit markdown, **Generate with AI**, link watched repos, see which contexts apply before **Run OPA Review**.

## Branch protection

Require these Check Runs on protected branches (after GitHub App is installed):

1. **OPA AppSec Gate** — fail closed on high/critical findings for the PR’s security run
2. **OPA Review** (optional) — default non-blocking; set `ai_blocking` on a watched repo to fail the check when the AI reports findings

Legacy CI without Repo Watch can still call `harness/appsec-pr-check.sh` (tenant or `SECURITY_RUN_ID`-scoped).

## APIs

- `GET /api/connectors`
- `POST /api/connectors/github/pat`
- `GET /api/connectors/github/install-url`
- `GET|PATCH|DELETE /api/connectors/{id}` — get / edit (login, display_name, replace PAT) / soft-delete + cascade watched
- `GET /api/connectors/{id}/repos` — installable repos (hydrates encrypted PAT from CH after restart)
- `GET /api/connectors/{id}/pulls?repo=owner/name` — open PRs
- `GET|PUT /api/connectors/{id}/watched`
- `GET /api/scm/jobs` — live SCM jobs (`running` → `queued` → `waiting` first; `counts`/`total`; `limit` max 500). **running** = actively processing; **queued** = next to run (slot reserved / ready); **waiting** = backlog until a free slot or prior stack item. Stack drain keeps at most `OPA_REVIEW_STACK_CONCURRENCY` items in `queued`+`running`; extras stay `waiting`. Non-stack manual jobs stay `queued` until a process slot frees. Jobs + stacks persist under `$OPA_SCM_STATE_DIR` (default `$OPA_SECURITY_WORKSPACE/scm-state`) and ClickHouse; on Agent boot, stuck `running` jobs are recovered (`recovered_from_restart`), incomplete stacks resume drain, and **all non-stack `queued` jobs are re-dispatched** up to concurrency (enqueue-time goroutines do not survive recreate). Also `POST /api/scm/jobs/resume` (admin one-shot), `POST /api/scm/jobs/{id}/retry`, `POST /api/scm/jobs/{id}/cancel`, `POST /api/scm/jobs/{id}/ai-review`, `POST /api/scm/opa-review/stacks/{id}/cancel`
- `GET /api/scm/webhooks` — GitHub delivery receipts (`outcome` queued/ignored/skipped/duplicate/ping/error; `counts`/`total`; org visibility like jobs). Dual-written to `$OPA_SCM_STATE_DIR/webhooks/*.json` + `opa.scm_webhooks`. Boot backfills synthetic rows from webhook-origin `scm_jobs` when live receipts were missing.
- `GET /api/scm/webhooks/{id}` — receipt detail (+ related job when visible)
- `POST /api/scm/ai-review` / `POST /api/scm/opa-review` — manual OPA Review enqueue
- `POST /api/scm/opa-review/stack` (alias `/api/scm/ai-review/stack`) — multi repo×PR stack `{items, force?, ai_only?, preview_url?}` → `{stack_id, job_ids}` (absolute max **500**; over 40 soft-advises `"note": "large stack — items wait and run serially"`; extras stay `waiting` until a slot frees)
- `GET /api/scm/opa-review/stacks/{id}` — stack progress (`waiting` | `queued` | `running` | `completed` | `failed`)
- `OPA_REVIEW_STACK_CONCURRENCY` — parallel SCM jobs (default 1, max 4); drain promotes waiting → queued → running as slots free
- Global OPA Review comment = narrative résumé only; line findings are inline; stack waiting semantics as above
- **UI visual MCP (required for UI diffs):** orchestrator image must ship Node.js (`node`/`npx`), Playwright Chromium + system libs, and set `OPA_REVIEW_BROWSER_DEPS_OK=1`. CLI already uses `--approve-mcps`. Env:
  - `OPA_REVIEW_BROWSER_MCP` — `1` (default) enables browser MCP for UI-touched PRs; `0` disables
  - `OPA_REVIEW_BROWSER_DEPS_OK` — must be `1` when Chromium/deps are provisioned (image default); otherwise visual MCP is skipped as unmet requirement
  - `OPA_REVIEW_PREVIEW_URL` — optional preview URL for the agent to open
  - `OPA_REVIEW_MCP_CONFIG` — optional path to extra `mcpServers` JSON merged into worktree `.cursor/mcp.json`
- `GET|POST /api/scm/contexts`, `GET|PATCH|DELETE /api/scm/contexts/{id}`, `POST /api/scm/contexts/generate`
- `PUT /api/scm/context-links`
- `GET /api/scm/settings`, `POST /api/scm/settings/cursor-key` — `cursor_key_set` only; key AES-GCM in `opa.scm_secrets`
- `POST /v1/scm/github/webhook`
- `POST /api/scm/simulate`
- `POST /api/security/runs` (Wave 33 workspace scans)
