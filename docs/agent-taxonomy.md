# Agent taxonomy

OPA splits PR work into kinds on the existing `scmJob` row (`kind`, `run_id`,
`attempt`) so least-privilege is expressible without a new run table.

| Kind | Role | Executes untrusted code | GitHub write |
|------|------|-------------------------|--------------|
| `run` | Parent folder for children | No | No |
| `prepare` | Worktree + related checkouts | No (git only) | No |
| `security` | Lite scanners + gitleaks | Yes (scan) | Publish only (in-process) |
| `bugbot` | Cursor agent review | Yes (review) | Publish only (in-process) |
| `approval` | Policy + review event | No | Yes (sole APPROVE path) |
| `cloud` | Autofix (patch → gate → clean land) | Yes (patch/verify) | Land only (in-process) |
| `checkup` | AI-planned repo tests (opt-in) | Yes (sandbox required) | Check run only (in-process) |

Invariant enforced at init: no stage combines `capExecUntrusted` with
`capGitHubWrite` / `capGitPush` (`assertNoConfusedProfile`).

Prefs freeze on run create (`Summary.prefs`). Kill switches:
`OPA_AGENTS_RUN_GRAPH=0` → legacy monolith; `OPA_JOB_SANDBOX=off|docker`.
Capability prefs (default off): `checkup_enabled`, `cloud_run_tests`.
`cloud_enabled` defaults on with `autofix_mode` `branch` (use `off` to disable; `suggest` for proposal-only).

## Status

Increments 1–7 are landed in this service: hardening (`jobEnv`, timeouts,
scoped tokens), run graph + prefs, approval integrity, product surface (risk /
summaries / rules), sandbox substrate, AI-planned checkup (incl. **phpstan
checkstyle** + baseline best-effort new-errors-only), and cloud branch mode
(authorize → patch → `gateCloudDiff` → optional verify → **clean-tree land**,
bounded re-auth iterations, babysit deleted).

**Dashboard Agents UI** (tri-state prefs, run DAG detail) ships in OPA-Dashboard
against the prefs/promote APIs — not a remaining orchestrator gap.

## Enable cloud locally

Set repo/installation prefs:

```json
{"cloud_enabled": true, "autofix_mode": "branch", "autofix_severity_threshold": "high"}
```

Optional verify: `"cloud_run_tests": true` with `OPA_JOB_SANDBOX=docker`.
Requires a `github_app` connector — PAT push is refused.
`OPA_CLOUD_MAX_ITERATIONS` defaults to 3 (clamped 1–3).

See also [job-isolation.md](./job-isolation.md).

## Honesty / remaining gaps

- **PAT GitHub writes** (`capGitHubWrite`): refused unless
  `OPA_AGENTS_ALLOW_PAT_WRITE=1`. When set, writes use the shared undifferentiable
  PAT and `Summary.capability_honesty` records the matrix degradation.
  `capGitPush` (land) still refuses PATs unconditionally — use a `github_app`
  connector. Installation tokens for clone/publish/push are repo-scoped with
  explicit permissions (`workflows` never requested).
- Legacy jobs (`kind=""`) still run the pre-split pipeline — dual path until
  traffic fully migrates.
- **PHP checkup runner** ships as `opa-runner-php` (official `php:8.4-cli-bookworm`
  + extensions + Composer). Org-private `hebabil/php-8.4-cli` remains allowlisted
  via `OPA_JOB_IMAGE_PHP` when exact fleet parity is required; see job-isolation
  Honesty.
- Cloud land applies a **gated** patch onto a fresh checkout (never trusts the
  agent WD). Suggest mode posts a proposal without land. Multi-iteration is
  bounded (not babysit); gate/auth failures stop the loop.
- `capRunRepoCode` hard-requires docker sandbox (never silent host exec).
- Prompt injection and publish-path exfil remain residual risks bounded by
  the capability envelope, not eliminated.
- Approval waits for cloud (plus bugbot/security) so `pending_autofix` cannot race.
- AI docker egress uses a **shared allowlist proxy** on `--internal` job nets;
  `HTTP(S)_PROXY` is unsettable by the guest and only a hint — network boundary
  is `--internal` (see job-isolation Honesty).
- Checkup **phpstan** is best-effort new-errors-only when a baseline file exists
  **and** the neon includes it; no host-side error differ vs prior job yet.
- Checkup per-step log viewer / stdout surfacing in the Dashboard is still a
  product gap (failing `composer`/`phinx` steps are not JUnit/Checkstyle).
