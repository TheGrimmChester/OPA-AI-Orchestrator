# AI Issues and Roadmap automation

OPA can investigate GitHub Issues labelled for AI, generate product roadmaps from the Dashboard, publish milestones + Issues, and (opt-in) open implementation PRs. Patterns follow [AutoCursor](https://github.com/TheGrimmChester/AutoCursor) / Aperant-style lifecycle — reimplemented for the Go orchestrator (not an AGPL copy).

## Gate

Only Issues whose labels intersect agent prefs `ai_issue_labels` (default `["AI"]`) are auto-processed. Prefs (org → installation → repo):

| Pref | Default | Meaning |
|------|---------|---------|
| `ai_issues_enabled` | `true` | Master switch for webhook enqueue |
| `ai_issue_labels` | `["AI"]` | Gate labels (case-insensitive) |
| `issue_auto_implement` | `false` | Auto enqueue implement after plan |
| `require_human_before_coding` | `true` | Block implement until Dashboard approve |
| `roadmap_projects_v2` | `false` | Also link published Issues into a Projects v2 board |

## GitHub App

Required: **Issues write**, Contents write, Pull requests write, Checks write, Metadata. Events: `issues`, `issue_comment`, `label` (plus existing PR/push/installation).

Optional: **Organization projects** write + `projects_v2_item` when `roadmap_projects_v2` is on.

Probe: `GET /api/connectors/{id}/permissions`.

## Issue run graph

`issues.labeled|opened|…` → `issue_run` → `issue_prepare` → `issue_investigate` → `issue_publish` → (`issue_implement` if allowed).

Lifecycle labels: `opa:plan-ready`, `opa:building`, `opa:pr-open`.

Approve coding: `POST /api/scm/jobs/{issue_run_id}/approve-coding`.

No auto-merge.

## Roadmap APIs

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/scm/roadmap/generate` | `{repo_full_name, connector_id?, contexts[], competitors[], audience_notes?, publish?}` |
| GET | `/api/scm/roadmap/runs` | List roadmap runs |
| GET | `/api/scm/roadmap/runs/{id}` | Run + artifacts |
| POST | `/api/scm/roadmap/publish` | Milestones + Issues (label AI); Projects v2 if flagged |

Contexts: `discovery`, `competitor`, `audience`, `features`.

Publish creates GitHub **milestones** and Issues (with gate labels). Projects v2 is best-effort behind the flag.
