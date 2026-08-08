# AI Issues automation

ORA can investigate GitHub Issues labelled for AI and (opt-in) open implementation PRs. Product roadmaps live in **OPM**; ORA keeps GitHub Issues / milestones / Projects v2 helpers for peers via `scm:pm` (see [Interop](interop.md)).

## Gate

Only Issues whose labels intersect agent prefs `ai_issue_labels` (default `["AI"]`) are auto-processed. Prefs (org → project → repo):

| Pref | Default | Meaning |
|------|---------|---------|
| `ai_issues_enabled` | `true` | Master switch for webhook enqueue |
| `ai_issue_labels` | `["AI"]` | Gate labels (case-insensitive) |
| `issue_auto_implement` | `false` | Auto enqueue implement after plan |
| `require_human_before_coding` | `true` | Block implement until Dashboard approve |

## GitHub App

Required: **Issues write**, Contents write, Pull requests write, Checks write, Metadata. Events: `issues`, `issue_comment`, `label` (plus existing PR/push/installation).

Optional: **Organization projects** write + `projects_v2_item` when peers use the Projects v2 `scm:pm` surface.

Probe: `GET /api/connectors/{id}/permissions`.

## Issue run graph

`issues.labeled|opened|…` → `issue_run` → `issue_prepare` → `issue_investigate` → `issue_publish` → (`issue_implement` if allowed).

Lifecycle labels: `opa:plan-ready`, `opa:building`, `opa:pr-open`.

Approve coding: `POST /api/scm/jobs/{issue_run_id}/approve-coding`.

No auto-merge.
