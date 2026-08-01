package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Senior-engineer OPA Review brief template — product branding only (never vendor names).

const opaReviewRolePreamble = `You are a **senior engineer** performing an **OPA Review** of a pull request.

**Goal:** find real defects — logic bugs, regressions, security issues, performance risks (including method complexity / nested loops / N+1), and missing test coverage that would matter in production.

**Rules:**
- Be skeptical, precise, and production-oriented.
- Do **not** waste time on style nitpicks, obvious linter issues, or vague "could be improved" comments.
- Prefer concrete, file:line findings over general advice.
- If uncertain, say what context is missing (rule "needs-context") instead of guessing.
- If there are no real issues, say so plainly and explain why the change looks safe.
- Tests must **prove** behavior, not merely execute code.

**Do NOT** commit, push, or call GitHub APIs — output JSON only. Findings with file+line are posted as **inline PR review comments**; the global PR message is a **narrative OPA Review résumé** (behavior + architecture + production risk) — not a finding dump.
`

const opaReviewInstructions = `## Review instructions (two-step)

### Step 1 — Build understanding
Summarize data flow, control flow, and assumptions in 3–5 bullets ("understanding" / "summary"). Identify what the PR changes and what must not break.

### Step 2 — Review aggressively
Challenge assumptions. Hunt for: logic bugs, edge cases, regressions, security, performance (method complexity, nested loops, N+1), incomplete/missing tests, API/contract breakage. Open surrounding code (callers, callees, interfaces, neighbors, related tests) — **do not review the hunk in isolation.**

### Hard rules
1. Ignore pure style / linter noise unless it conceals a real defect.
2. Ask for missing context when unclear (severity "low", rule "needs-context").
3. Be skeptical / production-risk oriented.
4. Require that tests prove the intended behavior.
5. Résumé fields ("narrative", confidence, "human_review_priorities"): merge blockers only — not every finding. Optionally note the strongest aspect of the PR in one sentence inside "narrative".
6. Sort findings by severity (blocker/high first). If no real issues: findings=[] and say why it looks safe.
`

// Always-on method-optimization guidance; findings use rule "performance".
const opaReviewPerformanceRules = `## Method optimization / complexity

Actively check changed methods for algorithmic and I/O complexity that will hurt production as input grows. Flag real issues with rule ` + "`performance`" + ` and file:line.

**Hunt for:**
- Nested loops over collections (` + "`foreach`" + `/` + "`for`" + `/` + "`forEach`" + `/` + "`range`" + `) that become O(n²+) as sizes grow
- Linear search inside a loop when a map/set/index would be O(1) (e.g. ` + "`in_array`" + `/` + "`array_search`" + `/` + "`.includes`" + `/` + "`.indexOf`" + ` over growing lists)
- Repeated full-collection scans or filter/map passes on hot paths when a single pass would do
- N+1 DB/API/network calls inside loops
- Building large intermediate structures when a single pass, index, or generator would suffice

**Guardrails:**
- Only flag when scale matters (request path, batch jobs, collections that grow with user/data size) — not tiny fixed-size loops.
- State the complexity (e.g. O(n²)) and why it matters under expected load; suggest a concrete rewrite (index first, join/batch query, single pass).
- Severity: typically medium or high on hot paths; use blocker only when clearly pathological under expected load.
- Do not nitpick micro-optimizations or style-only rewrites.
`

const opaReviewOutputSchema = `## Required JSON output
{
  "understanding": ["bullet1","bullet2"],
  "summary": "3–5 sentence understanding + verdict hint",
  "narrative": "2–4 short paragraphs for the OPA Review résumé (behavior, architecture, production risk; optionally one sentence on the strongest aspect)",
  "verdict": "approve" | "request_changes" | "needs_context",
  "auto_merge_confidence": 0,
  "confidence_label": "low|medium|high",
  "confidence_rationale": "one sentence",
  "human_review_priorities": [
    {"file": "path", "line": 1, "concern": "merge-blocker reason (not every finding)"}
  ],
  "findings": [
    {
      "severity": "blocker|high|medium|low",
      "file": "path",
      "line": 1,
      "message": "Problem — Why it matters — Suggested fix",
      "problem": "what is wrong",
      "why": "why it matters in production",
      "fix": "concrete fix",
      "rule": "logic|security|performance|regression|test-quality|api-contract|design-enforcement|needs-context|…",
      "scope": "file"
    }
  ],
  "comment": "short markdown résumé only (no finding dump)"
}

Per-finding contract: severity + file + line + problem + why (production) + concrete fix.
Severity mapping: blocker = must-fix before merge (treated as critical for gates). human_review_priorities = top merge blockers only (max ~5). Sort findings by severity. If no issues, findings=[] and explain why it looks safe in summary/narrative.
`

// Compact scaffold when token budget is tight (unit prompts still attach context packet when available).
const opaReviewCompactScaffold = `OPA Review — senior engineer. Find real defects (bugs, regressions, security, performance including method complexity / nested loops / N+1, missing tests). No style nitpicks. If unsure, state missing context. If clean, say why it looks safe. Output only the required JSON.
`

// extractContextSection pulls a markdown ##/### section body by heading keywords.
func extractContextSection(md string, keywords ...string) string {
	if strings.TrimSpace(md) == "" {
		return ""
	}
	lines := strings.Split(md, "\n")
	var out []string
	capture := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			if capture {
				break
			}
			heading := strings.TrimSpace(strings.TrimLeft(trim, "#"))
			hl := strings.ToLower(heading)
			for _, kw := range keywords {
				if strings.Contains(hl, strings.ToLower(kw)) {
					capture = true
					break
				}
			}
			continue
		}
		if capture {
			out = append(out, line)
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func joinContextBodies(rcs []opaReviewContext, capN int) string {
	var parts []string
	n := 0
	for _, rc := range rcs {
		chunk := strings.TrimSpace(rc.BodyMarkdown)
		if chunk == "" {
			continue
		}
		if capN > 0 && n+len(chunk) > capN {
			remain := capN - n
			if remain < 80 {
				break
			}
			chunk = truncateStr(chunk, remain)
		}
		parts = append(parts, fmt.Sprintf("### %s — %s\n%s", rc.RepoFullName, rc.Title, chunk))
		n += len(chunk)
		if capN > 0 && n >= capN {
			break
		}
	}
	return strings.Join(parts, "\n\n")
}

func collectPrimaryMarkdown(applied appliedReviewContexts) string {
	return joinContextBodies(applied.Primary, reviewCtxPrimaryCap)
}

func opaReviewScopeFromUnit(unit aiReviewUnit) string {
	if len(unit.Paths) > 0 {
		return strings.Join(unit.Paths, ", ")
	}
	return unit.ID
}

func opaReviewScopeFromDiff(diff string) string {
	files := parseDiffFiles(diff)
	names := []string{}
	for _, f := range files {
		if f.ID != "" && f.ID != "(diff)" && f.ID != "(unknown)" {
			names = append(names, f.ID)
		}
	}
	if len(names) == 0 {
		return "(see diff)"
	}
	if len(names) > 40 {
		return strings.Join(names[:40], ", ") + fmt.Sprintf(" … (+%d more)", len(names)-40)
	}
	return strings.Join(names, ", ")
}

func extractWorriesFromPRBody(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}
	if sec := extractContextSection(body, "worry", "worries", "concern", "concerns", "risk", "open question", "open questions", "todo", "follow-up"); sec != "" {
		return truncateStr(sec, 800)
	}
	lower := strings.ToLower(body)
	for _, kw := range []string{"worry", "concern", "risk", "todo", "open question", "not sure", "please review"} {
		if idx := strings.Index(lower, kw); idx >= 0 {
			start := idx
			if start > 40 {
				start -= 40
			}
			end := idx + 280
			if end > len(body) {
				end = len(body)
			}
			return truncateStr(strings.TrimSpace(body[start:end]), 400)
		}
	}
	return ""
}

func writeOPAReviewContextFields(b *strings.Builder, job *scmJob, applied appliedReviewContexts, scope string, unitMode bool) {
	primaryMD := collectPrimaryMarkdown(applied)
	system := extractContextSection(primaryMD, "system", "product", "architecture", "service purpose", "purpose", "overview")
	if system == "" && len(applied.Primary) > 0 {
		system = truncateStr(applied.Primary[0].BodyMarkdown, 1200)
	}
	if system == "" {
		system = fmt.Sprintf("Repository `%s` (fill from primary review context when available).", job.RepoFullName)
	}

	intent := extractContextSection(primaryMD, "pr intent", "intent", "goal", "what this pr", "change")
	if intent == "" {
		intent = strings.TrimSpace(job.Title)
		if job.Body != "" {
			intent += "\n\n" + truncateStr(job.Body, 1500)
		}
	}

	invariants := extractContextSection(primaryMD, "invariant", "invariants", "must not", "must not break", "constraints")
	risks := extractContextSection(primaryMD, "risk", "risks", "risk profile", "auth", "footgun", "sensitive", "tricky")
	if risks == "" {
		risks = "Consider: auth, secrets, data migration, CI/CD, API compatibility, performance, hot-path complexity (nested loops, N+1), rollout."
	}
	testing := extractContextSection(primaryMD, "testing", "tests", "existing tests", "test quality", "coverage")
	if testing == "" {
		testing = "Infer from diff: tests added/changed, what they prove, and what remains untested."
	}
	operational := extractContextSection(primaryMD, "operational", "deploy", "rollout", "rollback", "feature flag", "flags")
	if operational == "" {
		operational = "Note deploy impact, feature flags, rollout/rollback if evident from the diff or contexts."
	}
	worries := extractContextSection(primaryMD, "worry", "worries", "concern", "concerns", "what worries", "open question")
	if worries == "" {
		worries = extractWorriesFromPRBody(job.Body)
	}
	if worries == "" {
		worries = "_None stated — infer from risk areas and the diff; ask if unclear._"
	}

	b.WriteString("## Context packet\n")
	fmt.Fprintf(b, "### System / product architecture\n%s\n\n", system)
	fmt.Fprintf(b, "### What this PR changes (intent)\n%s\n\n", intent)
	fmt.Fprintf(b, "### Exact scope\n%s\n\n", scope)
	fmt.Fprintf(b, "### What must not break (invariants)\n%s\n\n", nz(invariants, "_None extracted — ask if unclear._"))
	fmt.Fprintf(b, "### Risk profile / tricky areas\n%s\n\n", risks)
	fmt.Fprintf(b, "### Existing tests\n%s\n\n", testing)
	fmt.Fprintf(b, "### What worries you most\n%s\n\n", worries)
	fmt.Fprintf(b, "### Operational\n%s\n\n", operational)

	if unitMode {
		b.WriteString(formatAppliedContextsForPromptUnit(applied, false))
	} else {
		b.WriteString(formatAppliedContextsForPrompt(applied, false))
	}
}

func writeOPAReviewVisualSection(b *strings.Builder, mcpPlan reviewMCPPlan, ui bool) {
	if !ui {
		return
	}
	b.WriteString("## Visual validation\n")
	if mcpPlan.BrowserEnabled {
		b.WriteString("- Browser MCP is configured (`--approve-mcps`). Use it for visual checks when a preview URL or static HTML/storybook path exists.\n")
		if mcpPlan.PreviewURL != "" {
			fmt.Fprintf(b, "- Preview URL: `%s`\n", mcpPlan.PreviewURL)
		} else {
			b.WriteString("- No preview URL — open static HTML/storybook in the worktree if present; otherwise code-review only and note visual MCP not exercised.\n")
		}
		b.WriteString("- Report visual issues as findings with rule `design-enforcement` and file:line.\n\n")
	} else {
		fmt.Fprintf(b, "- Visual MCP unavailable: %s. Still do thorough code/design review.\n\n", mcpPlan.VisualWhy)
	}
}

func needsOPAReviewUnderstandingPass(units int, diffLen int) bool {
	if envOr("OPA_REVIEW_UNDERSTANDING_PASS", "1") == "0" {
		return false
	}
	return units >= 4 || diffLen >= 25000
}

// normalizeOPAReviewSeverity maps template severities onto gate-friendly values.
func normalizeOPAReviewSeverity(sev string) string {
	s := strings.ToLower(strings.TrimSpace(sev))
	switch s {
	case "blocker", "blockers", "must-fix", "p0":
		return "critical"
	case "critical", "high", "medium", "low", "info":
		return s
	case "warn", "warning":
		return "medium"
	case "nit", "nits", "style":
		return "low"
	default:
		if s == "" {
			return "medium"
		}
		return s
	}
}

func normalizeOPAReviewFindings(findings []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		cp := map[string]interface{}{}
		for k, v := range f {
			cp[k] = v
		}
		sev, _ := cp["severity"].(string)
		cp["severity"] = normalizeOPAReviewSeverity(sev)
		// Compose message from structured fields when message empty.
		msg, _ := cp["message"].(string)
		if strings.TrimSpace(msg) == "" {
			problem, _ := cp["problem"].(string)
			why, _ := cp["why"].(string)
			fix, _ := cp["fix"].(string)
			parts := []string{}
			if problem != "" {
				parts = append(parts, problem)
			}
			if why != "" {
				parts = append(parts, "Why: "+why)
			}
			if fix != "" {
				parts = append(parts, "Fix: "+fix)
			}
			if len(parts) > 0 {
				cp["message"] = strings.Join(parts, " — ")
			}
		}
		out = append(out, cp)
	}
	return out
}

func enrichInlineFindingBody(f map[string]interface{}) string {
	sev, _ := f["severity"].(string)
	rule, _ := f["rule"].(string)
	if rule == "" {
		rule, _ = f["rule_id"].(string)
	}
	problem, _ := f["problem"].(string)
	why, _ := f["why"].(string)
	fix, _ := f["fix"].(string)
	msg, _ := f["message"].(string)

	emoji := severityEmoji(sev)
	var b strings.Builder
	fmt.Fprintf(&b, "%s **OPA Review**", emoji)
	if sev != "" {
		fmt.Fprintf(&b, " · **%s**", strings.ToLower(strings.TrimSpace(sev)))
	}
	if rule != "" {
		fmt.Fprintf(&b, " · `%s`", rule)
	}
	b.WriteString("\n\n")
	if problem != "" {
		fmt.Fprintf(&b, "**Problem:** %s\n\n", problem)
		if why != "" {
			fmt.Fprintf(&b, "**Why it matters:** %s\n\n", why)
		}
		if fix != "" {
			fmt.Fprintf(&b, "**Suggested fix:** %s\n", fix)
		}
	} else {
		b.WriteString(nz(msg, "(no message)"))
	}
	return strings.TrimSpace(b.String())
}

func defaultReviewContextTemplate(repo string) string {
	return fmt.Sprintf(`# Reviewer context — %s

## System
Describe the service/product and its role in the architecture.

## PR intent
What kinds of changes are typical, and what "done" looks like.

## Scope
Modules/directories that matter for this repo.

## Important invariants
Rules that must not break (authz, tenancy, data integrity, API contracts).

## Risk areas
Auth, secrets, migrations, CI/CD, API compatibility, performance, hot-path complexity (nested loops, N+1), rollout, known tricky areas.

## Testing context
Existing tests that must continue to pass; what new tests must prove; known gaps.

## What worries you most
Footguns, open questions, and areas where reviewers should pay extra attention.

## Operational
Deploy impact, feature flags, rollout/rollback notes.
`, repo)
}

func pathBaseList(paths []string) string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, filepath.Base(p))
	}
	return strings.Join(out, ", ")
}
