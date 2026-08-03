package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	aiReviewMaxUnitsDefault = 10
	aiReviewMaxUnitDiff     = 40000
)

type aiReviewPriority struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Concern string `json:"concern"`
}

type aiReviewResult struct {
	ID                    string                   `json:"id"`
	Status                string                   `json:"status"`
	Model                 string                   `json:"model"`
	Summary               string                   `json:"summary"`
	Comment               string                   `json:"comment"`
	Findings              []map[string]interface{} `json:"findings"`
	Annotations           []map[string]interface{} `json:"annotations"`
	Usage                 string                   `json:"cursor_usage"`
	Error                 string                   `json:"error,omitempty"`
	Fallback              bool                     `json:"fallback,omitempty"`
	Parts                 []aiReviewPartResult     `json:"parts,omitempty"`
	UnitsReviewed         int                      `json:"units_reviewed,omitempty"`
	DesignEnforced        bool                     `json:"design_enforced,omitempty"`
	MCP                   *reviewMCPPlan           `json:"mcp,omitempty"`
	InlinePosted          int                      `json:"inline_posted,omitempty"`
	InlineFailed          int                      `json:"inline_failed,omitempty"`
	InlineMode            string                   `json:"inline_mode,omitempty"` // review | comments | annotations_only | mock
	InlineHonesty         string                   `json:"inline_honesty,omitempty"`
	Narrative             string                   `json:"narrative,omitempty"`
	AutoMergeConfidence   int                      `json:"auto_merge_confidence,omitempty"`
	ConfidenceLabel       string                   `json:"confidence_label,omitempty"`
	ConfidenceRationale   string                   `json:"confidence_rationale,omitempty"`
	HumanReviewPriorities []aiReviewPriority       `json:"human_review_priorities,omitempty"`
	Verdict               string                   `json:"verdict,omitempty"`
	Understanding         []string                 `json:"understanding,omitempty"`
}

type aiReviewPartResult struct {
	UnitID   string                   `json:"unit_id"`
	Kind     string                   `json:"kind"` // file | package
	Paths    []string                 `json:"paths"`
	Summary  string                   `json:"summary"`
	Comment  string                   `json:"comment,omitempty"`
	Findings []map[string]interface{} `json:"findings"`
	Fallback bool                     `json:"fallback,omitempty"`
	Error    string                   `json:"error,omitempty"`
}

type aiReviewUnit struct {
	ID    string
	Kind  string // file | package
	Paths []string
	Diff  string
	IsUI  bool
}

// aiReviewPublishMeta carries gate/scan/context details for PR + Check Run copy.
type aiReviewPublishMeta struct {
	SecurityRunID     string
	Gate              map[string]interface{}
	Scanners          []string
	ContextTitles     []string
	WorktreeOK        bool
	WorktreeDetail    string
	DesignEnforcement bool
	ScanSeverity      map[string]int
	MCP               reviewMCPPlan
	InlinePosted      int
	InlineFailed      int
	InlineMode        string
	InlineHonesty     string
}

func runCursorAIReview(job *scmJob, conn *opaConnector, wr *opaWatchedRepo, checkoutRoot, securityRunID string) aiReviewResult {
	id := loadID("airev", job.ID, newRandomHex(6))
	res := aiReviewResult{ID: id, Status: "pending", Model: envOr("OPA_CURSOR_MODEL", "auto"), Findings: []map[string]interface{}{}, Annotations: []map[string]interface{}{}}

	if envOr("SKIP_CURSOR_AI", "0") == "1" {
		res.Status = "skipped"
		res.Summary = "OPA Review skipped (SKIP_CURSOR_AI=1)"
		persistAIReview(job, res)
		return res
	}
	key, agentBin, model, force := resolveCLICursorConfig(job.OrganizationID, job.ProjectID, job.ActorUserID)
	res.Model = model
	if key == "" {
		res.Status = "skipped"
		if strings.TrimSpace(job.ActorUserID) == "" {
			res.Summary = "OPA Review API key not set — webhook jobs need an org CLI agent key under Account → Organization (personal keys are ignored when ActorUserID is empty)"
		} else {
			res.Summary = "OPA Review API key not set — save a CLI agent key under Account (personal or org)"
		}
		persistAIReview(job, res)
		return res
	}

	owner, repoName := splitOwnerRepo(job.RepoFullName)
	diff, _ := githubPRDiff(conn, owner, repoName, job.PRNumber)
	if len(diff) > 120000 {
		diff = diff[:120000] + "\n… truncated …\n"
	}

	units := splitDiffIntoReviewUnits(diff, aiReviewMaxUnits())
	res.DesignEnforced = diffTouchesUI(diff)
	res.UnitsReviewed = len(units)

	mcpPlan := prepareOPAReviewMCP(checkoutRoot, res.DesignEnforced, opaReviewPreviewURL(job))
	res.MCP = &mcpPlan

	baseArgs := []string{"-p", "--trust", "--approve-mcps", "--output-format", "text", "--model", model}
	if force {
		baseArgs = append(baseArgs, "--force")
	}

	service := ""
	if wr != nil {
		service = wr.ServiceName
	}
	appliedAll := resolveReviewContextsForRepo(job.OrganizationID, job.ProjectID, job.RepoFullName)

	var usageParts []string
	anyFallback := false
	anyAISuccess := false

	if len(units) == 0 {
		// Empty / unparseable diff — one global heuristic pass.
		units = []aiReviewUnit{{ID: "(whole PR)", Kind: "package", Paths: nil, Diff: diff, IsUI: diffTouchesUI(diff)}}
	}

	// Optional high-level understanding pass before adversarial per-unit review.
	understandingBullets := []string{}
	if needsOPAReviewUnderstandingPass(len(units), len(diff)) {
		understand := runOPAReviewUnderstandingPass(job, key, agentBin, baseArgs, checkoutRoot, securityRunID, service, appliedAll, diff, mcpPlan)
		if understand != "" {
			usageParts = append(usageParts, "understanding: "+truncateStr(understand, 500))
			if job.Summary == nil {
				job.Summary = map[string]interface{}{}
			}
			job.Summary["opa_review_understanding"] = truncateStr(understand, 2000)
			understandingBullets = splitUnderstandingBullets(understand)
		}
	}

	for i, unit := range units {
		part := reviewOneUnit(job, key, agentBin, model, baseArgs, checkoutRoot, securityRunID, service, appliedAll, unit, id, i, mcpPlan)
		res.Parts = append(res.Parts, part)
		if part.Fallback {
			anyFallback = true
		} else {
			anyAISuccess = true
		}
		for _, f := range part.Findings {
			res.Findings = append(res.Findings, f)
		}
		if part.Error != "" {
			usageParts = append(usageParts, unit.ID+": "+truncateStr(part.Error, 200))
		}
	}

	global := synthesizeGlobalSummary(job, units, res.Parts)
	for _, f := range global.Findings {
		res.Findings = append(res.Findings, f)
	}
	res.Summary = global.Summary
	if anyFallback && !anyAISuccess {
		res.Fallback = true
		if !strings.Contains(strings.ToLower(res.Summary), "fallback") {
			res.Summary = "Structured review output unavailable; applied rule-based fallback. " + res.Summary
		}
	} else if anyFallback {
		res.Summary = res.Summary + " (some parts used rule-based fallback)"
	}

	gateStatus := "unknown"
	if job.Summary != nil {
		if g, ok := job.Summary["gate"].(map[string]interface{}); ok {
			if s, _ := g["status"].(string); s != "" {
				gateStatus = s
			}
		}
	}
	ctxTitles := contextTitlesFromApplied(summarizeAppliedContexts(appliedAll))
	synth := runOPAReviewSynthesis(job, key, agentBin, baseArgs, checkoutRoot, res, understandingBullets, gateStatus, ctxTitles)
	applyOPAReviewSynthesis(&res, synth)
	if res.Summary == "" {
		res.Summary = truncateStr(res.Narrative, 400)
	}

	// needs_context: optionally clone additional related repos discovered mid-review, then re-synthesize once.
	if strings.EqualFold(res.Verdict, "needs_context") && conn != nil {
		texts := []string{res.Narrative, res.Summary, res.ConfidenceRationale}
		for _, u := range res.Understanding {
			texts = append(texts, u)
		}
		extra := extractRelatedReposFromText(texts...)
		already := relatedRepoNames(relatedCheckoutsForReview(job))
		more := resolveRelatedReposForJob(job, appliedAll, "", extra, already)
		if len(more) > 0 {
			srcMap := map[string]string{}
			for _, n := range more {
				srcMap[strings.ToLower(n)] = "mid_review"
			}
			// Clones land under the run worktree (RunID), not the bugbot child id.
			added := prepareRelatedCheckouts(conn, nz(job.RunID, job.ID), more, srcMap)
			prev := relatedCheckoutsForReview(job)
			prev = append(prev, added...)
			if job.Summary == nil {
				job.Summary = map[string]interface{}{}
			}
			job.Summary["related_mid_review"] = true
			persistRelatedCheckoutsOnRun(job, prev)
			usageParts = append(usageParts, fmt.Sprintf("needs_context: cloned %d additional related repo(s)", len(added)))
			synth2 := runOPAReviewSynthesis(job, key, agentBin, baseArgs, checkoutRoot, res, understandingBullets, gateStatus, ctxTitles)
			applyOPAReviewSynthesis(&res, synth2)
		}
	}

	res.Findings = sortFindingsBySeverity(res.Findings)
	res.Usage = truncateStr(strings.Join(usageParts, "\n"), 4000)
	res.Annotations = findingsToAnnotations(res.Findings)
	if len(res.Findings) > 0 {
		res.Status = "findings"
	} else {
		res.Status = "clean"
	}
	persistAIReview(job, res)
	return res
}

func sortFindingsBySeverity(findings []map[string]interface{}) []map[string]interface{} {
	if len(findings) < 2 {
		return findings
	}
	out := make([]map[string]interface{}, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		si, _ := out[i]["severity"].(string)
		sj, _ := out[j]["severity"].(string)
		return findingSeverityRank(si) < findingSeverityRank(sj)
	})
	return out
}

func aiReviewMaxUnits() int {
	n := 0
	fmt.Sscanf(envOr("OPA_AI_REVIEW_MAX_UNITS", ""), "%d", &n)
	if n <= 0 {
		n = aiReviewMaxUnitsDefault
	}
	if n > 12 {
		n = 12
	}
	return n
}

var skipReviewPathSuffixes = []string{
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf",
	".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz",
	".jar", ".wasm", ".bin", ".exe", ".dll", ".so", ".dylib",
	".min.js", ".min.css", ".map",
}

var skipReviewPathNames = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.sum": true, "composer.lock": true, "cargo.lock": true,
	"poetry.lock": true, "gemfile.lock": true, "bun.lockb": true,
}

func shouldSkipReviewPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if skipReviewPathNames[base] {
		return true
	}
	for _, s := range skipReviewPathSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	if strings.Contains(path, "/vendor/") || strings.Contains(path, "/node_modules/") {
		return true
	}
	return false
}

// splitDiffIntoReviewUnits parses a unified diff into per-file units, then
// collapses into top-level package/dir groups when over the cap.
func splitDiffIntoReviewUnits(diff string, maxUnits int) []aiReviewUnit {
	files := parseDiffFiles(diff)
	kept := []aiReviewUnit{}
	for _, f := range files {
		if shouldSkipReviewPath(f.ID) {
			continue
		}
		hunk := f.Diff
		if len(hunk) > aiReviewMaxUnitDiff {
			hunk = hunk[:aiReviewMaxUnitDiff] + "\n… truncated …\n"
		}
		kept = append(kept, aiReviewUnit{
			ID: f.ID, Kind: "file", Paths: []string{f.ID}, Diff: hunk, IsUI: pathLooksUI(f.ID),
		})
	}
	if len(kept) == 0 {
		return nil
	}
	if len(kept) <= maxUnits {
		return kept
	}
	return groupUnitsByPackage(kept, maxUnits)
}

func pathLooksUI(path string) bool {
	low := strings.ToLower(path)
	for _, h := range uiPathHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

type parsedDiffFile struct {
	ID   string
	Diff string
}

func parseDiffFiles(diff string) []parsedDiffFile {
	if strings.TrimSpace(diff) == "" {
		return nil
	}
	lines := strings.Split(diff, "\n")
	var out []parsedDiffFile
	var cur *parsedDiffFile
	flush := func() {
		if cur != nil && cur.ID != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			path := parseDiffGitPath(line)
			cur = &parsedDiffFile{ID: path, Diff: line + "\n"}
			continue
		}
		if cur == nil {
			// orphan preamble — start a synthetic unit
			cur = &parsedDiffFile{ID: "(diff)", Diff: ""}
		}
		cur.Diff += line + "\n"
		// Prefer +++ b/path when present
		if strings.HasPrefix(line, "+++ b/") {
			p := strings.TrimPrefix(line, "+++ b/")
			if p != "" && p != "/dev/null" {
				cur.ID = p
			}
		}
	}
	flush()
	return out
}

func parseDiffGitPath(line string) string {
	// diff --git a/foo b/foo
	parts := strings.Fields(line)
	if len(parts) >= 4 {
		b := parts[3]
		return strings.TrimPrefix(b, "b/")
	}
	if len(parts) >= 3 {
		return strings.TrimPrefix(parts[2], "a/")
	}
	return "(unknown)"
}

func groupUnitsByPackage(units []aiReviewUnit, maxUnits int) []aiReviewUnit {
	type bucket struct {
		key   string
		paths []string
		diff  strings.Builder
		isUI  bool
	}
	order := []string{}
	m := map[string]*bucket{}
	for _, u := range units {
		key := topLevelPackage(u.ID)
		b, ok := m[key]
		if !ok {
			b = &bucket{key: key}
			m[key] = b
			order = append(order, key)
		}
		b.paths = append(b.paths, u.Paths...)
		b.diff.WriteString(u.Diff)
		if !strings.HasSuffix(b.diff.String(), "\n") {
			b.diff.WriteByte('\n')
		}
		if u.IsUI {
			b.isUI = true
		}
	}
	// Prefer larger packages first when we must truncate.
	sort.SliceStable(order, func(i, j int) bool {
		return m[order[i]].diff.Len() > m[order[j]].diff.Len()
	})
	if len(order) > maxUnits {
		order = order[:maxUnits]
	}
	out := make([]aiReviewUnit, 0, len(order))
	for _, key := range order {
		b := m[key]
		hunk := b.diff.String()
		if len(hunk) > aiReviewMaxUnitDiff {
			hunk = hunk[:aiReviewMaxUnitDiff] + "\n… truncated …\n"
		}
		out = append(out, aiReviewUnit{
			ID: key, Kind: "package", Paths: b.paths, Diff: hunk, IsUI: b.isUI,
		})
	}
	return out
}

func topLevelPackage(path string) string {
	path = strings.TrimPrefix(path, "./")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "(root)"
	}
	if len(parts) == 1 {
		return "(root)"
	}
	// src/foo → src/foo, packages/ui → packages/ui, example_x.go → (root)
	if parts[0] == "src" || parts[0] == "pkg" || parts[0] == "internal" || parts[0] == "lib" || parts[0] == "app" || parts[0] == "packages" || parts[0] == "services" {
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	return parts[0]
}

func reviewOneUnit(job *scmJob, key, agentBin, model string, baseArgs []string, checkoutRoot, securityRunID, service string, applied appliedReviewContexts, unit aiReviewUnit, reviewID string, idx int, mcpPlan reviewMCPPlan) aiReviewPartResult {
	part := aiReviewPartResult{
		UnitID: unit.ID, Kind: unit.Kind, Paths: unit.Paths,
		Findings: []map[string]interface{}{},
	}
	brief := packAIUnitContext(job, securityRunID, service, checkoutRoot, applied, unit, mcpPlan)
	labelID := job.ID
	runID := nz(job.RunID, job.ID)
	promptPath, cleanupBrief, errBrief := writeAgentBrief(checkoutRoot, labelID, fmt.Sprintf("opa-review-%s-u%d.md", reviewID, idx), brief)
	if errBrief != nil {
		part.Fallback = true
		part.Error = "brief write: " + errBrief.Error()
		return part
	}
	defer cleanupBrief()

	uiMode := ""
	if unit.IsUI {
		uiMode = " This unit touches UI files: enforce existing design-system consistency (rule design-enforcement)."
		if mcpPlan.BrowserEnabled {
			uiMode += " Use the browser MCP for visual checks when a preview URL or static HTML/storybook path is available."
			if mcpPlan.PreviewURL != "" {
				uiMode += " Preview URL: " + mcpPlan.PreviewURL + "."
			}
		} else {
			uiMode += " Browser/visual MCP is unavailable — note that in findings if relevant, but still do a thorough code review."
		}
	}
	workVisible := agentVisibleWorkDir(checkoutRoot, labelID)
	prompt := fmt.Sprintf(
		"%s Working directory is the full PR git tree at %s (OPA Review checkout). Step 2 — review aggressively: surrounding files, callers, interfaces, related tests — not the hunk alone.%s Focus unit %q (paths: %s). Read the brief at %s (full context packet) and produce ONLY the required JSON. Findings need severity blocker|high|medium|low, file, line, problem, why (production), concrete fix. human_review_priorities = merge blockers only. If clean, say why it looks safe. Do not commit, push, or call gh.",
		opaReviewCompactScaffold, workVisible, uiMode, unit.ID, strings.Join(unit.Paths, ", "), promptPath,
	)
	args := append(append([]string{}, baseArgs...), prompt)
	extra := map[string]string{}
	if mcpPlan.PreviewURL != "" {
		extra["OPA_REVIEW_PREVIEW_URL"] = mcpPlan.PreviewURL
	}
	_ = agentBin // resolveAgentBin inside launchAgentSandbox ignores settings bin
	out, err := launchAgentSandbox(agentLaunchSpec{
		Phase: jobPhaseReview, Args: args, Dir: checkoutRoot, WorktreeRoot: checkoutRoot,
		APIKey: key, Extra: extra, Parent: scmJobContext(job.ID), JobID: labelID, RunID: runID,
		LiveUnit: unit.ID,
	})
	if err != nil {
		part.Fallback = true
		part.Error = err.Error()
		if snip := truncateStr(strings.TrimSpace(string(out)), 480); snip != "" {
			part.Error += ": " + snip
		}
		part = mergePartHeuristic(part, unit, string(out))
		return part
	}
	parsed := parseAIReviewJSON(string(out))
	if parsed.Summary == "" && parsed.Comment == "" && len(parsed.Findings) == 0 {
		part.Fallback = true
		part.Error = "unparseable OPA Review output"
		if snip := truncateStr(strings.TrimSpace(string(out)), 480); snip != "" {
			part.Error += ": " + snip
		}
		part = mergePartHeuristic(part, unit, string(out))
		return part
	}
	part.Summary = nz(parsed.Summary, "ok")
	part.Findings = tagFindingsScope(parsed.Findings, "file", unit)
	return part
}

func mergePartHeuristic(part aiReviewPartResult, unit aiReviewUnit, rawOut string) aiReviewPartResult {
	h := heuristicFindingsForDiff(unit.Diff, unit)
	part.Findings = append(part.Findings, h...)
	if part.Summary == "" {
		if len(h) == 0 {
			part.Summary = "No heuristic issues in this unit"
		} else {
			part.Summary = fmt.Sprintf("%d heuristic finding(s)", len(h))
		}
	}
	_ = rawOut
	return part
}

func tagFindingsScope(findings []map[string]interface{}, defaultScope string, unit aiReviewUnit) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		cp := map[string]interface{}{}
		for k, v := range f {
			cp[k] = v
		}
		if _, ok := cp["scope"]; !ok {
			cp["scope"] = defaultScope
		}
		if file, _ := cp["file"].(string); file == "" || file == "diff" {
			if len(unit.Paths) == 1 {
				cp["file"] = unit.Paths[0]
			} else if unit.ID != "" {
				cp["file"] = unit.ID
			}
		}
		out = append(out, cp)
	}
	return out
}

func heuristicFindingsForDiff(diff string, unit aiReviewUnit) []map[string]interface{} {
	out := []map[string]interface{}{}
	fileHint := unit.ID
	if len(unit.Paths) == 1 {
		fileHint = unit.Paths[0]
	}
	if strings.Contains(diff, "eval(") {
		out = append(out, map[string]interface{}{
			"severity": "high", "file": fileHint, "line": 1,
			"message": "Possible eval() usage in changed code", "rule": "ai-heuristic-eval",
			"scope": "file",
		})
	}
	if strings.Contains(diff, "AKIA") {
		out = append(out, map[string]interface{}{
			"severity": "critical", "file": fileHint, "line": 1,
			"message": "Possible AWS access key in diff", "rule": "ai-heuristic-aws-key",
			"scope": "file",
		})
	}
	for _, f := range heuristicDesignFindings(diff) {
		if _, ok := f["scope"]; !ok {
			f["scope"] = "file"
		}
		if file, _ := f["file"].(string); file == "" || file == "diff" {
			f["file"] = fileHint
		}
		out = append(out, f)
	}
	return out
}

func synthesizeGlobalSummary(job *scmJob, units []aiReviewUnit, parts []aiReviewPartResult) aiReviewPartResult {
	var b strings.Builder
	totalFindings := 0
	fallbacks := 0
	for _, p := range parts {
		totalFindings += len(p.Findings)
		if p.Fallback {
			fallbacks++
		}
	}
	fmt.Fprintf(&b, "Reviewed %d unit(s) across PR #%d (%s).", len(parts), job.PRNumber, job.RepoFullName)
	if totalFindings == 0 {
		b.WriteString(" No OPA Review findings.")
	} else {
		fmt.Fprintf(&b, " %d finding(s) across parts.", totalFindings)
	}
	if fallbacks > 0 {
		fmt.Fprintf(&b, " %d part(s) used rule-based fallback.", fallbacks)
	}
	// Cross-cutting heuristic on concatenated small sample (global scope)
	globalFindings := []map[string]interface{}{}
	// Keep global findings empty unless we detect cross-file patterns later;
	// per-file heuristics already ran. Mark synthesis notes only.
	_ = units
	return aiReviewPartResult{
		UnitID:   "(global)",
		Kind:     "package",
		Summary:  b.String(),
		Findings: tagFindingsScope(globalFindings, "global", aiReviewUnit{ID: "(global)"}),
		Comment:  b.String(),
	}
}

const opaReviewNarrativeCap = 1200
const opaReviewPrioritiesMax = 5

type opaReviewSynthesis struct {
	Narrative             string
	AutoMergeConfidence   int
	ConfidenceLabel       string
	ConfidenceRationale   string
	HumanReviewPriorities []aiReviewPriority
	Verdict               string
	Understanding         []string
	FromHeuristic         bool
}

func applyOPAReviewSynthesis(res *aiReviewResult, synth opaReviewSynthesis) {
	if res == nil {
		return
	}
	res.Narrative = truncateStr(strings.TrimSpace(synth.Narrative), opaReviewNarrativeCap)
	res.AutoMergeConfidence = clampInt(synth.AutoMergeConfidence, 0, 100)
	// Always derive the band from the score so emoji/label cannot disagree.
	res.ConfidenceLabel = confidenceLabelFromScore(res.AutoMergeConfidence)
	res.ConfidenceRationale = truncateStr(strings.TrimSpace(synth.ConfidenceRationale), 280)
	res.HumanReviewPriorities = capPriorities(synth.HumanReviewPriorities, opaReviewPrioritiesMax)
	res.Verdict = strings.TrimSpace(synth.Verdict)
	if len(synth.Understanding) > 0 {
		res.Understanding = synth.Understanding
	}
	if synth.FromHeuristic && !res.Fallback {
		// Heuristic synthesis alone does not mark the whole review as fallback.
	}
}

func confidenceLabelFromScore(n int) string {
	switch {
	case n >= 70:
		return "high"
	case n >= 40:
		return "medium"
	default:
		return "low"
	}
}

// decideOPAReviewEvent lives in approval_policy.go (confidence veto-only).

func hasBlockerOrHighFinding(res aiReviewResult) bool {
	for _, f := range res.Findings {
		sev := strings.ToLower(strings.TrimSpace(fmt.Sprint(f["severity"])))
		if sev == "" {
			sev = strings.ToLower(strings.TrimSpace(fmt.Sprint(f["Severity"])))
		}
		if sev == "blocker" || sev == "critical" || sev == "high" {
			return true
		}
	}
	return false
}

func formatOPAReviewDecisionBody(res aiReviewResult, event string, minScore int) string {
	conf := res.AutoMergeConfidence
	label := confidenceLabelFromScore(conf)
	var b strings.Builder
	switch event {
	case "APPROVE":
		fmt.Fprintf(&b, "**OPA Review — approved**\n\n")
		fmt.Fprintf(&b, "Auto-merge confidence **%d/100** (%s) meets threshold **%d**.\n", conf, label, minScore)
		if res.ConfidenceRationale != "" {
			fmt.Fprintf(&b, "\n%s\n", res.ConfidenceRationale)
		}
	case "REQUEST_CHANGES":
		fmt.Fprintf(&b, "**OPA Review — changes requested**\n\n")
		fmt.Fprintf(&b, "Auto-merge confidence **%d/100** (%s); threshold **%d**.\n", conf, label, minScore)
		why := concreteConfidenceWhy(res)
		if why != "" {
			fmt.Fprintf(&b, "\n**Why:** %s\n", why)
		} else if res.ConfidenceRationale != "" {
			fmt.Fprintf(&b, "\n**Why:** %s\n", res.ConfidenceRationale)
		} else {
			b.WriteString("\n**Why:** confidence below threshold without a detailed rationale — re-run review or address open findings.\n")
		}
	default:
		fmt.Fprintf(&b, "**OPA Review**\n\nConfidence **%d/100** (%s).\n", conf, label)
		if res.ConfidenceRationale != "" {
			fmt.Fprintf(&b, "\n%s\n", res.ConfidenceRationale)
		}
	}
	if res.Verdict != "" {
		fmt.Fprintf(&b, "\nVerdict: `%s`\n", res.Verdict)
	}
	return strings.TrimSpace(b.String())
}

func capPriorities(in []aiReviewPriority, max int) []aiReviewPriority {
	if max <= 0 || len(in) <= max {
		return in
	}
	return in[:max]
}

func splitUnderstandingBullets(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := regexp.MustCompile(`(?m)^\s*[-*•]\s+`).Split(s, -1)
	out := []string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Also split on "; " from joined understanding.
		for _, bit := range strings.Split(p, "; ") {
			bit = strings.TrimSpace(bit)
			if bit != "" {
				out = append(out, truncateStr(bit, 240))
			}
		}
		if len(out) >= 8 {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, truncateStr(s, 240))
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func findingLineInt(f map[string]interface{}) int {
	switch v := f["line"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func findingSeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "blocker":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func topFindingsAsPriorities(findings []map[string]interface{}, max int) []aiReviewPriority {
	if max <= 0 {
		max = 2
	}
	sorted := make([]map[string]interface{}, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		si, _ := sorted[i]["severity"].(string)
		sj, _ := sorted[j]["severity"].(string)
		return findingSeverityRank(si) < findingSeverityRank(sj)
	})
	out := []aiReviewPriority{}
	for _, f := range sorted {
		if len(out) >= max {
			break
		}
		file, _ := f["file"].(string)
		msg, _ := f["message"].(string)
		if file == "" {
			file = "(unknown)"
		}
		concern := nz(msg, "Review this change carefully")
		out = append(out, aiReviewPriority{
			File: file, Line: findingLineInt(f), Concern: truncateStr(concern, 200),
		})
	}
	return out
}

func heuristicOPAReviewSynthesis(job *scmJob, findings []map[string]interface{}, understanding []string, unitsN int, gateStatus string, contextTitles []string, fallback bool) opaReviewSynthesis {
	counts := severityCountsFromFindings(findings)
	title := strings.TrimSpace(job.Title)
	if title == "" {
		title = fmt.Sprintf("PR #%d", job.PRNumber)
	}
	var narr strings.Builder
	fmt.Fprintf(&narr, "This pull request (“%s”) was reviewed across %d unit(s) in `%s`.", title, unitsN, job.RepoFullName)
	if len(findings) == 0 {
		narr.WriteString(" No line-level findings were raised.")
	} else {
		fmt.Fprintf(&narr, " OPA Review raised %d finding(s) (%s); details are on the changed lines.", len(findings), formatSeverityCounts(counts))
	}
	if len(understanding) > 0 {
		fmt.Fprintf(&narr, "\n\nUnderstanding: %s", strings.Join(understanding, "; "))
	} else if body := strings.TrimSpace(job.Body); body != "" {
		fmt.Fprintf(&narr, "\n\nPR description (excerpt): %s", truncateStr(body, 280))
	}
	narr.WriteString("\n\nArchitecture and production risk should be validated against surrounding callers, tests, and any related migrations or infra touched by this change.")
	if len(contextTitles) > 0 {
		fmt.Fprintf(&narr, " Applied contexts: %s.", strings.Join(contextTitles, "; "))
	}
	if gateStatus != "" && gateStatus != "unknown" {
		fmt.Fprintf(&narr, " AppSec gate: %s.", gateStatus)
	}

	conf := 55
	label := "medium"
	rationale := "Heuristic résumé from title and finding counts — treat confidence as advisory."
	verdict := "needs_context"
	if fallback {
		conf = 25
		label = "low"
		rationale = "Structured synthesis unavailable; rule-based résumé only."
		verdict = "needs_context"
	} else if counts["critical"] > 0 || counts["high"] > 0 {
		conf = 30
		label = "low"
		rationale = "High-severity findings reduce auto-merge confidence."
		verdict = "request_changes"
	} else if len(findings) == 0 {
		conf = 65
		label = "medium"
		rationale = "No findings, but confidence stays medium without a full synthesis pass."
		verdict = "approve"
	} else if counts["medium"] > 0 {
		conf = 45
		label = "medium"
		rationale = "Medium findings present; human review recommended on priorities."
		verdict = "request_changes"
	}

	prios := topFindingsAsPriorities(findings, 2)
	return opaReviewSynthesis{
		Narrative:             truncateStr(narr.String(), opaReviewNarrativeCap),
		AutoMergeConfidence:   conf,
		ConfidenceLabel:       label,
		ConfidenceRationale:   rationale,
		HumanReviewPriorities: prios,
		Verdict:               verdict,
		Understanding:         understanding,
		FromHeuristic:         true,
	}
}

func parseOPAReviewSynthesisJSON(out string) (opaReviewSynthesis, bool) {
	re := regexp.MustCompile(`(?s)\{.*\}`)
	loc := re.FindString(out)
	if loc == "" {
		return opaReviewSynthesis{}, false
	}
	var body struct {
		Narrative             string             `json:"narrative"`
		AutoMergeConfidence   int                `json:"auto_merge_confidence"`
		ConfidenceLabel       string             `json:"confidence_label"`
		ConfidenceRationale   string             `json:"confidence_rationale"`
		HumanReviewPriorities []aiReviewPriority `json:"human_review_priorities"`
		Verdict               string             `json:"verdict"`
		Understanding         []string           `json:"understanding"`
		Summary               string             `json:"summary"`
	}
	if json.Unmarshal([]byte(loc), &body) != nil {
		idx := strings.LastIndex(out, "{")
		if idx < 0 || json.Unmarshal([]byte(out[idx:]), &body) != nil {
			return opaReviewSynthesis{}, false
		}
	}
	narr := strings.TrimSpace(body.Narrative)
	if narr == "" {
		narr = strings.TrimSpace(body.Summary)
	}
	if narr == "" && body.AutoMergeConfidence == 0 && body.ConfidenceLabel == "" && len(body.HumanReviewPriorities) == 0 {
		return opaReviewSynthesis{}, false
	}
	conf := clampInt(body.AutoMergeConfidence, 0, 100)
	return opaReviewSynthesis{
		Narrative:             truncateStr(narr, opaReviewNarrativeCap),
		AutoMergeConfidence:   conf,
		ConfidenceLabel:       confidenceLabelFromScore(conf),
		ConfidenceRationale:   truncateStr(strings.TrimSpace(body.ConfidenceRationale), 280),
		HumanReviewPriorities: capPriorities(body.HumanReviewPriorities, opaReviewPrioritiesMax),
		Verdict:               strings.TrimSpace(body.Verdict),
		Understanding:         body.Understanding,
	}, true
}

func packOPAReviewSynthesisBrief(job *scmJob, res aiReviewResult, understanding []string, gateStatus string, contextTitles []string) string {
	var b strings.Builder
	b.WriteString("# OPA Review — synthesis (narrative résumé)\n\n")
	b.WriteString(opaReviewRolePreamble)
	b.WriteString("Produce a **narrative résumé** for the global PR comment: behavior change, architecture judgment, and production risk. Optionally one sentence on the strongest aspect of the PR. Do **not** dump every finding — pick merge-blocker priorities only. Verdict must be approve | request_changes | needs_context.\n\n")
	fmt.Fprintf(&b, "## PR\n- repo: `%s`\n- pr: #%d\n- title: %s\n- units: %d\n- gate: `%s`\n\n",
		job.RepoFullName, job.PRNumber, job.Title, res.UnitsReviewed, gateStatus)
	if body := strings.TrimSpace(job.Body); body != "" {
		fmt.Fprintf(&b, "## PR body\n%s\n\n", truncateStr(body, 1500))
		if w := extractWorriesFromPRBody(body); w != "" {
			fmt.Fprintf(&b, "## Author worries / open questions\n%s\n\n", w)
		}
	}
	if len(understanding) > 0 {
		b.WriteString("## Understanding (Step 1)\n")
		for _, u := range understanding {
			fmt.Fprintf(&b, "- %s\n", u)
		}
		b.WriteString("\n")
	}
	if len(contextTitles) > 0 {
		fmt.Fprintf(&b, "## Applied contexts\n%s\n\n", strings.Join(contextTitles, "; "))
	}
	fmt.Fprintf(&b, "## Aggregated findings (%d, severity-sorted for inline)\n%s\n", len(res.Findings), formatTopFindingsMarkdown(sortFindingsBySeverity(res.Findings), 12))
	if len(res.Parts) > 0 {
		b.WriteString("## Unit summaries\n")
		for _, p := range res.Parts {
			fmt.Fprintf(&b, "- `%s`: %s (%d finding(s))\n", p.UnitID, nz(p.Summary, "—"), len(p.Findings))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Required JSON\n")
	b.WriteString(`{
  "narrative": "2–4 short paragraphs (optionally end with one sentence on the strongest aspect)",
  "auto_merge_confidence": 0,
  "confidence_label": "low|medium|high",
  "confidence_rationale": "one sentence",
  "human_review_priorities": [{"file":"path","line":0,"concern":"merge blocker only"}],
  "verdict": "approve|request_changes|needs_context",
  "understanding": ["…"]
}
`)
	b.WriteString("confidence_label MUST match auto_merge_confidence bands: low = 0–39, medium = 40–69, high = 70–100.\n")
	b.WriteString("Rules for confidence:\n")
	b.WriteString("- If there are **no findings** and **no merge-blocker priorities**, auto_merge_confidence MUST be **≥ 70**, confidence_label **high**, and verdict **approve** (do not under-score for title/description mismatch alone).\n")
	b.WriteString("- Low/medium confidence is allowed **only** when you list concrete human_review_priorities (merge blockers a human can fix) or findings warrant it — always explain in confidence_rationale.\n")
	b.WriteString("- Verdict needs_context requires at least one human_review_priority stating what context is missing.\n")
	return b.String()
}

func runOPAReviewSynthesis(job *scmJob, key, agentBin string, baseArgs []string, checkoutRoot string, res aiReviewResult, understanding []string, gateStatus string, contextTitles []string) opaReviewSynthesis {
	unitsN := res.UnitsReviewed
	if unitsN == 0 {
		unitsN = len(res.Parts)
	}
	fallbackSynth := heuristicOPAReviewSynthesis(job, res.Findings, understanding, unitsN, gateStatus, contextTitles, res.Fallback)
	if key == "" || envOr("SKIP_CURSOR_AI", "0") == "1" || res.Fallback {
		return fallbackSynth
	}
	brief := packOPAReviewSynthesisBrief(job, res, understanding, gateStatus, contextTitles)
	labelID := job.ID
	runID := nz(job.RunID, job.ID)
	promptPath, cleanupBrief, errBrief := writeAgentBrief(checkoutRoot, labelID, fmt.Sprintf("opa-review-synth-%s.md", nz(job.ID, res.ID)), brief)
	if errBrief != nil {
		return fallbackSynth
	}
	defer cleanupBrief()
	prompt := fmt.Sprintf(
		"%s Synthesis for the OPA Review narrative résumé. Working directory is the PR checkout at %s. Read %s and output ONLY the required JSON (narrative, confidence, human_review_priorities as merge blockers only — max 5, verdict). Do not dump all findings. Do not commit, push, or call gh.",
		opaReviewCompactScaffold, agentVisibleWorkDir(checkoutRoot, labelID), promptPath,
	)
	args := append(append([]string{}, baseArgs...), prompt)
	_ = agentBin
	out, err := launchAgentSandbox(agentLaunchSpec{
		Phase: jobPhaseReview, Args: args, Dir: checkoutRoot, WorktreeRoot: checkoutRoot,
		APIKey: key, Parent: scmJobContext(job.ID), JobID: labelID, RunID: runID,
		LivePhase: "synth",
	})
	if err != nil {
		return fallbackSynth
	}
	parsed, ok := parseOPAReviewSynthesisJSON(string(out))
	if !ok || strings.TrimSpace(parsed.Narrative) == "" {
		return fallbackSynth
	}
	if len(parsed.Understanding) == 0 {
		parsed.Understanding = understanding
	}
	if parsed.ConfidenceRationale == "" {
		parsed.ConfidenceRationale = fallbackSynth.ConfidenceRationale
	}
	if len(parsed.HumanReviewPriorities) == 0 && len(res.Findings) > 0 {
		parsed.HumanReviewPriorities = topFindingsAsPriorities(res.Findings, 2)
	}
	return parsed
}

func packAIUnitContext(job *scmJob, securityRunID, service, checkoutRoot string, applied appliedReviewContexts, unit aiReviewUnit, mcpPlan reviewMCPPlan) string {
	var b strings.Builder
	b.WriteString("# OPA Review brief (unit)\n\n")
	b.WriteString(opaReviewRolePreamble)
	fmt.Fprintf(&b, "## PR\n- repo: `%s`\n- pr: #%d\n- sha: `%s`\n- title: %s\n- unit: `%s` (%s)\n- ui: %v\n\n",
		job.RepoFullName, job.PRNumber, job.CommitSHA, job.Title, unit.ID, unit.Kind, unit.IsUI)

	filtered := filterContextsForUI(applied, unit.IsUI)
	writeOPAReviewContextFields(&b, job, filtered, opaReviewScopeFromUnit(unit), true)
	b.WriteString(opaReviewInstructions)
	b.WriteString(opaReviewPerformanceRules)
	if unit.IsUI {
		b.WriteString(packDesignEnforcementFromWorktree(checkoutRoot))
		b.WriteString(designEnforcementPromptExtra(true))
	}
	writeOPAReviewVisualSection(&b, mcpPlan, unit.IsUI)
	fmt.Fprintf(&b, "## Unit diff\n```\n%s\n```\n\n", unit.Diff)
	fmt.Fprintf(&b, "## Security run\n- security_run_id: `%s`\n- service: `%s`\n\n", securityRunID, service)
	fmt.Fprintf(&b, "## Worktree isolation\n- Absolute path: `%s`\n- This is the full PR branch tree under OPA_REVIEW_TMP. Only cite findings for files inside this primary checkout.\n- **Surrounding-code requirement:** open changed files, read callers/callees/interfaces/neighbors, and search for related tests/invariants — do not judge the hunk alone.\n\n", checkoutRoot)
	agentJob := ""
	if job != nil {
		agentJob = job.ID
	}
	b.WriteString(formatRelatedCheckoutsForPromptWithJob(relatedCheckoutsForReview(job), agentJob))
	b.WriteString(opaReviewOutputSchema)
	return b.String()
}

func packAIContext(job *scmJob, wr *opaWatchedRepo, securityRunID, diff, checkoutRoot string) string {
	service := ""
	if wr != nil {
		service = wr.ServiceName
	}
	uiTouched := diffTouchesUI(diff)
	mcpPlan := prepareOPAReviewMCP(checkoutRoot, uiTouched, opaReviewPreviewURL(job))
	applied := filterContextsForUI(resolveReviewContextsForRepo(job.OrganizationID, job.ProjectID, job.RepoFullName), uiTouched)

	var b strings.Builder
	b.WriteString("# OPA Review brief\n\n")
	b.WriteString(opaReviewRolePreamble)
	if uiTouched {
		b.WriteString("Also enforce design-system consistency against the existing UI kit in the worktree.\n\n")
	}
	fmt.Fprintf(&b, "## PR\n- repo: `%s`\n- pr: #%d\n- sha: `%s`\n- title: %s\n- ui_files_changed: %v\n\n",
		job.RepoFullName, job.PRNumber, job.CommitSHA, job.Title, uiTouched)
	writeOPAReviewContextFields(&b, job, applied, opaReviewScopeFromDiff(diff), false)
	b.WriteString(opaReviewInstructions)
	b.WriteString(opaReviewPerformanceRules)
	if uiTouched {
		b.WriteString(packDesignEnforcementFromWorktree(checkoutRoot))
		b.WriteString(designEnforcementPromptExtra(true))
	}
	writeOPAReviewVisualSection(&b, mcpPlan, uiTouched)
	fmt.Fprintf(&b, "## Diff\n```\n%s\n```\n\n", diff)
	fmt.Fprintf(&b, "## Security run\n- security_run_id: `%s`\n- service: `%s`\n\n", securityRunID, service)

	if queryClient != nil && service != "" {
		scope := fmt.Sprintf(" AND service = '%s'", escapeSQL(service))
		if rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT sink, route, evidence, trace_id FROM opa.iast_findings WHERE 1=1%s ORDER BY scraped_at DESC LIMIT 10`, scope)); err == nil && len(rows) > 0 {
			b.WriteString("## Recent IAST findings\n")
			jb, _ := json.MarshalIndent(rows, "", "  ")
			b.Write(jb)
			b.WriteString("\n\n")
		}
		if rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT advisory_id, package_name, severity, reachability FROM opa.vuln_findings WHERE 1=1%s ORDER BY scraped_at DESC LIMIT 10`, scope)); err == nil && len(rows) > 0 {
			b.WriteString("## Related vulns\n")
			jb, _ := json.MarshalIndent(rows, "", "  ")
			b.Write(jb)
			b.WriteString("\n\n")
		}
	}
	if securityRunID != "" && queryClient != nil {
		rid := escapeSQL(securityRunID)
		if rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT rule, file, line, severity FROM opa.secret_findings WHERE security_run_id = '%s' LIMIT 20`, rid)); err == nil && len(rows) > 0 {
			b.WriteString("## This-run secret findings\n")
			jb, _ := json.MarshalIndent(rows, "", "  ")
			b.Write(jb)
			b.WriteString("\n\n")
		}
		if rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT rule, file, line, severity, message FROM opa.sast_findings WHERE security_run_id = '%s' LIMIT 20`, rid)); err == nil && len(rows) > 0 {
			b.WriteString("## This-run SAST findings\n")
			jb, _ := json.MarshalIndent(rows, "", "  ")
			b.Write(jb)
			b.WriteString("\n\n")
		}
	}
	fmt.Fprintf(&b, "## Worktree isolation\n- Absolute path: `%s`\n- Full PR tree under OPA_REVIEW_TMP. Read surrounding code, callers, and related tests — not the hunk alone.\n\n", checkoutRoot)
	agentJob := ""
	if job != nil {
		agentJob = job.ID
	}
	b.WriteString(formatRelatedCheckoutsForPromptWithJob(relatedCheckoutsForReview(job), agentJob))
	b.WriteString(opaReviewOutputSchema)
	return b.String()
}

func parseAIReviewJSON(out string) aiReviewResult {
	res := aiReviewResult{Findings: []map[string]interface{}{}}
	re := regexp.MustCompile(`(?s)\{.*\}`)
	loc := re.FindString(out)
	if loc == "" {
		return res
	}
	var body struct {
		Summary               string                   `json:"summary"`
		Comment               string                   `json:"comment"`
		Narrative             string                   `json:"narrative"`
		Verdict               string                   `json:"verdict"`
		Understanding         []string                 `json:"understanding"`
		AutoMergeConfidence   int                      `json:"auto_merge_confidence"`
		ConfidenceLabel       string                   `json:"confidence_label"`
		ConfidenceRationale   string                   `json:"confidence_rationale"`
		HumanReviewPriorities []aiReviewPriority       `json:"human_review_priorities"`
		Findings              []map[string]interface{} `json:"findings"`
	}
	if json.Unmarshal([]byte(loc), &body) != nil {
		idx := strings.LastIndex(out, "{")
		if idx >= 0 {
			_ = json.Unmarshal([]byte(out[idx:]), &body)
		}
	}
	res.Summary = body.Summary
	res.Understanding = body.Understanding
	res.Verdict = body.Verdict
	res.Narrative = body.Narrative
	if body.AutoMergeConfidence > 0 {
		res.AutoMergeConfidence = clampInt(body.AutoMergeConfidence, 0, 100)
	}
	res.ConfidenceLabel = confidenceLabelFromScore(res.AutoMergeConfidence)
	res.ConfidenceRationale = body.ConfidenceRationale
	res.HumanReviewPriorities = body.HumanReviewPriorities
	if len(body.Understanding) > 0 && res.Summary == "" {
		res.Summary = strings.Join(body.Understanding, "; ")
	} else if len(body.Understanding) > 0 {
		res.Summary = strings.Join(body.Understanding, "; ") + " — " + res.Summary
	}
	if body.Verdict != "" {
		res.Summary = strings.TrimSpace(res.Summary + " [verdict: " + body.Verdict + "]")
	}
	res.Comment = body.Comment
	res.Findings = normalizeOPAReviewFindings(body.Findings)
	if res.Findings == nil {
		res.Findings = []map[string]interface{}{}
	}
	return res
}

func heuristicAIReview(id, model, diff, runID, rawOut string) aiReviewResult {
	units := splitDiffIntoReviewUnits(diff, aiReviewMaxUnits())
	if len(units) == 0 {
		units = []aiReviewUnit{{ID: "(whole PR)", Kind: "package", Paths: nil, Diff: diff, IsUI: diffTouchesUI(diff)}}
	}
	res := aiReviewResult{
		ID: id, Model: model, Status: "findings", Fallback: true,
		Summary:        "Structured AI output unavailable; applied rule-based fallback",
		Findings:       []map[string]interface{}{},
		Annotations:    []map[string]interface{}{},
		Usage:          truncateStr(rawOut, 1500),
		UnitsReviewed:  len(units),
		DesignEnforced: diffTouchesUI(diff),
	}
	for _, u := range units {
		h := heuristicFindingsForDiff(u.Diff, u)
		part := aiReviewPartResult{
			UnitID: u.ID, Kind: u.Kind, Paths: u.Paths, Fallback: true, Findings: h,
			Summary: fmt.Sprintf("%d heuristic finding(s)", len(h)),
		}
		if len(h) == 0 {
			part.Summary = "No heuristic issues in this unit"
		}
		res.Parts = append(res.Parts, part)
		res.Findings = append(res.Findings, h...)
	}
	if len(res.Findings) == 0 {
		res.Status = "clean"
		res.Summary = "No heuristic issues; structured AI output unavailable; applied rule-based fallback"
	}
	synth := heuristicOPAReviewSynthesis(
		&scmJob{RepoFullName: "", PRNumber: 0, Title: "", Body: "", ID: id},
		res.Findings, nil, len(units), "unknown", nil, true,
	)
	// Prefer runID-aware narrative when called from a real job path later; here keep thin.
	_ = runID
	applyOPAReviewSynthesis(&res, synth)
	res.Annotations = findingsToAnnotations(res.Findings)
	res.Comment = fmt.Sprintf("### OPA Review\n\n%s\n\n_security_run_id: `%s`_", res.Summary, runID)
	return res
}

func shortCommitSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 7 {
		return sha[:7]
	}
	if sha == "" {
		return "—"
	}
	return sha
}

func severityCountsFromFindings(findings []map[string]interface{}) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		sev, _ := f["severity"].(string)
		sev = strings.ToLower(strings.TrimSpace(sev))
		if sev == "" {
			sev = "unknown"
		}
		out[sev]++
	}
	return out
}

func formatSeverityCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	order := []string{"critical", "high", "medium", "low", "info", "unknown"}
	parts := []string{}
	seen := map[string]bool{}
	for _, k := range order {
		if n, ok := counts[k]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, n))
			seen[k] = true
		}
	}
	for k, n := range counts {
		if seen[k] || n <= 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", k, n))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func formatTopFindingsMarkdown(findings []map[string]interface{}, limit int) string {
	if limit <= 0 {
		limit = 8
	}
	if len(findings) == 0 {
		return "_No findings._\n"
	}
	var b strings.Builder
	n := 0
	for _, f := range findings {
		if n >= limit {
			break
		}
		file, _ := f["file"].(string)
		msg, _ := f["message"].(string)
		sev, _ := f["severity"].(string)
		rule, _ := f["rule"].(string)
		scope, _ := f["scope"].(string)
		line := 0
		switch v := f["line"].(type) {
		case float64:
			line = int(v)
		case int:
			line = v
		}
		loc := file
		if loc == "" {
			loc = "unknown"
		}
		if line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, line)
		}
		extra := ""
		if rule != "" {
			extra = fmt.Sprintf(" (`%s`)", rule)
		}
		scopeTag := ""
		if scope != "" {
			scopeTag = fmt.Sprintf(" [%s]", scope)
		}
		fmt.Fprintf(&b, "- **%s**%s `%s` — %s%s\n", nz(sev, "info"), scopeTag, loc, nz(msg, "(no message)"), extra)
		n++
	}
	if len(findings) > limit {
		fmt.Fprintf(&b, "- _…and %d more_\n", len(findings)-limit)
	}
	return b.String()
}

func formatPerPartFindingsMarkdown(parts []aiReviewPartResult) string {
	if len(parts) == 0 {
		return "_No review units._\n"
	}
	var b strings.Builder
	for _, p := range parts {
		fb := ""
		if p.Fallback {
			fb = " _(rule-based fallback)_"
		}
		fmt.Fprintf(&b, "#### `%s` (%s)%s\n", p.UnitID, p.Kind, fb)
		fmt.Fprintf(&b, "%s\n\n", nz(p.Summary, "—"))
		if len(p.Findings) == 0 {
			b.WriteString("_No findings in this unit._\n\n")
			continue
		}
		b.WriteString(formatTopFindingsMarkdown(p.Findings, 6))
		b.WriteString("\n")
	}
	return b.String()
}

func scanSeverityCountsForRun(runID string) map[string]int {
	out := map[string]int{}
	if runID == "" {
		return out
	}
	if live := liveSecurityRun(runID); live != nil {
		if sj, _ := live["summary_json"].(string); sj != "" {
			var sm struct {
				SeverityCounts map[string]map[string]int `json:"severity_counts"`
				Counts         map[string]int            `json:"counts"`
			}
			if json.Unmarshal([]byte(sj), &sm) == nil {
				for _, bySev := range sm.SeverityCounts {
					for sev, n := range bySev {
						out[strings.ToLower(sev)] += n
					}
				}
				if len(out) == 0 {
					for k, n := range sm.Counts {
						if n > 0 {
							out[k] = n
						}
					}
				}
			}
		}
	}
	return out
}

func contextTitlesFromApplied(applied []map[string]interface{}) []string {
	titles := []string{}
	for _, c := range applied {
		t, _ := c["title"].(string)
		role, _ := c["role"].(string)
		if t == "" {
			continue
		}
		if role != "" {
			titles = append(titles, fmt.Sprintf("%s (%s)", t, role))
		} else {
			titles = append(titles, t)
		}
	}
	return titles
}

// publishAIReviewComment builds a narrative Automated-review résumé for the PR / Check Run.
// Findings are posted separately as inline review comments — not listed here.
// Never names the underlying AI vendor in user-visible copy.
func publishAIReviewComment(job *scmJob, res aiReviewResult, meta aiReviewPublishMeta) (comment, checkSummary string) {
	gateStatus := "unknown"
	if meta.Gate != nil {
		if s, _ := meta.Gate["status"].(string); s != "" {
			gateStatus = s
		}
	}
	aiSev := severityCountsFromFindings(res.Findings)
	narrative := strings.TrimSpace(res.Narrative)
	if narrative == "" {
		narrative = strings.TrimSpace(res.Summary)
	}
	if narrative == "" {
		narrative = "OPA Review completed; see inline comments for line-level findings."
	}
	narrative = truncateStr(narrative, opaReviewNarrativeCap)

	conf := res.AutoMergeConfidence
	label := confidenceLabelFromScore(conf)
	rationale := strings.TrimSpace(res.ConfidenceRationale)
	if rationale == "" {
		rationale = "See inline findings and priorities below."
	}
	priorities := res.HumanReviewPriorities
	if len(priorities) == 0 && len(res.Findings) > 0 {
		priorities = topFindingsAsPriorities(res.Findings, 2)
	}

	var b strings.Builder
	b.WriteString("## OPA Review\n\n")
	if res.Fallback {
		b.WriteString("⚠️ **Structured review output unavailable; applied rule-based fallback.**\n\n")
	}
	b.WriteString(narrative)
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "%s **Auto-merge confidence:** %d/100 (**%s**) — %s\n\n",
		confidenceEmoji(conf), conf, label, rationale)
	b.WriteString("### Priority for human review\n")
	if len(priorities) == 0 {
		b.WriteString("- ✅ _None flagged as merge blockers._\n")
	} else {
		for _, p := range priorities {
			file := nz(p.File, "(unknown)")
			concern := nz(p.Concern, "Review carefully")
			prioEmoji := "⚠️"
			// Prefer matching finding severity when the priority file appears in findings.
			for _, f := range res.Findings {
				fp, _ := f["file"].(string)
				if normalizeFindingPath(fp) == normalizeFindingPath(file) {
					if sev, _ := f["severity"].(string); sev != "" {
						prioEmoji = severityEmoji(sev)
						break
					}
				}
			}
			if p.Line > 0 {
				fmt.Fprintf(&b, "- %s `%s:%d` — %s\n", prioEmoji, file, p.Line, concern)
			} else {
				fmt.Fprintf(&b, "- %s `%s` — %s\n", prioEmoji, file, concern)
			}
		}
	}
	fmt.Fprintf(&b, "\n_Inline comments cover line-level findings. AppSec gate: `%s`. security_run_id: `%s`._\n",
		gateStatus, nz(meta.SecurityRunID, job.SecurityRunID))
	if job != nil && job.Summary != nil {
		analyzed := strFromAny(job.Summary["analyzed_sha"])
		prev := strFromAny(job.Summary["previous_analyzed_sha"])
		if analyzed == "" {
			analyzed = job.CommitSHA
		}
		if analyzed != "" {
			fmt.Fprintf(&b, "\n_Analyzed commit: `%s`", truncateStr(analyzed, 12))
			if prev != "" && !strings.EqualFold(prev, analyzed) {
				fmt.Fprintf(&b, " · previous review: `%s` (new commits since last OPA Review)", truncateStr(prev, 12))
			} else if prev != "" {
				b.WriteString(" · same commit as previous OPA Review")
			}
			b.WriteString("_\n")
		}
	}
	comment = embedOPAReviewResumeMarker(strings.TrimSpace(b.String()))

	var cs strings.Builder
	fmt.Fprintf(&cs, "OPA Review · %s · conf %d/100 (%s) · %d finding(s) (%s)",
		nz(res.Status, "—"), conf, label, len(res.Findings), formatSeverityCounts(aiSev))
	if res.Verdict != "" {
		fmt.Fprintf(&cs, " · verdict=%s", res.Verdict)
	}
	cs.WriteByte('\n')
	checkSummary = strings.TrimSpace(cs.String())
	return comment, checkSummary
}

type opaReviewInlineResult struct {
	Posted   int
	Failed   int
	Updated  int
	Resolved int
	Created  int
	Mode     string // review | comments | annotations_only | mock | none | sync
	Honesty  string
	ResumeOK bool
}

func formatInlineFindingBody(f map[string]interface{}) string {
	return enrichInlineFindingBody(f)
}

func findingFileLine(f map[string]interface{}) (path string, line int, ok bool) {
	path, _ = f["file"].(string)
	path = strings.TrimSpace(path)
	if path == "" || path == "diff" || strings.HasPrefix(path, "(") {
		return "", 0, false
	}
	line = 0
	switch v := f["line"].(type) {
	case float64:
		line = int(v)
	case int:
		line = v
	case int64:
		line = int(v)
	case json.Number:
		n, _ := v.Int64()
		line = int(n)
	}
	if line < 1 {
		return path, 0, false
	}
	return path, line, true
}

// upsertOPAReviewResumeComment edits the existing résumé issue comment in place, or creates one.
// When job is non-nil, records the post into job evidence.
func upsertOPAReviewResumeComment(conn *opaConnector, owner, repo string, pr int, body string) (updated bool, err error) {
	return upsertOPAReviewResumeCommentForJob(conn, owner, repo, pr, body, nil)
}

func upsertOPAReviewResumeCommentForJob(conn *opaConnector, owner, repo string, pr int, body string, job *scmJob) (updated bool, err error) {
	body = embedOPAReviewResumeMarker(body)
	if githubUseMockAPI(conn) {
		if job != nil {
			appendEvidencePost(job, JobEvidencePost{
				Type: "resume", Target: "issue_comment", Status: "created", Body: body,
			})
		}
		return true, nil
	}
	comments, lerr := githubListIssueComments(conn, owner, repo, pr)
	if lerr != nil {
		return false, lerr
	}
	for _, c := range comments {
		if isOPAReviewResumeBody(c.Body) {
			if bodiesMeaningfullyEqual(c.Body, body) {
				if job != nil {
					appendEvidencePost(job, JobEvidencePost{
						Type: "resume", Target: "issue_comment", GitHubID: c.ID, Status: "updated", Body: body,
						URL: fmt.Sprintf("https://github.com/%s/%s/pull/%d#issuecomment-%d", owner, repo, pr, c.ID),
					})
				}
				return true, nil
			}
			err := githubUpdateIssueComment(conn, owner, repo, c.ID, body)
			if job != nil && err == nil {
				appendEvidencePost(job, JobEvidencePost{
					Type: "resume", Target: "issue_comment", GitHubID: c.ID, Status: "updated", Body: body,
					URL: fmt.Sprintf("https://github.com/%s/%s/pull/%d#issuecomment-%d", owner, repo, pr, c.ID),
				})
			}
			return true, err
		}
	}
	id, err := githubPRCommentCreate(conn, owner, repo, pr, body)
	if job != nil && err == nil {
		appendEvidencePost(job, JobEvidencePost{
			Type: "resume", Target: "issue_comment", GitHubID: id, Status: "created", Body: body,
			URL: fmt.Sprintf("https://github.com/%s/%s/pull/%d#issuecomment-%d", owner, repo, pr, id),
		})
	}
	return err == nil, err
}

func collectPriorOPAReviewComments(conn *opaConnector, owner, repo string, pr int) []opaReviewPriorComment {
	raw, err := githubListPRReviewComments(conn, owner, repo, pr)
	if err != nil || len(raw) == 0 {
		return nil
	}
	out := []opaReviewPriorComment{}
	for _, c := range raw {
		if c.InReplyTo != 0 {
			continue
		}
		if !isOPAReviewInlineBody(c.Body) {
			continue
		}
		key := extractOPAReviewFindingID(c.Body)
		if key == "" {
			// Legacy: approximate key from path + body text so re-runs can still close/update.
			key = opaReviewFindingKey(map[string]interface{}{
				"file": c.Path, "message": stripOPAReviewMarkers(c.Body),
			})
		}
		out = append(out, opaReviewPriorComment{
			ID: c.ID, Key: key, Path: c.Path, Line: c.Line, Body: c.Body,
		})
	}
	return out
}

func closeOPAReviewComment(conn *opaConnector, owner, repo string, pr int, commitSHA string, prior opaReviewPriorComment) error {
	superseded := formatSupersededFindingBody(prior.Body, commitSHA)
	if err := githubUpdatePRReviewComment(conn, owner, repo, prior.ID, superseded); err != nil {
		// Fall through to reply-only.
		_ = err
	} else {
		_ = githubReplyPRReviewComment(conn, owner, repo, pr, commitSHA, prior.ID, formatFixedReplyBody(commitSHA))
		return nil
	}
	return githubReplyPRReviewComment(conn, owner, repo, pr, commitSHA, prior.ID, formatFixedReplyBody(commitSHA))
}

// closeOPAReviewFindingsByKeys marks matching OPA Review inline comments as fixed/superseded
// (used after Auto-fix so threads do not stay open until the follow-up review runs).
func closeOPAReviewFindingsByKeys(conn *opaConnector, owner, repo string, pr int, commitSHA string, keys []string) int {
	if conn == nil || pr <= 0 || len(keys) == 0 || githubUseMockAPI(conn) {
		return 0
	}
	want := map[string]struct{}{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k != "" {
			want[k] = struct{}{}
		}
	}
	if len(want) == 0 {
		return 0
	}
	closed := 0
	for _, old := range collectPriorOPAReviewComments(conn, owner, repo, pr) {
		if _, ok := want[old.Key]; !ok {
			continue
		}
		if err := closeOPAReviewComment(conn, owner, repo, pr, commitSHA, old); err != nil {
			continue
		}
		closed++
	}
	return closed
}

// opaReviewShouldPostResume is false when the CLI agent did not run (no key /
// SKIP_CURSOR_AI / other skip). Avoid posting a 0/100 résumé that only says
// the review was skipped.
func opaReviewShouldPostResume(res aiReviewResult) bool {
	return strings.ToLower(strings.TrimSpace(res.Status)) != "skipped"
}

// postOPAReviewFindings syncs line-level PR review comments (add/update/close) and
// upserts the global résumé issue comment. Falls back to annotations honesty.
// Decision events (APPROVE / REQUEST_CHANGES) are NOT submitted here — approval.decide
// (or the legacy caller via publishPRReview) owns that through the chokepoint.
func postOPAReviewFindings(conn *opaConnector, owner, repo string, job *scmJob, res aiReviewResult, meta aiReviewPublishMeta, autoApproveMinScore int) opaReviewInlineResult {
	out := opaReviewInlineResult{Mode: "none"}
	if job == nil || job.PRNumber <= 0 {
		return out
	}
	if !githubUseMockAPI(conn) {
		if err := ensureGitHubWriteAllowed(job, conn); err != nil {
			out.Mode = "refused"
			out.Failed = 1
			if job.Summary == nil {
				job.Summary = map[string]interface{}{}
			}
			job.Summary["publish_refused"] = err.Error()
			return out
		}
	}

	pubMeta := meta
	if pubMeta.DesignEnforcement == false {
		pubMeta.DesignEnforcement = res.DesignEnforced
	}
	if pubMeta.SecurityRunID == "" {
		pubMeta.SecurityRunID = job.SecurityRunID
	}
	if res.MCP != nil && pubMeta.MCP.VisualStatus == "" {
		pubMeta.MCP = *res.MCP
	}
	postResume := opaReviewShouldPostResume(res)
	resume := ""
	if postResume {
		resume, _ = publishAIReviewComment(job, res, pubMeta)
	}
	_ = autoApproveMinScore // decision deferred to evaluateApproval / publishPRReview

	if githubUseMockAPI(conn) {
		out.Mode = "mock"
		n := 0
		for _, f := range res.Findings {
			if _, _, ok := findingFileLine(f); ok {
				n++
			}
		}
		out.Posted = n
		out.Created = n
		out.ResumeOK = postResume
		out.Honesty = "mock GitHub — inline sync skipped; decision deferred to approval"
		if !postResume {
			out.Honesty += "; résumé omitted (CLI agent unavailable)"
		}
		if job.Summary == nil {
			job.Summary = map[string]interface{}{}
		}
		job.Summary["pending_decision"] = true
		return out
	}

	if postResume && resume != "" {
		if _, err := upsertOPAReviewResumeCommentForJob(conn, owner, repo, job.PRNumber, resume, job); err == nil {
			out.ResumeOK = true
		}
	}

	prior := collectPriorOPAReviewComments(conn, owner, repo, job.PRNumber)
	carried := carriedForwardKeysFromJob(job)
	plan := planOPAReviewCommentActions(res.Findings, prior, carried)

	for _, old := range plan.Close {
		if err := closeOPAReviewComment(conn, owner, repo, job.PRNumber, job.CommitSHA, old); err != nil {
			out.Failed++
			continue
		}
		out.Resolved++
		appendEvidencePost(job, JobEvidencePost{
			Type: "inline", Target: "review_comment", GitHubID: old.ID, Status: "resolved",
			Body: old.Body, FindingKey: old.Key,
			URL: fmt.Sprintf("https://github.com/%s/%s/pull/%d#discussion_r%d", owner, repo, job.PRNumber, old.ID),
		})
	}

	for _, u := range plan.Update {
		if u.Retarget {
			if err := closeOPAReviewComment(conn, owner, repo, job.PRNumber, job.CommitSHA, u.Prior); err != nil {
				out.Failed++
			} else {
				out.Resolved++
				appendEvidencePost(job, JobEvidencePost{
					Type: "inline", Target: "review_comment", GitHubID: u.Prior.ID, Status: "resolved",
					Body: u.Body, FindingKey: u.Prior.Key,
				})
			}
			continue
		}
		if err := githubUpdatePRReviewComment(conn, owner, repo, u.Prior.ID, u.Body); err != nil {
			out.Failed++
			continue
		}
		out.Updated++
		appendEvidencePost(job, JobEvidencePost{
			Type: "inline", Target: "review_comment", GitHubID: u.Prior.ID, Status: "updated",
			Body: u.Body, FindingKey: u.Prior.Key,
			URL: fmt.Sprintf("https://github.com/%s/%s/pull/%d#discussion_r%d", owner, repo, job.PRNumber, u.Prior.ID),
		})
	}

	createSpecs := []githubPRReviewCommentSpec{}
	for _, c := range plan.Create {
		createSpecs = append(createSpecs, githubPRReviewCommentSpec{Path: c.Path, Line: c.Line, Body: c.Body})
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	job.Summary["pending_inline_creates"] = createSpecs
	job.Summary["pending_decision"] = true

	if len(createSpecs) > 0 {
		reviewBody := "OPA Review — inline findings updated."
		if err := publishPRReview(conn, owner, repo, job, reviewBody, "COMMENT", createSpecs); err != nil {
			posted := 0
			for _, spec := range createSpecs {
				if err := githubPRInlineComment(conn, owner, repo, job.PRNumber, job.CommitSHA, spec.Path, spec.Line, spec.Body); err != nil {
					out.Failed++
					continue
				}
				posted++
			}
			out.Created = posted
			out.Posted = posted + out.Updated
			if posted == 0 && out.Updated == 0 && out.Resolved == 0 {
				out.Mode = "annotations_only"
				out.Honesty = "inline PR comments unavailable (token/App permissions or line not in diff) — using Check Run annotations"
				return out
			}
			out.Mode = "comments"
		} else {
			out.Created = len(createSpecs)
			out.Posted = len(createSpecs) + out.Updated
			out.Mode = "sync"
			job.Summary["pending_inline_creates"] = []githubPRReviewCommentSpec{}
		}
	} else {
		out.Posted = out.Updated
		out.Mode = "sync"
	}

	parts := []string{}
	if !postResume {
		parts = append(parts, "résumé omitted (CLI agent unavailable)")
	} else if out.ResumeOK {
		parts = append(parts, "résumé upserted")
	}
	if out.Created > 0 {
		parts = append(parts, fmt.Sprintf("%d created", out.Created))
	}
	if out.Updated > 0 {
		parts = append(parts, fmt.Sprintf("%d updated", out.Updated))
	}
	if out.Resolved > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved/superseded", out.Resolved))
	}
	if out.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", out.Failed))
	}
	parts = append(parts, "decision deferred to approval")
	out.Honesty = strings.Join(parts, "; ")
	return out
}

func findingsToAnnotations(findings []map[string]interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, f := range findings {
		path, _ := f["file"].(string)
		if path == "" || path == "diff" || strings.HasPrefix(path, "(") {
			continue
		}
		line := 1
		switch v := f["line"].(type) {
		case float64:
			line = int(v)
		case int:
			line = v
		}
		if line < 1 {
			line = 1
		}
		sev, _ := f["severity"].(string)
		level := "warning"
		if sev == "critical" || sev == "high" {
			level = "failure"
		}
		msg, _ := f["message"].(string)
		out = append(out, map[string]interface{}{
			"path": path, "start_line": line, "end_line": line,
			"annotation_level": level, "message": msg,
		})
	}
	return out
}

func persistAIReview(job *scmJob, res aiReviewResult) {
	aiReviewLive.Store(res.ID, res)
	if writer == nil {
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	fj, _ := json.Marshal(res.Findings)
	payload, _ := json.Marshal(map[string]interface{}{
		"id": res.ID, "organization_id": job.OrganizationID, "project_id": job.ProjectID,
		"job_id": job.ID, "model": res.Model, "summary": res.Summary,
		"findings_json": string(fj), "cursor_usage": truncateStr(res.Usage, 1024),
		"status": res.Status, "created_at": now, "finished_at": now,
	})
	writer.insertAsync("ai_reviews", append(payload, '\n'))
}
