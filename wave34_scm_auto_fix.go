package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Auto-fix jobs apply OPA Review findings via the review agent, then commit
// on an opa-fix/* branch and optionally open a GitHub PR. Post-PR babysit was
// removed: iterations are orchestrator-driven re-authorized patch→verify→land.

type opaAutoFixJob struct {
	ID            string                   `json:"id"`
	ParentJobID   string                   `json:"parent_job_id"`
	Status        string                   `json:"status"` // queued|running|completed|failed|skipped
	CreatePR      bool                     `json:"create_pr"`
	CommitDirect  bool                     `json:"commit_direct,omitempty"`
	FindingKeys   []string                 `json:"finding_keys"`
	Findings      []map[string]interface{} `json:"findings,omitempty"`
	Branch        string                   `json:"branch,omitempty"`
	CommitSHA     string                   `json:"commit_sha,omitempty"`
	PRNumber      int                      `json:"pr_number,omitempty"`
	PRURL         string                   `json:"pr_url,omitempty"`
	Error         string                   `json:"error,omitempty"`
	Honesty       string                   `json:"honesty,omitempty"`
	StartedAt     string                   `json:"started_at,omitempty"`
	FinishedAt    string                   `json:"finished_at,omitempty"`
	RepoFullName  string                   `json:"repo_full_name,omitempty"`
	BasePRNumber  int                      `json:"base_pr_number,omitempty"`
}

var (
	autoFixLive   sync.Map
	autoFixSemOnce sync.Once
	autoFixSem    chan struct{}
)

func autoFixConcurrency() int {
	n := atoiDefault(envOr("OPA_AUTO_FIX_CONCURRENCY", "1"), 1)
	if n < 1 {
		n = 1
	}
	if n > 4 {
		n = 4
	}
	return n
}

func acquireAutoFixSlot() {
	autoFixSemOnce.Do(func() {
		autoFixSem = make(chan struct{}, autoFixConcurrency())
	})
	autoFixSem <- struct{}{}
}

func releaseAutoFixSlot() {
	<-autoFixSem
}

func getAutoFixJob(id string) *opaAutoFixJob {
	if v, ok := autoFixLive.Load(id); ok {
		if j, ok := v.(*opaAutoFixJob); ok {
			return j
		}
	}
	return nil
}

func persistAutoFixOnParent(parent *scmJob, fix *opaAutoFixJob) {
	if parent == nil || fix == nil {
		return
	}
	if parent.Summary == nil {
		parent.Summary = map[string]interface{}{}
	}
	list, _ := parent.Summary["auto_fixes"].([]interface{})
	// Replace existing entry with same id, else append.
	replaced := false
	for i, item := range list {
		if m, ok := item.(map[string]interface{}); ok {
			if strFromAny(m["id"]) == fix.ID {
				list[i] = autoFixToMap(fix)
				replaced = true
				break
			}
		}
	}
	if !replaced {
		list = append(list, autoFixToMap(fix))
	}
	// Cap history.
	if len(list) > 20 {
		list = list[len(list)-20:]
	}
	parent.Summary["auto_fixes"] = list
	parent.Summary["auto_fix_latest"] = autoFixToMap(fix)
	persistSCMJob(parent)
}

func autoFixToMap(fix *opaAutoFixJob) map[string]interface{} {
	b, _ := json.Marshal(fix)
	out := map[string]interface{}{}
	_ = json.Unmarshal(b, &out)
	return out
}

// scmJobFindings extracts OPA Review findings from a job summary and stamps finding keys.
func scmJobFindings(job *scmJob) []map[string]interface{} {
	if job == nil || job.Summary == nil {
		return nil
	}
	ai, _ := job.Summary["ai"].(map[string]interface{})
	if ai == nil {
		// aiReviewResult may be stored as typed value via json round-trip
		raw, ok := job.Summary["ai"]
		if !ok {
			return nil
		}
		b, _ := json.Marshal(raw)
		ai = map[string]interface{}{}
		_ = json.Unmarshal(b, &ai)
	}
	rawFindings, _ := ai["findings"].([]interface{})
	out := []map[string]interface{}{}
	for _, item := range rawFindings {
		f, ok := item.(map[string]interface{})
		if !ok {
			b, _ := json.Marshal(item)
			f = map[string]interface{}{}
			_ = json.Unmarshal(b, &f)
		}
		cp := map[string]interface{}{}
		for k, v := range f {
			cp[k] = v
		}
		key := opaReviewFindingKey(cp)
		cp["finding_key"] = key
		out = append(out, cp)
	}
	return out
}

func filterFindingsByKeys(findings []map[string]interface{}, keys []string) []map[string]interface{} {
	// Empty keys must refuse "fix everything" — never return the full set.
	if len(keys) == 0 {
		return nil
	}
	want := map[string]struct{}{}
	for _, k := range keys {
		k = strings.TrimSpace(strings.ToLower(k))
		if k != "" {
			want[k] = struct{}{}
		}
	}
	if len(want) == 0 {
		return nil
	}
	out := []map[string]interface{}{}
	for _, f := range findings {
		key := strFromAny(f["finding_key"])
		if key == "" {
			key = opaReviewFindingKey(f)
		}
		if _, ok := want[strings.ToLower(key)]; ok {
			out = append(out, f)
		}
	}
	return out
}

func scmJobAPIView(job *scmJob) map[string]interface{} {
	b, _ := json.Marshal(job)
	out := map[string]interface{}{}
	_ = json.Unmarshal(b, &out)
	findings := scmJobFindings(job)
	out["findings"] = findings
	out["finding_count"] = len(findings)
	if job != nil && job.Summary != nil {
		if sha := strFromAny(job.Summary["analyzed_sha"]); sha != "" {
			out["analyzed_sha"] = sha
		}
		if at := strFromAny(job.Summary["analyzed_at"]); at != "" {
			out["analyzed_at"] = at
		}
		if prev := strFromAny(job.Summary["previous_analyzed_sha"]); prev != "" {
			out["previous_analyzed_sha"] = prev
		}
		if fixes, ok := job.Summary["auto_fixes"]; ok {
			out["auto_fixes"] = fixes
		}
	}
	return out
}

// handleSCMJobAutoFix POST /api/scm/jobs/{id}/auto-fix
// body: { finding_keys?: [], create_pr?: bool, commit_direct?: bool }
func handleSCMJobAutoFix(w http.ResponseWriter, r *http.Request, source *scmJob) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if source == nil {
		http.Error(w, "not found", 404)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		FindingKeys  []string `json:"finding_keys"`
		CreatePR     *bool    `json:"create_pr"`
		CommitDirect bool     `json:"commit_direct"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	createPR := true
	if body.CreatePR != nil {
		createPR = *body.CreatePR
	}
	if body.CommitDirect {
		createPR = false
	}
	fix, err := enqueueOPAAutoFix(source, body.FindingKeys, createPR, body.CommitDirect && !createPR)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "auto_fix_id": fix.ID, "status": fix.Status,
		"create_pr": createPR, "finding_count": len(fix.Findings),
		"honesty": fix.Honesty,
	})
}

// enqueueOPAAutoFix starts a bounded auto-fix for selected findings on a completed review job.
func enqueueOPAAutoFix(parent *scmJob, findingKeys []string, createPR, commitDirect bool) (*opaAutoFixJob, error) {
	if parent == nil {
		return nil, fmt.Errorf("job not found")
	}
	if len(findingKeys) == 0 {
		return nil, fmt.Errorf("empty finding_keys — refusing to fix everything")
	}
	conn := getConnector(parent.ConnectorID)
	if conn == nil {
		conn = getOrHydrateConnector(parent.ConnectorID)
	}
	prefs, _ := resolveAgentPrefs(parent.OrganizationID, parent.ProjectID, parent.ConnectorID, parent.RepoFullName)
	ledger := ledgerFromParentJob(parent)
	if _, err := authorizeAutofixRequest(conn, prefs, parent.RepoFullName, ledger, findingKeys); err != nil {
		return nil, err
	}
	findings := filterFindingsByKeys(scmJobFindings(parent), findingKeys)
	if len(findings) == 0 {
		// Fall back to ledger-derived maps when parent summary lacks ai.findings shape.
		for _, f := range ledger {
			for _, k := range findingKeys {
				if strings.EqualFold(strings.TrimSpace(f.Key), strings.TrimSpace(k)) {
					findings = append(findings, map[string]interface{}{
						"finding_key": f.Key, "severity": f.Severity, "file": f.File,
						"line": f.Line, "message": f.Message, "problem": f.Message,
					})
					break
				}
			}
		}
	}
	if len(findings) == 0 {
		return nil, fmt.Errorf("no matching findings to fix")
	}
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		k := strFromAny(f["finding_key"])
		if k == "" {
			k = opaReviewFindingKey(f)
		}
		keys = append(keys, k)
	}
	// suggest mode never opens a land PR from this path.
	if prefs.AutofixMode == "suggest" {
		createPR = false
		commitDirect = false
	}
	fix := &opaAutoFixJob{
		ID:           "autofix-" + newRandomHex(10),
		ParentJobID:  parent.ID,
		Status:       "queued",
		CreatePR:     createPR,
		CommitDirect: commitDirect,
		FindingKeys:  keys,
		Findings:     findings,
		RepoFullName: parent.RepoFullName,
		BasePRNumber: parent.PRNumber,
		StartedAt:    time.Now().UTC().Format("2006-01-02 15:04:05.000"),
		Honesty:      "queued — Auto-fix patch → gateCloudDiff → land (no babysit)",
	}
	autoFixLive.Store(fix.ID, fix)
	persistAutoFixOnParent(parent, fix)
	go processOPAAutoFix(fix.ID, parent.ID)
	return fix, nil
}

func ledgerFromParentJob(parent *scmJob) []agentFinding {
	if parent == nil {
		return nil
	}
	if parent.Summary != nil {
		if raw, err := json.Marshal(parent.Summary["ledger"]); err == nil {
			var led []agentFinding
			if json.Unmarshal(raw, &led) == nil && len(led) > 0 {
				return led
			}
		}
	}
	runID := parent.RunID
	if runID == "" && agentKind(parent.Kind) == kindRun {
		runID = parent.ID
	}
	if runID != "" {
		return ledgerForCloudJob(&scmJob{RunID: runID, OrganizationID: parent.OrganizationID, ID: parent.ID})
	}
	var bugbot aiReviewResult
	if parent.Summary != nil {
		if raw, err := json.Marshal(parent.Summary["ai"]); err == nil {
			_ = json.Unmarshal(raw, &bugbot)
		}
	}
	return buildLedger(bugbot, nil)
}

func processOPAAutoFix(fixID, parentID string) {
	acquireAutoFixSlot()
	defer releaseAutoFixSlot()

	fix := getAutoFixJob(fixID)
	parent := getSCMJob(parentID)
	if fix == nil || parent == nil {
		return
	}
	fix.Status = "running"
	fix.Honesty = "running Auto-fix"
	persistAutoFixOnParent(parent, fix)

	conn := getConnector(parent.ConnectorID)
	result, err := runOPAAutoFix(parent, conn, fix)
	if result != nil {
		*fix = *result
	}
	if err != nil && fix.Error == "" {
		fix.Error = err.Error()
		if fix.Status == "running" || fix.Status == "queued" {
			fix.Status = "failed"
		}
	}
	fix.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	autoFixLive.Store(fix.ID, fix)
	persistAutoFixOnParent(parent, fix)
}

func runOPAAutoFix(parent *scmJob, conn *opaConnector, fix *opaAutoFixJob) (*opaAutoFixJob, error) {
	if fix == nil || parent == nil {
		return fix, fmt.Errorf("missing job")
	}
	owner, repo := splitOwnerRepo(parent.RepoFullName)
	if owner == "" || repo == "" {
		fix.Status = "failed"
		return fix, fmt.Errorf("invalid repo")
	}

	wtID := "autofix-" + fix.ID
	baseSHA := parent.CommitSHA
	if parent.Summary != nil {
		if a := strFromAny(parent.Summary["analyzed_sha"]); a != "" {
			baseSHA = a
		}
	}
	absRoot, _, wtMeta, err := prepareSCMWorktree(conn, parent.RepoFullName, baseSHA, parent.PRNumber, wtID)
	defer removeSCMJobCheckout(wtID, parent.RepoFullName)
	if err != nil && !githubUseMockAPI(conn) {
		fix.Status = "failed"
		fix.Error = "checkout: " + err.Error()
		return fix, err
	}
	if absRoot == "" {
		absRoot = scmPrimaryCheckoutAbs(wtID)
		_ = writeMockWorktreeFixture(absRoot)
	}
	_ = wtMeta

	baseBranch := "main"
	headBranch := ""
	if pull, perr := githubGetPull(conn, owner, repo, parent.PRNumber); perr == nil && pull != nil {
		if pull.BaseRef != "" {
			baseBranch = pull.BaseRef
		}
		headBranch = pull.HeadRef
		if pull.HeadSHA != "" && (parent.CommitSHA == "" || strings.HasPrefix(parent.CommitSHA, "manual-")) {
			parent.CommitSHA = pull.HeadSHA
		}
	}
	if headBranch == "" {
		headBranch = baseBranch
	}

	short := parent.ID
	if parent.RunID != "" {
		short = parent.RunID
	}
	attempt := 1
	if parent.Summary != nil {
		if n := intFromAny(parent.Summary["autofix_attempt"]); n > 0 {
			attempt = n
		}
	}
	branch := opaFixBranchName(short, attempt)
	fix.Branch = branch

	if err := gitCheckoutNewBranch(absRoot, branch); err != nil {
		fix.Status = "failed"
		fix.Error = "branch: " + err.Error()
		return fix, err
	}

	skippedAI := envOr("SKIP_CURSOR_AI", "0") == "1" || resolveCursorAPIKey(parent.OrganizationID, parent.ProjectID, parent.ActorUserID) == ""
	if skippedAI || githubUseMockAPI(conn) {
		// Mock / skipped: write a small honesty note file so there is something to commit.
		note := filepath.Join(absRoot, ".opa-review-autofix.md")
		var b strings.Builder
		b.WriteString("# OPA Review Auto-fix (smoke)\n\n")
		b.WriteString("AI agent skipped or mock GitHub — no code patch applied.\n\n")
		for _, f := range fix.Findings {
			fmt.Fprintf(&b, "- `%s` %s\n", strFromAny(f["finding_key"]), truncateStr(strFromAny(f["message"])+strFromAny(f["problem"]), 120))
		}
		_ = os.WriteFile(note, []byte(b.String()), 0o644)
		fix.Honesty = "AI skipped or mock — recorded finding list only; create_pr still exercised when credentials allow"
		if skippedAI {
			fix.Status = "skipped"
		}
	} else {
		if err := runAutoFixAgent(parent, absRoot, fix); err != nil {
			fix.Status = "failed"
			fix.Error = "agent: " + err.Error()
			fix.Honesty = "Auto-fix agent failed"
			return fix, err
		}
		fix.Honesty = "Auto-fix agent completed"
	}

	diff, derr := gitUnifiedDiff(absRoot)
	if derr != nil {
		fix.Status = "failed"
		fix.Error = "diff: " + derr.Error()
		return fix, derr
	}
	allow := []string{}
	if !skippedAI && !githubUseMockAPI(conn) {
		for _, f := range fix.Findings {
			if p := strFromAny(f["file"]); p != "" {
				allow = append(allow, p)
			}
		}
	}
	if err := gateCloudDiff(parseCloudDiffChanges(diff), allow, defaultCloudDiffCaps()); err != nil {
		fix.Status = "failed"
		fix.Error = err.Error()
		fix.Honesty = "gateCloudDiff denied"
		return fix, err
	}

	validatedPatch, perr := captureValidatedPatch(absRoot)
	if perr != nil {
		fix.Status = "failed"
		fix.Error = "capture patch: " + perr.Error()
		return fix, perr
	}
	if strings.TrimSpace(validatedPatch) == "" {
		fix.Honesty += "; no file changes after patch"
		if fix.Status != "skipped" {
			fix.Status = "completed"
		}
		return fix, nil
	}

	// Land on a separate clean tree — never commit/push from the agent sandbox.
	landWtID := wtID + "-land"
	defer removeSCMJobCheckout(landWtID, parent.RepoFullName)
	landRoot, _, _, lerr := prepareSCMWorktree(conn, parent.RepoFullName, baseSHA, parent.PRNumber, landWtID)
	if lerr != nil && !githubUseMockAPI(conn) {
		fix.Status = "failed"
		fix.Error = "land checkout: " + lerr.Error()
		return fix, lerr
	}
	if landRoot == "" {
		landRoot = scmPrimaryCheckoutAbs(landWtID)
		_ = writeMockWorktreeFixture(landRoot)
	}
	if err := gitCheckoutNewBranch(landRoot, branch); err != nil {
		fix.Status = "failed"
		fix.Error = "land branch: " + err.Error()
		return fix, err
	}
	if err := applyValidatedPatch(landRoot, validatedPatch); err != nil {
		fix.Status = "failed"
		fix.Error = "apply validated patch: " + err.Error()
		fix.Honesty = "clean-tree land apply failed"
		return fix, err
	}

	sha, cerr := gitCommitAll(landRoot, fmt.Sprintf("OPA Review fix: %d finding(s) from job %s", len(fix.Findings), parent.ID))
	if cerr != nil {
		if !hasGitChanges(landRoot) && gitRevParse(landRoot) != "" {
			fix.CommitSHA = gitRevParse(landRoot)
			fix.Honesty += "; no file changes to commit on clean tree"
			if fix.Status != "skipped" {
				fix.Status = "completed"
			}
			return fix, nil
		}
		fix.Status = "failed"
		fix.Error = "commit: " + cerr.Error()
		return fix, cerr
	}
	fix.CommitSHA = sha
	fix.Honesty += "; landed on clean tree"

	if githubUseMockAPI(conn) {
		fix.PRURL = fmt.Sprintf("https://github.com/%s/pull/mock-autofix", parent.RepoFullName)
		fix.PRNumber = 0
		fix.Status = nz(fix.Status, "completed")
		if fix.Status == "running" {
			fix.Status = "completed"
		}
		fix.Honesty += "; mock PR URL"
		return fix, nil
	}

	if err := gitPushBranch(conn, landRoot, branch); err != nil {
		fix.Status = "failed"
		fix.Error = "push: " + err.Error()
		return fix, err
	}

	if fix.CreatePR || !fix.CommitDirect {
		title := fmt.Sprintf("OPA Review fix: %d finding(s)", len(fix.Findings))
		if len(fix.Findings) == 1 {
			msg := firstNonEmpty(strFromAny(fix.Findings[0]["problem"]), strFromAny(fix.Findings[0]["message"]))
			if msg != "" {
				title = "OPA Review fix: " + truncateStr(msg, 72)
			}
		}
		body := buildAutoFixPRBody(parent, fix)
		// Open PR into the original PR head branch when possible so it lands on the same branch tip;
		// fall back to repo default/base.
		prBase := headBranch
		if prBase == "" || prBase == branch {
			prBase = baseBranch
		}
		prNum, prURL, perr := githubCreatePullRequest(conn, owner, repo, title, body, branch, prBase, false)
		if perr != nil {
			// Retry against base branch.
			prNum, prURL, perr = githubCreatePullRequest(conn, owner, repo, title, body, branch, baseBranch, false)
		}
		if perr != nil {
			fix.Status = "failed"
			fix.Error = "create PR: " + perr.Error()
			fix.Honesty += "; branch pushed but PR create failed"
			return fix, perr
		}
		fix.PRNumber = prNum
		fix.PRURL = prURL

		// Close addressed finding threads on the original PR immediately.
		if parent.PRNumber > 0 && conn != nil && !githubUseMockAPI(conn) {
			sha := fix.CommitSHA
			if sha == "" {
				sha = parent.CommitSHA
			}
			n := closeOPAReviewFindingsByKeys(conn, owner, repo, parent.PRNumber, sha, fix.FindingKeys)
			if n > 0 {
				fix.Honesty += fmt.Sprintf("; closed %d finding comment(s) on PR #%d", n, parent.PRNumber)
			}
		}

		// Follow-up OPA Review (force): refresh auto_merge_confidence, sync/close
		// remaining comments, and APPROVE when the tree is clean. No babysit agent.
		if !skippedAI {
			followIDs := enqueueAutoFixFollowUpReviews(parent, fix)
			if len(followIDs) > 0 {
				fix.Honesty += "; follow-up OPA Review queued: " + strings.Join(followIDs, ", ")
			}
		}
	}

	if fix.Status == "running" || fix.Status == "queued" {
		fix.Status = "completed"
	}
	return fix, nil
}

func buildAutoFixPRBody(parent *scmJob, fix *opaAutoFixJob) string {
	var b strings.Builder
	b.WriteString("## OPA Review Auto-fix\n\n")
	fmt.Fprintf(&b, "Automated fix for findings from SCM job `%s`", parent.ID)
	if parent.PRNumber > 0 {
		fmt.Fprintf(&b, " (original PR #%d)", parent.PRNumber)
	}
	b.WriteString(".\n\n### Findings addressed\n")
	for _, f := range fix.Findings {
		sev := strFromAny(f["severity"])
		path := strFromAny(f["file"])
		line := f["line"]
		msg := firstNonEmpty(strFromAny(f["problem"]), strFromAny(f["message"]))
		fmt.Fprintf(&b, "- %s **%s** `%s`", severityEmoji(sev), sev, path)
		if line != nil {
			fmt.Fprintf(&b, ":%v", line)
		}
		fmt.Fprintf(&b, " — %s\n", truncateStr(msg, 160))
	}
	b.WriteString("\n_Minimal patches only — no drive-by refactors._\n")
	b.WriteString("\nDiff was gated by `gateCloudDiff` and applied to a **clean tree** before land. ")
	b.WriteString("Follow-up OPA Review refreshes **auto_merge_confidence** and **APPROVE**s when clean (no babysit agent).\n")
	return b.String()
}

func runAutoFixAgent(parent *scmJob, checkoutRoot string, fix *opaAutoFixJob) error {
	key, agentBin, model, force := resolveCLICursorConfig(parent.OrganizationID, parent.ProjectID, parent.ActorUserID)
	if key == "" {
		return fmt.Errorf("CLI agent API key not set — save one under Account (personal or org)")
	}
	brief := packAutoFixBrief(parent, checkoutRoot, fix)
	promptPath := filepath.Join(os.TempDir(), fmt.Sprintf("opa-autofix-%s.md", fix.ID))
	_ = os.WriteFile(promptPath, []byte(brief), 0o600)
	defer os.Remove(promptPath)

	prompt := fmt.Sprintf(
		`You are applying OPA Auto-fix patches (cloud.patch). Working directory: %s. Read the brief at %s. Apply ONLY the minimal code changes needed to address the listed findings. Do not refactor unrelated code. Do not push, open PRs, run git remote, or babysit CI — only edit files on disk. The orchestrator will gate the diff and land. When done, summarize what you changed in one short paragraph.`,
		checkoutRoot, promptPath,
	)
	args := []string{"-p", "--trust", "--output-format", "text", "--model", model}
	if force {
		args = append(args, "--force")
	}
	args = append(args, prompt)
	_ = agentBin
	jobID := ""
	if parent != nil {
		jobID = nz(parent.RunID, parent.ID)
	}
	out, err := launchAgentSandbox(agentLaunchSpec{
		Phase: jobPhaseAutofix, Args: args, Dir: checkoutRoot, WorktreeRoot: checkoutRoot,
		APIKey: key, Parent: scmJobContext(jobID), Timeout: 1200 * time.Second, JobID: jobID,
	})
	if err != nil {
		return fmt.Errorf("%v (%s)", err, truncateStr(string(out), 300))
	}
	return nil
}

func packAutoFixBrief(parent *scmJob, checkoutRoot string, fix *opaAutoFixJob) string {
	var b strings.Builder
	b.WriteString("# OPA Review Auto-fix brief\n\n")
	b.WriteString("Apply **minimal** patches for the findings below. No drive-by refactors. Keep public APIs stable unless a finding requires a change.\n\n")
	b.WriteString("This is cloud.patch only (edit files). Do not push or open PRs — the orchestrator lands after gateCloudDiff.\n\n")
	fmt.Fprintf(&b, "## Repo\n- `%s` PR #%d sha `%s`\n- checkout: `%s`\n\n", parent.RepoFullName, parent.PRNumber, parent.CommitSHA, checkoutRoot)
	b.WriteString("## Findings to fix\n")
	for i, f := range fix.Findings {
		jb, _ := json.MarshalIndent(f, "", "  ")
		fmt.Fprintf(&b, "### %d. key `%s`\n```json\n%s\n```\n\n", i+1, strFromAny(f["finding_key"]), string(jb))
	}
	return b.String()
}

// enqueueAutoFixFollowUpReviews queues force AI-only re-reviews so multi-pass
// Auto-fix closes remaining comments, updates auto_merge_confidence, and APPROVEs
// when the PR is clean. Prefer the original PR; also cover the fix PR when distinct.
func enqueueAutoFixFollowUpReviews(parent *scmJob, fix *opaAutoFixJob) []string {
	if parent == nil || fix == nil {
		return nil
	}
	actor := strings.TrimSpace(parent.ActorUserID)
	targets := []int{}
	seen := map[int]struct{}{}
	add := func(pr int) {
		if pr <= 0 {
			return
		}
		if _, ok := seen[pr]; ok {
			return
		}
		seen[pr] = struct{}{}
		targets = append(targets, pr)
	}
	add(parent.PRNumber)
	add(fix.BasePRNumber)
	add(fix.PRNumber)

	var ids []string
	for _, pr := range targets {
		job, errMsg, _ := enqueueManualAIReview(
			parent.RepoFullName, pr, parent.ConnectorID, "", "", false,
			true, /* force — bypass already-reviewed SHA so confidence/approve can update */
			true, /* ai_only */
			true, /* allow_unwatched */
			actor,
		)
		if errMsg != "" || job == nil {
			continue
		}
		if job.Summary == nil {
			job.Summary = map[string]interface{}{}
		}
		job.Summary["autofix_follow_up"] = true
		job.Summary["autofix_id"] = fix.ID
		job.Summary["autofix_parent_job_id"] = parent.ID
		persistSCMJob(job)
		go processSCMJob(job.ID)
		ids = append(ids, job.ID)
	}
	return ids
}

func gitCheckoutNewBranch(root, branch string) error {
	cmd := exec.Command("git", "-C", root, "checkout", "-B", branch)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v (%s)", err, truncateStr(string(out), 160))
	}
	return nil
}

func hasGitChanges(root string) bool {
	cmd := exec.Command("git", "-C", root, "status", "--porcelain")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

func gitCommitAll(root, message string) (string, error) {
	_ = exec.Command("git", "-C", root, "config", "user.email", "opa-review@localhost").Run()
	_ = exec.Command("git", "-C", root, "config", "user.name", "OPA Review").Run()
	if out, err := exec.Command("git", "-C", root, "add", "-A").CombinedOutput(); err != nil {
		return "", fmt.Errorf("git add: %v (%s)", err, truncateStr(string(out), 120))
	}
	if !hasGitChanges(root) {
		return "", fmt.Errorf("no changes to commit")
	}
	if out, err := exec.Command("git", "-C", root, "commit", "-m", message).CombinedOutput(); err != nil {
		return "", fmt.Errorf("git commit: %v (%s)", err, truncateStr(string(out), 160))
	}
	return gitRevParse(root), nil
}

func gitPushBranch(conn *opaConnector, root, branch string) error {
	if err := authorizeGitPush(conn); err != nil {
		return err
	}
	tok, err := githubAccessToken(conn)
	if err != nil {
		return err
	}
	askEnv, cleanup, aerr := gitAskPassEnv(tok)
	if aerr != nil {
		return aerr
	}
	defer cleanup()
	cmd := exec.Command("git", "-C", root, "push", "-u", "origin", "HEAD:refs/heads/"+branch, "--force-with-lease")
	cmd.Env = askEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v (%s)", err, truncateStr(string(out), 200))
	}
	return nil
}
