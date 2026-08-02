package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// runCloudAgent is the kind=cloud child: bounded patch → gateCloudDiff →
// verify? → land-on-clean-tree (or suggest). GitHub write stays in-process; the
// patch agent never receives a push token. Land never trusts the sandbox WD.
func runCloudAgent(job *scmJob) error {
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	parent := getSCMJob(job.RunID)
	prefs := agentPrefsFromSummary(parent)
	if !prefs.CloudEnabled || prefs.AutofixMode == "" || prefs.AutofixMode == "off" {
		job.Status = "skipped"
		job.Summary["skip_reason"] = "cloud_enabled/autofix_mode off"
		persistSCMJob(job)
		return nil
	}

	wr, conn := findWatched(job.RepoFullName)
	_ = wr
	if conn == nil {
		conn = getOrHydrateConnector(job.ConnectorID)
	}
	ledger := ledgerForCloudJob(job)
	keys, rationale := cloudFindingKeys(job, ledger, prefs)
	if len(keys) == 0 {
		job.Status = "skipped"
		job.Summary["skip_reason"] = "no findings meeting autofix threshold"
		job.Summary["cloud"] = map[string]interface{}{"status": "skipped", "honesty": "no eligible findings"}
		persistSCMJob(job)
		return nil
	}
	if rationale != "" {
		job.Summary["cloud_rationale"] = rationale
	}

	owner, repoName := splitOwnerRepo(job.RepoFullName)
	jobDashURL := scmJobDashboardURL(nz(job.RunID, job.ID))
	checkID, _ := githubCreateCheckRun(conn, owner, repoName, "OPA Auto-fix", job.CommitSHA, "in_progress", "",
		"Cloud autofix…", checkRunSummaryWithJobLink("patch → gate → clean land", nz(job.RunID, job.ID)), jobDashURL, nil)
	if job.CheckRunIDs == nil {
		job.CheckRunIDs = map[string]int64{}
	}
	job.CheckRunIDs["autofix"] = checkID
	persistSCMJob(job)

	result, runErr := runCloudStages(job, conn, keys)
	job.Summary["cloud"] = result
	conclusion := "success"
	title := "OPA Auto-fix completed"
	if runErr != nil {
		conclusion = "failure"
		title = "OPA Auto-fix failed"
		job.Error = runErr.Error()
	} else if strFromAny(result["status"]) == "skipped" || strFromAny(result["status"]) == "suggest" || strFromAny(result["status"]) == "refused" {
		conclusion = "neutral"
		title = "OPA Auto-fix " + strFromAny(result["status"])
	}
	if checkID != 0 {
		_ = githubUpdateCheckRun(conn, owner, repoName, checkID, "completed", conclusion, title,
			checkRunSummaryWithJobLink(nz(strFromAny(result["honesty"]), title), nz(job.RunID, job.ID)), jobDashURL, nil)
	}
	persistSCMJob(job)
	return runErr
}

func cloudMaxIterations() int {
	n := atoiDefault(envOr("OPA_CLOUD_MAX_ITERATIONS", "3"), 3)
	if n < 1 {
		n = 1
	}
	if n > 3 {
		n = 3
	}
	return n
}

func cloudBaseSHA(job *scmJob) string {
	baseSHA := job.CommitSHA
	if parent := getSCMJob(job.RunID); parent != nil && parent.Summary != nil {
		if a := strFromAny(parent.Summary["analyzed_sha"]); a != "" {
			baseSHA = a
		}
	}
	if prep := childByKind(job.RunID, kindPrepare); prep != nil && prep.Summary != nil {
		if a := strFromAny(prep.Summary["analyzed_sha"]); a != "" {
			baseSHA = a
		}
	}
	return baseSHA
}

// runCloudStages runs up to cloudMaxIterations of patch→gate→verify?→land.
// Stops on success, gate denial, or auth failure. Verify failure may retry.
func runCloudStages(job *scmJob, conn *opaConnector, keys []string) (map[string]interface{}, error) {
	prefs := agentPrefsFromSummary(getSCMJob(job.RunID))
	ledger := ledgerForCloudJob(job)
	max := cloudMaxIterations()
	out := map[string]interface{}{"status": "running", "max_iterations": max}
	var attempts []map[string]interface{}
	var lastErr error

	for i := 1; i <= max; i++ {
		auth, err := authorizeAutofixRequestAttempt(conn, prefs, job.RepoFullName, ledger, keys, i == 1)
		if err != nil {
			out["status"] = "refused"
			out["honesty"] = err.Error()
			out["attempts"] = attempts
			out["iterations"] = i
			job.Summary["cloud_auth"] = err.Error()
			return out, nil
		}
		job.Summary["cloud_auth"] = auth.Honesty
		out["mode"] = auth.Mode

		attemptOut, aerr := runOneCloudAttempt(job, conn, auth, prefs, i)
		attemptOut["iteration"] = i
		attempts = append(attempts, attemptOut)
		status := strFromAny(attemptOut["status"])

		if aerr == nil && (status == "completed" || status == "suggest") {
			for k, v := range attemptOut {
				out[k] = v
			}
			out["attempts"] = attempts
			out["iterations"] = i
			return out, nil
		}

		lastErr = aerr
		// Gate / auth-style hard stops — do not keep generating denied diffs.
		if status == "gate_denied" || strings.Contains(strFromAny(attemptOut["honesty"]), "gateCloudDiff") {
			for k, v := range attemptOut {
				out[k] = v
			}
			out["attempts"] = attempts
			out["iterations"] = i
			out["honesty"] = nz(strFromAny(attemptOut["honesty"]), "gate denied")
			return out, aerr
		}
		// Verify failed — retry with a fresh patch if iterations remain.
		if status == "verify_failed" && i < max {
			continue
		}
		if aerr != nil && i < max && status != "gate_denied" {
			continue
		}
		for k, v := range attemptOut {
			out[k] = v
		}
		out["attempts"] = attempts
		out["iterations"] = i
		return out, aerr
	}

	out["status"] = "failed"
	out["honesty"] = fmt.Sprintf("exhausted %d cloud iterations", max)
	out["attempts"] = attempts
	out["iterations"] = max
	if lastErr == nil {
		lastErr = fmt.Errorf("%s", out["honesty"])
	}
	return out, lastErr
}

func runOneCloudAttempt(job *scmJob, conn *opaConnector, auth autofixAuthOK, prefs agentPrefs, iteration int) (map[string]interface{}, error) {
	out := map[string]interface{}{"status": "running", "mode": auth.Mode}
	findings := findingsMapsFromAgent(auth.Findings)
	allowlist := findingPaths(auth.Findings)
	baseSHA := cloudBaseSHA(job)

	patchWtID := fmt.Sprintf("cloud-patch-%s-%d", job.ID, iteration)
	landWtID := fmt.Sprintf("cloud-land-%s-%d", job.ID, iteration)
	defer removeSCMJobCheckout(patchWtID, job.RepoFullName)
	defer removeSCMJobCheckout(landWtID, job.RepoFullName)

	absRoot, _, _, err := prepareSCMWorktree(conn, job.RepoFullName, baseSHA, job.PRNumber, patchWtID)
	if err != nil && !githubUseMockAPI(conn) {
		out["status"] = "failed"
		out["honesty"] = "checkout: " + err.Error()
		return out, err
	}
	if absRoot == "" {
		absRoot = scmPrimaryCheckoutAbs(patchWtID)
		_ = writeMockWorktreeFixture(absRoot)
	}

	branchAttempt := job.Attempt
	if branchAttempt < 1 {
		branchAttempt = 1
	}
	// Deterministic per run + iteration: opa-fix/<run_id>-N where N folds attempt*10+iter
	branchN := branchAttempt
	if iteration > 1 {
		branchN = branchAttempt*10 + iteration
	}
	branch := opaFixBranchName(nz(job.RunID, job.ID), branchN)
	out["branch"] = branch
	if err := gitCheckoutNewBranch(absRoot, branch); err != nil {
		out["status"] = "failed"
		out["honesty"] = "branch: " + err.Error()
		return out, err
	}

	// --- cloud.patch (sandbox / agent-writable tree only) ---
	skippedAI := envOr("SKIP_CURSOR_AI", "0") == "1" || resolveCursorAPIKey(job.OrganizationID, job.ProjectID, job.ActorUserID) == ""
	if skippedAI || githubUseMockAPI(conn) {
		note := filepath.Join(absRoot, ".opa-review-autofix.md")
		var b strings.Builder
		b.WriteString("# OPA Auto-fix (smoke)\n\n")
		for _, f := range auth.Findings {
			fmt.Fprintf(&b, "- `%s` %s\n", f.Key, truncateStr(f.Message, 120))
		}
		_ = os.WriteFile(note, []byte(b.String()), 0o644)
		out["patch"] = "mock_or_skipped"
		if skippedAI {
			out["honesty"] = "AI skipped — recorded finding list only"
		}
	} else {
		fixStub := &opaAutoFixJob{ID: fmt.Sprintf("%s-%d", job.ID, iteration), FindingKeys: keysFromFindings(auth.Findings), Findings: findings}
		if err := runAutoFixAgent(job, absRoot, fixStub); err != nil {
			out["status"] = "failed"
			out["honesty"] = "cloud.patch: " + err.Error()
			return out, err
		}
		out["patch"] = "ok"
	}

	diff, derr := gitUnifiedDiff(absRoot)
	if derr != nil {
		out["status"] = "failed"
		out["honesty"] = "diff: " + derr.Error()
		return out, derr
	}
	changes := parseCloudDiffChanges(diff)
	gateAllow := allowlist
	if skippedAI || githubUseMockAPI(conn) {
		gateAllow = nil
	}
	if err := gateCloudDiff(changes, gateAllow, defaultCloudDiffCaps()); err != nil {
		out["status"] = "gate_denied"
		out["honesty"] = err.Error()
		out["gate"] = "denied"
		return out, err
	}
	out["gate"] = "ok"
	out["diff_files"] = len(changes)

	validatedPatch, perr := captureValidatedPatch(absRoot)
	if perr != nil {
		out["status"] = "failed"
		out["honesty"] = "capture patch: " + perr.Error()
		return out, perr
	}
	if strings.TrimSpace(validatedPatch) == "" {
		out["status"] = "completed"
		out["honesty"] = "no file changes after patch"
		return out, nil
	}
	out["patch_bytes"] = len(validatedPatch)

	// suggest mode: post proposal, do not land.
	if auth.Mode == "suggest" {
		body := formatCloudSuggestComment(job, auth, changes, branch)
		owner, repoName := splitOwnerRepo(job.RepoFullName)
		if job.PRNumber > 0 && conn != nil {
			_, _ = githubPRCommentCreate(conn, owner, repoName, job.PRNumber, body)
		}
		out["status"] = "suggest"
		out["honesty"] = "suggest mode — proposal posted, no land"
		return out, nil
	}

	// --- cloud.verify (optional) runs against the patch tree before land ---
	if prefs.CloudRunTests {
		if sandboxMode() != "docker" {
			out["status"] = "failed"
			out["honesty"] = "cloud.verify SANDBOX_REQUIRED — OPA_JOB_SANDBOX=docker"
			out["verify"] = "refused"
			return out, fmt.Errorf("cloud.verify refused: SANDBOX_REQUIRED")
		}
		vRes, verr := runCloudVerify(job, absRoot)
		out["verify"] = vRes
		if verr != nil {
			out["status"] = "verify_failed"
			out["honesty"] = "cloud.verify: " + verr.Error()
			return out, verr
		}
		// Re-capture + re-gate after verify (tests may rewrite files).
		diff2, _ := gitUnifiedDiff(absRoot)
		if err := gateCloudDiff(parseCloudDiffChanges(diff2), allowlist, defaultCloudDiffCaps()); err != nil {
			out["status"] = "gate_denied"
			out["honesty"] = "re-gate after verify: " + err.Error()
			return out, err
		}
		validatedPatch, perr = captureValidatedPatch(absRoot)
		if perr != nil {
			out["status"] = "failed"
			out["honesty"] = "re-capture patch: " + perr.Error()
			return out, perr
		}
	}

	// --- cloud.land on a SEPARATE clean tree — never commit from sandbox WD ---
	landResult, landErr := landValidatedPatch(job, conn, landWtID, baseSHA, branch, validatedPatch, auth)
	for k, v := range landResult {
		out[k] = v
	}
	return out, landErr
}

// landValidatedPatch checks out a fresh tree, applies the gated patch, commits
// and pushes. The agent-writable sandbox is not used for land.
func landValidatedPatch(job *scmJob, conn *opaConnector, landWtID, baseSHA, branch, patch string, auth autofixAuthOK) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	if err := authorizeGitPush(conn); err != nil {
		out["status"] = "failed"
		out["honesty"] = err.Error()
		return out, err
	}

	landRoot, _, _, err := prepareSCMWorktree(conn, job.RepoFullName, baseSHA, job.PRNumber, landWtID)
	if err != nil && !githubUseMockAPI(conn) {
		out["status"] = "failed"
		out["honesty"] = "land checkout: " + err.Error()
		return out, err
	}
	if landRoot == "" {
		landRoot = scmPrimaryCheckoutAbs(landWtID)
		_ = writeMockWorktreeFixture(landRoot)
	}
	if err := gitCheckoutNewBranch(landRoot, branch); err != nil {
		out["status"] = "failed"
		out["honesty"] = "land branch: " + err.Error()
		return out, err
	}
	if err := applyValidatedPatch(landRoot, patch); err != nil {
		out["status"] = "failed"
		out["honesty"] = "apply validated patch: " + err.Error()
		out["land"] = "apply_failed"
		return out, err
	}
	out["land"] = "clean_tree"

	sha, cerr := gitCommitAll(landRoot, fmt.Sprintf("OPA Auto-fix: %d finding(s) from run %s", len(auth.Findings), nz(job.RunID, job.ID)))
	if cerr != nil {
		if !hasGitChanges(landRoot) {
			out["status"] = "completed"
			out["honesty"] = "no file changes to commit on clean tree"
			return out, nil
		}
		out["status"] = "failed"
		out["honesty"] = "commit: " + cerr.Error()
		return out, cerr
	}
	out["commit_sha"] = sha

	if githubUseMockAPI(conn) {
		out["status"] = "completed"
		out["pr_url"] = fmt.Sprintf("https://github.com/%s/pull/mock-autofix", job.RepoFullName)
		out["honesty"] = "mock land on clean tree"
		return out, nil
	}

	if err := gitPushBranch(conn, landRoot, branch); err != nil {
		out["status"] = "failed"
		out["honesty"] = "push: " + err.Error()
		return out, err
	}

	owner, repoName := splitOwnerRepo(job.RepoFullName)
	baseBranch, headBranch := "main", ""
	if pull, perr := githubGetPull(conn, owner, repoName, job.PRNumber); perr == nil && pull != nil {
		if pull.BaseRef != "" {
			baseBranch = pull.BaseRef
		}
		headBranch = pull.HeadRef
	}
	prBase := headBranch
	if prBase == "" || prBase == branch {
		prBase = baseBranch
	}
	title := fmt.Sprintf("OPA Auto-fix: %d finding(s)", len(auth.Findings))
	if len(auth.Findings) == 1 {
		title = "OPA Auto-fix: " + truncateStr(auth.Findings[0].Message, 72)
	}
	body := formatCloudLandPRBody(job, auth, branch)
	prNum, prURL, perr := githubCreatePullRequest(conn, owner, repoName, title, body, branch, prBase, false)
	if perr != nil {
		prNum, prURL, perr = githubCreatePullRequest(conn, owner, repoName, title, body, branch, baseBranch, false)
	}
	if perr != nil {
		out["status"] = "failed"
		out["honesty"] = "create PR: " + perr.Error()
		return out, perr
	}
	out["pr_number"] = prNum
	out["pr_url"] = prURL
	out["status"] = "completed"
	out["honesty"] = "landed " + branch + " from clean tree"

	if job.PRNumber > 0 {
		n := closeOPAReviewFindingsByKeys(conn, owner, repoName, job.PRNumber, sha, keysFromFindings(auth.Findings))
		if n > 0 {
			out["honesty"] = fmt.Sprintf("%s; closed %d finding comment(s)", out["honesty"], n)
		}
	}
	return out, nil
}

func runCloudVerify(job *scmJob, workRoot string) (map[string]interface{}, error) {
	rawPlan, err := deriveCheckupPlan(workRoot)
	if err != nil {
		rawPlan = &checkupPlan{Version: 1, Source: "error", Image: defaultCheckupImage()}
	}
	policed := intersectSpecWithPolicy(rawPlan)
	ctx := scmJobContext(job.ID)
	result, _ := runCheckupPlan(ctx, nz(job.RunID, job.ID)+"-cloud-verify", workRoot, policed.Plan)
	m := map[string]interface{}{
		"status": result.Status, "honesty": result.Honesty, "drops": policed.Drops,
	}
	if result.Status == "failed" || result.Status == "refused" {
		return m, fmt.Errorf("%s", nz(result.Honesty, result.Status))
	}
	return m, nil
}

var opaFixBranchSafe = regexp.MustCompile(`[^a-zA-Z0-9._/-]+`)

// opaFixBranchName is deterministic: opa-fix/<run_id>-N (no random suffix).
func opaFixBranchName(runID string, attempt int) string {
	id := strings.TrimSpace(runID)
	id = strings.ReplaceAll(id, " ", "-")
	id = opaFixBranchSafe.ReplaceAllString(id, "-")
	if len(id) > 40 {
		id = id[:40]
	}
	if id == "" {
		id = "run"
	}
	if attempt < 1 {
		attempt = 1
	}
	return fmt.Sprintf("opa-fix/%s-%d", id, attempt)
}

func ledgerForCloudJob(job *scmJob) []agentFinding {
	if job == nil {
		return nil
	}
	if apr := childByKind(job.RunID, kindApproval); apr != nil && apr.Summary != nil {
		if raw, err := json.Marshal(apr.Summary["ledger"]); err == nil {
			var led []agentFinding
			if json.Unmarshal(raw, &led) == nil && len(led) > 0 {
				return led
			}
		}
	}
	var bugbot aiReviewResult
	if bot := childByKind(job.RunID, kindBugbot); bot != nil && bot.Summary != nil {
		if raw, err := json.Marshal(bot.Summary["ai"]); err == nil {
			_ = json.Unmarshal(raw, &bugbot)
		}
	}
	secFindings := []agentFinding{}
	if sec := childByKind(job.RunID, kindSecurity); sec != nil {
		secFindings = securityFindingsFromRun(job.OrganizationID, sec.SecurityRunID)
	}
	return buildLedger(bugbot, secFindings)
}

func cloudFindingKeys(job *scmJob, ledger []agentFinding, prefs agentPrefs) ([]string, string) {
	if job != nil && job.Summary != nil {
		if raw, ok := job.Summary["mutation_proposal"]; ok && raw != nil {
			b, _ := json.Marshal(raw)
			var prop agentMutationProposal
			if json.Unmarshal(b, &prop) == nil && len(prop.FindingKeys) > 0 {
				return prop.FindingKeys, prop.Rationale
			}
		}
		if keys, ok := stringSliceFromAny(job.Summary["finding_keys"]); ok && len(keys) > 0 {
			return keys, ""
		}
	}
	threshold := strings.ToLower(strings.TrimSpace(prefs.AutofixSeverityThreshold))
	if threshold == "" {
		threshold = "high"
	}
	var keys []string
	for _, f := range ledger {
		if severityAtLeast(f.Severity, threshold) || severityEqualsBlocker(f.Severity) {
			keys = append(keys, f.Key)
		}
	}
	return keys, "auto from ledger"
}

func findingsMapsFromAgent(fs []agentFinding) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(fs))
	for _, f := range fs {
		out = append(out, map[string]interface{}{
			"finding_key": f.Key, "severity": f.Severity, "file": f.File,
			"line": f.Line, "message": f.Message, "problem": f.Message, "rule": f.Rule,
		})
	}
	return out
}

func keysFromFindings(fs []agentFinding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		if f.Key != "" {
			out = append(out, f.Key)
		}
	}
	return out
}

func findingPaths(fs []agentFinding) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range fs {
		p := filepath.ToSlash(strings.TrimSpace(f.File))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func formatCloudSuggestComment(job *scmJob, auth autofixAuthOK, changes []cloudDiffChange, branch string) string {
	var b strings.Builder
	b.WriteString("## OPA Auto-fix suggestion\n\n")
	b.WriteString("Cloud agent prepared a patch (**suggest** mode — no branch pushed).\n\n")
	b.WriteString("### Findings\n")
	for _, f := range auth.Findings {
		fmt.Fprintf(&b, "- **%s** `%s` — %s\n", f.Severity, f.File, truncateStr(f.Message, 120))
	}
	b.WriteString("\n### Touched paths\n")
	for _, c := range changes {
		fmt.Fprintf(&b, "- `%s` (+%d/-%d)\n", c.Path, c.Added, c.Removed)
	}
	fmt.Fprintf(&b, "\n_Set `autofix_mode=branch` to land on `%s`._\n", branch)
	_ = job
	return b.String()
}

func formatCloudLandPRBody(job *scmJob, auth autofixAuthOK, branch string) string {
	var b strings.Builder
	b.WriteString("## OPA Auto-fix\n\n")
	fmt.Fprintf(&b, "Automated fix from run `%s` on branch `%s`.\n\n", nz(job.RunID, job.ID), branch)
	if job.PRNumber > 0 {
		fmt.Fprintf(&b, "Original PR #%d.\n\n", job.PRNumber)
	}
	b.WriteString("### Findings addressed\n")
	for _, f := range auth.Findings {
		fmt.Fprintf(&b, "- **%s** `%s`", f.Severity, f.File)
		if f.Line > 0 {
			fmt.Fprintf(&b, ":%d", f.Line)
		}
		fmt.Fprintf(&b, " — %s\n", truncateStr(f.Message, 160))
	}
	b.WriteString("\n_Minimal patches only. Diff gated by `gateCloudDiff`, applied to a clean tree before land._\n")
	return b.String()
}

func stringSliceFromAny(v interface{}) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		return t, true
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out, true
	default:
		return nil, false
	}
}
