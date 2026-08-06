package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	openlogger "github.com/TheGrimmChester/open-logger-go"
)

// processPRRun drives a kind=run parent: plan children, launch ready ones,
// fold status when all terminal. Barriers are derived from persisted child
// status — never from WaitGroup — so restart mid-run re-enters safely.
func processPRRun(jobID string) {
	if _, loaded := scmProcessing.LoadOrStore(jobID, struct{}{}); loaded {
		return
	}
	defer scmProcessing.Delete(jobID)

	job := getSCMJob(jobID)
	if job == nil {
		return
	}
	switch job.Status {
	case "cancelled", "completed", "failed", "error", "skipped", "completed_with_errors":
		return
	}

	if skip, reason, priorID := scmRunSkipGate(job); skip {
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		job.Status = "skipped"
		if job.Summary == nil {
			job.Summary = map[string]interface{}{}
		}
		job.Summary["skip_reason"] = reason
		if priorID != "" {
			job.Summary["prior_reviewed_job_id"] = priorID
		}
		job.FinishedAt = now
		if job.StartedAt == "" {
			job.StartedAt = now
		}
		persistSCMJob(job)
		return
	}

	_, cancel := registerSCMJobCancel(jobID)
	defer func() {
		cancel()
		clearSCMJobCancel(jobID)
	}()

	if job.Status != "running" {
		job.Status = "running"
		job.StartedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
		persistSCMJob(job)
	}

	_ = ensureRunChildren(job)

	deadline := time.Now().Add(2 * time.Hour)
	for time.Now().Before(deadline) {
		if scmJobIsCancelled(jobID) {
			// Cascade already cancelled children; wait briefly so approval cannot
			// still APPROVE after finalize's COMMENT fallback.
			waitRunChildrenTerminal(jobID, 30*time.Second)
			finalizePRRun(jobID)
			return
		}
		ready := readyChildren(jobID)
		for _, c := range ready {
			cid := c.ID
			go processSCMJob(cid)
		}
		children := listRunChildren(jobID)
		allDone := len(children) > 0
		for _, c := range children {
			if !jobTerminal(c.Status) {
				allDone = false
				break
			}
		}
		if allDone {
			finalizePRRun(jobID)
			return
		}
		time.Sleep(400 * time.Millisecond)
	}
	job = getSCMJob(jobID)
	if job != nil && !jobTerminal(job.Status) {
		job.Status = "error"
		job.Error = "run barrier deadline exceeded"
		job.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
		persistSCMJob(job)
	}
}

// finalizeGraphRun folds issue_run / roadmap_run parents when all children are terminal.
func finalizeGraphRun(runID string) {
	job := getSCMJob(runID)
	if job == nil {
		return
	}
	children := listRunChildren(runID)
	for _, c := range children {
		if c == nil || c.Summary == nil {
			continue
		}
		if job.Summary == nil {
			job.Summary = map[string]interface{}{}
		}
		for _, k := range []string{
			"findings", "spec_draft", "implement", "roadmap", "discovery",
			"competitor_analysis", "publish", "checkout_path", "issue_status",
		} {
			if v, ok := c.Summary[k]; ok {
				job.Summary[k] = v
			}
		}
	}
	job.Status = foldRunStatus(children, job.Status)
	job.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	_ = finalizeJobEvidence(job)
	persistSCMJob(job)
}

func finalizePRRun(runID string) {
	job := getSCMJob(runID)
	if job == nil {
		return
	}
	if agentKind(job.Kind) == kindIssueRun || agentKind(job.Kind) == kindRoadmapRun {
		finalizeGraphRun(runID)
		return
	}
	children := listRunChildren(runID)
	var approval *scmJob
	var bugbot *scmJob
	pendingDecision := false
	// Mirror child outputs onto the parent for Dashboard / smoke.
	for _, c := range children {
		if c.SecurityRunID != "" {
			job.SecurityRunID = c.SecurityRunID
		}
		if c.AIJobID != "" {
			job.AIJobID = c.AIJobID
		}
		switch agentKind(c.Kind) {
		case kindApproval:
			approval = c
		case kindBugbot:
			bugbot = c
		}
		if c.Summary != nil {
			if job.Summary == nil {
				job.Summary = map[string]interface{}{}
			}
			if c.Summary["pending_decision"] == true {
				pendingDecision = true
			}
			switch agentKind(c.Kind) {
			case kindPrepare:
				if v, ok := c.Summary["checkout_path"]; ok {
					job.Summary["checkout_path"] = v
				}
				if v, ok := c.Summary["worktree"]; ok {
					job.Summary["worktree"] = v
				}
				if v, ok := c.Summary["related_checkouts"]; ok {
					job.Summary["related_checkouts"] = v
				}
			case kindSecurity:
				if v, ok := c.Summary["gate"]; ok {
					job.Summary["gate"] = v
				}
			case kindBugbot:
				if v, ok := c.Summary["ai"]; ok {
					job.Summary["ai"] = v
				}
			case kindCheckup:
				if v, ok := c.Summary["checkup"]; ok {
					job.Summary["checkup"] = v
				}
				if v, ok := c.Summary["checkup_drops"]; ok {
					job.Summary["checkup_drops"] = v
				}
			case kindCloud:
				if v, ok := c.Summary["cloud"]; ok {
					job.Summary["cloud"] = v
				}
			case kindApproval:
				if v, ok := c.Summary["review_event"]; ok {
					job.Summary["review_event"] = v
				}
				if v, ok := c.Summary["risk_score"]; ok {
					job.Summary["risk_score"] = v
				}
				if v, ok := c.Summary["risk_factors"]; ok {
					job.Summary["risk_factors"] = v
				}
				if c.Summary["pending_decision"] == false {
					pendingDecision = false
				}
			}
			for k, v := range c.CheckRunIDs {
				if job.CheckRunIDs == nil {
					job.CheckRunIDs = map[string]int64{}
				}
				job.CheckRunIDs[k] = v
			}
		}
	}
	// If approval failed/skipped/missing while bugbot left a pending decision,
	// publish COMMENT so inline findings are never silently orphaned.
	// Skip on cancelled runs — publishPRReview refuses cancelled jobs anyway.
	approvalOK := approval != nil && (approval.Status == "completed" || approval.Status == "skipped") &&
		approval.Summary != nil && approval.Summary["pending_decision"] == false
	if pendingDecision && !approvalOK && bugbot != nil && !scmJobIsCancelled(runID) {
		ensureFinalCOMMENTReview(job, bugbot)
	}
	folded := foldRunStatus(children, job.Status)
	if scmJobIsCancelled(runID) {
		folded = "cancelled"
	}
	job.Status = folded
	job.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	persistSCMJob(job)
	go cleanupOldSCMWorktrees(securityWorkspaceRoot(), 24*time.Hour)
}

// waitRunChildrenTerminal blocks until every child is terminal or timeout elapses.
// Used after parent cancel so finalize does not race a still-running approval.
func waitRunChildrenTerminal(runID string, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		children := listRunChildren(runID)
		allDone := true
		for _, c := range children {
			if c == nil {
				continue
			}
			// Cloud drain intentionally stays non-terminal until land finishes.
			if agentKind(c.Kind) == kindCloud && c.Summary != nil &&
				(c.Summary["supersede_drain"] == true || c.Summary["cancel_drain"] != nil) &&
				(c.Status == "running" || c.Status == "waiting") {
				continue
			}
			if !jobTerminal(c.Status) {
				allDone = false
				break
			}
		}
		if allDone {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ensureFinalCOMMENTReview posts a decision-less COMMENT via the chokepoint when
// approval did not complete — so humans still get one review notification.
func ensureFinalCOMMENTReview(parent, bugbot *scmJob) {
	if parent == nil || bugbot == nil {
		return
	}
	if parent.Summary == nil {
		parent.Summary = map[string]interface{}{}
	}
	if parent.Summary["final_comment_published"] == true {
		return
	}
	_, conn := findWatched(parent.RepoFullName)
	if conn == nil {
		conn = getOrHydrateConnector(parent.ConnectorID)
	}
	if conn == nil || githubUseMockAPI(conn) {
		parent.Summary["final_comment_published"] = true
		parent.Summary["pending_decision"] = false
		return
	}
	owner, repoName := splitOwnerRepo(parent.RepoFullName)
	body := "OPA Review — findings posted; approval agent did not complete (COMMENT fallback)."
	if err := publishPRReview(conn, owner, repoName, parent, body, "COMMENT", nil); err != nil {
		parent.Summary["final_comment_error"] = err.Error()
		return
	}
	parent.Summary["final_comment_published"] = true
	parent.Summary["pending_decision"] = false
	parent.Summary["review_event"] = "COMMENT"
	if bugbot.Summary != nil {
		bugbot.Summary["pending_decision"] = false
		persistSCMJob(bugbot)
	}
}

func processAgentChild(jobID string) {
	job := getSCMJob(jobID)
	if job == nil {
		return
	}
	if !agentChildReady(job) {
		// Leave queued; parent loop will retry when deps complete.
		return
	}
	if _, loaded := scmProcessing.LoadOrStore(jobID, struct{}{}); loaded {
		return
	}
	defer scmProcessing.Delete(jobID)

	acquireKindSlot(agentKind(job.Kind))
	defer releaseKindSlot(agentKind(job.Kind))

	switch job.Status {
	case "cancelled", "completed", "failed", "error", "skipped":
		return
	}

	_, cancel := registerSCMJobCancel(jobID)
	defer func() {
		cancel()
		clearSCMJobCancel(jobID)
	}()

	job.Status = "running"
	job.StartedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	persistSCMJob(job)

	var err error
	switch agentKind(job.Kind) {
	case kindPrepare:
		err = runPrepareAgent(job)
	case kindSecurity:
		err = runSecurityAgent(job)
	case kindBugbot:
		err = runBugbotAgent(job)
	case kindCheckup:
		err = runCheckupAgent(job)
	case kindApproval:
		err = runApprovalAgent(job)
	case kindCloud:
		err = runCloudAgent(job)
	case kindIssuePrepare:
		err = runIssuePrepareAgent(job)
	case kindIssueInvestigate:
		err = runIssueInvestigateAgent(job)
	case kindIssuePublish:
		err = runIssuePublishAgent(job)
	case kindIssueImplement:
		err = runIssueImplementAgent(job)
	case kindRoadmapGenerate:
		err = runRoadmapGenerateAgent(job)
	case kindRoadmapPublish:
		err = runRoadmapPublishAgent(job)
	default:
		err = fmt.Errorf("unknown agent kind %q", job.Kind)
	}

	job = getSCMJob(jobID)
	if job == nil {
		return
	}
	if scmJobIsCancelled(jobID) {
		if job.FinishedAt == "" {
			job.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
			persistSCMJob(job)
		}
		return
	}
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
	} else if job.Status != "skipped" {
		job.Status = "completed"
		job.Error = ""
	}
	job.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	_ = finalizeJobEvidence(job)
	persistSCMJob(job)
}

func agentChildReady(job *scmJob) bool {
	if job == nil {
		return false
	}
	deps := agentDependsOn[agentKind(job.Kind)]
	if len(deps) == 0 {
		return true
	}
	for _, d := range deps {
		dep := childByKind(job.RunID, d)
		if dep == nil || !jobTerminal(dep.Status) {
			return false
		}
		if d == kindPrepare && dep.Status != "completed" && dep.Status != "skipped" {
			return false
		}
	}
	return true
}

func runPrepareAgent(job *scmJob) error {
	wr, conn := findWatched(job.RepoFullName)
	if conn == nil {
		conn = getOrHydrateConnector(job.ConnectorID)
	}
	_ = wr
	worktreeID := job.RunID
	if worktreeID == "" {
		worktreeID = job.ID
	}
	absRoot, relPath, wtMeta, err := prepareSCMWorktree(conn, job.RepoFullName, job.CommitSHA, job.PRNumber, worktreeID)
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	if wtMeta != nil {
		job.Summary["worktree"] = wtMeta
		if rs, _ := wtMeta["resolved_sha"].(string); rs != "" && (job.CommitSHA == "" || strings.HasPrefix(job.CommitSHA, "manual-") || strings.HasPrefix(job.CommitSHA, "cron-")) {
			job.CommitSHA = rs
		}
	}
	if err != nil {
		job.Summary["checkout_error"] = err.Error()
		useMock := githubUseMockAPI(conn) || conn == nil || (conn.TokenRef == "" && conn.InstallationID == "")
		if !useMock {
			return fmt.Errorf("git worktree checkout failed: %w", err)
		}
		_ = writeMockWorktreeFixture(absRoot)
		job.Summary["checkout_fallback"] = "mock_worktree_fixture"
	}
	job.Summary["checkout_path"] = absRoot
	job.Summary["checkout_rel"] = relPath

	analyzed := job.CommitSHA
	if wtMeta != nil {
		if rs, _ := wtMeta["resolved_sha"].(string); rs != "" {
			analyzed = rs
		}
	}
	if analyzed != "" && !strings.HasPrefix(analyzed, "manual-") && !strings.HasPrefix(analyzed, "cron-") {
		recordAnalyzedSHA(job, analyzed)
	}

	if sandboxMode() == "docker" && absRoot != "" {
		if sb, n, merr := materializeSandboxTreeForJob(worktreeID, absRoot); merr != nil {
			job.Summary["sandbox_tree_error"] = merr.Error()
			if !allowHostExecFallback() {
				return fmt.Errorf("sandbox materialize failed (set OPA_JOB_ALLOW_HOST_EXEC=1 to fall back): %w", merr)
			}
			stampSandboxHonesty(job.ID, "UNSANDBOXED: prepare fell back to primary .git (OPA_JOB_ALLOW_HOST_EXEC=1; materialize failed)")
			job.Summary["sandbox_fallback"] = "host_exec"
			openlogger.LogWarn("sandbox tree materialize — host fallback", map[string]interface{}{"error": merr.Error(), "job": job.ID})
		} else if sb != "" {
			job.Summary["sandbox_tree"] = sb
			job.Summary["sandbox_file_count"] = n
		}
	}

	owner, repoName := splitOwnerRepo(job.RepoFullName)
	appliedEarly := resolveReviewContextsForRepo(job.OrganizationID, job.ProjectID, job.RepoFullName)
	prBody := job.Body
	if job.PRNumber > 0 && !githubUseMockAPI(conn) {
		if pull, perr := githubGetPull(conn, owner, repoName, job.PRNumber); perr == nil && pull != nil {
			prBody = pull.Body
			if job.Title == "" {
				job.Title = pull.Title
			}
		}
	}
	relatedNames := resolveRelatedReposForJob(job, appliedEarly, prBody, nil, nil)
	if len(relatedNames) > 0 {
		related := prepareRelatedCheckouts(conn, worktreeID, relatedNames, nil)
		job.Summary["related_checkouts"] = related
		job.Summary["related_repos"] = relatedRepoNames(related)
	}
	persistSCMJob(job)
	// Mirror checkout + related onto parent early so bugbot briefs can read
	// sibling clones before finalize folds prepare summary.
	if parent := getSCMJob(job.RunID); parent != nil && parent.ID != job.ID {
		if parent.Summary == nil {
			parent.Summary = map[string]interface{}{}
		}
		parent.Summary["checkout_path"] = absRoot
		parent.Summary["checkout_rel"] = relPath
		if analyzed != "" {
			parent.CommitSHA = analyzed
		}
		for _, k := range []string{"analyzed_sha", "previous_analyzed_sha", "previous_analyzed_at", "previous_analyzed_job_id", "commits_since_previous", "new_commits_since_review", "sandbox_tree", "sandbox_file_count", "related_checkouts", "related_repos"} {
			if v, ok := job.Summary[k]; ok {
				parent.Summary[k] = v
			}
		}
		persistSCMJob(parent)
	}
	return nil
}

func runSecurityAgent(job *scmJob) error {
	wr, conn := findWatched(job.RepoFullName)
	if conn == nil {
		conn = getOrHydrateConnector(job.ConnectorID)
	}
	owner, repoName := splitOwnerRepo(job.RepoFullName)
	_ = conn

	var checks []string
	profile := "auto"
	minSev := "high"
	service := strings.ReplaceAll(job.RepoFullName, "/", "-")
	if wr != nil {
		jsonUnmarshalChecks(wr.ChecksJSON, &checks)
		profile = nz(wr.Profile, "auto")
		minSev = nz(wr.MinSeverity, "high")
		service = nz(wr.ServiceName, service)
	}
	if len(checks) == 0 {
		checks = defaultWatchedChecks()
	}
	scanList := []string{}
	for _, c := range checks {
		if c == "sbom" || c == "secrets" || c == "sast" || c == "iac" || c == "container" {
			scanList = append(scanList, c)
		}
	}
	if len(scanList) == 0 {
		scanList = []string{"secrets", "sast", "iac", "sbom"}
	}
	if job.AIOnly {
		scanList = []string{}
	}

	relPath := checkoutRelForRun(job)
	runID := securityRunID(job.OrganizationID, job.ProjectID, job.RunID)
	job.SecurityRunID = runID

	jobDashURL := scmJobDashboardURL(job.RunID)
	if !githubUseMockAPI(conn) {
		if err := ensureGitHubWriteAllowed(job, conn); err != nil {
			if job.Summary == nil {
				job.Summary = map[string]interface{}{}
			}
			job.Summary["publish_refused"] = err.Error()
			persistSCMJob(job)
			return err
		}
	}
	appSecID, _ := githubCreateCheckRun(conn, owner, repoName, "AppSec Gate", job.CommitSHA, "in_progress", "", "Scanning…", checkRunSummaryWithJobLink("Repo Watch scanners running", job.RunID), jobDashURL, nil)
	if job.CheckRunIDs == nil {
		job.CheckRunIDs = map[string]int64{}
	}
	job.CheckRunIDs["appsec"] = appSecID
	persistSCMJob(job)

	// scmJob label = security child id so cancelSCMJob(teardown opa.job) hits scan boxes;
	// checkout layout stays under the parent run (relPath already absolute).
	scanStartErr := runSecurityScanJob(runID, job.OrganizationID, job.ProjectID, service, profile, scanList, relPath, "", job.RepoFullName, job.ConnectorID, job.PRNumber, job.CommitSHA, job.ID)

	gate := gateAfterScan(job.OrganizationID, runID, minSev, scanStartErr)
	if job.AIOnly {
		gate = map[string]interface{}{
			"status": gateStatusPass, "fail": false, "reasons": []string{"ai_only"},
			"scope": "security_run", "security_run_id": runID, "min_severity": minSev,
		}
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	job.Summary["gate"] = gate
	conclusion, title := gateCheckOutcome(gate)
	if appSecID != 0 {
		_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", conclusion, title,
			checkRunSummaryWithJobLink(gateCheckSummary(gate, runID), job.RunID), jobDashURL, nil)
	}
	persistSCMJob(job)
	return nil
}

func runBugbotAgent(job *scmJob) error {
	wr, conn := findWatched(job.RepoFullName)
	if conn == nil {
		conn = getOrHydrateConnector(job.ConnectorID)
	}
	owner, repoName := splitOwnerRepo(job.RepoFullName)
	absRoot := checkoutPathForRun(job)
	sec := childByKind(job.RunID, kindSecurity)
	runID := ""
	var gate map[string]interface{}
	scanList := []string{"secrets", "sast", "iac", "sbom"}
	if sec != nil {
		runID = sec.SecurityRunID
		if sec.Summary != nil {
			if g, ok := sec.Summary["gate"].(map[string]interface{}); ok {
				gate = g
			}
		}
	}
	if runID == "" {
		runID = securityRunID(job.OrganizationID, job.ProjectID, job.RunID)
	}
	if gate == nil {
		gate = map[string]interface{}{"status": "pass", "fail": false, "reasons": []string{"no security child"}}
	}

	autoApproveMinScore := 0
	if wr != nil {
		autoApproveMinScore = wr.AutoApproveMinScore
	}

	jobDashURL := scmJobDashboardURL(job.RunID)
	if !githubUseMockAPI(conn) {
		if err := ensureGitHubWriteAllowed(job, conn); err != nil {
			if job.Summary == nil {
				job.Summary = map[string]interface{}{}
			}
			job.Summary["publish_refused"] = err.Error()
			persistSCMJob(job)
			return err
		}
	}
	aiCheckID, _ := githubCreateCheckRun(conn, owner, repoName, "OPA Review", job.CommitSHA, "in_progress", "", "OPA reviewing…", checkRunSummaryWithJobLink("Running OPA Review", job.RunID), jobDashURL, nil)
	if job.CheckRunIDs == nil {
		job.CheckRunIDs = map[string]int64{}
	}
	job.CheckRunIDs["ai"] = aiCheckID
	persistSCMJob(job)

	prefs := agentPrefsFromSummary(getSCMJob(job.RunID))
	applied := resolveReviewContextsForPrefs(job.OrganizationID, job.ProjectID, job.RepoFullName, prefs)
	appliedSummary := summarizeAppliedContexts(applied)
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	job.Summary["review_contexts"] = appliedSummary

	aiResult := runCursorAIReview(job, conn, wr, absRoot, runID)
	job.AIJobID = aiResult.ID

	wtOK := absRoot != ""
	mcpPlan := reviewMCPPlan{VisualStatus: "not_applicable", VisualWhy: "no UI files in diff"}
	if aiResult.MCP != nil {
		mcpPlan = *aiResult.MCP
	}
	pubMeta := aiReviewPublishMeta{
		SecurityRunID: runID, Gate: gate, Scanners: scanList,
		ContextTitles: contextTitlesFromApplied(appliedSummary),
		WorktreeOK: wtOK, DesignEnforcement: aiResult.DesignEnforced,
		ScanSeverity: scanSeverityCountsForRun(runID), MCP: mcpPlan,
	}
	populateCarriedFindingKeys(job, conn, owner, repoName, prefs)
	inline := postOPAReviewFindings(conn, owner, repoName, job, aiResult, pubMeta, autoApproveMinScore)
	aiResult.InlinePosted = inline.Posted
	aiResult.InlineFailed = inline.Failed
	aiResult.InlineMode = inline.Mode
	aiResult.InlineHonesty = inline.Honesty

	checkSum := ""
	if opaReviewShouldPostResume(aiResult) {
		aiComment, cs := publishAIReviewComment(job, aiResult, pubMeta)
		aiResult.Comment = aiComment
		checkSum = cs
	} else {
		checkSum = truncateStr(nz(aiResult.Summary, "OPA Review skipped"), 500)
	}
	job.Summary["ai"] = aiResult
	if scmAIReviewSucceeded(aiResult.Status) {
		reviewedSHA := job.CommitSHA
		if a := strFromAny(job.Summary["analyzed_sha"]); a != "" {
			reviewedSHA = a
		}
		recordSuccessfulAIReview(job, reviewedSHA, aiResult.Status)
	}
	if n := mineLearnedRuleCandidates(job, aiResult, prefs); n > 0 {
		job.Summary["learned_rule_candidates"] = n
	}
	// Decision deferred to approval.decide — only provisional check-run conclusion here.
	aiConclusion := "success"
	if aiResult.Status == "skipped" || aiResult.Status == "error" {
		aiConclusion = "neutral"
	} else if hasBlockerOrHighFinding(aiResult) || strings.EqualFold(aiResult.Status, "findings") {
		aiConclusion = "failure"
	}
	if aiCheckID != 0 {
		_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", aiConclusion, "OPA Review "+aiResult.Status,
			checkRunSummaryWithJobLink(checkSum, job.RunID), jobDashURL, aiResult.Annotations)
	}
	persistSCMJob(job)
	return nil
}

func runApprovalAgent(job *scmJob) error {
	bugbot := childByKind(job.RunID, kindBugbot)
	sec := childByKind(job.RunID, kindSecurity)
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	if scmJobIsCancelled(job.ID) || (job.RunID != "" && scmJobIsCancelled(job.RunID)) {
		job.Status = "cancelled"
		job.Summary["skip_reason"] = "parent/run cancelled"
		persistSCMJob(job)
		return nil
	}
	if bugbot == nil || !jobTerminal(bugbot.Status) || sec == nil || !jobTerminal(sec.Status) {
		return fmt.Errorf("approval requires terminal bugbot+security")
	}
	if bugbot.Status == "failed" && sec.Status == "failed" {
		job.Status = "skipped"
		job.Summary["skip_reason"] = "no reviewer input"
		job.Summary["degraded"] = []string{"bugbot failed", "security failed"}
		persistSCMJob(job)
		return nil
	}

	wr, conn := findWatched(job.RepoFullName)
	if conn == nil {
		conn = getOrHydrateConnector(job.ConnectorID)
	}
	owner, repoName := splitOwnerRepo(job.RepoFullName)
	if !githubUseMockAPI(conn) {
		if err := ensureGitHubWriteAllowed(job, conn); err != nil {
			job.Summary["approval_publish_error"] = err.Error()
			return err
		}
	}
	prefs := agentPrefsFromSummary(getSCMJob(job.RunID))
	minScore := 0
	if wr != nil {
		minScore = wr.AutoApproveMinScore
	}
	if prefs.AutoApprove && minScore <= 0 {
		minScore = 70 // default veto threshold when auto_approve on without watched score
	}

	var res aiReviewResult
	if bugbot.Summary != nil {
		if raw, err := json.Marshal(bugbot.Summary["ai"]); err == nil {
			_ = json.Unmarshal(raw, &res)
		}
	}
	secFindings := securityFindingsFromRun(job.OrganizationID, sec.SecurityRunID)
	gateFail := false
	if sec.Summary != nil {
		if g, ok := sec.Summary["gate"].(map[string]interface{}); ok && g["fail"] == true {
			gateFail = true
		}
	}
	var degraded []string
	if bugbot.Status == "failed" || bugbot.Status == "error" {
		degraded = append(degraded, "bugbot incomplete")
	}
	if sec.Status == "failed" || sec.Status == "error" {
		degraded = append(degraded, "security incomplete")
	}
	if cloud := childByKind(job.RunID, kindCloud); cloud != nil && !jobTerminal(cloud.Status) {
		job.Summary["pending_autofix"] = true
	}

	baseRef := "main"
	if pull, err := githubGetPull(conn, owner, repoName, job.PRNumber); err == nil && pull != nil && pull.BaseRef != "" {
		baseRef = pull.BaseRef
	}
	policyPath, _ := safePolicyPath(prefs.PolicyFilePath)
	var policy *approvalPolicy
	policyHonesty := ""
	if raw, err := githubGetContentAtRef(conn, owner, repoName, policyPath, baseRef); err != nil {
		policyHonesty = "policy unavailable: " + err.Error()
	} else if p, err := parseApprovalPolicy(raw); err != nil {
		policyHonesty = "policy unparseable: " + err.Error()
	} else {
		policy = p
	}

	risk := computeRiskScore(riskEvidence{
		Bugbot: res, SecurityFail: gateFail, SecurityFindings: secFindings, Degraded: degraded,
	})
	job.Summary["risk_score"] = risk.Score
	job.Summary["risk_factors"] = risk.Factors

	ev := approvalEvidence{
		Prefs: prefs, Bugbot: res, SecurityRunID: sec.SecurityRunID,
		SecurityFail: gateFail, SecurityFindings: secFindings,
		BugbotOK: bugbot.Status == "completed",
		SecurityOK: sec.Status == "completed",
		Degraded: degraded, CloudChildExists: job.Summary["pending_autofix"] == true,
		Policy: policy, PolicyHonesty: policyHonesty, BaseRef: baseRef, MinScore: minScore,
		RiskScore: risk.Score,
	}
	decision := evaluateApproval(ev)
	job.Summary["review_event"] = decision.Event
	job.Summary["approval_reasons"] = decision.Reasons
	job.Summary["approval_honesty"] = decision.Honesty
	job.Summary["ledger"] = buildLedger(res, secFindings)
	if len(degraded) > 0 {
		job.Summary["degraded"] = degraded
	}

	// Masked inline security findings (own namespace) when pref enabled.
	if prefs.InlineFindings && conn != nil && !githubUseMockAPI(conn) {
		specs := []githubPRReviewCommentSpec{}
		for _, f := range secFindings {
			if f.File == "" || f.Line < 1 {
				continue
			}
			specs = append(specs, githubPRReviewCommentSpec{
				Path: f.File, Line: f.Line, Body: formatMaskedSecurityInline(f),
			})
		}
		if len(specs) > 0 {
			_ = publishPRReview(conn, owner, repoName, job, "OPA AppSec — masked inline findings", "COMMENT", specs)
		}
	}

	if prefs.PRSummaries {
		var riskPtr *riskScoreResult
		if prefs.PostPRRiskScore {
			riskPtr = &risk
		}
		narrative := formatPRSummaryNarrative(res, riskPtr)
		if skipped, err := upsertPRSummary(conn, owner, repoName, job, narrative); err != nil {
			job.Summary["pr_summary_error"] = err.Error()
		} else if skipped != "" {
			job.Summary["pr_summary_skipped"] = skipped
		} else {
			job.Summary["pr_summary_updated"] = true
		}
	}

	body := formatOPAReviewDecisionBody(decision.Bugbot, decision.Event, minScore)
	// Honesty / risk stay in job summary + résumé / PR fence — not as stacked review cards.
	if err := publishPRReview(conn, owner, repoName, job, body, decision.Event, nil); err != nil {
		job.Summary["approval_publish_error"] = err.Error()
	}
	job.Summary["pending_decision"] = false

	// Reviewer routing after findings exist.
	if prefs.ReviewerRouting && policy != nil {
		_ = githubRequestPRReviewersEx(conn, owner, repoName, job.PRNumber, policy.Route.Reviewers, policy.Route.TeamReviewers)
	} else if wr != nil && wr.AutoRequestReviewer {
		_ = githubRequestPRReviewers(conn, owner, repoName, job.PRNumber, []string{githubAppReviewerLogin()})
	}

	persistSCMJob(job)
	return nil
}

func checkoutPathForRun(job *scmJob) string {
	if prep := childByKind(job.RunID, kindPrepare); prep != nil && prep.Summary != nil {
		if sandboxMode() == "docker" {
			if p, _ := prep.Summary["sandbox_tree"].(string); p != "" {
				return p
			}
		}
		if p, _ := prep.Summary["checkout_path"].(string); p != "" {
			return p
		}
	}
	if parent := getSCMJob(job.RunID); parent != nil && parent.Summary != nil {
		if sandboxMode() == "docker" {
			if p, _ := parent.Summary["sandbox_tree"].(string); p != "" {
				return p
			}
		}
		if p, _ := parent.Summary["checkout_path"].(string); p != "" {
			return p
		}
	}
	return ""
}

func checkoutRelForRun(job *scmJob) string {
	if sandboxMode() == "docker" {
		if p := checkoutPathForRun(job); p != "" {
			return p
		}
	}
	if prep := childByKind(job.RunID, kindPrepare); prep != nil && prep.Summary != nil {
		if p, _ := prep.Summary["checkout_rel"].(string); p != "" {
			return p
		}
		if p, _ := prep.Summary["checkout_path"].(string); p != "" {
			return p
		}
	}
	return checkoutPathForRun(job)
}

func jsonUnmarshalChecks(raw string, out *[]string) {
	_ = json.Unmarshal([]byte(raw), out)
}