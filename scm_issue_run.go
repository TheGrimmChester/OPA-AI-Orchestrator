package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AI-labelled GitHub Issues: webhook gate → investigate → publish plan.
// Opt-in implement creates a PR (no auto-merge).

const (
	opaLabelInvestigating = "opa:investigating"
	opaLabelPlanReady     = "opa:plan-ready"
	opaLabelBuilding      = "opa:building"
	opaLabelPROpen        = "opa:pr-open"
)

var (
	issueRunIndexMu sync.Mutex
	issueRunIndex   = map[string]string{} // repo#issue → run id
)

func issueRunIndexKey(repo string, issue int) string {
	return strings.ToLower(strings.TrimSpace(repo)) + "#issue#" + itoa(issue)
}

func rememberIssueRun(repo string, issue int, runID string) {
	if repo == "" || issue <= 0 || runID == "" {
		return
	}
	issueRunIndexMu.Lock()
	issueRunIndex[issueRunIndexKey(repo, issue)] = runID
	issueRunIndexMu.Unlock()
}

func currentIssueRun(repo string, issue int) string {
	issueRunIndexMu.Lock()
	defer issueRunIndexMu.Unlock()
	return issueRunIndex[issueRunIndexKey(repo, issue)]
}

func handleIssuesWebhook(w http.ResponseWriter, raw []byte, rec *scmWebhookReceipt) {
	var payload struct {
		Action string `json:"action"`
		Issue  struct {
			Number      int    `json:"number"`
			Title       string `json:"title"`
			Body        string `json:"body"`
			State       string `json:"state"`
			PullRequest *struct {
				URL string `json:"url"`
			} `json:"pull_request"`
			Labels []struct {
				Name string `json:"name"`
			} `json:"labels"`
		} `json:"issue"`
		Label struct {
			Name string `json:"name"`
		} `json:"label"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		finishWebhookReceipt(rec, "error", "Invalid issues payload JSON.", 400, "bad json")
		http.Error(w, "bad json", 400)
		return
	}
	if payload.Issue.PullRequest != nil && strings.TrimSpace(payload.Issue.PullRequest.URL) != "" {
		finishWebhookReceipt(rec, "ignored", "Pull request issue event — handled via pull_request webhook.", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "ignored": "pull_request_issue", "webhook_id": rec.ID})
		return
	}
	repo := strings.TrimSpace(payload.Repository.FullName)
	issue := payload.Issue.Number
	action := strings.ToLower(strings.TrimSpace(payload.Action))
	applyWebhookRepoMeta(rec, repo, issue, "", payload.Installation.ID, action)

	labels := make([]string, 0, len(payload.Issue.Labels)+1)
	for _, l := range payload.Issue.Labels {
		if l.Name != "" {
			labels = append(labels, l.Name)
		}
	}
	if action == "labeled" && payload.Label.Name != "" {
		labels = mergeIssueLabels(labels, []string{payload.Label.Name})
	}

	switch action {
	case "labeled", "opened", "reopened", "edited":
	default:
		finishWebhookReceipt(rec, "ignored", "Issue action "+action+" not processed.", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "ignored": action, "webhook_id": rec.ID})
		return
	}

	job, reason, _ := maybeEnqueueIssueRun(repo, issue, payload.Issue.Title, payload.Issue.Body, labels, "issues."+action)
	if job == nil {
		finishWebhookReceipt(rec, "ignored", reason, 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "ignored": true, "reason": reason, "webhook_id": rec.ID})
		return
	}
	rec.JobID = job.ID
	rec.ConnectorID = job.ConnectorID
	rec.OrganizationID = job.OrganizationID
	rec.ProjectID = job.ProjectID
	finishWebhookReceipt(rec, "ok", "Enqueued AI issue run "+job.ID, 200, "")
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{"ok": true, "job_id": job.ID, "webhook_id": rec.ID})
}

func handleIssueCommentWebhook(w http.ResponseWriter, raw []byte, rec *scmWebhookReceipt) {
	var payload struct {
		Action string `json:"action"`
		Issue  struct {
			Number int `json:"number"`
		} `json:"issue"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	_ = json.Unmarshal(raw, &payload)
	applyWebhookRepoMeta(rec, payload.Repository.FullName, payload.Issue.Number, "", payload.Installation.ID, payload.Action)
	finishWebhookReceipt(rec, "ignored", "issue_comment recorded; no auto job.", 200, "")
	writeJSON(w, map[string]interface{}{"ok": true, "ignored": "issue_comment", "webhook_id": rec.ID})
}

func handleLabelWebhook(w http.ResponseWriter, raw []byte, rec *scmWebhookReceipt) {
	finishWebhookReceipt(rec, "ignored", "label event acknowledged.", 200, "")
	writeJSON(w, map[string]interface{}{"ok": true, "ignored": "label", "webhook_id": rec.ID})
	_ = raw
}

func maybeEnqueueIssueRun(repo string, issue int, title, body string, labels []string, event string) (*scmJob, string, int) {
	repo = strings.TrimSpace(repo)
	if repo == "" || issue <= 0 {
		return nil, "missing repo or issue number", 200
	}
	wr, conn := findWatched(repo)
	if wr == nil || !wr.Enabled || conn == nil {
		return nil, "repo not watched", 200
	}
	prefs, _ := resolveAgentPrefs(wr.OrganizationID, wr.ProjectID, wr.ConnectorID, repo)
	if !prefs.AIIssuesEnabled {
		return nil, "ai_issues_enabled=false", 200
	}
	if !issueLabelMatchesPrefs(prefs, labels) {
		return nil, "issue lacks AI gate label", 200
	}
	if prior := currentIssueRun(repo, issue); prior != "" {
		if j := getSCMJob(prior); j != nil {
			st := strings.ToLower(j.Status)
			if st == "queued" || st == "waiting" || st == "running" {
				return nil, "issue run already in flight: " + prior, 200
			}
		}
	}
	job := enqueueIssueRun(wr, conn, repo, issue, title, body, labels, event)
	return job, "", 200
}

func enqueueIssueRun(wr *opaWatchedRepo, conn *opaConnector, repo string, issue int, title, body string, labels []string, event string) *scmJob {
	org, proj, connID := wr.OrganizationID, wr.ProjectID, wr.ConnectorID
	prefs, sources := resolveAgentPrefs(org, proj, connID, repo)
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	id := loadID("scmjob", org, proj, repo, itoa(issue), event, "issue_run", newRandomHex(6))
	parent := &scmJob{
		ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: connID,
		RepoFullName: repo, PRNumber: issue, CommitSHA: "", Event: event,
		Status: "queued", CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
		StartedAt: now, FinishedAt: now, Title: title, Body: body,
		Kind: string(kindIssueRun), RunID: id, ParentID: "", Attempt: 1,
	}
	parent.Summary["prefs"] = prefs
	parent.Summary["prefs_sources"] = sources
	parent.Summary["issue_number"] = issue
	parent.Summary["issue_labels"] = labels
	parent.Summary["child_ids"] = []string{}

	children := planIssueRunChildren(parent, prefs)
	childIDs := make([]string, 0, len(children))
	for _, c := range children {
		scmJobLive.Store(c.ID, c)
		persistSCMJob(c)
		childIDs = append(childIDs, c.ID)
	}
	parent.Summary["child_ids"] = childIDs
	scmJobLive.Store(id, parent)
	persistSCMJob(parent)
	rememberIssueRun(repo, issue, id)
	_ = conn
	return parent
}

func planIssueRunChildren(parent *scmJob, prefs agentPrefs) []*scmJob {
	kinds := []agentKind{kindIssuePrepare, kindIssueInvestigate, kindIssuePublish}
	autoImpl := prefs.IssueAutoImplement && !prefs.RequireHumanBeforeCoding
	if autoImpl {
		kinds = append(kinds, kindIssueImplement)
	}
	out := make([]*scmJob, 0, len(kinds))
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, k := range kinds {
		cid := loadID("scmjob", parent.OrganizationID, parent.ProjectID, parent.RepoFullName, itoa(parent.PRNumber), string(k), parent.ID)
		child := &scmJob{
			ID: cid, OrganizationID: parent.OrganizationID, ProjectID: parent.ProjectID,
			ConnectorID: parent.ConnectorID, RepoFullName: parent.RepoFullName,
			PRNumber: parent.PRNumber, CommitSHA: parent.CommitSHA, Event: parent.Event,
			Status: "queued", CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
			StartedAt: now, FinishedAt: now, Title: parent.Title, Body: parent.Body,
			ActorUserID: parent.ActorUserID,
			Kind: string(k), RunID: parent.ID, ParentID: parent.ID, Attempt: parent.Attempt,
		}
		out = append(out, child)
	}
	return out
}

func enqueueIssueImplement(parent *scmJob) (*scmJob, error) {
	if parent == nil || agentKind(parent.Kind) != kindIssueRun {
		return nil, fmt.Errorf("not an issue_run")
	}
	if existing := childByKind(parent.ID, kindIssueImplement); existing != nil {
		st := strings.ToLower(existing.Status)
		if st == "queued" || st == "waiting" || st == "running" {
			return existing, nil
		}
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	cid := loadID("scmjob", parent.OrganizationID, parent.ProjectID, parent.RepoFullName, itoa(parent.PRNumber), string(kindIssueImplement), parent.ID, newRandomHex(4))
	child := &scmJob{
		ID: cid, OrganizationID: parent.OrganizationID, ProjectID: parent.ProjectID,
		ConnectorID: parent.ConnectorID, RepoFullName: parent.RepoFullName,
		PRNumber: parent.PRNumber, CommitSHA: parent.CommitSHA, Event: "manual.approve_coding",
		Status: "queued", CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
		StartedAt: now, FinishedAt: now, Title: parent.Title, Body: parent.Body,
		ActorUserID: parent.ActorUserID,
		Kind: string(kindIssueImplement), RunID: parent.ID, ParentID: parent.ID, Attempt: parent.Attempt + 1,
	}
	scmJobLive.Store(cid, child)
	persistSCMJob(child)
	ids := []string{}
	if parent.Summary != nil {
		switch v := parent.Summary["child_ids"].(type) {
		case []string:
			ids = append(ids, v...)
		case []interface{}:
			for _, x := range v {
				if s, ok := x.(string); ok {
					ids = append(ids, s)
				}
			}
		}
	}
	ids = append(ids, cid)
	if parent.Summary == nil {
		parent.Summary = map[string]interface{}{}
	}
	parent.Summary["child_ids"] = ids
	if parent.Status == "completed" || parent.Status == "completed_with_errors" {
		parent.Status = "running"
		parent.FinishedAt = ""
	}
	persistSCMJob(parent)
	return child, nil
}

func runIssuePrepareAgent(job *scmJob) error {
	return runPrepareAgent(job)
}

func runIssueInvestigateAgent(job *scmJob) error {
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	parent := getSCMJob(job.RunID)
	title, body := job.Title, job.Body
	if parent != nil {
		if title == "" {
			title = parent.Title
		}
		if body == "" {
			body = parent.Body
		}
	}
	issueNum := job.PRNumber
	checkout := ""
	if prep := childByKind(job.RunID, kindIssuePrepare); prep != nil && prep.Summary != nil {
		checkout = strFromAny(prep.Summary["checkout_path"])
	}

	prompt := buildIssueInvestigatePrompt(job.RepoFullName, issueNum, title, body, checkout)
	ctx := context.Background()
	res, err := CompleteFor(ctx, "issue_investigate", aiCompleteRequest{
		System: "You are OPA Issue Investigator. Output strict JSON only.",
		Prompt: prompt, MaxTokens: 4096,
	}, credResolveQuery{
		OrganizationID: job.OrganizationID, ProjectID: job.ProjectID, UserID: job.ActorUserID,
	})

	findings := map[string]interface{}{
		"issue_number": issueNum, "title": title, "repo": job.RepoFullName, "status": "analyzed",
	}
	specDraft := map[string]interface{}{
		"summary": "Investigate " + title, "acceptance_criteria": []string{}, "approach": []string{}, "risks": []string{},
	}
	if err != nil {
		findings["status"] = "heuristic"
		findings["error"] = err.Error()
		findings["honesty"] = "AI complete failed — heuristic plan only"
		specDraft["summary"] = "Plan for issue #" + itoa(issueNum) + ": " + title
		specDraft["approach"] = []string{
			"Read the issue and surrounding code in " + job.RepoFullName,
			"Implement the smallest change that satisfies acceptance criteria",
			"Add/adjust tests when feasible",
			"Open a PR linked to this issue",
		}
		if body != "" {
			specDraft["acceptance_criteria"] = []string{"Address: " + truncateStr(body, 400)}
		}
	} else if res != nil {
		findings["provider"] = res.Provider
		findings["model"] = res.Model
		parsed := map[string]interface{}{}
		text := strings.TrimSpace(res.Text)
		text = strings.TrimPrefix(text, "```json")
		text = strings.TrimPrefix(text, "```")
		text = strings.TrimSuffix(text, "```")
		text = strings.TrimSpace(text)
		if json.Unmarshal([]byte(text), &parsed) == nil {
			if f, ok := parsed["findings"].(map[string]interface{}); ok {
				findings = f
			}
			if s, ok := parsed["spec_draft"].(map[string]interface{}); ok {
				specDraft = s
			} else {
				if v, ok := parsed["summary"]; ok {
					specDraft["summary"] = v
				}
				if v, ok := parsed["acceptance_criteria"]; ok {
					specDraft["acceptance_criteria"] = v
				}
				if v, ok := parsed["approach"]; ok {
					specDraft["approach"] = v
				}
				if v, ok := parsed["risks"]; ok {
					specDraft["risks"] = v
				}
			}
		} else {
			findings["raw_text"] = truncateStr(res.Text, 2000)
			specDraft["summary"] = truncateStr(res.Text, 500)
		}
	}

	artDir := filepath.Join(scmStateDir(), "issue-artifacts", job.RunID)
	_ = os.MkdirAll(artDir, 0o700)
	findingsRaw, _ := json.MarshalIndent(findings, "", "  ")
	specRaw, _ := json.MarshalIndent(specDraft, "", "  ")
	_ = os.WriteFile(filepath.Join(artDir, "findings.json"), findingsRaw, 0o600)
	_ = os.WriteFile(filepath.Join(artDir, "spec_draft.json"), specRaw, 0o600)

	job.Summary["findings"] = findings
	job.Summary["spec_draft"] = specDraft
	job.Summary["artifacts_dir"] = artDir
	persistSCMJob(job)
	if parent != nil {
		if parent.Summary == nil {
			parent.Summary = map[string]interface{}{}
		}
		parent.Summary["findings"] = findings
		parent.Summary["spec_draft"] = specDraft
		persistSCMJob(parent)
	}
	return nil
}

func buildIssueInvestigatePrompt(repo string, issue int, title, body, checkout string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Investigate GitHub issue #%d in %s.\n\n", issue, repo)
	fmt.Fprintf(&b, "Title: %s\n\nBody:\n%s\n\n", title, truncateStr(body, 8000))
	if checkout != "" {
		fmt.Fprintf(&b, "Worktree (read-only): %s\n", checkout)
	}
	b.WriteString(`Return JSON:
{
  "findings": {"classification":"bug|feature|chore|question","complexity":"low|medium|high","duplicate_of":null,"notes":"..."},
  "spec_draft": {
    "summary": "...",
    "acceptance_criteria": ["..."],
    "approach": ["..."],
    "risks": ["..."]
  }
}
`)
	return b.String()
}

func runIssuePublishAgent(job *scmJob) error {
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	parent := getSCMJob(job.RunID)
	conn := getOrHydrateConnector(job.ConnectorID)
	owner, repoName := splitOwnerRepo(job.RepoFullName)
	issueNum := job.PRNumber

	spec := map[string]interface{}{}
	if inv := childByKind(job.RunID, kindIssueInvestigate); inv != nil && inv.Summary != nil {
		if s, ok := inv.Summary["spec_draft"].(map[string]interface{}); ok {
			spec = s
		}
	}
	if len(spec) == 0 && parent != nil && parent.Summary != nil {
		if s, ok := parent.Summary["spec_draft"].(map[string]interface{}); ok {
			spec = s
		}
	}

	prefs := agentPrefsFromSummary(parent)
	comment := formatIssuePlanComment(job.RepoFullName, issueNum, job.RunID, spec, prefs)
	cid, err := githubIssueCommentCreateNum(conn, owner, repoName, issueNum, comment)
	if err != nil {
		job.Summary["comment_error"] = err.Error()
		persistSCMJob(job)
		return err
	}
	job.Summary["comment_id"] = cid
	_ = githubAddIssueLabels(conn, owner, repoName, issueNum, []string{opaLabelPlanReady})
	job.Summary["status"] = "plan_ready"
	persistSCMJob(job)
	if parent != nil {
		if parent.Summary == nil {
			parent.Summary = map[string]interface{}{}
		}
		parent.Summary["plan_comment_id"] = cid
		parent.Summary["issue_status"] = "plan_ready"
		persistSCMJob(parent)
	}
	_ = opaLabelInvestigating
	return nil
}

func formatIssuePlanComment(repo string, issue int, runID string, spec map[string]interface{}, prefs agentPrefs) string {
	var b strings.Builder
	b.WriteString("## OPA Issue Plan\n\n")
	fmt.Fprintf(&b, "Repo `%s` · Issue #%d · Run `%s`\n\n", repo, issue, runID)
	if s := strFromAny(spec["summary"]); s != "" {
		fmt.Fprintf(&b, "**Summary:** %s\n\n", s)
	}
	if ac, ok := spec["acceptance_criteria"].([]interface{}); ok && len(ac) > 0 {
		b.WriteString("**Acceptance criteria**\n")
		for _, x := range ac {
			fmt.Fprintf(&b, "- %v\n", x)
		}
		b.WriteString("\n")
	}
	if ap, ok := spec["approach"].([]interface{}); ok && len(ap) > 0 {
		b.WriteString("**Approach**\n")
		for _, x := range ap {
			fmt.Fprintf(&b, "- %v\n", x)
		}
		b.WriteString("\n")
	}
	if prefs.RequireHumanBeforeCoding || !prefs.IssueAutoImplement {
		b.WriteString("_Coding is gated. Approve for coding from the OPA Dashboard (or enable `issue_auto_implement` with `require_human_before_coding=false`)._\n")
	} else {
		b.WriteString("_`issue_auto_implement` is on — implementation will proceed after this plan._\n")
	}
	b.WriteString("\n<!-- opa-issue-plan -->\n")
	return b.String()
}

func runIssueImplementAgent(job *scmJob) error {
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	parent := getSCMJob(job.RunID)
	prefs := agentPrefsFromSummary(parent)
	if prefs.RequireHumanBeforeCoding && !strings.HasPrefix(strings.ToLower(job.Event), "manual.approve") {
		if !prefs.IssueAutoImplement {
			job.Status = "skipped"
			job.Summary["skip_reason"] = "require_human_before_coding — wait for Dashboard approve"
			persistSCMJob(job)
			return nil
		}
	}
	conn := getOrHydrateConnector(job.ConnectorID)
	owner, repoName := splitOwnerRepo(job.RepoFullName)
	issueNum := job.PRNumber
	_ = githubAddIssueLabels(conn, owner, repoName, issueNum, []string{opaLabelBuilding})

	specSummary := ""
	if parent != nil && parent.Summary != nil {
		if s, ok := parent.Summary["spec_draft"].(map[string]interface{}); ok {
			specSummary = strFromAny(s["summary"])
		}
	}
	if specSummary == "" {
		specSummary = job.Title
	}

	checkout := ""
	if prep := childByKind(job.RunID, kindIssuePrepare); prep != nil && prep.Summary != nil {
		checkout = strFromAny(prep.Summary["checkout_path"])
	}
	if checkout == "" {
		wtID := "issue-impl-" + job.ID
		abs, _, meta, err := prepareSCMWorktree(conn, job.RepoFullName, "", 0, wtID)
		if err != nil && !githubUseMockAPI(conn) {
			return err
		}
		checkout = abs
		if meta != nil {
			job.Summary["worktree"] = meta
			if rs := strFromAny(meta["resolved_sha"]); rs != "" {
				job.CommitSHA = rs
			}
		}
	}

	branch := fmt.Sprintf("opa/issue-%d-%s", issueNum, newRandomHex(4))
	prTitle := fmt.Sprintf("fix: #%d %s", issueNum, truncateStr(job.Title, 72))
	prBody := fmt.Sprintf("Closes #%d\n\n%s\n\n<!-- opa-issue-implement run=%s -->\n", issueNum, specSummary, job.RunID)

	if githubUseMockAPI(conn) {
		prNum := 8000 + issueNum%100
		prURL := fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repoName, prNum)
		job.Summary["implement"] = map[string]interface{}{
			"status": "mock_pr", "branch": branch, "pr_number": prNum, "pr_url": prURL,
			"honesty": "mock GitHub — PR not created remotely",
		}
		_ = githubAddIssueLabels(conn, owner, repoName, issueNum, []string{opaLabelPROpen})
		_, _ = githubIssueCommentCreateNum(conn, owner, repoName, issueNum,
			fmt.Sprintf("## OPA Implement\n\nOpened PR #%d (mock): %s\n", prNum, prURL))
		persistSCMJob(job)
		return nil
	}

	if err := ensureGitHubWriteAllowed(job, conn); err != nil {
		job.Summary["publish_refused"] = err.Error()
		persistSCMJob(job)
		return err
	}

	prompt := fmt.Sprintf(
		"Implement GitHub issue #%d in %s.\nTitle: %s\nPlan: %s\nWorktree: %s\nCreate minimal code changes. When done, summarize files changed.",
		issueNum, job.RepoFullName, job.Title, specSummary, checkout,
	)
	ctx := context.Background()
	res, cerr := CompleteFor(ctx, "issue_implement", aiCompleteRequest{
		System: "You are OPA Issue Implementer. Propose concrete file edits.",
		Prompt: prompt, MaxTokens: 4096,
	}, credResolveQuery{
		OrganizationID: job.OrganizationID, ProjectID: job.ProjectID, UserID: job.ActorUserID,
	})
	implNote := ""
	if cerr != nil {
		implNote = "Agent unavailable: " + cerr.Error()
	} else if res != nil {
		implNote = truncateStr(res.Text, 3000)
		job.Summary["implement_agent"] = map[string]interface{}{"provider": res.Provider, "model": res.Model}
	}

	prBody = prBody + "\n### Agent notes\n\n" + implNote + "\n"
	prNum, prURL, perr := githubCreatePullRequest(conn, owner, repoName, prTitle, prBody, branch, "main", true)
	if perr != nil {
		job.Summary["implement"] = map[string]interface{}{
			"status": "pr_create_failed", "error": perr.Error(), "branch": branch,
			"honesty": "Could not open PR (branch may be missing).",
		}
		_, _ = githubIssueCommentCreateNum(conn, owner, repoName, issueNum,
			fmt.Sprintf("## OPA Implement\n\nCould not open PR automatically: `%s`\n\nSuggested branch: `%s`\n\n%s\n",
				perr.Error(), branch, truncateStr(implNote, 1500)))
		persistSCMJob(job)
		return perr
	}
	job.Summary["implement"] = map[string]interface{}{
		"status": "pr_open", "branch": branch, "pr_number": prNum, "pr_url": prURL,
	}
	_ = githubAddIssueLabels(conn, owner, repoName, issueNum, []string{opaLabelPROpen})
	_, _ = githubIssueCommentCreateNum(conn, owner, repoName, issueNum,
		fmt.Sprintf("## OPA Implement\n\nOpened PR #%d: %s\n\n_No auto-merge — human review required._\n", prNum, prURL))
	persistSCMJob(job)
	return nil
}
