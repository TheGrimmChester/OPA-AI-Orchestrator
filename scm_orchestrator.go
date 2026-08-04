package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scmJob struct {
	ID             string                 `json:"id"`
	OrganizationID string                 `json:"organization_id"`
	ProjectID      string                 `json:"project_id"`
	ConnectorID    string                 `json:"connector_id"`
	RepoFullName   string                 `json:"repo_full_name"`
	PRNumber       int                    `json:"pr_number"`
	CommitSHA      string                 `json:"commit_sha"`
	Event          string                 `json:"event"`
	Status         string                 `json:"status"`
	SecurityRunID  string                 `json:"security_run_id"`
	AIJobID        string                 `json:"ai_job_id"`
	CheckRunIDs    map[string]int64       `json:"check_run_ids"`
	Error          string                 `json:"error"`
	Summary        map[string]interface{} `json:"summary"`
	StartedAt      string                 `json:"started_at"`
	FinishedAt     string                 `json:"finished_at"`
	Draft          bool                   `json:"draft"`
	Title          string                 `json:"title"`
	Body           string                 `json:"body"`
	// ForceAI runs OPA Review even when ai_review is off on the watched policy.
	ForceAI bool `json:"force_ai,omitempty"`
	// AIOnly skips AppSec scanners / gate; still checkouts + runs OPA Review.
	AIOnly bool `json:"ai_only,omitempty"`
	// ActorUserID is the Dashboard user who triggered a manual run (empty for
	// webhooks). Used for CLI key resolution: user → org → fail closed.
	ActorUserID string `json:"actor_user_id,omitempty"`

	// Kind/RunID/ParentID/Attempt are the run-graph fields. Continuous push/cron
	// jobs use kind=continuous. Empty/unknown kinds fail closed at process time.
	// Correctness also rides summary_json for older ClickHouse rows without ALTER columns.
	Kind     string `json:"kind,omitempty"`      // run|prepare|security|bugbot|approval|cloud|checkup|continuous
	RunID    string `json:"run_id,omitempty"`    // parent run id (children); self for kind=run
	ParentID string `json:"parent_id,omitempty"` // same as RunID for children
	Attempt  int    `json:"attempt,omitempty"`
}

func handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read error", 400)
		return
	}
	deliveryID := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	event := r.Header.Get("X-GitHub-Event")
	secret := strings.TrimSpace(os.Getenv("OPA_GITHUB_WEBHOOK_SECRET"))
	sigOK := verifyGitHubSignature(secret, raw, r.Header.Get("X-Hub-Signature-256"))
	rec := newSCMWebhookReceipt(deliveryID, event, sigOK)

	if !sigOK {
		finishWebhookReceipt(rec, "error", "Invalid X-Hub-Signature-256 (or webhook secret unset without OPA_SCM_ALLOW_UNSIGNED).", 401, "invalid signature")
		http.Error(w, "invalid signature", 401)
		return
	}
	if deliveryID != "" {
		if prev := findSCMWebhookByDelivery(deliveryID); prev != nil && prev.ID != rec.ID {
			rec.RepoFullName = prev.RepoFullName
			rec.Action = prev.Action
			rec.PRNumber = prev.PRNumber
			rec.CommitSHA = prev.CommitSHA
			rec.InstallationID = prev.InstallationID
			rec.OrganizationID = prev.OrganizationID
			rec.ProjectID = prev.ProjectID
			rec.ConnectorID = prev.ConnectorID
			rec.JobID = prev.JobID
			finishWebhookReceipt(rec, "duplicate", "Duplicate X-GitHub-Delivery — already processed as "+prev.ID+".", 200, "")
			writeJSON(w, map[string]interface{}{"ok": true, "duplicate": true, "prior_id": prev.ID})
			return
		}
	}
	switch event {
	case "ping":
		finishWebhookReceipt(rec, "ping", "GitHub ping acknowledged.", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "pong": true, "webhook_id": rec.ID})
		return
	case "pull_request":
		handlePRWebhook(w, raw, rec)
	case "push":
		handlePushWebhook(w, raw, rec)
	case "installation", "installation_repositories":
		handleInstallationWebhook(w, event, raw, rec)
	case "issues":
		handleIssuesWebhook(w, raw, rec)
	case "issue_comment":
		handleIssueCommentWebhook(w, raw, rec)
	case "label":
		handleLabelWebhook(w, raw, rec)
	default:
		finishWebhookReceipt(rec, "ignored", "Unhandled GitHub event type — no action taken.", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "ignored": event, "webhook_id": rec.ID})
	}
}

func handleInstallationWebhook(w http.ResponseWriter, event string, raw []byte, rec *scmWebhookReceipt) {
	var payload struct {
		Action       string `json:"action"`
		Installation struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
		} `json:"installation"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
		RepositoriesAdded []struct {
			FullName string `json:"full_name"`
		} `json:"repositories_added"`
		RepositoriesRemoved []struct {
			FullName string `json:"full_name"`
		} `json:"repositories_removed"`
	}
	_ = json.Unmarshal(raw, &payload)
	applyWebhookRepoMeta(rec, "", 0, "", payload.Installation.ID, payload.Action)

	repos := make([]string, 0, 8)
	for _, r := range payload.RepositoriesAdded {
		if r.FullName != "" {
			repos = append(repos, r.FullName)
		}
	}
	for _, r := range payload.Repositories {
		if r.FullName != "" {
			repos = append(repos, r.FullName)
		}
	}
	if len(repos) == 1 {
		rec.RepoFullName = repos[0]
	}

	action := strings.ToLower(strings.TrimSpace(payload.Action))
	inst := ""
	if payload.Installation.ID != 0 {
		inst = strconv.FormatInt(payload.Installation.ID, 10)
	}

	switch action {
	case "deleted", "suspend":
		finishWebhookReceipt(rec, "ignored", "Installation "+action+" recorded; watches left intact.", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "ignored": event, "action": action, "webhook_id": rec.ID})
		return
	case "removed":
		// repositories_removed — disable matching watches on this installation connector.
		conn := findConnectorByInstallation(inst)
		disabled := 0
		if conn != nil {
			for _, r := range payload.RepositoriesRemoved {
				key := conn.ID + "|" + r.FullName
				if v, ok := watchedLive.Load(key); ok {
					if wr, ok := v.(*opaWatchedRepo); ok && wr.Enabled {
						wr.Enabled = false
						wr.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
						persistWatched(wr)
						disabled++
					}
				}
			}
		}
		finishWebhookReceipt(rec, "ok", fmt.Sprintf("Disabled %d watch(es) after repository removal.", disabled), 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "disabled": disabled, "webhook_id": rec.ID})
		return
	}

	// created / added / unsuspend / new_permissions_accepted — provision + auto-watch.
	conn := ensureGitHubAppConnector(inst, payload.Installation.Account.Login)
	watched := []string{}
	if conn != nil {
		for _, repo := range repos {
			if wr := autoWatchInstalledRepo(conn, repo); wr != nil && wr.Enabled {
				watched = append(watched, repo)
			}
		}
	}
	honesty := fmt.Sprintf("Installation %s: auto-watched %d repo(s) for automatic PR checks.", action, len(watched))
	if conn == nil {
		honesty = "Installation recorded but GitHub App env not configured — could not auto-watch."
	}
	finishWebhookReceipt(rec, "ok", honesty, 200, "")
	writeJSON(w, map[string]interface{}{
		"ok": true, "event": event, "action": action, "watched": watched,
		"connector_id": func() string {
			if conn != nil {
				return conn.ID
			}
			return ""
		}(),
		"webhook_id": rec.ID,
	})
}

func handlePRWebhook(w http.ResponseWriter, raw []byte, rec *scmWebhookReceipt) {
	var payload struct {
		Action string `json:"action"`
		Number int    `json:"number"`
		PR     struct {
			Number   int    `json:"number"`
			Title    string `json:"title"`
			Body     string `json:"body"`
			Draft    bool   `json:"draft"`
			State    string `json:"state"`
			Merged   bool   `json:"merged"`
			MergedAt string `json:"merged_at"`
			Head     struct {
				SHA string `json:"sha"`
				Ref string `json:"ref"`
			} `json:"head"`
		} `json:"pull_request"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		finishWebhookReceipt(rec, "error", "Failed to parse pull_request JSON body.", 400, "bad json")
		http.Error(w, "bad json", 400)
		return
	}
	action := payload.Action
	pr := payload.PR.Number
	if pr == 0 {
		pr = payload.Number
	}
	applyWebhookRepoMeta(rec, payload.Repository.FullName, pr, payload.PR.Head.SHA, payload.Installation.ID, action)
	if scmPRIsMerged(payload.PR.Merged, payload.PR.MergedAt, payload.PR.State) {
		cancelled := cancelInFlightJobsForMergedPR(payload.Repository.FullName, pr, "pull request merged")
		msg := "Pull request is already merged — SCM job not queued."
		if len(cancelled) > 0 {
			msg = fmt.Sprintf("Pull request merged — cancelled %d in-flight job(s): %s", len(cancelled), strings.Join(cancelled, ", "))
		}
		finishWebhookReceipt(rec, "skipped", msg, 200, "")
		writeJSON(w, map[string]interface{}{
			"ok": true, "skipped": "merged", "reason": "pull request is already merged",
			"cancelled_job_ids": cancelled, "webhook_id": rec.ID,
		})
		return
	}
	if priorID, already := lookupSuccessfulAIReviewForSHA(payload.Repository.FullName, payload.PR.Head.SHA, ""); already {
		// Head is already reviewed — drop any stale in-flight work for older commits.
		_ = supersedeInFlightPRJobs(payload.Repository.FullName, pr, payload.PR.Head.SHA)
		finishWebhookReceipt(rec, "skipped", "Commit already had a successful OPA Review — SCM job not queued.", 200, "")
		writeJSON(w, map[string]interface{}{
			"ok": true, "skipped": "already_reviewed",
			"reason": "commit already reviewed successfully", "prior_job_id": priorID,
			"commit_sha": payload.PR.Head.SHA, "webhook_id": rec.ID,
		})
		return
	}
	if action != "opened" && action != "synchronize" && action != "reopened" && action != "ready_for_review" {
		finishWebhookReceipt(rec, "skipped", "PR action '"+action+"' is not actionable (only opened/synchronize/reopened/ready_for_review).", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "skipped": action, "webhook_id": rec.ID})
		return
	}
	repo := payload.Repository.FullName
	wr, conn := findWatched(repo)
	inst := ""
	if payload.Installation.ID != 0 {
		inst = strconv.FormatInt(payload.Installation.ID, 10)
	}
	// Prefer / provision GitHub App connector so Check Runs post as the bot.
	if inst != "" && githubAppConfigured() {
		if appConn := ensureGitHubAppConnector(inst, ""); appConn != nil {
			if wrApp := autoWatchInstalledRepo(appConn, repo); wrApp != nil {
				wr, conn = wrApp, appConn
			}
		}
	}
	if wr == nil {
		conn = findConnectorByInstallation(inst)
		if conn != nil {
			wr = autoWatchInstalledRepo(conn, repo)
		}
	}
	if wr == nil {
		finishWebhookReceipt(rec, "ignored", "Repo not watched and no GitHub App connector — no job queued.", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "skipped": "repo not watched", "repo": repo, "webhook_id": rec.ID})
		return
	}
	job := enqueuePRRun(wr, conn, repo, pr, payload.PR.Head.SHA, "pull_request."+action, payload.PR.Draft, payload.PR.Title, payload.PR.Body)
	rec.JobID = job.ID
	rec.OrganizationID = job.OrganizationID
	rec.ProjectID = job.ProjectID
	rec.ConnectorID = job.ConnectorID
	if job.Summary != nil {
		if sid, _ := job.Summary["stack_id"].(string); sid != "" {
			rec.StackID = sid
		}
	}
	finishWebhookReceipt(rec, "queued", "PR job queued.", 200, "")
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{"ok": true, "job_id": job.ID, "status": "queued", "webhook_id": rec.ID})
}

func handlePushWebhook(w http.ResponseWriter, raw []byte, rec *scmWebhookReceipt) {
	var payload struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Repository struct {
			FullName      string `json:"full_name"`
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		finishWebhookReceipt(rec, "error", "Failed to parse push JSON body.", 400, "bad json")
		http.Error(w, "bad json", 400)
		return
	}
	applyWebhookRepoMeta(rec, payload.Repository.FullName, 0, payload.After, payload.Installation.ID, "push")
	def := nz(payload.Repository.DefaultBranch, "main")
	if payload.Ref != "refs/heads/"+def {
		rec.Action = "non_default"
		finishWebhookReceipt(rec, "skipped", "Push to non-default branch ("+payload.Ref+") — ignored.", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "skipped": "not default branch", "webhook_id": rec.ID})
		return
	}
	rec.Action = "default"
	repo := payload.Repository.FullName
	wr, conn := findWatched(repo)
	if wr == nil {
		finishWebhookReceipt(rec, "ignored", "Repo not watched — no job queued.", 200, "")
		writeJSON(w, map[string]interface{}{"ok": true, "skipped": "repo not watched", "webhook_id": rec.ID})
		return
	}
	job := enqueueSCMJob(wr, conn, repo, 0, payload.After, "push.default", false, "default-branch scan", "")
	rec.JobID = job.ID
	rec.OrganizationID = job.OrganizationID
	rec.ProjectID = job.ProjectID
	rec.ConnectorID = job.ConnectorID
	finishWebhookReceipt(rec, "queued", "Default-branch push job queued.", 200, "")
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{"ok": true, "job_id": job.ID, "webhook_id": rec.ID})
}

func findConnectorByInstallation(inst string) *opaConnector {
	var found *opaConnector
	connectorLive.Range(func(_, v interface{}) bool {
		c, ok := v.(*opaConnector)
		if ok && c.InstallationID == inst && c.Status == "active" {
			found = c
			return false
		}
		return true
	})
	return found
}

func enqueueSCMJob(wr *opaWatchedRepo, conn *opaConnector, repo string, pr int, sha, event string, draft bool, title, body string) *scmJob {
	org, proj, connID := "", "", ""
	if wr != nil {
		org, proj, connID = wr.OrganizationID, wr.ProjectID, wr.ConnectorID
	}
	if conn != nil {
		org, proj, connID = conn.OrganizationID, conn.ProjectID, conn.ID
	}
	// Continuous path: same cancel-and-supersede as run graph when a PR number
	// is present (unusual for push/cron, but kept for safety).
	if pr > 0 {
		unlock := lockPREnqueue(repo, pr)
		defer unlock()
		supersedeInFlightPRJobs(repo, pr, sha)
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	id := loadID("scmjob", org, proj, repo, sha, event, newRandomHex(6))
	job := &scmJob{
		ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: connID,
		RepoFullName: repo, PRNumber: pr, CommitSHA: sha, Event: event,
		Kind: string(kindContinuous),
		Status: "queued", CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
		StartedAt: now, FinishedAt: now, Draft: draft, Title: title, Body: body,
	}
	scmJobLive.Store(id, job)
	persistSCMJob(job)
	return job
}

func persistSCMJob(job *scmJob) {
	if job == nil {
		return
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	if job.ForceAI {
		job.Summary["force_ai"] = true
	}
	if job.AIOnly {
		job.Summary["ai_only"] = true
	}
	if uid := strings.TrimSpace(job.ActorUserID); uid != "" {
		job.Summary["actor_user_id"] = uid
	}
	if k := strings.TrimSpace(job.Kind); k != "" {
		job.Summary["kind"] = k
	}
	if rid := strings.TrimSpace(job.RunID); rid != "" {
		job.Summary["run_id"] = rid
	}
	if pid := strings.TrimSpace(job.ParentID); pid != "" {
		job.Summary["parent_id"] = pid
	}
	if job.Attempt > 0 {
		job.Summary["attempt"] = job.Attempt
	}
	persistSCMJobFile(job)
	reconcileWebhooksForJob(job)
	if writer == nil {
		return
	}
	checkJSON, _ := json.Marshal(job.CheckRunIDs)
	sumJSON, _ := json.Marshal(job.Summary)
	// Bump finished_at on active status writes so ReplacingMergeTree keeps latest.
	chFinished := job.FinishedAt
	switch job.Status {
	case "queued", "waiting", "running":
		chFinished = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"id": job.ID, "organization_id": job.OrganizationID, "project_id": job.ProjectID,
		"connector_id": job.ConnectorID, "repo_full_name": job.RepoFullName,
		"pr_number": job.PRNumber, "commit_sha": job.CommitSHA, "event": job.Event,
		"status": job.Status, "security_run_id": job.SecurityRunID, "ai_job_id": job.AIJobID,
		"check_run_ids": string(checkJSON), "error": job.Error, "summary_json": string(sumJSON),
		"started_at": job.StartedAt, "finished_at": chFinished,
	})
	writer.insertAsync("scm_jobs", append(payload, '\n'))
}

func getSCMJob(id string) *scmJob {
	if v, ok := scmJobLive.Load(id); ok {
		if j, ok := v.(*scmJob); ok {
			return j
		}
	}
	if job := loadSCMJobFile(id); job != nil {
		scmJobLive.Store(job.ID, job)
		return job
	}
	return nil
}

var scmJobCancel sync.Map // jobID -> context.CancelFunc
var scmJobCtx sync.Map    // jobID -> context.Context

func scmJobIsCancelled(id string) bool {
	job := getSCMJob(id)
	return job != nil && job.Status == "cancelled"
}

func registerSCMJobCancel(id string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	scmJobCancel.Store(id, cancel)
	scmJobCtx.Store(id, ctx)
	return ctx, cancel
}

func scmJobContext(id string) context.Context {
	if v, ok := scmJobCtx.Load(id); ok {
		if c, ok := v.(context.Context); ok && c != nil {
			return c
		}
	}
	return context.Background()
}

func clearSCMJobCancel(id string) {
	if v, ok := scmJobCancel.Load(id); ok {
		scmJobCancel.Delete(id)
		if c, ok := v.(context.CancelFunc); ok {
			c()
		}
	}
	scmJobCtx.Delete(id)
}

// cancelSCMJob marks a live job cancelled when it is still queued/waiting/running.
// Running work is interrupted best-effort via the registered cancel func; stack drain
// skips cancelled jobs so waiting items can proceed.
func cancelSCMJob(id string) (*scmJob, string, int) {
	return cancelSCMJobWithReason(id, "cancelled")
}

func cancelSCMJobWithReason(id, reason string) (*scmJob, string, int) {
	job := getSCMJob(id)
	if job == nil {
		return nil, "not found", 404
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "cancelled"
	}
	switch job.Status {
	case "queued", "waiting", "running":
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		job.Status = "cancelled"
		job.FinishedAt = now
		job.Error = reason
		if job.Summary == nil {
			job.Summary = map[string]interface{}{}
		}
		job.Summary["cancel_reason"] = reason
		persistSCMJob(job)
		if v, ok := scmJobCancel.Load(id); ok {
			if c, ok := v.(context.CancelFunc); ok {
				c()
			}
		}
		// Parent kind=run must cascade — otherwise approval/cloud keep mutating GitHub.
		if agentKind(job.Kind) == kindRun {
			cascadeCancelRunChildren(id, reason)
		}
		// Close open Check Runs immediately (skipped for supersede, cancelled otherwise).
		// Snapshot ids — processors may still race a late update with the same fields.
		go closeSCMJobGitHubChecks(job, reason)
		go func(jobID, runID, kind string) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = teardownJobContainers(ctx, jobID)
			_ = removeJobInternalNetwork(ctx, jobID)
			// Parent run cancel also reaps boxes labeled opa.run=<runID> (children
			// that shared the run network/layout) and drops the shared network.
			if agentKind(kind) == kindRun {
				rid := nz(runID, jobID)
				_ = teardownJobContainersByRun(ctx, rid)
				_ = removeJobInternalNetwork(ctx, rid)
			}
		}(id, job.RunID, job.Kind)
		refreshStacksForJob(id)
		return job, "", 0
	case "cancelled":
		return job, "", 0
	default:
		return job, "job not cancellable in status " + job.Status, 409
	}
}

// cascadeCancelRunChildren cancels (or drains) every child of a kind=run parent.
// Cloud mid-push drains like supersede — never hard-kill a land in flight.
func cascadeCancelRunChildren(runID, reason string) {
	for _, c := range listRunChildren(runID) {
		if c == nil {
			continue
		}
		if agentKind(c.Kind) == kindCloud && (c.Status == "running" || c.Status == "waiting") {
			if c.Summary == nil {
				c.Summary = map[string]interface{}{}
			}
			c.Summary["supersede_drain"] = true
			c.Summary["cancel_drain"] = reason
			persistSCMJob(c)
			continue
		}
		switch c.Status {
		case "queued", "waiting", "running":
			_, _, _ = cancelSCMJobWithReason(c.ID, reason)
		}
	}
}

// cancelInFlightJobsForMergedPR cancels queued/waiting/running SCM jobs (and related
// Auto-fix runs) for repo+PR when that pull request has been merged.
func cancelInFlightJobsForMergedPR(repo string, pr int, reason string) []string {
	if strings.TrimSpace(reason) == "" {
		reason = "pull request merged"
	}
	return cancelInFlightJobsForPR(repo, pr, reason)
}

// cancelInFlightJobsForPR cancels every in-flight SCM job for repo+PR.
// Top-level jobs (ParentID empty) are cancelled first so kind=run parents cascade
// to children (cloud drains mid-push). Remaining orphan children are cancelled after.
func cancelInFlightJobsForPR(repo string, pr int, reason string) []string {
	repo = strings.TrimSpace(repo)
	if repo == "" || pr <= 0 {
		return nil
	}
	if strings.TrimSpace(reason) == "" {
		reason = "cancelled"
	}
	var topLevel, children []string
	scmJobLive.Range(func(_, v interface{}) bool {
		job, ok := v.(*scmJob)
		if !ok || job == nil {
			return true
		}
		if job.PRNumber != pr || !strings.EqualFold(job.RepoFullName, repo) {
			return true
		}
		st := strings.ToLower(job.Status)
		if st != "queued" && st != "waiting" && st != "running" {
			return true
		}
		if strings.TrimSpace(job.ParentID) != "" {
			children = append(children, job.ID)
		} else {
			topLevel = append(topLevel, job.ID)
		}
		return true
	})
	var ids []string
	for _, id := range topLevel {
		if _, errMsg, _ := cancelSCMJobWithReason(id, reason); errMsg == "" {
			ids = append(ids, id)
		}
	}
	for _, id := range children {
		j := getSCMJob(id)
		if j == nil {
			continue
		}
		st := strings.ToLower(j.Status)
		if st != "queued" && st != "waiting" && st != "running" {
			continue
		}
		// Orphan cloud mid-push: drain, don't hard-kill.
		if agentKind(j.Kind) == kindCloud && (st == "running" || st == "waiting") {
			if j.Summary == nil {
				j.Summary = map[string]interface{}{}
			}
			j.Summary["supersede_drain"] = true
			j.Summary["cancel_drain"] = reason
			persistSCMJob(j)
			ids = append(ids, id)
			continue
		}
		if _, errMsg, _ := cancelSCMJobWithReason(id, reason); errMsg == "" {
			ids = append(ids, id)
		}
	}
	cancelInFlightAutoFixesForPR(repo, pr, reason)
	return ids
}

// supersedeInFlightPRJobs cancels every in-flight job for repo+PR that is not
// already analyzing newSHA, so only the newly enqueued head commit runs. Same-SHA
// re-triggers (manual AI review + webhook) must not cancel the live run mid-approval.
func supersedeInFlightPRJobs(repo string, pr int, newSHA string) []string {
	newSHA = strings.TrimSpace(newSHA)
	reason := "Superseded by " + newSHA
	if reason == "Superseded by " {
		reason = "Superseded by newer push"
	}
	return cancelInFlightJobsForPRExceptSHA(repo, pr, reason, newSHA)
}

// cancelInFlightJobsForPRExceptSHA is cancelInFlightJobsForPR but leaves jobs
// whose CommitSHA matches keepSHA (case-insensitive). Empty keepSHA cancels all.
func cancelInFlightJobsForPRExceptSHA(repo string, pr int, reason, keepSHA string) []string {
	repo = strings.TrimSpace(repo)
	keepSHA = strings.TrimSpace(keepSHA)
	if repo == "" || pr <= 0 {
		return nil
	}
	if strings.TrimSpace(reason) == "" {
		reason = "cancelled"
	}
	var topLevel, children []string
	scmJobLive.Range(func(_, v interface{}) bool {
		job, ok := v.(*scmJob)
		if !ok || job == nil {
			return true
		}
		if job.PRNumber != pr || !strings.EqualFold(job.RepoFullName, repo) {
			return true
		}
		st := strings.ToLower(job.Status)
		if st != "queued" && st != "waiting" && st != "running" {
			return true
		}
		if keepSHA != "" && strings.EqualFold(strings.TrimSpace(job.CommitSHA), keepSHA) {
			return true
		}
		if strings.TrimSpace(job.ParentID) != "" {
			children = append(children, job.ID)
		} else {
			topLevel = append(topLevel, job.ID)
		}
		return true
	})
	var ids []string
	for _, id := range topLevel {
		if _, errMsg, _ := cancelSCMJobWithReason(id, reason); errMsg == "" {
			ids = append(ids, id)
		}
	}
	for _, id := range children {
		j := getSCMJob(id)
		if j == nil {
			continue
		}
		st := strings.ToLower(j.Status)
		if st != "queued" && st != "waiting" && st != "running" {
			continue
		}
		if keepSHA != "" && strings.EqualFold(strings.TrimSpace(j.CommitSHA), keepSHA) {
			continue
		}
		if agentKind(j.Kind) == kindCloud && (st == "running" || st == "waiting") {
			if j.Summary == nil {
				j.Summary = map[string]interface{}{}
			}
			j.Summary["supersede_drain"] = true
			j.Summary["cancel_drain"] = reason
			persistSCMJob(j)
			ids = append(ids, id)
			continue
		}
		if _, errMsg, _ := cancelSCMJobWithReason(id, reason); errMsg == "" {
			ids = append(ids, id)
		}
	}
	cancelInFlightAutoFixesForPR(repo, pr, reason)
	return ids
}

func cancelInFlightAutoFixesForPR(repo string, pr int, reason string) {
	autoFixLive.Range(func(_, v interface{}) bool {
		fix, ok := v.(*opaAutoFixJob)
		if !ok || fix == nil {
			return true
		}
		if !strings.EqualFold(fix.RepoFullName, repo) {
			return true
		}
		if fix.BasePRNumber != pr && fix.PRNumber != pr {
			return true
		}
		st := strings.ToLower(fix.Status)
		if st != "queued" && st != "running" {
			return true
		}
		fix.Status = "cancelled"
		fix.Error = reason
		fix.Honesty = strings.TrimSpace(fix.Honesty + "; cancelled — " + reason)
		fix.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
		autoFixLive.Store(fix.ID, fix)
		if parent := getSCMJob(fix.ParentJobID); parent != nil {
			persistAutoFixOnParent(parent, fix)
		}
		return true
	})
}

func refreshStacksForJob(jobID string) {
	reviewStackLive.Range(func(_, v interface{}) bool {
		stack, ok := v.(*opaReviewStack)
		if !ok || stack == nil {
			return true
		}
		for _, it := range stack.Items {
			if it.JobID == jobID {
				refreshOPAReviewStack(stack)
				break
			}
		}
		return true
	})
}

func scmJobStatusRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return 0
	case "queued":
		return 1
	case "waiting":
		return 2
	case "failed", "error":
		return 3
	case "cancelled":
		return 4
	case "completed":
		return 5
	default:
		return 6
	}
}

func sortSCMJobsActiveFirst(list []*scmJob) {
	sort.SliceStable(list, func(i, j int) bool {
		ri, rj := scmJobStatusRank(list[i].Status), scmJobStatusRank(list[j].Status)
		if ri != rj {
			return ri < rj
		}
		// Newest first within the same status bucket.
		return list[i].StartedAt > list[j].StartedAt
	})
}

func handleSCMJobsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	a := actorFromRequest(r)
	requestedConnector := strings.TrimSpace(r.URL.Query().Get("connector_id"))
	connectorFilter, resolvedFromPAT := resolveWebhookConnectorFilter(requestedConnector)
	list := []*scmJob{}
	counts := map[string]int{}
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || !canSeeSCMJob(a, j, connectorFilter) {
			return true
		}
		list = append(list, j)
		st := strings.TrimSpace(j.Status)
		if st == "" {
			st = "unknown"
		}
		counts[st]++
		return true
	})
	sortSCMJobsActiveFirst(list)
	total := len(list)
	limit := clampInt(atoiDefault(r.URL.Query().Get("limit"), 50), 1, 500)
	if len(list) > limit {
		list = list[:limit]
	}
	filter := "all"
	honesty := "Showing jobs across organizations (tenant picker = All)."
	if connectorFilter != "" {
		filter = "connector:" + connectorFilter
		honesty = "Filtered to connector " + connectorFilter + " (tenant org filter bypassed for this connector's job log)."
		if resolvedFromPAT != "" && resolvedFromPAT != connectorFilter {
			honesty = "PAT " + resolvedFromPAT + " — showing sibling App install " + connectorFilter + " jobs (tenant org filter bypassed)."
		}
	} else if a.OrganizationID != "" {
		filter = a.OrganizationID
		honesty = "Filtered to organization " + a.OrganizationID + ". App webhook jobs often land on the org that owns the GitHub App install — pick that connector if this list looks empty while reviews are running."
	} else if authEnforced {
		honesty = "Scoped to default-org / default-project (missing tenant headers). Send X-Organization-ID / X-Project-ID to select another tenant."
		filter = defaultOrgID
	}
	writeJSON(w, map[string]interface{}{
		"jobs": list, "total": total, "counts": counts, "limit": limit,
		"organization_id":        a.OrganizationID,
		"connector_id":           connectorFilter,
		"requested_connector_id": requestedConnector,
		"tenant_filter":          filter,
		"honesty":                honesty,
	})
}

// canSeeSCMJob applies tenant visibility for SCM / PR jobs.
//
//   - Concrete org selected → that org only (legacy empty-org rows count as default-org)
//   - Auth off + empty org → everything
//   - Auth on + empty org → fail closed (HTTP actors use WriteTenant / default-org)
//   - connectorFilter set → that connector's jobs even across org (admin), or if
//     non-admin's selected org matches the job/connector org
func canSeeSCMJob(a credActor, j *scmJob, connectorFilter string) bool {
	if j == nil {
		return false
	}
	if cf := strings.TrimSpace(connectorFilter); cf != "" {
		if strings.TrimSpace(j.ConnectorID) != cf {
			return false
		}
		if !authEnforced || a.isAdmin() {
			return true
		}
		conn := getConnector(cf)
		connOrg := ""
		if conn != nil {
			connOrg = strings.TrimSpace(nz(conn.OrganizationID, defaultOrgID))
		}
		jobOrg := strings.TrimSpace(j.OrganizationID)
		if jobOrg == "" {
			jobOrg = defaultOrgID
		}
		sel := strings.TrimSpace(a.OrganizationID)
		if sel == "" {
			return false
		}
		return sel == connOrg || sel == jobOrg
	}
	jobOrg := strings.TrimSpace(j.OrganizationID)
	if jobOrg == "" {
		jobOrg = defaultOrgID
	}
	if sel := strings.TrimSpace(a.OrganizationID); sel != "" {
		return jobOrg == sel
	}
	if !authEnforced {
		return true
	}
	// Auth on + empty org should not reach here (actorFromRequest → WriteTenant).
	// Fail closed: never dump all tenants.
	return false
}

// handleSCMJobsResume POST /api/scm/jobs/resume — one-shot kick after recreate/stall:
// resumes incomplete stack drains and re-dispatches orphaned non-stack queued jobs.
func handleSCMJobsResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	stacks, queued := resumeSCMProcessing()
	writeJSON(w, map[string]interface{}{
		"ok": true, "stacks_resumed": stacks, "queued_dispatched": queued,
		"concurrency": scmProcessConcurrency(),
		"honesty":     "Re-dispatches non-stack queued jobs and incomplete stack drains. processSCMJob is concurrency-bounded and dedupes in-flight IDs.",
	})
}

func handleSCMJobSub(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scm/jobs/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "not found", 404)
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		job := getSCMJob(id)
		if job == nil {
			http.Error(w, "not found", 404)
			return
		}
		a := actorFromRequest(r)
		if !canSeeSCMJob(a, job, "") && !canSeeSCMJob(a, job, strings.TrimSpace(job.ConnectorID)) {
			http.Error(w, "not found", 404)
			return
		}
		view := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("view")))
		if view == "" {
			view = "ops"
		}
		writeJSON(w, runPRRunAPIViewWithView(job, view))
		return
	}
	if len(parts) >= 3 && parts[1] == "artifacts" && r.Method == http.MethodGet {
		job := getSCMJob(id)
		if job == nil {
			http.Error(w, "not found", 404)
			return
		}
		a := actorFromRequest(r)
		if !canSeeSCMJob(a, job, "") && !canSeeSCMJob(a, job, strings.TrimSpace(job.ConnectorID)) {
			http.Error(w, "not found", 404)
			return
		}
		name := parts[2]
		raw, err := readJobArtifact(id, name)
		if err != nil {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
		return
	}
	if len(parts) >= 2 && parts[1] == "retry" && r.Method == http.MethodPost {
		job := getSCMJob(id)
		if job == nil {
			http.Error(w, "not found", 404)
			return
		}
		a := actorFromRequest(r)
		if !canSeeSCMJob(a, job, "") && !canSeeSCMJob(a, job, strings.TrimSpace(job.ConnectorID)) {
			http.Error(w, "not found", 404)
			return
		}
		// Explicit Retry from the dashboard must re-run (bypass already-reviewed
		// skip) and carry the signed-in user so personal CLI keys resolve.
		if uid := strings.TrimSpace(a.Username); uid != "" {
			job.ActorUserID = uid
		}
		job.ForceAI = true
		// Legacy PR rows may lack kind=run — upgrade before re-dispatch.
		if strings.TrimSpace(job.Kind) == "" && shouldEnqueuePRRun(job.Event, job.PRNumber) {
			job.Kind = string(kindRun)
			if strings.TrimSpace(job.RunID) == "" {
				job.RunID = job.ID
			}
		}
		if strings.TrimSpace(job.Kind) == "" {
			ev := strings.ToLower(strings.TrimSpace(job.Event))
			if strings.HasPrefix(ev, "push.") || strings.HasPrefix(ev, "cron.") {
				job.Kind = string(kindContinuous)
			}
		}
		job.Status = "queued"
		job.Error = ""
		job.FinishedAt = ""
		if job.Summary == nil {
			job.Summary = map[string]interface{}{}
		}
		if job.ActorUserID != "" {
			job.Summary["actor_user_id"] = job.ActorUserID
		}
		delete(job.Summary, "skip_reason")
		delete(job.Summary, "prior_reviewed_job_id")
		persistSCMJob(job)
		go processSCMJob(id)
		writeJSON(w, map[string]interface{}{
			"ok": true, "job_id": id, "status": "queued",
			"force_ai":       true,
			"kind":           job.Kind,
			"actor_user_id":  job.ActorUserID,
			"cursor_key_set": resolveCursorAPIKey(job.OrganizationID, job.ProjectID, job.ActorUserID) != "",
			"honesty":        "Retry stamps actor_user_id from the signed-in user, upgrades empty kind for legacy PR/push rows, and sets force_ai so already-reviewed SHAs re-run. Personal CLI keys apply; webhook-origin jobs without an actor still need an org key under Account → Organization.",
		})
		return
	}
	if len(parts) >= 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		job, errMsg, code := cancelSCMJob(id)
		if code != 0 {
			http.Error(w, errMsg, code)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "job_id": id, "status": job.Status})
		return
	}
	if len(parts) >= 2 && parts[1] == "ai-review" && r.Method == http.MethodPost {
		job := getSCMJob(id)
		if job == nil {
			http.Error(w, "not found", 404)
			return
		}
		if job.PRNumber <= 0 {
			http.Error(w, "job has no pr_number — cannot re-run AI only", 400)
			return
		}
		handleSCMAIReviewFromJob(w, r, job)
		return
	}
	if len(parts) >= 2 && (parts[1] == "auto-fix" || parts[1] == "autofix") && r.Method == http.MethodPost {
		job := getSCMJob(id)
		if job == nil {
			http.Error(w, "not found", 404)
			return
		}
		handleSCMJobAutoFix(w, r, job)
		return
	}
	if len(parts) >= 2 && (parts[1] == "approve-coding" || parts[1] == "approve_coding") && r.Method == http.MethodPost {
		job := getSCMJob(id)
		if job == nil {
			http.Error(w, "not found", 404)
			return
		}
		a := actorFromRequest(r)
		if !canSeeSCMJob(a, job, "") && !canSeeSCMJob(a, job, strings.TrimSpace(job.ConnectorID)) {
			http.Error(w, "not found", 404)
			return
		}
		if agentKind(job.Kind) != kindIssueRun {
			http.Error(w, "approve-coding only for issue_run jobs", 400)
			return
		}
		if uid := strings.TrimSpace(a.Username); uid != "" {
			job.ActorUserID = uid
		}
		child, err := enqueueIssueImplement(job)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		go processSCMJob(job.ID)
		writeJSON(w, map[string]interface{}{
			"ok": true, "job_id": job.ID, "implement_job_id": child.ID, "status": child.Status,
			"honesty": "Implement child enqueued; no auto-merge — human review still required on the PR.",
		})
		return
	}
	http.Error(w, "not found", 404)
}

// handleSCMAIReview enqueues a manual OPA Review job for a selected PR.
// POST /api/scm/ai-review  body: { repo_full_name, pr_number, connector_id?, force?, ai_only?, sha?, allow_unwatched? }
func handleSCMAIReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		RepoFullName    string `json:"repo_full_name"`
		Repo            string `json:"repo"` // alias
		PRNumber        int    `json:"pr_number"`
		PR              int    `json:"pr"` // alias
		ConnectorID     string `json:"connector_id"`
		Force           *bool  `json:"force"` // default true for manual runs
		AIOnly          bool   `json:"ai_only"`
		SHA             string `json:"sha"`
		AllowUnwatched  bool   `json:"allow_unwatched"`
		Title           string `json:"title"`
		Draft           bool   `json:"draft"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	repo := strings.TrimSpace(nz(body.RepoFullName, body.Repo))
	pr := body.PRNumber
	if pr == 0 {
		pr = body.PR
	}
	if repo == "" || pr <= 0 {
		http.Error(w, "repo_full_name and pr_number required", 400)
		return
	}
	force := true
	if body.Force != nil {
		force = *body.Force
	}
	actor := actorFromRequest(r)
	job, errMsg, code := enqueueManualAIReview(repo, pr, body.ConnectorID, body.SHA, body.Title, body.Draft, force, body.AIOnly, body.AllowUnwatched, actor.Username)
	if errMsg != "" {
		http.Error(w, errMsg, code)
		return
	}
	applied := resolveReviewContextsForRepo(job.OrganizationID, job.ProjectID, repo)
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{
		"ok": true, "job_id": job.ID, "status": "queued",
		"repo_full_name": repo, "pr_number": pr,
		"force_ai": job.ForceAI, "ai_only": job.AIOnly,
		"cursor_key_set": resolveCursorAPIKey(job.OrganizationID, job.ProjectID, job.ActorUserID) != "",
		"skip_cursor_ai": envOr("SKIP_CURSOR_AI", "0") == "1",
		"review_contexts": summarizeAppliedContexts(applied),
		"honesty":         "Manual OPA Review — Check Runs need GitHub App (PAT often cannot create checks). SKIP_CURSOR_AI=1 still completes with ai.status=skipped. Reviewer contexts: full primary for this repo + linked awareness; related repos are shallow-cloned under job/related/. Findings sync as inline PR comments (add/update/resolve on re-run); global body is a short résumé upserted in place.",
	})
}

func handleSCMAIReviewFromJob(w http.ResponseWriter, r *http.Request, src *scmJob) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		Force  *bool `json:"force"`
		AIOnly *bool `json:"ai_only"`
	}
	_ = json.Unmarshal(raw, &body)
	force := true
	if body.Force != nil {
		force = *body.Force
	}
	aiOnly := true
	if body.AIOnly != nil {
		aiOnly = *body.AIOnly
	}
	actor := actorFromRequest(r)
	job, errMsg, code := enqueueManualAIReview(src.RepoFullName, src.PRNumber, src.ConnectorID, src.CommitSHA, src.Title, src.Draft, force, aiOnly, true, actor.Username)
	if errMsg != "" {
		http.Error(w, errMsg, code)
		return
	}
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{
		"ok": true, "job_id": job.ID, "status": "queued",
		"source_job_id": src.ID, "ai_only": job.AIOnly, "force_ai": job.ForceAI,
	})
}

func enqueueManualAIReview(repo string, pr int, connectorID, sha, title string, draft, force, aiOnly, allowUnwatched bool, actorUserID string) (*scmJob, string, int) {
	wr, conn := findWatched(repo)
	if connectorID != "" {
		if c := getOrHydrateConnector(connectorID); c != nil && c.Status != "deleted" {
			conn = c
		}
	}
	if wr == nil && conn != nil {
		// Prefer watched row for this connector+repo (may be disabled).
		if key := conn.ID + "|" + repo; true {
			if v, ok := watchedLive.Load(key); ok {
				if w, ok := v.(*opaWatchedRepo); ok {
					wr = w
				}
			}
		}
	}
	if wr == nil && !allowUnwatched {
		if conn == nil {
			return nil, "repo not watched and no connector_id — watch the repo or pass connector_id with allow_unwatched", 404
		}
		// One-off: bind ephemeral watched policy with ai_review on.
		wr = upsertWatched(conn.OrganizationID, conn.ProjectID, conn.ID, repo, "", true, defaultWatchedChecks(), "auto", "high", false, false, 0)
	} else if wr == nil && allowUnwatched {
		if conn == nil {
			return nil, "connector_id required for unwatched one-off", 400
		}
		wr = upsertWatched(conn.OrganizationID, conn.ProjectID, conn.ID, repo, "", true, defaultWatchedChecks(), "auto", "high", false, false, 0)
	}
	if conn == nil {
		conn = getOrHydrateConnector(wr.ConnectorID)
	}
	if conn == nil {
		return nil, "connector not found — hydrate failed", 404
	}

	owner, repoName := splitOwnerRepo(repo)
	prBody := ""
	if meta, err := githubGetPull(conn, owner, repoName, pr); err == nil && meta != nil {
		if scmPRIsMerged(meta.Merged, meta.MergedAt, meta.State) {
			return nil, "pull request is already merged — review skipped", 409
		}
		if sha == "" {
			sha = meta.HeadSHA
		}
		if title == "" {
			title = meta.Title
		}
		draft = meta.Draft
		prBody = meta.Body
	}
	if sha == "" {
		sha = "manual-" + newRandomHex(8)
	}
	// Force (manual / Auto-fix follow-up) may re-review the same SHA so
	// comments can close, auto_merge_confidence refresh, and APPROVE fire.
	if !force {
		if priorID, already := lookupSuccessfulAIReviewForSHA(repo, sha, ""); already {
			return nil, fmt.Sprintf("commit already reviewed successfully — review skipped (prior job %s)", priorID), 409
		}
	}
	if title == "" {
		title = fmt.Sprintf("Manual OPA Review PR #%d", pr)
	}

	event := "manual.ai_review"
	if aiOnly {
		event = "manual.ai_only"
	}
	job := enqueuePRRun(wr, conn, repo, pr, sha, event, draft, title, prBody)
	job.ForceAI = force
	job.AIOnly = aiOnly
	job.ActorUserID = strings.TrimSpace(actorUserID)
	persistSCMJob(job)
	for _, c := range listRunChildren(job.ID) {
		c.ForceAI = force
		c.AIOnly = aiOnly
		c.ActorUserID = job.ActorUserID
		persistSCMJob(c)
	}
	return job, "", 0
}

func handleSCMSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		Repo    string `json:"repo"`
		PR      int    `json:"pr"`
		SHA     string `json:"sha"`
		Service string `json:"service"`
		Profile string `json:"profile"`
		Draft   bool   `json:"draft"`
	}
	_ = json.Unmarshal(raw, &body)
	repo := nz(body.Repo, "local/smoke-repo")
	sha := nz(body.SHA, "deadbeef"+newRandomHex(8))
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	connID := loadID("conn", org, proj, "sim", "local")
	if getConnector(connID) == nil {
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		c := &opaConnector{
			ID: connID, OrganizationID: org, ProjectID: proj, Kind: "github_pat",
			AccountLogin: "simulate", Status: "active", MetaJSON: `{"simulate":true}`,
			CreatedAt: now, UpdatedAt: now,
		}
		connectorLive.Store(connID, c)
		persistConnector(c)
	}
	checks := defaultWatchedChecks()
	wr := upsertWatched(org, proj, connID, repo, "", true, checks, nz(body.Profile, "auto"), "high", false, false, 0)
	if body.Service != "" {
		wr.ServiceName = body.Service
	}
	os.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	job := enqueuePRRun(wr, getConnector(connID), repo, body.PR, sha, "simulate", body.Draft, "simulated PR", "")
	go processSCMJob(job.ID)
	resp := map[string]interface{}{"ok": true, "job_id": job.ID, "repo": repo, "sha": sha}
	if job.Kind != "" {
		resp["kind"] = job.Kind
		resp["run_id"] = job.RunID
		if ids, ok := job.Summary["child_ids"]; ok {
			resp["child_ids"] = ids
		}
	}
	writeJSON(w, resp)
}

// scmProcessing tracks job IDs with an active processSCMJob goroutine so boot/admin
// resume and enqueue cannot run the same job twice concurrently.
var scmProcessing sync.Map // jobID -> struct{}

// shouldSkipSCMJobForMergedPR returns true when a PR-scoped job targets a merged PR.
// Simulate/mock and non-PR events are never skipped here. Fail-open if GitHub is unreachable.
func shouldSkipSCMJobForMergedPR(job *scmJob) bool {
	if job == nil || job.PRNumber <= 0 {
		return false
	}
	ev := strings.ToLower(job.Event)
	if strings.HasPrefix(ev, "push.") || strings.HasPrefix(ev, "cron.") || strings.HasPrefix(ev, "simulate") {
		return false
	}
	conn := getOrHydrateConnector(job.ConnectorID)
	if conn == nil {
		if _, c := findWatched(job.RepoFullName); c != nil {
			conn = c
		}
	}
	if conn == nil || githubUseMockAPI(conn) {
		return false
	}
	owner, repoName := splitOwnerRepo(job.RepoFullName)
	if owner == "" || repoName == "" {
		return false
	}
	meta, err := githubGetPull(conn, owner, repoName, job.PRNumber)
	if err != nil || meta == nil {
		return false
	}
	return scmPRIsMerged(meta.Merged, meta.MergedAt, meta.State)
}

// shouldSkipSCMJobForAlreadyReviewed returns true when this repo+commit SHA already
// had a successful OPA Review. Push/cron/simulate are never skipped here.
// ForceAI jobs (manual re-pass / Auto-fix follow-up) are never skipped so they can
// close fixed comments, refresh auto_merge_confidence, and APPROVE when clean.
func shouldSkipSCMJobForAlreadyReviewed(job *scmJob) (priorJobID string, skip bool) {
	if job == nil {
		return "", false
	}
	if job.ForceAI {
		return "", false
	}
	ev := strings.ToLower(job.Event)
	if strings.HasPrefix(ev, "push.") || strings.HasPrefix(ev, "cron.") || strings.HasPrefix(ev, "simulate") {
		return "", false
	}
	sha := strings.TrimSpace(job.CommitSHA)
	if scmPlaceholderCommitSHA(sha) {
		return "", false
	}
	return lookupSuccessfulAIReviewForSHA(job.RepoFullName, sha, job.ID)
}

func processSCMJob(jobID string) {
	job := getSCMJob(jobID)
	if job == nil {
		return
	}
	// One-shot cutover: empty-kind rows from before the run/continuous split.
	if strings.TrimSpace(job.Kind) == "" {
		ev := strings.ToLower(strings.TrimSpace(job.Event))
		if strings.HasPrefix(ev, "push.") || strings.HasPrefix(ev, "cron.") {
			job.Kind = string(kindContinuous)
			persistSCMJob(job)
		} else if shouldEnqueuePRRun(job.Event, job.PRNumber) {
			job.Kind = string(kindRun)
			if strings.TrimSpace(job.RunID) == "" {
				job.RunID = job.ID
			}
			persistSCMJob(job)
		}
	}
	switch scmJobProcessor(agentKind(strings.TrimSpace(job.Kind))) {
	case "run":
		processPRRun(jobID)
	case "agent":
		processAgentChild(jobID)
	case "continuous":
		processContinuousSCMJob(jobID)
	default:
		failClosedUnknownSCMJobKind(job)
	}
}

// scmJobProcessor selects which processor handles a job kind. Pure helper so
// dispatch wiring is unit-testable without running agents.
func scmJobProcessor(k agentKind) string {
	switch {
	case k == kindRun || k == kindIssueRun || k == kindRoadmapRun:
		return "run"
	case isAgentChildKind(k):
		return "agent"
	case k == kindContinuous:
		return "continuous"
	default:
		return "unknown"
	}
}

// isAgentChildKind reports kinds handled by processAgentChild (not the run
// parent and not the continuous monolith).
func isAgentChildKind(k agentKind) bool {
	switch k {
	case kindPrepare, kindSecurity, kindBugbot, kindCheckup, kindApproval, kindCloud,
		kindIssuePrepare, kindIssueInvestigate, kindIssuePublish, kindIssueImplement,
		kindRoadmapGenerate, kindRoadmapPublish:
		return true
	default:
		return false
	}
}

// failClosedUnknownSCMJobKind marks empty/unknown kinds failed instead of
// silently running the continuous pipeline.
func failClosedUnknownSCMJobKind(job *scmJob) {
	if job == nil {
		return
	}
	switch job.Status {
	case "cancelled", "completed", "failed", "error", "skipped":
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	kind := strings.TrimSpace(job.Kind)
	if kind == "" {
		job.Error = "empty job kind — run graph required for PR jobs; continuous scans must use kind=continuous"
	} else {
		job.Error = fmt.Sprintf("unknown job kind %q — refused", kind)
	}
	job.Status = "failed"
	job.FinishedAt = now
	if job.StartedAt == "" {
		job.StartedAt = now
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	job.Summary["fail_reason"] = "unknown_kind"
	persistSCMJob(job)
}

func processContinuousSCMJob(jobID string) {
	if _, loaded := scmProcessing.LoadOrStore(jobID, struct{}{}); loaded {
		return
	}
	defer scmProcessing.Delete(jobID)

	acquireSCMProcessSlot()
	defer releaseSCMProcessSlot()
	job := getSCMJob(jobID)
	if job == nil {
		return
	}
	switch job.Status {
	case "cancelled", "completed", "failed", "error", "running", "skipped":
		// Terminal, or another path already marked running (should be rare with scmProcessing).
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

	jobCtx, cancel := registerSCMJobCancel(jobID)
	_ = jobCtx // threaded to children via scmJobContext(jobID)
	defer func() {
		cancel()
		clearSCMJobCancel(jobID)
	}()

	job.Status = "running"
	job.StartedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	persistSCMJob(job)

	finishIfCancelled := func() bool {
		if !scmJobIsCancelled(jobID) {
			return false
		}
		// cancelSCMJob already set status; ensure finished_at is set.
		if j := getSCMJob(jobID); j != nil {
			if j.FinishedAt == "" {
				j.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
				persistSCMJob(j)
			}
		}
		return true
	}
	if finishIfCancelled() {
		return
	}

	wr, conn := findWatched(job.RepoFullName)
	if conn == nil {
		conn = getOrHydrateConnector(job.ConnectorID)
	}
	owner, repoName := splitOwnerRepo(job.RepoFullName)

	var checks []string
	profile := "auto"
	minSev := "high"
	aiBlocking := false
	autoRequestReviewer := false
	autoApproveMinScore := 0
	service := strings.ReplaceAll(job.RepoFullName, "/", "-")
	if wr != nil {
		_ = json.Unmarshal([]byte(wr.ChecksJSON), &checks)
		profile = nz(wr.Profile, "auto")
		minSev = nz(wr.MinSeverity, "high")
		aiBlocking = wr.AIBlocking
		autoRequestReviewer = wr.AutoRequestReviewer
		autoApproveMinScore = wr.AutoApproveMinScore
		service = nz(wr.ServiceName, service)
	}
	if len(checks) == 0 {
		checks = defaultWatchedChecks()
	}

	wantAI := false
	scanList := []string{}
	for _, c := range checks {
		if c == "ai_review" {
			wantAI = true
			continue
		}
		if c == "sbom" || c == "secrets" || c == "sast" || c == "iac" || c == "container" {
			scanList = append(scanList, c)
		}
	}
	if len(scanList) == 0 {
		scanList = []string{"secrets", "sast", "iac", "sbom"}
	}
	// Continuous / default-branch / cron: always include SBOM, never OPA Review.
	if strings.HasPrefix(job.Event, "push.") || strings.HasPrefix(job.Event, "cron.") {
		wantAI = false
		hasSbom := false
		for _, c := range scanList {
			if c == "sbom" {
				hasSbom = true
				break
			}
		}
		if !hasSbom {
			scanList = append(scanList, "sbom")
		}
		if profile == "auto" {
			profile = "full"
		}
	}
	if job.ForceAI {
		wantAI = true
	}
	if job.AIOnly {
		scanList = []string{}
	}
	runAI := wantAI && job.PRNumber > 0

	// Reviewer routing moved to approval.decide (after findings exist).

	// Check runs (queued) — details_url + summary link → Dashboard /security/jobs/:id
	jobDashURL := scmJobDashboardURL(job.ID)
	var appSecID int64
	if !job.AIOnly {
		appSecID, _ = githubCreateCheckRun(conn, owner, repoName, "AppSec Gate", job.CommitSHA, "in_progress", "", "Scanning…", checkRunSummaryWithJobLink("Repo Watch lite/stub scanners running", job.ID), jobDashURL, nil)
		job.CheckRunIDs["appsec"] = appSecID
	}
	var aiCheckID int64
	if runAI {
		aiCheckID, _ = githubCreateCheckRun(conn, owner, repoName, "OPA Review", job.CommitSHA, "queued", "", "Queued", checkRunSummaryWithJobLink("Waiting for AppSec context", job.ID), jobDashURL, nil)
		job.CheckRunIDs["ai"] = aiCheckID
	}
	persistSCMJob(job)
	if finishIfCancelled() {
		if appSecID != 0 {
			githubCompleteCheckRunForCancel(conn, owner, repoName, appSecID, job, jobDashURL)
		}
		if aiCheckID != 0 {
			githubCompleteCheckRunForCancel(conn, owner, repoName, aiCheckID, job, jobDashURL)
		}
		return
	}

	// Isolated checkout under $OPA_REVIEW_TMP/{job_id} (default /tmp/opa-review) — never shared workspace root.
	absRoot, relPath, wtMeta, err := prepareSCMWorktree(conn, job.RepoFullName, job.CommitSHA, job.PRNumber, job.ID)
	if wtMeta != nil {
		job.Summary["worktree"] = wtMeta
		if rs, _ := wtMeta["resolved_sha"].(string); rs != "" && (job.CommitSHA == "" || strings.HasPrefix(job.CommitSHA, "manual-") || strings.HasPrefix(job.CommitSHA, "cron-")) {
			job.CommitSHA = rs
		}
	}
	if err != nil {
		if finishIfCancelled() {
			return
		}
		job.Summary["checkout_error"] = err.Error()
		useMock := githubUseMockAPI(conn) || conn == nil || (conn.TokenRef == "" && conn.InstallationID == "")
		if !useMock {
			// Real credentials: fail clearly — do not scan shared fixture.
			job.Status = "error"
			job.Error = "git worktree checkout failed: " + err.Error()
			job.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
			if appSecID != 0 {
				_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", "failure", "Checkout failed", checkRunSummaryWithJobLink(err.Error(), job.ID), jobDashURL, nil)
			}
			if aiCheckID != 0 {
				_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "failure", "Checkout failed", checkRunSummaryWithJobLink(err.Error(), job.ID), jobDashURL, nil)
			}
			persistSCMJob(job)
			go cleanupOldSCMWorktrees(securityWorkspaceRoot(), 24*time.Hour)
			return
		}
		// Mock path: ensure fixture worktree exists even if prepare partially failed.
		_ = writeMockWorktreeFixture(absRoot)
		job.Summary["checkout_fallback"] = "mock_worktree_fixture"
	}
	job.Summary["checkout_path"] = absRoot
	job.Summary["checkout_rel"] = relPath

	// Persist analyzed SHA early (checkout revision) for re-review / Auto-fix basing.
	analyzed := job.CommitSHA
	if wtMeta != nil {
		if rs, _ := wtMeta["resolved_sha"].(string); rs != "" {
			analyzed = rs
		}
	}
	if analyzed != "" && !strings.HasPrefix(analyzed, "manual-") && !strings.HasPrefix(analyzed, "cron-") {
		recordAnalyzedSHA(job, analyzed)
	}

	// After checkout resolves a real SHA, skip if that commit was already reviewed
	// (covers manual-*/cron-* placeholders that resolve late).
	if priorID, skip := shouldSkipSCMJobForAlreadyReviewed(job); skip {
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		job.Status = "skipped"
		job.Summary["skip_reason"] = "commit already reviewed successfully"
		if priorID != "" {
			job.Summary["prior_reviewed_job_id"] = priorID
		}
		job.FinishedAt = now
		reason := "Commit already had a successful OPA Review"
		if appSecID != 0 {
			_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", "neutral", "Skipped", checkRunSummaryWithJobLink(reason, job.ID), jobDashURL, nil)
		}
		if aiCheckID != 0 {
			_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "neutral", "Skipped", checkRunSummaryWithJobLink(reason, job.ID), jobDashURL, nil)
		}
		persistSCMJob(job)
		go cleanupOldSCMWorktrees(securityWorkspaceRoot(), 24*time.Hour)
		return
	}

	// Sibling clones for linked / mentioned related repos (cross-repo context).
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
		related := prepareRelatedCheckouts(conn, job.ID, relatedNames, nil)
		job.Summary["related_checkouts"] = related
		job.Summary["related_repos"] = relatedRepoNames(related)
		clonedOK := 0
		for _, r := range related {
			if r.Error == "" {
				clonedOK++
			}
		}
		job.Summary["related_honesty"] = fmt.Sprintf("cloned %d/%d related repo(s) under %s/related/ (cap OPA_REVIEW_RELATED_MAX=%d)",
			clonedOK, len(related), scmJobContainerAbs(job.ID), opaReviewRelatedMax())
	}

	runID := securityRunID(job.OrganizationID, job.ProjectID, job.ID)
	job.SecurityRunID = runID
	persistSCMJob(job)
	if finishIfCancelled() {
		if appSecID != 0 {
			githubCompleteCheckRunForCancel(conn, owner, repoName, appSecID, job, jobDashURL)
		}
		if aiCheckID != 0 {
			githubCompleteCheckRunForCancel(conn, owner, repoName, aiCheckID, job, jobDashURL)
		}
		return
	}

	var scanStartErr error
	if !job.AIOnly {
		scanStartErr = runSecurityScanJob(runID, job.OrganizationID, job.ProjectID, service, profile, scanList, relPath, "", job.RepoFullName, job.PRNumber, job.CommitSHA, job.ID)
	} else {
		job.Summary["ai_only"] = true
		// Seed an empty security run so AI context still has a run id.
		scanStartErr = runSecurityScanJob(runID, job.OrganizationID, job.ProjectID, service, "auto", []string{}, relPath, "", job.RepoFullName, job.PRNumber, job.CommitSHA, job.ID)
	}
	if finishIfCancelled() {
		if appSecID != 0 {
			githubCompleteCheckRunForCancel(conn, owner, repoName, appSecID, job, jobDashURL)
		}
		if aiCheckID != 0 {
			githubCompleteCheckRunForCancel(conn, owner, repoName, aiCheckID, job, jobDashURL)
		}
		return
	}

	// Scoped gate — waits for the scanners to finish before reading findings.
	gate := gateAfterScan(job.OrganizationID, runID, minSev, scanStartErr)
	if job.AIOnly {
		gate = map[string]interface{}{
			"status": gateStatusPass, "fail": false, "reasons": []string{"ai_only"},
			"scope": "security_run", "security_run_id": runID, "min_severity": minSev,
		}
	}
	job.Summary["gate"] = gate
	conclusion, title := gateCheckOutcome(gate)
	sum := checkRunSummaryWithJobLink(gateCheckSummary(gate, runID), job.ID)
	if appSecID != 0 {
		_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", conclusion, title, sum, jobDashURL, nil)
	}

	// AI review (ForceAI overrides draft skip). Runs even when the gate failed so
	// manual.ai_review / force_ai jobs still deliver AI + gate together.
	if runAI {
		if finishIfCancelled() {
			if aiCheckID != 0 {
				githubCompleteCheckRunForCancel(conn, owner, repoName, aiCheckID, job, jobDashURL)
			}
			return
		}
		// PR may have merged while AppSec ran — stop before spending Cursor tokens.
		if shouldSkipSCMJobForMergedPR(job) {
			_, _, _ = cancelSCMJobWithReason(jobID, "pull request merged")
			if aiCheckID != 0 {
				_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "cancelled", "Cancelled — PR merged", checkRunSummaryWithJobLink("PR merged — review cancelled", job.ID), jobDashURL, nil)
			}
			return
		}
		applied := resolveReviewContextsForRepo(job.OrganizationID, job.ProjectID, job.RepoFullName)
		appliedSummary := summarizeAppliedContexts(applied)
		job.Summary["review_contexts"] = appliedSummary
		_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "in_progress", "", "OPA reviewing…", checkRunSummaryWithJobLink("Running OPA Review", job.ID), jobDashURL, nil)
		aiResult := runCursorAIReview(job, conn, wr, absRoot, runID)
		job.AIJobID = aiResult.ID

		if finishIfCancelled() || shouldSkipSCMJobForMergedPR(job) {
			if !scmJobIsCancelled(jobID) {
				_, _, _ = cancelSCMJobWithReason(jobID, "pull request merged")
			}
			if aiCheckID != 0 {
				_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "cancelled", "Cancelled — PR merged", checkRunSummaryWithJobLink("PR merged — review cancelled", job.ID), jobDashURL, nil)
			}
			return
		}

		wtOK := err == nil && absRoot != ""
		wtDetail := ""
		if job.Summary["checkout_fallback"] != nil {
			wtOK = true
			wtDetail = "mock fixture"
		} else if !wtOK {
			if ce, _ := job.Summary["checkout_error"].(string); ce != "" {
				wtDetail = truncateStr(ce, 120)
			}
		} else if rel, _ := job.Summary["checkout_rel"].(string); rel != "" {
			wtDetail = rel
		}
		mcpPlan := reviewMCPPlan{VisualStatus: "not_applicable", VisualWhy: "no UI files in diff"}
		if aiResult.MCP != nil {
			mcpPlan = *aiResult.MCP
		}
		pubMeta := aiReviewPublishMeta{
			SecurityRunID:     runID,
			Gate:              gate,
			Scanners:          scanList,
			ContextTitles:     contextTitlesFromApplied(appliedSummary),
			WorktreeOK:        wtOK,
			WorktreeDetail:    wtDetail,
			DesignEnforcement: aiResult.DesignEnforced,
			ScanSeverity:      scanSeverityCountsForRun(runID),
			MCP:               mcpPlan,
		}
		legacyPrefsEarly := agentPrefsFromSummary(job)
		populateCarriedFindingKeys(job, conn, owner, repoName, legacyPrefsEarly)
		inline := postOPAReviewFindings(conn, owner, repoName, job, aiResult, pubMeta, autoApproveMinScore)
		aiResult.InlinePosted = inline.Posted
		aiResult.InlineFailed = inline.Failed
		aiResult.InlineMode = inline.Mode
		aiResult.InlineHonesty = inline.Honesty
		pubMeta.InlinePosted = inline.Posted
		pubMeta.InlineFailed = inline.Failed
		pubMeta.InlineMode = inline.Mode
		pubMeta.InlineHonesty = inline.Honesty

		checkSum := ""
		if opaReviewShouldPostResume(aiResult) {
			aiComment, cs := publishAIReviewComment(job, aiResult, pubMeta)
			aiResult.Comment = aiComment
			checkSum = cs
		} else {
			// Keep Check Run text honest without posting a PR résumé.
			checkSum = truncateStr(nz(aiResult.Summary, "OPA Review skipped"), 500)
			aiResult.Comment = ""
		}
		job.Summary["ai"] = aiResult
		if scmAIReviewSucceeded(aiResult.Status) {
			reviewedSHA := job.CommitSHA
			if a := strFromAny(job.Summary["analyzed_sha"]); a != "" {
				reviewedSHA = a
			}
			recordSuccessfulAIReview(job, reviewedSHA, aiResult.Status)
		}

		// Approval integrity: decide + publish through the chokepoint (de-fused from findings).
		// MinScore is veto-only — never promote AutoApprove from auto_approve_min_score.
		legacyPrefs := agentPrefsFromSummary(job)
		gateFail := gate["fail"] == true
		secFindings := securityFindingsFromRun(job.OrganizationID, runID)
		baseRef := "main"
		if pull, err := githubGetPull(conn, owner, repoName, job.PRNumber); err == nil && pull != nil && pull.BaseRef != "" {
			baseRef = pull.BaseRef
		}
		policyPath, _ := safePolicyPath(legacyPrefs.PolicyFilePath)
		var policy *approvalPolicy
		policyHonesty := ""
		if raw, err := githubGetContentAtRef(conn, owner, repoName, policyPath, baseRef); err != nil {
			policyHonesty = "policy unavailable: " + err.Error()
		} else if p, err := parseApprovalPolicy(raw); err != nil {
			policyHonesty = "policy unparseable: " + err.Error()
		} else {
			policy = p
		}
		decision := evaluateApproval(approvalEvidence{
			Prefs: legacyPrefs, Bugbot: aiResult, SecurityRunID: runID,
			SecurityFail: gateFail, SecurityFindings: secFindings,
			BugbotOK: scmAIReviewSucceeded(aiResult.Status) || strings.EqualFold(aiResult.Status, "ok") || strings.EqualFold(aiResult.Status, "clean"),
			SecurityOK: !gateFail,
			Policy: policy, PolicyHonesty: policyHonesty, BaseRef: baseRef, MinScore: autoApproveMinScore,
		})
		job.Summary["review_event"] = decision.Event
		job.Summary["approval_reasons"] = decision.Reasons
		job.Summary["approval_honesty"] = decision.Honesty
		decisionBody := formatOPAReviewDecisionBody(decision.Bugbot, decision.Event, autoApproveMinScore)
		if err := publishPRReview(conn, owner, repoName, job, decisionBody, decision.Event, nil); err != nil {
			job.Summary["approval_publish_error"] = err.Error()
		}
		job.Summary["pending_decision"] = false
		if legacyPrefs.ReviewerRouting && policy != nil {
			_ = githubRequestPRReviewersEx(conn, owner, repoName, job.PRNumber, policy.Route.Reviewers, policy.Route.TeamReviewers)
		} else if autoRequestReviewer {
			if err := githubRequestPRReviewers(conn, owner, repoName, job.PRNumber, []string{githubAppReviewerLogin()}); err != nil {
				job.Summary["request_reviewer_error"] = err.Error()
			} else {
				job.Summary["requested_reviewer"] = githubAppReviewerLogin()
			}
		}

		aiConclusion := "neutral"
		if aiBlocking && aiResult.Status == "findings" {
			aiConclusion = "failure"
		} else if decision.Event == "REQUEST_CHANGES" && autoApproveMinScore > 0 {
			aiConclusion = "failure"
		} else if aiResult.Status == "skipped" || aiResult.Status == "error" {
			aiConclusion = "neutral"
		} else if decision.Event == "APPROVE" || aiResult.Status != "findings" {
			aiConclusion = "success"
		} else {
			aiConclusion = "success"
		}
		checkTitle := "OPA Review " + aiResult.Status
		if aiResult.Fallback {
			checkTitle = "OPA Review fallback"
		}
		ann := aiResult.Annotations
		if inline.Mode == "review" || inline.Mode == "comments" {
			// Inline PR comments already carry findings; keep annotations as backup when some failed.
			if inline.Failed == 0 && inline.Posted > 0 {
				ann = nil
			}
		}
		_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", aiConclusion, checkTitle, checkRunSummaryWithJobLink(checkSum, job.ID), jobDashURL, ann)
		// Résumé is upserted inside postOPAReviewFindings (issue comment with <!-- opa-review:resume -->).
		// Only fall back here when inline sync could not touch GitHub at all — never when CLI key missing.
		if opaReviewShouldPostResume(aiResult) && aiResult.Comment != "" && inline.Mode == "annotations_only" && !inline.ResumeOK {
			_ = githubPRComment(conn, owner, repoName, job.PRNumber, aiResult.Comment)
		}
	} else if wantAI {
		job.Summary["ai"] = map[string]interface{}{"status": "skipped", "reason": "no PR number (pass force=true to override)"}
	}

	if finishIfCancelled() {
		return
	}

	job.Status = "completed"
	if gate["fail"] == true {
		// force_ai / ai_only / manual AI: report gate failure in summary but keep
		// job completed so the AI result is the primary outcome.
		if job.ForceAI || job.AIOnly || strings.HasPrefix(job.Event, "manual.ai") {
			job.Summary["gate_failed_but_continued"] = true
		} else {
			job.Status = "failed"
		}
	}
	job.FinishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	persistSCMJob(job)

	// Cleanup old worktrees (best-effort)
	go cleanupOldSCMWorktrees(securityWorkspaceRoot(), 24*time.Hour)
	_ = absRoot
}

func checkoutSCMRepo(c *opaConnector, fullName, sha string, pr int, relPath string) (string, error) {
	// Legacy helper — prefer prepareSCMWorktree. Keep for callers that pass an explicit rel path.
	id := filepath.Base(relPath)
	if id == "" || id == "." || id == "jobs" || id == "worktrees" {
		id = "legacy-" + newRandomHex(6)
	}
	abs, _, _, err := prepareSCMWorktree(c, fullName, sha, pr, id)
	return abs, err
}

var scmCronOnce sync.Once

func startSCMCronOnce() {
	scmCronOnce.Do(func() {
		if envOr("OPA_SCM_CRON", "0") != "1" {
			return
		}
		go func() {
			t := time.NewTicker(6 * time.Hour)
			defer t.Stop()
			for range t.C {
				watchedLive.Range(func(_, v interface{}) bool {
					wr, ok := v.(*opaWatchedRepo)
					if !ok || !wr.Enabled {
						return true
					}
					conn := getConnector(wr.ConnectorID)
					job := enqueueSCMJob(wr, conn, wr.RepoFullName, 0, "cron-"+newRandomHex(8), "cron.full", false, "scheduled scan", "")
					go processSCMJob(job.ID)
					return true
				})
			}
		}()
	})
}
