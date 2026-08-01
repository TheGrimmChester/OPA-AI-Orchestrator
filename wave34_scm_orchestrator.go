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
	// ForceAI runs OPA Review even when draft, and forces ai_review on.
	ForceAI bool `json:"force_ai,omitempty"`
	// AIOnly skips AppSec scanners / gate; still checkouts + runs OPA Review.
	AIOnly bool `json:"ai_only,omitempty"`
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
	secret := strings.TrimSpace(os.Getenv("OPA_GITHUB_WEBHOOK_SECRET"))
	if !verifyGitHubSignature(secret, raw, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "invalid signature", 401)
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	switch event {
	case "ping":
		writeJSON(w, map[string]interface{}{"ok": true, "pong": true})
		return
	case "pull_request":
		handlePRWebhook(w, raw)
	case "push":
		handlePushWebhook(w, raw)
	case "installation", "installation_repositories":
		writeJSON(w, map[string]interface{}{"ok": true, "ignored": event})
	default:
		writeJSON(w, map[string]interface{}{"ok": true, "ignored": event})
	}
}

func handlePRWebhook(w http.ResponseWriter, raw []byte) {
	var payload struct {
		Action string `json:"action"`
		Number int    `json:"number"`
		PR     struct {
			Number int    `json:"number"`
			Title  string `json:"title"`
			Body   string `json:"body"`
			Draft  bool   `json:"draft"`
			Head   struct {
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
		http.Error(w, "bad json", 400)
		return
	}
	action := payload.Action
	if action != "opened" && action != "synchronize" && action != "reopened" && action != "ready_for_review" {
		writeJSON(w, map[string]interface{}{"ok": true, "skipped": action})
		return
	}
	repo := payload.Repository.FullName
	wr, conn := findWatched(repo)
	if wr == nil {
		// Do not auto-watch on webhook — only explicitly watched repos run jobs.
		writeJSON(w, map[string]interface{}{"ok": true, "skipped": "repo not watched", "repo": repo})
		return
	}
	_ = conn
	pr := payload.PR.Number
	if pr == 0 {
		pr = payload.Number
	}
	job := enqueueSCMJob(wr, conn, repo, pr, payload.PR.Head.SHA, "pull_request."+action, payload.PR.Draft, payload.PR.Title, payload.PR.Body)
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{"ok": true, "job_id": job.ID, "status": "queued"})
}

func handlePushWebhook(w http.ResponseWriter, raw []byte) {
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
		http.Error(w, "bad json", 400)
		return
	}
	def := nz(payload.Repository.DefaultBranch, "main")
	if payload.Ref != "refs/heads/"+def {
		writeJSON(w, map[string]interface{}{"ok": true, "skipped": "not default branch"})
		return
	}
	repo := payload.Repository.FullName
	wr, conn := findWatched(repo)
	if wr == nil {
		writeJSON(w, map[string]interface{}{"ok": true, "skipped": "repo not watched"})
		return
	}
	job := enqueueSCMJob(wr, conn, repo, 0, payload.After, "push.default", false, "default-branch scan", "")
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{"ok": true, "job_id": job.ID})
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
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	id := loadID("scmjob", org, proj, repo, sha, event, newRandomHex(6))
	job := &scmJob{
		ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: connID,
		RepoFullName: repo, PRNumber: pr, CommitSHA: sha, Event: event,
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
	persistSCMJobFile(job)
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

func scmJobIsCancelled(id string) bool {
	job := getSCMJob(id)
	return job != nil && job.Status == "cancelled"
}

func registerSCMJobCancel(id string) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx
	scmJobCancel.Store(id, cancel)
	return cancel
}

func clearSCMJobCancel(id string) {
	if v, ok := scmJobCancel.Load(id); ok {
		scmJobCancel.Delete(id)
		if c, ok := v.(context.CancelFunc); ok {
			c()
		}
	}
}

// cancelSCMJob marks a live job cancelled when it is still queued/waiting/running.
// Running work is interrupted best-effort via the registered cancel func; stack drain
// skips cancelled jobs so waiting items can proceed.
func cancelSCMJob(id string) (*scmJob, string, int) {
	job := getSCMJob(id)
	if job == nil {
		return nil, "not found", 404
	}
	switch job.Status {
	case "queued", "waiting", "running":
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		job.Status = "cancelled"
		job.FinishedAt = now
		if job.Error == "" {
			job.Error = "cancelled"
		}
		persistSCMJob(job)
		if v, ok := scmJobCancel.Load(id); ok {
			if c, ok := v.(context.CancelFunc); ok {
				c()
			}
		}
		refreshStacksForJob(id)
		return job, "", 0
	case "cancelled":
		return job, "", 0
	default:
		return job, "job not cancellable in status " + job.Status, 409
	}
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
	list := []*scmJob{}
	counts := map[string]int{}
	scmJobLive.Range(func(_, v interface{}) bool {
		if j, ok := v.(*scmJob); ok {
			list = append(list, j)
			st := strings.TrimSpace(j.Status)
			if st == "" {
				st = "unknown"
			}
			counts[st]++
		}
		return true
	})
	sortSCMJobsActiveFirst(list)
	total := len(list)
	limit := clampInt(atoiDefault(r.URL.Query().Get("limit"), 50), 1, 500)
	if len(list) > limit {
		list = list[:limit]
	}
	writeJSON(w, map[string]interface{}{
		"jobs": list, "total": total, "counts": counts, "limit": limit,
	})
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
		writeJSON(w, scmJobAPIView(job))
		return
	}
	if len(parts) >= 2 && parts[1] == "retry" && r.Method == http.MethodPost {
		job := getSCMJob(id)
		if job == nil {
			http.Error(w, "not found", 404)
			return
		}
		job.Status = "queued"
		job.Error = ""
		persistSCMJob(job)
		go processSCMJob(id)
		writeJSON(w, map[string]interface{}{"ok": true, "job_id": id, "status": "queued"})
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
	job, errMsg, code := enqueueManualAIReview(repo, pr, body.ConnectorID, body.SHA, body.Title, body.Draft, force, body.AIOnly, body.AllowUnwatched)
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
		"cursor_key_set": resolveCursorAPIKey(job.OrganizationID, job.ProjectID) != "",
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
	job, errMsg, code := enqueueManualAIReview(src.RepoFullName, src.PRNumber, src.ConnectorID, src.CommitSHA, src.Title, src.Draft, force, aiOnly, true)
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

func enqueueManualAIReview(repo string, pr int, connectorID, sha, title string, draft, force, aiOnly, allowUnwatched bool) (*scmJob, string, int) {
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
		wr = upsertWatched(conn.OrganizationID, conn.ProjectID, conn.ID, repo, "", true, defaultWatchedChecks(), "auto", "high", false)
	} else if wr == nil && allowUnwatched {
		if conn == nil {
			return nil, "connector_id required for unwatched one-off", 400
		}
		wr = upsertWatched(conn.OrganizationID, conn.ProjectID, conn.ID, repo, "", true, defaultWatchedChecks(), "auto", "high", false)
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
	if title == "" {
		title = fmt.Sprintf("Manual OPA Review PR #%d", pr)
	}

	event := "manual.ai_review"
	if aiOnly {
		event = "manual.ai_only"
	}
	job := enqueueSCMJob(wr, conn, repo, pr, sha, event, draft, title, prBody)
	job.ForceAI = force
	job.AIOnly = aiOnly
	persistSCMJob(job)
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
	wr := upsertWatched(org, proj, connID, repo, "", true, checks, nz(body.Profile, "auto"), "high", false)
	if body.Service != "" {
		wr.ServiceName = body.Service
	}
	os.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	job := enqueueSCMJob(wr, getConnector(connID), repo, body.PR, sha, "simulate", body.Draft, "simulated PR", "")
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{"ok": true, "job_id": job.ID, "repo": repo, "sha": sha})
}

// scmProcessing tracks job IDs with an active processSCMJob goroutine so boot/admin
// resume and enqueue cannot run the same job twice concurrently.
var scmProcessing sync.Map // jobID -> struct{}

func processSCMJob(jobID string) {
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
	case "cancelled", "completed", "failed", "error", "running":
		// Terminal, or another path already marked running (should be rare with scmProcessing).
		return
	}
	cancel := registerSCMJobCancel(jobID)
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
	service := strings.ReplaceAll(job.RepoFullName, "/", "-")
	if wr != nil {
		_ = json.Unmarshal([]byte(wr.ChecksJSON), &checks)
		profile = nz(wr.Profile, "auto")
		minSev = nz(wr.MinSeverity, "high")
		aiBlocking = wr.AIBlocking
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
	runAI := wantAI && job.PRNumber > 0 && (!job.Draft || job.ForceAI)

	// Check runs (queued)
	var appSecID int64
	if !job.AIOnly {
		appSecID, _ = githubCreateCheckRun(conn, owner, repoName, "OPA AppSec Gate", job.CommitSHA, "in_progress", "", "Scanning…", "Repo Watch lite/stub scanners running", nil)
		job.CheckRunIDs["appsec"] = appSecID
	}
	var aiCheckID int64
	if runAI {
		aiCheckID, _ = githubCreateCheckRun(conn, owner, repoName, "OPA Review", job.CommitSHA, "queued", "", "Queued", "Waiting for AppSec context", nil)
		job.CheckRunIDs["ai"] = aiCheckID
	}
	persistSCMJob(job)
	if finishIfCancelled() {
		if appSecID != 0 {
			_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", "cancelled", "Cancelled", "Job cancelled", nil)
		}
		if aiCheckID != 0 {
			_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "cancelled", "Cancelled", "Job cancelled", nil)
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
				_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", "failure", "Checkout failed", err.Error(), nil)
			}
			if aiCheckID != 0 {
				_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "failure", "Checkout failed", err.Error(), nil)
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
			_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", "cancelled", "Cancelled", "Job cancelled", nil)
		}
		if aiCheckID != 0 {
			_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "cancelled", "Cancelled", "Job cancelled", nil)
		}
		return
	}

	if !job.AIOnly {
		runSecurityScanJob(runID, job.OrganizationID, job.ProjectID, service, profile, scanList, relPath, "", job.RepoFullName, job.PRNumber, job.CommitSHA, job.ID)
	} else {
		job.Summary["ai_only"] = true
		// Seed an empty security run so AI context still has a run id.
		runSecurityScanJob(runID, job.OrganizationID, job.ProjectID, service, "auto", []string{}, relPath, "", job.RepoFullName, job.PRNumber, job.CommitSHA, job.ID)
	}
	if finishIfCancelled() {
		if appSecID != 0 {
			_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", "cancelled", "Cancelled", "Job cancelled", nil)
		}
		if aiCheckID != 0 {
			_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "cancelled", "Cancelled", "Job cancelled", nil)
		}
		return
	}

	// Scoped gate
	gate := evaluateScopedGate(job.OrganizationID, runID, minSev)
	if job.AIOnly {
		gate = map[string]interface{}{
			"status": "pass", "fail": false, "reasons": []string{"ai_only"},
			"scope": "security_run", "security_run_id": runID, "min_severity": minSev,
		}
	}
	job.Summary["gate"] = gate
	conclusion := "success"
	title := "AppSec Gate passed"
	if gate["fail"] == true {
		conclusion = "failure"
		title = "AppSec Gate failed"
	}
	sum := fmt.Sprintf("scope=%v reasons=%v security_run_id=%s", gate["scope"], gate["reasons"], runID)
	if appSecID != 0 {
		_ = githubUpdateCheckRun(conn, owner, repoName, appSecID, "completed", conclusion, title, sum, nil)
	}

	// AI review (ForceAI overrides draft skip). Runs even when the gate failed so
	// manual.ai_review / force_ai jobs still deliver AI + gate together.
	if runAI {
		if finishIfCancelled() {
			if aiCheckID != 0 {
				_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", "cancelled", "Cancelled", "Job cancelled", nil)
			}
			return
		}
		applied := resolveReviewContextsForRepo(job.OrganizationID, job.ProjectID, job.RepoFullName)
		appliedSummary := summarizeAppliedContexts(applied)
		job.Summary["review_contexts"] = appliedSummary
		_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "in_progress", "", "OPA reviewing…", "Running OPA Review", nil)
		aiResult := runCursorAIReview(job, conn, wr, absRoot, runID)
		job.AIJobID = aiResult.ID

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
		inline := postOPAReviewFindings(conn, owner, repoName, job, aiResult, pubMeta)
		aiResult.InlinePosted = inline.Posted
		aiResult.InlineFailed = inline.Failed
		aiResult.InlineMode = inline.Mode
		aiResult.InlineHonesty = inline.Honesty
		pubMeta.InlinePosted = inline.Posted
		pubMeta.InlineFailed = inline.Failed
		pubMeta.InlineMode = inline.Mode
		pubMeta.InlineHonesty = inline.Honesty

		aiComment, checkSum := publishAIReviewComment(job, aiResult, pubMeta)
		aiResult.Comment = aiComment
		job.Summary["ai"] = aiResult
		aiConclusion := "neutral"
		if aiBlocking && aiResult.Status == "findings" {
			aiConclusion = "failure"
		} else if aiResult.Status == "skipped" || aiResult.Status == "error" {
			aiConclusion = "neutral"
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
		_ = githubUpdateCheckRun(conn, owner, repoName, aiCheckID, "completed", aiConclusion, checkTitle, checkSum, ann)
		// Résumé is upserted inside postOPAReviewFindings (issue comment with <!-- opa-review:resume -->).
		// Only fall back here when inline sync could not touch GitHub at all.
		if aiResult.Comment != "" && inline.Mode == "annotations_only" && !inline.ResumeOK {
			_ = githubPRComment(conn, owner, repoName, job.PRNumber, aiResult.Comment)
		}
	} else if wantAI {
		job.Summary["ai"] = map[string]interface{}{"status": "skipped", "reason": "draft PR or no PR number (pass force=true to override)"}
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

func evaluateScopedGate(org, runID, minSev string) map[string]interface{} {
	fail := false
	reasons := []string{}
	softNotes := []string{}
	if queryClient != nil && runID != "" {
		sevFilter := "severity IN ('critical','high')"
		switch strings.ToLower(minSev) {
		case "critical":
			sevFilter = "severity = 'critical'"
		case "medium":
			sevFilter = "severity IN ('critical','high','medium')"
		case "low":
			sevFilter = "1=1"
		}
		rid := escapeSQL(runID)
		for _, table := range []string{"secret_findings", "sast_findings", "iac_findings"} {
			rows, err := queryClient.Query(fmt.Sprintf(`SELECT count() AS c FROM opa.%s WHERE security_run_id = '%s' AND %s`, table, rid, sevFilter))
			if err == nil && len(rows) > 0 && getFloat64(rows[0], "c") > 0 {
				fail = true
				reasons = append(reasons, table+" findings present")
			}
		}
	}
	// Immediate path: live run summary (insertAsync may lag behind CH queries).
	if !fail {
		if live := liveSecurityRun(runID); live != nil {
			if sj, _ := live["summary_json"].(string); sj != "" {
				var sm struct {
					Counts          map[string]int            `json:"counts"`
					SeverityCounts  map[string]map[string]int `json:"severity_counts"`
					FilteredSecrets int                       `json:"secrets_filtered_fp"`
				}
				_ = json.Unmarshal([]byte(sj), &sm)
				if blocking := liveBlockingCount(sm.SeverityCounts, "secrets", minSev); blocking > 0 {
					fail = true
					reasons = append(reasons, "secret findings present (live)")
				} else if sm.Counts["secrets"] > 0 {
					// Counts exist but none meet min_severity (e.g. medium generic-api-key only).
					softNotes = append(softNotes, fmt.Sprintf("secrets below gate threshold (min=%s, filtered_fp=%d)", minSev, sm.FilteredSecrets))
				}
				if sm.Counts["sast"] > 0 && strings.ToLower(minSev) != "critical" {
					if blocking := liveBlockingCount(sm.SeverityCounts, "sast", minSev); blocking > 0 || sm.SeverityCounts["sast"] == nil {
						fail = true
						reasons = append(reasons, "sast findings present (live)")
					}
				}
				if sm.Counts["iac"] > 0 && (minSev == "medium" || minSev == "low") {
					fail = true
					reasons = append(reasons, "iac findings present (live)")
				}
			}
		}
	}
	status := "pass"
	if fail {
		status = "fail"
	}
	_ = org
	out := map[string]interface{}{
		"status": status, "fail": fail, "reasons": reasons, "scope": "security_run",
		"security_run_id": runID, "min_severity": minSev,
	}
	if len(softNotes) > 0 {
		out["soft_notes"] = softNotes
	}
	return out
}

// liveBlockingCount returns how many findings at/above minSev are in severity_counts[kind].
func liveBlockingCount(sev map[string]map[string]int, kind, minSev string) int {
	if sev == nil || sev[kind] == nil {
		return 0
	}
	m := sev[kind]
	n := m["critical"]
	switch strings.ToLower(minSev) {
	case "critical":
		return n
	case "medium":
		return n + m["high"] + m["medium"]
	case "low":
		return n + m["high"] + m["medium"] + m["low"] + m["info"]
	default: // high
		return n + m["high"]
	}
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
