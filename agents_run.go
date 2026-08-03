package main

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// Active PR run index: "repo#pr" → run job id. Used for cancel-and-supersede.
var (
	prRunIndexMu sync.Mutex
	prRunIndex   = map[string]string{}
	// Serialize enqueue+supersede per PR so concurrent synchronize webhooks
	// cannot both miss each other and leave two runs in flight.
	prEnqueueMu sync.Map // prRunIndexKey → *sync.Mutex
)

func prRunIndexKey(repo string, pr int) string {
	return strings.ToLower(strings.TrimSpace(repo)) + "#" + itoa(pr)
}

func lockPREnqueue(repo string, pr int) func() {
	key := prRunIndexKey(repo, pr)
	muI, _ := prEnqueueMu.LoadOrStore(key, &sync.Mutex{})
	mu := muI.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func rememberPRRun(repo string, pr int, runID string) {
	if repo == "" || pr <= 0 || runID == "" {
		return
	}
	prRunIndexMu.Lock()
	prRunIndex[prRunIndexKey(repo, pr)] = runID
	prRunIndexMu.Unlock()
}

func currentPRRun(repo string, pr int) string {
	prRunIndexMu.Lock()
	defer prRunIndexMu.Unlock()
	return prRunIndex[prRunIndexKey(repo, pr)]
}

// rebuildPRRunIndexFromLive scans in-flight kind=run parents and restores
// prRunIndex after boot hydrate (index is process-memory only).
func rebuildPRRunIndexFromLive() int {
	best := map[string]*scmJob{}
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || j == nil || j.PRNumber <= 0 {
			return true
		}
		if agentKind(j.Kind) != kindRun || strings.TrimSpace(j.ParentID) != "" {
			return true
		}
		st := strings.ToLower(j.Status)
		if st != "queued" && st != "waiting" && st != "running" {
			return true
		}
		key := prRunIndexKey(j.RepoFullName, j.PRNumber)
		if prev, ok := best[key]; ok && prev.StartedAt >= j.StartedAt {
			return true
		}
		best[key] = j
		return true
	})
	prRunIndexMu.Lock()
	prRunIndex = map[string]string{}
	for k, j := range best {
		prRunIndex[k] = j.ID
	}
	n := len(prRunIndex)
	prRunIndexMu.Unlock()
	return n
}

// pruneSupersededInFlightPRRuns keeps only the newest top-level in-flight job
// per repo+PR (by StartedAt) and cancels the rest. Covers restart residue and
// any race that left intermediate commits still queued/running.
func pruneSupersededInFlightPRRuns() int {
	type group struct {
		repo string
		pr   int
		jobs []*scmJob
	}
	byKey := map[string]*group{}
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || j == nil || j.PRNumber <= 0 {
			return true
		}
		if strings.TrimSpace(j.ParentID) != "" {
			return true
		}
		st := strings.ToLower(j.Status)
		if st != "queued" && st != "waiting" && st != "running" {
			return true
		}
		key := prRunIndexKey(j.RepoFullName, j.PRNumber)
		g := byKey[key]
		if g == nil {
			g = &group{repo: j.RepoFullName, pr: j.PRNumber}
			byKey[key] = g
		}
		g.jobs = append(g.jobs, j)
		return true
	})
	cancelled := 0
	for _, g := range byKey {
		if len(g.jobs) < 2 {
			if len(g.jobs) == 1 && agentKind(g.jobs[0].Kind) == kindRun {
				rememberPRRun(g.repo, g.pr, g.jobs[0].ID)
			}
			continue
		}
		newest := g.jobs[0]
		for _, j := range g.jobs[1:] {
			if j.StartedAt >= newest.StartedAt {
				newest = j
			}
		}
		reason := "Superseded by " + strings.TrimSpace(newest.CommitSHA)
		if reason == "Superseded by " {
			reason = "Superseded by newer push"
		}
		for _, j := range g.jobs {
			if j.ID == newest.ID {
				continue
			}
			if _, errMsg, _ := cancelSCMJobWithReason(j.ID, reason); errMsg == "" {
				cancelled++
			}
		}
		if agentKind(newest.Kind) == kindRun {
			rememberPRRun(g.repo, g.pr, newest.ID)
		}
	}
	return cancelled
}

// findInFlightPRRunForSHA returns a live parent run for repo+PR already on sha.
func findInFlightPRRunForSHA(repo string, pr int, sha string) *scmJob {
	repo = strings.TrimSpace(repo)
	sha = strings.TrimSpace(sha)
	if repo == "" || pr <= 0 || sha == "" {
		return nil
	}
	var found *scmJob
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || j == nil {
			return true
		}
		if j.PRNumber != pr || !strings.EqualFold(j.RepoFullName, repo) {
			return true
		}
		if strings.TrimSpace(j.ParentID) != "" {
			return true
		}
		st := strings.ToLower(j.Status)
		if st != "queued" && st != "waiting" && st != "running" {
			return true
		}
		if !strings.EqualFold(strings.TrimSpace(j.CommitSHA), sha) {
			return true
		}
		if found == nil || j.StartedAt >= found.StartedAt {
			found = j
		}
		return true
	})
	return found
}

// enqueuePRRun creates a parent kind=run job and its agent children (queued).
// Prefs are resolved once and frozen onto the parent summary.
func enqueuePRRun(wr *opaWatchedRepo, conn *opaConnector, repo string, pr int, sha, event string, draft bool, title, body string) *scmJob {
	org, proj, connID := "", "", ""
	if wr != nil {
		org, proj, connID = wr.OrganizationID, wr.ProjectID, wr.ConnectorID
	}
	if conn != nil {
		org, proj, connID = conn.OrganizationID, conn.ProjectID, conn.ID
	}
	prefs, sources := resolveAgentPrefs(org, proj, connID, repo)

	// Cancel every older in-flight job for this PR; only this head SHA should run.
	// Same-SHA re-entry reuses the live parent so manual + webhook do not cancel
	// each other mid-approval (GitHub checks would stay "skipped").
	if pr > 0 {
		unlock := lockPREnqueue(repo, pr)
		defer unlock()
		sha = strings.TrimSpace(sha)
		if sha != "" {
			if existing := findInFlightPRRunForSHA(repo, pr, sha); existing != nil {
				rememberPRRun(repo, pr, existing.ID)
				return existing
			}
		}
		supersedeInFlightPRJobs(repo, pr, sha)
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	// Unique id per enqueue attempt so retries don't collide with a finished run row.
	id := loadID("scmjob", org, proj, repo, sha, event, "run", newRandomHex(6))
	parent := &scmJob{
		ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: connID,
		RepoFullName: repo, PRNumber: pr, CommitSHA: sha, Event: event,
		Status: "queued", CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
		StartedAt: now, FinishedAt: now, Draft: draft, Title: title, Body: body,
		Kind: string(kindRun), RunID: id, ParentID: "", Attempt: 1,
	}
	parent.Summary["prefs"] = prefs
	parent.Summary["prefs_sources"] = sources
	parent.Summary["child_ids"] = []string{}

	// Trigger / draft gates: still create the run (webhook honesty) but skip kinds.
	skipBugbot := false
	skipReason := ""
	if draft && !prefs.ReviewDraftPRs {
		skipBugbot = true
		skipReason = "draft PR — review_draft_prs=off"
	}
	if !triggerModeAdmits(prefs.TriggerMode, event) {
		parent.Status = "skipped"
		parent.Summary["skip_reason"] = "trigger_mode=" + prefs.TriggerMode + " does not admit event " + event
		scmJobLive.Store(id, parent)
		persistSCMJob(parent)
		return parent
	}

	children := planRunChildren(parent, prefs, skipBugbot, skipReason)
	childIDs := make([]string, 0, len(children))
	for _, c := range children {
		scmJobLive.Store(c.ID, c)
		persistSCMJob(c)
		childIDs = append(childIDs, c.ID)
	}
	parent.Summary["child_ids"] = childIDs
	scmJobLive.Store(id, parent)
	persistSCMJob(parent)
	if pr > 0 {
		rememberPRRun(repo, pr, id)
	}
	return parent
}

func planRunChildren(parent *scmJob, prefs agentPrefs, skipBugbot bool, skipBugbotReason string) []*scmJob {
	kinds := []agentKind{kindPrepare, kindSecurity, kindBugbot, kindApproval}
	if prefs.CheckupEnabled {
		// Insert checkup after bugbot slot (sibling of security/bugbot; before approval).
		kinds = []agentKind{kindPrepare, kindSecurity, kindBugbot, kindCheckup, kindApproval}
	}
	cloudOn := prefs.CloudEnabled && prefs.AutofixMode != "" && prefs.AutofixMode != "off"
	// Always enqueue cloud so approval's cloud dependency is satisfiable. When
	// cloud is off, the child is skipped immediately (avoids approval stuck forever).
	kinds = append(kinds, kindCloud)
	out := make([]*scmJob, 0, len(kinds))
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, k := range kinds {
		cid := loadID("scmjob", parent.OrganizationID, parent.ProjectID, parent.RepoFullName, parent.CommitSHA, string(k), parent.ID)
		child := &scmJob{
			ID: cid, OrganizationID: parent.OrganizationID, ProjectID: parent.ProjectID,
			ConnectorID: parent.ConnectorID, RepoFullName: parent.RepoFullName,
			PRNumber: parent.PRNumber, CommitSHA: parent.CommitSHA, Event: parent.Event,
			Status: "queued", CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
			StartedAt: now, FinishedAt: now, Draft: parent.Draft, Title: parent.Title, Body: parent.Body,
			ForceAI: parent.ForceAI, AIOnly: parent.AIOnly, ActorUserID: parent.ActorUserID,
			Kind: string(k), RunID: parent.ID, ParentID: parent.ID, Attempt: parent.Attempt,
		}
		if k == kindBugbot && skipBugbot {
			child.Status = "skipped"
			child.Summary["skip_reason"] = skipBugbotReason
		}
		if k == kindCheckup && sandboxMode() != "docker" {
			child.Status = "skipped"
			child.Summary["skip_reason"] = "OPA_JOB_SANDBOX=docker required for checkup"
		}
		if k == kindCloud && !cloudOn {
			child.Status = "skipped"
			child.Summary["skip_reason"] = "cloud_enabled/autofix_mode off"
		}
		out = append(out, child)
	}
	return out
}

func supersedePRRun(runID, newSHA string) {
	job := getSCMJob(runID)
	if job == nil {
		return
	}
	// Prefer PR-wide supersede so intermediate commits (A running, B queued, C arrives)
	// all get cancelled — not only the single indexed run.
	if job.PRNumber > 0 && strings.TrimSpace(job.RepoFullName) != "" {
		supersedeInFlightPRJobs(job.RepoFullName, job.PRNumber, newSHA)
		return
	}
	reason := "Superseded by " + strings.TrimSpace(newSHA)
	if reason == "Superseded by " {
		reason = "Superseded by newer push"
	}
	// cancelSCMJobWithReason cascades children (cloud drains mid-push).
	_, _, _ = cancelSCMJobWithReason(runID, reason)
}

func listRunChildren(runID string) []*scmJob {
	parent := getSCMJob(runID)
	var ids []string
	if parent != nil && parent.Summary != nil {
		switch v := parent.Summary["child_ids"].(type) {
		case []string:
			ids = v
		case []interface{}:
			for _, x := range v {
				if s, ok := x.(string); ok && s != "" {
					ids = append(ids, s)
				}
			}
		}
	}
	out := []*scmJob{}
	seen := map[string]struct{}{}
	for _, id := range ids {
		if j := getSCMJob(id); j != nil {
			out = append(out, j)
			seen[id] = struct{}{}
		}
	}
	// Also scan live map for orphans (resume / partial persist).
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || j == nil || j.ParentID != runID {
			return true
		}
		if _, ok := seen[j.ID]; ok {
			return true
		}
		out = append(out, j)
		return true
	})
	return out
}

func childByKind(runID string, k agentKind) *scmJob {
	for _, c := range listRunChildren(runID) {
		if agentKind(c.Kind) == k {
			return c
		}
	}
	return nil
}

func jobTerminal(status string) bool {
	switch status {
	case "completed", "failed", "error", "cancelled", "skipped":
		return true
	default:
		return false
	}
}

func jobSucceeded(status string) bool {
	return status == "completed" || status == "skipped"
}

// readyChildren returns child jobs whose dependencies are all terminal-success
// (skipped counts as success for fan-in) and which are still queued/waiting.
func readyChildren(runID string) []*scmJob {
	children := listRunChildren(runID)
	byKind := map[agentKind]*scmJob{}
	for _, c := range children {
		byKind[agentKind(c.Kind)] = c
	}
	var ready []*scmJob
	for _, c := range children {
		if c.Status != "queued" && c.Status != "waiting" && c.Status != "" {
			continue
		}
		deps := agentDependsOn[agentKind(c.Kind)]
		ok := true
		for _, d := range deps {
			dep := byKind[d]
			if dep == nil || !jobTerminal(dep.Status) {
				ok = false
				break
			}
			// Hard failure of prepare blocks everything; soft-fail security/bugbot
			// still lets approval run (with Degraded) in later increments.
			if d == kindPrepare && dep.Status != "completed" && dep.Status != "skipped" {
				ok = false
				break
			}
		}
		if ok {
			ready = append(ready, c)
		}
	}
	return ready
}

// runPRRunAPIView mirrors child fields onto the parent for smoke/Dashboard
// compatibility (security_run_id / ai_job_id lived on the monolithic job).
func runPRRunAPIView(job *scmJob) map[string]interface{} {
	return runPRRunAPIViewWithView(job, "ops")
}

func runPRRunAPIViewWithView(job *scmJob, view string) map[string]interface{} {
	out := scmJobAPIViewWithOpts(job, view, false)
	if job == nil || agentKind(job.Kind) != kindRun {
		return out
	}
	children := listRunChildren(job.ID)
	compact := make([]map[string]interface{}, 0, len(children))
	childViews := make([]map[string]interface{}, 0, len(children))
	kinds := map[string]string{}
	for _, c := range children {
		kinds[c.Kind] = c.Status
		if c.SecurityRunID != "" && job.SecurityRunID == "" {
			out["security_run_id"] = c.SecurityRunID
		}
		if c.AIJobID != "" && job.AIJobID == "" {
			out["ai_job_id"] = c.AIJobID
		}
		// Ensure evidence exists for older jobs that never finalized.
		_ = evidenceFromJob(c)
		compact = append(compact, evidenceCompactSummary(c))
		childViews = append(childViews, scmJobAPIViewWithOpts(c, view, true))
	}
	out["children"] = childViews
	out["children_evidence"] = compact
	out["child_status"] = kinds
	out["status"] = foldRunStatus(children, job.Status)
	return out
}

func foldRunStatus(children []*scmJob, parentStatus string) string {
	if len(children) == 0 {
		return parentStatus
	}
	anyRunning, anyFailed, anyQueued, allTerminal := false, false, false, true
	for _, c := range children {
		switch c.Status {
		case "running", "waiting":
			anyRunning = true
			allTerminal = false
		case "queued", "":
			anyQueued = true
			allTerminal = false
		case "failed", "error":
			anyFailed = true
		case "cancelled":
			// count as terminal
		case "completed", "skipped":
		default:
			allTerminal = false
		}
	}
	if anyRunning {
		return "running"
	}
	if anyQueued {
		return "queued"
	}
	if !allTerminal {
		return parentStatus
	}
	if anyFailed {
		return "completed_with_errors"
	}
	if parentStatus == "cancelled" {
		return "cancelled"
	}
	return "completed"
}

// restartMidRunDoesNotDuplicate is the design proof for derived barriers:
// planning children is idempotent on (runID, kind). Missing kinds (e.g. cloud
// on runs planned before cloud was always enqueued) are filled in without
// duplicating existing children.
func ensureRunChildren(parent *scmJob) []*scmJob {
	existing := listRunChildren(parent.ID)
	prefs := agentPrefsFromSummary(parent)
	planned := planRunChildren(parent, prefs, false, "")
	have := map[agentKind]bool{}
	for _, c := range existing {
		have[agentKind(c.Kind)] = true
	}
	ids := make([]string, 0, len(existing)+len(planned))
	for _, c := range existing {
		ids = append(ids, c.ID)
	}
	added := false
	for _, c := range planned {
		k := agentKind(c.Kind)
		if have[k] {
			continue
		}
		if getSCMJob(c.ID) == nil {
			scmJobLive.Store(c.ID, c)
			persistSCMJob(c)
		}
		ids = append(ids, c.ID)
		have[k] = true
		added = true
	}
	if len(existing) == 0 || added {
		if parent.Summary == nil {
			parent.Summary = map[string]interface{}{}
		}
		parent.Summary["child_ids"] = ids
		persistSCMJob(parent)
	}
	return listRunChildren(parent.ID)
}

func agentPrefsFromSummary(job *scmJob) agentPrefs {
	if job == nil || job.Summary == nil {
		return builtinAgentPrefs()
	}
	raw, _ := json.Marshal(job.Summary["prefs"])
	var p agentPrefs
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	if p.TriggerMode == "" {
		p = builtinAgentPrefs()
	}
	return p
}
