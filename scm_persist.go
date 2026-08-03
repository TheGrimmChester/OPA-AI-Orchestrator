package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SCM job + OPA Review stack durability.
//
// ClickHouse already receives scm_jobs rows (history), but list/drain state lived
// only in sync.Map and vanished on Agent recreate. Active jobs and stacks are
// also snapshotted under $OPA_SCM_STATE_DIR (default $OPA_SECURITY_WORKSPACE/scm-state)
// so smoke bind-mounts (/workspace) and production data dirs keep Select-all
// stacks across restarts. Stacks are dual-written to opa.scm_review_stacks.

var (
	scmPersistMu       sync.Mutex
	scmResumeDrainOnce sync.Once
)

func scmStateDir() string {
	if d := strings.TrimSpace(os.Getenv("OPA_SCM_STATE_DIR")); d != "" {
		return d
	}
	return filepath.Join(securityWorkspaceRoot(), "scm-state")
}

func scmJobsStateDir() string  { return filepath.Join(scmStateDir(), "jobs") }
func scmStacksStateDir() string { return filepath.Join(scmStateDir(), "stacks") }

func ensureSCMStateDirs() error {
	for _, d := range []string{scmJobsStateDir(), scmStacksStateDir(), scmWebhooksStateDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func persistSCMJobFile(job *scmJob) {
	if job == nil || job.ID == "" {
		return
	}
	scmPersistMu.Lock()
	defer scmPersistMu.Unlock()
	if err := ensureSCMStateDirs(); err != nil {
		log.Printf("[WARN] scm-state mkdir: %v", err)
		return
	}
	path := filepath.Join(scmJobsStateDir(), job.ID+".json")
	raw, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		log.Printf("[WARN] scm job file write %s: %v", job.ID, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		log.Printf("[WARN] scm job file rename %s: %v", job.ID, err)
	}
}

func persistOPAReviewStackFile(stack *opaReviewStack) {
	if stack == nil || stack.ID == "" {
		return
	}
	scmPersistMu.Lock()
	defer scmPersistMu.Unlock()
	if err := ensureSCMStateDirs(); err != nil {
		log.Printf("[WARN] scm-state mkdir: %v", err)
		return
	}
	path := filepath.Join(scmStacksStateDir(), stack.ID+".json")
	raw, err := json.MarshalIndent(stack, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		log.Printf("[WARN] scm stack file write %s: %v", stack.ID, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		log.Printf("[WARN] scm stack file rename %s: %v", stack.ID, err)
	}
}

func persistOPAReviewStack(stack *opaReviewStack) {
	if stack == nil {
		return
	}
	persistOPAReviewStackFile(stack)
	persistOPAReviewStackCH(stack)
}

func persistOPAReviewStackCH(stack *opaReviewStack) {
	if writer == nil || stack == nil {
		return
	}
	jobIDs, _ := json.Marshal(stack.JobIDs)
	items, _ := json.Marshal(stack.Items)
	force, aiOnly := 0, 0
	if stack.Force {
		force = 1
	}
	if stack.AIOnly {
		aiOnly = 1
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"id": stack.ID, "status": stack.Status,
		"job_ids_json": string(jobIDs), "items_json": string(items),
		"force": force, "ai_only": aiOnly,
		"note": stack.Note, "honesty": stack.Honesty,
		"created_at": stack.CreatedAt, "updated_at": stack.UpdatedAt,
	})
	writer.insertAsync("scm_review_stacks", append(payload, '\n'))
}

func loadSCMJobFile(id string) *scmJob {
	raw, err := os.ReadFile(filepath.Join(scmJobsStateDir(), id+".json"))
	if err != nil {
		return nil
	}
	var job scmJob
	if json.Unmarshal(raw, &job) != nil || job.ID == "" {
		return nil
	}
	return &job
}

func loadOPAReviewStackFile(id string) *opaReviewStack {
	raw, err := os.ReadFile(filepath.Join(scmStacksStateDir(), id+".json"))
	if err != nil {
		return nil
	}
	var stack opaReviewStack
	if json.Unmarshal(raw, &stack) != nil || stack.ID == "" {
		return nil
	}
	return &stack
}

func hydrateSCMJobsFromFiles() int {
	entries, err := os.ReadDir(scmJobsStateDir())
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if _, ok := scmJobLive.Load(id); ok {
			continue
		}
		job := loadSCMJobFile(id)
		if job == nil {
			continue
		}
		scmJobLive.Store(job.ID, job)
		n++
	}
	return n
}

func hydrateSCMStacksFromFiles() int {
	entries, err := os.ReadDir(scmStacksStateDir())
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if _, ok := reviewStackLive.Load(id); ok {
			continue
		}
		stack := loadOPAReviewStackFile(id)
		if stack == nil {
			continue
		}
		reviewStackLive.Store(stack.ID, stack)
		n++
	}
	return n
}

func hydrateSCMJobsFromCH() int {
	if queryClient == nil {
		return 0
	}
	// Prefer recent active rows; ReplacingMergeTree may lag — files are primary.
	rows, err := queryClient.Query(`
		SELECT id, organization_id, project_id, connector_id, repo_full_name, pr_number,
		       commit_sha, event, status, security_run_id, ai_job_id, check_run_ids,
		       error, summary_json, started_at, finished_at
		FROM opa.scm_jobs
		WHERE status IN ('queued','waiting','running')
		ORDER BY started_at DESC
		LIMIT 500`)
	if err != nil {
		log.Printf("[WARN] hydrateSCMJobsFromCH: %v", err)
		return 0
	}
	n := 0
	for _, row := range rows {
		job := scmJobFromCHRow(row)
		if job == nil || job.ID == "" {
			continue
		}
		if _, ok := scmJobLive.Load(job.ID); ok {
			continue
		}
		scmJobLive.Store(job.ID, job)
		persistSCMJobFile(job) // backfill file mirror
		n++
	}
	return n
}

func hydrateSCMStacksFromCH() int {
	if queryClient == nil {
		return 0
	}
	rows, err := queryClient.Query(`
		SELECT id, status, job_ids_json, items_json, force, ai_only, note, honesty, created_at, updated_at
		FROM opa.scm_review_stacks
		WHERE status IN ('queued','running')
		ORDER BY updated_at DESC
		LIMIT 200`)
	if err != nil {
		// Table may not exist yet on older deploys before migrate 37.
		log.Printf("[WARN] hydrateSCMStacksFromCH: %v", err)
		return 0
	}
	n := 0
	for _, row := range rows {
		stack := opaReviewStackFromCHRow(row)
		if stack == nil || stack.ID == "" {
			continue
		}
		if _, ok := reviewStackLive.Load(stack.ID); ok {
			continue
		}
		reviewStackLive.Store(stack.ID, stack)
		persistOPAReviewStackFile(stack)
		n++
	}
	return n
}

func scmJobFromCHRow(row map[string]interface{}) *scmJob {
	id := strFromAny(row["id"])
	if id == "" {
		return nil
	}
	job := &scmJob{
		ID: id, OrganizationID: strFromAny(row["organization_id"]), ProjectID: strFromAny(row["project_id"]),
		ConnectorID: strFromAny(row["connector_id"]), RepoFullName: strFromAny(row["repo_full_name"]),
		PRNumber: intFromAny(row["pr_number"]), CommitSHA: strFromAny(row["commit_sha"]),
		Event: strFromAny(row["event"]), Status: strFromAny(row["status"]),
		SecurityRunID: strFromAny(row["security_run_id"]), AIJobID: strFromAny(row["ai_job_id"]),
		Error: strFromAny(row["error"]),
		StartedAt: strFromAny(row["started_at"]), FinishedAt: strFromAny(row["finished_at"]),
		CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
	}
	if raw := strFromAny(row["check_run_ids"]); raw != "" {
		_ = json.Unmarshal([]byte(raw), &job.CheckRunIDs)
	}
	if raw := strFromAny(row["summary_json"]); raw != "" {
		_ = json.Unmarshal([]byte(raw), &job.Summary)
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	if v, ok := job.Summary["force_ai"].(bool); ok {
		job.ForceAI = v
	}
	if v, ok := job.Summary["ai_only"].(bool); ok {
		job.AIOnly = v
	}
	if uid, _ := job.Summary["actor_user_id"].(string); strings.TrimSpace(uid) != "" {
		job.ActorUserID = strings.TrimSpace(uid)
	}
	if k, _ := job.Summary["kind"].(string); strings.TrimSpace(k) != "" {
		job.Kind = strings.TrimSpace(k)
	}
	if rid, _ := job.Summary["run_id"].(string); strings.TrimSpace(rid) != "" {
		job.RunID = strings.TrimSpace(rid)
	}
	if pid, _ := job.Summary["parent_id"].(string); strings.TrimSpace(pid) != "" {
		job.ParentID = strings.TrimSpace(pid)
	}
	if n, ok := job.Summary["attempt"].(float64); ok && int(n) > 0 {
		job.Attempt = int(n)
	} else if n, ok := job.Summary["attempt"].(int); ok && n > 0 {
		job.Attempt = n
	}
	return job
}

func opaReviewStackFromCHRow(row map[string]interface{}) *opaReviewStack {
	id := strFromAny(row["id"])
	if id == "" {
		return nil
	}
	stack := &opaReviewStack{
		ID: id, Status: strFromAny(row["status"]),
		Note: strFromAny(row["note"]), Honesty: strFromAny(row["honesty"]),
		CreatedAt: strFromAny(row["created_at"]), UpdatedAt: strFromAny(row["updated_at"]),
		Force: intFromAny(row["force"]) != 0, AIOnly: intFromAny(row["ai_only"]) != 0,
	}
	if raw := strFromAny(row["job_ids_json"]); raw != "" {
		_ = json.Unmarshal([]byte(raw), &stack.JobIDs)
	}
	if raw := strFromAny(row["items_json"]); raw != "" {
		_ = json.Unmarshal([]byte(raw), &stack.Items)
	}
	return stack
}

func strFromAny(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		if v == nil {
			return ""
		}
		return strings.TrimSpace(toString(v))
	}
}

func intFromAny(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		return atoiDefault(t, 0)
	default:
		return 0
	}
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// hydrateSCMJobsAndStacksOnBoot reloads durable job/stack state and resumes drain.
func hydrateSCMJobsAndStacksOnBoot() {
	_ = ensureSCMStateDirs()
	nf := hydrateSCMJobsFromFiles()
	nc := hydrateSCMJobsFromCH()
	sf := hydrateSCMStacksFromFiles()
	sc := hydrateSCMStacksFromCH()
	log.Printf("[INFO] SCM job/stack hydrate: jobs file=%d ch=%d; stacks file=%d ch=%d; state_dir=%s",
		nf, nc, sf, sc, scmStateDir())
	rebuildSuccessfulAIReviewIndex()
	hydrateSCMWebhooksOnBoot()
	nRun, _ := recoverStuckRunningSCMJobs()
	if nRun > 0 {
		log.Printf("[INFO] SCM recovered %d stuck running job(s) after restart", nRun)
	}
	if nPR := rebuildPRRunIndexFromLive(); nPR > 0 {
		log.Printf("[INFO] SCM rebuilt PR run index for %d in-flight PR run(s)", nPR)
	}
	if nSuper := pruneSupersededInFlightPRRuns(); nSuper > 0 {
		log.Printf("[INFO] SCM pruned %d superseded in-flight PR job(s) after restart", nSuper)
	}
	nOrphan := reconstructOrphanStacksFromJobs()
	if nOrphan > 0 {
		log.Printf("[INFO] SCM reconstructed %d orphan stack(s) from job summaries", nOrphan)
	}
	nNorm := normalizeAllStackJobSlots()
	if nNorm > 0 {
		log.Printf("[INFO] SCM normalized %d stack job status(es) to waiting/queued slots", nNorm)
	}
	resumeIncompleteOPAReviewStacks()
	// Non-stack queued jobs previously only got processSCMJob at enqueue time; after
	// recreate those goroutines are gone and status=queued stalls forever. Re-dispatch
	// all of them (bounded by scmProcessSem). Stack members are owned by drain above.
	nQueued := dispatchQueuedNonStackSCMJobs()
	if nQueued > 0 {
		log.Printf("[INFO] SCM re-dispatched %d queued non-stack job(s) after restart", nQueued)
	}
}

// dispatchQueuedNonStackSCMJobs starts processSCMJob for every non-stack job still
// in queued (or empty) status. Returns how many goroutines were spawned. Safe to call
// from boot or the admin resume endpoint; processSCMJob dedupes in-flight IDs.
func dispatchQueuedNonStackSCMJobs() int {
	type item struct {
		id        string
		startedAt string
	}
	var list []item
	scmJobLive.Range(func(_, v interface{}) bool {
		job, ok := v.(*scmJob)
		if !ok || job == nil {
			return true
		}
		switch job.Status {
		case "queued", "":
		default:
			return true
		}
		if scmJobBelongsToStack(job.ID) {
			return true
		}
		list = append(list, item{id: job.ID, startedAt: job.StartedAt})
		return true
	})
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].startedAt < list[j].startedAt
	})
	for _, it := range list {
		jobID := it.id
		go processSCMJob(jobID)
	}
	return len(list)
}

// resumeSCMProcessing kicks incomplete stack drains and re-dispatches orphaned
// non-stack queued jobs. Used by POST /api/scm/jobs/resume after recreates or stalls.
func resumeSCMProcessing() (stacks int, queued int) {
	reviewStackLive.Range(func(_, v interface{}) bool {
		stack, ok := v.(*opaReviewStack)
		if !ok || stack == nil {
			return true
		}
		if !stackNeedsResume(stack) {
			return true
		}
		prepareStackForResume(stack)
		persistOPAReviewStack(stack)
		id := stack.ID
		log.Printf("[INFO] admin resume: OPA Review stack drain %s (%s)", id, stack.Status)
		go drainOPAReviewStack(id)
		stacks++
		return true
	})
	queued = dispatchQueuedNonStackSCMJobs()
	if queued > 0 {
		log.Printf("[INFO] admin resume: re-dispatched %d queued non-stack job(s)", queued)
	}
	return stacks, queued
}

// recoverStuckRunningSCMJobs resets orphaned running jobs after Agent restart.
// Nothing is actually processing yet, so leaving status=running would stall forever.
// Stack members become waiting (slot assignment happens in prepareStackForResume);
// non-stack jobs become queued. Re-dispatch of queued non-stack jobs is handled by
// dispatchQueuedNonStackSCMJobs after stack drains are resumed.
func recoverStuckRunningSCMJobs() (int, []string) {
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	var resume []string
	n := 0
	scmJobLive.Range(func(_, v interface{}) bool {
		job, ok := v.(*scmJob)
		if !ok || job == nil || job.Status != "running" {
			return true
		}
		if job.Summary == nil {
			job.Summary = map[string]interface{}{}
		}
		job.Summary["recovered_from_restart"] = true
		job.Error = ""
		job.StartedAt = now
		if scmJobBelongsToStack(job.ID) {
			job.Status = "waiting"
		} else {
			job.Status = "queued"
			resume = append(resume, job.ID)
		}
		persistSCMJob(job)
		n++
		return true
	})
	return n, resume
}

func scmJobBelongsToStack(jobID string) bool {
	if jobID == "" {
		return false
	}
	found := false
	reviewStackLive.Range(func(_, v interface{}) bool {
		stack, ok := v.(*opaReviewStack)
		if !ok || stack == nil {
			return true
		}
		for _, it := range stack.Items {
			if it.JobID == jobID {
				found = true
				return false
			}
		}
		if !found {
			for _, id := range stack.JobIDs {
				if id == jobID {
					found = true
					return false
				}
			}
		}
		return true
	})
	if found {
		return true
	}
	if job := getSCMJob(jobID); job != nil && job.Summary != nil {
		if sid, _ := job.Summary["stack_id"].(string); strings.TrimSpace(sid) != "" {
			return true
		}
	}
	return false
}

// reconstructOrphanStacksFromJobs rebuilds reviewStackLive entries when jobs still
// carry summary.stack_id but the stack JSON/CH row was lost (pre-persist or crash).
func reconstructOrphanStacksFromJobs() int {
	type agg struct {
		jobs []*scmJob
	}
	by := map[string]*agg{}
	scmJobLive.Range(func(_, v interface{}) bool {
		job, ok := v.(*scmJob)
		if !ok || job == nil || job.Summary == nil {
			return true
		}
		sid, _ := job.Summary["stack_id"].(string)
		sid = strings.TrimSpace(sid)
		if sid == "" {
			return true
		}
		switch job.Status {
		case "queued", "waiting", "running":
			// only need incomplete members to decide reconstruction
		case "completed", "failed", "error", "cancelled":
			// still attach so stack history is coherent
		default:
			return true
		}
		if _, ok := reviewStackLive.Load(sid); ok {
			return true
		}
		a := by[sid]
		if a == nil {
			a = &agg{}
			by[sid] = a
		}
		a.jobs = append(a.jobs, job)
		return true
	})
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for sid, a := range by {
		if len(a.jobs) == 0 {
			continue
		}
		sort.SliceStable(a.jobs, func(i, j int) bool {
			return a.jobs[i].StartedAt < a.jobs[j].StartedAt
		})
		items := make([]opaReviewStackItem, 0, len(a.jobs))
		jobIDs := make([]string, 0, len(a.jobs))
		anyIncomplete := false
		for _, job := range a.jobs {
			jobIDs = append(jobIDs, job.ID)
			st := job.Status
			started := st == "completed" || st == "failed" || st == "error" || st == "cancelled" || st == "running"
			if st == "queued" || st == "waiting" || st == "running" {
				anyIncomplete = true
			}
			items = append(items, opaReviewStackItem{
				RepoFullName: job.RepoFullName, PRNumber: job.PRNumber,
				ConnectorID: job.ConnectorID, JobID: job.ID, Status: st, Started: started,
				Error: job.Error,
			})
		}
		if !anyIncomplete {
			continue
		}
		stack := &opaReviewStack{
			ID: sid, Status: "queued", JobIDs: jobIDs, Items: items,
			CreatedAt: now, UpdatedAt: now,
			Note:    "reconstructed from job summaries after restart",
			Honesty: "Stack record was missing on disk/CH; rebuilt from scm jobs with this stack_id so drain can resume.",
		}
		reviewStackLive.Store(sid, stack)
		persistOPAReviewStack(stack)
		n++
	}
	return n
}

// normalizeAllStackJobSlots enforces at most scmProcessConcurrency() queued+running
// jobs per stack_id (from live stacks and/or job summaries). Excess → waiting.
func normalizeAllStackJobSlots() int {
	conc := scmProcessConcurrency()
	type agg struct {
		jobs []*scmJob
	}
	by := map[string]*agg{}
	scmJobLive.Range(func(_, v interface{}) bool {
		job, ok := v.(*scmJob)
		if !ok || job == nil {
			return true
		}
		sid := ""
		if job.Summary != nil {
			sid, _ = job.Summary["stack_id"].(string)
			sid = strings.TrimSpace(sid)
		}
		if sid == "" {
			return true
		}
		switch job.Status {
		case "queued", "waiting", "running":
		default:
			return true
		}
		a := by[sid]
		if a == nil {
			a = &agg{}
			by[sid] = a
		}
		a.jobs = append(a.jobs, job)
		return true
	})
	changed := 0
	for sid, a := range by {
		sort.SliceStable(a.jobs, func(i, j int) bool {
			return a.jobs[i].StartedAt < a.jobs[j].StartedAt
		})
		slots := 0
		for _, job := range a.jobs {
			switch job.Status {
			case "running":
				slots++
			case "queued", "waiting":
				if slots < conc {
					if job.Status != "queued" {
						job.Status = "queued"
						persistSCMJob(job)
						changed++
					}
					slots++
				} else if job.Status != "waiting" {
					job.Status = "waiting"
					persistSCMJob(job)
					changed++
				}
			}
		}
		if v, ok := reviewStackLive.Load(sid); ok {
			if stack, ok := v.(*opaReviewStack); ok && stack != nil {
				assignStackConcurrencySlots(stack)
				persistOPAReviewStack(stack)
			}
		}
	}
	return changed
}

func resumeIncompleteOPAReviewStacks() {
	scmResumeDrainOnce.Do(func() {
		reviewStackLive.Range(func(_, v interface{}) bool {
			stack, ok := v.(*opaReviewStack)
			if !ok || stack == nil {
				return true
			}
			if !stackNeedsResume(stack) {
				return true
			}
			prepareStackForResume(stack)
			persistOPAReviewStack(stack)
			id := stack.ID
			log.Printf("[INFO] resuming OPA Review stack drain %s (%s)", id, stack.Status)
			go drainOPAReviewStack(id)
			return true
		})
	})
}

func stackNeedsResume(stack *opaReviewStack) bool {
	if stack == nil {
		return false
	}
	switch stack.Status {
	case "queued", "running":
		return true
	}
	for _, it := range stack.Items {
		st := it.Status
		if st == "" {
			if job := getSCMJob(it.JobID); job != nil {
				st = job.Status
			}
		}
		switch st {
		case "waiting", "queued", "running":
			return true
		}
	}
	return false
}

// prepareStackForResume demotes interrupted work and assigns at most
// OPA_REVIEW_STACK_CONCURRENCY jobs to queued; the rest stay waiting.
func prepareStackForResume(stack *opaReviewStack) {
	if stack == nil {
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for i := range stack.Items {
		it := &stack.Items[i]
		job := getSCMJob(it.JobID)
		if job == nil {
			continue
		}
		switch job.Status {
		case "running":
			// Interrupted mid-flight — not processing after restart.
			if job.Summary == nil {
				job.Summary = map[string]interface{}{}
			}
			job.Summary["recovered_from_restart"] = true
			job.Status = "waiting"
			job.Error = ""
			job.StartedAt = now
			persistSCMJob(job)
			it.Status = "waiting"
			it.Started = false
			it.Error = ""
		case "queued", "waiting", "":
			it.Status = "waiting"
			it.Started = false
		case "cancelled", "completed", "failed", "error":
			it.Status = job.Status
			it.Started = true
			it.Error = job.Error
		}
	}
	assignStackConcurrencySlots(stack)
	stack.Status = "queued"
	stack.UpdatedAt = now
	reviewStackLive.Store(stack.ID, stack)
}

// assignStackConcurrencySlots keeps at most scmProcessConcurrency() incomplete
// stack items in queued (+ any already running). Remaining incomplete items are waiting.
func assignStackConcurrencySlots(stack *opaReviewStack) {
	if stack == nil {
		return
	}
	conc := scmProcessConcurrency()
	slots := 0
	for i := range stack.Items {
		it := &stack.Items[i]
		job := getSCMJob(it.JobID)
		if job == nil {
			continue
		}
		switch job.Status {
		case "cancelled", "completed", "failed", "error":
			it.Status = job.Status
			it.Started = true
			it.Error = job.Error
		case "running":
			slots++
			it.Status = "running"
			it.Started = true
		case "queued", "waiting", "":
			if slots < conc {
				if job.Status != "queued" {
					job.Status = "queued"
					persistSCMJob(job)
				}
				it.Status = "queued"
				it.Started = false
				slots++
			} else {
				if job.Status != "waiting" {
					job.Status = "waiting"
					persistSCMJob(job)
				}
				it.Status = "waiting"
				it.Started = false
			}
		}
	}
}
