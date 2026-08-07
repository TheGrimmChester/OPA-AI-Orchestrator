package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// opaReviewStack batches multiple (repo, PR) OPA Review jobs with limited concurrency.
type opaReviewStack struct {
	ID        string               `json:"id"`
	Status    string               `json:"status"` // queued | running | completed | failed
	JobIDs    []string             `json:"job_ids"`
	Items     []opaReviewStackItem `json:"items"`
	Force     bool                 `json:"force"`
	AIOnly    bool                 `json:"ai_only"`
	CreatedAt string               `json:"created_at"`
	UpdatedAt string               `json:"updated_at"`
	Honesty   string               `json:"honesty,omitempty"`
	Note      string               `json:"note,omitempty"`
}

type opaReviewStackItem struct {
	RepoFullName string `json:"repo_full_name"`
	PRNumber     int    `json:"pr_number"`
	ConnectorID  string `json:"connector_id,omitempty"`
	JobID        string `json:"job_id,omitempty"`
	Status       string `json:"status"` // waiting | queued | running | completed | failed | error | cancelled
	Error        string `json:"error,omitempty"`
	PreviewURL   string `json:"preview_url,omitempty"`
	Started      bool   `json:"started,omitempty"` // processSCMJob handed off (persisted for resume)
}

var reviewStackLive sync.Map // id -> *opaReviewStack

func scmProcessConcurrency() int {
	n := 1
	fmt.Sscanf(envOr("OPA_REVIEW_STACK_CONCURRENCY", "1"), "%d", &n)
	if n < 1 {
		n = 1
	}
	if n > 4 {
		n = 4
	}
	return n
}

var (
	scmProcessOnce sync.Once
	scmProcessSem  chan struct{}
)

func acquireSCMProcessSlot() {
	scmProcessOnce.Do(func() {
		scmProcessSem = make(chan struct{}, scmProcessConcurrency())
	})
	scmProcessSem <- struct{}{}
}

func releaseSCMProcessSlot() {
	<-scmProcessSem
}

const opaReviewStackAbsoluteMax = 500
const opaReviewStackSoftAdvisory = 40

// handleOPAReviewStack POST /api/scm/opa-review/stack (alias: /api/scm/ai-review/stack)
func handleOPAReviewStack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if st, msg := requireEnabledOAMProject(r, "ora"); st != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": msg})
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		Items   []opaReviewStackItem `json:"items"`
		Force   *bool                `json:"force"`
		AIOnly  bool                 `json:"ai_only"`
		Preview string               `json:"preview_url"`
	}
	if json.Unmarshal(raw, &body) != nil || len(body.Items) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "items[] required"})
		return
	}
	if len(body.Items) > opaReviewStackAbsoluteMax {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "error": fmt.Sprintf("max %d items per stack", opaReviewStackAbsoluteMax),
			"max": opaReviewStackAbsoluteMax, "count": len(body.Items),
			"honesty": "Absolute safety ceiling — split into fewer items if needed. Below the ceiling, large stacks wait and drain serially.",
		})
		return
	}
	force := true
	if body.Force != nil {
		force = *body.Force
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	stackID := "stack-" + newRandomHex(10)
	conc := scmProcessConcurrency()
	note := ""
	if len(body.Items) > opaReviewStackSoftAdvisory {
		note = "large stack — items wait and run serially"
	}
	stack := &opaReviewStack{
		ID: stackID, Status: "queued", Force: force, AIOnly: body.AIOnly,
		CreatedAt: now, UpdatedAt: now, Note: note,
		Honesty: "OPA Review stack — jobs run with OPA_REVIEW_STACK_CONCURRENCY (default 1). Excess items stay waiting until a slot frees. Each job packs full primary context for its repo + linked awareness. Inline findings + narrative résumé per PR.",
	}

	jobIDs := []string{}
	items := []opaReviewStackItem{}
	queuedSlots := 0
	for _, it := range body.Items {
		repo := strings.TrimSpace(it.RepoFullName)
		pr := it.PRNumber
		if repo == "" || pr <= 0 {
			items = append(items, opaReviewStackItem{
				RepoFullName: repo, PRNumber: pr, Status: "failed",
				Error: "repo_full_name and pr_number required",
			})
			continue
		}
		preview := strings.TrimSpace(nz(it.PreviewURL, body.Preview))
		actorUID := actorFromRequest(r).Username
		job, errMsg, code := enqueueManualAIReview(repo, pr, it.ConnectorID, "", "", false, force, body.AIOnly, true, actorUID)
		if errMsg != "" {
			st := "failed"
			if code == 409 && (strings.Contains(errMsg, "already merged") || strings.Contains(errMsg, "already reviewed")) {
				st = "skipped"
			}
			items = append(items, opaReviewStackItem{
				RepoFullName: repo, PRNumber: pr, ConnectorID: it.ConnectorID,
				Status: st, Error: fmt.Sprintf("%s (%d)", errMsg, code),
			})
			continue
		}
		if job.Summary == nil {
			job.Summary = map[string]interface{}{}
		}
		job.Summary["stack_id"] = stackID
		if preview != "" {
			job.Summary["preview_url"] = preview
		}
		jobIDs = append(jobIDs, job.ID)
		st := "waiting"
		if queuedSlots < conc {
			st = "queued"
			queuedSlots++
		} else {
			// Keep SCM job status aligned with stack waiting so Jobs UI shows drain backlog.
			job.Status = "waiting"
		}
		persistSCMJob(job)
		items = append(items, opaReviewStackItem{
			RepoFullName: repo, PRNumber: pr, ConnectorID: it.ConnectorID,
			JobID: job.ID, Status: st, PreviewURL: preview,
		})
	}
	stack.JobIDs = jobIDs
	stack.Items = items
	if len(jobIDs) == 0 {
		stack.Status = "failed"
	}
	reviewStackLive.Store(stackID, stack)
	persistOPAReviewStack(stack)
	if len(jobIDs) > 0 {
		go drainOPAReviewStack(stackID)
	}
	resp := map[string]interface{}{
		"ok": true, "stack_id": stackID, "job_ids": jobIDs,
		"status": stack.Status, "items": items,
		"concurrency": scmProcessConcurrency(),
		"honesty":     stack.Honesty,
		"count":       len(body.Items),
	}
	if note != "" {
		resp["note"] = note
	}
	writeJSON(w, resp)
}

func handleOPAReviewStackGet(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scm/opa-review/stacks/")
	path = strings.Trim(path, "/")
	if path == "" || path == r.URL.Path {
		path = strings.TrimPrefix(r.URL.Path, "/api/scm/ai-review/stacks/")
		path = strings.Trim(path, "/")
	}
	parts := strings.Split(path, "/")
	id := parts[0]
	if id == "" {
		http.Error(w, "stack id required", 400)
		return
	}
	if len(parts) >= 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		handleOPAReviewStackCancel(w, r, id)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	v, ok := reviewStackLive.Load(id)
	if !ok {
		http.Error(w, "stack not found", 404)
		return
	}
	stack := v.(*opaReviewStack)
	refreshOPAReviewStack(stack)
	writeJSON(w, stack)
}

func handleOPAReviewStackCancel(w http.ResponseWriter, r *http.Request, stackID string) {
	v, ok := reviewStackLive.Load(stackID)
	if !ok {
		http.Error(w, "stack not found", 404)
		return
	}
	stack := v.(*opaReviewStack)
	cancelled := 0
	for _, it := range stack.Items {
		if it.JobID == "" {
			continue
		}
		job, _, code := cancelSCMJob(it.JobID)
		if code == 0 && job != nil && job.Status == "cancelled" {
			cancelled++
		}
	}
	refreshOPAReviewStack(stack)
	writeJSON(w, map[string]interface{}{
		"ok": true, "stack_id": stackID, "cancelled": cancelled,
		"status": stack.Status, "items": stack.Items,
	})
}

func handleOPAReviewStackRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasSuffix(path, "/stack") || strings.HasSuffix(path, "/stack/") {
		handleOPAReviewStack(w, r)
		return
	}
	if strings.Contains(path, "/stacks/") {
		handleOPAReviewStackGet(w, r)
		return
	}
	http.Error(w, "not found", 404)
}

// drainOPAReviewStack runs jobs with bounded concurrency: waiting → queued → running.
// Unlike a fan-out WaitGroup over all JobIDs, only up to OPA_REVIEW_STACK_CONCURRENCY
// processSCMJob calls are in flight; the rest stay waiting until a slot frees.
func drainOPAReviewStack(stackID string) {
	v, ok := reviewStackLive.Load(stackID)
	if !ok {
		return
	}
	stack := v.(*opaReviewStack)
	// Ensure backlog is waiting — at most concurrency slots stay queued before work starts.
	assignStackConcurrencySlots(stack)
	stack.Status = "running"
	stack.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	reviewStackLive.Store(stackID, stack)
	persistOPAReviewStack(stack)

	conc := scmProcessConcurrency()
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex

	type work struct {
		idx   int
		jobID string
	}
	works := []work{}
	for i, it := range stack.Items {
		if it.JobID == "" || it.Status == "failed" || it.Status == "cancelled" {
			continue
		}
		if job := getSCMJob(it.JobID); job != nil && (job.Status == "cancelled" || job.Status == "completed" || job.Status == "failed" || job.Status == "error") {
			continue
		}
		works = append(works, work{idx: i, jobID: it.JobID})
	}

	for _, w := range works {
		wg.Add(1)
		go func(w work) {
			defer wg.Done()

			// Skip cancelled before taking a concurrency slot so waiting items can proceed.
			if job := getSCMJob(w.jobID); job != nil && job.Status == "cancelled" {
				mu.Lock()
				if v, ok := reviewStackLive.Load(stackID); ok {
					s := v.(*opaReviewStack)
					if w.idx < len(s.Items) {
						s.Items[w.idx].Status = "cancelled"
						s.Items[w.idx].Started = true
						reviewStackLive.Store(stackID, s)
					}
					refreshOPAReviewStack(s)
				}
				mu.Unlock()
				return
			}

			// Backlog must stay waiting until this goroutine holds a drain slot.
			// Otherwise resume/race can leave dozens falsely "queued" while blocked on sem.
			mu.Lock()
			if job := getSCMJob(w.jobID); job != nil {
				switch job.Status {
				case "queued", "":
					job.Status = "waiting"
					persistSCMJob(job)
				}
			}
			if v, ok := reviewStackLive.Load(stackID); ok {
				s := v.(*opaReviewStack)
				if w.idx < len(s.Items) && s.Items[w.idx].Status == "queued" {
					s.Items[w.idx].Status = "waiting"
					s.Items[w.idx].Started = false
					reviewStackLive.Store(stackID, s)
				}
			}
			mu.Unlock()

			sem <- struct{}{}
			defer func() { <-sem }()

			mu.Lock()
			if job := getSCMJob(w.jobID); job != nil && job.Status == "cancelled" {
				if v, ok := reviewStackLive.Load(stackID); ok {
					s := v.(*opaReviewStack)
					if w.idx < len(s.Items) {
						s.Items[w.idx].Status = "cancelled"
						s.Items[w.idx].Started = true
						reviewStackLive.Store(stackID, s)
					}
					refreshOPAReviewStack(s)
				}
				mu.Unlock()
				return
			}
			if v, ok := reviewStackLive.Load(stackID); ok {
				s := v.(*opaReviewStack)
				if w.idx < len(s.Items) {
					s.Items[w.idx].Status = "queued"
					s.Items[w.idx].Started = true
					s.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
					reviewStackLive.Store(stackID, s)
				}
			}
			if job := getSCMJob(w.jobID); job != nil && (job.Status == "waiting" || job.Status == "" || job.Status == "queued") {
				job.Status = "queued"
				persistSCMJob(job)
			}
			mu.Unlock()

			processSCMJob(w.jobID)

			mu.Lock()
			if v, ok := reviewStackLive.Load(stackID); ok {
				refreshOPAReviewStack(v.(*opaReviewStack))
			}
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	if v, ok := reviewStackLive.Load(stackID); ok {
		refreshOPAReviewStack(v.(*opaReviewStack))
	}
}

func refreshOPAReviewStack(stack *opaReviewStack) {
	if stack == nil {
		return
	}
	anyRunning := false
	anyQueued := false
	anyWaiting := false
	anyFailed := false
	allDone := true
	for i := range stack.Items {
		it := &stack.Items[i]
		if it.JobID == "" {
			if it.Status != "failed" {
				it.Status = "failed"
			}
			anyFailed = true
			continue
		}
		job := getSCMJob(it.JobID)
		if job == nil {
			it.Status = "failed"
			it.Error = "job missing"
			anyFailed = true
			allDone = false
			continue
		}
		// Preserve waiting until this item has been handed to processSCMJob.
		if job.Status == "cancelled" {
			it.Status = "cancelled"
			it.Error = job.Error
			continue
		}
		if !it.Started && (job.Status == "queued" || job.Status == "waiting" || job.Status == "") {
			if job.Status == "waiting" || it.Status != "queued" {
				it.Status = "waiting"
				anyWaiting = true
			} else {
				it.Status = "queued"
				anyQueued = true
			}
			allDone = false
			continue
		}
		it.Status = job.Status
		it.Error = job.Error
		switch job.Status {
		case "queued":
			anyQueued = true
			allDone = false
		case "running":
			anyRunning = true
			allDone = false
		case "failed", "error":
			anyFailed = true
		case "cancelled":
			// terminal — not a failure of the remaining stack drain
		case "completed":
			// ok
		default:
			allDone = false
		}
	}
	switch {
	case anyRunning || anyWaiting || (anyQueued && stack.Status == "running"):
		stack.Status = "running"
	case allDone && anyFailed:
		stack.Status = "failed"
	case allDone:
		stack.Status = "completed"
	case anyQueued || anyWaiting:
		stack.Status = "queued"
	default:
		stack.Status = "running"
	}
	stack.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	reviewStackLive.Store(stack.ID, stack)
	persistOPAReviewStack(stack)
}
