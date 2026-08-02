package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// scmWebhookReceipt records one GitHub delivery and the orchestrator's decision.
// Dual-written to scm-state/webhooks/*.json and opa.scm_webhooks (ClickHouse).
type scmWebhookReceipt struct {
	ID               string `json:"id"`
	ReceivedAt       string `json:"received_at"`
	DeliveryID       string `json:"delivery_id"`
	Event            string `json:"event"`
	Action           string `json:"action"`
	RepoFullName     string `json:"repo_full_name"`
	PRNumber         int    `json:"pr_number"`
	CommitSHA        string `json:"commit_sha"`
	InstallationID   string `json:"installation_id"`
	OrganizationID   string `json:"organization_id"`
	ProjectID        string `json:"project_id"`
	ConnectorID      string `json:"connector_id"`
	SignatureValid   bool   `json:"signature_valid"`
	Outcome          string `json:"outcome"` // queued | ignored | skipped | error | ping | duplicate
	JobID            string `json:"job_id,omitempty"`
	StackID          string `json:"stack_id,omitempty"`
	Error            string `json:"error,omitempty"`
	Honesty          string `json:"honesty"`
	HTTPStatus       int    `json:"http_status"`
	Source           string `json:"source,omitempty"` // live | backfill
}

var scmWebhookLive sync.Map // id -> *scmWebhookReceipt

func scmWebhooksStateDir() string { return filepath.Join(scmStateDir(), "webhooks") }

func ensureSCMWebhookDirs() error {
	return os.MkdirAll(scmWebhooksStateDir(), 0o755)
}

func persistSCMWebhook(rec *scmWebhookReceipt) {
	if rec == nil || rec.ID == "" {
		return
	}
	scmWebhookLive.Store(rec.ID, rec)
	persistSCMWebhookFile(rec)
	persistSCMWebhookCH(rec)
}

func persistSCMWebhookFile(rec *scmWebhookReceipt) {
	if rec == nil || rec.ID == "" {
		return
	}
	scmPersistMu.Lock()
	defer scmPersistMu.Unlock()
	if err := ensureSCMWebhookDirs(); err != nil {
		log.Printf("[WARN] scm-webhook mkdir: %v", err)
		return
	}
	path := filepath.Join(scmWebhooksStateDir(), rec.ID+".json")
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		log.Printf("[WARN] scm webhook file write %s: %v", rec.ID, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		log.Printf("[WARN] scm webhook file rename %s: %v", rec.ID, err)
	}
}

func persistSCMWebhookCH(rec *scmWebhookReceipt) {
	if writer == nil || rec == nil {
		return
	}
	sig := 0
	if rec.SignatureValid {
		sig = 1
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"id": rec.ID, "received_at": rec.ReceivedAt, "delivery_id": rec.DeliveryID,
		"event": rec.Event, "action": rec.Action, "repo_full_name": rec.RepoFullName,
		"pr_number": rec.PRNumber, "commit_sha": rec.CommitSHA,
		"installation_id": rec.InstallationID,
		"organization_id": rec.OrganizationID, "project_id": rec.ProjectID,
		"connector_id": rec.ConnectorID, "signature_valid": sig,
		"outcome": rec.Outcome, "job_id": rec.JobID, "stack_id": rec.StackID,
		"error": rec.Error, "honesty": rec.Honesty, "http_status": rec.HTTPStatus,
		"source": nz(rec.Source, "live"),
	})
	writer.insertAsync("scm_webhooks", append(payload, '\n'))
}

func loadSCMWebhookFile(id string) *scmWebhookReceipt {
	raw, err := os.ReadFile(filepath.Join(scmWebhooksStateDir(), id+".json"))
	if err != nil {
		return nil
	}
	var rec scmWebhookReceipt
	if json.Unmarshal(raw, &rec) != nil || rec.ID == "" {
		return nil
	}
	return &rec
}

func getSCMWebhook(id string) *scmWebhookReceipt {
	if v, ok := scmWebhookLive.Load(id); ok {
		if r, ok := v.(*scmWebhookReceipt); ok {
			return r
		}
	}
	if rec := loadSCMWebhookFile(id); rec != nil {
		scmWebhookLive.Store(rec.ID, rec)
		return rec
	}
	return nil
}

func findSCMWebhookByDelivery(deliveryID string) *scmWebhookReceipt {
	deliveryID = strings.TrimSpace(deliveryID)
	if deliveryID == "" {
		return nil
	}
	var found *scmWebhookReceipt
	scmWebhookLive.Range(func(_, v interface{}) bool {
		r, ok := v.(*scmWebhookReceipt)
		if !ok || r == nil {
			return true
		}
		if r.DeliveryID == deliveryID && r.Source != "backfill" {
			found = r
			return false
		}
		return true
	})
	return found
}

func hydrateSCMWebhooksFromFiles() int {
	entries, err := os.ReadDir(scmWebhooksStateDir())
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if _, ok := scmWebhookLive.Load(id); ok {
			continue
		}
		rec := loadSCMWebhookFile(id)
		if rec == nil {
			continue
		}
		scmWebhookLive.Store(rec.ID, rec)
		// Re-mirror to ClickHouse so a late CREATE TABLE / recreate still fills CH.
		persistSCMWebhookCH(rec)
		n++
	}
	return n
}

func hydrateSCMWebhooksFromCH() int {
	if queryClient == nil {
		return 0
	}
	rows, err := queryClient.Query(`
		SELECT id, received_at, delivery_id, event, action, repo_full_name,
		       pr_number, commit_sha, installation_id, organization_id, project_id,
		       connector_id, signature_valid, outcome, job_id, stack_id, error,
		       honesty, http_status, source
		FROM opa.scm_webhooks
		ORDER BY received_at DESC
		LIMIT 2000`)
	if err != nil {
		// Table may not exist yet on older deploys before migrate 40.
		log.Printf("[WARN] hydrateSCMWebhooksFromCH: %v", err)
		return 0
	}
	n := 0
	for _, row := range rows {
		id := toString(row["id"])
		if id == "" {
			continue
		}
		if _, ok := scmWebhookLive.Load(id); ok {
			continue
		}
		sig := false
		switch v := row["signature_valid"].(type) {
		case float64:
			sig = v != 0
		case int64:
			sig = v != 0
		case string:
			sig = v == "1" || strings.EqualFold(v, "true")
		}
		rec := &scmWebhookReceipt{
			ID: id, ReceivedAt: toString(row["received_at"]), DeliveryID: toString(row["delivery_id"]),
			Event: toString(row["event"]), Action: toString(row["action"]),
			RepoFullName: toString(row["repo_full_name"]), PRNumber: int(getFloat64(row, "pr_number")),
			CommitSHA: toString(row["commit_sha"]), InstallationID: toString(row["installation_id"]),
			OrganizationID: toString(row["organization_id"]), ProjectID: toString(row["project_id"]),
			ConnectorID: toString(row["connector_id"]), SignatureValid: sig,
			Outcome: toString(row["outcome"]), JobID: toString(row["job_id"]),
			StackID: toString(row["stack_id"]), Error: toString(row["error"]),
			Honesty: toString(row["honesty"]), HTTPStatus: int(getFloat64(row, "http_status")),
			Source: toString(row["source"]),
		}
		scmWebhookLive.Store(rec.ID, rec)
		n++
	}
	return n
}

// backfillSCMWebhooksFromJobs synthesizes receipts for webhook-origin jobs that
// predate live capture so the Dashboard Webhooks tab is not empty on first deploy.
// Skips jobs that already have any receipt (live or prior backfill) for the same job_id
// so the Webhooks tab does not show duplicate live+backfill rows.
func backfillSCMWebhooksFromJobs() int {
	n := 0
	scmJobLive.Range(func(_, v interface{}) bool {
		job, ok := v.(*scmJob)
		if !ok || job == nil {
			return true
		}
		event, action := splitWebhookJobEvent(job.Event)
		if event == "" {
			return true
		}
		if findSCMWebhookByJobID(job.ID) != nil {
			return true
		}
		id := "scmwh-bf-" + strings.TrimPrefix(job.ID, "scmjob-")
		if len(id) > 40 {
			id = loadID("scmwh", "bf", job.ID)
		}
		if _, exists := scmWebhookLive.Load(id); exists {
			return true
		}
		if loadSCMWebhookFile(id) != nil {
			return true
		}
		stackID := ""
		if job.Summary != nil {
			if s, _ := job.Summary["stack_id"].(string); s != "" {
				stackID = s
			}
		}
		rec := &scmWebhookReceipt{
			ID: id, ReceivedAt: nz(job.StartedAt, time.Now().UTC().Format("2006-01-02 15:04:05.000")),
			DeliveryID: "", Event: event, Action: action,
			RepoFullName: job.RepoFullName, PRNumber: job.PRNumber, CommitSHA: job.CommitSHA,
			OrganizationID: job.OrganizationID, ProjectID: job.ProjectID, ConnectorID: job.ConnectorID,
			SignatureValid: true, Outcome: "queued", JobID: job.ID, StackID: stackID,
			Honesty:    "Backfilled from scm job — webhook receipt was not captured at receive time.",
			HTTPStatus: 200, Source: "backfill",
		}
		persistSCMWebhook(rec)
		n++
		return true
	})
	return n
}

func findSCMWebhookByJobID(jobID string) *scmWebhookReceipt {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil
	}
	var found *scmWebhookReceipt
	scmWebhookLive.Range(func(_, v interface{}) bool {
		r, ok := v.(*scmWebhookReceipt)
		if !ok || r == nil || strings.TrimSpace(r.JobID) != jobID {
			return true
		}
		// Prefer live over backfill when both somehow exist.
		if found == nil || (r.Source != "backfill" && found.Source == "backfill") {
			found = r
		}
		return true
	})
	return found
}

// dedupeSCMWebhookBackfills drops backfill receipts when a live receipt already
// covers the same job_id (fixes Webhooks tab double-rows after first live capture).
func dedupeSCMWebhookBackfills() int {
	liveByJob := map[string]struct{}{}
	scmWebhookLive.Range(func(_, v interface{}) bool {
		r, ok := v.(*scmWebhookReceipt)
		if !ok || r == nil || strings.TrimSpace(r.JobID) == "" {
			return true
		}
		if r.Source != "backfill" {
			liveByJob[r.JobID] = struct{}{}
		}
		return true
	})
	n := 0
	scmWebhookLive.Range(func(k, v interface{}) bool {
		r, ok := v.(*scmWebhookReceipt)
		if !ok || r == nil || r.Source != "backfill" {
			return true
		}
		if _, hasLive := liveByJob[r.JobID]; !hasLive {
			return true
		}
		scmWebhookLive.Delete(k)
		_ = os.Remove(filepath.Join(scmWebhooksStateDir(), r.ID+".json"))
		n++
		return true
	})
	return n
}

func splitWebhookJobEvent(jobEvent string) (event, action string) {
	jobEvent = strings.TrimSpace(jobEvent)
	switch {
	case strings.HasPrefix(jobEvent, "pull_request."):
		return "pull_request", strings.TrimPrefix(jobEvent, "pull_request.")
	case strings.HasPrefix(jobEvent, "push."):
		return "push", strings.TrimPrefix(jobEvent, "push.")
	default:
		return "", ""
	}
}

func hydrateSCMWebhooksOnBoot() {
	_ = ensureSCMWebhookDirs()
	nf := hydrateSCMWebhooksFromFiles()
	nc := hydrateSCMWebhooksFromCH()
	nd := dedupeSCMWebhookBackfills()
	nb := backfillSCMWebhooksFromJobs()
	log.Printf("[INFO] SCM webhook hydrate: file=%d ch=%d dedupe=%d backfill=%d; state_dir=%s",
		nf, nc, nd, nb, scmWebhooksStateDir())
}

func newSCMWebhookReceipt(deliveryID, event string, sigOK bool) *scmWebhookReceipt {
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	idParts := []string{deliveryID, event, now, newRandomHex(4)}
	if deliveryID == "" {
		idParts = []string{event, now, newRandomHex(8)}
	}
	return &scmWebhookReceipt{
		ID:             loadID("scmwh", idParts...),
		ReceivedAt:     now,
		DeliveryID:     strings.TrimSpace(deliveryID),
		Event:          event,
		SignatureValid: sigOK,
		Source:         "live",
		HTTPStatus:     200,
	}
}

func finishWebhookReceipt(rec *scmWebhookReceipt, outcome, honesty string, status int, errMsg string) {
	if rec == nil {
		return
	}
	rec.Outcome = outcome
	rec.Honesty = honesty
	if status > 0 {
		rec.HTTPStatus = status
	}
	if errMsg != "" {
		rec.Error = errMsg
	}
	// Enrich org from watched repo / installation when still empty.
	if rec.OrganizationID == "" && rec.RepoFullName != "" {
		if wr, conn := findWatched(rec.RepoFullName); wr != nil {
			rec.OrganizationID = wr.OrganizationID
			rec.ProjectID = wr.ProjectID
			rec.ConnectorID = wr.ConnectorID
			_ = conn
		}
	}
	if rec.OrganizationID == "" && rec.InstallationID != "" {
		if c := findConnectorByInstallation(rec.InstallationID); c != nil {
			rec.OrganizationID = c.OrganizationID
			rec.ProjectID = c.ProjectID
			rec.ConnectorID = c.ID
		}
	}
	persistSCMWebhook(rec)
}

func applyWebhookRepoMeta(rec *scmWebhookReceipt, repo string, pr int, sha string, installation int64, action string) {
	if rec == nil {
		return
	}
	if repo != "" {
		rec.RepoFullName = repo
	}
	if pr > 0 {
		rec.PRNumber = pr
	}
	if sha != "" {
		rec.CommitSHA = sha
	}
	if installation > 0 {
		rec.InstallationID = fmt.Sprintf("%d", installation)
	}
	if action != "" {
		rec.Action = action
	}
}

// canSeeSCMWebhook mirrors canSeeSCMJob tenant visibility (org filter; All+admin = all;
// All+non-admin = only rows with matching org empty treated as default-org, no actor filter
// since webhooks have no actor — non-admins with All see nothing unless they pick an org,
// matching the honesty for webhook-origin jobs).
func canSeeSCMWebhook(a credActor, r *scmWebhookReceipt) bool {
	if r == nil {
		return false
	}
	org := strings.TrimSpace(r.OrganizationID)
	if org == "" {
		org = defaultOrgID
	}
	if sel := strings.TrimSpace(a.OrganizationID); sel != "" {
		return org == sel
	}
	if !authEnforced {
		return true
	}
	if a.isAdmin() {
		return true
	}
	// Non-admin + All: webhook deliveries are not user-queued; hide (same honesty as jobs).
	return false
}

func handleSCMWebhooksList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	a := actorFromRequest(r)
	rawList := []*scmWebhookReceipt{}
	scmWebhookLive.Range(func(_, v interface{}) bool {
		rec, ok := v.(*scmWebhookReceipt)
		if !ok || !canSeeSCMWebhook(a, rec) {
			return true
		}
		rawList = append(rawList, rec)
		return true
	})
	liveJobs := map[string]struct{}{}
	for _, rec := range rawList {
		if jid := strings.TrimSpace(rec.JobID); jid != "" && rec.Source != "backfill" {
			liveJobs[jid] = struct{}{}
		}
	}
	list := make([]*scmWebhookReceipt, 0, len(rawList))
	counts := map[string]int{}
	for _, rec := range rawList {
		if jid := strings.TrimSpace(rec.JobID); jid != "" && rec.Source == "backfill" {
			if _, hasLive := liveJobs[jid]; hasLive {
				continue
			}
		}
		list = append(list, rec)
		st := strings.TrimSpace(rec.Outcome)
		if st == "" {
			st = "unknown"
		}
		counts[st]++
	}
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].ReceivedAt > list[j].ReceivedAt
	})
	total := len(list)
	limit := clampInt(atoiDefault(r.URL.Query().Get("limit"), 100), 1, 500)
	if len(list) > limit {
		list = list[:limit]
	}
	filter := "all"
	honesty := "Showing webhook deliveries across organizations (tenant picker = All)."
	if a.OrganizationID != "" {
		filter = a.OrganizationID
		honesty = "Filtered to organization " + a.OrganizationID + "."
	} else if authEnforced && !a.isAdmin() {
		honesty = "Tenant picker is All — webhook deliveries require selecting an organization (they have no actor_user_id)."
		filter = "none"
	} else if authEnforced && a.isAdmin() {
		honesty = "Tenant picker is All — admin-wide webhook list. Select an organization to narrow."
	}
	writeJSON(w, map[string]interface{}{
		"webhooks": list, "total": total, "counts": counts, "limit": limit,
		"organization_id": a.OrganizationID,
		"tenant_filter":   filter,
		"honesty":         honesty,
	})
}

func handleSCMWebhookSub(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scm/webhooks/")
	path = strings.Trim(path, "/")
	if path == "" {
		http.Error(w, "not found", 404)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	rec := getSCMWebhook(path)
	if rec == nil {
		http.Error(w, "not found", 404)
		return
	}
	a := actorFromRequest(r)
	if !canSeeSCMWebhook(a, rec) {
		http.Error(w, "not found", 404)
		return
	}
	out := map[string]interface{}{"webhook": rec}
	if rec.JobID != "" {
		if job := getSCMJob(rec.JobID); job != nil && canSeeSCMJob(a, job) {
			out["job"] = scmJobAPIView(job)
		}
	}
	writeJSON(w, out)
}
