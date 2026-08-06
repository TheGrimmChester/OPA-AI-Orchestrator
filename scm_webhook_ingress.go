package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// handleGitHubWebhookByConnector serves per-repo PAT webhooks at
// POST /v1/scm/github/webhook/{connector_id}.
func handleGitHubWebhookByConnector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/scm/github/webhook/")
	connectorID := strings.Trim(strings.TrimSpace(path), "/")
	if connectorID == "" {
		handleGitHubWebhook(w, r)
		return
	}
	ingressGitHubWebhook(w, r, connectorID)
}

func ingressGitHubWebhook(w http.ResponseWriter, r *http.Request, connectorID string) {
	raw, err := readWebhookBody(r)
	if err != nil {
		http.Error(w, "read error", 400)
		return
	}
	deliveryID := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	event := r.Header.Get("X-GitHub-Event")
	sigHeader := r.Header.Get("X-Hub-Signature-256")

	var sigOK bool
	var conn *opaConnector
	if connectorID != "" {
		conn = getOrHydrateConnector(connectorID)
		if conn == nil || conn.Status == "deleted" {
			http.Error(w, "connector not found", 404)
			return
		}
		repo := extractWebhookRepoFullName(raw, event)
		wr := findWatchedForConnectorRepo(connectorID, repo)
		if wr == nil && repo != "" {
			wr, _ = findWatched(repo)
		}
		if wr != nil && wr.WebhookMode == "repo" {
			sigOK = verifyRepoWebhookSignature(wr, raw, sigHeader)
		} else {
			secret := strings.TrimSpace(os.Getenv("OPA_GITHUB_WEBHOOK_SECRET"))
			sigOK = verifyGitHubSignature(secret, raw, sigHeader)
		}
	} else {
		secret := strings.TrimSpace(os.Getenv("OPA_GITHUB_WEBHOOK_SECRET"))
		sigOK = verifyGitHubSignature(secret, raw, sigHeader)
	}

	rec := newSCMWebhookReceipt(deliveryID, event, sigOK)
	if connectorID != "" {
		rec.ConnectorID = connectorID
	}

	if !sigOK {
		finishWebhookReceipt(rec, "error", "Invalid X-Hub-Signature-256.", 401, "invalid signature")
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
		writeJSON(w, map[string]interface{}{"ok": true, "pong": true, "webhook_id": rec.ID, "connector_id": connectorID})
	case "pull_request":
		handlePRWebhookIngress(w, raw, rec, connectorID, conn)
	case "push":
		handlePushWebhookIngress(w, raw, rec, connectorID, conn)
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

func extractWebhookRepoFullName(raw []byte, event string) string {
	repo, _, _, _, _ := parseWebhookPayloadMeta(raw, event)
	return repo
}

func parseWebhookPayloadMeta(raw []byte, event string) (repo string, pr int, sha string, installation int64, action string) {
	switch strings.TrimSpace(event) {
	case "pull_request":
		var payload struct {
			Action string `json:"action"`
			Number int    `json:"number"`
			PR     struct {
				Number int    `json:"number"`
				Head   struct {
					SHA string `json:"sha"`
				} `json:"head"`
			} `json:"pull_request"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
			Installation struct {
				ID int64 `json:"id"`
			} `json:"installation"`
		}
		if json.Unmarshal(raw, &payload) == nil {
			repo = payload.Repository.FullName
			pr = payload.PR.Number
			if pr == 0 {
				pr = payload.Number
			}
			sha = payload.PR.Head.SHA
			installation = payload.Installation.ID
			action = payload.Action
		}
	case "push":
		var payload struct {
			After string `json:"after"`
			Repository struct {
				FullName      string `json:"full_name"`
				DefaultBranch string `json:"default_branch"`
			} `json:"repository"`
			Installation struct {
				ID int64 `json:"id"`
			} `json:"installation"`
		}
		if json.Unmarshal(raw, &payload) == nil {
			repo = payload.Repository.FullName
			sha = payload.After
			installation = payload.Installation.ID
			action = "push"
		}
	}
	return repo, pr, sha, installation, action
}

func finishSCMIngressPipeline(w http.ResponseWriter, rec *scmWebhookReceipt, job *scmJob, wr *opaWatchedRepo, conn *opaConnector, raw []byte, event string, queued bool) {
	checks := defaultWatchedChecks()
	if wr != nil {
		checks = parseWatchedChecks(wr.ChecksJSON)
	}
	if job != nil && conn != nil {
		env := buildSCMEventEnvelope(rec, job, wr, raw, event)
		peerIDs := dispatchSCMCheckers(conn, env, checks, raw)
		mergeCheckerRunIDs(job, peerIDs)
		persistSCMJob(job)
	}
	out := map[string]interface{}{"ok": true, "webhook_id": rec.ID}
	if job != nil {
		out["job_id"] = job.ID
		out["status"] = job.Status
	}
	writeJSON(w, out)
	if queued && job != nil {
		go processSCMJob(job.ID)
	}
}
