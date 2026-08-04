package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Peer Issues endpoints for OPM task ↔ GitHub Issue sync.
// Credentials never leave ORA; peers call with service JWT scope scm:pm.
//
// Every failure carries a machine-readable `status` plus the upstream detail so
// the caller can report the concrete reason instead of a silent no-op:
//   missing_issues_permission — the App installation has no Issues write
//   issue_not_found           — the issue was deleted, transferred, or is invisible
//   upstream_error            — anything else GitHub returned
const (
	issueStatusMissingPermission = "missing_issues_permission"
	issueStatusNotFound          = "issue_not_found"
	issueStatusUpstreamError     = "upstream_error"
)

func registerPeerSCMIssuesMux(mux *http.ServeMux) {
	mux.HandleFunc("/api/peer/scm/issues/get", handlePeerIssueGet)
	mux.HandleFunc("/api/peer/scm/issues/create", handlePeerIssueCreate)
	mux.HandleFunc("/api/peer/scm/issues/update", handlePeerIssueUpdate)
}

func writeJSONStatus(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// peerIssuesPreflight refuses the call when the connector demonstrably cannot
// write Issues, so OPM gets "grant Issues write" rather than a 502 from GitHub.
// PAT connectors cannot be probed: they fall through and surface GitHub's own
// answer verbatim.
func peerIssuesPreflight(w http.ResponseWriter, c *opaConnector, needWrite bool) bool {
	if !needWrite || c == nil || c.Kind != "github_app" {
		return true
	}
	if githubUseMockAPI(c) {
		return true
	}
	health := assessInstallationPermHealth(c)
	for _, m := range health.Missing {
		if !strings.HasPrefix(m, "issues") {
			continue
		}
		writeJSONStatus(w, http.StatusForbidden, map[string]interface{}{
			"ok":      false,
			"status":  issueStatusMissingPermission,
			"error":   "GitHub App installation is missing Issues write on this repository",
			"missing": health.Missing,
			"granted": health.Granted,
			"note":    "Grant Issues: Read and write on the GitHub App, then re-accept the installation permissions.",
		})
		return false
	}
	return true
}

// peerIssueError maps a GitHub Issues failure onto an honest status + HTTP code.
func peerIssueError(w http.ResponseWriter, c *opaConnector, err error) {
	var apiErr *githubIssueAPIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.IssueMissing():
			writeJSONStatus(w, http.StatusNotFound, map[string]interface{}{
				"ok": false, "status": issueStatusNotFound,
				"error":  "the linked GitHub issue is not reachable (deleted, transferred, or not visible to this connector)",
				"detail": apiErr.Error(),
			})
			return
		case apiErr.Forbidden():
			payload := map[string]interface{}{
				"ok": false, "status": issueStatusMissingPermission,
				"error":  "GitHub refused the Issues call for this connector",
				"detail": apiErr.Error(),
				"note":   "Grant Issues: Read and write on the GitHub App (or repo scope on a PAT), then retry.",
			}
			if c != nil && c.Kind == "github_app" && !githubUseMockAPI(c) {
				h := assessInstallationPermHealth(c)
				payload["missing"] = h.Missing
				payload["granted"] = h.Granted
			}
			writeJSONStatus(w, http.StatusForbidden, payload)
			return
		}
	}
	writeJSONStatus(w, http.StatusBadGateway, map[string]interface{}{
		"ok": false, "status": issueStatusUpstreamError, "error": err.Error(),
	})
}

func peerIssuePayload(m *githubIssueMeta) map[string]interface{} {
	if m == nil {
		return nil
	}
	labels := m.Labels
	if labels == nil {
		labels = []string{}
	}
	assignees := m.Assignees
	if assignees == nil {
		assignees = []string{}
	}
	return map[string]interface{}{
		"number": m.Number, "title": m.Title, "body": m.Body, "state": m.State,
		"html_url": m.HTMLURL, "labels": labels, "milestone": m.Milestone,
		"milestone_title": m.MilestoneTitle, "assignees": assignees,
		"updated_at": m.UpdatedAt,
	}
}

// peerIssueRepo decodes the connector + owner/repo shared by every Issues call.
func peerIssueRepo(w http.ResponseWriter, claims *peerSCMClaims, connectorID, repoFullName string) (*opaConnector, string, string, bool) {
	c := peerResolveConnector(w, claims, connectorID)
	if c == nil {
		return nil, "", "", false
	}
	owner, repo, ok := peerOwnerRepo(repoFullName)
	if !ok {
		http.Error(w, "repo_full_name (owner/repo) required", 400)
		return nil, "", "", false
	}
	return c, owner, repo, true
}

func handlePeerIssueGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, "scm:pm")
	if !ok {
		return
	}
	var body struct {
		ConnectorID  string `json:"connector_id"`
		RepoFullName string `json:"repo_full_name"`
		Number       int    `json:"number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c, owner, repo, ok := peerIssueRepo(w, claims, body.ConnectorID, body.RepoFullName)
	if !ok {
		return
	}
	if body.Number <= 0 {
		http.Error(w, "number required", 400)
		return
	}
	meta, err := githubGetIssue(c, owner, repo, body.Number)
	if err != nil {
		peerIssueError(w, c, err)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "repo_full_name": body.RepoFullName,
		"issue": peerIssuePayload(meta),
	})
}

func handlePeerIssueCreate(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, "scm:pm")
	if !ok {
		return
	}
	var body struct {
		ConnectorID  string   `json:"connector_id"`
		RepoFullName string   `json:"repo_full_name"`
		Title        string   `json:"title"`
		Body         string   `json:"body"`
		Labels       []string `json:"labels"`
		Milestone    int      `json:"milestone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c, owner, repo, ok := peerIssueRepo(w, claims, body.ConnectorID, body.RepoFullName)
	if !ok {
		return
	}
	body.Title = strings.TrimSpace(body.Title)
	if body.Title == "" {
		http.Error(w, "title required", 400)
		return
	}
	if !peerIssuesPreflight(w, c, true) {
		return
	}
	meta, err := githubCreateIssue(c, owner, repo, body.Title, body.Body, body.Labels, body.Milestone)
	if err != nil {
		peerIssueError(w, c, err)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "repo_full_name": body.RepoFullName,
		"issue": peerIssuePayload(meta),
	})
}

func handlePeerIssueUpdate(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, "scm:pm")
	if !ok {
		return
	}
	var body struct {
		ConnectorID  string   `json:"connector_id"`
		RepoFullName string   `json:"repo_full_name"`
		Number       int      `json:"number"`
		Title        string   `json:"title"`
		Body         string   `json:"body"`
		State        string   `json:"state"`
		Milestone    int      `json:"milestone"` // >0 set, <0 clear, 0 leave alone
		Labels       []string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c, owner, repo, ok := peerIssueRepo(w, claims, body.ConnectorID, body.RepoFullName)
	if !ok {
		return
	}
	if body.Number <= 0 {
		http.Error(w, "number required", 400)
		return
	}
	body.State = strings.TrimSpace(body.State)
	if body.State != "" && body.State != "open" && body.State != "closed" {
		http.Error(w, "state must be open or closed", 400)
		return
	}
	if !peerIssuesPreflight(w, c, true) {
		return
	}
	meta, applied, err := githubUpdateIssue(c, owner, repo, body.Number,
		body.Title, body.Body, body.State, body.Milestone, body.Labels)
	if err != nil {
		peerIssueError(w, c, err)
		return
	}
	if applied == nil {
		applied = []string{}
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "repo_full_name": body.RepoFullName,
		"applied": applied, "issue": peerIssuePayload(meta),
	})
}
