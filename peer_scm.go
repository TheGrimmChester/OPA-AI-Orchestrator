package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// registerPeerSCMMux exposes service-JWT-only SCM helpers for peer products (OPM, OSA).
// GitHub App/PAT secrets stay in ORA; peers receive short-lived clone credentials only.
// PM helpers (milestones / Projects v2) live in peer_scm_pm.go and Issues sync in
// peer_scm_issues.go, both under scope scm:pm.
func registerPeerSCMMux(mux *http.ServeMux) {
	mux.HandleFunc("/api/peer/scm/clone-credentials", handlePeerCloneCredentials)
	registerPeerSCMPMMux(mux)
	registerPeerSCMIssuesMux(mux)
}

func handlePeerCloneCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	secret := []byte(strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")))
	if len(secret) == 0 {
		http.Error(w, "service auth disabled", 503)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized", 401)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	claims, err := openauth.ValidateServiceJWT(token, secret, "ora-api")
	if err != nil {
		http.Error(w, "invalid service token", 401)
		return
	}
	if err := openauth.RequireScope(claims, "scm:clone"); err != nil {
		http.Error(w, "missing scope", 403)
		return
	}

	var body struct {
		ConnectorID  string `json:"connector_id"`
		RepoFullName string `json:"repo_full_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	body.ConnectorID = strings.TrimSpace(body.ConnectorID)
	body.RepoFullName = strings.TrimSpace(body.RepoFullName)
	if body.ConnectorID == "" || body.RepoFullName == "" || !strings.Contains(body.RepoFullName, "/") {
		http.Error(w, "connector_id and repo_full_name (owner/repo) required", 400)
		return
	}

	c := getOrHydrateConnector(body.ConnectorID)
	if c == nil || c.Status == "deleted" {
		http.Error(w, "connector not found", 404)
		return
	}
	if org := strings.TrimSpace(claims.OrgID); org != "" && c.OrganizationID != "" && c.OrganizationID != org {
		http.Error(w, "connector org mismatch", 403)
		return
	}

	tok, err := githubAccessTokenFor(c, body.RepoFullName, map[string]string{"contents": "read", "metadata": "read"})
	if err != nil {
		tok, err = githubAccessToken(c)
		if err != nil {
			http.Error(w, "credentials unavailable: "+err.Error(), 502)
			return
		}
	}

	expires := time.Now().UTC().Add(10 * time.Minute)
	writeJSON(w, map[string]interface{}{
		"ok":             true,
		"connector_id":   c.ID,
		"repo_full_name": body.RepoFullName,
		"token":          tok,
		"clone_url":      "https://github.com/" + body.RepoFullName + ".git",
		"expires_at":     expires.Format(time.RFC3339),
		"note":           "Short-lived clone credential for ephemeral workspaces. Do not persist. Prefer GIT_ASKPASS over embedding in URLs.",
	})
}
