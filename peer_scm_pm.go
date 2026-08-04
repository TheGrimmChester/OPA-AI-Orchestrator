package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// Peer PM endpoints for OPM: milestones (REST) + Projects v2 (GraphQL).
// Credentials never leave ORA; peers call with service JWT scope scm:pm.

func registerPeerSCMPMMux(mux *http.ServeMux) {
	mux.HandleFunc("/api/peer/scm/milestones/list", handlePeerMilestonesList)
	mux.HandleFunc("/api/peer/scm/milestones/upsert", handlePeerMilestonesUpsert)
	mux.HandleFunc("/api/peer/scm/projects/list", handlePeerProjectsList)
	mux.HandleFunc("/api/peer/scm/projects/items/upsert", handlePeerProjectItemUpsert)
	mux.HandleFunc("/api/peer/scm/projects/items/status", handlePeerProjectItemStatus)
}

type peerSCMClaims = openauth.ServiceClaims

func peerSCMAuth(w http.ResponseWriter, r *http.Request, scope string) (*peerSCMClaims, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return nil, false
	}
	secret := []byte(strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")))
	if len(secret) == 0 {
		http.Error(w, "service auth disabled", 503)
		return nil, false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized", 401)
		return nil, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	claims, err := openauth.ValidateServiceJWT(token, secret, "ora-api")
	if err != nil {
		http.Error(w, "invalid service token", 401)
		return nil, false
	}
	if err := openauth.RequireScope(claims, scope); err != nil {
		http.Error(w, "missing scope", 403)
		return nil, false
	}
	return claims, true
}

func peerResolveConnector(w http.ResponseWriter, claims *peerSCMClaims, connectorID string) *opaConnector {
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		http.Error(w, "connector_id required", 400)
		return nil
	}
	c := getOrHydrateConnector(connectorID)
	if c == nil || c.Status == "deleted" {
		http.Error(w, "connector not found", 404)
		return nil
	}
	if org := strings.TrimSpace(claims.OrgID); org != "" && c.OrganizationID != "" && c.OrganizationID != org {
		http.Error(w, "connector org mismatch", 403)
		return nil
	}
	return c
}

func peerOwnerRepo(full string) (owner, repo string, ok bool) {
	owner, repo = splitOwnerRepo(full)
	ok = owner != "" && repo != ""
	return
}

func handlePeerMilestonesList(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, "scm:pm")
	if !ok {
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
	c := peerResolveConnector(w, claims, body.ConnectorID)
	if c == nil {
		return
	}
	owner, repo, ok := peerOwnerRepo(body.RepoFullName)
	if !ok {
		http.Error(w, "repo_full_name (owner/repo) required", 400)
		return
	}
	list, err := githubListMilestones(c, owner, repo)
	if err != nil {
		http.Error(w, "list milestones: "+err.Error(), 502)
		return
	}
	out := make([]map[string]interface{}, 0, len(list))
	for _, m := range list {
		out = append(out, map[string]interface{}{
			"number":      m.Number,
			"title":       m.Title,
			"description": m.Description,
			"state":       m.State,
			"html_url":    m.HTMLURL,
		})
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "repo_full_name": body.RepoFullName, "milestones": out,
	})
}

func handlePeerMilestonesUpsert(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, "scm:pm")
	if !ok {
		return
	}
	var body struct {
		ConnectorID  string `json:"connector_id"`
		RepoFullName string `json:"repo_full_name"`
		Number       int    `json:"number"`
		Title        string `json:"title"`
		Description  string `json:"description"`
		State        string `json:"state"` // open | closed
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c := peerResolveConnector(w, claims, body.ConnectorID)
	if c == nil {
		return
	}
	owner, repo, ok := peerOwnerRepo(body.RepoFullName)
	if !ok {
		http.Error(w, "repo_full_name (owner/repo) required", 400)
		return
	}
	body.Title = strings.TrimSpace(body.Title)
	body.State = strings.TrimSpace(body.State)
	if body.State != "" && body.State != "open" && body.State != "closed" {
		http.Error(w, "state must be open or closed", 400)
		return
	}

	var meta *githubMilestoneMeta
	var err error
	if body.Number > 0 {
		meta, err = githubUpdateMilestone(c, owner, repo, body.Number, body.Title, body.Description, body.State)
	} else {
		if body.Title == "" {
			http.Error(w, "title required when number omitted", 400)
			return
		}
		meta, err = githubFindOrCreateMilestone(c, owner, repo, body.Title, body.Description)
		if err == nil && body.State != "" && meta != nil && meta.State != body.State {
			meta, err = githubUpdateMilestone(c, owner, repo, meta.Number, "", "", body.State)
		}
	}
	if err != nil {
		http.Error(w, "upsert milestone: "+err.Error(), 502)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "repo_full_name": body.RepoFullName,
		"milestone": map[string]interface{}{
			"number": meta.Number, "title": meta.Title, "description": meta.Description,
			"state": meta.State, "html_url": meta.HTMLURL,
		},
	})
}

func handlePeerProjectsList(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, "scm:pm")
	if !ok {
		return
	}
	var body struct {
		ConnectorID  string `json:"connector_id"`
		Owner        string `json:"owner"`
		RepoFullName string `json:"repo_full_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c := peerResolveConnector(w, claims, body.ConnectorID)
	if c == nil {
		return
	}
	owner := strings.TrimSpace(body.Owner)
	if owner == "" {
		if o, _, ok := peerOwnerRepo(body.RepoFullName); ok {
			owner = o
		}
	}
	if owner == "" {
		http.Error(w, "owner or repo_full_name required", 400)
		return
	}

	health := assessInstallationPermHealth(c)
	if c.Kind == "github_app" && !health.ProjectsOK {
		writeJSON(w, map[string]interface{}{
			"ok": false, "status": "missing_organization_projects",
			"missing": health.OptionalMissing,
			"note":    "GitHub App needs organization_projects:write (or read) for Projects v2. PAT connectors need project scopes.",
			"projects": []interface{}{},
		})
		return
	}

	projects, err := githubListProjectsV2(c, owner)
	if err != nil {
		http.Error(w, "list projects: "+err.Error(), 502)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "owner": owner, "projects": projects,
		"note": "Projects v2 GraphQL. Requires organization_projects (App) or classic/fine-grained project scopes (PAT).",
	})
}

func handlePeerProjectItemUpsert(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, "scm:pm")
	if !ok {
		return
	}
	var body struct {
		ConnectorID   string `json:"connector_id"`
		ProjectID     string `json:"project_id"`
		ItemID        string `json:"item_id"`
		Title         string `json:"title"`
		Body          string `json:"body"`
		StatusHint    string `json:"status_hint"` // backlog|queue|in_progress|… mapped best-effort
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c := peerResolveConnector(w, claims, body.ConnectorID)
	if c == nil {
		return
	}
	body.ProjectID = strings.TrimSpace(body.ProjectID)
	body.Title = strings.TrimSpace(body.Title)
	if body.ProjectID == "" || body.Title == "" {
		http.Error(w, "project_id and title required", 400)
		return
	}

	itemID := strings.TrimSpace(body.ItemID)
	var err error
	if itemID == "" {
		itemID, err = githubAddProjectV2DraftIssue(c, body.ProjectID, body.Title, body.Body)
		if err != nil {
			http.Error(w, "add draft item: "+err.Error(), 502)
			return
		}
	} else if body.Title != "" {
		// Title edits on draft issues are best-effort via updateProjectV2DraftIssue
		_ = githubUpdateProjectV2DraftIssue(c, itemID, body.Title, body.Body)
	}

	statusSynced := false
	statusNote := ""
	if hint := strings.TrimSpace(body.StatusHint); hint != "" && itemID != "" {
		if serr := githubSetProjectV2ItemStatus(c, body.ProjectID, itemID, hint); serr != nil {
			statusNote = serr.Error()
		} else {
			statusSynced = true
		}
	}

	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "project_id": body.ProjectID,
		"item_id": itemID, "status_synced": statusSynced, "status_note": statusNote,
	})
}

func handlePeerProjectItemStatus(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, "scm:pm")
	if !ok {
		return
	}
	var body struct {
		ConnectorID string `json:"connector_id"`
		ProjectID   string `json:"project_id"`
		ItemID      string `json:"item_id"`
		StatusHint  string `json:"status_hint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c := peerResolveConnector(w, claims, body.ConnectorID)
	if c == nil {
		return
	}
	body.ProjectID = strings.TrimSpace(body.ProjectID)
	body.ItemID = strings.TrimSpace(body.ItemID)
	body.StatusHint = strings.TrimSpace(body.StatusHint)
	if body.ProjectID == "" || body.ItemID == "" || body.StatusHint == "" {
		http.Error(w, "project_id, item_id, and status_hint required", 400)
		return
	}
	if err := githubSetProjectV2ItemStatus(c, body.ProjectID, body.ItemID, body.StatusHint); err != nil {
		writeJSON(w, map[string]interface{}{
			"ok": false, "status_synced": false, "error": err.Error(),
			"note": "Status field must exist on the Project (single-select). Map OPM columns to option names best-effort.",
		})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "status_synced": true})
}
