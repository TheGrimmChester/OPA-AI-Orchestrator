package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Wave 34 — GitHub Repo Watch connectors + settings.

func registerWave34Mux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	authView("/api/connectors", handleConnectorsList)
	authAdmin("/api/connectors/github/install-url", handleGitHubInstallURL)
	mux.HandleFunc("/api/connectors/github/callback", handleGitHubCallback)
	authAdmin("/api/connectors/github/pat", handleGitHubPATConnect)
	// Method-aware auth: GET viewer, mutating admin when OPA_AUTH_REQUIRED=1.
	registerSCMAuthFlexible(mux, "/api/connectors/", handleConnectorSub)
	authView("/api/scm/jobs", handleSCMJobsList)
	registerSCMAuthFlexible(mux, "/api/scm/jobs/", handleSCMJobSub)
	authView("/api/scm/settings", handleSCMSettings)
	authAdmin("/api/scm/settings/cursor-key", handleCursorKeySet)
	mux.HandleFunc("/v1/scm/github/webhook", handleGitHubWebhook)
	authAdmin("/api/scm/simulate", handleSCMSimulate)
	authAdmin("/api/scm/ai-review", handleSCMAIReview)
	authAdmin("/api/scm/opa-review", handleSCMAIReview) // alias
	authAdmin("/api/scm/ai-review/stack", handleOPAReviewStack)
	authAdmin("/api/scm/opa-review/stack", handleOPAReviewStack)
	registerSCMAuthFlexible(mux, "/api/scm/ai-review/stacks/", handleOPAReviewStackGet)
	registerSCMAuthFlexible(mux, "/api/scm/opa-review/stacks/", handleOPAReviewStackGet)
	// POST create needs admin; GET list stays viewer.
	registerSCMAuthFlexible(mux, "/api/scm/contexts", handleReviewContexts)
	authAdmin("/api/scm/contexts/generate", handleReviewContextGenerate)
	authAdmin("/api/scm/context-links", handleContextLinks)
	registerSCMAuthFlexible(mux, "/api/scm/contexts/", handleReviewContextSub)
	startSCMCronOnce()
}

// registerSCMAuthFlexible wraps a handler so GET/HEAD are viewer-scoped and
// mutating methods are admin-scoped when auth is enforced; open when auth is off.
func registerSCMAuthFlexible(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !authEnforced {
			h(w, r)
			return
		}
		role := "viewer"
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			role = "viewer"
		default:
			role = "admin"
		}
		AuthMiddleware(h, role)(w, r)
	})
}

var (
	connectorLive sync.Map
	watchedLive   sync.Map
	scmJobLive    sync.Map
	aiReviewLive  sync.Map
	cursorKeyMu   sync.Mutex
	cursorKeyMem  string
	cursorKeyOrg  string
	cursorKeyProj string
)

const scmCursorSecretKey = "cursor_api_key"

type opaConnector struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	Kind           string `json:"kind"`
	InstallationID string `json:"installation_id"`
	AccountLogin   string `json:"account_login"`
	Status         string `json:"status"`
	TokenRef       string `json:"-"`
	MetaJSON       string `json:"meta_json"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type opaWatchedRepo struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	ConnectorID    string `json:"connector_id"`
	RepoFullName   string `json:"repo_full_name"`
	RepoID         string `json:"repo_id"`
	Enabled        bool   `json:"enabled"`
	ServiceName    string `json:"service_name"`
	Profile        string `json:"profile"`
	ChecksJSON     string `json:"checks_json"`
	MinSeverity    string `json:"min_severity"`
	AIBlocking     bool   `json:"ai_blocking"`
	LinkGroupID    string `json:"link_group_id"`
	UpdatedAt      string `json:"updated_at"`
}

func handleConnectorsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	seen := map[string]struct{}{}
	list := []map[string]interface{}{}
	connectorLive.Range(func(_, v interface{}) bool {
		c, ok := v.(*opaConnector)
		if !ok || c.Status == "deleted" {
			return true
		}
		list = append(list, connectorPublic(c))
		seen[c.ID] = struct{}{}
		return true
	})
	// Merge ClickHouse rows and hydrate encrypted PATs when missing from memory.
	if queryClient != nil {
		scope := tenantScopeSQL(r, queryClient, "")
		rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT id, organization_id, project_id, kind, installation_id, account_login,
			       status, token_ref, meta_json, created_at, updated_at
			FROM opa.connectors WHERE status != 'deleted'%s ORDER BY updated_at DESC LIMIT 50`, scope))
		if err == nil {
			for _, row := range rows {
				id, _ := row["id"].(string)
				if id == "" {
					continue
				}
				if _, ok := seen[id]; ok {
					continue
				}
				if live := getOrHydrateConnector(id); live != nil && live.Status != "deleted" {
					list = append(list, connectorPublic(live))
					seen[id] = struct{}{}
					continue
				}
				row["has_token"] = false
				delete(row, "token_ref")
				list = append(list, row)
				seen[id] = struct{}{}
			}
		}
	}
	writeJSON(w, map[string]interface{}{
		"connectors":            list,
		"github_app_configured": githubAppConfigured(),
		"honesty":               "GitHub App is production; PAT is local/dev bootstrap. PATs and OPA Review API keys are AES-GCM encrypted in ClickHouse (OPA_CONNECTOR_SECRET or JWT_SECRET) and rehydrated on Agent boot.",
	})
}

func connectorPublic(c *opaConnector) map[string]interface{} {
	display := ""
	if meta := parseConnectorMeta(c.MetaJSON); meta != nil {
		if s, ok := meta["display_name"].(string); ok {
			display = s
		}
	}
	return map[string]interface{}{
		"id": c.ID, "kind": c.Kind, "installation_id": c.InstallationID,
		"account_login": c.AccountLogin, "status": c.Status,
		"meta_json": c.MetaJSON, "display_name": display,
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt,
		"has_token": c.TokenRef != "",
	}
}

func parseConnectorMeta(raw string) map[string]interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]interface{}{}
	}
	var m map[string]interface{}
	if json.Unmarshal([]byte(raw), &m) != nil || m == nil {
		return map[string]interface{}{}
	}
	return m
}

func setConnectorMetaField(c *opaConnector, key, value string) {
	m := parseConnectorMeta(c.MetaJSON)
	if strings.TrimSpace(value) == "" {
		delete(m, key)
	} else {
		m[key] = value
	}
	b, _ := json.Marshal(m)
	c.MetaJSON = string(b)
}

func githubAppConfigured() bool {
	return strings.TrimSpace(os.Getenv("OPA_GITHUB_APP_ID")) != "" &&
		strings.TrimSpace(os.Getenv("OPA_GITHUB_APP_PRIVATE_KEY")) != ""
}

func handleGitHubInstallURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	appSlug := envOr("OPA_GITHUB_APP_SLUG", "")
	appID := strings.TrimSpace(os.Getenv("OPA_GITHUB_APP_ID"))
	public := strings.TrimRight(envOr("OPA_PUBLIC_URL", "http://127.0.0.1:8080"), "/")
	if appSlug == "" && appID == "" {
		writeJSON(w, map[string]interface{}{
			"ok": false, "configured": false,
			"note":        "Set OPA_GITHUB_APP_ID, OPA_GITHUB_APP_PRIVATE_KEY, OPA_GITHUB_APP_SLUG, OPA_GITHUB_WEBHOOK_SECRET, OPA_PUBLIC_URL. Or use PAT bootstrap POST /api/connectors/github/pat.",
			"webhook_url": public + "/v1/scm/github/webhook",
		})
		return
	}
	url := fmt.Sprintf("https://github.com/apps/%s/installations/new", nz(appSlug, "opa-repo-watch"))
	if cid := strings.TrimSpace(os.Getenv("OPA_GITHUB_APP_CLIENT_ID")); cid != "" {
		url = fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=opa-scm", cid)
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "configured": true, "install_url": url,
		"webhook_url":  public + "/v1/scm/github/webhook",
		"callback_url": public + "/api/connectors/github/callback",
	})
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	inst := strings.TrimSpace(r.URL.Query().Get("installation_id"))
	setup := strings.TrimSpace(r.URL.Query().Get("setup_action"))
	if inst == "" {
		http.Error(w, "installation_id required", 400)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	id := loadID("conn", org, proj, "github_app", inst)
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	c := &opaConnector{
		ID: id, OrganizationID: org, ProjectID: proj, Kind: "github_app",
		InstallationID: inst, AccountLogin: "", Status: "active",
		MetaJSON: fmt.Sprintf(`{"setup_action":%q}`, setup), CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(id, c)
	persistConnector(c)
	dash := envOr("OPA_DASHBOARD_URL", "http://127.0.0.1:8088")
	http.Redirect(w, r, dash+"/security?tab=watch&connector="+id, http.StatusFound)
}

func handleGitHubPATConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		Token   string   `json:"token"`
		Login   string   `json:"login"`
		Repos []string `json:"repos"`
	}
	if json.Unmarshal(raw, &body) != nil || strings.TrimSpace(body.Token) == "" {
		http.Error(w, "token required", 400)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	if !enforceWriteLocalityHTTP(w, r, org, proj) {
		return
	}
	login := nz(body.Login, "pat-user")
	id := loadID("conn", org, proj, "github_pat", login, newRandomHex(8))
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	c := &opaConnector{
		ID: id, OrganizationID: org, ProjectID: proj, Kind: "github_pat",
		InstallationID: "", AccountLogin: login, Status: "active",
		TokenRef: body.Token, MetaJSON: `{"bootstrap":true}`, CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(id, c)
	persistConnector(c)
	for _, repo := range body.Repos {
		repo = strings.TrimSpace(repo)
		if repo == "" {
			continue
		}
		upsertWatched(org, proj, id, repo, "", true, defaultWatchedChecks(), "auto", "high", false)
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector": connectorPublic(c),
		"honesty": "PAT bootstrap — prefer GitHub App for webhooks and Check Runs in production. Token is AES-GCM encrypted in ClickHouse.",
	})
}

func handleConnectorSub(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/connectors/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "not found", 404)
		return
	}
	if parts[0] == "github" {
		http.Error(w, "not found", 404)
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			handleConnectorGet(w, r, id)
			return
		case http.MethodPatch, http.MethodPut:
			handleConnectorPatch(w, r, id)
			return
		case http.MethodDelete:
			handleConnectorDelete(w, r, id)
			return
		}
	}
	if len(parts) >= 2 && parts[1] == "repos" && r.Method == http.MethodGet {
		handleConnectorRepos(w, r, id)
		return
	}
	if len(parts) >= 2 && parts[1] == "pulls" && r.Method == http.MethodGet {
		handleConnectorPulls(w, r, id)
		return
	}
	if len(parts) >= 2 && parts[1] == "watched" {
		switch r.Method {
		case http.MethodGet:
			handleWatchedList(w, r, id)
		case http.MethodPut:
			handleWatchedPut(w, r, id)
		default:
			http.Error(w, "method not allowed", 405)
		}
		return
	}
	http.Error(w, "not found", 404)
}

func handleConnectorGet(w http.ResponseWriter, r *http.Request, id string) {
	c := getOrHydrateConnector(id)
	if c == nil || c.Status == "deleted" {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, map[string]interface{}{"connector": connectorPublic(c)})
}

func handleConnectorPatch(w http.ResponseWriter, r *http.Request, id string) {
	c := getOrHydrateConnector(id)
	if c == nil || c.Status == "deleted" {
		http.Error(w, "not found", 404)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		AccountLogin string `json:"account_login"`
		DisplayName  string `json:"display_name"`
		Token        string `json:"token"`
		Login        string `json:"login"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	if login := strings.TrimSpace(nz(body.AccountLogin, body.Login)); login != "" {
		c.AccountLogin = login
	}
	if strings.Contains(string(raw), `"display_name"`) {
		setConnectorMetaField(c, "display_name", strings.TrimSpace(body.DisplayName))
	}
	if tok := strings.TrimSpace(body.Token); tok != "" {
		if c.Kind != "github_pat" {
			http.Error(w, "token replace only for github_pat connectors", 400)
			return
		}
		c.TokenRef = tok
	}
	c.UpdatedAt = now
	connectorLive.Store(id, c)
	persistConnector(c)
	writeJSON(w, map[string]interface{}{"ok": true, "connector": connectorPublic(c)})
}

func handleConnectorDelete(w http.ResponseWriter, r *http.Request, id string) {
	c := getOrHydrateConnector(id)
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	if c != nil {
		c.Status = "deleted"
		c.TokenRef = ""
		c.UpdatedAt = now
		connectorLive.Store(id, c)
		persistConnector(c)
	} else if queryClient != nil {
		rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT id, organization_id, project_id, kind, installation_id, account_login,
			       status, token_ref, meta_json, created_at, updated_at
			FROM opa.connectors WHERE id = '%s' ORDER BY updated_at DESC LIMIT 1`, escapeSQL(id)))
		if err == nil && len(rows) > 0 {
			c = connectorFromCHRow(rows[0], false)
			if c != nil {
				c.Status = "deleted"
				c.TokenRef = ""
				c.UpdatedAt = now
				persistConnector(c)
			}
		}
	}
	cascadeDeleteWatched(id)
	connectorLive.Delete(id)
	writeJSON(w, map[string]interface{}{"ok": true, "deleted": id})
}

func cascadeDeleteWatched(connectorID string) {
	watchedLive.Range(func(k, v interface{}) bool {
		wr, ok := v.(*opaWatchedRepo)
		if !ok || wr.ConnectorID != connectorID {
			return true
		}
		wr.Enabled = false
		wr.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
		persistWatched(wr)
		watchedLive.Delete(k)
		return true
	})
	if queryClient == nil || connectorID == "" {
		return
	}
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT id, organization_id, project_id, connector_id, repo_full_name, repo_id,
		       enabled, service_name, profile, checks_json, min_severity, ai_blocking, link_group_id, updated_at
		FROM opa.watched_repos
		WHERE connector_id = '%s'
		ORDER BY updated_at DESC LIMIT 500`, escapeSQL(connectorID)))
	if err != nil {
		return
	}
	seen := map[string]struct{}{}
	for _, row := range rows {
		wr := watchedFromCHRow(row)
		if wr == nil {
			continue
		}
		if _, ok := seen[wr.RepoFullName]; ok {
			continue
		}
		seen[wr.RepoFullName] = struct{}{}
		wr.Enabled = false
		wr.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
		persistWatched(wr)
	}
}

func handleConnectorRepos(w http.ResponseWriter, r *http.Request, id string) {
	c := getOrHydrateConnector(id)
	if c == nil {
		writeJSON(w, map[string]interface{}{
			"repos": []interface{}{},
			"error": "connector_not_in_memory",
			"note":  "Connector missing or token could not be decrypted — use Edit → Replace token, or Connect PAT. Needs stable OPA_CONNECTOR_SECRET or JWT_SECRET.",
		})
		return
	}
	if c.Kind == "github_pat" && c.TokenRef == "" {
		writeJSON(w, map[string]interface{}{
			"repos": []interface{}{},
			"error": "connector_token_unavailable",
			"note":  "Connector exists but no decryptable PAT (legacy sha256-only rows cannot be recovered). Use Edit → Replace token.",
		})
		return
	}
	repos, err := githubListRepos(c)
	if err != nil {
		note := "Provide repos manually via Extra repos + Save, or fix GitHub credentials."
		errStr := err.Error()
		if strings.Contains(errStr, "401") {
			note = "Token rejected — create a new classic PAT with `repo` scope, or a fine-grained token with Repository access + Metadata."
		} else if strings.Contains(errStr, "SSO") || strings.Contains(errStr, "403 SSO") {
			note = "Authorize the PAT for each org (GitHub → Settings → Applications → Enable SSO)."
		} else if strings.Contains(errStr, "403") {
			note = "Missing permissions — classic: `repo`; fine-grained: select repos + Metadata (Contents to clone)."
		}
		writeJSON(w, map[string]interface{}{
			"repos": []interface{}{}, "error": errStr, "note": note,
		})
		return
	}
	out := map[string]interface{}{"repos": repos}
	if githubUseMockAPI(c) {
		out["mock"] = true
		out["honesty"] = "OPA_SCM_MOCK_GITHUB=1 — listing mock installable repos (no GitHub API call). Paste a real ghp_ / github_pat_ token to list your repos."
	} else if envOr("OPA_SCM_MOCK_GITHUB", "0") == "1" {
		out["honesty"] = "OPA_SCM_MOCK_GITHUB=1 is set for smoke, but a real PAT was detected — calling GitHub API."
	}
	writeJSON(w, out)
}

func handleWatchedList(w http.ResponseWriter, r *http.Request, connectorID string) {
	list := []opaWatchedRepo{}
	watchedLive.Range(func(_, v interface{}) bool {
		wr, ok := v.(*opaWatchedRepo)
		if !ok || wr.ConnectorID != connectorID {
			return true
		}
		list = append(list, *wr)
		return true
	})
	if len(list) == 0 && queryClient != nil && connectorID != "" {
		scope := tenantScopeSQL(r, queryClient, "")
		rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT id, organization_id, project_id, connector_id, repo_full_name, repo_id,
			       enabled, service_name, profile, checks_json, min_severity, ai_blocking, link_group_id, updated_at
			FROM opa.watched_repos
			WHERE connector_id = '%s'%s
			ORDER BY updated_at DESC LIMIT 200`, escapeSQL(connectorID), scope))
		if err == nil {
			for _, row := range rows {
				wr := watchedFromCHRow(row)
				if wr == nil {
					continue
				}
				list = append(list, *wr)
				watchedLive.Store(wr.ConnectorID+"|"+wr.RepoFullName, wr)
			}
		}
	}
	writeJSON(w, map[string]interface{}{"watched": list})
}

func watchedFromCHRow(row map[string]interface{}) *opaWatchedRepo {
	if row == nil {
		return nil
	}
	id, _ := row["id"].(string)
	repo, _ := row["repo_full_name"].(string)
	if id == "" || repo == "" {
		return nil
	}
	enabled := true
	switch v := row["enabled"].(type) {
	case uint8:
		enabled = v != 0
	case int64:
		enabled = v != 0
	case float64:
		enabled = v != 0
	case bool:
		enabled = v
	}
	ai := false
	switch v := row["ai_blocking"].(type) {
	case uint8:
		ai = v != 0
	case int64:
		ai = v != 0
	case float64:
		ai = v != 0
	case bool:
		ai = v
	}
	str := func(k string) string {
		if s, ok := row[k].(string); ok {
			return s
		}
		return ""
	}
	return &opaWatchedRepo{
		ID: id, OrganizationID: str("organization_id"), ProjectID: str("project_id"),
		ConnectorID: str("connector_id"), RepoFullName: repo, RepoID: str("repo_id"),
		Enabled: enabled, ServiceName: str("service_name"), Profile: nz(str("profile"), "auto"),
		ChecksJSON: nz(str("checks_json"), "[]"), MinSeverity: nz(str("min_severity"), "high"),
		AIBlocking: ai, LinkGroupID: str("link_group_id"), UpdatedAt: str("updated_at"),
	}
}

func handleWatchedPut(w http.ResponseWriter, r *http.Request, connectorID string) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	var body struct {
		Repos []struct {
			RepoFullName string   `json:"repo_full_name"`
			RepoID       string   `json:"repo_id"`
			Enabled      *bool    `json:"enabled"`
			ServiceName  string   `json:"service_name"`
			Profile      string   `json:"profile"`
			Checks       []string `json:"checks"`
			MinSeverity  string   `json:"min_severity"`
			AIBlocking   bool     `json:"ai_blocking"`
		} `json:"repos"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	c := getOrHydrateConnector(connectorID)
	org, proj := "", ""
	if c != nil {
		org, proj = c.OrganizationID, c.ProjectID
	} else {
		ctx, _ := ExtractTenantContext(r, queryClient)
		org, proj = ctx.WriteTenant()
	}
	saved := []opaWatchedRepo{}
	for _, item := range body.Repos {
		repo := strings.TrimSpace(item.RepoFullName)
		if repo == "" {
			continue
		}
		en := true
		if item.Enabled != nil {
			en = *item.Enabled
		}
		checks := item.Checks
		if len(checks) == 0 {
			checks = defaultWatchedChecks()
		}
		wr := upsertWatched(org, proj, connectorID, repo, item.RepoID, en, checks, nz(item.Profile, "auto"), nz(item.MinSeverity, "high"), item.AIBlocking)
		if item.ServiceName != "" {
			wr.ServiceName = item.ServiceName
			persistWatched(wr)
		}
		saved = append(saved, *wr)
	}
	writeJSON(w, map[string]interface{}{"ok": true, "watched": saved})
}

func defaultWatchedChecks() []string {
	return []string{"secrets", "sast", "iac", "sbom", "ai_review"}
}

func upsertWatched(org, proj, connectorID, repo, repoID string, enabled bool, checks []string, profile, minSev string, aiBlock bool) *opaWatchedRepo {
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	checksJSON, _ := json.Marshal(checks)
	id := loadID("watch", org, proj, connectorID, repo)
	prevGroup := ""
	if v, ok := watchedLive.Load(connectorID + "|" + repo); ok {
		if old, ok := v.(*opaWatchedRepo); ok {
			prevGroup = old.LinkGroupID
		}
	}
	wr := &opaWatchedRepo{
		ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: connectorID,
		RepoFullName: repo, RepoID: repoID, Enabled: enabled,
		ServiceName: strings.ReplaceAll(repo, "/", "-"),
		Profile: profile, ChecksJSON: string(checksJSON),
		MinSeverity: minSev, AIBlocking: aiBlock, LinkGroupID: prevGroup, UpdatedAt: now,
	}
	watchedLive.Store(connectorID+"|"+repo, wr)
	persistWatched(wr)
	return wr
}

func getConnector(id string) *opaConnector {
	if v, ok := connectorLive.Load(id); ok {
		if c, ok := v.(*opaConnector); ok {
			return c
		}
	}
	return nil
}

// getOrHydrateConnector returns the in-memory connector, loading+decrypting from
// ClickHouse when missing (Agent recreate / cold GET repos).
func getOrHydrateConnector(id string) *opaConnector {
	if c := getConnector(id); c != nil {
		if c.Kind == "github_pat" && c.TokenRef == "" {
			if h := hydrateConnectorFromCH(id); h != nil && h.TokenRef != "" {
				return h
			}
		}
		return c
	}
	return hydrateConnectorFromCH(id)
}

func hydrateConnectorFromCH(id string) *opaConnector {
	if queryClient == nil || strings.TrimSpace(id) == "" {
		return nil
	}
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT id, organization_id, project_id, kind, installation_id, account_login,
		       status, token_ref, meta_json, created_at, updated_at
		FROM opa.connectors
		WHERE id = '%s' AND status != 'deleted'
		ORDER BY updated_at DESC LIMIT 1`, escapeSQL(id)))
	if err != nil || len(rows) == 0 {
		return nil
	}
	c := connectorFromCHRow(rows[0], true)
	if c == nil || c.Status == "deleted" {
		return nil
	}
	connectorLive.Store(c.ID, c)
	return c
}

func connectorFromCHRow(row map[string]interface{}, decryptToken bool) *opaConnector {
	if row == nil {
		return nil
	}
	id, _ := row["id"].(string)
	if id == "" {
		return nil
	}
	str := func(k string) string {
		if s, ok := row[k].(string); ok {
			return s
		}
		return ""
	}
	c := &opaConnector{
		ID: id, OrganizationID: str("organization_id"), ProjectID: str("project_id"),
		Kind: str("kind"), InstallationID: str("installation_id"), AccountLogin: str("account_login"),
		Status: nz(str("status"), "active"), MetaJSON: nz(str("meta_json"), "{}"),
		CreatedAt: str("created_at"), UpdatedAt: str("updated_at"),
	}
	ref := str("token_ref")
	if decryptToken && isEncryptedSecret(ref) {
		if plain, err := decryptSecret(ref); err == nil {
			c.TokenRef = plain
		}
	}
	return c
}

func findWatched(repo string) (*opaWatchedRepo, *opaConnector) {
	var found *opaWatchedRepo
	watchedLive.Range(func(_, v interface{}) bool {
		wr, ok := v.(*opaWatchedRepo)
		if !ok || !wr.Enabled {
			return true
		}
		if strings.EqualFold(wr.RepoFullName, repo) {
			found = wr
			return false
		}
		return true
	})
	if found == nil {
		return nil, nil
	}
	return found, getOrHydrateConnector(found.ConnectorID)
}

func persistConnector(c *opaConnector) {
	if writer == nil || c == nil {
		return
	}
	tokenRef := ""
	if strings.TrimSpace(c.TokenRef) != "" {
		enc, err := persistTokenRef(c.TokenRef)
		if err != nil {
			log.Printf("[WARN] persistConnector %s: encrypt failed — skipping CH write to avoid wiping token_ref: %v", c.ID, err)
			return
		}
		tokenRef = enc
	} else if c.Status != "deleted" && c.Kind == "github_pat" {
		// Empty in-memory token on a live PAT connector: do not insert a blank
		// token_ref row (ReplacingMergeTree would wipe the prior ciphertext).
		log.Printf("[WARN] persistConnector %s: empty TokenRef — skipping CH write to preserve existing ciphertext", c.ID)
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"id": c.ID, "organization_id": c.OrganizationID, "project_id": c.ProjectID,
		"kind": c.Kind, "installation_id": c.InstallationID, "account_login": c.AccountLogin,
		"status": c.Status, "token_ref": tokenRef, "meta_json": c.MetaJSON,
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt,
	})
	// Sync insert so PAT ciphertext survives an immediate Agent recreate.
	writer.insert("connectors", append(payload, '\n'))
}

func persistWatched(wr *opaWatchedRepo) {
	if writer == nil {
		return
	}
	en, ai := uint8(0), uint8(0)
	if wr.Enabled {
		en = 1
	}
	if wr.AIBlocking {
		ai = 1
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"id": wr.ID, "organization_id": wr.OrganizationID, "project_id": wr.ProjectID,
		"connector_id": wr.ConnectorID, "repo_full_name": wr.RepoFullName, "repo_id": wr.RepoID,
		"enabled": en, "service_name": wr.ServiceName, "profile": wr.Profile,
		"checks_json": wr.ChecksJSON, "min_severity": wr.MinSeverity, "ai_blocking": ai,
		"link_group_id": wr.LinkGroupID, "updated_at": wr.UpdatedAt,
	})
	writer.insertAsync("watched_repos", append(payload, '\n'))
}

func handleSCMSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	// Lazy hydrate if boot missed CH (or key set after boot on another replica).
	if resolveCursorAPIKey(org, proj) == "" {
		hydrateCursorKeyFromCH(org, proj)
	}
	hasKey := resolveCursorAPIKey(org, proj) != ""
	writeJSON(w, map[string]interface{}{
		"github_app_configured": githubAppConfigured(),
		"cursor_key_set":        hasKey,
		"cursor_model":          envOr("OPA_CURSOR_MODEL", "auto"),
		"webhook_url":           strings.TrimRight(envOr("OPA_PUBLIC_URL", "http://127.0.0.1:8080"), "/") + "/v1/scm/github/webhook",
		"skip_cursor_ai":        envOr("SKIP_CURSOR_AI", "0") == "1",
		"workspace":             securityWorkspaceRoot(),
		"cursor_key_scope":      "organization_id+project_id in opa.scm_secrets; env CURSOR_API_KEY is a process-wide override (single-tenant)",
		"honesty":               "OPA Review API key is AES-GCM encrypted in opa.scm_secrets (never returned). Prefer tenant-scoped rows; CURSOR_API_KEY env is a global override for single-tenant deploys. Set SKIP_CURSOR_AI=0 (default) to run OPA Review when a key is present.",
	})
}

func handleCursorKeySet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		APIKey string `json:"api_key"`
		Clear  bool   `json:"clear"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	cursorKeyMu.Lock()
	defer cursorKeyMu.Unlock()
	if body.Clear {
		cursorKeyMem = ""
		cursorKeyOrg, cursorKeyProj = "", ""
		persistSCMSecret(org, proj, scmCursorSecretKey, "", true)
		writeJSON(w, map[string]interface{}{"ok": true, "cursor_key_set": false})
		return
	}
	if strings.TrimSpace(body.APIKey) == "" {
		http.Error(w, "api_key required", 400)
		return
	}
	key := strings.TrimSpace(body.APIKey)
	if err := persistSCMSecret(org, proj, scmCursorSecretKey, key, false); err != nil {
		log.Printf("[WARN] persist cursor key: %v", err)
		http.Error(w, "failed to encrypt/persist cursor key — set OPA_CONNECTOR_SECRET or stable JWT_SECRET", 500)
		return
	}
	cursorKeyMem = key
	cursorKeyOrg, cursorKeyProj = org, proj
	writeJSON(w, map[string]interface{}{"ok": true, "cursor_key_set": true, "organization_id": org, "project_id": proj})
}

// resolveCursorAPIKey returns the Cursor API key for an optional org/project.
// Precedence: CURSOR_API_KEY env (process-wide single-tenant override) →
// in-memory key matching org/proj (or any if org empty) → CH hydrate.
func resolveCursorAPIKey(orgProj ...string) string {
	org, proj := "", ""
	if len(orgProj) >= 1 {
		org = orgProj[0]
	}
	if len(orgProj) >= 2 {
		proj = orgProj[1]
	}
	if env := strings.TrimSpace(os.Getenv("CURSOR_API_KEY")); env != "" {
		return env
	}
	cursorKeyMu.Lock()
	if cursorKeyMem != "" {
		if org == "" || (cursorKeyOrg == org && (proj == "" || cursorKeyProj == proj || cursorKeyProj == "")) {
			k := cursorKeyMem
			cursorKeyMu.Unlock()
			return k
		}
	}
	cursorKeyMu.Unlock()
	hydrateCursorKeyFromCH(org, proj)
	cursorKeyMu.Lock()
	defer cursorKeyMu.Unlock()
	if cursorKeyMem == "" {
		return ""
	}
	if org == "" || (cursorKeyOrg == org && (proj == "" || cursorKeyProj == proj || cursorKeyProj == "")) {
		return cursorKeyMem
	}
	// Single-tenant honesty: if only one key is loaded and caller asked for a
	// different empty-default tenant, still return it (smoke / default tenant).
	if cursorKeyOrg != "" && org != "" && cursorKeyOrg != org {
		return ""
	}
	return cursorKeyMem
}

func persistSCMSecret(org, proj, key, plaintext string, deleted bool) error {
	if writer == nil {
		return nil
	}
	ct := ""
	if !deleted && plaintext != "" {
		enc, err := encryptSecret(plaintext)
		if err != nil {
			return err
		}
		ct = enc
	}
	del := uint8(0)
	if deleted {
		del = 1
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	payload, _ := json.Marshal(map[string]interface{}{
		"key": key, "organization_id": org, "project_id": proj,
		"ciphertext": ct, "updated_at": now, "deleted": del,
	})
	writer.insert("scm_secrets", append(payload, '\n'))
	return nil
}

func hydrateCursorKeyFromCH(org, proj string) {
	if queryClient == nil {
		return
	}
	// Prefer exact org+project, then org-wide, then any legacy row.
	q := fmt.Sprintf(`
		SELECT organization_id, project_id, ciphertext, deleted FROM opa.scm_secrets
		WHERE key = '%s'
		ORDER BY updated_at DESC LIMIT 20`, escapeSQL(scmCursorSecretKey))
	rows, err := queryClient.Query(q)
	if err != nil || len(rows) == 0 {
		return
	}
	pick := func(wantOrg, wantProj string, allowAny bool) bool {
		for _, row := range rows {
			deleted := false
			switch v := row["deleted"].(type) {
			case uint8:
				deleted = v != 0
			case int64:
				deleted = v != 0
			case float64:
				deleted = v != 0
			case bool:
				deleted = v
			}
			if deleted {
				continue
			}
			rowOrg, _ := row["organization_id"].(string)
			rowProj, _ := row["project_id"].(string)
			if !allowAny {
				if wantOrg != "" && rowOrg != wantOrg {
					continue
				}
				if wantProj != "" && rowProj != wantProj && rowProj != "" {
					continue
				}
			}
			ct, _ := row["ciphertext"].(string)
			if !isEncryptedSecret(ct) {
				continue
			}
			plain, err := decryptSecret(ct)
			if err != nil || plain == "" {
				continue
			}
			cursorKeyMu.Lock()
			if cursorKeyMem == "" {
				cursorKeyMem = plain
				cursorKeyOrg, cursorKeyProj = rowOrg, rowProj
			}
			cursorKeyMu.Unlock()
			return true
		}
		return false
	}
	if org != "" && pick(org, proj, false) {
		return
	}
	if org != "" && pick(org, "", false) {
		return
	}
	_ = pick("", "", true)
}

// hydrateSCMOnBoot reloads encrypted PATs, watched repos, and Cursor API key after ClickHouse is ready.
func hydrateSCMOnBoot() {
	if queryClient == nil {
		return
	}
	n := 0
	rows, err := queryClient.Query(`
		SELECT id, organization_id, project_id, kind, installation_id, account_login,
		       status, token_ref, meta_json, created_at, updated_at
		FROM opa.connectors
		WHERE status != 'deleted'
		ORDER BY updated_at DESC LIMIT 200`)
	if err != nil {
		log.Printf("[WARN] hydrateSCMOnBoot connectors: %v", err)
	} else {
		seen := map[string]struct{}{}
		for _, row := range rows {
			id, _ := row["id"].(string)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			if getConnector(id) != nil {
				continue
			}
			c := connectorFromCHRow(row, true)
			if c == nil || c.Status == "deleted" {
				continue
			}
			connectorLive.Store(c.ID, c)
			n++
		}
	}
	nw := hydrateWatchedReposOnBoot()
	hydrateCursorKeyFromCH("", "")
	hydrateSCMJobsAndStacksOnBoot()
	cursorKeyMu.Lock()
	hasCursor := cursorKeyMem != ""
	cursorKeyMu.Unlock()
	log.Printf("[INFO] SCM hydrate: %d connector(s), %d watched repo(s) from ClickHouse; cursor_key_set=%v", n, nw, hasCursor || strings.TrimSpace(os.Getenv("CURSOR_API_KEY")) != "")
}

func hydrateWatchedReposOnBoot() int {
	if queryClient == nil {
		return 0
	}
	rows, err := queryClient.Query(`
		SELECT id, organization_id, project_id, connector_id, repo_full_name, repo_id,
		       enabled, service_name, profile, checks_json, min_severity, ai_blocking, link_group_id, updated_at
		FROM opa.watched_repos
		ORDER BY updated_at DESC LIMIT 500`)
	if err != nil {
		log.Printf("[WARN] hydrateSCMOnBoot watched_repos: %v", err)
		return 0
	}
	seen := map[string]struct{}{}
	n := 0
	for _, row := range rows {
		wr := watchedFromCHRow(row)
		if wr == nil || wr.ConnectorID == "" || wr.RepoFullName == "" {
			continue
		}
		key := wr.ConnectorID + "|" + wr.RepoFullName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if _, ok := watchedLive.Load(key); ok {
			continue
		}
		watchedLive.Store(key, wr)
		n++
	}
	return n
}

func verifyGitHubSignature(secret string, body []byte, sigHeader string) bool {
	sigHeader = strings.TrimSpace(sigHeader)
	if secret == "" {
		return envOr("OPA_SCM_ALLOW_UNSIGNED", "0") == "1"
	}
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(sigHeader, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}
