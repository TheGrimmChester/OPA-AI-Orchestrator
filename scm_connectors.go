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
	"strconv"
	"strings"
	"sync"
	"time"
)

// Repo watch — GitHub Repo Watch connectors + settings.

func registerRepoWatchMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	authView("/api/connectors", handleConnectorsList)
	authAdmin("/api/connectors/github/install-url", handleGitHubInstallURL)
	mux.HandleFunc("/api/connectors/github/callback", handleGitHubCallback)
	// PAT connect: viewer+ (scope gates in-handler — users can add personal PATs).
	registerAISettingsAuth(mux, "/api/connectors/github/pat", handleGitHubPATConnect)
	// Connector sub-routes: viewer+; mutate gates live in-handler (owner / org-admin / admin).
	registerAISettingsAuth(mux, "/api/connectors/", handleConnectorSub)
	authView("/api/scm/jobs", handleSCMJobsList)
	authAdmin("/api/scm/jobs/resume", handleSCMJobsResume)
	registerSCMAuthFlexible(mux, "/api/scm/jobs/", handleSCMJobSub)
	authView("/api/scm/webhooks", handleSCMWebhooksList)
	registerSCMAuthFlexible(mux, "/api/scm/webhooks/", handleSCMWebhookSub)
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
	Scope          string `json:"scope"`   // admin|org|user
	UserID         string `json:"user_id"` // set for user-scoped connectors
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
	// AutoRequestReviewer asks GitHub to add this App as a PR reviewer.
	AutoRequestReviewer bool `json:"auto_request_reviewer"`
	// AutoApproveMinScore is 1–100 confidence veto only: when >0 and
	// auto_merge_confidence is below the threshold, APPROVE is blocked
	// (REQUEST_CHANGES). It never grants APPROVE by itself — that requires
	// agent prefs AutoApprove plus the evidence conjunction.
	AutoApproveMinScore int    `json:"auto_approve_min_score"`
	LinkGroupID         string `json:"link_group_id"`
	UpdatedAt           string `json:"updated_at"`
}

func handleConnectorsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	a := actorFromRequest(r)
	seen := map[string]struct{}{}
	list := []map[string]interface{}{}
	appendIfVisible := func(c *opaConnector) {
		if c == nil || c.Status == "deleted" {
			return
		}
		scope := inferLegacyScope(c.OrganizationID, c.Scope)
		if !canSeeCredScope(a, scope, c.UserID, c.OrganizationID) {
			return
		}
		list = append(list, connectorPublic(c))
		seen[c.ID] = struct{}{}
	}
	connectorLive.Range(func(_, v interface{}) bool {
		c, ok := v.(*opaConnector)
		if !ok {
			return true
		}
		appendIfVisible(c)
		return true
	})
	if queryClient != nil {
		scopeSQL := tenantScopeSQL(r, queryClient, "")
		rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT id, organization_id, project_id, scope, user_id, kind, installation_id, account_login,
			       status, token_ref, meta_json, created_at, updated_at
			FROM opa.connectors WHERE status != 'deleted'%s ORDER BY updated_at DESC LIMIT 100`, scopeSQL))
		if err != nil {
			// Pre-migration schemas lack scope/user_id.
			rows, err = queryClient.Query(fmt.Sprintf(`
				SELECT id, organization_id, project_id, kind, installation_id, account_login,
				       status, token_ref, meta_json, created_at, updated_at
				FROM opa.connectors WHERE status != 'deleted'%s ORDER BY updated_at DESC LIMIT 100`, scopeSQL))
		}
		if err == nil {
			for _, row := range rows {
				id, _ := row["id"].(string)
				if id == "" {
					continue
				}
				if _, ok := seen[id]; ok {
					continue
				}
				if live := getOrHydrateConnector(id); live != nil {
					appendIfVisible(live)
					continue
				}
				c := connectorFromCHRow(row, false)
				appendIfVisible(c)
			}
		}
	}
	writeJSON(w, map[string]interface{}{
		"connectors":            list,
		"github_app_configured": githubAppConfigured(),
		"scopes":                []string{credScopeUser, credScopeOrg, credScopeAdmin},
		"can_edit_org":          a.isAdmin() && a.OrganizationID != "",
		"can_edit_admin":        a.isAdmin(),
		"can_edit_user":         a.Username != "" || !authEnforced,
		"honesty":               "Connectors are scoped admin|org|user. Admin connectors are never shared. Org connectors are inherited by members; users may add personal overrides.",
	})
}

func connectorPublic(c *opaConnector) map[string]interface{} {
	display := ""
	if meta := parseConnectorMeta(c.MetaJSON); meta != nil {
		if s, ok := meta["display_name"].(string); ok {
			display = s
		}
	}
	scope := inferLegacyScope(c.OrganizationID, c.Scope)
	return map[string]interface{}{
		"id": c.ID, "kind": c.Kind, "installation_id": c.InstallationID,
		"account_login": c.AccountLogin, "status": c.Status,
		"organization_id": c.OrganizationID, "project_id": c.ProjectID,
		"scope": scope, "user_id": c.UserID,
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
		ID: id, OrganizationID: org, ProjectID: proj, Scope: credScopeOrg, UserID: "",
		Kind: "github_app", InstallationID: inst, AccountLogin: "", Status: "active",
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
		Scope   string   `json:"scope"`
	}
	if json.Unmarshal(raw, &body) != nil || strings.TrimSpace(body.Token) == "" {
		http.Error(w, "token required", 400)
		return
	}
	a := actorFromRequest(r)
	scope, err := normalizeCredScope(body.Scope, a)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// Non-admins may only create personal connectors.
	if !a.isAdmin() {
		scope = credScopeUser
	}
	if err := canWriteCredScope(a, scope); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	org, proj, userID := resolveCredTarget(a, scope)
	if !enforceWriteLocalityHTTP(w, r, org, proj) {
		return
	}
	login := nz(body.Login, "pat-user")
	id := loadID("conn", org, proj, scope, userID, "github_pat", login, newRandomHex(8))
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	c := &opaConnector{
		ID: id, OrganizationID: org, ProjectID: proj, Scope: scope, UserID: userID,
		Kind: "github_pat", InstallationID: "", AccountLogin: login, Status: "active",
		TokenRef: body.Token, MetaJSON: `{"bootstrap":true}`, CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(id, c)
	persistConnector(c)
	for _, repo := range body.Repos {
		repo = strings.TrimSpace(repo)
		if repo == "" {
			continue
		}
		upsertWatched(org, proj, id, repo, "", true, defaultWatchedChecks(), "auto", "high", false, false, 0)
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector": connectorPublic(c),
		"honesty": "PAT bootstrap — prefer GitHub App for webhooks and Check Runs in production. Token is AES-GCM encrypted. Scope=" + scope + " (admin keys are never shared with org/users).",
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
	if len(parts) >= 2 && parts[1] == "permissions" && r.Method == http.MethodGet {
		handleConnectorPermissions(w, r, id)
		return
	}
	http.Error(w, "not found", 404)
}

// GET /api/connectors/{id}/permissions — installation permission health for
// AI Issues / roadmap (Dashboard banner).
func handleConnectorPermissions(w http.ResponseWriter, r *http.Request, id string) {
	c := getOrHydrateConnector(id)
	if denyConnectorIfInvisible(w, r, c) {
		return
	}
	health := assessInstallationPermHealth(c)
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": id, "permissions": health,
		"required_events": []string{
			"pull_request", "push", "installation", "installation_repositories",
			"issues", "issue_comment", "label",
		},
		"optional_events": []string{"projects_v2_item"},
	})
}

// denyConnectorIfInvisible writes 404 when the connector is missing or the
// caller must not learn it exists (no cross-tenant / cross-scope leakage).
func denyConnectorIfInvisible(w http.ResponseWriter, r *http.Request, c *opaConnector) bool {
	if c == nil || c.Status == "deleted" {
		http.Error(w, "not found", 404)
		return true
	}
	a := actorFromRequest(r)
	scope := inferLegacyScope(c.OrganizationID, c.Scope)
	if !canSeeCredScope(a, scope, c.UserID, c.OrganizationID) {
		http.Error(w, "not found", 404)
		return true
	}
	return false
}

// denyConnectorIfImmutable writes 404 if invisible, else 403 if the caller
// cannot mutate this connector's scope/ownership.
func denyConnectorIfImmutable(w http.ResponseWriter, r *http.Request, c *opaConnector) bool {
	if denyConnectorIfInvisible(w, r, c) {
		return true
	}
	a := actorFromRequest(r)
	scope := inferLegacyScope(c.OrganizationID, c.Scope)
	if err := canMutateCred(a, scope, c.UserID, c.OrganizationID); err != nil {
		http.Error(w, err.Error(), 403)
		return true
	}
	return false
}

func handleConnectorGet(w http.ResponseWriter, r *http.Request, id string) {
	c := getOrHydrateConnector(id)
	if denyConnectorIfInvisible(w, r, c) {
		return
	}
	writeJSON(w, map[string]interface{}{"connector": connectorPublic(c)})
}

func handleConnectorPatch(w http.ResponseWriter, r *http.Request, id string) {
	c := getOrHydrateConnector(id)
	if denyConnectorIfImmutable(w, r, c) {
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
	if c == nil && queryClient != nil {
		// Soft-load metadata for auth before delete (token not required).
		rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT id, organization_id, project_id, scope, user_id, kind, installation_id, account_login,
			       status, token_ref, meta_json, created_at, updated_at
			FROM opa.connectors WHERE id = '%s' ORDER BY updated_at DESC LIMIT 1`, escapeSQL(id)))
		if err != nil {
			rows, err = queryClient.Query(fmt.Sprintf(`
				SELECT id, organization_id, project_id, kind, installation_id, account_login,
				       status, token_ref, meta_json, created_at, updated_at
				FROM opa.connectors WHERE id = '%s' ORDER BY updated_at DESC LIMIT 1`, escapeSQL(id)))
		}
		if err == nil && len(rows) > 0 {
			c = connectorFromCHRow(rows[0], false)
		}
	}
	if denyConnectorIfImmutable(w, r, c) {
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	c.Status = "deleted"
	c.TokenRef = ""
	c.UpdatedAt = now
	connectorLive.Store(id, c)
	persistConnector(c)
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
	if c.Status == "deleted" {
		writeJSON(w, map[string]interface{}{
			"repos": []interface{}{},
			"error": "connector_not_found",
			"note":  "Connector was deleted. Pick another connector or reconnect under Settings · Connectors.",
		})
		return
	}
	a := actorFromRequest(r)
	scope := inferLegacyScope(c.OrganizationID, c.Scope)
	if !canSeeCredScope(a, scope, c.UserID, c.OrganizationID) {
		note := "Select the connector's organization in the tenant picker (top bar), then reload."
		if c.OrganizationID != "" {
			note = fmt.Sprintf("This connector belongs to organization %q. Select that org (or All, as admin) in the tenant picker, then reload.", c.OrganizationID)
		}
		if scope == credScopeUser && c.UserID != "" && a.Username != "" && c.UserID != a.Username {
			note = fmt.Sprintf("This is a personal connector owned by %q (signed in as %q).", c.UserID, a.Username)
		}
		writeJSON(w, map[string]interface{}{
			"repos": []interface{}{},
			"error": "connector_org_mismatch",
			"note":  note,
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
	c := getOrHydrateConnector(connectorID)
	if denyConnectorIfInvisible(w, r, c) {
		return
	}
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
			       enabled, service_name, profile, checks_json, min_severity, ai_blocking,
			       auto_request_reviewer, auto_approve_min_score, link_group_id, updated_at
			FROM opa.watched_repos
			WHERE connector_id = '%s'%s
			ORDER BY updated_at DESC LIMIT 200`, escapeSQL(connectorID), scope))
		if err != nil {
			rows, err = queryClient.Query(fmt.Sprintf(`
				SELECT id, organization_id, project_id, connector_id, repo_full_name, repo_id,
				       enabled, service_name, profile, checks_json, min_severity, ai_blocking, link_group_id, updated_at
				FROM opa.watched_repos
				WHERE connector_id = '%s'%s
				ORDER BY updated_at DESC LIMIT 200`, escapeSQL(connectorID), scope))
		}
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
	enabled := chBool(row["enabled"], true)
	ai := chBool(row["ai_blocking"], false)
	autoReq := chBool(row["auto_request_reviewer"], false)
	minScore := chInt(row["auto_approve_min_score"], 0)
	if minScore < 0 {
		minScore = 0
	}
	if minScore > 100 {
		minScore = 100
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
		AIBlocking: ai, AutoRequestReviewer: autoReq, AutoApproveMinScore: minScore,
		LinkGroupID: str("link_group_id"), UpdatedAt: str("updated_at"),
	}
}

func chBool(v interface{}, def bool) bool {
	switch t := v.(type) {
	case nil:
		return def
	case bool:
		return t
	case uint8:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case string:
		s := strings.TrimSpace(strings.ToLower(t))
		return s == "1" || s == "true" || s == "yes"
	default:
		return def
	}
}

func chInt(v interface{}, def int) int {
	switch t := v.(type) {
	case nil:
		return def
	case int:
		return t
	case int64:
		return int(t)
	case uint8:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return def
		}
		return n
	default:
		return def
	}
}

func handleWatchedPut(w http.ResponseWriter, r *http.Request, connectorID string) {
	c := getOrHydrateConnector(connectorID)
	if denyConnectorIfImmutable(w, r, c) {
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	var body struct {
		Repos []struct {
			RepoFullName          string   `json:"repo_full_name"`
			RepoID                string   `json:"repo_id"`
			Enabled               *bool    `json:"enabled"`
			ServiceName           string   `json:"service_name"`
			Profile               string   `json:"profile"`
			Checks                []string `json:"checks"`
			MinSeverity           string   `json:"min_severity"`
			AIBlocking            bool     `json:"ai_blocking"`
			AutoRequestReviewer   bool     `json:"auto_request_reviewer"`
			AutoApproveMinScore   int      `json:"auto_approve_min_score"`
		} `json:"repos"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	org, proj := c.OrganizationID, c.ProjectID
	if org == "" {
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
		minScore := item.AutoApproveMinScore
		if minScore < 0 {
			minScore = 0
		}
		if minScore > 100 {
			minScore = 100
		}
		wr := upsertWatched(org, proj, connectorID, repo, item.RepoID, en, checks, nz(item.Profile, "auto"), nz(item.MinSeverity, "high"), item.AIBlocking, item.AutoRequestReviewer, minScore)
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

func upsertWatched(org, proj, connectorID, repo, repoID string, enabled bool, checks []string, profile, minSev string, aiBlock, autoRequest bool, minScore int) *opaWatchedRepo {
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	checksJSON, _ := json.Marshal(checks)
	id := loadID("watch", org, proj, connectorID, repo)
	prevGroup := ""
	if v, ok := watchedLive.Load(connectorID + "|" + repo); ok {
		if old, ok := v.(*opaWatchedRepo); ok {
			prevGroup = old.LinkGroupID
		}
	}
	if minScore < 0 {
		minScore = 0
	}
	if minScore > 100 {
		minScore = 100
	}
	wr := &opaWatchedRepo{
		ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: connectorID,
		RepoFullName: repo, RepoID: repoID, Enabled: enabled,
		ServiceName: strings.ReplaceAll(repo, "/", "-"),
		Profile: profile, ChecksJSON: string(checksJSON),
		MinSeverity: minSev, AIBlocking: aiBlock,
		AutoRequestReviewer: autoRequest, AutoApproveMinScore: minScore,
		LinkGroupID: prevGroup, UpdatedAt: now,
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
		SELECT id, organization_id, project_id, scope, user_id, kind, installation_id, account_login,
		       status, token_ref, meta_json, created_at, updated_at
		FROM opa.connectors
		WHERE id = '%s' AND status != 'deleted'
		ORDER BY updated_at DESC LIMIT 1`, escapeSQL(id)))
	if err != nil {
		// Pre-migration schemas lack scope/user_id.
		rows, err = queryClient.Query(fmt.Sprintf(`
			SELECT id, organization_id, project_id, kind, installation_id, account_login,
			       status, token_ref, meta_json, created_at, updated_at
			FROM opa.connectors
			WHERE id = '%s' AND status != 'deleted'
			ORDER BY updated_at DESC LIMIT 1`, escapeSQL(id)))
	}
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
		Scope: inferLegacyScope(str("organization_id"), str("scope")), UserID: str("user_id"),
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
	var candidates []*opaWatchedRepo
	watchedLive.Range(func(_, v interface{}) bool {
		wr, ok := v.(*opaWatchedRepo)
		if !ok || !wr.Enabled {
			return true
		}
		if strings.EqualFold(wr.RepoFullName, repo) {
			candidates = append(candidates, wr)
		}
		return true
	})
	if len(candidates) == 0 {
		return nil, nil
	}
	found := preferWatchedForChecks(candidates)
	return found, getOrHydrateConnector(found.ConnectorID)
}

// preferWatchedForChecks picks the github_app watch when both App and PAT watch
// the same repo so Check Runs post as the GitHub App bot.
func preferWatchedForChecks(cands []*opaWatchedRepo) *opaWatchedRepo {
	if len(cands) == 1 {
		return cands[0]
	}
	var best *opaWatchedRepo
	bestScore := -1
	for _, wr := range cands {
		score := 0
		c := getOrHydrateConnector(wr.ConnectorID)
		if c != nil && c.Kind == "github_app" && c.InstallationID != "" {
			score += 100
		}
		if wr.AutoRequestReviewer {
			score += 10
		}
		if strings.Contains(wr.ChecksJSON, "ai_review") {
			score += 5
		}
		if score > bestScore {
			bestScore = score
			best = wr
		}
	}
	if best == nil {
		return cands[0]
	}
	return best
}

// ensureGitHubAppConnector creates or returns the connector for an installation.
// Used by install webhooks and PR auto-watch so every installed repo can be checked.
func ensureGitHubAppConnector(installationID, accountLogin string) *opaConnector {
	inst := strings.TrimSpace(installationID)
	if inst == "" || !githubAppConfigured() {
		return nil
	}
	if c := findConnectorByInstallation(inst); c != nil {
		if accountLogin != "" && strings.TrimSpace(c.AccountLogin) == "" {
			c.AccountLogin = accountLogin
			c.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
			persistConnector(c)
		}
		return c
	}
	org, proj := "default-org", "default-project"
	connectorLive.Range(func(_, v interface{}) bool {
		c, ok := v.(*opaConnector)
		if !ok || c.Status == "deleted" {
			return true
		}
		if c.Kind == "github_app" || c.Kind == "github_pat" {
			if c.OrganizationID != "" {
				org = c.OrganizationID
			}
			if c.ProjectID != "" {
				proj = c.ProjectID
			}
			return false
		}
		return true
	})
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	id := loadID("conn", org, proj, "github_app", inst)
	c := &opaConnector{
		ID: id, OrganizationID: org, ProjectID: proj, Scope: credScopeOrg, UserID: "",
		Kind: "github_app", InstallationID: inst, AccountLogin: accountLogin, Status: "active",
		MetaJSON: `{"auto_provisioned":true}`, CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(id, c)
	persistConnector(c)
	log.Printf("[INFO] provisioned github_app connector %s installation=%s account=%s", id, inst, accountLogin)
	return c
}

// autoWatchInstalledRepo enables Repo Watch + OPA Review for a repo on an
// installation connector. Idempotent: existing enabled watches are left as-is
// (checks are not overwritten).
func autoWatchInstalledRepo(c *opaConnector, repo string) *opaWatchedRepo {
	if c == nil {
		return nil
	}
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return nil
	}
	key := c.ID + "|" + repo
	if v, ok := watchedLive.Load(key); ok {
		if wr, ok := v.(*opaWatchedRepo); ok && wr.Enabled {
			return wr
		}
	}
	// Prefer cloning policy from any existing watch of this repo.
	autoReq := true
	minScore := 0
	minSev := "high"
	checks := defaultWatchedChecks()
	watchedLive.Range(func(_, v interface{}) bool {
		wr, ok := v.(*opaWatchedRepo)
		if !ok || !strings.EqualFold(wr.RepoFullName, repo) {
			return true
		}
		if wr.ChecksJSON != "" {
			var parsed []string
			if json.Unmarshal([]byte(wr.ChecksJSON), &parsed) == nil && len(parsed) > 0 {
				checks = parsed
			}
		}
		autoReq = wr.AutoRequestReviewer
		minScore = wr.AutoApproveMinScore
		minSev = nz(wr.MinSeverity, minSev)
		return false
	})
	hasAI := false
	for _, ch := range checks {
		if ch == "ai_review" {
			hasAI = true
			break
		}
	}
	if !hasAI {
		checks = append(checks, "ai_review")
	}
	wr := upsertWatched(c.OrganizationID, c.ProjectID, c.ID, repo, "", true, checks, "auto", minSev, false, autoReq, minScore)
	log.Printf("[INFO] auto-watched %s on connector %s (checks=%v)", repo, c.ID, checks)
	return wr
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
		"scope": inferLegacyScope(c.OrganizationID, c.Scope), "user_id": c.UserID,
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
	en, ai, autoReq := uint8(0), uint8(0), uint8(0)
	if wr.Enabled {
		en = 1
	}
	if wr.AIBlocking {
		ai = 1
	}
	if wr.AutoRequestReviewer {
		autoReq = 1
	}
	minScore := wr.AutoApproveMinScore
	if minScore < 0 {
		minScore = 0
	}
	if minScore > 100 {
		minScore = 100
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"id": wr.ID, "organization_id": wr.OrganizationID, "project_id": wr.ProjectID,
		"connector_id": wr.ConnectorID, "repo_full_name": wr.RepoFullName, "repo_id": wr.RepoID,
		"enabled": en, "service_name": wr.ServiceName, "profile": wr.Profile,
		"checks_json": wr.ChecksJSON, "min_severity": wr.MinSeverity, "ai_blocking": ai,
		"auto_request_reviewer": autoReq, "auto_approve_min_score": minScore,
		"link_group_id": wr.LinkGroupID, "updated_at": wr.UpdatedAt,
	})
	writer.insertAsync("watched_repos", append(payload, '\n'))
}

func handleSCMSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	a := actorFromRequest(r)
	org, proj := a.OrganizationID, a.ProjectID
	ctx, _ := ExtractTenantContext(r, queryClient)
	if ctx == nil {
		ctx = &TenantContext{}
	}
	if org == "" {
		org, proj = ctx.WriteTenant()
	} else if proj == "" || proj == tenantAll {
		_, defProj := ctx.WriteTenant()
		proj = defProj
	}
	userID := strings.TrimSpace(a.Username)
	// Same resolution as OPA Review / Generate: user → org → fail closed.
	hit := resolveSCMSecret(credResolveQuery{
		OrganizationID: org, ProjectID: proj, UserID: userID,
	}, scmCursorSecretKey)
	hasKey := hit.Plain != ""
	_, _, cursorModel, _ := resolveCLICursorConfig(org, proj, userID)
	honesty := "OPA Review CLI key resolves user → org → fail closed (never admin, never process env). Manage under Account (personal or org)."
	if !hasKey {
		who := userID
		if who == "" {
			who = "(no username — sign in so personal keys can resolve)"
		}
		orgLabel := org
		if orgLabel == "" {
			orgLabel = "(no org selected)"
		}
		honesty = "No CLI agent API key for user " + who + " in org " + orgLabel +
			". Save a personal key while signed in as that user, or an org key under Account → Organization. Keys are not shared across usernames (e.g. admin ≠ opa-admin)."
	}
	writeJSON(w, map[string]interface{}{
		"github_app_configured": githubAppConfigured(),
		"cursor_key_set":        hasKey,
		"cursor_key_scope":      hit.Scope,
		"cursor_model":          cursorModel,
		"organization_id":       org,
		"project_id":            proj,
		"user_id":               userID,
		"webhook_url":           strings.TrimRight(envOr("OPA_PUBLIC_URL", "http://127.0.0.1:8080"), "/") + "/v1/scm/github/webhook",
		"skip_cursor_ai":        envOr("SKIP_CURSOR_AI", "0") == "1",
		"workspace":             securityWorkspaceRoot(),
		"ai_settings_path":      "/api/ai/settings",
		"account_path":          "/settings/account",
		"honesty":               honesty,
	})
}

func handleCursorKeySet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	a := actorFromRequest(r)
	if err := canWriteCredScope(a, credScopeOrg); err != nil {
		http.Error(w, err.Error(), 403)
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
	if a.OrganizationID == "" {
		http.Error(w, "org scope requires X-Organization-ID", 400)
		return
	}
	org = a.OrganizationID
	if a.ProjectID != "" {
		proj = a.ProjectID
	}
	if body.Clear {
		if err := setCLICursorKeyFromAlias(org, proj, "", true); err != nil {
			log.Printf("[WARN] clear cli_cursor via cursor-key alias: %v", err)
			http.Error(w, "failed to clear cursor key", 500)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "cursor_key_set": false})
		return
	}
	if strings.TrimSpace(body.APIKey) == "" {
		http.Error(w, "api_key required", 400)
		return
	}
	key := strings.TrimSpace(body.APIKey)
	if err := setCLICursorKeyFromAlias(org, proj, key, false); err != nil {
		log.Printf("[WARN] persist cursor key via AI settings: %v", err)
		http.Error(w, "failed to encrypt/persist cursor key — set OPA_CONNECTOR_SECRET or stable JWT_SECRET", 500)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "cursor_key_set": true, "organization_id": org, "project_id": proj, "alias_of": "cli_cursor"})
}

// resolveCursorAPIKey returns the CLI agent API key for a tenant job.
// Resolution: user (optional) → org → fail closed. Never admin, never env.
func resolveCursorAPIKey(orgProj ...string) string {
	org, proj, userID := "", "", ""
	if len(orgProj) >= 1 {
		org = orgProj[0]
	}
	if len(orgProj) >= 2 {
		proj = orgProj[1]
	}
	if len(orgProj) >= 3 {
		userID = orgProj[2]
	}
	key, _, _, _ := resolveCLICursorConfig(org, proj, userID)
	return key
}

func hydrateCursorKeyFromCH(org, proj string) {
	// Fail-closed scoped load only — no "any row" / admin / env fallback.
	plain := loadSCMSecretPlain(org, proj, scmCursorSecretKey)
	if plain == "" {
		return
	}
	cursorKeyMu.Lock()
	cursorKeyMem = plain
	cursorKeyOrg, cursorKeyProj = org, proj
	cursorKeyMu.Unlock()
}

// hydrateSCMOnBoot reloads encrypted PATs, watched repos, and Cursor API key after ClickHouse is ready.
func hydrateSCMOnBoot() {
	if queryClient == nil {
		return
	}
	ensureCredentialScopeColumns()
	ensureWatchedRepoReviewColumns()
	ensureAgentsTables()
	n := 0
	rows, err := queryClient.Query(`
		SELECT id, organization_id, project_id, scope, user_id, kind, installation_id, account_login,
		       status, token_ref, meta_json, created_at, updated_at
		FROM opa.connectors
		WHERE status != 'deleted'
		ORDER BY updated_at DESC LIMIT 200`)
	if err != nil {
		// Pre-migration schemas lack scope/user_id.
		rows, err = queryClient.Query(`
			SELECT id, organization_id, project_id, kind, installation_id, account_login,
			       status, token_ref, meta_json, created_at, updated_at
			FROM opa.connectors
			WHERE status != 'deleted'
			ORDER BY updated_at DESC LIMIT 200`)
	}
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
	_ = hydrateAgentPrefsOnBoot()
	nWide := ensureOrgWideCLICursorKeys()
	hydrateCursorKeyFromCH("", "")
	hydrateSCMJobsAndStacksOnBoot()
	cursorKeyMu.Lock()
	hasCursor := cursorKeyMem != ""
	cursorKeyMu.Unlock()
	// cursor_key_set here is legacy admin/mem hydrate (empty org) — per-tenant
	// resolution uses scm_secrets via resolveCursorAPIKey. Prefer org keys.
	orgKeyHint := nWide > 0 || resolveCursorAPIKey("default-org", "default-project", "") != "" ||
		resolveCursorAPIKey("nas", "infra", "") != ""
	log.Printf("[INFO] SCM hydrate: %d connector(s), %d watched repo(s) from ClickHouse; cursor_key_mem=%v org_cli_keys=%v org_wide_seeded=%d",
		n, nw, hasCursor, orgKeyHint, nWide)
}

func ensureWatchedRepoReviewColumns() {
	if queryClient == nil {
		return
	}
	for _, q := range []string{
		`ALTER TABLE opa.watched_repos ADD COLUMN IF NOT EXISTS auto_request_reviewer UInt8 DEFAULT 0`,
		`ALTER TABLE opa.watched_repos ADD COLUMN IF NOT EXISTS auto_approve_min_score UInt8 DEFAULT 0`,
	} {
		if err := queryClient.Execute(q); err != nil {
			log.Printf("[WARN] ensureWatchedRepoReviewColumns: %v", err)
		}
	}
}

func hydrateWatchedReposOnBoot() int {
	if queryClient == nil {
		return 0
	}
	rows, err := queryClient.Query(`
		SELECT id, organization_id, project_id, connector_id, repo_full_name, repo_id,
		       enabled, service_name, profile, checks_json, min_severity, ai_blocking,
		       auto_request_reviewer, auto_approve_min_score, link_group_id, updated_at
		FROM opa.watched_repos
		ORDER BY updated_at DESC LIMIT 500`)
	if err != nil {
		// Older schemas lack review-policy columns — fall back then retry after ALTER.
		rows, err = queryClient.Query(`
			SELECT id, organization_id, project_id, connector_id, repo_full_name, repo_id,
			       enabled, service_name, profile, checks_json, min_severity, ai_blocking, link_group_id, updated_at
			FROM opa.watched_repos
			ORDER BY updated_at DESC LIMIT 500`)
		if err != nil {
			log.Printf("[WARN] hydrateSCMOnBoot watched_repos: %v", err)
			return 0
		}
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
