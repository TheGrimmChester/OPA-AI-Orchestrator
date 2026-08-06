package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// Repo watch — GitHub Repo Watch connectors + settings.

func registerRepoWatchMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	// Connector list/read accept user JWT or peer service JWT (connectors:read).
	registerConnectorReadAuth(mux, "/api/connectors", handleConnectorsList)
	authAdmin("/api/connectors/github/install-url", handleGitHubInstallURL)
	mux.HandleFunc("/api/connectors/github/callback", handleGitHubCallback)
	// PAT connect: viewer+ (scope gates in-handler — users can add personal PATs).
	registerAISettingsAuth(mux, "/api/connectors/github/pat", handleGitHubPATConnect)
	// Connector sub-routes: viewer+ or peer service; mutate gates live in-handler.
	registerConnectorReadAuth(mux, "/api/connectors/", handleConnectorSub)
	registerPeerSCMMux(mux)
	authView("/api/scm/jobs", handleSCMJobsList)
	authAdmin("/api/scm/jobs/resume", handleSCMJobsResume)
	registerSCMAuthFlexible(mux, "/api/scm/jobs/", handleSCMJobSub)
	authView("/api/scm/webhooks", handleSCMWebhooksList)
	registerSCMAuthFlexible(mux, "/api/scm/webhooks/", handleSCMWebhookSub)
	authView("/api/scm/settings", handleSCMSettings)
	authAdmin("/api/scm/settings/cursor-key", handleCursorKeySet)
	mux.HandleFunc("/v1/scm/github/webhook", handleGitHubWebhook)
	mux.HandleFunc("/v1/scm/github/webhook/", handleGitHubWebhookByConnector)
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

// registerConnectorReadAuth allows user JWTs (viewer+) or peer service JWTs with
// connectors:read. Mutations require a user JWT so peers cannot bootstrap PATs.
func registerConnectorReadAuth(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !authEnforced {
			h(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			AuthMiddleware(h, "viewer")(w, r)
			return
		}
		AuthUserOrServiceMiddleware(h, "viewer", "connectors:read")(w, r)
	})
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
	GithubHookID        int64  `json:"github_hook_id"`
	WebhookSecretRef    string `json:"-"`
	WebhookMode         string `json:"webhook_mode"` // app | repo
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
		if !canSeeConnector(a, c) {
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
				c := connectorFromCHRow(context.Background(), row, false)
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
		"webhook_mode": connectorWebhookMode(c),
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
	if !requireOrganizationAccountHTTP(w, r, "GitHub App install") {
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
	a := actorFromRequest(r)
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	if a.OrganizationID != "" {
		org, proj = a.OrganizationID, nz(a.ProjectID, proj)
	}
	if claims := claimsFromRequestToken(r); claims != nil {
		if jo := strings.TrimSpace(claims.OrgID); jo != "" {
			org = jo
		}
	}
	org = strings.TrimSpace(org)
	if org == "" {
		http.Error(w, "organization_id required — GitHub App install binds to an Open organization account", 400)
		return
	}
	state := ""
	stateNote := ""
	if s, err := mintGitHubInstallState(org, proj, a.Username); err == nil {
		state = s
	} else {
		stateNote = err.Error()
	}
	installURL := fmt.Sprintf("https://github.com/apps/%s/installations/new", nz(appSlug, "opa-repo-watch"))
	if state != "" {
		installURL += "?state=" + state
	}
	if cid := strings.TrimSpace(os.Getenv("OPA_GITHUB_APP_CLIENT_ID")); cid != "" {
		installURL = fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s", cid)
		if state != "" {
			installURL += "&state=" + state
		}
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "configured": true, "install_url": installURL,
		"webhook_url":  public + "/v1/scm/github/webhook",
		"callback_url": public + "/api/connectors/github/callback",
		"organization_id": org, "project_id": proj,
		"state_signed": state != "", "state_note": stateNote,
	})
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	inst := strings.TrimSpace(r.URL.Query().Get("installation_id"))
	setup := strings.TrimSpace(r.URL.Query().Get("setup_action"))
	stateRaw := strings.TrimSpace(r.URL.Query().Get("state"))
	if inst == "" {
		http.Error(w, "installation_id required", 400)
		return
	}
	org, proj, userID, status := "", "", "", "active"
	if stateRaw != "" {
		if st, err := parseGitHubInstallState(stateRaw); err == nil && st != nil {
			org, proj, userID = st.OrganizationID, st.ProjectID, st.UserID
		}
	}
	claimRaw, claimHash := "", ""
	if org == "" {
		status = "pending_claim"
		raw, hash, err := mintConnectorClaimNonce()
		if err != nil {
			http.Error(w, "claim nonce unavailable", 500)
			return
		}
		claimRaw, claimHash = raw, hash
	}
	id := loadID("conn", nz(org, "pending"), nz(proj, "pending"), "github_app", inst)
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	meta := map[string]interface{}{"setup_action": setup}
	if status == "pending_claim" {
		meta["pending_claim"] = true
		if claimHash != "" {
			meta["claim_nonce_hash"] = claimHash
		}
	}
	metaJSON, _ := json.Marshal(meta)
	c := &opaConnector{
		ID: id, OrganizationID: org, ProjectID: proj, Scope: credScopeOrg, UserID: userID,
		Kind: "github_app", InstallationID: inst, AccountLogin: "", Status: status,
		MetaJSON: string(metaJSON), CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(id, c)
	persistConnector(c)
	dash := strings.TrimRight(envOr("OPA_DASHBOARD_URL", "http://127.0.0.1:8088"), "/")
	q := url.Values{}
	q.Set("connector", id)
	if claimRaw != "" {
		q.Set("claim_token", claimRaw)
	}
	http.Redirect(w, r, dash+"/settings/connectors?"+q.Encode(), http.StatusFound)
}

// mintConnectorClaimNonce returns a high-entropy one-time claim token and its
// sha256 hex hash. The raw token is returned to the browser once via redirect;
// only the hash is stored. Never log the raw token.
func mintConnectorClaimNonce() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash, nil
}

// requireOrganizationAccountHTTP rejects personal Open accounts. GitHub App
// install/claim is organization-only (role admin does not bypass account_type).
func requireOrganizationAccountHTTP(w http.ResponseWriter, r *http.Request, action string) bool {
	claims := claimsFromRequestToken(r)
	if claims == nil {
		return true
	}
	at := strings.ToLower(strings.TrimSpace(claims.AccountType))
	if at == openauth.AccountTypePersonal {
		http.Error(w, action+" requires an organization Open account (not personal)", 400)
		return false
	}
	if at == "" && strings.TrimSpace(claims.OrgID) == "" {
		// Legacy unbound token without account_type — treat as personal for App bind.
		http.Error(w, action+" requires an organization Open account (not personal)", 400)
		return false
	}
	return true
}

var connectorClaimMu sync.Mutex

// POST /api/connectors/{id}/claim — organization account attaches a pending_claim
// GitHub App install using the one-time claim_token from the orphan callback.
// CAS pending→active; wipe nonce; stamp watches; OAM sync via persist.
func handleConnectorClaim(w http.ResponseWriter, r *http.Request, id string) {
	if !requireOrganizationAccountHTTP(w, r, "GitHub App claim") {
		return
	}
	rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		ClaimToken string `json:"claim_token"`
	}
	_ = json.Unmarshal(rawBody, &body)
	claimToken := strings.TrimSpace(body.ClaimToken)
	if claimToken == "" {
		http.Error(w, "claim_token required", 400)
		return
	}

	connectorClaimMu.Lock()
	defer connectorClaimMu.Unlock()

	c := getOrHydrateConnector(id)
	if c == nil || c.Status == "deleted" {
		http.Error(w, "not found", 404)
		return
	}
	a := actorFromRequest(r)
	if !a.isAdmin() {
		http.Error(w, "admin role required to claim a connector", 403)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(c.Status), "pending_claim") {
		writeJSONStatus(w, http.StatusConflict, map[string]interface{}{
			"ok": false, "error": "not_pending_claim",
			"message": "connector is not pending_claim",
			"status":  c.Status,
		})
		return
	}
	meta := parseConnectorMeta(c.MetaJSON)
	wantHash, _ := meta["claim_nonce_hash"].(string)
	wantHash = strings.TrimSpace(wantHash)
	gotSum := sha256.Sum256([]byte(claimToken))
	gotHash := hex.EncodeToString(gotSum[:])
	if wantHash == "" || !hmac.Equal([]byte(wantHash), []byte(gotHash)) {
		http.Error(w, "invalid claim_token", 403)
		return
	}

	org := strings.TrimSpace(a.OrganizationID)
	proj := strings.TrimSpace(a.ProjectID)
	if claims := claimsFromRequestToken(r); claims != nil {
		if jo := strings.TrimSpace(claims.OrgID); jo != "" {
			org = jo
		}
	}
	if org == "" {
		ctx, _ := ExtractTenantContext(r, queryClient)
		if ctx != nil {
			org, proj = ctx.WriteTenant()
		}
	}
	org = strings.TrimSpace(org)
	if org == "" {
		http.Error(w, "organization_id required — select an Open organization before claiming", 400)
		return
	}
	if proj == "" || proj == tenantAll {
		proj = defaultProjectID
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	c.OrganizationID = org
	c.ProjectID = proj
	c.Scope = credScopeOrg
	if uid := strings.TrimSpace(a.Username); uid != "" {
		c.UserID = uid
	}
	c.Status = "active"
	c.UpdatedAt = now
	delete(meta, "pending_claim")
	delete(meta, "claim_nonce_hash")
	meta["claimed_at"] = now
	if a.Username != "" {
		meta["claimed_by"] = a.Username
	}
	meta["claimed_organization_id"] = org
	meta["claimed_project_id"] = proj
	b, _ := json.Marshal(meta)
	c.MetaJSON = string(b)
	connectorLive.Store(id, c)
	persistConnector(c)
	stampWatchedTenantForConnector(c)
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector": connectorPublic(c),
		"honesty": "Claimed into the Open organization from your session — not from GitHub account_login.",
	})
}

func handleGitHubPATConnect(w http.ResponseWriter, r *http.Request) {
	if refuseOAMLocalWrite(w) {
		return
	}
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
	if len(parts) >= 2 && parts[1] == "claim" && r.Method == http.MethodPost {
		handleConnectorClaim(w, r, id)
		return
	}
	http.Error(w, "not found", 404)
}

// stampWatchedTenantForConnector copies connector org/project onto watches that
// still lack organization_id (auto-watch during pending_claim).
func stampWatchedTenantForConnector(c *opaConnector) {
	if c == nil || strings.TrimSpace(c.OrganizationID) == "" {
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	watchedLive.Range(func(_, v interface{}) bool {
		wr, ok := v.(*opaWatchedRepo)
		if !ok || wr.ConnectorID != c.ID {
			return true
		}
		if strings.TrimSpace(wr.OrganizationID) != "" {
			return true
		}
		wr.OrganizationID = c.OrganizationID
		wr.ProjectID = nz(strings.TrimSpace(c.ProjectID), defaultProjectID)
		wr.UpdatedAt = now
		persistWatched(wr)
		return true
	})
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
// pending_claim / empty-org rows are invisible to everyone including admins.
func denyConnectorIfInvisible(w http.ResponseWriter, r *http.Request, c *opaConnector) bool {
	if c == nil || c.Status == "deleted" {
		http.Error(w, "not found", 404)
		return true
	}
	a := actorFromRequest(r)
	if !canSeeConnector(a, c) {
		http.Error(w, "not found", 404)
		return true
	}
	return false
}

// denyConnectorIfImmutable writes 404 if invisible, else 403 if the caller
// cannot mutate this connector's scope/ownership. Unclaimed rows are never mutable here.
func denyConnectorIfImmutable(w http.ResponseWriter, r *http.Request, c *opaConnector) bool {
	if denyConnectorIfInvisible(w, r, c) {
		return true
	}
	if connectorIsUnclaimed(c) {
		http.Error(w, "connector is pending claim — use POST /claim with claim_token", 403)
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
	if refuseOAMLocalWrite(w) {
		return
	}
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
	if refuseOAMLocalWrite(w) {
		return
	}
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
			c = connectorFromCHRow(context.Background(), rows[0], false)
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
	if !canSeeConnector(a, c) {
		note := "Select the connector's organization in the tenant picker (top bar), then reload."
		if c.OrganizationID != "" {
			note = fmt.Sprintf("This connector belongs to organization %q. Select that org in the tenant picker, then reload.", c.OrganizationID)
		}
		scope := inferLegacyScope(c.OrganizationID, c.Scope)
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
		LinkGroupID: str("link_group_id"),
		GithubHookID: watchedHookIDFromRow(row), WebhookSecretRef: str("webhook_secret_ref"),
		WebhookMode: nz(str("webhook_mode"), "app"), UpdatedAt: str("updated_at"),
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
	items, err := parseWatchedPutItems(raw)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	org, proj := c.OrganizationID, c.ProjectID
	if org == "" {
		ctx, _ := ExtractTenantContext(r, queryClient)
		org, proj = ctx.WriteTenant()
	}
	saved := []opaWatchedRepo{}
	for _, item := range items {
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
		if c.Kind == "github_pat" {
			if err := syncWatchedRepoWebhook(c, wr, en); err != nil {
				log.Printf("[WARN] watched repo webhook sync %s: %v", repo, err)
			}
		}
		saved = append(saved, *wr)
	}
	writeJSON(w, map[string]interface{}{"ok": true, "watched": saved})
}

type watchedPutItem struct {
	RepoFullName        string
	RepoID              string
	Enabled             *bool
	ServiceName         string
	Profile             string
	Checks              []string
	MinSeverity         string
	AIBlocking          bool
	AutoRequestReviewer bool
	AutoApproveMinScore int
}

func parseWatchedPutItems(raw []byte) ([]watchedPutItem, error) {
	var body struct {
		Repos   []json.RawMessage `json:"repos"`
		Watched []json.RawMessage `json:"watched"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return nil, fmt.Errorf("bad json")
	}
	entries := body.Repos
	if len(entries) == 0 {
		entries = body.Watched
	}
	out := make([]watchedPutItem, 0, len(entries))
	for _, entryRaw := range entries {
		item, err := watchedPutItemFromRaw(entryRaw)
		if err != nil {
			return nil, err
		}
		if item.RepoFullName != "" {
			out = append(out, item)
		}
	}
	return out, nil
}

func watchedPutItemFromRaw(raw json.RawMessage) (watchedPutItem, error) {
	var item watchedPutItem
	var row map[string]interface{}
	if json.Unmarshal(raw, &row) != nil {
		return item, fmt.Errorf("bad json")
	}
	strField := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := row[k]; ok {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}
	item.RepoFullName = strField("repo_full_name", "repo")
	item.RepoID = strField("repo_id")
	item.ServiceName = strField("service_name")
	item.Profile = strField("profile")
	item.MinSeverity = strField("min_severity")
	if v, ok := row["enabled"].(bool); ok {
		item.Enabled = &v
	}
	if v, ok := row["ai_blocking"].(bool); ok {
		item.AIBlocking = v
	}
	if v, ok := row["auto_request_reviewer"].(bool); ok {
		item.AutoRequestReviewer = v
	}
	if v, ok := row["auto_approve_min_score"].(float64); ok {
		item.AutoApproveMinScore = int(v)
	}
	item.Checks = parseChecksField(row["checks"])
	if len(item.Checks) == 0 {
		item.Checks = parseChecksField(row["checks_json"])
	}
	return item, nil
}

func parseChecksField(v interface{}) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case []string:
		return t
	case string:
		raw := strings.TrimSpace(t)
		if raw == "" {
			return nil
		}
		var checks []string
		if json.Unmarshal([]byte(raw), &checks) == nil {
			return checks
		}
	}
	return nil
}

func defaultWatchedChecks() []string {
	checks := []string{"ora:review"}
	if peerProductConfigured("PEER_OSA_URL") {
		checks = append(checks, "osa:dependencies")
	}
	if peerProductConfigured("PEER_OPL_URL") {
		checks = append(checks, "opl:perf-gate")
	}
	if peerProductConfigured("PEER_OPM_URL") {
		checks = append(checks, "opm:delivery")
	}
	return checks
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
		LinkGroupID: prevGroup, WebhookMode: "app", UpdatedAt: now,
	}
	if v, ok := watchedLive.Load(connectorID + "|" + repo); ok {
		if old, ok := v.(*opaWatchedRepo); ok {
			wr.GithubHookID = old.GithubHookID
			wr.WebhookSecretRef = old.WebhookSecretRef
			if old.WebhookMode != "" {
				wr.WebhookMode = old.WebhookMode
			}
		}
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

// needsLegacyConnectorFallback is true when ORA runs in a product DB (ora) and
// legacy connector rows may still live in hub opa.connectors (QueryExact only).
func needsLegacyConnectorFallback() bool {
	db := clickHouseDatabase()
	return db != "" && db != "opa" && db != "default"
}

func connectorSelectCols() string {
	return `id, organization_id, project_id, scope, user_id, kind, installation_id, account_login,
		       status, token_ref, meta_json, created_at, updated_at`
}

func connectorSelectColsLegacy() string {
	return `id, organization_id, project_id, kind, installation_id, account_login,
			       status, token_ref, meta_json, created_at, updated_at`
}

func queryProductConnectorRows(id string, limit int) ([]map[string]interface{}, error) {
	if queryClient == nil {
		return nil, fmt.Errorf("clickhouse query client not configured")
	}
	where := "status != 'deleted'"
	if strings.TrimSpace(id) != "" {
		where += fmt.Sprintf(" AND id = '%s'", escapeSQL(id))
	}
	lim := ""
	if limit > 0 {
		lim = fmt.Sprintf(" LIMIT %d", limit)
	}
	q := fmt.Sprintf(`SELECT %s FROM opa.connectors WHERE %s ORDER BY updated_at DESC%s`,
		connectorSelectCols(), where, lim)
	rows, err := queryClient.Query(q)
	if err != nil {
		rows, err = queryClient.Query(fmt.Sprintf(`SELECT %s FROM opa.connectors WHERE %s ORDER BY updated_at DESC%s`,
			connectorSelectColsLegacy(), where, lim))
	}
	return rows, err
}

func queryLegacyHubConnectorRows(id string, limit int) ([]map[string]interface{}, error) {
	if queryClient == nil || !needsLegacyConnectorFallback() {
		return nil, nil
	}
	where := "status != 'deleted'"
	if strings.TrimSpace(id) != "" {
		where += fmt.Sprintf(" AND id = '%s'", escapeSQL(id))
	}
	lim := ""
	if limit > 0 {
		lim = fmt.Sprintf(" LIMIT %d", limit)
	}
	q := fmt.Sprintf(`SELECT %s FROM opa.connectors WHERE %s ORDER BY updated_at DESC%s`,
		connectorSelectCols(), where, lim)
	rows, err := queryClient.QueryExact(q)
	if err != nil {
		rows, err = queryClient.QueryExact(fmt.Sprintf(`SELECT %s FROM opa.connectors WHERE %s ORDER BY updated_at DESC%s`,
			connectorSelectColsLegacy(), where, lim))
	}
	return rows, err
}

func storeHydratedConnector(c *opaConnector, backfillLegacy bool) *opaConnector {
	if c == nil || c.Status == "deleted" {
		return nil
	}
	connectorLive.Store(c.ID, c)
	if backfillLegacy && needsLegacyConnectorFallback() {
		persistConnector(c)
	}
	return c
}

func hydrateConnectorFromCH(id string) *opaConnector {
	if queryClient == nil || strings.TrimSpace(id) == "" {
		return nil
	}
	rows, err := queryProductConnectorRows(id, 1)
	fromLegacy := false
	if err != nil || len(rows) == 0 {
		if legacy, lerr := queryLegacyHubConnectorRows(id, 1); lerr == nil && len(legacy) > 0 {
			rows, fromLegacy = legacy, true
		} else {
			return nil
		}
	}
	c := connectorFromCHRow(context.Background(), rows[0], true)
	return storeHydratedConnector(c, fromLegacy)
}

// backfillLegacyConnectorsOnBoot copies hub opa.connectors rows missing from the
// product DB into memory + ora.connectors so peer clone-credentials survives restart.
func backfillLegacyConnectorsOnBoot() int {
	if queryClient == nil || !needsLegacyConnectorFallback() {
		return 0
	}
	rows, err := queryLegacyHubConnectorRows("", 200)
	if err != nil || len(rows) == 0 {
		return 0
	}
	n := 0
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
		if prod, _ := queryProductConnectorRows(id, 1); len(prod) > 0 {
			continue
		}
		c := connectorFromCHRow(context.Background(), row, true)
		if storeHydratedConnector(c, true) != nil {
			n++
		}
	}
	return n
}

func connectorFromCHRow(ctx context.Context, row map[string]interface{}, decryptToken bool) *opaConnector {
	if row == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
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
		key := "connector:" + id + ":token_ref"
		cryptoCtx := cryptoContextForConnector(c.OrganizationID, c.Scope, c.UserID, key)
		plain, scopedErr := decryptSecretScoped(ctx, cryptoCtx, ref)
		scopedOK := scopedErr == nil && plain != ""
		if !scopedOK {
			// Pre-scoped enc:v2 (admin/_legacy) or enc:v1 under OPA_CONNECTOR_SECRET.
			if p, e := decryptSecret(ref); e == nil && p != "" {
				plain = p
			} else if p, e := legacyDecryptSecret(ref); e == nil && p != "" {
				plain = p
			}
		}
		if plain != "" {
			c.TokenRef = plain
			if !scopedOK {
				persistConnector(c)
			} else if enc, ok, reErr := maybeReencryptSecret(ctx, cryptoCtx, ref); reErr == nil && ok && enc != ref {
				persistConnector(c)
			}
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
// When org is unknown, status=pending_claim — no silent default-org fallback.
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
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	id := loadID("conn", "pending", "pending", "github_app", inst)
	c := &opaConnector{
		ID: id, OrganizationID: "", ProjectID: "", Scope: credScopeOrg, UserID: "",
		Kind: "github_app", InstallationID: inst, AccountLogin: accountLogin, Status: "pending_claim",
		MetaJSON: `{"auto_provisioned":true,"pending_claim":true}`, CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(id, c)
	persistConnector(c)
	log.Printf("[INFO] provisioned github_app connector %s installation=%s account=%s status=pending_claim", id, inst, accountLogin)
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
		if ch == "ai_review" || ch == "ora:review" {
			hasAI = true
			break
		}
	}
	if !hasAI {
		checks = append(checks, "ora:review")
	}
	wr := upsertWatched(c.OrganizationID, c.ProjectID, c.ID, repo, "", true, checks, "auto", minSev, false, autoReq, minScore)
	log.Printf("[INFO] auto-watched %s on connector %s (checks=%v)", repo, c.ID, checks)
	return wr
}

func persistConnector(c *opaConnector) {
	if c == nil {
		return
	}
	syncConnectorToOAM(c)
	if writer == nil {
		return
	}
	tokenRef := ""
	if strings.TrimSpace(c.TokenRef) != "" {
		enc, err := persistTokenRefScoped(context.Background(), c.OrganizationID, c.Scope, c.UserID, c.ID, c.TokenRef)
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
		"link_group_id": wr.LinkGroupID, "github_hook_id": wr.GithubHookID,
		"webhook_secret_ref": wr.WebhookSecretRef, "webhook_mode": nz(wr.WebhookMode, "app"),
		"updated_at": wr.UpdatedAt,
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
	ensureWatchedRepoWebhookColumns()
	ensureAgentsTables()
	nBackfill := backfillLegacyTablesOnBoot()
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
			c := connectorFromCHRow(context.Background(), row, true)
			if c == nil || c.Status == "deleted" {
				continue
			}
			connectorLive.Store(c.ID, c)
			n++
		}
	}
	nLegacy := backfillLegacyConnectorsOnBoot()
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
	log.Printf("[INFO] SCM hydrate: %d connector(s), %d connector legacy backfill, %d table rows backfilled, %d watched repo(s) from ClickHouse; cursor_key_mem=%v org_cli_keys=%v org_wide_seeded=%d",
		n+nLegacy, nLegacy, nBackfill, nw, hasCursor, orgKeyHint, nWide)
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
