package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Unified AI provider settings (OpenAI-compatible, Anthropic-compatible, CLI Cursor).
// Secrets are AES-GCM encrypted in opa.scm_secrets (+ file mirror under scm-state).
//
// Credential scopes: admin (isolated) | org | user. Job resolution: user → org → fail closed.
// Process env API keys (CURSOR_API_KEY / OPA_OPENAI_API_KEY / OPA_ANTHROPIC_API_KEY) are NOT
// used as tenant fallbacks — they formerly acted as a shared admin pool.

const (
	aiSecretOpenAI     = "ai_openai_api_key"
	aiSecretAnthropic  = "ai_anthropic_api_key"
	aiSecretCLICursor  = scmCursorSecretKey // "cursor_api_key" — shared with legacy alias
	aiSettingsMetaKey  = "ai_settings_meta"
	aiProviderOpenAI   = "openai"
	aiProviderAnthropic = "anthropic"
	aiProviderCLICursor = "cli_cursor"
)

type aiHTTPProvider struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"base_url"`
	APIKey  string `json:"-"` // plaintext in memory only
	Model   string `json:"model"`
}

type aiCLIProvider struct {
	Enabled bool   `json:"enabled"`
	APIKey  string `json:"-"`
	Model   string `json:"model"`
	Bin     string `json:"bin"`
	Force   bool   `json:"force"`
}

type aiSettingsDoc struct {
	OrganizationID  string         `json:"organization_id"`
	ProjectID       string         `json:"project_id"`
	Scope           string         `json:"scope"`   // admin|org|user (write target / effective)
	UserID          string         `json:"user_id"` // set for user scope
	DefaultProvider string         `json:"default_provider"` // openai|anthropic|cli_cursor|auto
	OpenAI          aiHTTPProvider `json:"openai"`
	Anthropic       aiHTTPProvider `json:"anthropic"`
	CLICursor       aiCLIProvider  `json:"cli_cursor"`
	UpdatedAt       string         `json:"updated_at"`
	// KeySources records which scope supplied each API key (user|org|admin|"").
	KeySources map[string]string `json:"-"`
}

var (
	aiSettingsMu  sync.RWMutex
	aiSettingsMem aiSettingsDoc
	aiSettingsHydrated bool
)

func registerAIMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	_ = authView
	_ = authAdmin
	registerAISettingsAuth(mux, "/api/ai/settings", handleAISettings)
	registerAISettingsAuth(mux, "/api/ai/settings/test", handleAISettingsTest)
	registerAISettingsAuth(mux, "/api/ai/tasks", handleAITasks)
}

// registerAISettingsAuth: GET/HEAD viewer; mutating methods require at least viewer
// when auth is on (write-scope gates live in the handler).
func registerAISettingsAuth(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !authEnforced {
			h(w, r)
			return
		}
		AuthMiddleware(h, "viewer")(w, r)
	})
}

func handleAISettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		handleAISettingsGet(w, r)
	case http.MethodPut, http.MethodPost:
		handleAISettingsPut(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func aiSettingsFilePath() string {
	return filepath.Join(scmStateDir(), "ai-settings.json")
}

func defaultAISettingsDoc(org, proj string) aiSettingsDoc {
	return aiSettingsDoc{
		OrganizationID:  org,
		ProjectID:       proj,
		DefaultProvider: "auto",
		OpenAI: aiHTTPProvider{
			Enabled: false,
			BaseURL: envOr("OPA_OPENAI_BASE_URL", "https://api.openai.com/v1"),
			Model:   envOr("OPA_OPENAI_MODEL", "gpt-4o-mini"),
		},
		Anthropic: aiHTTPProvider{
			Enabled: false,
			BaseURL: envOr("OPA_ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
			Model:   envOr("OPA_ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
		},
		CLICursor: aiCLIProvider{
			Enabled: true,
			Model:   envOr("OPA_CURSOR_MODEL", "auto"),
			Bin:     envOr("OPA_CURSOR_AGENT_BIN", "agent"),
			Force:   envOr("OPA_CURSOR_AGENT_FORCE", "0") == "1",
		},
		UpdatedAt: time.Now().UTC().Format("2006-01-02 15:04:05.000"),
	}
}

func loadAISettingsLocked() aiSettingsDoc {
	if !aiSettingsHydrated {
		hydrateAISettingsFromFileLocked()
	}
	doc := aiSettingsMem
	applyAIEnvOverrides(&doc)
	return doc
}

func hydrateAISettingsFromFileLocked() {
	doc := defaultAISettingsDoc("", "")
	raw, err := os.ReadFile(aiSettingsFilePath())
	if err == nil && len(raw) > 0 {
		var fileDoc aiSettingsFileDoc
		if json.Unmarshal(raw, &fileDoc) == nil {
			doc.OrganizationID = fileDoc.OrganizationID
			doc.ProjectID = fileDoc.ProjectID
			doc.DefaultProvider = nz(fileDoc.DefaultProvider, "auto")
			doc.UpdatedAt = fileDoc.UpdatedAt
			doc.OpenAI.Enabled = fileDoc.OpenAI.Enabled
			doc.OpenAI.BaseURL = nz(fileDoc.OpenAI.BaseURL, doc.OpenAI.BaseURL)
			doc.OpenAI.Model = nz(fileDoc.OpenAI.Model, doc.OpenAI.Model)
			if fileDoc.OpenAI.APIKeyEnc != "" {
				if p, e := decryptSecret(fileDoc.OpenAI.APIKeyEnc); e == nil {
					doc.OpenAI.APIKey = p
				}
			}
			doc.Anthropic.Enabled = fileDoc.Anthropic.Enabled
			doc.Anthropic.BaseURL = nz(fileDoc.Anthropic.BaseURL, doc.Anthropic.BaseURL)
			doc.Anthropic.Model = nz(fileDoc.Anthropic.Model, doc.Anthropic.Model)
			if fileDoc.Anthropic.APIKeyEnc != "" {
				if p, e := decryptSecret(fileDoc.Anthropic.APIKeyEnc); e == nil {
					doc.Anthropic.APIKey = p
				}
			}
			doc.CLICursor.Enabled = fileDoc.CLICursor.Enabled
			doc.CLICursor.Force = fileDoc.CLICursor.Force
			doc.CLICursor.Model = nz(fileDoc.CLICursor.Model, doc.CLICursor.Model)
			doc.CLICursor.Bin = nz(fileDoc.CLICursor.Bin, doc.CLICursor.Bin)
			if fileDoc.CLICursor.APIKeyEnc != "" {
				if p, e := decryptSecret(fileDoc.CLICursor.APIKeyEnc); e == nil {
					doc.CLICursor.APIKey = p
				}
			}
		}
	}
	if cursorKeyMem != "" && doc.CLICursor.APIKey == "" {
		doc.CLICursor.APIKey = cursorKeyMem
		doc.OrganizationID = nz(doc.OrganizationID, cursorKeyOrg)
		doc.ProjectID = nz(doc.ProjectID, cursorKeyProj)
	}
	if doc.CLICursor.APIKey != "" {
		cursorKeyMem = doc.CLICursor.APIKey
		cursorKeyOrg, cursorKeyProj = doc.OrganizationID, doc.ProjectID
	}
	applyAIEnvOverrides(&doc)
	aiSettingsMem = doc
	aiSettingsHydrated = true
}

func loadAISettingsFromFileOnBoot() {
	aiSettingsMu.Lock()
	defer aiSettingsMu.Unlock()
	hydrateAISettingsFromFileLocked()
}

// File-mirror shapes (secrets as api_key_enc).
type aiHTTPProviderFile struct {
	Enabled   bool   `json:"enabled"`
	BaseURL   string `json:"base_url"`
	APIKeyEnc string `json:"api_key_enc,omitempty"`
	Model     string `json:"model"`
}

type aiCLIProviderFile struct {
	Enabled   bool   `json:"enabled"`
	APIKeyEnc string `json:"api_key_enc,omitempty"`
	Model     string `json:"model"`
	Bin       string `json:"bin"`
	Force     bool   `json:"force"`
}

type aiSettingsFileDoc struct {
	OrganizationID  string             `json:"organization_id"`
	ProjectID       string             `json:"project_id"`
	DefaultProvider string             `json:"default_provider"`
	OpenAI          aiHTTPProviderFile `json:"openai"`
	Anthropic       aiHTTPProviderFile `json:"anthropic"`
	CLICursor       aiCLIProviderFile  `json:"cli_cursor"`
	UpdatedAt       string             `json:"updated_at"`
}

func applyAIEnvOverrides(doc *aiSettingsDoc) {
	// Non-secret defaults only. Process-wide API key env vars are intentionally
	// ignored — they used to act as a shared admin pool for every tenant job.
	if u := strings.TrimSpace(os.Getenv("OPA_OPENAI_BASE_URL")); u != "" {
		doc.OpenAI.BaseURL = u
	}
	if m := strings.TrimSpace(os.Getenv("OPA_OPENAI_MODEL")); m != "" {
		doc.OpenAI.Model = m
	}
	if u := strings.TrimSpace(os.Getenv("OPA_ANTHROPIC_BASE_URL")); u != "" {
		doc.Anthropic.BaseURL = u
	}
	if m := strings.TrimSpace(os.Getenv("OPA_ANTHROPIC_MODEL")); m != "" {
		doc.Anthropic.Model = m
	}
	if b := strings.TrimSpace(os.Getenv("OPA_CURSOR_AGENT_BIN")); b != "" {
		doc.CLICursor.Bin = b
	}
	if m := strings.TrimSpace(os.Getenv("OPA_CURSOR_MODEL")); m != "" {
		doc.CLICursor.Model = m
	}
	if os.Getenv("OPA_CURSOR_AGENT_FORCE") == "1" {
		doc.CLICursor.Force = true
	}
}

// getAISettings loads non-secret defaults then overlays scoped secrets.
// Legacy signature: org-only inheritance (no user layer). Prefer getAISettingsFor.
func getAISettings(org, proj string) aiSettingsDoc {
	return getAISettingsFor(credResolveQuery{OrganizationID: org, ProjectID: proj})
}

func getAISettingsFor(q credResolveQuery) aiSettingsDoc {
	aiSettingsMu.Lock()
	defer aiSettingsMu.Unlock()
	doc := loadAISettingsLocked()
	// Strip any keys that came from the legacy file mirror — secrets must come
	// from scoped CH resolution so admin file keys never leak to org/user jobs.
	doc.OpenAI.APIKey = ""
	doc.Anthropic.APIKey = ""
	doc.CLICursor.APIKey = ""
	doc.KeySources = map[string]string{}
	if q.WantAdminOnly {
		doc.Scope = credScopeAdmin
		doc.OrganizationID, doc.ProjectID, doc.UserID = "", "", ""
	} else {
		doc.OrganizationID = q.OrganizationID
		doc.ProjectID = q.ProjectID
		doc.UserID = q.UserID
		doc.Scope = credScopeOrg
		if q.UserID != "" {
			doc.Scope = credScopeUser
		}
	}
	hydrateAISecretsFromCHLocked(q, &doc)
	return doc
}

func hydrateAISecretsFromCHLocked(q credResolveQuery, doc *aiSettingsDoc) {
	if queryClient == nil {
		applyAIEnvOverrides(doc)
		return
	}
	applySecret := func(logicalKey string, set func(plain, scope string)) {
		h := resolveSCMSecret(q, logicalKey)
		if h.Plain != "" {
			set(h.Plain, h.Scope)
		}
	}
	applySecret(aiSecretOpenAI, func(plain, scope string) {
		doc.OpenAI.APIKey = plain
		doc.KeySources["openai"] = scope
	})
	applySecret(aiSecretAnthropic, func(plain, scope string) {
		doc.Anthropic.APIKey = plain
		doc.KeySources["anthropic"] = scope
	})
	applySecret(aiSecretCLICursor, func(plain, scope string) {
		doc.CLICursor.APIKey = plain
		doc.KeySources["cli_cursor"] = scope
	})
	// Meta: prefer same inheritance (user → org); admin-only when WantAdminOnly.
	if meta := resolveSCMSecret(q, aiSettingsMetaKey).Plain; meta != "" {
		var m aiSettingsFileDoc
		if json.Unmarshal([]byte(meta), &m) == nil {
			if m.DefaultProvider != "" {
				doc.DefaultProvider = m.DefaultProvider
			}
			doc.OpenAI.Enabled = m.OpenAI.Enabled
			if m.OpenAI.BaseURL != "" {
				doc.OpenAI.BaseURL = m.OpenAI.BaseURL
			}
			if m.OpenAI.Model != "" {
				doc.OpenAI.Model = m.OpenAI.Model
			}
			doc.Anthropic.Enabled = m.Anthropic.Enabled
			if m.Anthropic.BaseURL != "" {
				doc.Anthropic.BaseURL = m.Anthropic.BaseURL
			}
			if m.Anthropic.Model != "" {
				doc.Anthropic.Model = m.Anthropic.Model
			}
			doc.CLICursor.Enabled = m.CLICursor.Enabled
			doc.CLICursor.Force = m.CLICursor.Force
			if m.CLICursor.Model != "" {
				doc.CLICursor.Model = m.CLICursor.Model
			}
			if m.CLICursor.Bin != "" {
				doc.CLICursor.Bin = m.CLICursor.Bin
			}
		}
	}
	applyAIEnvOverrides(doc)
}

func persistAISettings(doc aiSettingsDoc) error {
	doc.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	scope := inferLegacyScope(doc.OrganizationID, doc.Scope)
	org, proj, userID := doc.OrganizationID, doc.ProjectID, doc.UserID
	if scope == credScopeAdmin {
		org, proj, userID = "", "", ""
	}

	aiSettingsMu.Lock()
	aiSettingsMem = doc
	aiSettingsHydrated = true
	if scope == credScopeAdmin && doc.CLICursor.APIKey != "" {
		cursorKeyMem = doc.CLICursor.APIKey
		cursorKeyOrg, cursorKeyProj = org, proj
	}
	aiSettingsMu.Unlock()

	// File mirror is admin-bootstrap only — never write org/user keys to a global file.
	if scope == credScopeAdmin {
		if err := persistAISettingsFile(doc); err != nil {
			log.Printf("[WARN] ai-settings file: %v", err)
		}
	}
	if doc.OpenAI.APIKey != "" {
		_ = persistSCMSecretScoped(org, proj, scope, userID, aiSecretOpenAI, doc.OpenAI.APIKey, false)
	}
	if doc.Anthropic.APIKey != "" {
		_ = persistSCMSecretScoped(org, proj, scope, userID, aiSecretAnthropic, doc.Anthropic.APIKey, false)
	}
	if doc.CLICursor.APIKey != "" {
		_ = persistSCMSecretScoped(org, proj, scope, userID, aiSecretCLICursor, doc.CLICursor.APIKey, false)
		// Webhook SCM jobs have empty ActorUserID and only resolve org keys.
		// Personal-only saves historically left reviews skipped with
		// "OPA Review API key not set". Seed org (+ org-wide) when missing.
		seedOrgCLICursorKeyForWebhooks(org, proj, scope, doc.CLICursor.APIKey)
	}
	meta := aiSettingsFileDoc{
		OrganizationID:  org,
		ProjectID:       proj,
		DefaultProvider: doc.DefaultProvider,
		OpenAI:          aiHTTPProviderFile{Enabled: doc.OpenAI.Enabled, BaseURL: doc.OpenAI.BaseURL, Model: doc.OpenAI.Model},
		Anthropic:       aiHTTPProviderFile{Enabled: doc.Anthropic.Enabled, BaseURL: doc.Anthropic.BaseURL, Model: doc.Anthropic.Model},
		CLICursor:       aiCLIProviderFile{Enabled: doc.CLICursor.Enabled, Model: doc.CLICursor.Model, Bin: doc.CLICursor.Bin, Force: doc.CLICursor.Force},
		UpdatedAt:       doc.UpdatedAt,
	}
	metaRaw, _ := json.Marshal(meta)
	_ = persistSCMSecretScoped(org, proj, scope, userID, aiSettingsMetaKey, string(metaRaw), false)
	return nil
}

func persistAISettingsFile(doc aiSettingsDoc) error {
	if err := ensureSCMStateDirs(); err != nil {
		return err
	}
	encKey := func(plain string) string {
		if plain == "" {
			return ""
		}
		e, err := encryptSecret(plain)
		if err != nil {
			return ""
		}
		return e
	}
	fileDoc := aiSettingsFileDoc{
		OrganizationID:  doc.OrganizationID,
		ProjectID:       doc.ProjectID,
		DefaultProvider: doc.DefaultProvider,
		OpenAI: aiHTTPProviderFile{
			Enabled: doc.OpenAI.Enabled, BaseURL: doc.OpenAI.BaseURL,
			APIKeyEnc: encKey(doc.OpenAI.APIKey), Model: doc.OpenAI.Model,
		},
		Anthropic: aiHTTPProviderFile{
			Enabled: doc.Anthropic.Enabled, BaseURL: doc.Anthropic.BaseURL,
			APIKeyEnc: encKey(doc.Anthropic.APIKey), Model: doc.Anthropic.Model,
		},
		CLICursor: aiCLIProviderFile{
			Enabled: doc.CLICursor.Enabled, APIKeyEnc: encKey(doc.CLICursor.APIKey),
			Model: doc.CLICursor.Model, Bin: doc.CLICursor.Bin, Force: doc.CLICursor.Force,
		},
		UpdatedAt: doc.UpdatedAt,
	}
	raw, err := json.MarshalIndent(fileDoc, "", "  ")
	if err != nil {
		return err
	}
	path := aiSettingsFilePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func redactAISettings(doc aiSettingsDoc) map[string]interface{} {
	src := doc.KeySources
	if src == nil {
		src = map[string]string{}
	}
	keyInfo := func(set bool, source string) map[string]interface{} {
		inherited := source == credScopeOrg && doc.Scope == credScopeUser
		return map[string]interface{}{
			"api_key_set": set,
			"key_scope":   source,
			"inherited":   inherited,
			"env_override": false, // process env API keys are no longer used
		}
	}
	openSet := doc.OpenAI.APIKey != ""
	anthSet := doc.Anthropic.APIKey != ""
	cliSet := doc.CLICursor.APIKey != ""
	return map[string]interface{}{
		"organization_id":  doc.OrganizationID,
		"project_id":       doc.ProjectID,
		"scope":            nz(doc.Scope, credScopeOrg),
		"user_id":          doc.UserID,
		"default_provider": nz(doc.DefaultProvider, "auto"),
		"openai": mergeMaps(map[string]interface{}{
			"enabled":  doc.OpenAI.Enabled,
			"base_url": doc.OpenAI.BaseURL,
			"model":    doc.OpenAI.Model,
		}, keyInfo(openSet, src["openai"])),
		"anthropic": mergeMaps(map[string]interface{}{
			"enabled":  doc.Anthropic.Enabled,
			"base_url": doc.Anthropic.BaseURL,
			"model":    doc.Anthropic.Model,
		}, keyInfo(anthSet, src["anthropic"])),
		"cli_cursor": mergeMaps(map[string]interface{}{
			"enabled": doc.CLICursor.Enabled,
			"model":   doc.CLICursor.Model,
			"bin":     doc.CLICursor.Bin,
			"force":   doc.CLICursor.Force,
			"label":   "CLI agent (Cursor)",
		}, keyInfo(cliSet, src["cli_cursor"])),
		"updated_at": doc.UpdatedAt,
		"inheritance": map[string]interface{}{
			"order":           []string{credScopeUser, credScopeOrg},
			"admin_isolated":  true,
			"env_keys_unused": true,
		},
		"routing": map[string]interface{}{
			"dashboard_tasks":  "auto: CLI agent (if key) → OpenAI → Anthropic; or explicit default_provider",
			"opa_review":       "cli_cursor first, HTTP fallback if CLI unavailable",
			"context_generate": "always CLI agent (user → org key); ignores default_provider",
		},
		"honesty": "API keys are AES-GCM encrypted (never returned). Resolution: user → org → fail closed. Admin keys are never inherited. Process env API keys are not used as tenant fallbacks.",
	}
}

func mergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func aiResolveQueryFromRequest(r *http.Request, writeScope string) (credResolveQuery, credActor, string, error) {
	a := actorFromRequest(r)
	scope, err := normalizeCredScope(writeScope, a)
	if err != nil {
		return credResolveQuery{}, a, "", err
	}
	// Explicit ?scope= on GET selects the view; empty → effective inheritance for actor.
	if writeScope == "" && r.Method != http.MethodPut && r.Method != http.MethodPost {
		q := r.URL.Query().Get("scope")
		if q != "" {
			scope, err = normalizeCredScope(q, a)
			if err != nil {
				return credResolveQuery{}, a, "", err
			}
		} else {
			// Default GET: show effective settings (user override → org), never admin.
			if a.isAdmin() && a.OrganizationID == "" && r.URL.Query().Get("admin") == "1" {
				scope = credScopeAdmin
			} else if a.Username != "" {
				scope = credScopeUser // resolve still inherits org when user has no key
			} else {
				scope = credScopeOrg
			}
		}
	}
	if err := canWriteCredScope(a, scope); err != nil && (r.Method == http.MethodPut || r.Method == http.MethodPost) {
		return credResolveQuery{}, a, scope, err
	}
	// Visibility: non-admins must not read admin scope.
	if scope == credScopeAdmin && !a.isAdmin() {
		return credResolveQuery{}, a, scope, fmt.Errorf("forbidden")
	}
	// Org scope requires a selected org — never fall through to default-org for strangers.
	if scope == credScopeOrg && a.OrganizationID == "" {
		return credResolveQuery{}, a, scope, fmt.Errorf("org scope requires X-Organization-ID")
	}
	// User secrets are owner-only; resolveCredTarget already binds to a.Username.
	if scope == credScopeUser && a.Username == "" && authEnforced {
		return credResolveQuery{}, a, scope, fmt.Errorf("user scope requires authenticated username")
	}
	org, proj, userID := resolveCredTarget(a, scope)
	q := credResolveQuery{
		OrganizationID: org,
		ProjectID:      proj,
		UserID:         userID,
		WantAdminOnly:  scope == credScopeAdmin,
	}
	// For effective user view, keep UserID so inheritance can prefer personal keys.
	if scope == credScopeUser {
		q.UserID = nz(userID, a.Username)
	}
	if scope == credScopeOrg {
		q.UserID = "" // org view/edit: do not mix in personal overrides
	}
	return q, a, scope, nil
}

func handleAISettingsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", 405)
		return
	}
	q, a, scope, err := aiResolveQueryFromRequest(r, r.URL.Query().Get("scope"))
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	_ = a
	doc := getAISettingsFor(q)
	doc.Scope = scope
	if scope == credScopeUser {
		doc.UserID = q.UserID
	}
	// Also report whether a personal override exists vs pure org inheritance.
	out := redactAISettings(doc)
	out["can_edit_org"] = a.isAdmin() && a.OrganizationID != ""
	out["can_edit_admin"] = a.isAdmin()
	out["can_edit_user"] = a.Username != "" || !authEnforced
	writeJSON(w, out)
}

func handleAISettingsPut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if refuseOAMLocalWrite(w) {
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		Scope           string `json:"scope"`
		DefaultProvider string `json:"default_provider"`
		OpenAI          *struct {
			Enabled  *bool  `json:"enabled"`
			BaseURL  string `json:"base_url"`
			Model    string `json:"model"`
			APIKey   string `json:"api_key"`
			ClearKey bool   `json:"clear_key"`
		} `json:"openai"`
		Anthropic *struct {
			Enabled  *bool  `json:"enabled"`
			BaseURL  string `json:"base_url"`
			Model    string `json:"model"`
			APIKey   string `json:"api_key"`
			ClearKey bool   `json:"clear_key"`
		} `json:"anthropic"`
		CLICursor *struct {
			Enabled  *bool  `json:"enabled"`
			Model    string `json:"model"`
			Bin      string `json:"bin"`
			Force    *bool  `json:"force"`
			APIKey   string `json:"api_key"`
			ClearKey bool   `json:"clear_key"`
		} `json:"cli_cursor"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	q, a, scope, err := aiResolveQueryFromRequest(r, body.Scope)
	if err != nil {
		code := 403
		if strings.Contains(err.Error(), "invalid scope") || strings.Contains(err.Error(), "requires") {
			code = 400
		}
		http.Error(w, err.Error(), code)
		return
	}
	doc := getAISettingsFor(q)
	doc.Scope = scope
	doc.OrganizationID = q.OrganizationID
	doc.ProjectID = q.ProjectID
	doc.UserID = q.UserID
	if body.DefaultProvider != "" {
		switch body.DefaultProvider {
		case "auto", aiProviderOpenAI, aiProviderAnthropic, aiProviderCLICursor:
			doc.DefaultProvider = body.DefaultProvider
		default:
			http.Error(w, "invalid default_provider", 400)
			return
		}
	}
	clearAt := func(logical string) {
		_ = persistSCMSecretScoped(q.OrganizationID, q.ProjectID, scope, q.UserID, logical, "", true)
	}
	if body.OpenAI != nil {
		if body.OpenAI.Enabled != nil {
			doc.OpenAI.Enabled = *body.OpenAI.Enabled
		}
		if body.OpenAI.BaseURL != "" {
			doc.OpenAI.BaseURL = strings.TrimRight(strings.TrimSpace(body.OpenAI.BaseURL), "/")
		}
		if body.OpenAI.Model != "" {
			doc.OpenAI.Model = strings.TrimSpace(body.OpenAI.Model)
		}
		if body.OpenAI.ClearKey {
			doc.OpenAI.APIKey = ""
			clearAt(aiSecretOpenAI)
		} else if strings.TrimSpace(body.OpenAI.APIKey) != "" {
			doc.OpenAI.APIKey = strings.TrimSpace(body.OpenAI.APIKey)
		}
	}
	if body.Anthropic != nil {
		if body.Anthropic.Enabled != nil {
			doc.Anthropic.Enabled = *body.Anthropic.Enabled
		}
		if body.Anthropic.BaseURL != "" {
			doc.Anthropic.BaseURL = strings.TrimRight(strings.TrimSpace(body.Anthropic.BaseURL), "/")
		}
		if body.Anthropic.Model != "" {
			doc.Anthropic.Model = strings.TrimSpace(body.Anthropic.Model)
		}
		if body.Anthropic.ClearKey {
			doc.Anthropic.APIKey = ""
			clearAt(aiSecretAnthropic)
		} else if strings.TrimSpace(body.Anthropic.APIKey) != "" {
			doc.Anthropic.APIKey = strings.TrimSpace(body.Anthropic.APIKey)
		}
	}
	if body.CLICursor != nil {
		if body.CLICursor.Enabled != nil {
			doc.CLICursor.Enabled = *body.CLICursor.Enabled
		}
		if body.CLICursor.Model != "" {
			doc.CLICursor.Model = strings.TrimSpace(body.CLICursor.Model)
		}
		if body.CLICursor.Bin != "" {
			bin := strings.TrimSpace(body.CLICursor.Bin)
			role := strings.TrimSpace(r.Header.Get("X-User-Role"))
			if authEnforced && !hasPermission(role, "admin") {
				http.Error(w, "forbidden: cli_cursor.bin requires admin", 403)
				return
			}
			if err := validateAgentBin(bin); err != nil {
				http.Error(w, "invalid cli_cursor.bin: "+err.Error(), 400)
				return
			}
			doc.CLICursor.Bin = bin
		}
		if body.CLICursor.Force != nil {
			doc.CLICursor.Force = *body.CLICursor.Force
		}
		if body.CLICursor.ClearKey {
			doc.CLICursor.APIKey = ""
			if scope == credScopeAdmin {
				cursorKeyMu.Lock()
				cursorKeyMem = ""
				cursorKeyOrg, cursorKeyProj = "", ""
				cursorKeyMu.Unlock()
			}
			clearAt(aiSecretCLICursor)
		} else if strings.TrimSpace(body.CLICursor.APIKey) != "" {
			doc.CLICursor.APIKey = strings.TrimSpace(body.CLICursor.APIKey)
		}
	}
	_ = a
	if err := persistAISettings(doc); err != nil {
		http.Error(w, "failed to persist AI settings", 500)
		return
	}
	fresh := getAISettingsFor(q)
	fresh.Scope = scope
	fresh.UserID = q.UserID
	writeJSON(w, map[string]interface{}{"ok": true, "settings": redactAISettings(fresh)})
}

func handleAISettingsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var body struct {
		Provider string `json:"provider"` // openai|anthropic|cli_cursor
		Scope    string `json:"scope"`
		// Optional draft key from the settings form — used for Test without Save.
		// Never persisted by this endpoint.
		APIKey string `json:"api_key"`
	}
	_ = json.Unmarshal(raw, &body)
	provider := strings.TrimSpace(body.Provider)
	if provider == "" {
		provider = aiProviderOpenAI
	}
	draftKey := strings.TrimSpace(body.APIKey)
	q, _, scope, err := aiResolveQueryFromRequest(r, body.Scope)
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	doc := getAISettingsFor(q)
	doc.Scope = scope
	// Overlay draft key onto the provider under test (same resolution as jobs
	// once saved; draft lets the UI Test before Save).
	if draftKey != "" {
		switch provider {
		case aiProviderOpenAI:
			doc.OpenAI.APIKey = draftKey
		case aiProviderAnthropic:
			doc.Anthropic.APIKey = draftKey
		case aiProviderCLICursor:
			doc.CLICursor.APIKey = draftKey
		}
	}

	missingKeyMsg := func(label string) string {
		return label + " api key not configured for this scope — save a key first, or paste one in the form and Test"
	}

	reqCtx := r.Context()
	var text, model string
	switch provider {
	case aiProviderOpenAI:
		if doc.OpenAI.APIKey == "" {
			http.Error(w, missingKeyMsg("openai"), 400)
			return
		}
		res, e := completeOpenAI(reqCtx, doc, aiCompleteRequest{
			System: "Reply with the single word pong.",
			Prompt: "ping",
			MaxTokens: 16,
		})
		err, text, model = e, "", doc.OpenAI.Model
		if res != nil {
			text, model = res.Text, res.Model
		}
	case aiProviderAnthropic:
		if doc.Anthropic.APIKey == "" {
			http.Error(w, missingKeyMsg("anthropic"), 400)
			return
		}
		res, e := completeAnthropic(reqCtx, doc, aiCompleteRequest{
			System: "Reply with the single word pong.",
			Prompt: "ping",
			MaxTokens: 16,
		})
		err, text, model = e, "", doc.Anthropic.Model
		if res != nil {
			text, model = res.Text, res.Model
		}
	case aiProviderCLICursor:
		if doc.CLICursor.APIKey == "" {
			http.Error(w, missingKeyMsg("cli agent"), 400)
			return
		}
		res, e := completeCLI(reqCtx, doc, aiCompleteRequest{
			Prompt: "Reply with the single word pong. No other output.",
			MaxTokens: 32,
		})
		err, text, model = e, "", doc.CLICursor.Model
		if res != nil {
			text, model = res.Text, res.Model
		}
	default:
		http.Error(w, "unknown provider", 400)
		return
	}
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"ok": false, "provider": provider, "scope": scope, "model": model, "error": err.Error(),
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "provider": provider, "scope": scope, "model": model, "text": truncateStr(text, 200),
	})
}

// seedOrgCLICursorKeyForWebhooks copies a freshly saved CLI agent key to org
// scope when webhooks would otherwise fail closed.
//
// Resolution for jobs is user → org → empty. Manual runs may carry ActorUserID
// (personal key works); GitHub webhooks do not — they need an org key.
// Additionally, project-scoped org keys fall back only to org-wide (empty
// project), not to sibling projects — so we seed org-wide when missing.
func seedOrgCLICursorKeyForWebhooks(org, proj, scope, plaintext string) {
	plaintext = strings.TrimSpace(plaintext)
	org = strings.TrimSpace(org)
	if plaintext == "" || org == "" || scope == credScopeAdmin {
		return
	}
	if scope != credScopeUser && scope != credScopeOrg {
		return
	}
	// Project-scoped org row (needed when only a personal key was saved).
	if scope == credScopeUser {
		if resolveSCMSecret(credResolveQuery{OrganizationID: org, ProjectID: proj}, aiSecretCLICursor).Plain == "" {
			if err := persistSCMSecretScoped(org, proj, credScopeOrg, "", aiSecretCLICursor, plaintext, false); err != nil {
				log.Printf("[WARN] seed org CLI key for %s/%s: %v", org, proj, err)
			} else {
				log.Printf("[INFO] seeded org CLI agent key for %s/%s from personal save (webhooks need org keys)", org, nz(proj, "(org-wide)"))
			}
		}
	}
	// Org-wide fallback so any project in the org can resolve the key.
	if loadSCMSecretAtScope(org, "", credScopeOrg, "", aiSecretCLICursor).Plain == "" {
		if err := persistSCMSecretScoped(org, "", credScopeOrg, "", aiSecretCLICursor, plaintext, false); err != nil {
			log.Printf("[WARN] seed org-wide CLI key for %s: %v", org, err)
		} else {
			log.Printf("[INFO] seeded org-wide CLI agent key for org=%s (cross-project + webhook fallback)", org)
		}
	}
}

// setCLICursorKeyFromAlias updates unified settings from legacy cursor-key endpoint (org scope).
func setCLICursorKeyFromAlias(org, proj, key string, clear bool) error {
	doc := getAISettingsFor(credResolveQuery{OrganizationID: org, ProjectID: proj})
	doc.OrganizationID = org
	doc.ProjectID = proj
	doc.Scope = credScopeOrg
	doc.UserID = ""
	if clear {
		doc.CLICursor.APIKey = ""
		_ = persistSCMSecretScoped(org, proj, credScopeOrg, "", aiSecretCLICursor, "", true)
	} else {
		doc.CLICursor.APIKey = key
		doc.CLICursor.Enabled = true
	}
	return persistAISettings(doc)
}
