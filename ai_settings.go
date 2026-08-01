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
// Env overrides (CURSOR_API_KEY, OPA_OPENAI_*, OPA_ANTHROPIC_*) win for single-tenant smoke.

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
	DefaultProvider string         `json:"default_provider"` // openai|anthropic|cli_cursor|auto
	OpenAI          aiHTTPProvider `json:"openai"`
	Anthropic       aiHTTPProvider `json:"anthropic"`
	CLICursor       aiCLIProvider  `json:"cli_cursor"`
	UpdatedAt       string         `json:"updated_at"`
}

var (
	aiSettingsMu  sync.RWMutex
	aiSettingsMem aiSettingsDoc
	aiSettingsHydrated bool
)

func registerAIMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	_ = authView
	// Method-aware: GET viewer, PUT/POST admin
	registerSCMAuthFlexible(mux, "/api/ai/settings", handleAISettings)
	authAdmin("/api/ai/settings/test", handleAISettingsTest)
	authAdmin("/api/ai/tasks", handleAITasks)
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
	if k := strings.TrimSpace(os.Getenv("CURSOR_API_KEY")); k != "" {
		doc.CLICursor.APIKey = k
	}
	if k := strings.TrimSpace(os.Getenv("OPA_OPENAI_API_KEY")); k != "" {
		doc.OpenAI.APIKey = k
		if !doc.OpenAI.Enabled {
			doc.OpenAI.Enabled = true
		}
	}
	if u := strings.TrimSpace(os.Getenv("OPA_OPENAI_BASE_URL")); u != "" {
		doc.OpenAI.BaseURL = u
	}
	if m := strings.TrimSpace(os.Getenv("OPA_OPENAI_MODEL")); m != "" {
		doc.OpenAI.Model = m
	}
	if k := strings.TrimSpace(os.Getenv("OPA_ANTHROPIC_API_KEY")); k != "" {
		doc.Anthropic.APIKey = k
		if !doc.Anthropic.Enabled {
			doc.Anthropic.Enabled = true
		}
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

func getAISettings(org, proj string) aiSettingsDoc {
	aiSettingsMu.Lock()
	defer aiSettingsMu.Unlock()
	doc := loadAISettingsLocked()
	if org != "" {
		doc.OrganizationID = nz(doc.OrganizationID, org)
	}
	if proj != "" {
		doc.ProjectID = nz(doc.ProjectID, proj)
	}
	hydrateAISecretsFromCHLocked(org, proj, &doc)
	return doc
}

func hydrateAISecretsFromCHLocked(org, proj string, doc *aiSettingsDoc) {
	if queryClient == nil {
		return
	}
	for _, key := range []string{aiSecretOpenAI, aiSecretAnthropic, aiSecretCLICursor} {
		if plain := loadSCMSecretPlain(org, proj, key); plain != "" {
			switch key {
			case aiSecretOpenAI:
				if doc.OpenAI.APIKey == "" {
					doc.OpenAI.APIKey = plain
				}
			case aiSecretAnthropic:
				if doc.Anthropic.APIKey == "" {
					doc.Anthropic.APIKey = plain
				}
			case aiSecretCLICursor:
				if doc.CLICursor.APIKey == "" {
					doc.CLICursor.APIKey = plain
				}
			}
		}
	}
	// Meta (enabled/urls/models) from CH when file missing pieces
	if meta := loadSCMSecretPlain(org, proj, aiSettingsMetaKey); meta != "" {
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
	aiSettingsMem = *doc
	applyAIEnvOverrides(doc)
}

func loadSCMSecretPlain(org, proj, key string) string {
	if queryClient == nil {
		return ""
	}
	q := fmt.Sprintf(`
		SELECT organization_id, project_id, ciphertext, deleted FROM opa.scm_secrets
		WHERE key = '%s'
		ORDER BY updated_at DESC LIMIT 20`, escapeSQL(key))
	rows, err := queryClient.Query(q)
	if err != nil || len(rows) == 0 {
		return ""
	}
	pick := func(wantOrg, wantProj string, allowAny bool) string {
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
			return plain
		}
		return ""
	}
	if org != "" {
		if p := pick(org, proj, false); p != "" {
			return p
		}
		if p := pick(org, "", false); p != "" {
			return p
		}
	}
	return pick("", "", true)
}

func persistAISettings(doc aiSettingsDoc) error {
	doc.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	aiSettingsMu.Lock()
	aiSettingsMem = doc
	aiSettingsHydrated = true
	// Keep legacy cursor memory in sync for OPA Review callers
	if doc.CLICursor.APIKey != "" {
		cursorKeyMem = doc.CLICursor.APIKey
		cursorKeyOrg, cursorKeyProj = doc.OrganizationID, doc.ProjectID
	}
	aiSettingsMu.Unlock()

	if err := persistAISettingsFile(doc); err != nil {
		log.Printf("[WARN] ai-settings file: %v", err)
	}
	org, proj := doc.OrganizationID, doc.ProjectID
	if doc.OpenAI.APIKey != "" {
		_ = persistSCMSecret(org, proj, aiSecretOpenAI, doc.OpenAI.APIKey, false)
	}
	if doc.Anthropic.APIKey != "" {
		_ = persistSCMSecret(org, proj, aiSecretAnthropic, doc.Anthropic.APIKey, false)
	}
	if doc.CLICursor.APIKey != "" {
		_ = persistSCMSecret(org, proj, aiSecretCLICursor, doc.CLICursor.APIKey, false)
	}
	// Meta JSON (non-secret) stored as plaintext-looking ciphertext encrypt of JSON
	meta := aiSettingsFileDoc{
		OrganizationID:  doc.OrganizationID,
		ProjectID:       doc.ProjectID,
		DefaultProvider: doc.DefaultProvider,
		OpenAI:          aiHTTPProviderFile{Enabled: doc.OpenAI.Enabled, BaseURL: doc.OpenAI.BaseURL, Model: doc.OpenAI.Model},
		Anthropic:       aiHTTPProviderFile{Enabled: doc.Anthropic.Enabled, BaseURL: doc.Anthropic.BaseURL, Model: doc.Anthropic.Model},
		CLICursor:       aiCLIProviderFile{Enabled: doc.CLICursor.Enabled, Model: doc.CLICursor.Model, Bin: doc.CLICursor.Bin, Force: doc.CLICursor.Force},
		UpdatedAt:       doc.UpdatedAt,
	}
	metaRaw, _ := json.Marshal(meta)
	_ = persistSCMSecret(org, proj, aiSettingsMetaKey, string(metaRaw), false)
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
	envOpenAI := strings.TrimSpace(os.Getenv("OPA_OPENAI_API_KEY")) != ""
	envAnthropic := strings.TrimSpace(os.Getenv("OPA_ANTHROPIC_API_KEY")) != ""
	envCursor := strings.TrimSpace(os.Getenv("CURSOR_API_KEY")) != ""
	return map[string]interface{}{
		"organization_id":  doc.OrganizationID,
		"project_id":       doc.ProjectID,
		"default_provider": nz(doc.DefaultProvider, "auto"),
		"openai": map[string]interface{}{
			"enabled":    doc.OpenAI.Enabled,
			"base_url":   doc.OpenAI.BaseURL,
			"model":      doc.OpenAI.Model,
			"api_key_set": doc.OpenAI.APIKey != "" || envOpenAI,
			"env_override": envOpenAI,
		},
		"anthropic": map[string]interface{}{
			"enabled":     doc.Anthropic.Enabled,
			"base_url":    doc.Anthropic.BaseURL,
			"model":       doc.Anthropic.Model,
			"api_key_set": doc.Anthropic.APIKey != "" || envAnthropic,
			"env_override": envAnthropic,
		},
		"cli_cursor": map[string]interface{}{
			"enabled":     doc.CLICursor.Enabled,
			"model":       doc.CLICursor.Model,
			"bin":         doc.CLICursor.Bin,
			"force":       doc.CLICursor.Force,
			"api_key_set": doc.CLICursor.APIKey != "" || envCursor,
			"env_override": envCursor,
			"label":       "CLI agent (Cursor)",
		},
		"updated_at": doc.UpdatedAt,
		"routing": map[string]interface{}{
			"dashboard_tasks": "openai then anthropic (or default_provider)",
			"opa_review":      "cli_cursor first, HTTP fallback if CLI unavailable",
		},
		"honesty": "API keys are AES-GCM encrypted (never returned). Env CURSOR_API_KEY / OPA_OPENAI_API_KEY / OPA_ANTHROPIC_API_KEY override stored keys for single-tenant smoke.",
	}
}

func handleAISettingsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", 405)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	doc := getAISettings(org, proj)
	writeJSON(w, redactAISettings(doc))
}

func handleAISettingsPut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		DefaultProvider string `json:"default_provider"`
		OpenAI          *struct {
			Enabled    *bool  `json:"enabled"`
			BaseURL    string `json:"base_url"`
			Model      string `json:"model"`
			APIKey     string `json:"api_key"`
			ClearKey   bool   `json:"clear_key"`
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
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	doc := getAISettings(org, proj)
	doc.OrganizationID = org
	doc.ProjectID = proj
	if body.DefaultProvider != "" {
		switch body.DefaultProvider {
		case "auto", aiProviderOpenAI, aiProviderAnthropic, aiProviderCLICursor:
			doc.DefaultProvider = body.DefaultProvider
		default:
			http.Error(w, "invalid default_provider", 400)
			return
		}
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
			_ = persistSCMSecret(org, proj, aiSecretOpenAI, "", true)
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
			_ = persistSCMSecret(org, proj, aiSecretAnthropic, "", true)
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
			doc.CLICursor.Bin = strings.TrimSpace(body.CLICursor.Bin)
		}
		if body.CLICursor.Force != nil {
			doc.CLICursor.Force = *body.CLICursor.Force
		}
		if body.CLICursor.ClearKey {
			doc.CLICursor.APIKey = ""
			cursorKeyMu.Lock()
			cursorKeyMem = ""
			cursorKeyOrg, cursorKeyProj = "", ""
			cursorKeyMu.Unlock()
			_ = persistSCMSecret(org, proj, aiSecretCLICursor, "", true)
		} else if strings.TrimSpace(body.CLICursor.APIKey) != "" {
			doc.CLICursor.APIKey = strings.TrimSpace(body.CLICursor.APIKey)
		}
	}
	if err := persistAISettings(doc); err != nil {
		http.Error(w, "failed to persist AI settings", 500)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "settings": redactAISettings(getAISettings(org, proj))})
}

func handleAISettingsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var body struct {
		Provider string `json:"provider"` // openai|anthropic|cli_cursor
	}
	_ = json.Unmarshal(raw, &body)
	provider := strings.TrimSpace(body.Provider)
	if provider == "" {
		provider = aiProviderOpenAI
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	doc := getAISettings(org, proj)

	reqCtx := r.Context()
	var err error
	var text, model string
	switch provider {
	case aiProviderOpenAI:
		if doc.OpenAI.APIKey == "" {
			http.Error(w, "openai api key not configured", 400)
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
			http.Error(w, "anthropic api key not configured", 400)
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
			http.Error(w, "cli agent api key not configured", 400)
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
			"ok": false, "provider": provider, "model": model, "error": err.Error(),
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "provider": provider, "model": model, "text": truncateStr(text, 200),
	})
}

// setCLICursorKeyFromAlias updates unified settings from legacy cursor-key endpoint.
func setCLICursorKeyFromAlias(org, proj, key string, clear bool) error {
	doc := getAISettings(org, proj)
	doc.OrganizationID = org
	doc.ProjectID = proj
	if clear {
		doc.CLICursor.APIKey = ""
		cursorKeyMu.Lock()
		cursorKeyMem = ""
		cursorKeyOrg, cursorKeyProj = "", ""
		cursorKeyMu.Unlock()
		// Must tombstone CH — persistAISettings skips empty keys and would leave the prior
		// ciphertext live (smoke was clearing via this path, then rehydrating the fake key).
		_ = persistSCMSecret(org, proj, aiSecretCLICursor, "", true)
	} else {
		doc.CLICursor.APIKey = key
		doc.CLICursor.Enabled = true
	}
	return persistAISettings(doc)
}
