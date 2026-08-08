package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentCatalogCoversORAKeys(t *testing.T) {
	want := map[string]bool{
		agentKeyReview: true, agentKeyAutoFix: true, agentKeyCloud: true,
		agentKeyContextGenerate: true, agentKeyIssueInvestigate: true, agentKeyIssueImplement: true,
	}
	for _, e := range agentCatalog() {
		if !want[e.AgentKey] {
			t.Fatalf("unexpected catalog key %q", e.AgentKey)
		}
		delete(want, e.AgentKey)
	}
	if len(want) != 0 {
		t.Fatalf("catalog missing keys: %v", want)
	}
	if agentKeyForTaskKind("opa_review") != agentKeyReview {
		t.Fatal("opa_review must map to review")
	}
	if agentKeyForTaskKind("context_generate") != agentKeyContextGenerate {
		t.Fatal("context_generate mapping")
	}
	if agentKeyForTaskKind("unknown_kind") != "" {
		t.Fatal("unknown kind must have no agent key")
	}
}

func TestAISettingsGoneWhenPeerOAM(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	mux := http.NewServeMux()
	registerAIMux(mux, func(p string, h http.HandlerFunc) { mux.HandleFunc(p, h) },
		func(p string, h http.HandlerFunc) { mux.HandleFunc(p, h) })

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/ai/settings"},
		{http.MethodPut, "/api/ai/settings"},
		{http.MethodPost, "/api/ai/settings/test"},
		{http.MethodGet, "/api/ai/settings/test"},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s: status=%d want 404 body=%s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
}

func TestAISettingsAvailableWhenPeerUnset(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "")
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ai/settings", nil)
	handleAISettings(rr, req)
	if rr.Code == http.StatusNotFound {
		t.Fatalf("solo path must not 404 settings: status=%d", rr.Code)
	}
}

func TestResolveCursorUsesOAMLease(t *testing.T) {
	var leaseHits, redeemHits int
	var sawProduct, sawAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/lease"):
			leaseHits++
			var body oamResolveRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			sawProduct, sawAgent = body.Product, body.AgentKey
			_ = json.NewEncoder(w).Encode(map[string]string{"lease_id": "L1"})
		case strings.HasSuffix(r.URL.Path, "/redeem"):
			redeemHits++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"api_key": "sk-test", "provider": "cli_cursor", "model": "auto", "agent_key_known": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("PEER_OAM_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-oam-lease-secret-32bytes-min!!")
	prevQC := queryClient
	queryClient = nil // family path must not need CH secrets
	defer func() { queryClient = prevQC }()

	key, _, model, _ := resolveCLICursorConfig(agentKeyReview, "org-a", "proj-a", "alice")
	if key != "sk-test" {
		t.Fatalf("key=%q want sk-test", key)
	}
	if model != "auto" {
		t.Fatalf("model=%q", model)
	}
	if leaseHits != 1 || redeemHits != 1 {
		t.Fatalf("lease=%d redeem=%d", leaseHits, redeemHits)
	}
	if sawProduct != "ora" || sawAgent != agentKeyReview {
		t.Fatalf("wire product=%q agent=%q", sawProduct, sawAgent)
	}
}

func TestResolveCursorEmptyLeaseFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/lease") {
			_ = json.NewEncoder(w).Encode(map[string]string{"lease_id": ""})
			return
		}
		http.Error(w, `{"error":"should_not_redeem"}`, 500)
	}))
	defer srv.Close()

	t.Setenv("PEER_OAM_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-oam-lease-secret-32bytes-min!!")
	prevQC := queryClient
	queryClient = nil
	defer func() { queryClient = prevQC }()

	key, _, _, _ := resolveCLICursorConfig(agentKeyReview, "org-a", "proj-a", "alice")
	if key != "" {
		t.Fatalf("empty lease_id must fail closed, got key=%q", key)
	}
}

func TestResolveCursorUnavailableFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"credential_unavailable"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("PEER_OAM_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-oam-lease-secret-32bytes-min!!")

	key := resolveCursorAPIKey(agentKeyAutoFix, "org-a", "proj-a", "")
	if key != "" {
		t.Fatalf("credential_unavailable must fail closed, got key=%q", key)
	}
}

func TestResolveCursorNoCHSecretLoadOnFamilyPath(t *testing.T) {
	var secretHits int
	// If hydrateAISecretsFromCHLocked ran, it would need queryClient — keep it nil
	// and ensure a successful lease path still works without loading secrets.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "scm_secrets") || strings.Contains(r.URL.Path, "clickhouse") {
			secretHits++
		}
		if strings.HasSuffix(r.URL.Path, "/lease") {
			_ = json.NewEncoder(w).Encode(map[string]string{"lease_id": "L2"})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/redeem") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"api_key": "sk-family", "provider": "cli_cursor", "model": "auto", "agent_key_known": true,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	t.Setenv("PEER_OAM_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-oam-lease-secret-32bytes-min!!")
	prevQC := queryClient
	queryClient = nil
	defer func() { queryClient = prevQC }()

	doc := getAISettingsFor(credResolveQuery{OrganizationID: "org-a", ProjectID: "proj-a", UserID: "alice"})
	if doc.CLICursor.APIKey != "" || doc.OpenAI.APIKey != "" || doc.Anthropic.APIKey != "" {
		t.Fatalf("family getAISettingsFor must not surface scm_secrets keys: %+v", doc.CLICursor)
	}
	key := resolveCursorAPIKey(agentKeyCloud, "org-a", "proj-a", "alice")
	if key != "sk-family" {
		t.Fatalf("key=%q", key)
	}
	if secretHits != 0 {
		t.Fatalf("secretHits=%d", secretHits)
	}
}

func TestPeerOAMUnsetUsesLocalPlane(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "")
	if oamConfigured() {
		t.Fatal("expected oamConfigured false")
	}
	// Without OAM and without local settings/CH, key stays empty — no invent-default.
	prevQC := queryClient
	queryClient = nil
	defer func() { queryClient = prevQC }()
	key := resolveCursorAPIKey(agentKeyReview, "org-a", "proj-a", "alice")
	if key != "" {
		t.Fatalf("solo without secrets must not invent a key: %q", key)
	}
	if !hasCLIAgentCredential("org-a", "proj-a", "alice") && key == "" {
		// hasCLIAgentCredential mirrors local key presence when peer unset
	}
	if hasCLIAgentCredential("org-a", "proj-a", "alice") {
		t.Fatal("hasCLIAgentCredential should be false without local key when peer unset")
	}
}

func TestOAMCredentialHomeMsgPointsAtEndpoints(t *testing.T) {
	if strings.Contains(oamCredentialHomeMsg, "/api/credentials") {
		t.Fatalf("message must cite /endpoints not /api/credentials: %s", oamCredentialHomeMsg)
	}
	if !strings.Contains(oamCredentialHomeMsg, "/endpoints") {
		t.Fatalf("message must mention /endpoints: %s", oamCredentialHomeMsg)
	}
}
