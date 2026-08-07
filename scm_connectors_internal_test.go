package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

func TestInternalConnectorPATBypassesOAMGuard(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "internal-conn-test-secret-32b!!")
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	secret := []byte("internal-conn-test-secret-32b!!")
	tok, err := openauth.MintServiceJWTWithOrg(secret, "oam-api", "ora-api", serviceScopeConnectorsWrite, "org-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"token":"ghp_test_token_for_unit","login":"alice","scope":"user"}`
	req := httptest.NewRequest(http.MethodPost, "/api/internal/connectors/github/pat", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerDelegatedUsername, "alice")
	req.Header.Set(headerDelegatedRole, "editor")
	req.Header.Set(headerDelegatedAccountType, openauth.AccountTypePersonal)
	req.Header.Set("X-Organization-ID", "org-a")
	req.Header.Set("X-Project-ID", "p1")

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerInternalConnectorsMux(mux)
	mux.ServeHTTP(rr, req)
	if rr.Code == http.StatusServiceUnavailable {
		t.Fatalf("internal PAT must not hit credentials_home_oam: %s", rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	conn, _ := out["connector"].(map[string]interface{})
	if conn == nil || conn["id"] == "" {
		t.Fatalf("expected connector in response: %v", out)
	}
	id, _ := conn["id"].(string)
	connectorLive.Delete(id)
}

func TestInternalConnectorReposDelegatesPersonal(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "internal-conn-test-secret-32b!!")
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	c := &opaConnector{
		ID: "conn-personal-repos", Kind: "github_app", Status: "active",
		Scope: credScopeUser, UserID: "solo", OrganizationID: "",
		InstallationID: "inst-personal-1", AccountLogin: "solo",
	}
	connectorLive.Store(c.ID, c)
	defer connectorLive.Delete(c.ID)

	secret := []byte("internal-conn-test-secret-32b!!")
	tok, err := openauth.MintServiceJWTWithOrg(secret, "oam-api", "ora-api", serviceScopeConnectorsWrite, "default-org", 0)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/internal/connectors/"+c.ID+"/repos", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(headerDelegatedUsername, "solo")
	req.Header.Set(headerDelegatedRole, "editor")
	req.Header.Set(headerDelegatedAccountType, openauth.AccountTypePersonal)

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerInternalConnectorsMux(mux)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	repos, _ := out["repos"].([]interface{})
	if repos == nil {
		t.Fatalf("expected repos array: %v", out)
	}
}

func TestInternalConnectorRejectsNonOAMIssuer(t *testing.T) {
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "internal-conn-test-secret-32b!!")
	secret := []byte("internal-conn-test-secret-32b!!")
	tok, err := openauth.MintServiceJWTWithOrg(secret, "opm-api", "ora-api", serviceScopeConnectorsWrite, "org-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/internal/connectors/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerInternalConnectorsMux(mux)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", rr.Code, rr.Body.String())
	}
}

func TestBrowserPATStillRefusedWhenOAM(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/github/pat", strings.NewReader(`{"token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleGitHubPATConnect(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rr.Code)
	}
}
