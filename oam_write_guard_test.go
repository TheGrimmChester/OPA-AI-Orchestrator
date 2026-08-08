package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalOAMWritesBlocked(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "")
	if localOAMWritesBlocked() {
		t.Fatal("expected open when OAM unset")
	}
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	if !localOAMWritesBlocked() {
		t.Fatal("expected blocked when OAM configured")
	}
}

func TestRefuseOAMLocalWrite(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/github/pat", nil)
	if !refuseOAMLocalWrite(rr, req) {
		t.Fatal("expected refuse")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestCursorKeySetRefusedWhenOAM(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	req := httptest.NewRequest(http.MethodPost, "/api/scm/settings/cursor-key", strings.NewReader(`{"api_key":"sk-test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-Organization-ID", "nas")
	rr := httptest.NewRecorder()
	handleCursorKeySet(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", rr.Code, rr.Body.String())
	}
}

func TestRefuseOAMLocalWriteAllowsPeerContext(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	rr := httptest.NewRecorder()
	req := withPeerOAMWrite(httptest.NewRequest(http.MethodPost, "/api/internal/connectors/github/pat", nil))
	if refuseOAMLocalWrite(rr, req) {
		t.Fatal("peer OAM write context must bypass refuse")
	}
}

func TestPersistSCMSecretBlockedWhenOAM(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	if err := persistSCMSecretScoped("org", "proj", credScopeOrg, "", "key", "val", false); err == nil {
		t.Fatal("expected error when OAM is credential home")
	}
}

func TestConnectorClaimRefusedWhenOAM(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	conn := &opaConnector{
		ID: "conn-claim-oam-refuse", Kind: "github_app", Status: "pending_claim",
		Scope: credScopeOrg, MetaJSON: `{"pending_claim":true,"claim_nonce_hash":"abcd"}`,
	}
	connectorLive.Store(conn.ID, conn)
	defer connectorLive.Delete(conn.ID)

	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+conn.ID+"/claim", strings.NewReader(`{"claim_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-Organization-ID", "nas")
	rr := httptest.NewRecorder()
	handleConnectorClaim(rr, req, conn.ID)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 body=%s", rr.Code, rr.Body.String())
	}
}
