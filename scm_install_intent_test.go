package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRememberAndConsumeInstallIntent(t *testing.T) {
	installIntentMu.Lock()
	installIntents = map[string]installIntent{}
	installIntentMu.Unlock()

	rememberInstallIntent("", "default-project", "alice", true)
	intent, ok := peekInstallIntent("alice", "", true)
	if !ok || intent.UserID != "alice" || intent.OrgID != "" {
		t.Fatalf("personal intent: %+v ok=%v", intent, ok)
	}
	_, ok = consumeInstallIntent("alice", "", true)
	if !ok {
		t.Fatal("expected consume")
	}
	if _, ok := peekInstallIntent("alice", "", true); ok {
		t.Fatal("intent should be gone after consume")
	}
}

func TestFinishInstallByInstallationID(t *testing.T) {
	prevAuth := authEnforced
	authEnforced = false
	defer func() { authEnforced = prevAuth }()
	t.Setenv("PEER_OAM_URL", "")

	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	c := &opaConnector{
		ID: "conn-finish-1", Kind: "github_app", InstallationID: "999001",
		AccountLogin: "AcmeGH", Status: "pending_claim", Scope: credScopeOrg,
		MetaJSON:  `{"pending_claim":true,"claim_nonce_hash":"abcd","auto_provisioned":true}`,
		CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(c.ID, c)
	t.Cleanup(func() { connectorLive.Delete(c.ID) })

	body, _ := json.Marshal(map[string]string{"installation_id": "999001"})
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/github/finish-install", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Username", "alice")
	req.Header.Set("X-User-Role", "viewer")
	req.Header.Set("X-Organization-ID", "nas")
	req.Header.Set("X-Project-ID", "infra")
	rr := httptest.NewRecorder()
	handleGitHubFinishInstall(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	conn, _ := out["connector"].(map[string]interface{})
	if conn["status"] != "active" || conn["organization_id"] != "nas" {
		t.Fatalf("expected active nas binder: %+v", conn)
	}
	live, _ := connectorLive.Load(c.ID)
	got := live.(*opaConnector)
	if got.Status != "active" || got.OrganizationID != "nas" || got.UserID != "alice" {
		t.Fatalf("live not activated: %+v", got)
	}
}
