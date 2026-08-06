package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

func TestBuildSCMEventEnvelopePR(t *testing.T) {
	rec := &scmWebhookReceipt{
		ID: "wh1", Event: "pull_request", Action: "opened",
		RepoFullName: "acme/app", PRNumber: 7, CommitSHA: "abc123",
		OrganizationID: "nas", ProjectID: "infra", ConnectorID: "conn1",
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"action": "opened",
		"pull_request": map[string]interface{}{
			"added":    []string{"package-lock.json"},
			"modified": []string{"src/main.go"},
		},
	})
	wr := &opaWatchedRepo{ChecksJSON: `["ora:review","osa:dependencies"]`}
	env := buildSCMEventEnvelope(rec, nil, wr, raw, "pull_request")
	if env.EventType != "pull_request.opened" {
		t.Fatalf("event_type=%q", env.EventType)
	}
	if len(env.ChangedPaths) != 2 {
		t.Fatalf("changed_paths=%v", env.ChangedPaths)
	}
	if !wantsORAReview(env.Checks) {
		t.Fatalf("checks=%v", env.Checks)
	}
}

func TestResolveSCMTenantPending(t *testing.T) {
	wr := &opaWatchedRepo{OrganizationID: "", ProjectID: ""}
	conn := &opaConnector{OrganizationID: "", Status: "active"}
	tenant := resolveSCMTenant(wr, conn)
	if !tenant.PendingTenant {
		t.Fatalf("expected pending tenant, got %+v", tenant)
	}
	if !scmTenantBlocksJob(tenant) {
		t.Fatal("pending tenant should block jobs")
	}
}

func TestResolveSCMTenantPendingClaim(t *testing.T) {
	conn := &opaConnector{Status: "pending_claim"}
	tenant := resolveSCMTenant(nil, conn)
	if !tenant.PendingClaim || !scmTenantBlocksJob(tenant) {
		t.Fatalf("expected pending_claim block, got %+v", tenant)
	}
}

func TestVerifyRepoWebhookSignature(t *testing.T) {
	secret := "super-secret-repo-hook"
	body := []byte(`{"zen":"test"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	enc, err := encryptSecret(secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	wr := &opaWatchedRepo{WebhookSecretRef: enc, WebhookMode: "repo"}
	if !verifyRepoWebhookSignature(wr, body, sig) {
		t.Fatal("expected valid per-repo signature")
	}
	if verifyRepoWebhookSignature(wr, body, "sha256=deadbeef") {
		t.Fatal("expected invalid signature")
	}
}

func TestFanOutSCMEventToPeers(t *testing.T) {
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-fanout-secret-32bytes-min!!")
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/peer/scm/events" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		gotBody = raw
		writeJSON(w, map[string]interface{}{
			"checkers": []map[string]interface{}{
				{"id": "dependencies", "check_run_name": "OSA Dependencies", "should_run": true, "reason": "lockfile"},
			},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("PEER_OPL_URL", "")
	t.Setenv("PEER_OPM_URL", "")

	env := &scmEventEnvelope{
		ID: "env1", EventType: "pull_request.opened", OrganizationID: "nas", ProjectID: "infra",
		RepoFullName: "acme/app", CommitSHA: "sha1", Checks: []string{"osa:dependencies"},
	}
	responses := fanOutSCMEventToPeers(t.Context(), env)
	if len(gotBody) == 0 {
		t.Fatal("peer did not receive envelope")
	}
	if len(responses["osa"].Checkers) != 1 {
		t.Fatalf("responses=%+v", responses)
	}
	decls := aggregatePeerCheckersWithProduct(responses, env.Checks)
	if len(decls) != 1 || decls[0].Product != "osa" {
		t.Fatalf("decls=%+v", decls)
	}
}

func TestFanOutSCMEventToMultiplePeers(t *testing.T) {
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-fanout-secret-32bytes-min!!")
	hits := map[string]int{}
	peerHandler := func(product string, checkerID string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/peer/scm/events" {
				http.NotFound(w, r)
				return
			}
			hits[product]++
			var env scmEventEnvelope
			_ = json.NewDecoder(r.Body).Decode(&env)
			if env.CommitSHA == "" || env.OrganizationID != "nas" {
				t.Errorf("%s: unexpected envelope commit_sha=%q org=%q", product, env.CommitSHA, env.OrganizationID)
			}
			writeJSON(w, map[string]interface{}{
				"checkers": []map[string]interface{}{
					{"id": checkerID, "check_run_name": product + " / " + checkerID, "should_run": product == "osa", "reason": "test"},
				},
			})
		}
	}
	osaSrv := httptest.NewServer(peerHandler("osa", "dependencies"))
	oplSrv := httptest.NewServer(peerHandler("opl", "perf-gate"))
	opmSrv := httptest.NewServer(peerHandler("opm", "delivery"))
	defer osaSrv.Close()
	defer oplSrv.Close()
	defer opmSrv.Close()

	t.Setenv("PEER_OSA_URL", osaSrv.URL)
	t.Setenv("PEER_OPL_URL", oplSrv.URL)
	t.Setenv("PEER_OPM_URL", opmSrv.URL)

	env := &scmEventEnvelope{
		ID: "env-multi", EventType: "pull_request.opened", OrganizationID: "nas", ProjectID: "infra",
		RepoFullName: "acme/app", CommitSHA: "sha-multi",
		Checks: []string{"osa:dependencies", "opl:perf-gate", "opm:delivery"},
	}
	responses := fanOutSCMEventToPeers(t.Context(), env)
	for _, product := range []string{"osa", "opl", "opm"} {
		if hits[product] != 1 {
			t.Fatalf("peer %s hit count=%d", product, hits[product])
		}
		if len(responses[product].Checkers) != 1 {
			t.Fatalf("%s responses=%+v", product, responses[product])
		}
	}
	decls := aggregatePeerCheckersWithProduct(responses, env.Checks)
	if len(decls) != 3 {
		t.Fatalf("expected 3 aggregated checkers, got %+v", decls)
	}
	shouldRun := 0
	for _, d := range decls {
		if d.ShouldRun {
			shouldRun++
		}
	}
	if shouldRun != 1 {
		t.Fatalf("expected only osa checker should_run, got %+v", decls)
	}
}

func TestPendingClaimBlocksPRWebhook(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	t.Setenv("OPA_SCM_ALLOW_UNSIGNED", "1")
	t.Setenv("OPA_GITHUB_WEBHOOK_SECRET", "")

	now := "2026-01-01 00:00:00.000"
	conn := &opaConnector{
		ID: "conn-pending", Kind: "github_app", InstallationID: "99", Status: "pending_claim",
		OrganizationID: "", ProjectID: "",
		CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(conn.ID, conn)
	wr := &opaWatchedRepo{
		ID: "w-pending", ConnectorID: conn.ID, RepoFullName: "acme/pending",
		Enabled: true, ChecksJSON: `["ora:review"]`, UpdatedAt: now,
	}
	watchedLive.Store(conn.ID+"|acme/pending", wr)

	payload := map[string]interface{}{
		"action": "opened",
		"number": 1,
		"pull_request": map[string]interface{}{
			"number": 1, "title": "t", "head": map[string]string{"sha": "deadbeef"},
		},
		"repository":   map[string]string{"full_name": "acme/pending"},
		"installation": map[string]interface{}{"id": 99},
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/scm/github/webhook", bytes.NewReader(raw))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "pending-claim-test")
	rr := httptest.NewRecorder()
	handleGitHubWebhook(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["skipped"] != "pending_claim" && out["skipped"] != "pending_tenant" {
		t.Fatalf("expected pending block, got %v", out)
	}
}

func TestMintAndParseInstallState(t *testing.T) {
	t.Setenv("OPA_GITHUB_INSTALL_STATE_SECRET", "install-state-secret-32bytes!!")
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "")
	state, err := mintGitHubInstallState("nas", "infra", "alice")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseGitHubInstallState(state)
	if err != nil || parsed.OrganizationID != "nas" || parsed.ProjectID != "infra" {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
}

func TestConnectorClaimSuccess(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()
	t.Setenv("PEER_OAM_URL", "")

	raw, hash, err := mintConnectorClaimNonce()
	if err != nil {
		t.Fatal(err)
	}
	now := "2026-01-01 00:00:00.000"
	conn := &opaConnector{
		ID: "conn-claim-ok", Kind: "github_app", InstallationID: "42",
		Status: "pending_claim", OrganizationID: "", ProjectID: "",
		Scope: credScopeOrg, MetaJSON: fmt.Sprintf(`{"pending_claim":true,"auto_provisioned":true,"claim_nonce_hash":%q}`, hash),
		CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(conn.ID, conn)
	defer connectorLive.Delete(conn.ID)

	wr := &opaWatchedRepo{
		ID: "w-claim", ConnectorID: conn.ID, RepoFullName: "acme/app",
		OrganizationID: "", ProjectID: "", Enabled: true, UpdatedAt: now,
	}
	watchedLive.Store(conn.ID+"|acme/app", wr)
	defer watchedLive.Delete(conn.ID + "|acme/app")

	body, _ := json.Marshal(map[string]string{"claim_token": raw})
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+conn.ID+"/claim", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-User-Username", "alice")
	req.Header.Set("X-Organization-ID", "nas")
	req.Header.Set("X-Project-ID", "infra")
	rr := httptest.NewRecorder()
	handleConnectorClaim(rr, req, conn.ID)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	cPub, _ := out["connector"].(map[string]interface{})
	if cPub["status"] != "active" || cPub["organization_id"] != "nas" || cPub["project_id"] != "infra" {
		t.Fatalf("connector=%v", cPub)
	}
	live := getConnector(conn.ID)
	if live == nil || live.Status != "active" {
		t.Fatalf("live=%+v", live)
	}
	meta := parseConnectorMeta(live.MetaJSON)
	if _, ok := meta["pending_claim"]; ok {
		t.Fatalf("pending_claim meta still set: %v", meta)
	}
	if _, ok := meta["claim_nonce_hash"]; ok {
		t.Fatalf("claim_nonce_hash still set: %v", meta)
	}
	tenant := resolveSCMTenant(wr, live)
	if scmTenantBlocksJob(tenant) || tenant.OrganizationID != "nas" {
		t.Fatalf("tenant after claim=%+v", tenant)
	}
	if wr.OrganizationID != "nas" || wr.ProjectID != "infra" {
		t.Fatalf("watched not stamped: %+v", wr)
	}

	// Double claim → 409
	body2, _ := json.Marshal(map[string]string{"claim_token": raw})
	req2 := httptest.NewRequest(http.MethodPost, "/api/connectors/"+conn.ID+"/claim", strings.NewReader(string(body2)))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-User-Role", "admin")
	req2.Header.Set("X-Organization-ID", "nas")
	req2.Header.Set("X-Project-ID", "infra")
	rr2 := httptest.NewRecorder()
	handleConnectorClaim(rr2, req2, conn.ID)
	if rr2.Code != http.StatusConflict {
		t.Fatalf("double claim status %d body %s", rr2.Code, rr2.Body.String())
	}
}

func TestConnectorClaimRejectsWrongNonce(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()
	t.Setenv("PEER_OAM_URL", "")

	_, hash, err := mintConnectorClaimNonce()
	if err != nil {
		t.Fatal(err)
	}
	conn := &opaConnector{
		ID: "conn-claim-bad-nonce", Kind: "github_app", Status: "pending_claim",
		Scope: credScopeOrg, MetaJSON: fmt.Sprintf(`{"pending_claim":true,"claim_nonce_hash":%q}`, hash),
	}
	connectorLive.Store(conn.ID, conn)
	defer connectorLive.Delete(conn.ID)

	body, _ := json.Marshal(map[string]string{"claim_token": "deadbeef"})
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+conn.ID+"/claim", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-Organization-ID", "nas")
	req.Header.Set("X-Project-ID", "infra")
	rr := httptest.NewRecorder()
	handleConnectorClaim(rr, req, conn.ID)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
}

func TestConnectorClaimRejectsNotPending(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()
	t.Setenv("PEER_OAM_URL", "")

	conn := &opaConnector{
		ID: "conn-claim-active", Kind: "github_app", Status: "active",
		OrganizationID: "nas", ProjectID: "infra", Scope: credScopeOrg,
	}
	connectorLive.Store(conn.ID, conn)
	defer connectorLive.Delete(conn.ID)

	body, _ := json.Marshal(map[string]string{"claim_token": "irrelevant"})
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+conn.ID+"/claim", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-Organization-ID", "nas")
	req.Header.Set("X-Project-ID", "infra")
	rr := httptest.NewRecorder()
	handleConnectorClaim(rr, req, conn.ID)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
}

func TestConnectorClaimRejectsUnauthorized(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()
	t.Setenv("PEER_OAM_URL", "")

	raw, hash, err := mintConnectorClaimNonce()
	if err != nil {
		t.Fatal(err)
	}
	conn := &opaConnector{
		ID: "conn-claim-forbidden", Kind: "github_app", Status: "pending_claim",
		Scope: credScopeOrg, MetaJSON: fmt.Sprintf(`{"pending_claim":true,"claim_nonce_hash":%q}`, hash),
	}
	connectorLive.Store(conn.ID, conn)
	defer connectorLive.Delete(conn.ID)

	body, _ := json.Marshal(map[string]string{"claim_token": raw})
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+conn.ID+"/claim", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "viewer")
	req.Header.Set("X-User-Username", "bob")
	req.Header.Set("X-Organization-ID", "nas")
	req.Header.Set("X-Project-ID", "infra")
	rr := httptest.NewRecorder()
	handleConnectorClaim(rr, req, conn.ID)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
}

func TestConnectorClaimRejectsPersonalAccount(t *testing.T) {
	prevAuth := authEnforced
	prevSecret := jwtSecret
	authEnforced = true
	jwtSecret = []byte("claim-personal-test-secret")
	defer func() {
		authEnforced = prevAuth
		jwtSecret = prevSecret
	}()
	t.Setenv("PEER_OAM_URL", "")

	raw, hash, err := mintConnectorClaimNonce()
	if err != nil {
		t.Fatal(err)
	}
	conn := &opaConnector{
		ID: "conn-claim-personal", Kind: "github_app", Status: "pending_claim",
		Scope: credScopeOrg, MetaJSON: fmt.Sprintf(`{"pending_claim":true,"claim_nonce_hash":%q}`, hash),
	}
	connectorLive.Store(conn.ID, conn)
	defer connectorLive.Delete(conn.ID)

	tok, err := openauth.MintUserJWTWithAccount(jwtSecret, "alice", "admin", "ora-api",
		openauth.AccountTypePersonal, "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"claim_token": raw})
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+conn.ID+"/claim", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-Organization-ID", "nas")
	rr := httptest.NewRecorder()
	handleConnectorClaim(rr, req, conn.ID)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
}

func TestPeerResolveConnectorFailClosed(t *testing.T) {
	active := &opaConnector{
		ID: "peer-fc-active", OrganizationID: "org-a", Status: "active", Kind: "github_app",
	}
	pending := &opaConnector{
		ID: "peer-fc-pending", OrganizationID: "", Status: "pending_claim", Kind: "github_app",
	}
	emptyOrgActive := &opaConnector{
		ID: "peer-fc-empty-org", OrganizationID: "", Status: "active", Kind: "github_app",
	}
	connectorLive.Store(active.ID, active)
	connectorLive.Store(pending.ID, pending)
	connectorLive.Store(emptyOrgActive.ID, emptyOrgActive)
	defer connectorLive.Delete(active.ID)
	defer connectorLive.Delete(pending.ID)
	defer connectorLive.Delete(emptyOrgActive.ID)

	cases := []struct {
		name   string
		claims *peerSCMClaims
		id     string
		want   int
	}{
		{"ok", &peerSCMClaims{OrgID: "org-a"}, active.ID, 0},
		{"empty_claims_org", &peerSCMClaims{OrgID: ""}, active.ID, 403},
		{"wrong_org", &peerSCMClaims{OrgID: "org-b"}, active.ID, 403},
		{"pending", &peerSCMClaims{OrgID: "org-a"}, pending.ID, 403},
		{"empty_org_active", &peerSCMClaims{OrgID: "org-a"}, emptyOrgActive.ID, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			got := peerResolveConnector(rr, tc.claims, tc.id)
			if tc.want == 0 {
				if got == nil || got.ID != active.ID {
					t.Fatalf("want connector, got %+v status=%d body=%s", got, rr.Code, rr.Body.String())
				}
				return
			}
			if got != nil || rr.Code != tc.want {
				t.Fatalf("got conn=%v code=%d want code=%d body=%s", got, rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// Negative isolation: foreign org viewer must not list/get/mutate another org's connector.
func TestConnectorsForeignViewerIsolation(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()
	// Ensure patch/delete reach visibility checks (not OAM write-guard 503).
	t.Setenv("PEER_OAM_URL", "")

	own := &opaConnector{
		ID: "iso-own", Kind: "github_app", Status: "active",
		OrganizationID: "org-a", ProjectID: "p1", Scope: credScopeOrg,
	}
	foreign := &opaConnector{
		ID: "iso-foreign", Kind: "github_app", Status: "active",
		OrganizationID: "org-b", ProjectID: "p1", Scope: credScopeOrg,
	}
	pending := &opaConnector{
		ID: "iso-pending", Kind: "github_app", Status: "pending_claim",
		OrganizationID: "", Scope: credScopeOrg,
	}
	connectorLive.Store(own.ID, own)
	connectorLive.Store(foreign.ID, foreign)
	connectorLive.Store(pending.ID, pending)
	defer connectorLive.Delete(own.ID)
	defer connectorLive.Delete(foreign.ID)
	defer connectorLive.Delete(pending.ID)

	viewerReq := func(method, path, body string) *http.Request {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("X-User-Role", "viewer")
		r.Header.Set("X-User-Username", "alice")
		r.Header.Set("X-Organization-ID", "org-a")
		r.Header.Set("X-Project-ID", "p1")
		return r
	}

	// List: only own org active; foreign + pending omitted.
	rr := httptest.NewRecorder()
	handleConnectorsList(rr, viewerReq(http.MethodGet, "/api/connectors", ""))
	if rr.Code != 200 {
		t.Fatalf("list status %d body %s", rr.Code, rr.Body.String())
	}
	var listOut map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &listOut)
	raw, _ := listOut["connectors"].([]interface{})
	ids := map[string]bool{}
	for _, item := range raw {
		m, _ := item.(map[string]interface{})
		if id, _ := m["id"].(string); id != "" {
			ids[id] = true
		}
	}
	if !ids[own.ID] || ids[foreign.ID] || ids[pending.ID] {
		t.Fatalf("list ids=%v want only %s", ids, own.ID)
	}

	// Get foreign / pending → 404 (not found; no existence leak).
	for _, id := range []string{foreign.ID, pending.ID} {
		rr = httptest.NewRecorder()
		handleConnectorGet(rr, viewerReq(http.MethodGet, "/api/connectors/"+id, ""), id)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("get %s status %d want 404 body %s", id, rr.Code, rr.Body.String())
		}
	}

	// Patch / delete foreign → 404 (invisible before mutate check).
	rr = httptest.NewRecorder()
	handleConnectorPatch(rr, viewerReq(http.MethodPatch, "/api/connectors/"+foreign.ID, `{"display_name":"x"}`), foreign.ID)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("patch foreign status %d want 404 body %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	handleConnectorDelete(rr, viewerReq(http.MethodDelete, "/api/connectors/"+foreign.ID, ""), foreign.ID)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete foreign status %d want 404 body %s", rr.Code, rr.Body.String())
	}
}

func TestEnsureGitHubAppConnectorMintsClaimNonce(t *testing.T) {
	t.Setenv("OPA_GITHUB_APP_ID", "12345")
	t.Setenv("OPA_GITHUB_APP_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGFw=\n-----END RSA PRIVATE KEY-----")

	inst := "inst-ensure-" + fmt.Sprint(time.Now().UnixNano())
	c := ensureGitHubAppConnector(inst, "acme-bot")
	if c == nil {
		t.Fatal("expected connector")
	}
	defer connectorLive.Delete(c.ID)
	if c.Status != "pending_claim" {
		t.Fatalf("status=%s", c.Status)
	}
	meta := parseConnectorMeta(c.MetaJSON)
	if strings.TrimSpace(fmt.Sprint(meta["claim_nonce_hash"])) == "" {
		t.Fatalf("claim_nonce_hash missing: %v", meta)
	}
	// Idempotent: same installation returns same row and keeps hash.
	again := ensureGitHubAppConnector(inst, "acme-bot")
	if again == nil || again.ID != c.ID {
		t.Fatalf("again=%+v want id=%s", again, c.ID)
	}
}

func TestEnsureGitHubAppConnectorBackfillsHash(t *testing.T) {
	t.Setenv("OPA_GITHUB_APP_ID", "12345")
	t.Setenv("OPA_GITHUB_APP_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGFw=\n-----END RSA PRIVATE KEY-----")

	inst := "inst-backfill-" + fmt.Sprint(time.Now().UnixNano())
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	c := &opaConnector{
		ID: "conn-hashless", Kind: "github_app", InstallationID: inst,
		Status: "pending_claim", Scope: credScopeOrg,
		MetaJSON: `{"auto_provisioned":true,"pending_claim":true}`, CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(c.ID, c)
	defer connectorLive.Delete(c.ID)

	got := ensureGitHubAppConnector(inst, "acme")
	if got == nil || got.ID != c.ID {
		t.Fatalf("got=%+v", got)
	}
	meta := parseConnectorMeta(got.MetaJSON)
	if strings.TrimSpace(fmt.Sprint(meta["claim_nonce_hash"])) == "" {
		t.Fatalf("expected backfilled claim_nonce_hash: %v", meta)
	}
}

func TestConnectorReposForeignReturns404(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	foreign := &opaConnector{
		ID: "repos-foreign", Kind: "github_app", Status: "active",
		OrganizationID: "org-b", ProjectID: "p1", Scope: credScopeOrg,
	}
	pending := &opaConnector{
		ID: "repos-pending", Kind: "github_app", Status: "pending_claim",
		OrganizationID: "", Scope: credScopeOrg,
	}
	connectorLive.Store(foreign.ID, foreign)
	connectorLive.Store(pending.ID, pending)
	defer connectorLive.Delete(foreign.ID)
	defer connectorLive.Delete(pending.ID)

	for _, id := range []string{foreign.ID, pending.ID} {
		req := httptest.NewRequest(http.MethodGet, "/api/connectors/"+id+"/repos", nil)
		req.Header.Set("X-User-Role", "viewer")
		req.Header.Set("X-User-Username", "alice")
		req.Header.Set("X-Organization-ID", "org-a")
		req.Header.Set("X-Project-ID", "p1")
		rr := httptest.NewRecorder()
		handleConnectorRepos(rr, req, id)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("repos %s status %d want 404 body %s", id, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "org-b") || strings.Contains(rr.Body.String(), "organization_id") {
			t.Fatalf("repos body leaked org: %s", rr.Body.String())
		}
	}
}

func TestIssueClaimTokenRemints(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	inst := "inst-remint-" + fmt.Sprint(time.Now().UnixNano())
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	rawPrior, oldHash, err := mintConnectorClaimNonce()
	if err != nil {
		t.Fatal(err)
	}
	c := &opaConnector{
		ID: "conn-remint", Kind: "github_app", InstallationID: inst,
		Status: "pending_claim", Scope: credScopeOrg,
		MetaJSON: fmt.Sprintf(`{"pending_claim":true,"claim_nonce_hash":%q}`, oldHash),
		CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(c.ID, c)
	defer connectorLive.Delete(c.ID)

	body, _ := json.Marshal(map[string]interface{}{
		"installation_id": inst, "force": true, "prior_claim_token": rawPrior,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/github/issue-claim-token", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-User-Username", "alice")
	req.Header.Set("X-Organization-ID", "nas")
	req.Header.Set("X-Project-ID", "infra")
	rr := httptest.NewRecorder()
	handleIssueClaimToken(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	raw, _ := out["claim_token"].(string)
	if raw == "" || !strings.Contains(fmt.Sprint(out["claim_url"]), "/connectors?") {
		t.Fatalf("claim_url missing /connectors: %v", out)
	}
	if !strings.Contains(fmt.Sprint(out["claim_url"]), "#claim_token=") {
		t.Fatalf("out=%v", out)
	}
	live := getConnector(c.ID)
	meta := parseConnectorMeta(live.MetaJSON)
	newHash := strings.TrimSpace(fmt.Sprint(meta["claim_nonce_hash"]))
	if newHash == "" || newHash == oldHash {
		t.Fatalf("hash not reminted: old=%s new=%s", oldHash, newHash)
	}
	sum := sha256.Sum256([]byte(raw))
	if hex.EncodeToString(sum[:]) != newHash {
		t.Fatalf("returned token does not match stored hash")
	}
}

func TestFindConnectorByInstallationPrefersActive(t *testing.T) {
	inst := "inst-pref-" + fmt.Sprint(time.Now().UnixNano())
	pending := &opaConnector{ID: "f-pending", InstallationID: inst, Status: "pending_claim"}
	active := &opaConnector{ID: "f-active", InstallationID: inst, Status: "active", OrganizationID: "nas"}
	connectorLive.Store(pending.ID, pending)
	connectorLive.Store(active.ID, active)
	defer connectorLive.Delete(pending.ID)
	defer connectorLive.Delete(active.ID)

	got := findConnectorByInstallation(inst)
	if got == nil || got.ID != active.ID {
		t.Fatalf("got=%+v want active", got)
	}
}

func TestGitHubCallbackDoesNotResetActive(t *testing.T) {
	t.Setenv("OPA_DASHBOARD_URL", "http://dash.test")
	t.Setenv("OPA_GITHUB_INSTALL_STATE_SECRET", "callback-protect-secret-32bytes!!")
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "")

	inst := "inst-protect-" + fmt.Sprint(time.Now().UnixNano())
	active := &opaConnector{
		ID: "conn-active-protect", Kind: "github_app", InstallationID: inst,
		Status: "active", OrganizationID: "nas", ProjectID: "infra", Scope: credScopeOrg,
	}
	connectorLive.Store(active.ID, active)
	defer connectorLive.Delete(active.ID)

	// Orphan-style callback (no state) must not demote active → pending_claim.
	req := httptest.NewRequest(http.MethodGet, "/api/connectors/github/callback?installation_id="+inst, nil)
	rr := httptest.NewRecorder()
	handleGitHubCallback(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	live := getConnector(active.ID)
	if live == nil || live.Status != "active" || live.OrganizationID != "nas" {
		t.Fatalf("active was mutated: %+v", live)
	}
	loc := rr.Header().Get("Location")
	if strings.Contains(loc, "claim_token") {
		t.Fatalf("must not remint claim_token over active: %s", loc)
	}

	// Stateful callback for a *different* org must also not overwrite.
	state, err := mintGitHubInstallState("other-org", "infra", "eve")
	if err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodGet,
		"/api/connectors/github/callback?installation_id="+inst+"&state="+url.QueryEscape(state), nil)
	rr2 := httptest.NewRecorder()
	handleGitHubCallback(rr2, req2)
	if rr2.Code != http.StatusFound {
		t.Fatalf("status %d", rr2.Code)
	}
	live = getConnector(active.ID)
	if live.Status != "active" || live.OrganizationID != "nas" {
		t.Fatalf("active overwritten by foreign state: %+v", live)
	}
	// No second active for same installation.
	var actives int
	connectorLive.Range(func(_, v interface{}) bool {
		c, _ := v.(*opaConnector)
		if c != nil && c.InstallationID == inst && c.Status == "active" {
			actives++
		}
		return true
	})
	if actives != 1 {
		t.Fatalf("actives=%d want 1", actives)
	}
}

func TestIssueClaimTokenRequiresForceWhenHashPresent(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	inst := "inst-noforce-" + fmt.Sprint(time.Now().UnixNano())
	_, hash, err := mintConnectorClaimNonce()
	if err != nil {
		t.Fatal(err)
	}
	c := &opaConnector{
		ID: "conn-noforce", Kind: "github_app", InstallationID: inst,
		Status: "pending_claim", Scope: credScopeOrg,
		MetaJSON: fmt.Sprintf(`{"pending_claim":true,"claim_nonce_hash":%q}`, hash),
	}
	connectorLive.Store(c.ID, c)
	defer connectorLive.Delete(c.ID)

	body, _ := json.Marshal(map[string]string{"installation_id": inst})
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/github/issue-claim-token", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-Organization-ID", "nas")
	rr := httptest.NewRecorder()
	handleIssueClaimToken(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status %d want 409 body %s", rr.Code, rr.Body.String())
	}
}

func TestFindWatchedSkipsDeletedConnector(t *testing.T) {
	repo := "acme/skip-deleted"
	del := &opaConnector{
		ID: "conn-del-watch", Kind: "github_app", InstallationID: "1",
		Status: "deleted", OrganizationID: "nas", Scope: credScopeOrg,
	}
	active := &opaConnector{
		ID: "conn-ok-watch", Kind: "github_pat", Status: "active",
		OrganizationID: "nas", ProjectID: "infra", Scope: credScopeOrg, TokenRef: "x",
	}
	connectorLive.Store(del.ID, del)
	connectorLive.Store(active.ID, active)
	defer connectorLive.Delete(del.ID)
	defer connectorLive.Delete(active.ID)

	wrDel := &opaWatchedRepo{ID: "w-del", ConnectorID: del.ID, RepoFullName: repo, Enabled: true, OrganizationID: "nas"}
	wrOK := &opaWatchedRepo{ID: "w-ok", ConnectorID: active.ID, RepoFullName: repo, Enabled: true, OrganizationID: "nas"}
	watchedLive.Store(del.ID+"|"+repo, wrDel)
	watchedLive.Store(active.ID+"|"+repo, wrOK)
	defer watchedLive.Delete(del.ID + "|" + repo)
	defer watchedLive.Delete(active.ID + "|" + repo)

	got, conn := findWatched(repo)
	if got == nil || got.ID != wrOK.ID || conn == nil || conn.ID != active.ID {
		t.Fatalf("got wr=%+v conn=%+v", got, conn)
	}
}

func TestGitHubCallbackActivatesPendingWithState(t *testing.T) {
	t.Setenv("OPA_DASHBOARD_URL", "http://dash.test")
	t.Setenv("OPA_GITHUB_INSTALL_STATE_SECRET", "callback-activate-secret-32bytes!")
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "")

	inst := "inst-activate-" + fmt.Sprint(time.Now().UnixNano())
	_, hash, err := mintConnectorClaimNonce()
	if err != nil {
		t.Fatal(err)
	}
	pending := &opaConnector{
		ID: "conn-pend-activate", Kind: "github_app", InstallationID: inst,
		Status: "pending_claim", Scope: credScopeOrg,
		MetaJSON: fmt.Sprintf(`{"pending_claim":true,"claim_nonce_hash":%q}`, hash),
	}
	connectorLive.Store(pending.ID, pending)
	defer connectorLive.Delete(pending.ID)

	state, err := mintGitHubInstallState("nas", "infra", "alice")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/api/connectors/github/callback?installation_id="+inst+"&state="+url.QueryEscape(state), nil)
	rr := httptest.NewRecorder()
	handleGitHubCallback(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	live := getConnector(pending.ID)
	if live == nil || live.Status != "active" || live.OrganizationID != "nas" {
		t.Fatalf("pending not activated in place: %+v", live)
	}
	meta := parseConnectorMeta(live.MetaJSON)
	if _, ok := meta["claim_nonce_hash"]; ok {
		t.Fatalf("nonce still present: %v", meta)
	}
}

func TestPublishCheckerResultCommitStatusFallback(t *testing.T) {
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	t.Setenv("OPA_SCM_SKIP_CHECK_RUNS", "1")
	conn := &opaConnector{Kind: "github_pat", TokenRef: "ghp_fake_token_for_mock_test_only"}
	_, mode, err := publishCheckerResult(conn, "o", "r", checkerPublishMeta{
		Key: "osa:dependencies", Name: "OSA Dependencies", SHA: "abc",
		Status: "completed", Conclusion: "success", Title: "ok", Summary: "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "commit_status" && mode != "check_run" {
		t.Fatalf("mode=%q", mode)
	}
}

func TestConnectorWebhookMode(t *testing.T) {
	if connectorWebhookMode(&opaConnector{Kind: "github_pat"}) != "repo" {
		t.Fatal("pat connector should use repo hooks")
	}
	if connectorWebhookMode(&opaConnector{Kind: "github_app"}) != "app" {
		t.Fatal("app connector should use app ingress")
	}
}

func TestParseWatchedPutItemsDashboardShape(t *testing.T) {
	raw := []byte(`{"watched":[{"repo_full_name":"acme/app","enabled":true,"checks_json":["ora:review","osa:dependencies"]}]}`)
	items, err := parseWatchedPutItems(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].RepoFullName != "acme/app" {
		t.Fatalf("items=%+v", items)
	}
	if len(items[0].Checks) != 2 || items[0].Checks[1] != "osa:dependencies" {
		t.Fatalf("checks=%v", items[0].Checks)
	}
}

func TestSyncConnectorToOAM(t *testing.T) {
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-oam-sync-secret-32bytes!!")
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/internal/connectors/sync" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		writeJSON(w, map[string]interface{}{"status": "ok"})
	}))
	defer srv.Close()
	t.Setenv("PEER_OAM_URL", srv.URL)

	c := &opaConnector{
		ID: "conn1", OrganizationID: "nas", ProjectID: "infra",
		Kind: "github_pat", AccountLogin: "acme-bot", Status: "active",
		Scope: credScopeOrg, MetaJSON: `{"display_name":"Acme PAT"}`,
	}
	syncConnectorToOAM(c)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got != nil && got["id"] == "conn1" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got == nil || got["webhook_mode"] != "repo" {
		t.Fatalf("sync body=%v", got)
	}
}
