package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "install-state-secret-32bytes!!")
	state, err := mintGitHubInstallState("nas", "infra", "alice")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseGitHubInstallState(state)
	if err != nil || parsed.OrganizationID != "nas" || parsed.ProjectID != "infra" {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
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
