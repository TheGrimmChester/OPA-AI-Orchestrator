package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

const testPRSecret = "peer-pr-test-secret"

func prTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("OPEN_SERVICE_JWT_SECRET", testPRSecret)
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	mux := http.NewServeMux()
	registerPeerSCMPRMux(mux)
	return mux
}

func prTestConnector(t *testing.T, id string) *opaConnector {
	t.Helper()
	c := &opaConnector{
		ID: id, OrganizationID: "default-org", Kind: "github_app",
		InstallationID: "inst-1", Status: "active",
	}
	connectorLive.Store(c.ID, c)
	t.Cleanup(func() { connectorLive.Delete(c.ID) })
	return c
}

func prTestToken(t *testing.T, scope string) string {
	t.Helper()
	tok, err := openauth.MintServiceJWT([]byte(testPRSecret), "opm-api", "ora-api", scope)
	if err != nil {
		t.Fatalf("mint service jwt: %v", err)
	}
	return tok
}

func prTestPost(t *testing.T, mux *http.ServeMux, path, scope string, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	if scope != "" {
		req.Header.Set("Authorization", "Bearer "+prTestToken(t, scope))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The delivery surface must be reachable only with scm:pr — it is the only scope
// that can obtain a write-capable git credential or open a pull request.
//
// This is checked against every scope ORA already mints for OPM, including a
// token carrying all of them at once, because that combined token is the
// realistic one: holding the whole read/PM set must still not grant code writes.
func TestPeerDeliveryRequiresPRScope(t *testing.T) {
	mux := prTestMux(t)
	prTestConnector(t, "conn-scope")
	body := map[string]interface{}{
		"connector_id": "conn-scope", "repo_full_name": "acme/demo",
		"title": "Deliver", "head": "opm/task", "base": "main",
	}
	insufficient := map[string]string{
		"pm":            "scm:pm",
		"clone":         "scm:clone",
		"connectors":    "connectors:read",
		"health":        "health:read",
		"all_non_write": "connectors:read scm:clone scm:pm health:read",
	}
	for _, path := range []string{"/api/peer/scm/push-credentials", "/api/peer/scm/pull-requests/create"} {
		for name, scope := range insufficient {
			t.Run(path+"/refused_with_"+name, func(t *testing.T) {
				rec := prTestPost(t, mux, path, scope, body)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("scope %q must not reach %s: code=%d body=%s",
						scope, path, rec.Code, rec.Body.String())
				}
			})
		}
		t.Run(path+"/no_token_refused", func(t *testing.T) {
			rec := prTestPost(t, mux, path, "", body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("missing token must be 401 on %s: code=%d", path, rec.Code)
			}
		})
		t.Run(path+"/get_refused", func(t *testing.T) {
			// The surface is write-only: there is no read variant to reach, so a
			// non-POST is refused outright rather than falling back to a read scope.
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+prTestToken(t, peerPRScope))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("GET on %s must be 405, got %d", path, rec.Code)
			}
		})
		t.Run(path+"/pr_scope_allowed", func(t *testing.T) {
			rec := prTestPost(t, mux, path, peerPRScope, body)
			if rec.Code != http.StatusOK {
				t.Fatalf("scm:pr must be accepted on %s: code=%d body=%s", path, rec.Code, rec.Body.String())
			}
		})
		t.Run(path+"/pr_scope_alongside_others_allowed", func(t *testing.T) {
			rec := prTestPost(t, mux, path, "scm:pm "+peerPRScope, body)
			if rec.Code != http.StatusOK {
				t.Fatalf("a token that includes scm:pr must be accepted on %s: code=%d body=%s",
					path, rec.Code, rec.Body.String())
			}
		})
	}
}

// A service token minted for another audience must not be accepted, so an OSA or
// hub token cannot be replayed against the delivery surface.
func TestPeerDeliveryRejectsWrongAudience(t *testing.T) {
	mux := prTestMux(t)
	prTestConnector(t, "conn-aud")
	tok, err := openauth.MintServiceJWT([]byte(testPRSecret), "opm-api", "osa-api", peerPRScope)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"connector_id": "conn-aud", "repo_full_name": "acme/demo",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/peer/scm/push-credentials", strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-audience token must be 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// Push credentials must be Contents-write scoped and advertise an expiry, so the
// caller knows the token is request-scoped and cannot be cached.
func TestPeerPushCredentialsAreContentsWriteAndExpiring(t *testing.T) {
	mux := prTestMux(t)
	prTestConnector(t, "conn-push")
	rec := prTestPost(t, mux, "/api/peer/scm/push-credentials", peerPRScope, map[string]interface{}{
		"connector_id": "conn-push", "repo_full_name": "acme/demo",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if out["token"] == nil || out["token"] == "" {
		t.Fatal("no token returned")
	}
	if out["expires_at"] == nil || out["expires_at"] == "" {
		t.Fatal("push credential must advertise expires_at")
	}
	perms, ok := out["permissions"].(map[string]interface{})
	if !ok {
		t.Fatalf("permissions missing: %#v", out["permissions"])
	}
	if perms["contents"] != "write" {
		t.Fatalf("push credential must request contents write, got %#v", perms)
	}
	if _, hasWorkflows := perms["workflows"]; hasWorkflows {
		t.Fatal("push credential must never request workflows")
	}

	// A missing repo_full_name must be refused rather than minting a wide token.
	bad := prTestPost(t, mux, "/api/peer/scm/push-credentials", peerPRScope, map[string]interface{}{
		"connector_id": "conn-push",
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("blank repo must be 400, got %d", bad.Code)
	}
}

func TestPeerPullRequestCreateHappyPath(t *testing.T) {
	mux := prTestMux(t)
	prTestConnector(t, "conn-pr")
	rec := prTestPost(t, mux, "/api/peer/scm/pull-requests/create", peerPRScope, map[string]interface{}{
		"connector_id": "conn-pr", "repo_full_name": "acme/demo",
		"title": "Deliver task 001", "body": "notes", "head": "opm/001-x", "base": "main",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		OK             bool `json:"ok"`
		AlreadyExisted bool `json:"already_existed"`
		PullRequest    struct {
			Number  int    `json:"number"`
			HTMLURL string `json:"html_url"`
			HeadRef string `json:"head_ref"`
			BaseRef string `json:"base_ref"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if !out.OK || out.PullRequest.Number <= 0 {
		t.Fatalf("expected an opened PR with a number: %s", rec.Body.String())
	}
	if out.PullRequest.HeadRef != "opm/001-x" || out.PullRequest.BaseRef != "main" {
		t.Fatalf("head/base not echoed: %+v", out.PullRequest)
	}
	if !strings.Contains(out.PullRequest.HTMLURL, "/pull/") {
		t.Fatalf("html_url must point at the PR: %q", out.PullRequest.HTMLURL)
	}
}

func TestPeerPullRequestCreateRejectsSameBranch(t *testing.T) {
	mux := prTestMux(t)
	prTestConnector(t, "conn-same")
	rec := prTestPost(t, mux, "/api/peer/scm/pull-requests/create", peerPRScope, map[string]interface{}{
		"connector_id": "conn-same", "repo_full_name": "acme/demo",
		"title": "Nope", "head": "main", "base": "main",
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("same branch must be 422, got %d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["status"] != prStatusNoCommitsBetween {
		t.Fatalf("status want %q got %v", prStatusNoCommitsBetween, out["status"])
	}
	if ok, _ := out["ok"].(bool); ok {
		t.Fatal("ok must be false")
	}
}

func TestGitHubPullAPIErrorClassification(t *testing.T) {
	noCommits := newGitHubPullAPIError("create pull request", http.StatusUnprocessableEntity,
		[]byte(`{"message":"Validation Failed","errors":[{"message":"No commits between main and opm/x"}]}`))
	if !noCommits.NoCommits() || noCommits.Forbidden() || noCommits.AlreadyExists() {
		t.Fatalf("no-commits misclassified: %+v", noCommits)
	}
	exists := newGitHubPullAPIError("create pull request", http.StatusUnprocessableEntity,
		[]byte(`{"errors":[{"message":"A pull request already exists for acme:opm/x."}]}`))
	if !exists.AlreadyExists() || exists.NoCommits() {
		t.Fatalf("already-exists misclassified: %+v", exists)
	}
	headMissing := newGitHubPullAPIError("create pull request", http.StatusUnprocessableEntity,
		[]byte(`{"errors":[{"resource":"PullRequest","field":"head","code":"invalid"}]}`))
	if !headMissing.HeadMissing() {
		t.Fatalf("head-missing misclassified: %+v", headMissing)
	}
	forbidden := newGitHubPullAPIError("create pull request", http.StatusForbidden,
		[]byte(`{"message":"Resource not accessible by integration"}`))
	if !forbidden.Forbidden() || forbidden.Unprocessable() {
		t.Fatalf("403 misclassified: %+v", forbidden)
	}
	if !newGitHubPullAPIError("op", http.StatusNotFound, nil).NotFound() {
		t.Fatal("404 should classify as not found")
	}
	// The message must carry the upstream body so operators see the real reason.
	if got := forbidden.Error(); !strings.Contains(got, "Resource not accessible by integration") {
		t.Fatalf("error text must include upstream body, got %q", got)
	}
}

func TestPeerPullRequestErrorStatuses(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantStat string
	}{
		{"no_commits", newGitHubPullAPIError("create", http.StatusUnprocessableEntity,
			[]byte(`{"errors":[{"message":"No commits between main and opm/x"}]}`)),
			http.StatusUnprocessableEntity, prStatusNoCommitsBetween},
		{"head_missing", newGitHubPullAPIError("create", http.StatusUnprocessableEntity,
			[]byte(`{"errors":[{"field":"head","code":"invalid"}]}`)),
			http.StatusUnprocessableEntity, prStatusHeadBranchNotFound},
		{"forbidden", newGitHubPullAPIError("create", http.StatusForbidden, []byte(`{"message":"nope"}`)),
			http.StatusForbidden, prStatusMissingPRPermission},
		{"repo_missing", newGitHubPullAPIError("create", http.StatusNotFound, []byte(`{"message":"Not Found"}`)),
			http.StatusNotFound, prStatusRepoNotFound},
		{"other", newGitHubPullAPIError("create", http.StatusInternalServerError, []byte(`boom`)),
			http.StatusBadGateway, prStatusUpstreamError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			peerPullRequestError(rec, nil, tc.err)
			if rec.Code != tc.wantCode {
				t.Fatalf("code want %d got %d body=%s", tc.wantCode, rec.Code, rec.Body.String())
			}
			var out map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("body not json: %v", err)
			}
			if out["status"] != tc.wantStat {
				t.Fatalf("status want %q got %v", tc.wantStat, out["status"])
			}
			if ok, _ := out["ok"].(bool); ok {
				t.Fatal("ok must be false on failure")
			}
			if s, _ := out["error"].(string); s == "" {
				t.Fatal("error message must not be empty")
			}
		})
	}
}

func TestGitHubOpenPullRequestGuards(t *testing.T) {
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	c := &opaConnector{ID: "c1", Kind: "github_app"}

	if _, _, err := githubOpenPullRequest(c, "acme", "demo", "T", "b", "feat", "feat", false); err == nil {
		t.Fatal("identical head/base must be refused")
	}
	if _, _, err := githubOpenPullRequest(c, "acme", "demo", "", "b", "feat", "main", false); err == nil {
		t.Fatal("empty title must be refused")
	}
	if _, _, err := githubOpenPullRequest(c, "acme", "demo", "T", "b", "", "main", false); err == nil {
		t.Fatal("empty head must be refused")
	}
	if _, _, err := githubOpenPullRequest(nil, "acme", "demo", "T", "b", "feat", "main", false); err == nil {
		t.Fatal("nil connector must be refused")
	}

	first, existed, err := githubOpenPullRequest(c, "acme", "demo", "T", "b", "opm/task-1", "main", false)
	if err != nil || existed {
		t.Fatalf("mock open: err=%v existed=%v", err, existed)
	}
	again, _, err := githubOpenPullRequest(c, "acme", "demo", "T", "b", "opm/task-1", "main", false)
	if err != nil {
		t.Fatalf("mock reopen: %v", err)
	}
	if first.Number != again.Number {
		t.Fatalf("mock PR number must be stable per branch: %d vs %d", first.Number, again.Number)
	}
	other, _, err := githubOpenPullRequest(c, "acme", "demo", "T", "b", "opm/task-2", "main", false)
	if err != nil {
		t.Fatalf("second branch: %v", err)
	}
	if other.Number == first.Number {
		t.Fatal("different branches must not collide on the same mock number")
	}
}

func TestDecodeGitHubDeliveryPull(t *testing.T) {
	raw := []byte(`{"number":7,"html_url":"https://github.com/acme/demo/pull/7","state":"open",
		"title":"Deliver","draft":true,"head":{"ref":"opm/x"},"base":{"ref":"main"}}`)
	p, err := decodeGitHubDeliveryPull(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Number != 7 || p.HeadRef != "opm/x" || p.BaseRef != "main" || !p.Draft {
		t.Fatalf("fields wrong: %+v", p)
	}
	if _, err := decodeGitHubDeliveryPull([]byte(`{"html_url":"x"}`)); err == nil {
		t.Fatal("a pull request without a number must not decode as success")
	}
}
