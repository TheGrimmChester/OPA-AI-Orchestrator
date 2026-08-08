package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOAMProjectsTargetForwardsProduct(t *testing.T) {
	q := url.Values{}
	q.Set("organization_id", "acme")
	q.Set("product", "ora")
	got := oamProjectsTarget("http://oam:8090/", q)
	want := "http://oam:8090/api/projects?organization_id=acme&product=ora"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRequireEnabledOAMProjectSkipsWhenUnset(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "")
	req := httptest.NewRequest(http.MethodPost, "/api/scm/ai-review", nil)
	req.Header.Set("X-Project-ID", "checkout-api")
	if st, msg := requireEnabledOAMProject(req, "ora"); st != 0 || msg != "" {
		t.Fatalf("expected skip, got %d %q", st, msg)
	}
}

func TestOAMDirectoryHasProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]string{{"id": "review"}},
		})
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ok, err := oamDirectoryHasProject(req.Context(), req, srv.URL, "ora", "review")
	if err != nil || !ok {
		t.Fatalf("want found, got ok=%v err=%v", ok, err)
	}
}

func TestResolveConnectorFromOAMProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]interface{}{
				{"id": "web", "connector_ids": []string{"conn-a"}},
				{"id": "empty", "connector_ids": []string{}},
			},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OAM_URL", srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Project-ID", "web")
	got, msg, code := resolveConnectorFromOAMProject(req, "")
	if msg != "" || code != 0 || got != "conn-a" {
		t.Fatalf("fill got=%q msg=%q code=%d", got, msg, code)
	}

	got, msg, code = resolveConnectorFromOAMProject(req, "explicit")
	if msg != "" || code != 0 || got != "explicit" {
		t.Fatalf("explicit got=%q msg=%q code=%d", got, msg, code)
	}

	reqEmpty := httptest.NewRequest(http.MethodGet, "/", nil)
	reqEmpty.Header.Set("X-Project-ID", "empty")
	_, msg, code = resolveConnectorFromOAMProject(reqEmpty, "")
	if code != 400 || msg == "" {
		t.Fatalf("empty connectors want 400, got %d %q", code, msg)
	}

	t.Setenv("PEER_OAM_URL", "")
	got, msg, code = resolveConnectorFromOAMProject(req, "")
	if got != "" || msg != "" || code != 0 {
		t.Fatalf("unset peer want skip, got %q %q %d", got, msg, code)
	}
}

func TestEnsureWatchedFromOAMMatch(t *testing.T) {
	connID := "conn-ensure-match"
	repo := "Acme/Web"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "product=ora") {
			t.Errorf("expected product=ora query, got %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]interface{}{
				{
					"id":              "web",
					"organization_id": "acme",
					"external_key":    "acme/web",
					"connector_ids":   []string{connID},
				},
			},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OAM_URL", srv.URL)

	conn := &opaConnector{
		ID: connID, OrganizationID: "acme", ProjectID: "web",
		Kind: "github_app", Status: "active",
	}
	connectorLive.Store(connID, conn)
	defer connectorLive.Delete(connID)
	defer watchedLive.Delete(connID + "|" + repo)

	wr, gotConn, skip := ensureWatchedFromOAM("acme", repo, connID)
	if skip != "" {
		t.Fatalf("unexpected skip: %q", skip)
	}
	if wr == nil || !wr.Enabled {
		t.Fatal("expected enabled watched row")
	}
	if gotConn == nil || gotConn.ID != connID {
		t.Fatalf("connector=%v", gotConn)
	}
	if wr.ProjectID != "web" {
		t.Fatalf("project_id=%q want web", wr.ProjectID)
	}
	if found, _ := findWatched(repo); found == nil {
		t.Fatal("findWatched should see ensured row")
	}
}

func TestEnsureWatchedFromOAMNoProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]interface{}{},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OAM_URL", srv.URL)

	wr, conn, skip := ensureWatchedFromOAM("acme", "acme/other", "conn-x")
	if wr != nil || conn != nil {
		t.Fatalf("expected nil, got wr=%v conn=%v", wr, conn)
	}
	if skip != "no OAM project with ora enabled for repo" {
		t.Fatalf("skip=%q", skip)
	}
}

func TestEnsureWatchedFromOAMConnectorNotBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]interface{}{
				{
					"id":            "web",
					"external_key":  "acme/web",
					"connector_ids": []string{"other-conn"},
				},
			},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OAM_URL", srv.URL)

	_, _, skip := ensureWatchedFromOAM("acme", "acme/web", "conn-x")
	if skip != "connector not bound on OAM project" {
		t.Fatalf("skip=%q", skip)
	}
}

func TestHandleWatchedPut404WhenPeerOAM(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	connID := "conn-watched-put-404"
	conn := &opaConnector{
		ID: connID, OrganizationID: "acme", ProjectID: "web",
		Kind: "github_app", Status: "active",
	}
	connectorLive.Store(connID, conn)
	defer connectorLive.Delete(connID)

	body := `{"repos":[{"repo_full_name":"acme/web","enabled":true}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/connectors/"+connID+"/watched", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleWatchedPut(rr, req, connID)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleWatchedPutAllowsPeerOAMWriteContext(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	connID := "conn-watched-put-peer"
	repo := "acme/peer-write"
	conn := &opaConnector{
		ID: connID, OrganizationID: "acme", ProjectID: "web",
		Kind: "github_app", Status: "active",
	}
	connectorLive.Store(connID, conn)
	defer connectorLive.Delete(connID)
	defer watchedLive.Delete(connID + "|" + repo)

	body := `{"repos":[{"repo_full_name":"` + repo + `","enabled":true}]}`
	req := withPeerOAMWrite(httptest.NewRequest(http.MethodPut, "/api/internal/connectors/"+connID+"/watched", strings.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Organization-ID", "acme")
	req.Header.Set("X-Project-ID", "web")
	rr := httptest.NewRecorder()
	handleWatchedPut(rr, req, connID)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rr.Code, rr.Body.String())
	}
}
