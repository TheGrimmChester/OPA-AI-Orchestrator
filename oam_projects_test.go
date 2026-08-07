package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
