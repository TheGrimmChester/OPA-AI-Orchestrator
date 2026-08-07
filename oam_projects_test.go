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
