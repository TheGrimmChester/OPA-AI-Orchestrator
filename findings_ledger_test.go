package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func loadOSAFindingsFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "osa_run_findings.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	return out
}

func TestSecurityFindingsFromRunUsesOSAPeer(t *testing.T) {
	fixture := loadOSAFindingsFixture(t)
	var calls int32
	var sawOrg, sawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		sawOrg = r.Header.Get("X-Organization-ID")
		sawPath = r.URL.Path
		if !strings.HasSuffix(r.URL.Path, "/findings") {
			t.Errorf("path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(fixture)
	}))
	defer srv.Close()

	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-osa-findings-secret-32bytes!!")
	prevQC := queryClient
	queryClient = nil
	defer func() { queryClient = prevQC }()

	got := securityFindingsFromRun("org-a", "run-1")
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("peer calls=%d want 1", calls)
	}
	if sawOrg != "org-a" {
		t.Fatalf("org header=%q", sawOrg)
	}
	if !strings.Contains(sawPath, "/api/security/runs/run-1/findings") {
		t.Fatalf("path=%q", sawPath)
	}
	if len(got) < 2 {
		t.Fatalf("want secrets+sast(+iac), got %+v", got)
	}
	var sawAWS, sawSQL, sawIAC bool
	for _, f := range got {
		if f.Source != "security" {
			t.Fatalf("source=%q", f.Source)
		}
		switch f.Rule {
		case "aws-key":
			sawAWS = true
			if f.File != "a.go" || f.Line != 3 || f.Severity != "high" {
				t.Fatalf("secret finding %+v", f)
			}
		case "sql-injection":
			sawSQL = true
		case "open-sg":
			sawIAC = true
		}
	}
	if !sawAWS || !sawSQL || !sawIAC {
		t.Fatalf("mapped flags aws=%v sql=%v iac=%v got=%+v", sawAWS, sawSQL, sawIAC, got)
	}
}

func TestSecurityFindingsNoCHFallbackOnPeerError(t *testing.T) {
	t.Setenv("PEER_OSA_URL", "http://127.0.0.1:1")
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-osa-findings-secret-32bytes!!")
	// Even with a non-nil client pointer, peer failure must not invent CH findings.
	prevQC := queryClient
	queryClient = &ClickHouseQuery{}
	defer func() { queryClient = prevQC }()

	if got := securityFindingsFromRun("org", "run-1"); len(got) != 0 {
		t.Fatalf("want empty on peer fail, got %+v", got)
	}
}

func TestSecurityFindingsPeerUnsetEmpty(t *testing.T) {
	t.Setenv("PEER_OSA_URL", "")
	prevQC := queryClient
	queryClient = &ClickHouseQuery{}
	defer func() { queryClient = prevQC }()

	if got := securityFindingsFromRun("org", "run-1"); len(got) != 0 {
		t.Fatalf("peer unset must not invent CH findings, got %+v", got)
	}
}

func TestSecurityFindingsEmptyRunIDNoPeerCall(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("PEER_OSA_URL", srv.URL)

	if got := securityFindingsFromRun("org", ""); len(got) != 0 {
		t.Fatalf("want nil, got %+v", got)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("empty run id must not call peer")
	}
}

func TestSecurityFindingsPeer404Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-osa-findings-secret-32bytes!!")

	if got := securityFindingsFromRun("org-b", "foreign-run"); len(got) != 0 {
		t.Fatalf("404/empty tenant must yield empty ledger, got %+v", got)
	}
}

func TestWriteThisRunSecurityFindingsBriefUsesPeer(t *testing.T) {
	fixture := loadOSAFindingsFixture(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("X-Organization-ID") != "org-brief" {
			t.Errorf("org=%q", r.Header.Get("X-Organization-ID"))
		}
		_ = json.NewEncoder(w).Encode(fixture)
	}))
	defer srv.Close()

	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-osa-findings-secret-32bytes!!")
	prevQC := queryClient
	queryClient = &ClickHouseQuery{} // must not be used for secret/sast
	defer func() { queryClient = prevQC }()

	var b strings.Builder
	writeThisRunSecurityFindingsBrief(&b, "org-brief", "run-1")
	out := b.String()
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls=%d", calls)
	}
	if !strings.Contains(out, "## This-run secret findings") {
		t.Fatalf("missing secret section: %s", out)
	}
	if !strings.Contains(out, "## This-run SAST findings") {
		t.Fatalf("missing sast section: %s", out)
	}
	if !strings.Contains(out, "aws-key") || !strings.Contains(out, "sql-injection") {
		t.Fatalf("missing rules: %s", out)
	}
	if strings.Contains(out, "opa.secret_findings") || strings.Contains(out, "opa.sast_findings") {
		t.Fatalf("must not mention CH tables")
	}
}

func TestPackAIContextThisRunUsesPeer(t *testing.T) {
	fixture := loadOSAFindingsFixture(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode(fixture)
	}))
	defer srv.Close()

	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-osa-findings-secret-32bytes!!")
	prevQC := queryClient
	queryClient = nil
	defer func() { queryClient = prevQC }()

	job := &scmJob{
		OrganizationID: "org-pack",
		ProjectID:      "proj-a",
		RepoFullName:   "acme/demo",
		PRNumber:       7,
		CommitSHA:      "abc123",
		Title:          "demo",
	}
	brief := packAIContext(job, nil, "run-1", "diff --git a/x.go b/x.go\n", "")
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("peer calls=%d want 1", calls)
	}
	if !strings.Contains(brief, "## This-run secret findings") {
		t.Fatalf("brief missing secrets:\n%s", brief)
	}
	if !strings.Contains(brief, "aws-key") {
		t.Fatalf("brief missing aws-key:\n%s", brief)
	}
}

func TestPeerOSAGetSecurityRunFindingsPath(t *testing.T) {
	var sawPath, sawRaw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		sawRaw = r.URL.EscapedPath()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"security_run_id": "run with spaces",
			"findings":        map[string]interface{}{},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-osa-findings-secret-32bytes!!")

	ctx := t.Context()
	_, err := peerOSAGetSecurityRunFindings(ctx, "org", "run with spaces")
	if err != nil {
		t.Fatalf("peer: %v", err)
	}
	if !strings.HasSuffix(sawPath, "/findings") && !strings.HasSuffix(sawRaw, "/findings") {
		t.Fatalf("path=%q escaped=%q", sawPath, sawRaw)
	}
	if !strings.Contains(sawRaw, "%20") && strings.Contains(sawPath, " ") {
		// EscapedPath should keep the space encoding from PathEscape.
		t.Fatalf("expected path-escaped run id; path=%q escaped=%q", sawPath, sawRaw)
	}
}
