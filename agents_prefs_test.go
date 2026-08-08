package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuiltinAgentPrefsCloudDefaults(t *testing.T) {
	p := builtinAgentPrefs()
	if !p.CloudEnabled {
		t.Fatal("builtin cloud_enabled want true")
	}
	if p.AutofixMode != "branch" {
		t.Fatalf("builtin autofix_mode want branch, got %q", p.AutofixMode)
	}
	eff, sources := resolveAgentPrefs("default-org", "default-project", "", "")
	if !eff.CloudEnabled || eff.AutofixMode != "branch" {
		t.Fatalf("resolved defaults want cloud+branch, got %+v", eff)
	}
	if sources["cloud_enabled"] != "builtin" || sources["autofix_mode"] != "builtin" {
		t.Fatalf("sources want builtin, got %v", sources)
	}
}

func stampDefaultTenant(req *http.Request) {
	req.Header.Set("X-Organization-ID", defaultOrgID)
	req.Header.Set("X-Project-ID", defaultProjectID)
}

func TestHandleAgentPrefsGetOrgDefaultScopeKey(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	req := httptest.NewRequest(http.MethodGet, "/api/agents/prefs?level=org", nil)
	stampDefaultTenant(req)
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["level"] != "org" {
		t.Fatalf("level=%v", out["level"])
	}
	wantScope := defaultOrgID + "/" + defaultProjectID
	if out["scope_key"] != wantScope {
		t.Fatalf("scope_key want %s got %v", wantScope, out["scope_key"])
	}
	eff, _ := out["effective"].(map[string]interface{})
	if eff == nil {
		t.Fatal("missing effective")
	}
	if eff["cloud_enabled"] != true {
		t.Fatalf("effective.cloud_enabled=%v", eff["cloud_enabled"])
	}
	if eff["autofix_mode"] != "branch" {
		t.Fatalf("effective.autofix_mode=%v", eff["autofix_mode"])
	}
}

func TestHandleAgentPrefsPutOrgWithoutScopeKey(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	body := []byte(`{"level":"org","prefs":{"pr_summaries":false}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	stampDefaultTenant(req)
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	wantScope := defaultOrgID + "/" + defaultProjectID
	if out["scope_key"] != wantScope {
		t.Fatalf("scope_key want %s got %v", wantScope, out["scope_key"])
	}
	prefs, _ := out["prefs"].(map[string]interface{})
	if prefs == nil {
		t.Fatal("missing prefs")
	}
	if prefs["pr_summaries"] != false {
		t.Fatalf("stored pr_summaries want false, got %#v", prefs["pr_summaries"])
	}
}

func TestHandleAgentPrefsPutRequiresLevel(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	body := []byte(`{"prefs":{"pr_summaries":true}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "level required") {
		t.Fatalf("want 400 level required, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestHandleAgentPrefsPutRepoEmptyClear400(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	body := []byte(`{"level":"repo","prefs":{"pr_summaries":true}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 400 {
		t.Fatalf("want 400, got %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "repo/scope_key required") {
		t.Fatalf("want clear repo error, got %s", rr.Body.String())
	}
}

func TestParseAgentPrefsLevel(t *testing.T) {
	got, errMsg := parseAgentPrefsLevel("project", false)
	if got != "project" || errMsg != "" {
		t.Fatalf("project: got %q %q", got, errMsg)
	}
	got, errMsg = parseAgentPrefsLevel("org", false)
	if got != "org" || errMsg != "" {
		t.Fatalf("org: got %q %q", got, errMsg)
	}
	got, errMsg = parseAgentPrefsLevel("repo", false)
	if got != "repo" || errMsg != "" {
		t.Fatalf("repo: got %q %q", got, errMsg)
	}
	got, errMsg = parseAgentPrefsLevel("", true)
	if got != "org" || errMsg != "" {
		t.Fatalf("empty GET default: got %q %q", got, errMsg)
	}
	got, errMsg = parseAgentPrefsLevel("installation", false)
	if got != "" || !strings.Contains(errMsg, "level=project") {
		t.Fatalf("installation reject: got %q %q", got, errMsg)
	}
	got, errMsg = parseAgentPrefsLevel("bogus", false)
	if got != "" || !strings.Contains(errMsg, "org, project, or repo") {
		t.Fatalf("bogus reject: got %q %q", got, errMsg)
	}
}

func TestHandleAgentPrefsPutRepoWithScope(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	body := []byte(`{"level":"repo","repo":"acme/demo","prefs":{"pr_summaries":true}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	stampDefaultTenant(req)
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["level"] != "repo" || out["scope_key"] != "acme/demo" {
		t.Fatalf("want repo/acme/demo, got level=%v scope=%v", out["level"], out["scope_key"])
	}
}

func TestAgentPrefsRejectInstallationLevel(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	t.Setenv("PEER_OAM_URL", "")
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	wantMsg := "use level=project with X-Project-ID"

	getReq := httptest.NewRequest(http.MethodGet, "/api/agents/prefs?level=installation&connector_id=c1", nil)
	getRR := httptest.NewRecorder()
	handleAgentPrefs(getRR, getReq)
	if getRR.Code != 400 || !strings.Contains(getRR.Body.String(), wantMsg) {
		t.Fatalf("GET installation want 400 %q, got %d %s", wantMsg, getRR.Code, getRR.Body.String())
	}

	putBody := []byte(`{"level":"installation","connector_id":"c1","prefs":{"pr_summaries":false}}`)
	putReq := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRR := httptest.NewRecorder()
	handleAgentPrefs(putRR, putReq)
	if putRR.Code != 400 || !strings.Contains(putRR.Body.String(), wantMsg) {
		t.Fatalf("PUT installation want 400 %q, got %d %s", wantMsg, putRR.Code, putRR.Body.String())
	}
}

func TestHandleAgentPrefsPutInvalidLevel(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	body := []byte(`{"level":"team","prefs":{"pr_summaries":true}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "level must be org, project, or repo") {
		t.Fatalf("want 400 invalid level, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestHandleAgentPrefsPutProjectWithConnector(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	t.Setenv("PEER_OAM_URL", "")
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	body := []byte(`{"level":"project","connector_id":"conn-proj","prefs":{"pr_summaries":false}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	stampDefaultTenant(req)
	req.Header.Set("X-Project-ID", "web")
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["level"] != "project" {
		t.Fatalf("level=%v", out["level"])
	}
	if out["scope_key"] != "conn-proj" {
		t.Fatalf("scope_key want conn-proj got %v", out["scope_key"])
	}
	sources, _ := out["sources"].(map[string]interface{})
	if sources["pr_summaries"] != "project" {
		t.Fatalf("sources.pr_summaries want project, got %v", sources["pr_summaries"])
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/agents/prefs?level=project&connector_id=conn-proj", nil)
	stampDefaultTenant(getReq)
	getReq.Header.Set("X-Project-ID", "web")
	getRR := httptest.NewRecorder()
	handleAgentPrefs(getRR, getReq)
	if getRR.Code != 200 {
		t.Fatalf("GET status %d body %s", getRR.Code, getRR.Body.String())
	}
	var got map[string]interface{}
	if err := json.Unmarshal(getRR.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	prefs, _ := got["prefs"].(map[string]interface{})
	if prefs["pr_summaries"] != false {
		t.Fatalf("stored prefs want pr_summaries=false, got %#v", prefs)
	}
}

func TestHandleAgentPrefsPutProjectResolvesFromOAM(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]interface{}{
				{"id": "web", "connector_ids": []string{"oam-conn"}},
			},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OAM_URL", srv.URL)

	body := []byte(`{"level":"project","prefs":{"inline_findings":true}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	stampDefaultTenant(req)
	req.Header.Set("X-Project-ID", "web")
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["scope_key"] != "oam-conn" {
		t.Fatalf("scope_key want oam-conn got %v", out["scope_key"])
	}
}

func TestHandleAgentPrefsPutProjectMissingConnector400(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	t.Setenv("PEER_OAM_URL", "")
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	body := []byte(`{"level":"project","prefs":{"pr_summaries":true}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/agents/prefs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "connector_id/scope_key required for project level") {
		t.Fatalf("want 400 project connector required, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestResolveAgentPrefsReadsHistoricalInstallation(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	agentPrefsMu.Lock()
	agentPrefsLive = map[string]*agentPrefsRow{}
	agentPrefsMu.Unlock()

	row := &agentPrefsRow{
		OrganizationID: "o1", ProjectID: "p1", Level: "installation", ScopeKey: "conn-hist",
		PrefsJSON: `{"pr_summaries":false,"cloud_enabled":false}`,
	}
	if err := persistAgentPrefsRow(row); err != nil {
		t.Fatal(err)
	}

	eff, sources := resolveAgentPrefs("o1", "p1", "conn-hist", "")
	if eff.PRSummaries {
		t.Fatal("historical installation prefs should disable pr_summaries")
	}
	if eff.CloudEnabled {
		t.Fatal("historical installation prefs should disable cloud_enabled")
	}
	if sources["pr_summaries"] != "project" {
		t.Fatalf("source want project (not installation), got %q", sources["pr_summaries"])
	}
	if sources["cloud_enabled"] != "project" {
		t.Fatalf("source want project, got %q", sources["cloud_enabled"])
	}
}

func TestHandleAgentPrefsGetProjectSurfacesHistoricalInstallation(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	t.Setenv("PEER_OAM_URL", "")
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	agentPrefsMu.Lock()
	agentPrefsLive = map[string]*agentPrefsRow{}
	agentPrefsMu.Unlock()
	if err := persistAgentPrefsRow(&agentPrefsRow{
		OrganizationID: defaultOrgID, ProjectID: defaultProjectID,
		Level: "installation", ScopeKey: "conn-old",
		PrefsJSON: `{"auto_approve":true}`,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/agents/prefs?level=project&connector_id=conn-old", nil)
	stampDefaultTenant(req)
	rr := httptest.NewRecorder()
	handleAgentPrefs(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["level"] != "project" {
		t.Fatalf("level=%v", out["level"])
	}
	prefs, _ := out["prefs"].(map[string]interface{})
	if prefs["auto_approve"] != true {
		t.Fatalf("want historical prefs surfaced, got %#v", prefs)
	}
	sources, _ := out["sources"].(map[string]interface{})
	if sources["auto_approve"] != "project" {
		t.Fatalf("sources want project, got %v", sources["auto_approve"])
	}
}

func TestProjectPrefsOverrideOrgAndRepoWins(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	agentPrefsMu.Lock()
	agentPrefsLive = map[string]*agentPrefsRow{}
	agentPrefsMu.Unlock()

	mustPersist := func(level, scope, raw string) {
		t.Helper()
		if err := persistAgentPrefsRow(&agentPrefsRow{
			OrganizationID: "o", ProjectID: "p", Level: level, ScopeKey: scope, PrefsJSON: raw,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mustPersist("org", "o/p", `{"pr_summaries":false,"inline_findings":false}`)
	mustPersist("project", "c1", `{"pr_summaries":true}`)
	mustPersist("repo", "acme/app", `{"inline_findings":true}`)

	eff, sources := resolveAgentPrefs("o", "p", "c1", "acme/app")
	if !eff.PRSummaries {
		t.Fatal("project should override org pr_summaries")
	}
	if !eff.InlineFindings {
		t.Fatal("repo should override inline_findings")
	}
	if sources["pr_summaries"] != "project" {
		t.Fatalf("pr_summaries source=%v", sources["pr_summaries"])
	}
	if sources["inline_findings"] != "repo" {
		t.Fatalf("inline_findings source=%v", sources["inline_findings"])
	}
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestPlanRunChildrenCloudOffStillEnqueued(t *testing.T) {
	parent := &scmJob{
		ID: "plan-cloud-off", OrganizationID: "o", ProjectID: "p",
		RepoFullName: "o/r", CommitSHA: "abc", Kind: string(kindRun), RunID: "plan-cloud-off",
	}
	prefs := builtinAgentPrefs()
	prefs.CloudEnabled = false
	children := planRunChildren(parent, prefs, false, "")
	var cloud *scmJob
	for _, c := range children {
		if agentKind(c.Kind) == kindCloud {
			cloud = c
		}
	}
	if cloud == nil {
		t.Fatal("cloud-off must still enqueue kindCloud child")
	}
	if cloud.Status != "skipped" {
		t.Fatalf("want skipped, got %s", cloud.Status)
	}
	reason, _ := cloud.Summary["skip_reason"].(string)
	if !strings.Contains(reason, "cloud_enabled/autofix_mode off") {
		t.Fatalf("skip_reason=%q", reason)
	}
}
