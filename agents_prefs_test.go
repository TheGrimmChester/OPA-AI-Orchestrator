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

func TestHandleAgentPrefsGetOrgDefaultScopeKey(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	prev := authEnforced
	authEnforced = false
	defer func() { authEnforced = prev }()

	req := httptest.NewRequest(http.MethodGet, "/api/agents/prefs?level=org", nil)
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
	// JSON numbers/bools via RawMessage round-trip as decoded values in map after unmarshal of response
	raw := string(mustJSON(prefs["pr_summaries"]))
	if !strings.Contains(raw, "false") {
		// prefs values may already be bool
		if prefs["pr_summaries"] != false {
			t.Fatalf("stored pr_summaries want false, got %#v", prefs["pr_summaries"])
		}
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
