package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGitHubPermsIssuesAndProjects(t *testing.T) {
	m := githubPermsIssuesWrite()
	if m["issues"] != "write" {
		t.Fatalf("issues write: %+v", m)
	}
	p := githubPermsProjectsWrite()
	if p["organization_projects"] != "write" {
		t.Fatalf("projects: %+v", p)
	}
	req := githubAppRequiredPermsForAIIssues()
	if req["issues"] != "write" || req["contents"] != "write" {
		t.Fatalf("required: %+v", req)
	}
}

func TestAssessInstallationPermHealth(t *testing.T) {
	resetInstallationPermCacheForTest()
	defer resetInstallationPermCacheForTest()

	pat := &opaConnector{Kind: "github_pat", ID: "p1"}
	h := assessInstallationPermHealth(pat)
	if !h.OK {
		t.Fatalf("PAT should be ok-ish: %+v", h)
	}

	setInstallationPermCacheForTest("inst-ai", map[string]string{
		"contents": "write", "metadata": "read", "pull_requests": "write",
		"issues": "write", "checks": "write",
	})
	app := &opaConnector{Kind: "github_app", InstallationID: "inst-ai"}
	h = assessInstallationPermHealth(app)
	if !h.OK {
		t.Fatalf("want ok, missing=%v notes=%v", h.Missing, h.Notes)
	}
	if h.ProjectsOK {
		t.Fatal("projects should be optional-missing")
	}

	setInstallationPermCacheForTest("inst-no-issues", map[string]string{
		"contents": "read", "metadata": "read", "pull_requests": "write", "checks": "write",
	})
	app2 := &opaConnector{Kind: "github_app", InstallationID: "inst-no-issues"}
	h = assessInstallationPermHealth(app2)
	if h.OK {
		t.Fatal("want missing issues")
	}
	joined := strings.Join(h.Missing, ",")
	if !strings.Contains(joined, "issues") {
		t.Fatalf("missing=%v", h.Missing)
	}
}

func TestIssueLabelMatchesPrefs(t *testing.T) {
	p := builtinAgentPrefs()
	if !issueLabelMatchesPrefs(p, []string{"bug", "AI"}) {
		t.Fatal("AI should match")
	}
	if issueLabelMatchesPrefs(p, []string{"bug"}) {
		t.Fatal("no AI label")
	}
	p.AIIssueLabels = []string{"opa-ai"}
	if !issueLabelMatchesPrefs(p, []string{"OPA-AI"}) {
		t.Fatal("case-insensitive match")
	}
}

func TestValidateRoadmapJSON(t *testing.T) {
	if err := validateRoadmapJSON(nil); err == nil {
		t.Fatal("nil")
	}
	if err := validateRoadmapJSON(map[string]interface{}{"features": []interface{}{}}); err == nil {
		t.Fatal("missing phases")
	}
	if err := validateRoadmapJSON(heuristicRoadmap("a/b", heuristicDiscovery("a/b", ""))); err != nil {
		t.Fatal(err)
	}
}

func TestMergeIssueLabels(t *testing.T) {
	got := mergeIssueLabels([]string{"AI", "bug"}, []string{"ai", "opa:plan-ready"})
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}

func TestBuiltinAIIssuePrefs(t *testing.T) {
	p := builtinAgentPrefs()
	if !p.AIIssuesEnabled || p.IssueAutoImplement || p.RoadmapProjectsV2 {
		t.Fatalf("%+v", p)
	}
	if !p.RequireHumanBeforeCoding {
		t.Fatal("require_human_before_coding default true")
	}
	if len(p.AIIssueLabels) != 1 || p.AIIssueLabels[0] != "AI" {
		t.Fatalf("labels=%v", p.AIIssueLabels)
	}
}

func TestApplyPrefsAIIssueFields(t *testing.T) {
	out := builtinAgentPrefs()
	sources := map[string]string{}
	raw := map[string]json.RawMessage{
		"issue_auto_implement":       json.RawMessage(`true`),
		"roadmap_projects_v2":        json.RawMessage(`true`),
		"require_human_before_coding": json.RawMessage(`false`),
		"ai_issue_labels":            json.RawMessage(`["AI","auto"]`),
	}
	applyPrefsPatch(&out, sources, raw, "repo")
	if !out.IssueAutoImplement || !out.RoadmapProjectsV2 || out.RequireHumanBeforeCoding {
		t.Fatalf("%+v", out)
	}
	if len(out.AIIssueLabels) != 2 {
		t.Fatalf("labels=%v", out.AIIssueLabels)
	}
}
