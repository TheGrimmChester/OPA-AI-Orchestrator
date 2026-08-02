package main

import (
	"strings"
	"testing"
)

func TestGitHubPermMapsNeverRequestWorkflows(t *testing.T) {
	maps := []map[string]string{
		githubPermsCloneRead(),
		githubPermsPRRead(),
		githubPermsChecksWrite(),
		githubPermsPRWrite(),
		githubPermsPush(),
		githubPermsCreatePR(),
	}
	for i, m := range maps {
		if _, ok := m["workflows"]; ok {
			t.Fatalf("perm map %d requests workflows: %+v", i, m)
		}
		stripped := stripWorkflowsPerm(m)
		if _, ok := stripped["workflows"]; ok {
			t.Fatal("stripWorkflowsPerm failed")
		}
	}
	withWF := map[string]string{"contents": "write", "workflows": "write"}
	out := stripWorkflowsPerm(withWF)
	if _, ok := out["workflows"]; ok || out["contents"] != "write" {
		t.Fatalf("strip failed: %+v", out)
	}
}

func TestGitHubInstallationTokenRequestPayload(t *testing.T) {
	if githubInstallationTokenRequestPayload(nil, nil) != nil {
		t.Fatal("empty should be nil (full-scope)")
	}
	p := githubInstallationTokenRequestPayload([]string{"demo"}, githubPermsCloneRead())
	repos, _ := p["repositories"].([]string)
	if len(repos) != 1 || repos[0] != "demo" {
		t.Fatalf("repos: %+v", p["repositories"])
	}
	perms, _ := p["permissions"].(map[string]string)
	if perms["contents"] != "read" || perms["metadata"] != "read" {
		t.Fatalf("perms: %+v", perms)
	}
	// workflows stripped from payload even if passed.
	dirty := githubInstallationTokenRequestPayload([]string{"x"}, map[string]string{
		"contents": "write", "workflows": "write",
	})
	got := dirty["permissions"].(map[string]string)
	if _, ok := got["workflows"]; ok {
		t.Fatalf("workflows must not appear in payload: %+v", got)
	}
}

func TestRequireGrantedPerms(t *testing.T) {
	resetInstallationPermCacheForTest()
	defer resetInstallationPermCacheForTest()
	setInstallationPermCacheForTest("inst-1", map[string]string{
		"contents": "write", "metadata": "read", "checks": "write",
	})

	ok, err := requireGrantedPerms("inst-1", githubPermsCloneRead())
	if err != nil || ok["contents"] != "read" {
		t.Fatalf("clone read: err=%v got=%+v", err, ok)
	}

	_, err = requireGrantedPerms("inst-1", githubPermsPRWrite())
	if err == nil || !strings.Contains(err.Error(), "lacks required") {
		t.Fatalf("want refuse for missing pull_requests, got %v", err)
	}
	if !strings.Contains(err.Error(), "refusing full-scope") {
		t.Fatalf("honesty must refuse full-scope fallback: %v", err)
	}

	// write>read refused.
	setInstallationPermCacheForTest("inst-2", map[string]string{"contents": "read", "metadata": "read"})
	_, err = requireGrantedPerms("inst-2", githubPermsPush())
	if err == nil || !strings.Contains(err.Error(), "contents(write>read)") {
		t.Fatalf("want write>read refuse, got %v", err)
	}
}

func TestGitHubRepoShortName(t *testing.T) {
	if githubRepoShortName("acme/demo") != "demo" {
		t.Fatal(githubRepoShortName("acme/demo"))
	}
}
