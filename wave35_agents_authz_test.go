package main

import (
	"strings"
	"testing"
)

func TestAuthorizeAutofixRequestGates(t *testing.T) {
	repo := "acme/demo"
	conn := &opaConnector{ID: "conn-app", Kind: "github_app", InstallationID: "1", Status: "active"}
	pat := &opaConnector{ID: "conn-pat", Kind: "github_pat", TokenRef: "ghp_fake", Status: "active"}
	wr := &opaWatchedRepo{ConnectorID: conn.ID, RepoFullName: repo}
	watchedLive.Store(conn.ID+"|"+repo, wr)
	defer watchedLive.Delete(conn.ID + "|" + repo)

	ledger := []agentFinding{
		{Key: "k-high", Severity: "high", File: "a.go", Message: "bug"},
		{Key: "k-low", Severity: "low", File: "b.go", Message: "nit"},
	}
	prefs := agentPrefs{CloudEnabled: true, AutofixMode: "branch", AutofixSeverityThreshold: "high"}

	// Happy path.
	ok, err := authorizeAutofixRequest(conn, prefs, repo, ledger, []string{"k-high"})
	if err != nil || len(ok.Findings) != 1 || ok.Mode != "branch" {
		t.Fatalf("want ok branch: err=%v got=%+v", err, ok)
	}

	// Empty keys refuse.
	if _, err := authorizeAutofixRequest(conn, prefs, repo, ledger, nil); err == nil || !strings.Contains(err.Error(), "empty finding_keys") {
		t.Fatalf("empty keys want refuse, got %v", err)
	}

	// cloud_enabled off.
	off := prefs
	off.CloudEnabled = false
	if _, err := authorizeAutofixRequest(conn, off, repo, ledger, []string{"k-high"}); err == nil {
		t.Fatal("cloud off should refuse")
	}

	// autofix_mode off.
	modeOff := prefs
	modeOff.AutofixMode = "off"
	if _, err := authorizeAutofixRequest(conn, modeOff, repo, ledger, []string{"k-high"}); err == nil {
		t.Fatal("mode off should refuse")
	}

	// PAT refused.
	if _, err := authorizeAutofixRequest(pat, prefs, repo, ledger, []string{"k-high"}); err == nil || !strings.Contains(err.Error(), "PAT") {
		t.Fatalf("PAT want refuse, got %v", err)
	}

	// Unknown key.
	if _, err := authorizeAutofixRequest(conn, prefs, repo, ledger, []string{"missing"}); err == nil {
		t.Fatal("missing key should refuse")
	}

	// Severity from ledger (low below threshold).
	if _, err := authorizeAutofixRequest(conn, prefs, repo, ledger, []string{"k-low"}); err == nil || !strings.Contains(err.Error(), "below threshold") {
		t.Fatalf("low severity want refuse, got %v", err)
	}

	// Severity must not come from a forged request — ledger says low even if we only pass the key.
	// (already covered by k-low)

	// Repo not in installation.
	if _, err := authorizeAutofixRequest(conn, prefs, "other/repo", ledger, []string{"k-high"}); err == nil {
		t.Fatal("foreign repo should refuse")
	}
}

func TestAuthorizeGitPushRefusesPAT(t *testing.T) {
	if err := authorizeGitPush(&opaConnector{Kind: "github_pat"}); err == nil {
		t.Fatal("expected PAT refusal")
	}
	if err := authorizeGitPush(&opaConnector{Kind: "github_app", InstallationID: "1"}); err != nil {
		t.Fatalf("app should allow: %v", err)
	}
}

func TestGateCloudDiffDenials(t *testing.T) {
	caps := cloudDiffCaps{MaxFiles: 10, MaxLines: 100}

	if err := gateCloudDiff([]cloudDiffChange{{Path: "src/a.go", Added: 2}}, nil, caps); err != nil {
		t.Fatalf("clean path: %v", err)
	}

	cases := []struct {
		name string
		ch   []cloudDiffChange
		allow []string
		sub  string
	}{
		{"github", []cloudDiffChange{{Path: ".github/workflows/ci.yml", Added: 1}}, nil, ".github"},
		{"opa", []cloudDiffChange{{Path: ".opa/agents.json", Added: 1}}, nil, ".opa"},
		{"lockfile", []cloudDiffChange{{Path: "package-lock.json", Added: 1}}, nil, "lockfile"},
		{"exec", []cloudDiffChange{{Path: "bin/tool", Added: 1, NewMode: "100755"}}, nil, "exec bit"},
		{"submodule", []cloudDiffChange{{Path: "vendor/lib", Added: 1, NewMode: "160000", IsSubmodule: true}}, nil, "submodule"},
		{"allowlist", []cloudDiffChange{{Path: "other.go", Added: 1}}, []string{"src/a.go"}, "allowlist"},
		{"filecap", []cloudDiffChange{
			{Path: "a.go", Added: 1}, {Path: "b.go", Added: 1}, {Path: "c.go", Added: 1},
		}, nil, "file cap"},
	}
	for _, tc := range cases {
		c := caps
		if tc.name == "filecap" {
			c.MaxFiles = 2
		}
		err := gateCloudDiff(tc.ch, tc.allow, c)
		if err == nil || !strings.Contains(err.Error(), tc.sub) {
			t.Fatalf("%s: want deny containing %q, got %v", tc.name, tc.sub, err)
		}
	}

	if err := gateCloudDiff(nil, nil, caps); err == nil {
		t.Fatal("empty diff should deny")
	}
}

func TestParseCloudDiffChangesModes(t *testing.T) {
	diff := `diff --git a/bin/x b/bin/x
old mode 100644
new mode 100755
--- a/bin/x
+++ b/bin/x
@@ -1 +1 @@
-a
+b
diff --git a/.github/a.yml b/.github/a.yml
new file mode 100644
+++ b/.github/a.yml
+hi
`
	ch := parseCloudDiffChanges(diff)
	if len(ch) < 2 {
		t.Fatalf("want >=2 changes, got %+v", ch)
	}
	var sawExec, sawGH bool
	for _, c := range ch {
		if c.Path == "bin/x" && c.NewMode == "100755" {
			sawExec = true
		}
		if c.Path == ".github/a.yml" {
			sawGH = true
		}
	}
	if !sawExec || !sawGH {
		t.Fatalf("parse missed modes: %+v", ch)
	}
}

func TestOpaFixBranchNameDeterministic(t *testing.T) {
	a := opaFixBranchName("run-abc", 1)
	b := opaFixBranchName("run-abc", 1)
	if a != b || a != "opa-fix/run-abc-1" {
		t.Fatalf("got %q / %q", a, b)
	}
	if opaFixBranchName("run-abc", 2) == a {
		t.Fatal("attempt should change branch")
	}
}

func TestFilterFindingsByKeysEmptyRefusesAll(t *testing.T) {
	f1 := map[string]interface{}{"file": "a.go", "message": "one", "finding_key": "k1"}
	f2 := map[string]interface{}{"file": "b.go", "message": "two", "finding_key": "k2"}
	got := filterFindingsByKeys([]map[string]interface{}{f1, f2}, []string{"k2"})
	if len(got) != 1 || got[0]["finding_key"] != "k2" {
		t.Fatalf("filter failed: %+v", got)
	}
	all := filterFindingsByKeys([]map[string]interface{}{f1, f2}, nil)
	if len(all) != 0 {
		t.Fatal("empty keys must refuse fixing everything")
	}
}
