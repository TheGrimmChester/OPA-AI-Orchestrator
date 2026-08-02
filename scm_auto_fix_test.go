package main

import (
	"strings"
	"testing"
)

func TestAutofixShouldLandSuggestVsBranch(t *testing.T) {
	if autofixShouldLand("suggest") {
		t.Fatal("suggest must not land")
	}
	if autofixShouldLand("Suggest") {
		t.Fatal("Suggest (cased) must not land")
	}
	if !autofixShouldLand("branch") {
		t.Fatal("branch should land")
	}
	if autofixShouldLand("") {
		t.Fatal("empty mode must fail closed (no land)")
	}
	if autofixShouldLand("off") {
		t.Fatal("unknown mode must not land")
	}
}

func TestAutofixSuggestFlagsNeverOpenPR(t *testing.T) {
	// Regression: CreatePR || !CommitDirect was true when both were false (suggest).
	fix := &opaAutoFixJob{Mode: "suggest", CreatePR: false, CommitDirect: false}
	if autofixShouldLand(fix.Mode) {
		t.Fatal("suggest must skip land/push/PR")
	}
	if fix.CreatePR {
		t.Fatal("suggest must not open PR")
	}
	branch := &opaAutoFixJob{Mode: "branch", CreatePR: true, CommitDirect: false}
	if !autofixShouldLand(branch.Mode) || !branch.CreatePR {
		t.Fatal("branch+create_pr should land and open PR")
	}
	direct := &opaAutoFixJob{Mode: "branch", CreatePR: false, CommitDirect: true}
	if !autofixShouldLand(direct.Mode) {
		t.Fatal("commit_direct should still land (push)")
	}
	if direct.CreatePR {
		t.Fatal("commit_direct must not open PR")
	}
}

func TestAutofixModeCasingSuggestDoesNotBecomeBranch(t *testing.T) {
	mode := strings.ToLower(strings.TrimSpace("Suggest"))
	if mode != "suggest" {
		t.Fatalf("got %q", mode)
	}
	if mode != "suggest" && mode != "branch" {
		mode = "branch"
	}
	if autofixShouldLand(mode) {
		t.Fatal("Suggest prefs must authorize as suggest and never land")
	}
}

func TestAutofixFindingAllowlistRequired(t *testing.T) {
	allow := autofixFindingAllowlist([]map[string]interface{}{
		{"file": "src/a.go"},
		{"file": "src/a.go"},
		{"file": ""},
		{"file": "lib/b.go"},
	})
	if len(allow) != 2 || allow[0] != "src/a.go" || allow[1] != "lib/b.go" {
		t.Fatalf("allow=%v", allow)
	}
	if got := autofixFindingAllowlist([]map[string]interface{}{{"file": ""}, {"message": "x"}}); len(got) != 0 {
		t.Fatalf("empty paths: %v", got)
	}

	// Real AI path: empty allowlist must fail closed (gate skipped only when empty after require).
	if len(autofixFindingAllowlist(nil)) != 0 {
		t.Fatal("nil findings")
	}
	caps := defaultCloudDiffCaps()
	err := gateCloudDiff([]cloudDiffChange{{Path: "evil.sh", Added: 1}}, []string{"src/a.go"}, caps)
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("outside allowlist must deny: %v", err)
	}
}

func TestGitAutofixCmdEnvNoSecrets(t *testing.T) {
	t.Setenv("JWT_SECRET", "jwt-leak")
	t.Setenv("OPA_CONNECTOR_SECRET", "conn-leak")
	t.Setenv("PATH", "/usr/bin")
	cmd := gitAutofixCmd("/tmp/repo", "status", "--porcelain")
	if cmd.Env == nil {
		t.Fatal("gitAutofixCmd must set Env (not inherit process)")
	}
	joined := strings.Join(cmd.Env, "\n")
	for _, leak := range []string{"JWT_SECRET=", "OPA_CONNECTOR_SECRET="} {
		if strings.Contains(joined, leak) {
			t.Fatalf("autofix git env leaked %s", leak)
		}
	}
	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "core.hooksPath=/dev/null") {
		t.Fatalf("hooks must be disabled: %s", args)
	}
}
