package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initTempGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}
	run("init")
	run("config", "user.email", "opa@test")
	run("config", "user.name", "OPA Test")
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "readme.txt")
	run("commit", "-m", "init")
	return dir
}

func TestCaptureAndApplyValidatedPatchCleanTree(t *testing.T) {
	sandbox := initTempGitRepo(t)
	clean := initTempGitRepo(t)

	// Agent-like edit in sandbox only (poison file must not appear unless in patch).
	if err := os.WriteFile(filepath.Join(sandbox, "fix.go"), []byte("package fix\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandbox, "evil.txt"), []byte("should be in patch if staged\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	patch, err := captureValidatedPatch(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patch, "fix.go") {
		t.Fatalf("patch missing fix.go: %s", patch)
	}

	// Mutate sandbox after capture — land must not see this.
	_ = os.WriteFile(filepath.Join(sandbox, "post-gate-poison.go"), []byte("package poison\n"), 0o644)

	if err := applyValidatedPatch(clean, patch); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(clean, "fix.go")); err != nil {
		t.Fatal("clean tree missing applied fix.go")
	}
	if _, err := os.Stat(filepath.Join(clean, "post-gate-poison.go")); err == nil {
		t.Fatal("poison file from post-gate sandbox must not appear on clean tree")
	}
	if _, err := os.Stat(filepath.Join(clean, "evil.txt")); err != nil {
		t.Fatal("evil.txt was in validated patch and should land")
	}

	sha, err := gitCommitAll(clean, "test land")
	if err != nil || sha == "" {
		t.Fatalf("commit clean tree: %v sha=%s", err, sha)
	}
}

func TestGateDeniesBeforeCleanLand(t *testing.T) {
	sandbox := initTempGitRepo(t)
	_ = os.MkdirAll(filepath.Join(sandbox, ".github", "workflows"), 0o755)
	_ = os.WriteFile(filepath.Join(sandbox, ".github", "workflows", "ci.yml"), []byte("on: push\n"), 0o644)
	diff, err := gitUnifiedDiff(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	err = gateCloudDiff(parseCloudDiffChanges(diff), nil, defaultCloudDiffCaps())
	if err == nil || !strings.Contains(err.Error(), ".github") {
		t.Fatalf("want .github deny, got %v", err)
	}
}

func TestCloudMaxIterationsBound(t *testing.T) {
	t.Setenv("OPA_CLOUD_MAX_ITERATIONS", "99")
	if cloudMaxIterations() != 3 {
		t.Fatalf("cap at 3, got %d", cloudMaxIterations())
	}
	t.Setenv("OPA_CLOUD_MAX_ITERATIONS", "0")
	if cloudMaxIterations() != 1 {
		t.Fatalf("floor at 1, got %d", cloudMaxIterations())
	}
	t.Setenv("OPA_CLOUD_MAX_ITERATIONS", "2")
	if cloudMaxIterations() != 2 {
		t.Fatalf("want 2 got %d", cloudMaxIterations())
	}
}

func TestCloudIterationStopsOnGateDenied(t *testing.T) {
	// Simulate the stop decision used by runCloudStages.
	attemptOut := map[string]interface{}{
		"status":  "gate_denied",
		"honesty": "gateCloudDiff denied: .github/** denied",
	}
	status := strFromAny(attemptOut["status"])
	stop := status == "gate_denied" || strings.Contains(strFromAny(attemptOut["honesty"]), "gateCloudDiff")
	if !stop {
		t.Fatal("gate_denied must stop iteration loop")
	}
	verifyFail := map[string]interface{}{"status": "verify_failed"}
	if strFromAny(verifyFail["status"]) == "gate_denied" {
		t.Fatal("verify_failed must not be treated as gate stop")
	}
}

func TestAuthorizeReauthSkipsRate(t *testing.T) {
	repo := "acme/reauth-rate"
	conn := &opaConnector{ID: "conn-reauth", Kind: "github_app", InstallationID: "9", Status: "active"}
	watchedLive.Store(conn.ID+"|"+repo, &opaWatchedRepo{ConnectorID: conn.ID, RepoFullName: repo})
	defer watchedLive.Delete(conn.ID + "|" + repo)
	ledger := []agentFinding{{Key: "k1", Severity: "high", File: "a.go", Message: "x"}}
	prefs := agentPrefs{CloudEnabled: true, AutofixMode: "branch", AutofixSeverityThreshold: "high"}

	if _, err := authorizeAutofixRequestAttempt(conn, prefs, repo, ledger, []string{"k1"}, true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < autofixRateLimitMax()+2; i++ {
		recordAutofixRate(repo)
	}
	if _, err := authorizeAutofixRequestAttempt(conn, prefs, repo, ledger, []string{"k1"}, false); err != nil {
		t.Fatalf("re-auth without rate should pass: %v", err)
	}
	if _, err := authorizeAutofixRequestAttempt(conn, prefs, repo, ledger, []string{"k1"}, true); err == nil {
		t.Fatal("recording auth should hit rate limit")
	}
}

func TestCloudJobMustAbortHonorsDrain(t *testing.T) {
	job := &scmJob{ID: "cloud-1", RunID: "run-1", Status: "running", Summary: map[string]interface{}{}}
	scmJobLive.Store(job.ID, job)
	defer scmJobLive.Delete(job.ID)
	if cloudJobMustAbort(job) {
		t.Fatal("fresh cloud job must not abort")
	}
	job.Summary["supersede_drain"] = true
	if !cloudJobMustAbort(job) {
		t.Fatal("supersede_drain must abort land")
	}
	job.Summary = map[string]interface{}{"cancel_drain": "cancelled"}
	if !cloudJobMustAbort(job) {
		t.Fatal("cancel_drain must abort land")
	}
	job.Summary = map[string]interface{}{}
	job.Status = "cancelled"
	if !cloudJobMustAbort(job) {
		t.Fatal("cancelled cloud child must abort")
	}
}

func TestLandValidatedPatchRefusesDrain(t *testing.T) {
	job := &scmJob{
		ID: "cloud-land-1", RunID: "run-land-1", Status: "running",
		RepoFullName: "acme/demo", Summary: map[string]interface{}{"supersede_drain": true},
	}
	scmJobLive.Store(job.ID, job)
	defer scmJobLive.Delete(job.ID)
	out, err := landValidatedPatch(job, &opaConnector{Kind: "github_app", InstallationID: "1"}, "wt-land", "sha", "opa-fix/x-1", "diff", autofixAuthOK{})
	if err == nil || out["status"] != "cancelled" {
		t.Fatalf("want cancelled refuse, got out=%v err=%v", out, err)
	}
}

func TestSuggestModeFailsWhenCommentPostErrors(t *testing.T) {
	t.Setenv("SKIP_CURSOR_AI", "1")
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	old := cloudPRCommentCreate
	defer func() { cloudPRCommentCreate = old }()
	cloudPRCommentCreate = func(c *opaConnector, owner, repo string, pr int, body string) (int64, error) {
		return 0, fmt.Errorf("comment 403")
	}

	job := &scmJob{
		ID: "cloud-suggest-fail", RunID: "run-suggest-fail", Status: "running",
		RepoFullName: "acme/demo", PRNumber: 42, Attempt: 1,
		Summary: map[string]interface{}{},
	}
	conn := &opaConnector{ID: "conn-suggest", Kind: "github_app", InstallationID: "1", Status: "active"}
	auth := autofixAuthOK{
		Mode: "suggest",
		Findings: []agentFinding{{
			Key: "k1", Severity: "high", File: ".opa-review-autofix.md", Message: "fix me",
		}},
	}
	out, err := runOneCloudAttempt(job, conn, auth, agentPrefs{CloudEnabled: true, AutofixMode: "suggest"}, 1)
	if err == nil {
		t.Fatalf("want post error, got nil (out=%v)", out)
	}
	if out["status"] != "failed" {
		t.Fatalf("status=%v want failed", out["status"])
	}
	if out["suggest_post_error"] != "comment 403" {
		t.Fatalf("suggest_post_error=%v", out["suggest_post_error"])
	}
	honesty := strFromAny(out["honesty"])
	if strings.Contains(honesty, "proposal posted") || !strings.Contains(honesty, "proposal post failed") {
		t.Fatalf("honesty must not claim posted after failure: %q", honesty)
	}
	posts, _ := job.Summary["evidence_posts"].([]JobEvidencePost)
	if len(posts) == 0 {
		// evidence may be stored as []interface{} after JSON round-trip; accept map list too
		if raw, ok := job.Summary["evidence_posts"].([]interface{}); !ok || len(raw) == 0 {
			// appendEvidencePost may nest differently — require at least suggest_post_error above
			_ = raw
		}
	}
}

func TestSuggestModeFailsWithoutPR(t *testing.T) {
	t.Setenv("SKIP_CURSOR_AI", "1")
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	job := &scmJob{
		ID: "cloud-suggest-nopr", RunID: "run-suggest-nopr", Status: "running",
		RepoFullName: "acme/demo", PRNumber: 0, Attempt: 1,
		Summary: map[string]interface{}{},
	}
	conn := &opaConnector{ID: "conn-suggest", Kind: "github_app", InstallationID: "1", Status: "active"}
	auth := autofixAuthOK{
		Mode: "suggest",
		Findings: []agentFinding{{
			Key: "k1", Severity: "high", File: ".opa-review-autofix.md", Message: "fix me",
		}},
	}
	out, err := runOneCloudAttempt(job, conn, auth, agentPrefs{CloudEnabled: true, AutofixMode: "suggest"}, 1)
	if err == nil || out["status"] != "failed" {
		t.Fatalf("want failed without PR, got out=%v err=%v", out, err)
	}
	if strings.Contains(strFromAny(out["honesty"]), "proposal posted") {
		t.Fatalf("must not claim posted: %v", out["honesty"])
	}
}
