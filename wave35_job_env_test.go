package main

import (
	"os"
	"strings"
	"testing"
)

func TestJobEnvOmitsOrchestratorSecrets(t *testing.T) {
	secrets := []string{
		"JWT_SECRET", "OPA_CONNECTOR_SECRET", "OPA_GITHUB_APP_PRIVATE_KEY",
		"OPA_GITHUB_WEBHOOK_SECRET", "CLICKHOUSE_URL", "GIT_ASKPASS", "OPA_GIT_ASKPASS_TOKEN",
	}
	for _, k := range secrets {
		t.Setenv(k, "leak-me-"+k)
	}
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/tmp/opa-home")

	env := jobEnv(jobEnvSpec{
		Phase:        jobPhaseReview,
		WorktreeRoot: "/work/primary",
		Secrets:      map[string]string{"CURSOR_API_KEY": "sk-test"},
		Extra:        map[string]string{"OPA_REVIEW_PREVIEW_URL": "http://127.0.0.1:9"},
	})
	joined := strings.Join(env, "\n")
	for _, k := range secrets {
		prefix := k + "="
		for _, line := range env {
			if strings.HasPrefix(line, prefix) {
				t.Fatalf("jobEnv leaked %s", k)
			}
		}
		if strings.Contains(joined, "leak-me-"+k) {
			t.Fatalf("jobEnv leaked value for %s", k)
		}
	}
	mustHave := []string{
		"CURSOR_API_KEY=sk-test",
		"NO_OPEN_BROWSER=1",
		"OPA_SCAN_WORKTREE=/work/primary",
		"OPA_JOB_PHASE=review",
		"OPA_REVIEW_PREVIEW_URL=http://127.0.0.1:9",
		"PATH=/usr/bin",
		"HOME=/tmp/opa-home",
	}
	for _, want := range mustHave {
		found := false
		for _, line := range env {
			if line == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %q in %#v", want, env)
		}
	}
}

func TestJobEnvScanPhaseDropsAPIKey(t *testing.T) {
	env := jobEnv(jobEnvSpec{
		Phase:   jobPhaseScan,
		Secrets: map[string]string{"CURSOR_API_KEY": "should-drop"},
		Extra:   map[string]string{"GITLEAKS_CONFIG": ""},
	})
	for _, line := range env {
		if strings.HasPrefix(line, "CURSOR_API_KEY=") {
			t.Fatalf("scan phase must not receive CURSOR_API_KEY: %s", line)
		}
	}
	found := false
	for _, line := range env {
		if line == "GITLEAKS_CONFIG=" || strings.HasPrefix(line, "GITLEAKS_CONFIG=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected GITLEAKS_CONFIG in %#v", env)
	}
}

func TestJobEnvDropsSecretLookingExtra(t *testing.T) {
	env := jobEnv(jobEnvSpec{
		Phase: jobPhaseReview,
		Extra: map[string]string{"MY_TOKEN": "nope", "SAFE_FLAG": "1"},
	})
	for _, line := range env {
		if strings.HasPrefix(line, "MY_TOKEN=") {
			t.Fatalf("secret-looking Extra must be dropped")
		}
	}
	found := false
	for _, line := range env {
		if line == "SAFE_FLAG=1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SAFE_FLAG missing: %#v", env)
	}
}

func TestHostToolEnvOmitsServiceSecrets(t *testing.T) {
	t.Setenv("JWT_SECRET", "jwt-leak")
	t.Setenv("OPA_CONNECTOR_SECRET", "aes-leak")
	t.Setenv("PATH", "/bin")
	env := hostToolEnv("GIT_ASKPASS=/tmp/ask.sh", "OPA_GIT_ASKPASS_TOKEN=pat-xyz")
	for _, line := range env {
		if strings.HasPrefix(line, "JWT_SECRET=") || strings.HasPrefix(line, "OPA_CONNECTOR_SECRET=") {
			t.Fatalf("hostToolEnv leaked service secret: %s", line)
		}
	}
	hasAsk, hasTok := false, false
	for _, line := range env {
		if line == "GIT_ASKPASS=/tmp/ask.sh" {
			hasAsk = true
		}
		if line == "OPA_GIT_ASKPASS_TOKEN=pat-xyz" {
			hasTok = true
		}
	}
	if !hasAsk || !hasTok {
		t.Fatalf("askpass extras missing: %#v", env)
	}
	_ = os.Getenv("PATH")
}
