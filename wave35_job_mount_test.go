package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssertJobBindPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPA_REVIEW_TMP", tmp)
	job := "job-abc"
	ok := []string{
		filepath.Join(tmp, job, "primary"),
		filepath.Join(tmp, job, "sandbox"),
		filepath.Join(tmp, job, "related", "owner-repo"),
		filepath.Join(opaJobsContainerRoot, sanitizeDockerName(job), "primary"),
	}
	for _, p := range ok {
		if err := assertJobBindPath(p, job); err != nil {
			t.Fatalf("expected allow %s: %v", p, err)
		}
	}
	other := filepath.Join(tmp, "other-job", "primary")
	if err := assertJobBindPath(other, job); err == nil {
		t.Fatalf("expected reject cross-job bind %s", other)
	}
	if err := assertJobBindPath("/etc/passwd", job); err == nil {
		t.Fatal("expected reject /etc/passwd")
	}
}

func TestSandboxContainerNameUnique(t *testing.T) {
	a := sandboxContainerName("run1", jobPhaseReview, "aaa111")
	b := sandboxContainerName("run1", jobPhaseReview, "bbb222")
	if a == b {
		t.Fatal("suffix must disambiguate")
	}
	if !strings.Contains(a, "-review-") || !strings.HasPrefix(a, "opa-job-") {
		t.Fatalf("shape: %s", a)
	}
	c := sandboxContainerName("run1", jobPhaseCheckup, "")
	d := sandboxContainerName("run1", jobPhaseCheckup, "")
	if c == d {
		t.Fatal("empty suffix should randomize")
	}
	if !strings.Contains(c, "-checkup-") {
		t.Fatalf("checkup teardown matcher needs -checkup- in %s", c)
	}
}

func TestWriteSandboxSecretsEnvFile(t *testing.T) {
	path, cleanup, err := writeSandboxSecretsEnvFile(map[string]string{
		"CURSOR_API_KEY": "sk-test-secret",
		"":               "x",
		"EMPTY":          "",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "CURSOR_API_KEY=sk-test-secret\n" {
		t.Fatalf("got %q", raw)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("secrets env must be 0600, got %v", info.Mode())
	}
}
