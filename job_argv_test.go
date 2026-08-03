package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildDockerRunArgvHardening(t *testing.T) {
	argv, err := buildDockerRunArgv(dockerRunSpec{
		Name: "opa-job-test-scan", Image: "osa-runner-scan:smoke",
		JobID: "child1", RunID: "run1", WorkHostPath: "/tmp/opa-review/run1/primary",
		WorkRel: "primary", ReadOnlyBind: true, Network: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--user 65532:65532",
		"--cap-drop ALL",
		"--security-opt no-new-privileges",
		"--read-only",
		"--network none",
		"--memory-swap",
		"opa.owner=opa-orchestrator",
		"opa.job=child1",
		"opa.run=run1",
		"uid=65532,gid=65532,mode=1777",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %s", want, joined)
		}
	}
	if strings.Contains(joined, "--privileged") || strings.Contains(joined, "--cap-add") {
		t.Fatal("privileged/cap-add leaked into argv")
	}
	// Layout root bind (not leaf-only) so /opa-jobs/<id> is writable.
	if !strings.Contains(joined, "/tmp/opa-review/run1:/opa-jobs/child1:ro") {
		t.Fatalf("want layout root bind, got %s", joined)
	}
	if !strings.Contains(joined, "-w /opa-jobs/child1/primary") {
		t.Fatalf("want cwd under identity leaf, got %s", joined)
	}
	if err := validateDockerRunArgv(argv); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDockerRunArgvSandboxRemountsPrimaryRO(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPA_REVIEW_TMP", tmp)
	layout := filepath.Join(tmp, "run1")
	sandbox := filepath.Join(layout, "sandbox")
	primary := filepath.Join(layout, "primary")
	if err := os.MkdirAll(sandbox, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	argv, err := buildDockerRunArgv(dockerRunSpec{
		Name: "opa-job-test-cloud", Image: "ora-runner-ai:smoke",
		JobID: "child1", RunID: "run1", WorkHostPath: sandbox,
		WorkRel: "sandbox", ReadOnlyBind: false, Network: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, layout+":/opa-jobs/child1:rw") {
		t.Fatalf("want layout RW bind, got %s", joined)
	}
	wantRO := primary + ":/opa-jobs/child1/primary:ro"
	if !strings.Contains(joined, wantRO) {
		t.Fatalf("want primary RO remount %q in %s", wantRO, joined)
	}
}

func TestBuildDockerRunArgvSandboxRequiresPrimary(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPA_REVIEW_TMP", tmp)
	layout := filepath.Join(tmp, "run1")
	sandbox := filepath.Join(layout, "sandbox")
	if err := os.MkdirAll(sandbox, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := buildDockerRunArgv(dockerRunSpec{
		Name: "opa-job-test-cloud", Image: "ora-runner-ai:smoke",
		JobID: "child1", RunID: "run1", WorkHostPath: sandbox,
		WorkRel: "sandbox", ReadOnlyBind: false, Network: "none",
	})
	if err == nil {
		t.Fatal("expected error when primary missing")
	}
	if !strings.Contains(err.Error(), "requires primary") {
		t.Fatalf("want primary error, got %v", err)
	}
}

func TestValidateDockerRunArgvDenylist(t *testing.T) {
	cases := [][]string{
		{"run", "--privileged", "img"},
		{"run", "--cap-add", "SYS_ADMIN", "img"},
		{"run", "-p", "8080:80", "img"},
		{"run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img"},
		{"run", "-v", "/:/host", "img"},
		{"run", "-e", "SECRET=x", "img"},
	}
	for _, c := range cases {
		if err := validateDockerRunArgv(c); err == nil {
			t.Fatalf("expected deny for %v", c)
		}
	}
}

func TestSandboxModeDefaultOff(t *testing.T) {
	t.Setenv("OPA_JOB_SANDBOX", "")
	if sandboxMode() != "off" {
		t.Fatalf("default want off got %s", sandboxMode())
	}
	t.Setenv("OPA_JOB_SANDBOX", "docker")
	if sandboxMode() != "docker" {
		t.Fatal("docker mode")
	}
}

func TestGetSandboxRunnerHostByDefault(t *testing.T) {
	t.Setenv("OPA_JOB_SANDBOX", "")
	if getSandboxRunner().Name() != "host" {
		t.Fatal("expected host runner")
	}
}
