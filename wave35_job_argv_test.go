package main

import (
	"strings"
	"testing"
)

func TestBuildDockerRunArgvHardening(t *testing.T) {
	argv, err := buildDockerRunArgv(dockerRunSpec{
		Name: "opa-job-test-scan", Image: "opa-runner-scan:smoke",
		JobID: "testjob", WorkHostPath: "/tmp/opa-review/testjob/primary",
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
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %s", want, joined)
		}
	}
	if strings.Contains(joined, "--privileged") || strings.Contains(joined, "--cap-add") {
		t.Fatal("privileged/cap-add leaked into argv")
	}
	if err := validateDockerRunArgv(argv); err != nil {
		t.Fatal(err)
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
