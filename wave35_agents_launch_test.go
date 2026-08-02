package main

import "testing"

func TestValidateGitHubRepoFullName(t *testing.T) {
	ok := []string{"owner/repo", "Charge-Map/community-api", "a/b"}
	for _, n := range ok {
		if err := validateGitHubRepoFullName(n); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
	bad := []string{
		"", "nope", "../etc/passwd", "owner/repo.git",
		"owner/repo;rm", "owner/repo`id`", "owner/../../x",
		"owner/repo with space", "-/repo",
	}
	for _, n := range bad {
		if err := validateGitHubRepoFullName(n); err == nil {
			t.Fatalf("expected reject for %q", n)
		}
	}
}

func TestValidateAgentBin(t *testing.T) {
	if err := validateAgentBin("agent"); err != nil {
		t.Fatal(err)
	}
	if err := validateAgentBin("/opt/opa/agent"); err != nil {
		t.Fatal(err)
	}
	if err := validateAgentBin("/bin/sh"); err == nil {
		t.Fatal("expected /bin/sh rejected")
	}
	if err := validateAgentBin("sh"); err == nil {
		t.Fatal("expected sh rejected")
	}
}

func TestRedactJobOutput(t *testing.T) {
	raw := []byte("using key sk-secret-value-here in log")
	out := redactJobOutput(raw, "sk-secret-value-here")
	if string(out) != "using key *** in log" {
		t.Fatalf("got %q", out)
	}
}

func TestResolveSandboxJobID(t *testing.T) {
	if got := resolveSandboxJobID("run-abc", "/tmp/opa-review/run-abc/sandbox"); got != "run-abc" {
		t.Fatalf("explicit wins: %s", got)
	}
	if got := resolveSandboxJobID("", "/tmp/opa-review/job99/sandbox"); got != "job99" {
		t.Fatalf("sandbox leaf: %s", got)
	}
	if got := resolveSandboxJobID("", "/tmp/opa-review/job99/primary"); got != "job99" {
		t.Fatalf("primary leaf: %s", got)
	}
	a := resolveSandboxJobID("", "/tmp/opa-review/aaa/sandbox")
	b := resolveSandboxJobID("", "/tmp/opa-review/bbb/sandbox")
	if a == b || a == "sandbox" || b == "sandbox" {
		t.Fatalf("distinct jobs must not share leaf id: a=%s b=%s", a, b)
	}
	if sandboxWorkRel("/x/y/sandbox") != "sandbox" {
		t.Fatal("workRel sandbox")
	}
	if sandboxWorkRel("/x/y/primary") != "primary" {
		t.Fatal("workRel primary")
	}
}
