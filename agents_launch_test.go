package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestGitleaksSandboxBindUsesCheckoutLayout(t *testing.T) {
	// Security scans pass srun-* as runID but checkout lives under the SCM job/run folder.
	tmp := t.TempDir()
	t.Setenv("OPA_REVIEW_TMP", tmp)
	scmJobID := "scm-job-abc"
	securityRunID := "srun-be76e9a4c2814e13"
	checkout := filepath.Join(tmp, scmJobID, "sandbox")
	if err := os.MkdirAll(checkout, 0o755); err != nil {
		t.Fatal(err)
	}
	// Bug: resolveSandboxJobID(securityRunID, checkout) → srun-* and assertJobBindPath rejects.
	if err := assertJobBindPath(checkout, resolveSandboxJobID(securityRunID, checkout)); err == nil {
		t.Fatal("expected srun-* layout id to reject scm checkout bind")
	}
	layoutID := resolveSandboxJobID("", checkout)
	workRel := sandboxWorkRel(checkout)
	if layoutID != scmJobID {
		t.Fatalf("path-derived layout want %s got %s", scmJobID, layoutID)
	}
	if workRel != "sandbox" {
		t.Fatalf("workRel want sandbox got %s", workRel)
	}
	if err := assertJobBindPath(checkout, layoutID); err != nil {
		t.Fatalf("path-derived layout must allow bind: %v", err)
	}
	// Cancel label (opa.job) is the security/SCM child id — may differ from layout.
	secChild := "security-child-xyz"
	jobLabel := resolveSandboxJobID(secChild, checkout)
	if jobLabel != secChild {
		t.Fatalf("cancel JobID want %s got %s", secChild, jobLabel)
	}
	if jobLabel == layoutID {
		t.Fatal("gitleaks JobID (cancel) must differ from LayoutID (bind) when child ≠ checkout folder")
	}
	if err := assertJobBindPath(checkout, layoutID); err != nil {
		t.Fatal(err)
	}
}

func TestAutofixSandboxLabelsSplitJobFromLayout(t *testing.T) {
	// Cloud patch: opa.job=child, LayoutID=worktree (bind), RunID=parent run (opa.run).
	scmJobID := "cloud-child-abc"
	worktreeID := "cloud-patch-cloud-child-abc-1"
	parentRunID := "run-parent-xyz"
	checkout := "/tmp/opa-review/" + worktreeID + "/sandbox"
	jobLabel := resolveSandboxJobID(scmJobID, checkout)
	layoutLabel := resolveSandboxJobID(worktreeID, checkout)
	if jobLabel != scmJobID {
		t.Fatalf("JobID (opa.job) want %s got %s", scmJobID, jobLabel)
	}
	if layoutLabel != worktreeID {
		t.Fatalf("LayoutID want %s got %s", worktreeID, layoutLabel)
	}
	spec := agentLaunchSpec{JobID: jobLabel, RunID: parentRunID, LayoutID: layoutLabel, WorktreeRoot: checkout}
	labelID := resolveSandboxJobID(spec.JobID, spec.WorktreeRoot)
	runLabel := nz(strings.TrimSpace(spec.RunID), labelID)
	layoutID := nz(strings.TrimSpace(spec.LayoutID), runLabel)
	if labelID != scmJobID || layoutID != worktreeID || runLabel != parentRunID {
		t.Fatalf("launch spec: job=%s layout=%s run=%s", labelID, layoutID, runLabel)
	}
	if runLabel == layoutID {
		t.Fatal("opa.run (parent) must differ from LayoutID (cloud-patch worktree) so parent cancel reaps boxes")
	}
}

func TestWriteAgentBriefVisiblePath(t *testing.T) {
	dir := t.TempDir()
	checkout := filepath.Join(dir, "job1", "sandbox")
	if err := os.MkdirAll(checkout, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPA_JOB_SANDBOX", "off")
	ref, cleanup, err := writeAgentBrief(checkout, "job1", "unit.md", "# hi")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !strings.HasSuffix(ref, filepath.Join("sandbox", ".opa-briefs", "unit.md")) &&
		!strings.Contains(ref, ".opa-briefs/unit.md") &&
		!strings.Contains(ref, ".opa-briefs"+string(filepath.Separator)+"unit.md") {
		t.Fatalf("host mode ref: %s", ref)
	}
	t.Setenv("OPA_JOB_SANDBOX", "docker")
	ref2, cleanup2, err := writeAgentBrief(checkout, "job1", "unit2.md", "# hi")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup2()
	want := "/opa-jobs/job1/sandbox/.opa-briefs/unit2.md"
	if ref2 != want {
		t.Fatalf("docker visible path: got %s want %s", ref2, want)
	}
}

func TestResolveAgentBinForRunner(t *testing.T) {
	t.Setenv("OPA_CURSOR_AGENT_BIN", "")
	if got := resolveAgentBinForRunner("docker"); got != "/opt/opa/agent" {
		t.Fatalf("docker runner: got %q", got)
	}
	t.Setenv("OPA_CURSOR_AGENT_BIN", "/usr/local/bin/agent")
	if got := resolveAgentBinForRunner("host"); got != "/usr/local/bin/agent" {
		t.Fatalf("host with allowlisted env: got %q", got)
	}
	// Docker must ignore host env and keep the baked path.
	if got := resolveAgentBinForRunner("docker"); got != "/opt/opa/agent" {
		t.Fatalf("docker ignores OPA_CURSOR_AGENT_BIN: got %q", got)
	}
	t.Setenv("OPA_JOB_SANDBOX", "docker")
	// resolveAgentBin is host-side even when sandbox mode is docker (host fallback).
	if got := resolveAgentBin(); got != "/usr/local/bin/agent" {
		t.Fatalf("resolveAgentBin stays host-resolvable under docker sandbox mode: got %q", got)
	}
}
