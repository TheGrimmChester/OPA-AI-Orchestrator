package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJobIdentityHostRootExactOpaJobsOnly(t *testing.T) {
	t.Setenv("OPA_REVIEW_TMP", opaJobsContainerRoot)
	got := jobIdentityHostRoot("Job_ABC")
	want := filepath.Join(opaJobsContainerRoot, sanitizeDockerName("Job_ABC"))
	if got != want {
		t.Fatalf("exact /opa-jobs: got %s want %s", got, want)
	}

	// NAS-style path ending in /opa-jobs must NOT rewrite to /opa-jobs/<id>.
	nas := "/mnt/Apps/config-docker/opa/opa-jobs"
	t.Setenv("OPA_REVIEW_TMP", nas)
	got = jobIdentityHostRoot("scmjob-abc")
	want = filepath.Join(nas, sanitizeWorktreeID("scmjob-abc"))
	if got != want {
		t.Fatalf("nas suffix path: got %s want %s", got, want)
	}
	if strings.HasPrefix(got, opaJobsContainerRoot+"/") && !strings.HasPrefix(nas, opaJobsContainerRoot) {
		t.Fatalf("must not rewrite onto %s: %s", opaJobsContainerRoot, got)
	}
}

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

func TestAssertJobBindPathRejectsEmptyAndRelative(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPA_REVIEW_TMP", tmp)
	job := "job-abc"
	if err := assertJobBindPath(filepath.Join(tmp, job, "primary"), ""); err == nil {
		t.Fatal("empty job id must reject")
	}
	if err := assertJobBindPath("relative/path", job); err == nil {
		t.Fatal("relative path must reject")
	}
	// Prefix sibling must not match job identity root.
	evil := filepath.Join(tmp, job+"-evil", "primary")
	if err := assertJobBindPath(evil, job); err == nil {
		t.Fatalf("prefix sibling must reject: %s", evil)
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

func TestRelatedROBind(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPA_REVIEW_TMP", tmp)
	layout := "run-rel-1"
	sandbox := filepath.Join(tmp, layout, "sandbox")
	related := filepath.Join(tmp, layout, "related", "acme-shared")
	if err := os.MkdirAll(sandbox, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(related, 0o755); err != nil {
		t.Fatal(err)
	}
	jobID := "bugbot-child"
	bind, ok := relatedROBind(sandbox, jobID, layout)
	if !ok {
		t.Fatal("expected related bind")
	}
	wantCont := "/opa-jobs/" + sanitizeDockerName(jobID) + "/related"
	if !strings.Contains(bind, wantCont+":ro") {
		t.Fatalf("want %s:ro in %s", wantCont, bind)
	}
	if !strings.HasPrefix(bind, filepath.Join(tmp, layout, "related")) {
		t.Fatalf("bind host side: %s", bind)
	}
	if got := relatedContainerPath(jobID, "acme/shared"); got != wantCont+"/acme-shared" {
		t.Fatalf("container path: %s", got)
	}
	if _, ok := relatedROBind(sandbox, jobID, "other-layout"); ok {
		t.Fatal("cross-layout related bind must fail assertJobBindPath")
	}
}

func TestSiblingROBinds(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPA_REVIEW_TMP", tmp)
	layout := "run-sib-1"
	primary := filepath.Join(tmp, layout, "primary")
	dep := filepath.Join(tmp, layout, "Open-Auth-Go")
	for _, d := range []string{primary, dep} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	jobID := "checkup-child"
	binds := siblingROBinds([]string{dep}, jobID, layout)
	if len(binds) != 1 {
		t.Fatalf("binds = %v, want 1", binds)
	}
	want := dep + ":/opa-jobs/" + sanitizeDockerName(jobID) + "/Open-Auth-Go:ro"
	if binds[0] != want {
		t.Fatalf("bind = %q, want %q", binds[0], want)
	}

	// Paths outside the job layout are dropped, never mounted.
	outside := t.TempDir()
	if got := siblingROBinds([]string{outside}, jobID, layout); len(got) != 0 {
		t.Fatalf("outside-layout bind must be dropped, got %v", got)
	}
	// Relative paths and missing dirs are dropped.
	if got := siblingROBinds([]string{"relative/path", filepath.Join(tmp, layout, "nope")}, jobID, layout); len(got) != 0 {
		t.Fatalf("invalid binds must be dropped, got %v", got)
	}
	// Duplicates collapse.
	if got := siblingROBinds([]string{dep, dep}, jobID, layout); len(got) != 1 {
		t.Fatalf("duplicate binds must collapse, got %v", got)
	}
}
