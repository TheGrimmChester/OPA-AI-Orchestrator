package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGoModLocalReplaces(t *testing.T) {
	// Single-line form, as used by ORA / OSA / OPL.
	single := []byte(`module github.com/TheGrimmChester/ora-api

go 1.25

require github.com/TheGrimmChester/open-auth-go v0.0.0

replace github.com/TheGrimmChester/open-auth-go => ../Open-Auth-Go

replace github.com/TheGrimmChester/open-tenant-go => ../Open-Tenant-Go

replace github.com/example/pinned => github.com/example/pinned v1.2.3
`)
	got := parseGoModLocalReplaces(single)
	if len(got) != 2 {
		t.Fatalf("single-line: got %d replacements, want 2: %+v", len(got), got)
	}
	if got[0].Name != "Open-Auth-Go" || got[0].Rel != "../Open-Auth-Go" {
		t.Errorf("unexpected first replacement: %+v", got[0])
	}
	if got[1].Name != "Open-Tenant-Go" {
		t.Errorf("unexpected second replacement: %+v", got[1])
	}

	// Block form, as used by OPA-Hub.
	block := []byte(`module github.com/TheGrimmChester/opa-hub

go 1.25

replace (
	github.com/TheGrimmChester/open-auth-go => ../Open-Auth-Go
	github.com/TheGrimmChester/open-http-go => ../Open-HTTP-Go
	// commented => ../Nope
)
`)
	got = parseGoModLocalReplaces(block)
	if len(got) != 2 {
		t.Fatalf("block: got %d replacements, want 2: %+v", len(got), got)
	}
	names := got[0].Name + "," + got[1].Name
	if names != "Open-Auth-Go,Open-HTTP-Go" {
		t.Errorf("block names = %q", names)
	}

	// A go.mod with no filesystem replacements yields nothing.
	if r := parseGoModLocalReplaces([]byte("module x\n\ngo 1.25\n")); len(r) != 0 {
		t.Errorf("plain go.mod: got %+v", r)
	}
}

// writeModule creates a minimal module checkout at dir.
func writeModule(t *testing.T, dir, module string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+module+"\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte("package lib\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The failing production case: an isolated checkout whose go.mod replaces
// modules with siblings that are not there. With a source root configured the
// runner materializes them; without one it reports blocked, never failed.
func TestPrepareCheckupWorkspaceMaterializesSiblings(t *testing.T) {
	layout := t.TempDir()
	primary := filepath.Join(layout, "primary")
	if err := os.MkdirAll(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	goMod := "module github.com/TheGrimmChester/ora-api\n\ngo 1.25\n\n" +
		"replace github.com/TheGrimmChester/open-auth-go => ../Open-Auth-Go\n" +
		"replace github.com/TheGrimmChester/open-tenant-go => ../Open-Tenant-Go\n"
	if err := os.WriteFile(filepath.Join(primary, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}

	// No source root: blocked with an actionable message, and nothing ran.
	t.Setenv("OPA_CHECKUP_MODULE_SRC", "")
	t.Setenv("FAMILY_ROOT", "")
	t.Setenv("OPA_FAMILY_SRC", "")
	rep := prepareCheckupWorkspace(primary)
	if !rep.Blocked() {
		t.Fatalf("expected blocked without a module source, got %+v", rep)
	}
	if len(rep.Unresolved) != 2 {
		t.Errorf("unresolved = %v, want both modules", rep.Unresolved)
	}
	if !strings.Contains(rep.Honesty(), "OPA_CHECKUP_MODULE_SRC") {
		t.Errorf("honesty should name the knob to set: %s", rep.Honesty())
	}

	// With a source root the siblings are materialized next to the checkout.
	src := t.TempDir()
	writeModule(t, filepath.Join(src, "Open-Auth-Go"), "github.com/TheGrimmChester/open-auth-go")
	writeModule(t, filepath.Join(src, "Open-Tenant-Go"), "github.com/TheGrimmChester/open-tenant-go")
	t.Setenv("OPA_CHECKUP_MODULE_SRC", src)

	rep = prepareCheckupWorkspace(primary)
	if rep.Blocked() {
		t.Fatalf("expected resolution, got %+v", rep)
	}
	if len(rep.Satisfied) != 2 {
		t.Errorf("satisfied = %v, want 2", rep.Satisfied)
	}
	for _, name := range []string{"Open-Auth-Go", "Open-Tenant-Go"} {
		target := filepath.Join(layout, name, "go.mod")
		if _, err := os.Stat(target); err != nil {
			t.Errorf("%s not materialized: %v", target, err)
		}
	}
	// ../Name now resolves from the checkout, which is what the toolchain reads.
	if _, err := os.Stat(filepath.Join(primary, "..", "Open-Auth-Go", "go.mod")); err != nil {
		t.Errorf("../Open-Auth-Go does not resolve: %v", err)
	}

	sibs := checkupModuleSiblingDirs(primary, rep)
	if len(sibs) != 2 {
		t.Errorf("sibling binds = %v, want 2", sibs)
	}
}

func TestPrepareCheckupWorkspaceSkipsGitAndVendor(t *testing.T) {
	layout := t.TempDir()
	primary := filepath.Join(layout, "primary")
	if err := os.MkdirAll(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, "go.mod"),
		[]byte("module m\n\ngo 1.25\n\nreplace x => ../Dep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	dep := filepath.Join(src, "Dep")
	writeModule(t, dep, "x")
	writeModule(t, filepath.Join(dep, "vendor", "junk"), "junk")
	if err := os.MkdirAll(filepath.Join(dep, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dep, ".git", "HEAD"), []byte("ref: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPA_CHECKUP_MODULE_SRC", src)

	rep := prepareCheckupWorkspace(primary)
	if rep.Blocked() {
		t.Fatalf("unexpected block: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(layout, "Dep", "lib.go")); err != nil {
		t.Errorf("module file missing: %v", err)
	}
	for _, skipped := range []string{".git", "vendor"} {
		if _, err := os.Stat(filepath.Join(layout, "Dep", skipped)); !os.IsNotExist(err) {
			t.Errorf("%s should not be copied", skipped)
		}
	}
}

// A tree with no filesystem replacements must be left completely alone.
func TestPrepareCheckupWorkspaceNoop(t *testing.T) {
	primary := filepath.Join(t.TempDir(), "primary")
	if err := os.MkdirAll(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, "go.mod"), []byte("module m\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := prepareCheckupWorkspace(primary)
	if rep.Blocked() || len(rep.Required) != 0 {
		t.Errorf("expected noop, got %+v", rep)
	}
	// Non-Go trees too.
	php := filepath.Join(t.TempDir(), "primary")
	if err := os.MkdirAll(php, 0o755); err != nil {
		t.Fatal(err)
	}
	if rep := prepareCheckupWorkspace(php); rep.Blocked() {
		t.Errorf("tree without go.mod must not block: %+v", rep)
	}
}

func TestPurgeCheckupStateRemovesStaleCaptures(t *testing.T) {
	work := t.TempDir()
	stale := filepath.Join(work, ".opa-checkup")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "go-test.stdout"), []byte("output from a previous attempt"), 0o600); err != nil {
		t.Fatal(err)
	}
	purgeCheckupState(work)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale state survived purge: %v", err)
	}
	// The checkout itself must survive.
	if _, err := os.Stat(work); err != nil {
		t.Errorf("work root removed: %v", err)
	}
}

// A blocked workspace reports neutral, so an unprepared runner never reads as a
// failing commit.
func TestBlockedCheckupReportsNeutral(t *testing.T) {
	r := checkupRunResult{Status: "blocked", Honesty: "workspace not prepared — go.mod replaces Open-Auth-Go"}
	sum := formatCheckupCheckSummary(r, nil)
	if !strings.Contains(sum, "not a test failure") {
		t.Errorf("blocked summary should disclaim a test failure: %s", sum)
	}
	if !strings.Contains(sum, "status=blocked") {
		t.Errorf("summary missing status: %s", sum)
	}
}

// Failing checkups must name the step and show its output.
func TestFailingCheckupSummaryCarriesStepAndLog(t *testing.T) {
	r := checkupRunResult{
		Status: "failed",
		Steps: []checkupStepResult{
			{ID: "go-build", OK: true, ExitOK: true, PostOK: true, DurationMS: 1200},
			{
				ID: "go-test", OK: false, ExitOK: false, PostOK: false, DurationMS: 37775,
				Error:      "nonzero exit: exit status 1",
				LogExcerpt: "--- FAIL: TestTenantScope (0.00s)\n    tenant_test.go:42: want default-org",
			},
		},
	}
	s, ok := r.FailingStep()
	if !ok || s.ID != "go-test" {
		t.Fatalf("FailingStep = %+v, %v", s, ok)
	}
	sum := formatCheckupCheckSummary(r, nil)
	for _, want := range []string{"step go-test", "37775ms", "TestTenantScope", "tenant_test.go:42"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary missing %q:\n%s", want, sum)
		}
	}
}

func TestCheckupLogExcerptKeepsHeadAndTail(t *testing.T) {
	body := strings.Repeat("a", 100) + "MIDDLE" + strings.Repeat("b", 100)
	got := checkupLogExcerpt([]byte(body), 60)
	if strings.Contains(got, "MIDDLE") {
		t.Error("excerpt should drop the middle")
	}
	if !strings.HasPrefix(got, "aaa") || !strings.HasSuffix(got, "bbb") {
		t.Errorf("excerpt should keep both ends: %q", got)
	}
	short := checkupLogExcerpt([]byte("small output"), 60)
	if short != "small output" {
		t.Errorf("short output should pass through: %q", short)
	}
}
