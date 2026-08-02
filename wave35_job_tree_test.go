package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeTreeParity(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "primary")
	if err := os.MkdirAll(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = primary
		cmd.Env = hostToolEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v (%s)", args, err, out)
		}
	}
	must("git", "init")
	must("git", "config", "user.email", "t@example.com")
	must("git", "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(primary, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, "b.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	must("git", "add", ".")
	must("git", "commit", "-m", "init")

	dest := filepath.Join(dir, "sandbox")
	n, err := materializeTreeWithCheckoutIndex(primary, dest)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("want 2 files got %d", n)
	}
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		t.Fatal(".git must not appear in materialized tree from checkout-index prefix")
	}
}

func TestMaterializeSandboxTreeForJob(t *testing.T) {
	t.Setenv("OPA_REVIEW_TMP", t.TempDir())
	id := "mat-job-1"
	primary := scmPrimaryCheckoutAbs(id)
	_ = os.MkdirAll(primary, 0o755)
	_ = os.WriteFile(filepath.Join(primary, "x.txt"), []byte("x"), 0o644)
	sb, n, err := materializeSandboxTreeForJob(id, primary)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected files, got %d", n)
	}
	if filepath.Base(sb) != "sandbox" {
		t.Fatalf("path %s", sb)
	}
}

func TestSyncSandboxTreeToPrimary(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "primary")
	sandbox := filepath.Join(dir, "sandbox")
	must := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = hostToolEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v (%s)", args, err, out)
		}
	}
	_ = os.MkdirAll(primary, 0o755)
	must(primary, "git", "init")
	must(primary, "git", "config", "user.email", "t@example.com")
	must(primary, "git", "config", "user.name", "t")
	_ = os.WriteFile(filepath.Join(primary, "keep.go"), []byte("package keep\n"), 0o644)
	_ = os.WriteFile(filepath.Join(primary, "gone.go"), []byte("package gone\n"), 0o644)
	must(primary, "git", "add", ".")
	must(primary, "git", "commit", "-m", "init")

	_, err := materializeTreeWithCheckoutIndex(primary, sandbox)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sandbox, "keep.go"), []byte("package keep\n// patched\n"), 0o644)
	_ = os.WriteFile(filepath.Join(sandbox, "new.go"), []byte("package new\n"), 0o644)
	_ = os.Remove(filepath.Join(sandbox, "gone.go"))

	if err := syncSandboxTreeToPrimary(sandbox, primary); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(primary, "keep.go"))
	if !strings.Contains(string(raw), "patched") {
		t.Fatalf("keep.go not synced: %s", raw)
	}
	if _, err := os.Stat(filepath.Join(primary, "new.go")); err != nil {
		t.Fatal("new.go missing on primary")
	}
	if _, err := os.Stat(filepath.Join(primary, "gone.go")); err == nil {
		t.Fatal("gone.go should be removed from primary")
	}
	if _, err := os.Stat(filepath.Join(primary, ".git")); err != nil {
		t.Fatal("primary .git must remain")
	}
}

func TestMaterializeSandboxTreeForJobGitParity(t *testing.T) {
	t.Setenv("OPA_REVIEW_TMP", t.TempDir())
	id := "mat-git-1"
	primary := scmPrimaryCheckoutAbs(id)
	if err := os.MkdirAll(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = primary
		cmd.Env = hostToolEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v (%s)", args, err, out)
		}
	}
	must("git", "init")
	must("git", "config", "user.email", "t@example.com")
	must("git", "config", "user.name", "t")
	// Path that git archive would drop under export-ignore — checkout-index must keep it.
	secretDir := filepath.Join(primary, "secrets")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "keep.me"), []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, "app.go"), []byte("package app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, ".gitattributes"), []byte("secrets/ export-ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	must("git", "add", ".")
	must("git", "commit", "-m", "init")

	tracked, err := countGitTrackedFiles(primary)
	if err != nil {
		t.Fatal(err)
	}
	sb, n, err := materializeSandboxTreeForJob(id, primary)
	if err != nil {
		t.Fatal(err)
	}
	if n != tracked {
		t.Fatalf("parity: sandbox=%d tracked=%d", n, tracked)
	}
	if _, err := os.Stat(filepath.Join(sb, ".git")); err == nil {
		t.Fatal("sandbox must not contain .git")
	}
	if _, err := os.Stat(filepath.Join(sb, "secrets", "keep.me")); err != nil {
		t.Fatalf("export-ignore path must still materialize via checkout-index: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sb, "app.go")); err != nil {
		t.Fatalf("app.go missing: %v", err)
	}
}

func TestMaterializeTreeParityFailsClosed(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "primary")
	if err := os.MkdirAll(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = primary
		cmd.Env = hostToolEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v (%s)", args, err, out)
		}
	}
	must("git", "init")
	must("git", "config", "user.email", "t@example.com")
	must("git", "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(primary, "only.go"), []byte("package only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	must("git", "add", ".")
	must("git", "commit", "-m", "init")

	dest := filepath.Join(dir, "sandbox")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	// Extra file under dest makes dest_files > src_tracked after checkout-index.
	if err := os.WriteFile(filepath.Join(dest, "noise.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := materializeTreeWithCheckoutIndex(primary, dest)
	if err == nil || !strings.Contains(err.Error(), "tree parity failed") {
		t.Fatalf("want tree parity failed, got %v", err)
	}
}
