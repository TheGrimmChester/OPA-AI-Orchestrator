package main

import (
	"os"
	"os/exec"
	"path/filepath"
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
