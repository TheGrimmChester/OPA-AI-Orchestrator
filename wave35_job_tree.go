package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// materializeSandboxTreeForJob writes a no-.git tree under {job}/sandbox using
// checkout-index (never git archive). Used when OPA_JOB_SANDBOX=docker so
// export-ignore cannot shrink the scanned surface.
func materializeSandboxTreeForJob(worktreeID, primaryAbs string) (sandboxAbs string, fileCount int, err error) {
	primaryAbs = filepath.Clean(primaryAbs)
	if primaryAbs == "" {
		return "", 0, fmt.Errorf("empty primary")
	}
	container := scmJobContainerAbs(worktreeID)
	sandboxAbs = filepath.Join(container, "sandbox")
	_ = os.RemoveAll(sandboxAbs)
	if err := os.MkdirAll(sandboxAbs, 0o755); err != nil {
		return "", 0, err
	}
	// Non-git fixture (rare): copy files as-is and skip parity.
	if _, err := os.Stat(filepath.Join(primaryAbs, ".git")); err != nil {
		n, cerr := copyTreeFiles(primaryAbs, sandboxAbs)
		return sandboxAbs, n, cerr
	}
	n, err := materializeTreeWithCheckoutIndex(primaryAbs, sandboxAbs)
	if err != nil {
		return sandboxAbs, n, err
	}
	// Ensure no .git leaked into the sandbox tree.
	_ = os.RemoveAll(filepath.Join(sandboxAbs, ".git"))
	return sandboxAbs, n, nil
}

func copyTreeFiles(src, dst string) (int, error) {
	n := 0
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil || rel == "." {
			return err
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(os.PathSeparator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, raw, info.Mode().Perm()); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}

// materializeTreeWithCheckoutIndex copies the index of a git worktree into dest
// using `git checkout-index -a` (NOT git archive — export-ignore would shrink
// the scanned tree and bypass the secrets gate).
func materializeTreeWithCheckoutIndex(srcWorktree, dest string) (fileCount int, err error) {
	srcWorktree = filepath.Clean(srcWorktree)
	dest = filepath.Clean(dest)
	if srcWorktree == "" || dest == "" {
		return 0, fmt.Errorf("src and dest required")
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0, err
	}
	srcCount, err := countGitTrackedFiles(srcWorktree)
	if err != nil {
		return 0, err
	}
	prefix := dest + string(os.PathSeparator)
	cmd := exec.Command("git", "-C", srcWorktree, "checkout-index", "-a", "--prefix="+prefix)
	cmd.Env = hostToolEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("checkout-index: %w (%s)", err, truncateStr(string(out), 200))
	}
	dstCount, err := countFilesUnder(dest)
	if err != nil {
		return 0, err
	}
	if srcCount != dstCount {
		return dstCount, fmt.Errorf("tree parity failed: src_tracked=%d dest_files=%d (export-ignore or materializer bug)", srcCount, dstCount)
	}
	return dstCount, nil
}

func countGitTrackedFiles(worktree string) (int, error) {
	cmd := exec.Command("git", "-C", worktree, "ls-files", "-z")
	cmd.Env = hostToolEnv()
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	if len(out) == 0 {
		return 0, nil
	}
	n := 0
	for _, p := range strings.Split(string(out), "\x00") {
		if strings.TrimSpace(p) != "" {
			n++
		}
	}
	return n, nil
}

func countFilesUnder(root string) (int, error) {
	n := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			n++
		}
		return nil
	})
	return n, err
}
