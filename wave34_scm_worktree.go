package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Isolated git worktrees for SCM / OPA Review / security scans.
//
//	$OPA_SECURITY_WORKSPACE/cache/github/{owner}__{repo}.git  — bare mirror
//	$OPA_REVIEW_TMP/{job_or_run_id}/
//	  primary/              — PR checkout (default /tmp/opa-review)
//	  related/{owner-repo}/ — sibling clones for cross-repo context
//
// Legacy layout (still cleaned): flat $OPA_REVIEW_TMP/{id} and workspace worktrees|jobs/{id}
//
// OPA_SCAN_WORKTREE_ENFORCE default 1: scanners + AI agent must use the
// isolated checkout, never the shared workspace fixture root for SCM jobs.
//
// Credentials never go in the clone URL — GIT_ASKPASS (+ optional http.extraHeader).

func scanWorktreeEnforce() bool {
	return envOr("OPA_SCAN_WORKTREE_ENFORCE", "1") != "0"
}

// opaReviewTmpRoot is the parent for OPA Review + context-gen checkouts.
func opaReviewTmpRoot() string {
	return filepath.Clean(envOr("OPA_REVIEW_TMP", "/tmp/opa-review"))
}

// scmReviewWorktreeAbs returns the primary PR checkout path under the job container.
func scmReviewWorktreeAbs(id string) string {
	return scmPrimaryCheckoutAbs(id)
}

// underOPAReviewTmp reports whether abs is inside OPA_REVIEW_TMP (or is the root).
func underOPAReviewTmp(abs string) bool {
	abs = filepath.Clean(abs)
	root := opaReviewTmpRoot()
	if abs == root {
		return true
	}
	rel, err := filepath.Rel(root, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// isOPAReviewCheckoutPath is true for abs or display paths under OPA_REVIEW_TMP.
func isOPAReviewCheckoutPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" || p == "." {
		return false
	}
	if filepath.IsAbs(p) {
		return underOPAReviewTmp(p)
	}
	// Relative forms like "opa-review/job-id" are not used; accept cleaned abs only.
	return false
}

// scmWorktreeRel returns the checkout path used as target_path (absolute under OPA_REVIEW_TMP).
func scmWorktreeRel(id string) string {
	return scmReviewWorktreeAbs(id)
}

func sanitizeWorktreeID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.ReplaceAll(id, "/", "_")
	id = strings.ReplaceAll(id, "..", "_")
	if id == "" {
		id = "anon-" + newRandomHex(8)
	}
	if len(id) > 180 {
		id = id[:180]
	}
	return id
}

func scmBareCacheRel(fullName string) string {
	owner, repo := splitOwnerRepo(fullName)
	safe := strings.ReplaceAll(owner, "/", "_") + "__" + strings.ReplaceAll(repo, "/", "_")
	return filepath.Join("cache", "github", safe+".git")
}

func writeMockWorktreeFixture(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(root, "README.md"), []byte("# mock worktree checkout\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "app.js"), []byte("eval(x)\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM alpine:latest\n"), 0o644)
	// Minimal git repo so tools expecting .git still work in mock mode.
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		init := exec.Command("git", "init")
		init.Dir = root
		_ = init.Run()
		_ = exec.Command("git", "-C", root, "config", "user.email", "opa@localhost").Run()
		_ = exec.Command("git", "-C", root, "config", "user.name", "OPA").Run()
		_ = exec.Command("git", "-C", root, "add", "-A").Run()
		_ = exec.Command("git", "-C", root, "commit", "-m", "mock", "--allow-empty").Run()
	}
	return nil
}

// prepareSCMWorktree checks out an isolated tree for a job/run/context-gen.
// Layout: $OPA_REVIEW_TMP/{id}/primary (related siblings under {id}/related/).
// Bare cache stays under OPA_SECURITY_WORKSPACE. Mock / missing credentials →
// fixture in primary/. Real credentials → bare cache + git worktree add at SHA,
// pull/{n}/head, or default HEAD; errors are returned (no silent shared-fixture scan).
func prepareSCMWorktree(c *opaConnector, fullName, sha string, pr int, worktreeID string) (absRoot, relPath string, meta map[string]interface{}, err error) {
	container := scmJobContainerAbs(worktreeID)
	absRoot = scmPrimaryCheckoutAbs(worktreeID)
	relPath = absRoot // scanners + AI use the absolute primary checkout
	if err := os.MkdirAll(opaReviewTmpRoot(), 0o755); err != nil {
		return "", "", nil, fmt.Errorf("OPA_REVIEW_TMP: %w", err)
	}
	meta = map[string]interface{}{
		"worktree_rel": relPath, "worktree_abs": absRoot,
		"job_container": container, "review_tmp": opaReviewTmpRoot(),
		"repo_full_name": fullName, "commit_sha": sha, "pr_number": pr,
		"enforce": scanWorktreeEnforce(), "layout": "primary_related",
	}

	removeSCMJobCheckout(worktreeID, fullName)
	if err := os.MkdirAll(container, 0o755); err != nil {
		return "", "", nil, fmt.Errorf("job container: %w", err)
	}

	useMock := githubUseMockAPI(c) || c == nil || (c.TokenRef == "" && c.InstallationID == "")
	if useMock {
		if err := writeMockWorktreeFixture(absRoot); err != nil {
			return absRoot, relPath, meta, err
		}
		meta["checkout"] = "mock_worktree"
		meta["mock"] = true
		if head := gitRevParse(absRoot); head != "" {
			meta["resolved_sha"] = head
		}
		return absRoot, relPath, meta, nil
	}

	tok, terr := githubAccessToken(c)
	if terr != nil {
		return absRoot, relPath, meta, fmt.Errorf("github token: %w", terr)
	}
	bareRel := scmBareCacheRel(fullName)
	bareAbs, berr := resolveSecurityScanPath(bareRel)
	if berr != nil {
		return absRoot, relPath, meta, berr
	}
	meta["bare_cache"] = bareRel
	meta["auth"] = "git_askpass"
	if err := ensureBareMirror(bareAbs, fullName, tok); err != nil {
		return absRoot, relPath, meta, err
	}

	ref := strings.TrimSpace(sha)
	if ref == "" || strings.HasPrefix(ref, "manual-") || strings.HasPrefix(ref, "cron-") || strings.HasPrefix(ref, "mock") {
		ref = ""
	}
	askEnv, cleanup, aerr := gitAskPassEnv(tok)
	if aerr != nil {
		return absRoot, relPath, meta, aerr
	}
	defer cleanup()

	if ref == "" && pr > 0 {
		pullRef := fmt.Sprintf("refs/pull/%d/head", pr)
		fetch := exec.Command("git", "-C", bareAbs, "fetch", "origin", fmt.Sprintf("pull/%d/head:%s", pr, pullRef))
		fetch.Env = askEnv
		if out, ferr := fetch.CombinedOutput(); ferr != nil {
			return absRoot, relPath, meta, fmt.Errorf("fetch PR head: %v (%s)", ferr, truncateStr(string(out), 240))
		}
		ref = pullRef
		meta["pr_ref"] = pullRef
	}
	if ref == "" {
		// Context-gen / default-branch: detached HEAD of the bare mirror.
		ref = "HEAD"
		meta["ref"] = "default_branch"
	}

	// Prefer worktree add from bare; fallback to clone+checkout into worktree dir.
	add := exec.Command("git", "-C", bareAbs, "worktree", "add", "--detach", absRoot, ref)
	add.Env = askEnv
	if out, aerr := add.CombinedOutput(); aerr != nil {
		// Fallback: shallow clone into worktree path (URL has NO token).
		_ = os.RemoveAll(absRoot)
		cloneURL, uerr := githubHTTPSCloneURL(fullName)
		if uerr != nil {
			return absRoot, relPath, meta, uerr
		}
		clone := exec.Command("git", "clone", "--depth", "50", cloneURL, absRoot)
		clone.Env = askEnv
		if cout, cerr := clone.CombinedOutput(); cerr != nil {
			return absRoot, relPath, meta, fmt.Errorf("worktree add failed (%v: %s); clone fallback: %v (%s)",
				aerr, truncateStr(string(out), 160), cerr, truncateStr(string(cout), 160))
		}
		meta["checkout"] = "clone_fallback"
		if pr > 0 && (sha == "" || strings.HasPrefix(sha, "manual-")) {
			fetchPR := exec.Command("git", "-C", absRoot, "fetch", "origin", fmt.Sprintf("pull/%d/head", pr))
			fetchPR.Env = askEnv
			_ = fetchPR.Run()
			if co := exec.Command("git", "-C", absRoot, "checkout", "FETCH_HEAD"); co.Run() != nil {
				return absRoot, relPath, meta, fmt.Errorf("checkout PR FETCH_HEAD failed")
			}
		} else if sha != "" && !strings.HasPrefix(sha, "manual-") && !strings.HasPrefix(sha, "cron-") {
			co := exec.Command("git", "-C", absRoot, "checkout", sha)
			if out2, cerr := co.CombinedOutput(); cerr != nil {
				return absRoot, relPath, meta, fmt.Errorf("checkout %s: %v (%s)", sha, cerr, truncateStr(string(out2), 160))
			}
		}
	} else {
		meta["checkout"] = "git_worktree"
	}

	resolved := gitRevParse(absRoot)
	if resolved == "" {
		return absRoot, relPath, meta, fmt.Errorf("worktree has no HEAD after checkout")
	}
	meta["resolved_sha"] = resolved
	if sha == "" || strings.HasPrefix(sha, "manual-") || strings.HasPrefix(sha, "cron-") {
		meta["commit_sha"] = resolved
	}
	return absRoot, relPath, meta, nil
}

func ensureBareMirror(bareAbs, fullName, tok string) error {
	unlock, err := withBareMirrorLock(fullName)
	if err != nil {
		return err
	}
	defer unlock()

	cloneURL, err := githubHTTPSCloneURL(fullName)
	if err != nil {
		return err
	}
	askEnv, cleanup, err := gitAskPassEnv(tok)
	if err != nil {
		return err
	}
	defer cleanup()
	if st, err := os.Stat(filepath.Join(bareAbs, "HEAD")); err == nil && !st.IsDir() {
		fetch := exec.Command("git", "-C", bareAbs, "fetch", "--prune", "origin", "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
		fetch.Env = askEnv
		if out, err := fetch.CombinedOutput(); err != nil {
			return fmt.Errorf("bare fetch: %v (%s)", err, truncateStr(string(out), 200))
		}
		return nil
	}
	_ = os.RemoveAll(bareAbs)
	if err := os.MkdirAll(filepath.Dir(bareAbs), 0o755); err != nil {
		return err
	}
	cmd := exec.Command("git", "clone", "--mirror", cloneURL, bareAbs)
	cmd.Env = askEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bare clone: %v (%s)", err, truncateStr(string(out), 240))
	}
	return nil
}

// withBareMirrorLock serializes fetch/clone of a shared bare mirror across
// concurrent jobs on the same repo. Lock files live beside the cache tree.
func withBareMirrorLock(fullName string) (unlock func(), err error) {
	rel := scmBareCacheRel(fullName)
	if rel == "" {
		return func() {}, nil
	}
	bareAbs, err := resolveSecurityScanPath(rel)
	if err != nil {
		return nil, err
	}
	lockDir := filepath.Dir(bareAbs)
	if err := os.MkdirAll(lockDir, 0o755); err != nil {
		return nil, err
	}
	lockPath := bareAbs + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flockExclusive(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("bare mirror flock: %w", err)
	}
	return func() {
		_ = flockUnlock(f)
		_ = f.Close()
	}, nil
}

// gitAskPassEnv installs a short-lived askpass helper so the PAT never appears in
// the clone URL or git remote config. Token lives only in process env for the child.
func gitAskPassEnv(tok string) (env []string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "opa-git-askpass-*")
	if err != nil {
		return nil, func() {}, err
	}
	script := filepath.Join(dir, "askpass.sh")
	// Git may prompt for Username then Password; answer accordingly.
	body := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  *[Uu]sername*) echo x-access-token ;;\n" +
		"  *) echo \"$OPA_GIT_ASKPASS_TOKEN\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, func() {}, err
	}
	env = hostToolEnv(
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS="+script,
		"SSH_ASKPASS="+script,
		"GIT_ASKPASS_REQUIRE=force",
		"OPA_GIT_ASKPASS_TOKEN="+tok,
	)
	return env, func() { _ = os.RemoveAll(dir) }, nil
}

func gitRevParse(root string) string {
	cmd := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func removeSCMWorktree(absRoot, fullName string) {
	if absRoot == "" {
		return
	}
	// Try unlink from bare cache first.
	if fullName != "" {
		if bareRel := scmBareCacheRel(fullName); bareRel != "" {
			if bareAbs, err := resolveSecurityScanPath(bareRel); err == nil {
				rm := exec.Command("git", "-C", bareAbs, "worktree", "remove", "--force", absRoot)
				_ = rm.Run()
				_ = exec.Command("git", "-C", bareAbs, "worktree", "prune").Run()
			}
		}
	}
	_ = os.RemoveAll(absRoot)
}

// removeSCMJobCheckout removes the job container (primary + related siblings).
func removeSCMJobCheckout(worktreeID, primaryFullName string) {
	container := scmJobContainerAbs(worktreeID)
	primary := scmPrimaryCheckoutAbs(worktreeID)
	removeSCMWorktree(primary, primaryFullName)
	// Unlink any related worktrees we may have attached from bare caches.
	relatedRoot := scmRelatedDirAbs(worktreeID)
	if entries, err := os.ReadDir(relatedRoot); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(relatedRoot, e.Name())
			removeSCMWorktree(p, "")
		}
	}
	// Legacy flat layout (pre primary/related).
	legacy := filepath.Join(opaReviewTmpRoot(), sanitizeWorktreeID(worktreeID))
	if legacy != container {
		removeSCMWorktree(legacy, primaryFullName)
	}
	_ = os.RemoveAll(container)
}

func cleanupOldSCMWorktrees(workspace string, maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	cleanupAgedDirs := func(dir string, alsoUnlinkBare bool) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if !info.ModTime().Before(cutoff) {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if alsoUnlinkBare && workspace != "" {
				_ = filepath.Walk(filepath.Join(workspace, "cache", "github"), func(p string, fi os.FileInfo, err error) error {
					if err != nil || fi == nil || !fi.IsDir() || !strings.HasSuffix(p, ".git") {
						return nil
					}
					_ = exec.Command("git", "-C", p, "worktree", "remove", "--force", path).Run()
					_ = exec.Command("git", "-C", p, "worktree", "prune").Run()
					return nil
				})
			}
			_ = os.RemoveAll(path)
		}
	}
	// Primary: OPA Review checkouts under /tmp/opa-review (or OPA_REVIEW_TMP).
	cleanupAgedDirs(opaReviewTmpRoot(), true)
	// Legacy workspace worktrees/jobs.
	if workspace != "" {
		for _, sub := range []string{"worktrees", "jobs"} {
			cleanupAgedDirs(filepath.Join(workspace, sub), true)
		}
	}
}

// resolveScanRootForJob returns the absolute scan root, enforcing isolation for SCM-linked runs.
// Accepts absolute paths under OPA_REVIEW_TMP, or legacy relative worktrees/|jobs/ under the workspace.
func resolveScanRootForJob(targetPath, repo, scmJob, runID string) (string, error) {
	targetPath = strings.TrimSpace(targetPath)
	if filepath.IsAbs(targetPath) || isOPAReviewCheckoutPath(targetPath) {
		cleaned := filepath.Clean(targetPath)
		if !underOPAReviewTmp(cleaned) {
			return "", fmt.Errorf("OPA_SCAN_WORKTREE_ENFORCE: absolute target_path must be under OPA_REVIEW_TMP (%s)", opaReviewTmpRoot())
		}
		return cleaned, nil
	}
	root, err := resolveSecurityScanPath(targetPath)
	if err != nil {
		return "", err
	}
	if !scanWorktreeEnforce() || repo == "" {
		return root, nil
	}
	ws := securityWorkspaceRoot()
	// Must live under worktrees/ (or legacy jobs/) — never bare workspace root.
	rel, rerr := filepath.Rel(ws, root)
	if rerr != nil || rel == "." || rel == "" {
		return "", fmt.Errorf("OPA_SCAN_WORKTREE_ENFORCE: SCM scans require an isolated checkout under %s/{id} or %s/worktrees/{id}, got workspace root", opaReviewTmpRoot(), ws)
	}
	if !strings.HasPrefix(rel, "worktrees"+string(os.PathSeparator)) &&
		!strings.HasPrefix(rel, "jobs"+string(os.PathSeparator)) {
		return "", fmt.Errorf("OPA_SCAN_WORKTREE_ENFORCE: target_path %q must be under OPA_REVIEW_TMP, worktrees/, or jobs/ for repo %s (scm_job=%s run=%s)", targetPath, repo, scmJob, runID)
	}
	return root, nil
}
