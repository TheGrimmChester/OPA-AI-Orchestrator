package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// assertJobBindPath requires hostAbs under this job's identity root only —
// /opa-jobs/<id>/… or OPA_REVIEW_TMP/<id>/… (including related/). Soft-accepting
// any path under OPA_REVIEW_TMP allowed cross-job binds.
func assertJobBindPath(hostAbs, jobID string) error {
	hostAbs = filepath.Clean(hostAbs)
	if !filepath.IsAbs(hostAbs) {
		return fmt.Errorf("bind path must be absolute")
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return fmt.Errorf("bind path requires job id")
	}
	id := sanitizeDockerName(jobID)
	wantPrefix := filepath.Join(opaJobsContainerRoot, id)
	if pathUnder(hostAbs, wantPrefix) {
		return nil
	}
	tmp := opaReviewTmpRoot()
	for _, leaf := range []string{jobID, id} {
		if leaf == "" {
			continue
		}
		legacy := filepath.Join(tmp, leaf)
		if pathUnder(hostAbs, legacy) {
			return nil
		}
	}
	return fmt.Errorf("bind path %s is outside identity layout (%s or %s/<id>)", hostAbs, wantPrefix, tmp)
}

func pathUnder(abs, root string) bool {
	root = filepath.Clean(root)
	abs = filepath.Clean(abs)
	if abs == root {
		return true
	}
	prefix := root + string(os.PathSeparator)
	return strings.HasPrefix(abs, prefix)
}

func jobIdentityHostRoot(jobID string) string {
	// Exact /opa-jobs ⇒ identity layout used for docker binds.
	// Do NOT treat paths that merely *end with* "/opa-jobs" (e.g. NAS
	// /mnt/Apps/.../opa-jobs) as /opa-jobs — that made docker-from-docker
	// bind a non-existent host path while checkouts lived elsewhere.
	tmp := opaReviewTmpRoot()
	if tmp == opaJobsContainerRoot {
		return filepath.Join(opaJobsContainerRoot, sanitizeDockerName(jobID))
	}
	return scmJobContainerAbs(jobID)
}

// ensureSandboxWorkWritable chowns the host work tree to the sandbox UID so
// docker --user 65532:65532 can write (npm/composer/node_modules, etc.).
// Best-effort: ignore errors on platforms that disallow chown.
func ensureSandboxWorkWritable(hostDir string) {
	hostDir = filepath.Clean(hostDir)
	if hostDir == "" || hostDir == "/" || hostDir == "." {
		return
	}
	const uid, gid = 65532, 65532
	_ = filepath.Walk(hostDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		_ = os.Chown(path, uid, gid)
		if info.IsDir() {
			_ = os.Chmod(path, 0o775)
		}
		return nil
	})
	// Also fix the layout root (parent of primary|sandbox) when present.
	base := filepath.Base(hostDir)
	if base == "primary" || base == "sandbox" || base == "related" {
		parent := filepath.Dir(hostDir)
		if parent != "" && parent != "/" && underOPAReviewTmp(parent) {
			_ = os.Chown(parent, uid, gid)
			_ = os.Chmod(parent, 0o775)
		}
	}
}
