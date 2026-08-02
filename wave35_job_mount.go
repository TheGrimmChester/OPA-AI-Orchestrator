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
	// Prefer /opa-jobs when OPA_REVIEW_TMP points there; else OPA_REVIEW_TMP/{id}.
	tmp := opaReviewTmpRoot()
	if tmp == opaJobsContainerRoot || strings.HasSuffix(tmp, opaJobsContainerRoot) {
		return filepath.Join(opaJobsContainerRoot, sanitizeDockerName(jobID))
	}
	return filepath.Join(tmp, jobID)
}
