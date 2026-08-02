package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// assertJobBindPath prefers the identity layout /opa-jobs/<id>/… so prompts and
// container mounts agree when OPA_REVIEW_TMP=/opa-jobs.
func assertJobBindPath(hostAbs, jobID string) error {
	hostAbs = filepath.Clean(hostAbs)
	if !filepath.IsAbs(hostAbs) {
		return fmt.Errorf("bind path must be absolute")
	}
	id := sanitizeDockerName(jobID)
	wantPrefix := filepath.Join(opaJobsContainerRoot, id)
	// On the host the same identity path may be used when compose sets
	// OPA_REVIEW_TMP=/opa-jobs.
	if strings.HasPrefix(hostAbs, wantPrefix+string(os.PathSeparator)) || hostAbs == wantPrefix {
		return nil
	}
	// Also accept OPA_REVIEW_TMP/{id}/primary layout (legacy + current default).
	tmp := opaReviewTmpRoot()
	legacy := filepath.Join(tmp, jobID)
	if strings.HasPrefix(hostAbs, legacy+string(os.PathSeparator)) || hostAbs == legacy {
		return nil
	}
	// Soft accept: any path under OPA_REVIEW_TMP (related checkouts, etc.).
	if underOPAReviewTmp(hostAbs) {
		return nil
	}
	return fmt.Errorf("bind path %s is outside identity layout (%s or %s)", hostAbs, wantPrefix, legacy)
}

func jobIdentityHostRoot(jobID string) string {
	// Prefer /opa-jobs when OPA_REVIEW_TMP points there; else OPA_REVIEW_TMP/{id}.
	tmp := opaReviewTmpRoot()
	if tmp == opaJobsContainerRoot || strings.HasSuffix(tmp, opaJobsContainerRoot) {
		return filepath.Join(opaJobsContainerRoot, sanitizeDockerName(jobID))
	}
	return filepath.Join(tmp, jobID)
}
