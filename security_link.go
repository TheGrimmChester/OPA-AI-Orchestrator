package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// security_run_id helpers — ORA links review jobs to OSA runs; it does not own AppSec.

func securityRunID(parts ...string) string {
	return loadID("srun", parts...)
}

func securityRunIDFromBody(raw []byte) string {
	var body struct {
		SecurityRunID string `json:"security_run_id"`
		RunID         string `json:"run_id"`
	}
	_ = json.Unmarshal(raw, &body)
	return nz(body.SecurityRunID, body.RunID)
}

// runSecurityScanJob delegates to OSA when PEER_OSA_URL is set.
// Empty peer URL skips local AppSec execution (OSA owns scanners).
func runSecurityScanJob(runID, org, proj, service, profile string, scanners []string, targetPath, image, repo string, pr int, sha, scmJob string) {
	_ = image
	if runSecurityScanViaOSA(runID, org, proj, service, profile, scanners, targetPath, repo, pr, sha, scmJob) {
		return
	}
	LogWarn("security scan skipped — set PEER_OSA_URL for AppSec runs", map[string]interface{}{
		"security_run_id": runID, "repo": repo,
	})
}

// evaluateScopedGate prefers OSA AppSec gate via peer; otherwise fail-closed peer_unavailable.
func evaluateScopedGate(org, runID, minSev string) map[string]interface{} {
	if out, ok := evaluateScopedGateViaOSA(org, runID, minSev); ok {
		return out
	}
	return map[string]interface{}{
		"status": "error", "fail": true,
		"reasons":         []string{"peer_unavailable"},
		"scope":           "security_run",
		"security_run_id": runID,
		"min_severity":    minSev,
		"honesty":         "AppSec gate is owned by OSA; configure PEER_OSA_URL",
	}
}

// securityWorkspaceRoot is the review checkout root (not AppSec ownership).
func securityWorkspaceRoot() string {
	return filepath.Clean(envOr("OPA_REVIEW_TMP", envOr("OPA_SECURITY_WORKSPACE", "/tmp/ora-review")))
}

func resolveSecurityScanPath(rel string) (string, error) {
	root := securityWorkspaceRoot()
	rel = strings.TrimSpace(rel)
	if rel == "" || rel == "." {
		return root, nil
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute paths not allowed")
	}
	joined := filepath.Clean(filepath.Join(root, rel))
	relToRoot, err := filepath.Rel(root, joined)
	if err != nil || strings.HasPrefix(relToRoot, "..") {
		return "", fmt.Errorf("path escapes workspace")
	}
	return joined, nil
}

// liveSecurityRun is no longer local — OSA owns run state.
func liveSecurityRun(id string) map[string]interface{} {
	_ = id
	return nil
}

func newRandomHex(n int) string {
	h := sha1.Sum([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())))
	s := hex.EncodeToString(h[:])
	if n > len(s) {
		n = len(s)
	}
	return s[:n]
}
