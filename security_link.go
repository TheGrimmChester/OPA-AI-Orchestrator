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
	openlogger "github.com/TheGrimmChester/open-logger-go"
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
// The returned error reports a failed hand-off so the caller can mark the gate
// unavailable rather than reading findings from a run that never started.
func runSecurityScanJob(runID, org, proj, service, profile string, scanners []string, targetPath, image, repo string, pr int, sha, scmJob string) error {
	_ = image
	peered, err := runSecurityScanViaOSA(runID, org, proj, service, profile, scanners, targetPath, repo, pr, sha, scmJob)
	if peered {
		return err
	}
	openlogger.LogWarn("security scan skipped — set PEER_OSA_URL for AppSec runs", map[string]interface{}{
		"security_run_id": runID, "repo": repo,
	})
	return nil
}

// gateAfterScan waits for the OSA run to finish, then evaluates the gate.
// startErr is the hand-off error from runSecurityScanJob, if any. Every path
// that cannot produce a real verdict returns an unavailable one.
func gateAfterScan(org, runID, minSev string, startErr error) map[string]interface{} {
	if startErr != nil {
		v := gateUnavailable(runID, minSev, "scan_not_started",
			"the security run could not be created on OSA")
		v["error"] = startErr.Error()
		return v
	}
	if status, terminal := awaitOSASecurityRun(org, runID); !terminal {
		// No peer configured falls through to evaluateScopedGate, which reports
		// peer_not_configured. A configured peer that never finished is a timeout.
		if strings.TrimSpace(os.Getenv("PEER_OSA_URL")) != "" {
			v := gateUnavailable(runID, minSev, "scan_incomplete",
				"the security run did not reach a terminal state before the gate timeout")
			if status != "" {
				v["last_status"] = status
			}
			return v
		}
	}
	return evaluateScopedGate(org, runID, minSev)
}

// evaluateScopedGate asks the OSA AppSec gate over the peer link. When no peer
// is configured the gate is unavailable, not failing — ORA owns review and must
// not invent a security verdict it cannot obtain.
func evaluateScopedGate(org, runID, minSev string) map[string]interface{} {
	if out, ok := evaluateScopedGateViaOSA(org, runID, minSev); ok {
		return out
	}
	return gateUnavailable(runID, minSev, "peer_not_configured",
		"AppSec gate is owned by OSA; configure PEER_OSA_URL")
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
