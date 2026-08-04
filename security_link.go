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
// A non-nil error means no scan was dispatched — the caller must not report the
// resulting empty finding set as a pass.
func runSecurityScanJob(runID, org, proj, service, profile string, scanners []string, targetPath, image, repo string, pr int, sha, scmJob string) error {
	_ = image
	owned, err := runSecurityScanViaOSA(runID, org, proj, service, profile, scanners, targetPath, repo, pr, sha, scmJob)
	if owned {
		return err
	}
	openlogger.LogWarn("security scan skipped — set PEER_OSA_URL for AppSec runs", map[string]interface{}{
		"security_run_id": runID, "repo": repo,
	})
	return fmt.Errorf("no AppSec scan dispatched: PEER_OSA_URL is not set")
}

// gateNotRun is the gate result for "the scan or the gate never executed".
// evaluated=false marks that no finding data exists, so downstream reporting must
// not present an empty finding set as a clean scan. Still fails closed.
func gateNotRun(runID, minSev, reason, honesty string) map[string]interface{} {
	return map[string]interface{}{
		"status": "error", "fail": true, "evaluated": false,
		"reasons":         []string{reason},
		"scope":           "security_run",
		"security_run_id": runID,
		"min_severity":    minSev,
		"honesty":         honesty,
	}
}

// gateWasEvaluated reports whether the gate actually ran. A missing key means
// evaluated (older persisted summaries and the explicit ai_only result).
func gateWasEvaluated(gate map[string]interface{}) bool {
	if gate == nil {
		return false
	}
	ev, ok := gate["evaluated"].(bool)
	return !ok || ev
}

// evaluateScopedGate prefers OSA AppSec gate via peer; otherwise fail-closed peer_unavailable.
func evaluateScopedGate(org, runID, minSev string) map[string]interface{} {
	if out, ok := evaluateScopedGateViaOSA(org, runID, minSev); ok {
		return out
	}
	return gateNotRun(runID, minSev, "peer_unavailable",
		"AppSec gate is owned by OSA; configure PEER_OSA_URL")
}

// gateStatusLabel is the gate status for user-visible copy. A gate that never
// ran reads as not_evaluated rather than a bare "error", which readers otherwise
// conflate with "scanned, and something went wrong".
func gateStatusLabel(gate map[string]interface{}) string {
	if gate == nil {
		return "unknown"
	}
	if !gateWasEvaluated(gate) {
		return "not_evaluated"
	}
	if s, _ := gate["status"].(string); s != "" {
		return s
	}
	return "unknown"
}

// appSecCheckOutcome renders a gate result for the "AppSec Gate" check run.
// Three distinct outcomes — a gate that could not run must never read like a
// clean scan, so it never reports a finding count.
func appSecCheckOutcome(gate map[string]interface{}, runID string) (conclusion, title, summary string) {
	reasons := gate["reasons"]
	minSev := strFromAny(gate["min_severity"])
	switch {
	case !gateWasEvaluated(gate):
		return "failure", "AppSec Gate could not run — not scanned",
			fmt.Sprintf("not evaluated: no scan result exists, so findings were never counted (this is not a clean scan) — reasons=%v scope=%v security_run_id=%s",
				reasons, gate["scope"], runID)
	case gate["fail"] == true:
		return "failure", "AppSec Gate failed",
			fmt.Sprintf("evaluated: blocking findings at or above %s — reasons=%v scope=%v security_run_id=%s",
				nz(minSev, "high"), reasons, gate["scope"], runID)
	default:
		return "success", "AppSec Gate passed",
			fmt.Sprintf("evaluated: no findings at or above %s — scope=%v security_run_id=%s",
				nz(minSev, "high"), gate["scope"], runID)
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
