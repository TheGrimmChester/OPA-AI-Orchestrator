package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	openclient "github.com/TheGrimmChester/open-client-go"
	openlogger "github.com/TheGrimmChester/open-logger-go"
)

func peerOSAConfig(orgID, scope string) openclient.PeerConfig {
	cfg := openclient.PeerFromEnv("PEER_OSA_URL", "ora-api", "osa-api", scope)
	cfg.OrgID = orgID
	return cfg
}

func peerOSACreateSecurityRun(ctx context.Context, org, proj, service, profile string, scanners []string, targetPath, repo, connectorID string, pr int, sha, scmJob, runID string) (map[string]interface{}, error) {
	cfg := peerOSAConfig(org, "runs:write findings:read")
	body := map[string]interface{}{
		"service": service, "profile": profile, "scanners": scanners,
		"target_path": targetPath, "repo_full_name": repo, "pr_number": pr,
		"commit_sha": sha, "scm_job_id": scmJob, "security_run_id": runID,
		"organization_id": org, "project_id": proj,
	}
	// OSA refuses repo_full_name without connector_id (clone credentials live there).
	if id := strings.TrimSpace(connectorID); id != "" {
		body["connector_id"] = id
	}
	var out map[string]interface{}
	err := openclient.PeerJSON(ctx, cfg, http.MethodPost, "/api/security/runs", body, &out)
	return out, err
}

func peerOSAEvaluateGate(ctx context.Context, org, runID, minSev string) (map[string]interface{}, error) {
	cfg := peerOSAConfig(org, "findings:read")
	path := fmt.Sprintf("/api/security/gate?security_run_id=%s&min_severity=%s", runID, minSev)
	var out map[string]interface{}
	err := openclient.PeerJSON(ctx, cfg, http.MethodGet, path, nil, &out)
	return out, err
}

func runSecurityScanViaOSA(runID, org, proj, service, profile string, scanners []string, targetPath, repo, connectorID string, pr int, sha, scmJob string) (bool, error) {
	if strings.TrimSpace(os.Getenv("PEER_OSA_URL")) == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	_, err := peerOSACreateSecurityRun(ctx, org, proj, service, profile, scanners, targetPath, repo, connectorID, pr, sha, scmJob, runID)
	if err != nil {
		openlogger.LogWarn("peer OSA security run failed", map[string]interface{}{"error": err.Error(), "security_run_id": runID})
		return true, err
	}
	return true, nil
}

func peerOSAGetSecurityRun(ctx context.Context, org, runID string) (map[string]interface{}, error) {
	cfg := peerOSAConfig(org, "findings:read")
	var out map[string]interface{}
	err := openclient.PeerJSON(ctx, cfg, http.MethodGet, "/api/security/runs/"+runID, nil, &out)
	return out, err
}

// osaTerminalRunStatus lists the states after which findings are complete.
var osaTerminalRunStatus = map[string]bool{
	"completed": true, "complete": true, "passed": true, "failed": true,
	"error": true, "cancelled": true, "canceled": true, "skipped": true,
}

// osaGateWaitTimeout bounds how long the gate waits for scanners to finish.
func osaGateWaitTimeout() time.Duration {
	return envDurationSec("OPA_GATE_WAIT_TIMEOUT_SEC", 10*time.Minute)
}

// osaGateRunAppearTimeout bounds how long the gate waits for the run to exist at
// all. Shorter than the scan budget: a run that never appears is a broken
// hand-off, and the check should say so quickly.
func osaGateRunAppearTimeout() time.Duration {
	return envDurationSec("OPA_GATE_RUN_APPEAR_TIMEOUT_SEC", 90*time.Second)
}

func envDurationSec(name string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

// awaitOSASecurityRun blocks until the OSA run reaches a terminal state.
// Scanners run asynchronously, so evaluating the gate straight after creating
// the run reads an empty findings set — the check would complete in under a
// second and report a verdict about a scan that had not happened. Returns the
// final status and whether a terminal state was actually observed.
func awaitOSASecurityRun(org, runID string) (string, bool) {
	if strings.TrimSpace(os.Getenv("PEER_OSA_URL")) == "" {
		return "", false
	}
	start := time.Now()
	deadline := start.Add(osaGateWaitTimeout())
	appearBy := start.Add(osaGateRunAppearTimeout())
	delay := 2 * time.Second
	lastStatus := ""
	seen := false
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		run, err := peerOSAGetSecurityRun(ctx, org, runID)
		cancel()
		if err == nil && run != nil {
			status := strings.ToLower(strings.TrimSpace(fmt.Sprint(run["status"])))
			if status != "" && status != "<nil>" {
				seen = true
				lastStatus = status
				if osaTerminalRunStatus[status] {
					return status, true
				}
			}
		} else if err != nil {
			openlogger.LogWarn("peer OSA run status failed", map[string]interface{}{
				"error": err.Error(), "security_run_id": runID,
			})
		}
		now := time.Now()
		if now.After(deadline) {
			return lastStatus, false
		}
		// A run that never appears is a broken hand-off, not a slow scan. Give up
		// on the shorter appearance budget so a misconfigured peer answers in
		// about a minute instead of holding the check open for the full timeout.
		if !seen && now.After(appearBy) {
			return "", false
		}
		time.Sleep(delay)
		if delay < 15*time.Second {
			delay += 2 * time.Second
		}
	}
}

func evaluateScopedGateViaOSA(org, runID, minSev string) (map[string]interface{}, bool) {
	if strings.TrimSpace(os.Getenv("PEER_OSA_URL")) == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := peerOSAEvaluateGate(ctx, org, runID, minSev)
	if err != nil {
		openlogger.LogWarn("peer OSA gate failed", map[string]interface{}{"error": err.Error(), "security_run_id": runID})
		// Transport, auth and 5xx errors all mean "no verdict available". Never
		// present that as a findings failure.
		verdict := gateUnavailable(runID, minSev, "peer_unavailable",
			"could not reach the OSA AppSec gate")
		verdict["error"] = err.Error()
		return verdict, true
	}
	return out, true
}
