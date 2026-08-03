package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	openclient "github.com/TheGrimmChester/open-client-go"
)

func peerOSAConfig(orgID, scope string) openclient.PeerConfig {
	cfg := openclient.PeerFromEnv("PEER_OSA_URL", "ora-api", "osa-api", scope)
	cfg.OrgID = orgID
	return cfg
}

func peerOSACreateSecurityRun(ctx context.Context, org, proj, service, profile string, scanners []string, targetPath, repo string, pr int, sha, scmJob, runID string) (map[string]interface{}, error) {
	cfg := peerOSAConfig(org, "runs:write findings:read")
	body := map[string]interface{}{
		"service": service, "profile": profile, "scanners": scanners,
		"target_path": targetPath, "repo_full_name": repo, "pr_number": pr,
		"commit_sha": sha, "scm_job_id": scmJob, "security_run_id": runID,
		"organization_id": org, "project_id": proj,
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

func runSecurityScanViaOSA(runID, org, proj, service, profile string, scanners []string, targetPath, repo string, pr int, sha, scmJob string) bool {
	if strings.TrimSpace(os.Getenv("PEER_OSA_URL")) == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	_, err := peerOSACreateSecurityRun(ctx, org, proj, service, profile, scanners, targetPath, repo, pr, sha, scmJob, runID)
	if err != nil {
		LogWarn("peer OSA security run failed", map[string]interface{}{"error": err.Error(), "security_run_id": runID})
	}
	return true
}

func evaluateScopedGateViaOSA(org, runID, minSev string) (map[string]interface{}, bool) {
	if strings.TrimSpace(os.Getenv("PEER_OSA_URL")) == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := peerOSAEvaluateGate(ctx, org, runID, minSev)
	if err != nil {
		LogWarn("peer OSA gate failed", map[string]interface{}{"error": err.Error(), "security_run_id": runID})
		return map[string]interface{}{
			"status": "error", "fail": true, "reasons": []string{"peer_unavailable"},
			"scope": "security_run", "security_run_id": runID, "min_severity": minSev,
			"error": err.Error(),
		}, true
	}
	return out, true
}
