package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// reapOrphanJobContainers removes containers labelled opa.owner=opa-orchestrator
// for *this* instance only — never by owner alone (would kill a second
// orchestrator's live jobs during local multi-instance development).
func reapOrphanJobContainers(ctx context.Context) (removed int, err error) {
	if sandboxMode() != "docker" {
		return 0, nil
	}
	if err := requireDockerCLI(); err != nil {
		return 0, nil // quiet when docker unused
	}
	instance := opaInstanceID()
	out, err := dockerCmd(ctx, "ps", "-aq",
		"--filter", "label=opa.owner=opa-orchestrator",
		"--filter", "label=opa.instance="+instance,
	)
	if err != nil {
		return 0, err
	}
	ids := strings.Fields(string(out))
	for _, id := range ids {
		// Keep the long-lived shared egress proxy across reaper runs.
		roleOut, _ := dockerCmd(ctx, "inspect", "-f", "{{index .Config.Labels \"opa.role\"}}", id)
		if strings.TrimSpace(string(roleOut)) == egressProxyRoleLabel {
			continue
		}
		if _, err := dockerCmd(ctx, "rm", "-fv", id); err == nil {
			removed++
		}
	}
	return removed, nil
}

// teardownJobContainers removes every container for one job id.
func teardownJobContainers(ctx context.Context, jobID string) error {
	return teardownContainersByLabel(ctx, "opa.job", jobID)
}

// teardownJobContainersByRun removes containers labeled opa.run=<runID>
// (children that shared the parent run's network/layout).
func teardownJobContainersByRun(ctx context.Context, runID string) error {
	return teardownContainersByLabel(ctx, "opa.run", runID)
}

// dockerLabelFilter builds a `docker ps --filter` label selector. Teardown
// paths must use opa.run / opa.job through this helper so the filter shape
// stays testable without a live docker daemon.
func dockerLabelFilter(key, value string) string {
	return "label=" + key + "=" + sanitizeDockerName(value)
}

func teardownContainersByLabel(ctx context.Context, key, value string) error {
	if sandboxMode() != "docker" {
		return nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if _, err := dockerCmd(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return nil
	}
	out, err := dockerCmd(ctx, "ps", "-aq", "--filter", dockerLabelFilter(key, value))
	if err != nil {
		return err
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return nil
	}
	args := append([]string{"rm", "-fv"}, ids...)
	_, err = dockerCmd(ctx, args...)
	return err
}

// enforceJobDiskBudget fails closed when free space under the jobs root is low.
func enforceJobDiskBudget(jobsRoot string) error {
	minGB := 2.0
	if v := strings.TrimSpace(os.Getenv("OPA_JOB_MIN_FREE_GB")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			minGB = f
		}
	}
	free, err := freeBytesUnder(jobsRoot)
	if err != nil {
		return nil // don't block if statfs unavailable
	}
	need := uint64(minGB * 1024 * 1024 * 1024)
	if free < need {
		return fmt.Errorf("job disk budget: %.2f GiB free under %s (need ≥ %.1f GiB)",
			float64(free)/(1024*1024*1024), jobsRoot, minGB)
	}
	return nil
}

func freeBytesUnder(path string) (uint64, error) {
	path = filepath.Clean(path)
	if path == "" {
		path = opaReviewTmpRoot()
	}
	_ = os.MkdirAll(path, 0o755)
	return diskFreeBytes(path)
}

// bootSandboxMaintenance runs once at process start when docker mode is on.
func bootSandboxMaintenance() {
	if sandboxMode() != "docker" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if n, err := reapOrphanJobContainers(ctx); err != nil {
		LogWarn("sandbox reaper", map[string]interface{}{"error": err.Error()})
	} else if n > 0 {
		LogInfo("sandbox reaper removed orphan containers", map[string]interface{}{"removed": n, "instance": opaInstanceID()})
	}
	if egressProxyEnabled() {
		if _, err := ensureSharedEgressProxy(ctx); err != nil {
			LogWarn("egress proxy ensure", map[string]interface{}{"error": err.Error()})
		}
	}
	if err := enforceJobDiskBudget(opaReviewTmpRoot()); err != nil {
		LogWarn("sandbox disk budget", map[string]interface{}{"error": err.Error()})
	}
}
