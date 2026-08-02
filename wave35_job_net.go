package main

import (
	"context"
	"fmt"
	"strings"
)

// createJobInternalNetwork creates an --internal bridge with no default route.
// The shared allowlist egress proxy is attached via attachEgressProxyToJobNetwork;
// the boundary is the missing default route, not HTTPS_PROXY.
func createJobInternalNetwork(ctx context.Context, jobID string) (string, error) {
	name := "opa-job-" + sanitizeDockerName(jobID)
	if sandboxMode() != "docker" {
		return name, nil
	}
	if err := requireDockerCLI(); err != nil {
		return "", err
	}
	// Ignore "already exists".
	out, err := dockerCmd(ctx, "network", "create", "--internal", name)
	if err != nil && !strings.Contains(strings.ToLower(string(out)+err.Error()), "already") {
		return "", fmt.Errorf("network create: %w (%s)", err, truncateStr(string(out), 160))
	}
	return name, nil
}

func removeJobInternalNetwork(ctx context.Context, jobID string) error {
	if sandboxMode() != "docker" {
		return nil
	}
	if err := requireDockerCLI(); err != nil {
		return nil
	}
	name := "opa-job-" + sanitizeDockerName(jobID)
	// Shared egress proxy may still be attached; disconnect so network rm succeeds.
	detachEgressProxyFromNetwork(ctx, name)
	_, _ = dockerCmd(ctx, "network", "rm", name)
	return nil
}
