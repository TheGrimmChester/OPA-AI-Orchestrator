package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// checkupServiceRuntime tracks started sidecars for one job.
type checkupServiceRuntime struct {
	JobID   string
	Network string
	Names   []string // container names
}

// startCheckupServices creates the --internal network and brings up plan
// services. Health gate is fail-closed: neither image HEALTHCHECK nor plan
// health_cmd ⇒ error (never "assume running").
func startCheckupServices(ctx context.Context, jobID string, services []checkupService) (*checkupServiceRuntime, error) {
	rt := &checkupServiceRuntime{JobID: jobID}
	if len(services) == 0 {
		return rt, nil
	}
	if sandboxMode() != "docker" {
		return nil, fmt.Errorf("checkup services require OPA_JOB_SANDBOX=docker")
	}
	if err := requireDockerCLI(); err != nil {
		return nil, err
	}
	netName, err := createJobInternalNetwork(ctx, jobID)
	if err != nil {
		return nil, err
	}
	rt.Network = netName

	for _, svc := range services {
		name := checkupServiceContainerName(jobID, svc.Key)
		_ = dockerRmForce(ctx, name)

		envFile := ""
		var cleanup func()
		if len(svc.Env) > 0 {
			lines := envSliceSorted(svc.Env)
			envFile, cleanup, err = writeSandboxEnvFile(lines)
			if err != nil {
				_ = stopCheckupServices(context.Background(), rt)
				return nil, err
			}
		}
		argv, err := buildDockerServiceArgv(dockerServiceSpec{
			Name: name, Image: svc.Image, JobID: jobID,
			Network: netName, NetworkAlias: svc.Key,
			EnvFile: envFile, Memory: nz(svc.Memory, checkupDefaultSvcMemory),
			CPUs: nz(svc.CPUs, checkupDefaultSvcCPUs),
		})
		if err != nil {
			if cleanup != nil {
				cleanup()
			}
			_ = stopCheckupServices(context.Background(), rt)
			return nil, fmt.Errorf("service %s argv: %w", svc.Key, err)
		}
		out, runErr := dockerCmd(ctx, argv...)
		if cleanup != nil {
			cleanup()
		}
		if runErr != nil {
			_ = stopCheckupServices(context.Background(), rt)
			return nil, fmt.Errorf("service %s start: %w (%s)", svc.Key, runErr, truncateStr(string(out), 200))
		}
		rt.Names = append(rt.Names, name)

		timeout := time.Duration(nzInt(svc.HealthTimeoutSec, checkupDefaultServiceTimeout)) * time.Second
		if err := waitCheckupServiceHealthy(ctx, name, svc.HealthCmd, timeout); err != nil {
			_ = stopCheckupServices(context.Background(), rt)
			return nil, fmt.Errorf("service %s health: %w", svc.Key, err)
		}
	}
	return rt, nil
}

// stopCheckupServices removes checkup sidecars and the checkup job's own
// boxes. Callers must pass the checkup *child* job id (not the shared RunID),
// otherwise teardown would kill concurrent review/scan siblings.
func stopCheckupServices(ctx context.Context, rt *checkupServiceRuntime) error {
	if rt == nil {
		return nil
	}
	for _, name := range rt.Names {
		_ = dockerRmForce(ctx, name)
	}
	if rt.JobID != "" {
		// Phase-scoped: only containers named …-checkup / …-svc-* for this id.
		_ = teardownCheckupJobContainers(ctx, rt.JobID)
		_ = removeJobInternalNetwork(ctx, rt.JobID)
	}
	rt.Names = nil
	return nil
}

// teardownCheckupJobContainers removes containers for one checkup child id
// that are clearly checkup-owned (name suffix -checkup or -svc-).
func teardownCheckupJobContainers(ctx context.Context, jobID string) error {
	if sandboxMode() != "docker" {
		return nil
	}
	out, err := dockerCmd(ctx, "ps", "-aq", "--filter", "label=opa.job="+sanitizeDockerName(jobID))
	if err != nil {
		return err
	}
	for _, id := range strings.Fields(string(out)) {
		nameOut, _ := dockerCmd(ctx, "inspect", "-f", "{{.Name}}", id)
		name := strings.TrimPrefix(strings.TrimSpace(string(nameOut)), "/")
		if strings.HasSuffix(name, "-checkup") || strings.Contains(name, "-svc-") {
			_, _ = dockerCmd(ctx, "rm", "-fv", id)
		}
	}
	return nil
}

func checkupServiceContainerName(jobID, key string) string {
	return "opa-job-" + sanitizeDockerName(jobID) + "-svc-" + sanitizeDockerName(key)
}

type dockerServiceSpec struct {
	Name         string
	Image        string
	JobID        string
	Network      string
	NetworkAlias string
	EnvFile      string
	Memory       string
	CPUs         string
}

// buildDockerServiceArgv builds argv for a sidecar. Deliberately NOT using the
// job-box builder: services need no --user / no --read-only (mysql datadir init).
// Still: cap-drop ALL, no-new-privileges, no -p, no docker.sock, no --privileged.
func buildDockerServiceArgv(spec dockerServiceSpec) ([]string, error) {
	if strings.TrimSpace(spec.Image) == "" {
		return nil, fmt.Errorf("service image required")
	}
	if strings.TrimSpace(spec.JobID) == "" {
		return nil, fmt.Errorf("job id required")
	}
	name := nz(strings.TrimSpace(spec.Name), checkupServiceContainerName(spec.JobID, "svc"))
	mem := nz(spec.Memory, checkupDefaultSvcMemory)
	cpus := nz(spec.CPUs, checkupDefaultSvcCPUs)
	argv := []string{
		"run", "-d", "--rm",
		"--name", name,
		"--label", "opa.owner=opa-orchestrator",
		"--label", "opa.instance=" + opaInstanceID(),
		"--label", "opa.job=" + sanitizeDockerName(spec.JobID),
		"--label", "opa.role=service",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--memory", mem,
		"--memory-swap", mem,
		"--cpus", cpus,
		"--pids-limit", "256",
		"--stop-timeout", "5",
	}
	net := strings.TrimSpace(spec.Network)
	if net == "" {
		return nil, fmt.Errorf("service network required")
	}
	argv = append(argv, "--network", net)
	if alias := strings.TrimSpace(spec.NetworkAlias); alias != "" {
		argv = append(argv, "--network-alias", alias)
	}
	if ef := strings.TrimSpace(spec.EnvFile); ef != "" {
		if !filepath.IsAbs(ef) {
			return nil, fmt.Errorf("env-file must be absolute")
		}
		argv = append(argv, "--env-file", ef)
	}
	argv = append(argv, spec.Image)
	if err := validateDockerRunArgv(argv); err != nil {
		return nil, err
	}
	// Service boxes intentionally omit --user/--read-only — validate did not require them.
	return argv, nil
}

func waitCheckupServiceHealthy(ctx context.Context, name string, healthCmd []string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = time.Duration(checkupDefaultServiceTimeout) * time.Second
	}
	deadline := time.Now().Add(timeout)

	hasImageHealth, err := containerHasHealthcheck(ctx, name)
	if err != nil {
		return err
	}
	if !hasImageHealth && len(healthCmd) == 0 {
		return fmt.Errorf("fail-closed: neither image HEALTHCHECK nor plan health_cmd for %s", name)
	}

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if hasImageHealth {
			st, _ := containerHealthStatus(ctx, name)
			if st == "healthy" {
				return nil
			}
			if st == "unhealthy" {
				return fmt.Errorf("container %s unhealthy", name)
			}
		} else {
			out, err := dockerCmd(ctx, append([]string{"exec", name}, healthCmd...)...)
			if err == nil {
				return nil
			}
			_ = out
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("health timeout after %s for %s", timeout, name)
}

func containerHasHealthcheck(ctx context.Context, name string) (bool, error) {
	out, err := dockerCmd(ctx, "inspect", "-f", "{{if .Config.Healthcheck}}yes{{else}}no{{end}}", name)
	if err != nil {
		return false, fmt.Errorf("inspect healthcheck: %w (%s)", err, truncateStr(string(out), 120))
	}
	return strings.TrimSpace(string(out)) == "yes", nil
}

func containerHealthStatus(ctx context.Context, name string) (string, error) {
	out, err := dockerCmd(ctx, "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", name)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func nzInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
