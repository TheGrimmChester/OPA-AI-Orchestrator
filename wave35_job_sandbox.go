package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// jobSandboxRunner isolates untrusted phases. Host runner is the default
// (OPA_JOB_SANDBOX=off). Docker runner is selected when mode=docker.
type jobSandboxRunner interface {
	Name() string
	RunOnce(ctx context.Context, spec sandboxExecSpec) ([]byte, error)
}

type sandboxExecSpec struct {
	Phase       jobPhase
	JobID       string
	HostWorkDir string // absolute host path of the tree to scan/review
	WorkRel     string // primary|related/...
	Argv        []string
	Secrets     map[string]string // delivered only via docker exec --env
	ExtraEnv    map[string]string // non-secret → env-file / host env
	ReadOnly    bool
	Network     string
	Timeout     time.Duration
	Image       string
	// Ephemeral runs `docker run --rm … image argv` (no sleep/exec). Use for
	// one-shot tools like gitleaks. OutHostDir is bind-mounted at /out (rw).
	Ephemeral  bool
	OutHostDir string
}

func getSandboxRunner() jobSandboxRunner {
	switch sandboxMode() {
	case "docker":
		return dockerSandboxRunner{}
	default:
		return hostSandboxRunner{}
	}
}

type hostSandboxRunner struct{}

func (hostSandboxRunner) Name() string { return "host" }

func (hostSandboxRunner) RunOnce(ctx context.Context, spec sandboxExecSpec) ([]byte, error) {
	if len(spec.Argv) == 0 {
		return nil, fmt.Errorf("empty argv")
	}
	env := jobEnv(jobEnvSpec{
		Phase:        spec.Phase,
		WorktreeRoot: spec.HostWorkDir,
		Secrets:      spec.Secrets,
		Extra:        spec.ExtraEnv,
	})
	cmd := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
	if spec.HostWorkDir != "" {
		cmd.Dir = spec.HostWorkDir
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	out = redactJobOutput(out, secretValues(spec.Secrets)...)
	return out, err
}

type dockerSandboxRunner struct{}

func (dockerSandboxRunner) Name() string { return "docker" }

func (dockerSandboxRunner) RunOnce(ctx context.Context, spec sandboxExecSpec) ([]byte, error) {
	if err := requireDockerCLI(); err != nil {
		if allowHostExecFallback() {
			LogWarn("sandbox docker unavailable — OPA_JOB_ALLOW_HOST_EXEC=1 falling back to host", map[string]interface{}{
				"error": err.Error(), "honesty": "UNSANDBOXED: tools ran as root",
			})
			return hostSandboxRunner{}.RunOnce(ctx, spec)
		}
		return nil, err
	}
	if len(spec.Argv) == 0 {
		return nil, fmt.Errorf("empty argv")
	}
	jobID := nz(spec.JobID, "anon")
	image := nz(spec.Image, sandboxImageForPhase(spec.Phase))
	hostDir := filepath.Clean(spec.HostWorkDir)
	if hostDir == "" || !filepath.IsAbs(hostDir) {
		return nil, fmt.Errorf("HostWorkDir must be absolute")
	}
	if err := assertJobBindPath(hostDir, jobID); err != nil {
		if !underOPAReviewTmp(hostDir) && !strings.Contains(hostDir, "/opa-jobs/") {
			return nil, err
		}
	}

	envSpec := jobEnvSpec{
		Phase:        spec.Phase,
		WorktreeRoot: containerWorkPath(jobID, spec.WorkRel),
		Extra:        spec.ExtraEnv,
	}

	net := nz(spec.Network, "none")
	if net == networkModeInternalProxy {
		jobNet, err := prepareAIJobNetwork(ctx, jobID)
		if err != nil {
			return nil, fmt.Errorf("ai job network: %w", err)
		}
		net = jobNet
		if envSpec.Extra == nil {
			envSpec.Extra = map[string]string{}
		}
		for k, v := range egressProxyEnvVars() {
			envSpec.Extra[k] = v
		}
	}

	envFile, cleanup, err := writeSandboxEnvFile(jobEnv(envSpec))
	if err != nil {
		return nil, err
	}
	defer cleanup()

	name := "opa-job-" + sanitizeDockerName(jobID) + "-" + string(spec.Phase)
	_ = dockerRmForce(ctx, name)

	extraBinds := []string{}
	if spec.OutHostDir != "" {
		outDir := filepath.Clean(spec.OutHostDir)
		if !filepath.IsAbs(outDir) {
			return nil, fmt.Errorf("OutHostDir must be absolute")
		}
		_ = os.MkdirAll(outDir, 0o755)
		extraBinds = append(extraBinds, outDir+":/out:rw")
	}

	if spec.Ephemeral {
		runArgv, err := buildDockerRunArgv(dockerRunSpec{
			Name: name, Image: image, JobID: jobID, InstanceID: opaInstanceID(),
			WorkHostPath: hostDir, WorkRel: nz(spec.WorkRel, "primary"),
			ReadOnlyBind: spec.ReadOnly, Network: net,
			EnvFile: envFile, PidsLimit: pidsForPhase(spec.Phase),
			Rm: true, ExtraBinds: extraBinds, Command: spec.Argv,
		})
		if err != nil {
			return nil, err
		}
		out, err := dockerCmd(ctx, runArgv...)
		out = redactJobOutput(out, secretValues(spec.Secrets)...)
		return out, err
	}

	runArgv, err := buildDockerRunArgv(dockerRunSpec{
		Name: name, Image: image, JobID: jobID, InstanceID: opaInstanceID(),
		WorkHostPath: hostDir, WorkRel: nz(spec.WorkRel, "primary"),
		ReadOnlyBind: spec.ReadOnly, Network: net,
		EnvFile: envFile, PidsLimit: pidsForPhase(spec.Phase),
		ExtraBinds: extraBinds,
	})
	if err != nil {
		return nil, err
	}
	if out, err := dockerCmd(ctx, runArgv...); err != nil {
		return out, fmt.Errorf("docker run: %w (%s)", err, truncateStr(string(out), 200))
	}
	defer func() { _ = dockerRmForce(context.Background(), name) }()

	execArgv := []string{"exec"}
	for k, v := range spec.Secrets {
		if strings.TrimSpace(v) == "" {
			continue
		}
		execArgv = append(execArgv, "--env", k+"="+v)
	}
	execArgv = append(execArgv, name)
	execArgv = append(execArgv, spec.Argv...)
	out, err := dockerCmd(ctx, execArgv...)
	out = redactJobOutput(out, secretValues(spec.Secrets)...)
	return out, err
}

func pidsForPhase(phase jobPhase) int {
	switch phase {
	case jobPhaseReview, jobPhaseContext:
		return 1024
	default:
		return 512
	}
}

func secretValues(m map[string]string) []string {
	out := []string{}
	for _, v := range m {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func requireDockerCLI() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker CLI not found (OPA_JOB_SANDBOX=docker requires docker); set OPA_JOB_SANDBOX=off or OPA_JOB_ALLOW_HOST_EXEC=1: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := dockerCmd(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		return fmt.Errorf("docker daemon unreachable: %w (%s)", err, truncateStr(string(out), 120))
	}
	return nil
}

func allowHostExecFallback() bool {
	return strings.TrimSpace(os.Getenv("OPA_JOB_ALLOW_HOST_EXEC")) == "1"
}

func dockerCmd(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func dockerRmForce(ctx context.Context, name string) error {
	_, err := dockerCmd(ctx, "rm", "-fv", name)
	return err
}

func writeSandboxEnvFile(env []string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "opa-job-env-*.env")
	if err != nil {
		return "", func() {}, err
	}
	path = f.Name()
	cleanup = func() { _ = os.Remove(path) }
	_ = os.Chmod(path, 0o600)
	var b strings.Builder
	for _, line := range env {
		// env-file format: KEY=VAL — skip empty; refuse lines that look like secrets
		if i := strings.IndexByte(line, '='); i > 0 {
			key := line[:i]
			if envNameLooksSecret(key) {
				continue
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, err
	}
	_ = f.Close()
	return path, cleanup, nil
}

func containerWorkPath(jobID, rel string) string {
	rel = strings.Trim(nz(rel, "primary"), "/")
	return opaJobsContainerRoot + "/" + sanitizeDockerName(jobID) + "/" + rel
}

// runSandboxedArgv is the shared entry used by gitleaks + agent launch.
func runSandboxedArgv(ctx context.Context, spec sandboxExecSpec) ([]byte, error) {
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}
	return getSandboxRunner().RunOnce(ctx, spec)
}
