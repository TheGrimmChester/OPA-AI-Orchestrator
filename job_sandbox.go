package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	openlogger "github.com/TheGrimmChester/open-logger-go"
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
	Secrets     map[string]string // delivered only via docker exec --env-file
	ExtraEnv    map[string]string // non-secret → env-file / host env
	ReadOnly    bool
	Network     string
	Timeout     time.Duration
	Image       string
	// Ephemeral runs `docker run --rm … image argv` (no sleep/exec). Use for
	// one-shot tools like gitleaks. OutHostDir is bind-mounted at /out (rw).
	Ephemeral  bool
	OutHostDir string
	// NameSuffix disambiguates concurrent same-phase boxes; empty → random.
	NameSuffix string
	// LayoutID is the worktree identity used for bind-path checks (often the
	// run id). Empty → JobID. NetworkID names the docker network (shared AI
	// egress); empty → JobID. When LayoutID/NetworkID differ from JobID, boxes
	// also get label opa.run=<id> so parent-run cancel can reap them.
	LayoutID  string
	NetworkID string
	// LivePhase / LiveUnit drive mid-run artifacts/live.log + Summary["live"].
	// LivePhase overrides string(Phase) when set (e.g. "synth").
	LivePhase string
	LiveUnit  string
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
	if hostPhaseNeedsHonestyStamp(spec.Phase) {
		stampSandboxHonesty(spec.JobID, "UNSANDBOXED: OPA_JOB_SANDBOX=off — exec-untrusted phase ran on host")
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
	sink := liveSinkForSpec(spec)
	defer sink.Close()
	out, err := runCmdWithLiveSink(cmd, sink)
	out = redactJobOutput(out, secretValues(spec.Secrets)...)
	return out, err
}

func hostPhaseNeedsHonestyStamp(phase jobPhase) bool {
	switch phase {
	case jobPhaseReview, jobPhaseContext, jobPhaseScan, jobPhaseAutofix, jobPhaseCheckup, jobPhaseAITask:
		return true
	default:
		return false
	}
}

type dockerSandboxRunner struct{}

func (dockerSandboxRunner) Name() string { return "docker" }

func (dockerSandboxRunner) RunOnce(ctx context.Context, spec sandboxExecSpec) ([]byte, error) {
	if err := requireDockerCLI(); err != nil {
		if allowHostExecFallback() {
			stampSandboxHonesty(spec.JobID, "UNSANDBOXED: tools ran as root (OPA_JOB_ALLOW_HOST_EXEC=1)")
			openlogger.LogWarn("sandbox docker unavailable — OPA_JOB_ALLOW_HOST_EXEC=1 falling back to host", map[string]interface{}{
				"error": err.Error(), "honesty": "UNSANDBOXED: tools ran as root", "job_id": spec.JobID,
			})
			hostSpec := spec
			if len(hostSpec.Argv) > 0 && hostSpec.Argv[0] == "/opt/opa/agent" {
				hostSpec.Argv = append([]string{}, hostSpec.Argv...)
				hostSpec.Argv[0] = resolveAgentBinForRunner("host")
			}
			return hostSandboxRunner{}.RunOnce(ctx, hostSpec)
		}
		return nil, err
	}
	if len(spec.Argv) == 0 {
		return nil, fmt.Errorf("empty argv")
	}
	jobID := nz(spec.JobID, "anon")
	layoutID := nz(spec.LayoutID, jobID)
	networkID := nz(spec.NetworkID, jobID)
	image := nz(spec.Image, sandboxImageForPhase(spec.Phase))
	hostDir := filepath.Clean(spec.HostWorkDir)
	if hostDir == "" || !filepath.IsAbs(hostDir) {
		return nil, fmt.Errorf("HostWorkDir must be absolute")
	}
	if err := assertJobBindPath(hostDir, layoutID); err != nil {
		return nil, err
	}
	ensureSandboxWorkWritable(hostDir)
	// When we bind the layout root, make sure that tree is writable too.
	if base := filepath.Base(hostDir); base == "primary" || base == "sandbox" || base == "related" {
		ensureSandboxWorkWritable(filepath.Dir(hostDir))
	}

	envSpec := jobEnvSpec{
		Phase:        spec.Phase,
		WorktreeRoot: containerWorkPath(jobID, spec.WorkRel),
		Extra:        spec.ExtraEnv,
	}

	net := nz(spec.Network, "none")
	if net == networkModeInternalProxy {
		jobNet, err := prepareAIJobNetwork(ctx, networkID)
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

	name := sandboxContainerName(jobID, spec.Phase, spec.NameSuffix)
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
	if relBind, ok := relatedROBind(hostDir, jobID, layoutID); ok {
		extraBinds = append(extraBinds, relBind)
	}

	runLabel := ""
	if layoutID != jobID {
		runLabel = layoutID
	}
	if networkID != jobID {
		runLabel = networkID
	}

	if spec.Ephemeral {
		runArgv, err := buildDockerRunArgv(dockerRunSpec{
			Name: name, Image: image, JobID: jobID, RunID: runLabel, InstanceID: opaInstanceID(),
			WorkHostPath: hostDir, WorkRel: nz(spec.WorkRel, "primary"),
			ReadOnlyBind: spec.ReadOnly, Network: net,
			EnvFile: envFile, PidsLimit: pidsForPhase(spec.Phase),
			Rm: true, ExtraBinds: extraBinds, Command: spec.Argv,
		})
		if err != nil {
			return nil, err
		}
		sink := liveSinkForSpec(spec)
		defer sink.Close()
		out, err := dockerCmdCapture(ctx, sink, runArgv...)
		out = redactJobOutput(out, secretValues(spec.Secrets)...)
		return out, err
	}

	runArgv, err := buildDockerRunArgv(dockerRunSpec{
		Name: name, Image: image, JobID: jobID, RunID: runLabel, InstanceID: opaInstanceID(),
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
	secFile, secCleanup, secErr := writeSandboxSecretsEnvFile(spec.Secrets)
	if secErr != nil {
		return nil, secErr
	}
	defer secCleanup()
	if secFile != "" {
		execArgv = append(execArgv, "--env-file", secFile)
	}
	execArgv = append(execArgv, name)
	execArgv = append(execArgv, spec.Argv...)
	sink := liveSinkForSpec(spec)
	defer sink.Close()
	out, err := dockerCmdCapture(ctx, sink, execArgv...)
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

func stampSandboxHonesty(jobID, honesty string) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" || honesty == "" {
		return
	}
	// Sandbox JobID is often the run id (shared network label). Prefer that
	// job; if missing, stamp any live child that shares RunID == jobID.
	job := getSCMJob(jobID)
	if job == nil {
		scmJobLive.Range(func(_, v interface{}) bool {
			j, ok := v.(*scmJob)
			if !ok || j == nil {
				return true
			}
			if j.RunID == jobID || j.ID == jobID {
				job = j
				return false
			}
			return true
		})
	}
	if job == nil {
		return
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	job.Summary["sandbox_honesty"] = honesty
	persistSCMJob(job)
}

func dockerCmd(ctx context.Context, args ...string) ([]byte, error) {
	return dockerCmdCapture(ctx, nil, args...)
}

func dockerCmdCapture(ctx context.Context, sink *liveOutputSink, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	return runCmdWithLiveSink(cmd, sink)
}

func runCmdWithLiveSink(cmd *exec.Cmd, sink *liveOutputSink) ([]byte, error) {
	var buf bytes.Buffer
	var w io.Writer = &buf
	if sink != nil {
		w = io.MultiWriter(&buf, sink)
	}
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	if sink != nil {
		sink.Flush(true)
	}
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

// writeSandboxSecretsEnvFile writes ONLY explicit secrets for `docker exec
// --env-file` so values never appear on the orchestrator process argv.
func writeSandboxSecretsEnvFile(secrets map[string]string) (path string, cleanup func(), err error) {
	if len(secrets) == 0 {
		return "", func() {}, nil
	}
	lines := make([]string, 0, len(secrets))
	for k, v := range secrets {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		if strings.ContainsAny(k, "=\n\r") || strings.ContainsAny(v, "\n\r") {
			return "", func() {}, fmt.Errorf("secret env line contains illegal characters")
		}
		lines = append(lines, k+"="+v)
	}
	if len(lines) == 0 {
		return "", func() {}, nil
	}
	sort.Strings(lines)
	return writeSandboxEnvFileRaw(lines)
}

// writeSandboxEnvFileRaw writes KEY=VAL lines as-is (caller already filtered).
func writeSandboxEnvFileRaw(lines []string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "opa-job-sec-*.env")
	if err != nil {
		return "", func() {}, err
	}
	path = f.Name()
	cleanup = func() { _ = os.Remove(path) }
	_ = os.Chmod(path, 0o600)
	var b strings.Builder
	for _, line := range lines {
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

func sandboxContainerName(jobID string, phase jobPhase, suffix string) string {
	suf := strings.TrimSpace(suffix)
	if suf == "" {
		suf = newRandomHex(6)
	}
	return "opa-job-" + sanitizeDockerName(jobID) + "-" + string(phase) + "-" + sanitizeDockerName(suf)
}

func containerWorkPath(jobID, rel string) string {
	rel = strings.Trim(nz(rel, "primary"), "/")
	return opaJobsContainerRoot + "/" + sanitizeDockerName(jobID) + "/" + rel
}

// relatedROBind mounts {layout}/related read-only next to the agent cwd so
// cross-repo context is reachable inside docker (leaf bind alone omits siblings).
func relatedROBind(hostWork, jobID, layoutID string) (string, bool) {
	hostWork = filepath.Clean(hostWork)
	if hostWork == "" || jobID == "" {
		return "", false
	}
	layoutRoot := filepath.Dir(hostWork)
	relatedHost := filepath.Join(layoutRoot, "related")
	st, err := os.Stat(relatedHost)
	if err != nil || !st.IsDir() {
		return "", false
	}
	if err := assertJobBindPath(relatedHost, layoutID); err != nil {
		return "", false
	}
	cont := opaJobsContainerRoot + "/" + sanitizeDockerName(jobID) + "/related"
	return relatedHost + ":" + cont + ":ro", true
}

// relatedContainerPath is the path agents should read for a related checkout
// when OPA_JOB_SANDBOX=docker.
func relatedContainerPath(jobID, repoFullName string) string {
	return opaJobsContainerRoot + "/" + sanitizeDockerName(jobID) + "/related/" + sanitizeRelatedRepoDir(repoFullName)
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
