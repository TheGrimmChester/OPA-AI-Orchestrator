package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// dockerRunSpec is the declarative input for buildDockerRunArgv. Callers never
// assemble raw flags — the builder is the only place that emits docker run argv.
type dockerRunSpec struct {
	Name         string
	Image        string
	JobID        string
	RunID        string // optional opa.run label (shared run teardown)
	InstanceID   string
	WorkHostPath string // host abs path bound at identity path
	WorkRel      string // e.g. primary — container cwd is /opa-jobs/<id>/<WorkRel>
	ReadOnlyBind bool
	Network      string // "none" | network name | ""
	EnvFile      string // path to 0600 env-file (non-secrets)
	Memory       string // e.g. 4g
	CPUs         string // e.g. 2
	PidsLimit    int
	Command      []string // optional; empty → image default (often sleep for long-lived)
	Labels       map[string]string
	Rm           bool     // docker run --rm (ephemeral one-shot)
	ExtraBinds   []string // additional host:container:mode binds (validated)
}

const opaJobsContainerRoot = "/opa-jobs"

// buildDockerRunArgv produces `docker run -d …` argv (without the leading "docker").
// It refuses privileged/cap-add/port-publish/root-mount shapes via validateDockerRunArgv.
func buildDockerRunArgv(spec dockerRunSpec) ([]string, error) {
	if strings.TrimSpace(spec.Image) == "" {
		return nil, fmt.Errorf("image required")
	}
	if strings.TrimSpace(spec.JobID) == "" {
		return nil, fmt.Errorf("job id required")
	}
	if strings.TrimSpace(spec.WorkHostPath) == "" {
		return nil, fmt.Errorf("work host path required")
	}
	host := filepath.Clean(spec.WorkHostPath)
	if !filepath.IsAbs(host) {
		return nil, fmt.Errorf("work host path must be absolute")
	}
	if host == "/" || host == "/etc" || host == "/var" || host == "/usr" || host == "/root" {
		return nil, fmt.Errorf("refusing to bind dangerous host path %s", host)
	}
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = "opa-job-" + sanitizeDockerName(spec.JobID)
	}
	rel := strings.Trim(strings.TrimSpace(spec.WorkRel), "/")
	if rel == "" {
		rel = "primary"
	}
	containerWork := opaJobsContainerRoot + "/" + sanitizeDockerName(spec.JobID)
	containerCwd := containerWork + "/" + rel
	mem := nz(spec.Memory, "4g")
	cpus := nz(spec.CPUs, "2")
	pids := spec.PidsLimit
	if pids <= 0 {
		pids = 512
	}
	instance := nz(spec.InstanceID, opaInstanceID())

	argv := []string{
		"run",
	}
	if spec.Rm {
		argv = append(argv, "--rm")
	} else {
		argv = append(argv, "-d")
	}
	argv = append(argv,
		"--name", name,
		"--label", "opa.owner=opa-orchestrator",
		"--label", "opa.instance="+instance,
		"--label", "opa.job="+sanitizeDockerName(spec.JobID),
	)
	if rid := strings.TrimSpace(spec.RunID); rid != "" {
		argv = append(argv, "--label", "opa.run="+sanitizeDockerName(rid))
	}
	argv = append(argv,
		"--user", "65532:65532",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		// uid/gid required: default tmpfs is root:root 0755, so UID 65532 cannot
		// mkdir under /home/opa (Cursor CLI → EACCES on ~/.cursor/projects/…).
		// exec required on /tmp: go test writes binaries under GOCACHE and fails
		// with "permission denied" when the mount is noexec (docker tmpfs default).
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,uid=65532,gid=65532,mode=1777,size=1g",
		"--tmpfs", "/home/opa:rw,exec,nosuid,nodev,uid=65532,gid=65532,mode=1777,size=256m",
		"--pids-limit", strconv.Itoa(pids),
		"--memory", mem,
		"--memory-swap", mem, // equal ⇒ swap disabled
		"--cpus", cpus,
		"--ulimit", "nofile=8192:8192",
		"--ulimit", "core=0",
		"--stop-timeout", "5",
	)
	for k, v := range spec.Labels {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			continue
		}
		argv = append(argv, "--label", k+"="+v)
	}
	net := strings.TrimSpace(spec.Network)
	if net == "" {
		net = "none"
	}
	argv = append(argv, "--network", net)

	bindMode := "rw"
	if spec.ReadOnlyBind {
		bindMode = "ro"
	}
	// Bind the job layout root at /opa-jobs/<id> when WorkHostPath is a leaf
	// (primary|sandbox|…). Leaf-only binds made the parent path land on the
	// read-only container root (npm EACCES mkdir /opa-jobs/<id>).
	bindHost := host
	bindCont := containerCwd
	if base := filepath.Base(host); base == rel || base == "primary" || base == "sandbox" || base == "related" {
		parent := filepath.Dir(host)
		if parent != "" && parent != "/" && parent != "." {
			bindHost = parent
			bindCont = containerWork
		}
	}
	argv = append(argv, "-v", bindHost+":"+bindCont+":"+bindMode)
	// Autofix runs on …/sandbox but layout-root bind also exposes primary RW.
	// Remount primary RO so --trust agents cannot corrupt the git worktree
	// (symptom: post-agent `git ls-files` exit 128 during sandbox sync).
	if !spec.ReadOnlyBind && (rel == "sandbox" || filepath.Base(host) == "sandbox") {
		primaryHost := filepath.Join(bindHost, "primary")
		if st, err := os.Stat(primaryHost); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("autofix sandbox requires primary checkout at %s: %v", primaryHost, err)
		}
		argv = append(argv, "-v", primaryHost+":"+containerWork+"/primary:ro")
	}
	argv = append(argv, "-w", containerCwd)
	for _, b := range spec.ExtraBinds {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		if err := denyDangerousMount(b); err != nil {
			return nil, err
		}
		argv = append(argv, "-v", b)
	}

	if ef := strings.TrimSpace(spec.EnvFile); ef != "" {
		if !filepath.IsAbs(ef) {
			return nil, fmt.Errorf("env-file must be absolute")
		}
		argv = append(argv, "--env-file", ef)
	}

	argv = append(argv, spec.Image)
	if len(spec.Command) > 0 {
		argv = append(argv, spec.Command...)
	} else {
		// Long-lived phase box; steps arrive via docker exec.
		argv = append(argv, "sleep", "infinity")
	}

	if err := validateDockerRunArgv(argv); err != nil {
		return nil, err
	}
	return argv, nil
}

// validateDockerRunArgv is the denylist gate. Golden tests assert each refusal.
func validateDockerRunArgv(argv []string) error {
	joined := strings.Join(argv, "\x00")
	denySubstrings := []string{
		"--privileged",
		"--cap-add",
		"--device",
		"--pid=host",
		"--network=host",
		"--ipc=host",
		"--userns=host",
		"--security-opt=seccomp=unconfined",
		"--security-opt=apparmor=unconfined",
	}
	for _, d := range denySubstrings {
		for _, a := range argv {
			if a == d || strings.HasPrefix(a, d+"=") {
				return fmt.Errorf("docker run argv denied: %s", d)
			}
		}
		if strings.Contains(joined, d) {
			// also catch split forms already covered; keep for = variants in single token
			_ = d
		}
	}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch a {
		case "-p", "--publish", "--publish-all", "-P":
			return fmt.Errorf("docker run argv denied: port publish")
		case "--privileged":
			return fmt.Errorf("docker run argv denied: --privileged")
		case "--cap-add":
			return fmt.Errorf("docker run argv denied: --cap-add")
		case "-v", "--volume", "--mount":
			val := ""
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				val = argv[i+1]
			} else if eq := strings.Index(a, "="); eq >= 0 {
				val = a[eq+1:]
			}
			if err := denyDangerousMount(val); err != nil {
				return err
			}
		case "-e", "--env":
			return fmt.Errorf("docker run argv denied: -e/--env (use --env-file; secrets via docker exec --env)")
		}
		if strings.HasPrefix(a, "-v=") || strings.HasPrefix(a, "--volume=") {
			if err := denyDangerousMount(strings.SplitN(a, "=", 2)[1]); err != nil {
				return err
			}
		}
		if strings.HasPrefix(a, "-e=") || strings.HasPrefix(a, "--env=") {
			return fmt.Errorf("docker run argv denied: -e/--env")
		}
	}
	return nil
}

func denyDangerousMount(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	// type=bind,source=...,target=... or host:container:mode
	low := strings.ToLower(spec)
	if strings.Contains(low, "docker.sock") {
		return fmt.Errorf("docker run argv denied: docker.sock mount")
	}
	hostPart := spec
	if strings.Contains(spec, ",") && strings.Contains(low, "source=") {
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "source=") {
				hostPart = strings.TrimPrefix(part, "source=")
				hostPart = strings.TrimPrefix(hostPart, "Source=")
				break
			}
		}
	} else if i := strings.Index(spec, ":"); i >= 0 {
		hostPart = spec[:i]
	}
	hostPart = filepath.Clean(hostPart)
	switch hostPart {
	case "/", "/etc", "/var", "/usr", "/root", "/home", "/proc", "/sys", "/dev":
		return fmt.Errorf("docker run argv denied: bind of %s", hostPart)
	}
	if hostPart == "/var/run" || strings.HasPrefix(hostPart, "/var/run/") {
		return fmt.Errorf("docker run argv denied: /var/run bind")
	}
	return nil
}

func sanitizeDockerName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "job"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func opaInstanceID() string {
	if v := strings.TrimSpace(os.Getenv("OPA_INSTANCE_ID")); v != "" {
		return sanitizeDockerName(v)
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return sanitizeDockerName(h)
	}
	return "local"
}

func sandboxImageForPhase(phase jobPhase) string {
	tag := nz(strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_TAG")), "smoke")
	switch phase {
	case jobPhaseScan:
		return nz(os.Getenv("OPA_JOB_IMAGE_SCAN"), "opa-runner-scan:"+tag)
	case jobPhaseCheckup:
		// Prefer explicit checkup image; else PHP runner (composer trees are the
		// common checkup case). Plans still override via checkupPlan.Image.
		if v := strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_CHECKUP")); v != "" {
			return v
		}
		if v := strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_PHP")); v != "" {
			return v
		}
		return "opa-runner-php:" + tag
	case jobPhaseReview, jobPhaseContext, jobPhaseAutofix, jobPhaseAITask:
		return nz(os.Getenv("OPA_JOB_IMAGE_AI"), "opa-runner-ai:"+tag)
	default:
		return nz(os.Getenv("OPA_JOB_IMAGE_GIT"), "opa-runner-git:"+tag)
	}
}
