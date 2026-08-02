package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// launchAgentSandbox is the single seam for agent CLI children. Increment 1
// always runs on the host (OPA_JOB_SANDBOX defaults off); the signature is what
// later increments wrap with docker run/exec. Every call applies a timeout.

type agentLaunchSpec struct {
	Phase        jobPhase
	Bin          string // ignored for children — resolveAgentBin wins
	Args         []string
	Dir          string
	WorktreeRoot string
	APIKey       string
	Extra        map[string]string
	Timeout      time.Duration
	Parent       context.Context
}

func launchAgentSandbox(spec agentLaunchSpec) ([]byte, error) {
	parent := spec.Parent
	if parent == nil {
		parent = context.Background()
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultTimeoutForPhase(spec.Phase)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	bin := resolveAgentBin()
	argv := append([]string{bin}, spec.Args...)
	work := nz(spec.WorktreeRoot, spec.Dir)
	jobID := ""
	if work != "" {
		// Best-effort: basename of parent of primary, or leaf.
		jobID = filepath.Base(filepath.Clean(work))
		if jobID == "primary" {
			jobID = filepath.Base(filepath.Dir(work))
		}
	}
	out, err := runSandboxedArgv(ctx, sandboxExecSpec{
		Phase:       spec.Phase,
		JobID:       jobID,
		HostWorkDir: work,
		WorkRel:     "primary",
		Argv:        argv,
		Secrets:     map[string]string{"CURSOR_API_KEY": spec.APIKey},
		ExtraEnv:    spec.Extra,
		ReadOnly:    spec.Phase != jobPhaseAutofix,
		Network:     networkForPhase(spec.Phase),
		Timeout:     0, // already on ctx
		Image:       sandboxImageForPhase(spec.Phase),
	})
	out = redactJobOutput(out, spec.APIKey)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("agent timeout after %s: %w", timeout, err)
		}
		if ctx.Err() == context.Canceled {
			return out, fmt.Errorf("agent cancelled: %w", err)
		}
		return out, err
	}
	return out, nil
}

func networkForPhase(phase jobPhase) string {
	switch phase {
	case jobPhaseScan:
		return "none"
	case jobPhaseCheckup:
		// Checkup attaches to the per-job --internal network at run time.
		return "none" // overridden by runCheckupStep with the job network
	default:
		// AI needs Cursor API egress via the shared allowlist proxy on an
		// --internal job network. OPA_JOB_EGRESS_PROXY=0 falls back to bridge.
		if sandboxMode() == "docker" {
			if egressProxyEnabled() {
				return networkModeInternalProxy
			}
			return "bridge"
		}
		return "none"
	}
}

func sandboxMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OPA_JOB_SANDBOX"))) {
	case "docker":
		return "docker"
	default:
		return "off"
	}
}

// resolveAgentBin returns the binary used for agent children. Settings
// cli_cursor.bin is intentionally ignored here so a PUT cannot choose what
// executes inside review/autofix profiles. Precedence: OPA_CURSOR_AGENT_BIN
// (allowlisted) → baked /opt/opa/agent → "agent" on PATH.
func resolveAgentBin() string {
	if b := strings.TrimSpace(os.Getenv("OPA_CURSOR_AGENT_BIN")); b != "" {
		if err := validateAgentBin(b); err == nil {
			return b
		}
		LogWarn("resolveAgentBin: OPA_CURSOR_AGENT_BIN rejected", map[string]interface{}{"bin": b})
	}
	if _, err := os.Stat("/opt/opa/agent"); err == nil {
		return "/opt/opa/agent"
	}
	return "agent"
}

// agentBinAllowlist is the set of basenames / path prefixes admins may configure
// for display/docs. Agent children never read the setting; this gates PUT only.
func agentBinAllowed(bin string) bool {
	return validateAgentBin(bin) == nil
}

func validateAgentBin(bin string) error {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return fmt.Errorf("empty bin")
	}
	if strings.ContainsAny(bin, " \t\n") {
		return fmt.Errorf("bin must not contain whitespace")
	}
	if strings.Contains(bin, "..") {
		return fmt.Errorf("bin must not contain ..")
	}
	base := filepath.Base(bin)
	switch base {
	case "agent", "cursor-agent", "cursor":
		// ok
	default:
		return fmt.Errorf("bin basename %q not allowlisted (agent|cursor-agent|cursor)", base)
	}
	if filepath.IsAbs(bin) {
		allowedPrefixes := []string{"/opt/opa/", "/usr/local/bin/", "/usr/bin/"}
		ok := false
		for _, p := range allowedPrefixes {
			if strings.HasPrefix(bin, p) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("absolute bin must be under /opt/opa/, /usr/local/bin/, or /usr/bin/")
		}
	}
	return nil
}

// redactJobOutput strips known secret values from agent stdout/stderr before
// they are persisted into job summaries or returned to callers.
func redactJobOutput(raw []byte, secrets ...string) []byte {
	out := raw
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if len(s) < 8 {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(s), []byte("***"))
	}
	for _, name := range []string{
		"JWT_SECRET", "OPA_CONNECTOR_SECRET", "OPA_GITHUB_APP_PRIVATE_KEY",
		"OPA_GITHUB_WEBHOOK_SECRET", "CLICKHOUSE_URL", "OPA_GIT_ASKPASS_TOKEN",
		"CURSOR_API_KEY",
	} {
		if v := strings.TrimSpace(os.Getenv(name)); len(v) >= 8 {
			out = bytes.ReplaceAll(out, []byte(v), []byte("***"))
		}
	}
	return out
}
