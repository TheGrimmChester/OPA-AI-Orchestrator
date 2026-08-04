package main

// Agents — child-process environments constructed from an EMPTY slice.
//
// THIS FILE MUST NEVER CALL os.Environ(), AND NEITHER MAY ANY CALLER THAT
// BUILDS A cmd.Env FOR AN UNTRUSTED TOOL.
//
// Previously every tool child was launched with
//
//	cmd.Env = append(os.Environ(), "CURSOR_API_KEY="+key, ...)
//
// which handed the Cursor agent CLI — running with --trust (shell execution, no
// approval prompt) and cwd set to an attacker-authored PR checkout — the whole
// orchestrator environment: JWT_SECRET, OPA_CONNECTOR_SECRET (the AES key for
// every stored PAT), OPA_GITHUB_APP_PRIVATE_KEY, OPA_GITHUB_WEBHOOK_SECRET and
// CLICKHOUSE_URL. jobEnv replaces that with an explicit allowlist: names are
// inherited only if they appear in jobEnvPassthrough, and secrets are only ever
// the ones a phase is declared to be allowed to hold.
//
// Two independent controls, because an allowlist alone rots as env vars are
// added:
//   1. jobEnvPassthrough — the positive list of inherited names.
//   2. envNameLooksSecret — a belt-and-braces reject on anything that smells
//      like a credential, applied to passthrough AND extras. A future
//      OPA_SOMETHING_TOKEN added to the deployment cannot silently reach a
//      sandboxed tool even if someone adds it to the passthrough list.

import (
	"os"
	"sort"
	"strings"
	openlogger "github.com/TheGrimmChester/open-logger-go"
)

// jobPhase identifies what a child process is for. It selects which secrets the
// child may hold; see jobPhaseAllowedSecrets.
type jobPhase string

const (
	// jobPhaseReview is bugbot.review — the per-unit and synthesis agent passes.
	jobPhaseReview jobPhase = "review"
	// jobPhaseContext is reviewer-context generation and the understanding pass.
	jobPhaseContext jobPhase = "context"
	// jobPhaseScan is gitleaks and the lite scanners. Holds no secret at all.
	jobPhaseScan jobPhase = "scan"
	// jobPhaseAutofix is cloud.patch — the agent that writes files.
	jobPhaseAutofix jobPhase = "autofix"
	// jobPhaseAITask is the generic /api/ai/tasks CLI runner.
	jobPhaseAITask jobPhase = "ai_task"
	// jobPhaseCheckup runs allowlisted repo test/install argv in a sandbox.
	jobPhaseCheckup jobPhase = "checkup"
)

// jobPhaseAllowedSecrets is the per-phase secret allowlist. A secret handed to
// jobEnv for a phase that is not declared to hold it is DROPPED and logged —
// dropping fails closed (the tool loses a capability) rather than open.
//
// jobPhaseScan is deliberately absent: gitleaks needs no credential, so the
// scanner child must carry none. That is what makes it the cheapest phase to
// move behind a container boundary later.
var jobPhaseAllowedSecrets = map[jobPhase]map[string]bool{
	jobPhaseReview:  {"CURSOR_API_KEY": true},
	jobPhaseContext: {"CURSOR_API_KEY": true},
	jobPhaseAutofix: {"CURSOR_API_KEY": true},
	jobPhaseAITask:  {"CURSOR_API_KEY": true},
	jobPhaseScan:    {},
	jobPhaseCheckup: {
		"COMPOSER_AUTH": true, "NPM_TOKEN": true, "NPM_AUTH": true, "NODE_AUTH_TOKEN": true,
	},
}

// jobEnvPassthrough are variable NAMES inherited from the orchestrator process
// when set. Values are not synthesized here (beyond the defaults below) so that
// whatever the image and compose actually configure keeps working — notably
// PLAYWRIGHT_BROWSERS_PATH, which the Dockerfile sets and the browser MCP needs.
//
// Everything not listed is dropped. Adding a name here is a security decision:
// it must be operator- or image-provided configuration, never a credential.
var jobEnvPassthrough = []string{
	// Process basics. Without PATH the agent cannot find node/npx for its MCP
	// child; without HOME the Cursor CLI cannot read its own config or auth state.
	"PATH", "HOME", "TMPDIR", "TMP", "TEMP",
	"LANG", "LC_ALL", "TZ", "USER", "LOGNAME",

	// Node / npm — the browser MCP spawns a node child.
	"NODE_PATH", "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS",
	"npm_config_cache", "NPM_CONFIG_CACHE", "COREPACK_HOME",

	// Playwright / Chromium, set by the Dockerfile.
	"PLAYWRIGHT_BROWSERS_PATH",

	// TLS trust roots, in case the deployment injects a corporate CA.
	"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",

	// Proxy configuration is operator policy, not a credential. Passed through so
	// a deployment behind a proxy keeps working; note a hostile child can simply
	// unset these, which is why the network boundary is the per-job --internal
	// bridge and never the proxy variables.
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "no_proxy",

	// XDG dirs, so a relocated agent config still resolves.
	"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
}

// jobEnvDefaults apply when a passthrough name is absent from the orchestrator
// environment. Keep this minimal — a wrong default is worse than an absent var.
var jobEnvDefaults = map[string]string{
	"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"LANG": "C.UTF-8",
}

// dockerSandboxEnvOverrides force identity paths inside job boxes (UID 65532).
// Orchestrator HOME is often /root; passing that through makes npm/composer
// try /root/.npm and hit EACCES on the read-only rootfs.
var dockerSandboxEnvOverrides = map[string]string{
	"HOME":             "/home/opa",
	"npm_config_cache": "/tmp/npm-cache",
	"NPM_CONFIG_CACHE": "/tmp/npm-cache",
	"XDG_CACHE_HOME":   "/tmp/xdg-cache",
	"XDG_CONFIG_HOME":  "/home/opa/.config",
	"XDG_DATA_HOME":    "/home/opa/.local/share",
	"TMPDIR":           "/tmp",
	// golang:* images default GOPATH/GOMODCACHE under /go (read-only rootfs).
	"GOPATH":     "/tmp/go",
	"GOMODCACHE": "/tmp/go-mod",
	"GOCACHE":    "/tmp/go-cache",
}

// secretishFragments are substrings that mark a variable name as credential-
// bearing. Checked case-insensitively against every name jobEnv would emit
// from passthrough or Extra — the explicit Secrets map bypasses this, because
// there the caller has stated intent and the phase allowlist has agreed.
var secretishFragments = []string{
	"SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "APIKEY",
	"PRIVATE_KEY", "CREDENTIAL", "AUTH", "SESSION", "COOKIE",
	"CLICKHOUSE_URL", "DATABASE_URL", "DSN",
}

// envNameLooksSecret reports whether a variable name should never be inherited.
func envNameLooksSecret(name string) bool {
	u := strings.ToUpper(strings.TrimSpace(name))
	if u == "" {
		return true
	}
	for _, frag := range secretishFragments {
		if strings.Contains(u, frag) {
			return true
		}
	}
	return false
}

// jobEnvSpec describes the environment for one child process.
type jobEnvSpec struct {
	Phase jobPhase
	// WorktreeRoot populates OPA_SCAN_WORKTREE when non-empty.
	WorktreeRoot string
	// Secrets are delivered explicitly and filtered by jobPhaseAllowedSecrets.
	// They are never read from the orchestrator environment: process-env API
	// keys are deliberately not tenant fallbacks (they acted as a shared admin
	// pool — see applyAIEnvOverrides in ai_settings.go).
	Secrets map[string]string
	// Extra are additional NON-SECRET variables (e.g. OPA_REVIEW_PREVIEW_URL).
	Extra map[string]string
}

// jobEnv builds a child environment from an empty slice. The result is sorted so
// it is stable across calls, which keeps the unit tests and any future golden
// argv comparison deterministic.
func jobEnv(spec jobEnvSpec) []string {
	out := map[string]string{}

	for _, name := range jobEnvPassthrough {
		if envNameLooksSecret(name) {
			// A passthrough entry that looks like a credential is a bug in this
			// file, not a runtime condition. Refuse it loudly rather than ship it.
			openlogger.LogError(nil, "jobEnv: refusing secret-looking passthrough name", map[string]interface{}{
				"name":  name,
				"phase": string(spec.Phase),
			})
			continue
		}
		if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
			out[name] = v
			continue
		}
		if def, ok := jobEnvDefaults[name]; ok {
			out[name] = def
		}
	}

	// Non-secret markers every tool child gets.
	out["NO_OPEN_BROWSER"] = "1"
	out["CI"] = "true"
	out["OPA_JOB_PHASE"] = string(spec.Phase)
	if spec.WorktreeRoot != "" {
		out["OPA_SCAN_WORKTREE"] = spec.WorktreeRoot
	}

	for k, v := range spec.Extra {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if envNameLooksSecret(k) {
			openlogger.LogError(nil, "jobEnv: dropped secret-looking Extra variable", map[string]interface{}{
				"name":  k,
				"phase": string(spec.Phase),
				"hint":  "pass credentials via jobEnvSpec.Secrets so the phase allowlist applies",
			})
			continue
		}
		out[k] = v
	}

	allowed := jobPhaseAllowedSecrets[spec.Phase]
	for k, v := range spec.Secrets {
		k = strings.TrimSpace(k)
		if k == "" || strings.TrimSpace(v) == "" {
			continue
		}
		if !allowed[k] {
			// Fail closed: the child loses the capability rather than gaining a
			// secret its phase was never declared to hold.
			openlogger.LogError(nil, "jobEnv: dropped secret not allowed for this phase", map[string]interface{}{
				"name":  k,
				"phase": string(spec.Phase),
			})
			continue
		}
		out[k] = v
	}

	if sandboxMode() == "docker" {
		for k, v := range dockerSandboxEnvOverrides {
			out[k] = v
		}
		// Prefer the image PATH (golang includes /usr/local/go/bin). Forcing the
		// orchestrator's host PATH drops toolchain dirs inside job boxes.
		delete(out, "PATH")
	}

	return envSliceSorted(out)
}

// hostToolEnv is the curated environment for host-side tool children that stay
// in the orchestrator process — git, principally. It exists so that even the
// trusted git child stops carrying the service secrets: gitAskPassEnv used to
// build on os.Environ(), so a git subprocess inherited JWT_SECRET and friends
// alongside the PAT it actually needed.
//
// extra is a list of "K=V" strings appended verbatim. Callers pass the askpass
// variables here — that is legitimate: git is the one component that must hold
// the tenant token, it is argv-only with no shell, and it never runs repo hooks
// on the paths we drive.
func hostToolEnv(extra ...string) []string {
	out := map[string]string{}
	for _, name := range jobEnvPassthrough {
		if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
			out[name] = v
			continue
		}
		if def, ok := jobEnvDefaults[name]; ok {
			out[name] = def
		}
	}
	env := envSliceSorted(out)
	for _, kv := range extra {
		if strings.TrimSpace(kv) == "" || !strings.Contains(kv, "=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// envSliceSorted renders a name->value map as a sorted "K=V" slice.
func envSliceSorted(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, k := range keys {
		env = append(env, k+"="+m[k])
	}
	return env
}
