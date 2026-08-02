package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// agentMutationProposal is Bugbot's only channel to request Cloud work.
// Severity is never trusted from the request — authorizeAutofixRequest reads it
// from the findings ledger.
type agentMutationProposal struct {
	FindingKeys []string `json:"finding_keys"`
	Rationale   string   `json:"rationale,omitempty"`
}

// autofixAuthOK is a successful authorizeAutofixRequest result.
type autofixAuthOK struct {
	Findings []agentFinding
	Mode     string // suggest|branch
	Honesty  string
}

var (
	autofixRateMu     sync.Mutex
	autofixRateWindow = map[string][]time.Time{} // repo → request timestamps
)

func autofixRateLimitMax() int {
	n := atoiDefault(envOr("OPA_CLOUD_AUTOFIX_RATE_PER_HOUR", "5"), 5)
	if n < 1 {
		n = 1
	}
	if n > 30 {
		n = 30
	}
	return n
}

func checkAutofixRateLimit(repo string) error {
	repo = strings.ToLower(strings.TrimSpace(repo))
	if repo == "" {
		return fmt.Errorf("empty repo for rate limit")
	}
	now := time.Now().UTC()
	cutoff := now.Add(-time.Hour)
	autofixRateMu.Lock()
	defer autofixRateMu.Unlock()
	kept := autofixRateWindow[repo][:0]
	for _, t := range autofixRateWindow[repo] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	autofixRateWindow[repo] = kept
	if len(kept) >= autofixRateLimitMax() {
		return fmt.Errorf("autofix rate limit exceeded for %s (%d/hour)", repo, autofixRateLimitMax())
	}
	return nil
}

func recordAutofixRate(repo string) {
	repo = strings.ToLower(strings.TrimSpace(repo))
	if repo == "" {
		return
	}
	autofixRateMu.Lock()
	autofixRateWindow[repo] = append(autofixRateWindow[repo], time.Now().UTC())
	autofixRateMu.Unlock()
}

// authorizeAutofixRequest gates Cloud work. Empty finding keys refuse (never
// "fix everything"). Severity is taken from the ledger only. Rate limit is
// recorded on success (first attempt); use authorizeAutofixRequestAttempt for
// re-auth within a bounded iteration loop.
func authorizeAutofixRequest(conn *opaConnector, prefs agentPrefs, repo string, ledger []agentFinding, keys []string) (autofixAuthOK, error) {
	return authorizeAutofixRequestAttempt(conn, prefs, repo, ledger, keys, true)
}

// authorizeAutofixRequestAttempt is the same gate; recordRate=false skips the
// hourly counter so patch→land retries in one job do not burn the quota.
func authorizeAutofixRequestAttempt(conn *opaConnector, prefs agentPrefs, repo string, ledger []agentFinding, keys []string, recordRate bool) (autofixAuthOK, error) {
	var zero autofixAuthOK
	if !prefs.CloudEnabled {
		return zero, fmt.Errorf("cloud_enabled=off")
	}
	mode := strings.ToLower(strings.TrimSpace(prefs.AutofixMode))
	if mode == "" || mode == "off" {
		return zero, fmt.Errorf("autofix_mode=off")
	}
	if mode != "suggest" && mode != "branch" {
		return zero, fmt.Errorf("autofix_mode=%q not allowed", mode)
	}
	if len(keys) == 0 {
		return zero, fmt.Errorf("empty finding_keys — refusing to fix everything")
	}
	if conn == nil {
		return zero, fmt.Errorf("no connector")
	}
	if conn.Kind != "github_app" {
		return zero, fmt.Errorf("capGitPush/cloud requires github_app connector (PAT refused)")
	}
	if !connectorCoversRepo(conn, repo) {
		return zero, fmt.Errorf("repo %s not in installation for connector", repo)
	}
	if recordRate {
		if err := checkAutofixRateLimit(repo); err != nil {
			return zero, err
		}
	}

	byKey := map[string]agentFinding{}
	for _, f := range ledger {
		k := strings.ToLower(strings.TrimSpace(f.Key))
		if k != "" {
			byKey[k] = f
		}
	}
	threshold := strings.ToLower(strings.TrimSpace(prefs.AutofixSeverityThreshold))
	if threshold == "" {
		threshold = "high"
	}
	selected := make([]agentFinding, 0, len(keys))
	for _, raw := range keys {
		k := strings.ToLower(strings.TrimSpace(raw))
		if k == "" {
			continue
		}
		f, ok := byKey[k]
		if !ok {
			return zero, fmt.Errorf("finding key %q not in ledger", raw)
		}
		// Severity from ledger only — never from the request payload.
		if !severityAtLeast(f.Severity, threshold) && !severityEqualsBlocker(f.Severity) {
			return zero, fmt.Errorf("finding %q severity %q below threshold %q", f.Key, f.Severity, threshold)
		}
		selected = append(selected, f)
	}
	if len(selected) == 0 {
		return zero, fmt.Errorf("no authorized findings after key filter")
	}
	if recordRate {
		recordAutofixRate(repo)
	}
	return autofixAuthOK{
		Findings: selected,
		Mode:     mode,
		Honesty:  fmt.Sprintf("authorized %d finding(s) mode=%s", len(selected), mode),
	}, nil
}

func severityEqualsBlocker(sev string) bool {
	s := strings.ToLower(strings.TrimSpace(sev))
	return s == "blocker" || s == "critical"
}

// connectorCoversRepo is true when the repo is watched under this connector or
// listed in the installation (GitHub App). Fails closed on list errors.
func connectorCoversRepo(conn *opaConnector, repo string) bool {
	if conn == nil || strings.TrimSpace(repo) == "" {
		return false
	}
	want := strings.ToLower(strings.TrimSpace(repo))
	found := false
	watchedLive.Range(func(_, v interface{}) bool {
		wr, ok := v.(*opaWatchedRepo)
		if ok && wr != nil && wr.ConnectorID == conn.ID && strings.ToLower(wr.RepoFullName) == want {
			found = true
			return false
		}
		return true
	})
	if found {
		return true
	}
	repos, err := githubListRepos(conn)
	if err != nil {
		return githubUseMockAPI(conn)
	}
	for _, r := range repos {
		if strings.ToLower(strFromAny(r["full_name"])) == want {
			return true
		}
	}
	return false
}

// authorizeGitPush refuses PATs unconditionally (capGitPush). Land/push only.
func authorizeGitPush(conn *opaConnector) error {
	if conn == nil {
		return fmt.Errorf("no connector")
	}
	if conn.Kind == "github_pat" {
		return fmt.Errorf("capGitPush refuses PAT connectors — use github_app")
	}
	if conn.Kind != "github_app" {
		return fmt.Errorf("capGitPush requires github_app (got %s)", conn.Kind)
	}
	return nil
}

// cloudDiffChange is one path touched by a candidate autofix patch.
type cloudDiffChange struct {
	Path        string
	Added       int
	Removed     int
	NewMode     string // e.g. "100755", "160000"
	IsSubmodule bool
}

// cloudDiffCaps are structural limits on a landable patch.
type cloudDiffCaps struct {
	MaxFiles int
	MaxLines int
}

func defaultCloudDiffCaps() cloudDiffCaps {
	files := atoiDefault(envOr("OPA_CLOUD_DIFF_MAX_FILES", "20"), 20)
	lines := atoiDefault(envOr("OPA_CLOUD_DIFF_MAX_LINES", "800"), 800)
	if files < 1 {
		files = 1
	}
	if lines < 1 {
		lines = 1
	}
	return cloudDiffCaps{MaxFiles: files, MaxLines: lines}
}

func isCloudDeniedPath(path string) (bool, string) {
	p := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(path)), "./")
	if p == "" {
		return true, "empty path"
	}
	low := strings.ToLower(p)
	if low == ".github" || strings.HasPrefix(low, ".github/") {
		return true, ".github/** denied"
	}
	if low == ".opa" || strings.HasPrefix(low, ".opa/") {
		return true, ".opa/** denied"
	}
	base := strings.ToLower(filepath.Base(p))
	if skipReviewPathNames[base] {
		return true, "lockfile denied: " + base
	}
	return false, ""
}

func isExecGitMode(mode string) bool {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return false
	}
	if mode == "100755" || mode == "755" {
		return true
	}
	n, err := strconv.ParseInt(mode, 8, 32)
	if err != nil {
		return false
	}
	return n&0o111 != 0
}

// gateCloudDiff rejects patches that touch denied paths, exceed caps, set exec
// bits, or introduce submodules. allowlist, when non-empty, is a positive set of
// paths (typically finding files) — anything else is refused.
func gateCloudDiff(changes []cloudDiffChange, allowlist []string, caps cloudDiffCaps) error {
	if caps.MaxFiles <= 0 || caps.MaxLines <= 0 {
		caps = defaultCloudDiffCaps()
	}
	if len(changes) == 0 {
		return fmt.Errorf("gateCloudDiff: empty diff")
	}
	allow := map[string]struct{}{}
	for _, a := range allowlist {
		a = filepath.ToSlash(strings.TrimSpace(a))
		if a != "" {
			allow[a] = struct{}{}
		}
	}
	var reasons []string
	totalLines := 0
	seen := map[string]struct{}{}
	for _, c := range changes {
		path := filepath.ToSlash(strings.TrimSpace(c.Path))
		if path == "" || path == "/dev/null" {
			continue
		}
		seen[path] = struct{}{}
		totalLines += c.Added + c.Removed
		if denied, why := isCloudDeniedPath(path); denied {
			reasons = append(reasons, path+": "+why)
		}
		if c.IsSubmodule || c.NewMode == "160000" {
			reasons = append(reasons, path+": submodule denied")
		}
		if isExecGitMode(c.NewMode) {
			reasons = append(reasons, path+": exec bit denied")
		}
		if len(allow) > 0 {
			if _, ok := allow[path]; !ok {
				reasons = append(reasons, path+": outside finding allowlist")
			}
		}
	}
	if len(seen) > caps.MaxFiles {
		reasons = append(reasons, fmt.Sprintf("file cap exceeded: %d > %d", len(seen), caps.MaxFiles))
	}
	if totalLines > caps.MaxLines {
		reasons = append(reasons, fmt.Sprintf("line cap exceeded: %d > %d", totalLines, caps.MaxLines))
	}
	if len(reasons) > 0 {
		return fmt.Errorf("gateCloudDiff denied: %s", strings.Join(reasons, "; "))
	}
	return nil
}

// parseCloudDiffChanges extracts per-file stats + mode hints from a unified diff.
func parseCloudDiffChanges(diff string) []cloudDiffChange {
	if strings.TrimSpace(diff) == "" {
		return nil
	}
	var out []cloudDiffChange
	var cur *cloudDiffChange
	flush := func() {
		if cur != nil && cur.Path != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			path := parseDiffGitPath(line)
			cur = &cloudDiffChange{Path: path}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(line, "new mode ") {
			cur.NewMode = strings.TrimSpace(strings.TrimPrefix(line, "new mode "))
			if cur.NewMode == "160000" {
				cur.IsSubmodule = true
			}
		}
		if strings.HasPrefix(line, "new file mode ") {
			cur.NewMode = strings.TrimSpace(strings.TrimPrefix(line, "new file mode "))
			if cur.NewMode == "160000" {
				cur.IsSubmodule = true
			}
		}
		if strings.HasPrefix(line, "+++ b/") {
			p := strings.TrimPrefix(line, "+++ b/")
			if p != "" && p != "/dev/null" {
				cur.Path = p
			}
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			cur.Added++
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			cur.Removed++
		}
	}
	flush()
	return out
}

// captureValidatedPatch stages all sandbox changes and returns a git-applyable
// patch (including new files). Call only after gateCloudDiff on the same tree.
func captureValidatedPatch(sandboxRoot string) (string, error) {
	add := exec.Command("git", "-C", sandboxRoot, "add", "-A")
	add.Env = hostToolEnv()
	if out, err := add.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git add: %w (%s)", err, truncateStr(string(out), 120))
	}
	diff := exec.Command("git", "-C", sandboxRoot, "diff", "--cached", "--binary")
	diff.Env = hostToolEnv()
	out, err := diff.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git diff --cached: %w (%s)", err, truncateStr(string(out), 120))
	}
	return string(out), nil
}

// applyValidatedPatch applies a previously gated unified diff onto a clean
// worktree and stages it. Never run this against the agent-writable sandbox.
func applyValidatedPatch(cleanRoot, patch string) error {
	if strings.TrimSpace(patch) == "" {
		return fmt.Errorf("empty validated patch")
	}
	f, err := os.CreateTemp("", "opa-cloud-*.patch")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(patch); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	cmd := exec.Command("git", "-C", cleanRoot, "apply", "--index", "--whitespace=nowarn", path)
	cmd.Env = hostToolEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		// Fallback without --index then stage.
		cmd2 := exec.Command("git", "-C", cleanRoot, "apply", "--whitespace=nowarn", path)
		cmd2.Env = hostToolEnv()
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("git apply: %v (%s)", err, truncateStr(string(out)+" "+string(out2), 200))
		}
		add := exec.Command("git", "-C", cleanRoot, "add", "-A")
		add.Env = hostToolEnv()
		if out3, err3 := add.CombinedOutput(); err3 != nil {
			return fmt.Errorf("git add after apply: %w (%s)", err3, truncateStr(string(out3), 120))
		}
	}
	return nil
}

// gitUnifiedDiff returns working-tree + index diffs versus HEAD, plus untracked
// files approximated as new-file hunks so the gate sees them.
func gitUnifiedDiff(root string) (string, error) {
	cmd := exec.Command("git", "-C", root, "diff", "HEAD")
	cmd.Env = hostToolEnv()
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("git diff: %w", err)
	}
	diff := string(out)
	cmd2 := exec.Command("git", "-C", root, "diff", "--cached")
	cmd2.Env = hostToolEnv()
	if cached, err := cmd2.CombinedOutput(); err == nil && len(cached) > 0 {
		diff += string(cached)
	}
	st := exec.Command("git", "-C", root, "status", "--porcelain", "-uall")
	st.Env = hostToolEnv()
	stOut, _ := st.Output()
	for _, line := range strings.Split(string(stOut), "\n") {
		if len(line) < 4 {
			continue
		}
		code := strings.TrimSpace(line[:2])
		path := strings.TrimSpace(line[3:])
		if path == "" || code != "??" {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(root, path))
		added := 1
		if rerr == nil {
			added = strings.Count(string(raw), "\n") + 1
		}
		mode := "100644"
		if info, err := os.Stat(filepath.Join(root, path)); err == nil && info.Mode()&0o111 != 0 {
			mode = "100755"
		}
		diff += fmt.Sprintf("\ndiff --git a/%s b/%s\nnew file mode %s\n+++ b/%s\n", path, path, mode, path)
		n := added
		if n > 50 {
			n = 50
		}
		for i := 0; i < n; i++ {
			diff += "+\n"
		}
	}
	return diff, nil
}
