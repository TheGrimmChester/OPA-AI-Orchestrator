package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed gitleaks.toml
var embeddedGitleaksConfig []byte

// Embedded lite/stub scanners for Wave 33 security runs (honesty: not full engines).

var secretPatterns = []struct {
	rule     string
	re       *regexp.Regexp
	severity string
}{
	{"aws-access-key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "critical"},
	{"aws-secret-key", regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"][A-Za-z0-9/+=]{30,}['"]`), "critical"},
	{"private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "critical"},
	{"github-pat", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), "high"},
	{"slack-token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), "high"},
	{"generic-api-key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]`), "medium"},
}

var (
	// secretSevByRun accumulates severity counts for live gate evaluation.
	secretSevByRun   sync.Map // runID -> map[string]int
	secretFPFilterBy sync.Map // runID -> int
)

var uiPathHint = regexp.MustCompile(`(?i)(\.(jsx?|tsx?|vue|svelte|css|scss|less|mjs|cjs)$|/(src|components|pages|ui|dashboard|public|static|assets)/)`)
var objectKeyFP = regexp.MustCompile(`(?i)(?:^|[,\s{(\[])['"]?key['"]?\s*:`)
var jsxKeyFP = regexp.MustCompile(`(?i)\skey\s*=\s*\{?['"\x60]`)
var objectKeysCall = regexp.MustCompile(`(?i)Object\.keys\s*\(`)

var sastRules = []struct {
	rule     string
	re       *regexp.Regexp
	exts     map[string]bool
	severity string
	message  string
}{
	{"js-eval", regexp.MustCompile(`\beval\s*\(`), map[string]bool{".js": true, ".mjs": true, ".ts": true, ".tsx": true, ".jsx": true}, "high", "eval() call"},
	{"js-innerhtml", regexp.MustCompile(`\.innerHTML\s*=`), map[string]bool{".js": true, ".mjs": true, ".ts": true, ".tsx": true, ".jsx": true}, "medium", "innerHTML assignment"},
	{"js-document-write", regexp.MustCompile(`document\.write\s*\(`), map[string]bool{".js": true, ".mjs": true, ".ts": true, ".tsx": true, ".jsx": true}, "medium", "document.write()"},
	{"php-eval", regexp.MustCompile(`\beval\s*\(`), map[string]bool{".php": true}, "high", "PHP eval()"},
	// Go regexp has no backrefs — approximate quote+SQL+concat heuristics.
	{"php-sql-concat", regexp.MustCompile(`(?i)['"]\s*(SELECT|INSERT|UPDATE|DELETE)\b[^'"]{0,120}['"]\s*\.`), map[string]bool{".php": true}, "high", "SQL string concatenation"},
	{"php-sql-interp", regexp.MustCompile(`(?i)"(SELECT|INSERT|UPDATE|DELETE)\b[^"]*\$`), map[string]bool{".php": true}, "high", "SQL with variable interpolation"},
	{"js-sql-concat", regexp.MustCompile("(?i)[`'\"]\\s*(SELECT|INSERT|UPDATE|DELETE)\\b[^`'\"]{0,80}[`'\"]\\s*\\+"), map[string]bool{".js": true, ".mjs": true, ".ts": true}, "medium", "SQL string concat in JS"},
}

var scanSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".libs": true, "autom4te.cache": true, ".terraform": true,
}

var scanTextExt = map[string]bool{
	".js": true, ".mjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".py": true, ".go": true, ".php": true, ".yml": true, ".yaml": true,
	".json": true, ".env": true, ".tf": true, ".sh": true, ".c": true, ".h": true,
	".md": true, ".txt": true, ".ini": true, ".conf": true,
}

func securityWorkspaceRoot() string {
	return filepath.Clean(envOr("OPA_SECURITY_WORKSPACE", "/workspace"))
}

func resolveSecurityScanPath(rel string) (string, error) {
	root := securityWorkspaceRoot()
	rel = strings.TrimSpace(rel)
	if rel == "" || rel == "." {
		return root, nil
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute paths not allowed")
	}
	joined := filepath.Clean(filepath.Join(root, rel))
	relToRoot, err := filepath.Rel(root, joined)
	if err != nil || strings.HasPrefix(relToRoot, "..") {
		return "", fmt.Errorf("path escapes workspace")
	}
	return joined, nil
}

func normalizeSecurityScanners(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		switch s {
		case "secret", "secrets", "gitleaks":
			s = "secrets"
		case "sast":
			s = "sast"
		case "iac":
			s = "iac"
		case "container", "containers":
			s = "container"
		case "sbom", "vulns", "vuln":
			s = "sbom"
		case "iast":
			continue // runtime-only
		case "":
			continue
		default:
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func securityProfileScanners(profile string) []string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "php":
		return []string{"secrets", "sast", "sbom"}
	case "node":
		return []string{"secrets", "sast", "sbom"}
	case "container":
		return []string{"container", "iac"}
	case "iac":
		return []string{"iac", "secrets"}
	case "full":
		return []string{"secrets", "sast", "iac", "container", "sbom"}
	case "auto", "":
		return nil
	default:
		return []string{"secrets", "sast"}
	}
}

func detectSecurityScanners(root, image string) []string {
	out := []string{"secrets"}
	hasJS, hasPHP, hasDocker, hasTF, hasPkg := false, false, false, false, false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if scanSkipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(name))
		switch {
		case ext == ".js" || ext == ".mjs" || ext == ".ts" || ext == ".tsx" || ext == ".jsx":
			hasJS = true
		case ext == ".php":
			hasPHP = true
		case name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile."):
			hasDocker = true
		case ext == ".tf":
			hasTF = true
		case name == "package.json" || name == "composer.json" || name == "go.mod" || name == "requirements.txt":
			hasPkg = true
		}
		return nil
	})
	if hasJS || hasPHP {
		out = append(out, "sast")
	}
	if hasDocker || hasTF {
		out = append(out, "iac")
	}
	if image != "" || hasDocker {
		out = append(out, "container")
	}
	if hasPkg {
		out = append(out, "sbom")
	}
	return normalizeSecurityScanners(out)
}

func walkScanFiles(root string, maxFiles int) []string {
	var files []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			if scanSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		name := d.Name()
		if !scanTextExt[ext] && name != ".env" && !strings.HasSuffix(name, ".env.example") &&
			name != "Dockerfile" && !strings.HasPrefix(name, "Dockerfile.") {
			return nil
		}
		files = append(files, path)
		if maxFiles > 0 && len(files) >= maxFiles {
			return filepath.SkipAll
		}
		return nil
	})
	return files
}

func insertFindingRow(table string, row map[string]interface{}) {
	if writer == nil {
		return
	}
	payload, _ := json.Marshal(row)
	writer.insertAsync(table, append(payload, '\n'))
}

// gitleaksBin returns the gitleaks CLI path when available (OPA_GITLEAKS_BIN or PATH).
func gitleaksBin() string {
	if b := strings.TrimSpace(os.Getenv("OPA_GITLEAKS_BIN")); b != "" {
		if filepath.IsAbs(b) {
			if st, err := os.Stat(b); err == nil && !st.IsDir() {
				return b
			}
			return ""
		}
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
		return ""
	}
	if p, err := exec.LookPath("gitleaks"); err == nil {
		return p
	}
	return ""
}

func secretsScannerMode() string {
	if gitleaksBin() != "" {
		return "gitleaks"
	}
	return "lite"
}

func gitleaksSeverity(ruleID string) string {
	r := strings.ToLower(strings.TrimSpace(ruleID))
	switch {
	case strings.Contains(r, "private-key"), strings.Contains(r, "aws"),
		strings.Contains(r, "secret-key"), strings.Contains(r, "private_key"):
		return "critical"
	case strings.Contains(r, "github"), strings.Contains(r, "gitlab"),
		strings.Contains(r, "slack"), strings.Contains(r, "token"),
		strings.Contains(r, "password"), strings.Contains(r, "credential"):
		return "high"
	default:
		return "medium"
	}
}

// isLikelySecretFalsePositive filters common UI FPs (object keys named key, React
// key= props) that gitleaks generic-api-key still emits after config allowlists.
func isLikelySecretFalsePositive(rule, file, match, secret string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	if rule != "generic-api-key" && !strings.Contains(rule, "generic") {
		return false
	}
	line := match
	if line == "" {
		line = secret
	}
	ui := uiPathHint.MatchString(file)
	if objectKeyFP.MatchString(line) && (ui || len(secret) < 40) {
		// Object literal `key: '…'` — not an API credential name.
		if !regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?key|private[_-]?key)`).MatchString(line) {
			return true
		}
		// Still FP when the identifier is exactly `key:` in UI sources.
		if ui && regexp.MustCompile(`(?i)(?:^|[,\s{(\[])['"]?key['"]?\s*:`).MatchString(line) {
			return true
		}
	}
	if ui && jsxKeyFP.MatchString(line) {
		return true
	}
	if objectKeysCall.MatchString(line) {
		return true
	}
	// Placeholder / empty-ish secrets in frontend.
	sec := strings.TrimSpace(secret)
	if ui && (sec == "" || strings.EqualFold(sec, "undefined") || strings.EqualFold(sec, "null") ||
		strings.HasPrefix(sec, "process.env") || strings.HasPrefix(sec, "import.meta")) {
		return true
	}
	return false
}

func rememberSecretSeverity(runID, sev string) {
	if runID == "" {
		return
	}
	v, _ := secretSevByRun.LoadOrStore(runID, map[string]int{})
	m := v.(map[string]int)
	// Per-run maps are only written from that run's goroutine; copy-on-store
	// keeps the stored value immutable if another reader loads mid-update.
	cp := map[string]int{}
	for k, n := range m {
		cp[k] = n
	}
	cp[sev]++
	secretSevByRun.Store(runID, cp)
}

func rememberSecretFP(runID string) {
	if runID == "" {
		return
	}
	n := 0
	if v, ok := secretFPFilterBy.Load(runID); ok {
		n, _ = v.(int)
	}
	secretFPFilterBy.Store(runID, n+1)
}

func takeSecretSeverityCounts(runID string) (map[string]int, int) {
	sev := map[string]int{}
	if v, ok := secretSevByRun.Load(runID); ok {
		if m, ok := v.(map[string]int); ok {
			for k, n := range m {
				sev[k] = n
			}
		}
		secretSevByRun.Delete(runID)
	}
	fp := 0
	if v, ok := secretFPFilterBy.Load(runID); ok {
		fp, _ = v.(int)
		secretFPFilterBy.Delete(runID)
	}
	return sev, fp
}

// gitleaksConfigPath returns a config file for `gitleaks detect --config`.
// Order: OPA_GITLEAKS_CONFIG → /etc/opa/gitleaks.toml → embedded write to temp.
func gitleaksConfigPath() (path string, cleanup func()) {
	cleanup = func() {}
	if p := strings.TrimSpace(os.Getenv("OPA_GITLEAKS_CONFIG")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, cleanup
		}
	}
	if st, err := os.Stat("/etc/opa/gitleaks.toml"); err == nil && !st.IsDir() {
		return "/etc/opa/gitleaks.toml", cleanup
	}
	if len(embeddedGitleaksConfig) == 0 {
		return "", cleanup
	}
	f, err := os.CreateTemp("", "opa-gitleaks-config-*.toml")
	if err != nil {
		return "", cleanup
	}
	if _, err := f.Write(embeddedGitleaksConfig); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", cleanup
	}
	_ = f.Close()
	return f.Name(), func() { _ = os.Remove(f.Name()) }
}

type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
}

// scanSecrets prefers the gitleaks CLI when present; otherwise embedded regex lite.
// scmJobID labels sandboxed boxes (opa.job) for cancel teardown; the checkout
// LayoutID is always path-derived so srun-* security ids never fail bind checks.
func scanSecrets(runID, org, proj, service, root, scmJobID string) (int, string, error) {
	if bin := gitleaksBin(); bin != "" {
		n, err := scanSecretsGitleaks(bin, runID, org, proj, service, root, scmJobID)
		if err == nil {
			return n, "gitleaks", nil
		}
		// Soft fallback — binary present but failed (timeout, bad report, etc.).
		n2, err2 := scanSecretsLite(runID, org, proj, service, root)
		if err2 != nil {
			return n2, "embedded-secret-scan", fmt.Errorf("gitleaks: %v; lite: %w", err, err2)
		}
		return n2, "embedded-secret-scan", nil
	}
	n, err := scanSecretsLite(runID, org, proj, service, root)
	return n, "embedded-secret-scan", err
}

func scanSecretsGitleaks(bin, runID, org, proj, service, root, scmJobID string) (int, error) {
	report, err := os.CreateTemp("", "opa-gitleaks-*.json")
	if err != nil {
		return 0, err
	}
	reportPath := report.Name()
	_ = report.Close()
	defer os.Remove(reportPath)

	cfgPath, cfgCleanup := gitleaksConfigPath()
	defer cfgCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()

	if sandboxMode() == "docker" {
		if err := scanSecretsGitleaksSandboxed(ctx, scmJobID, root, reportPath); err != nil {
			return 0, err
		}
		return ingestGitleaksReport(reportPath, runID, org, proj, service, root)
	}

	args := []string{
		"detect",
		"--source", root,
		"--no-git",
		"--no-banner",
		"--report-format", "json",
		"--report-path", reportPath,
		"--exit-code", "0",
		"--timeout", "120",
	}
	env := jobEnv(jobEnvSpec{
		Phase: jobPhaseScan,
		Extra: map[string]string{"GITLEAKS_CONFIG": ""},
	})
	if cfgPath != "" {
		args = append(args, "--config", cfgPath)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	out = redactJobOutput(out)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return 0, fmt.Errorf("gitleaks detect: timeout")
		}
		msg := strings.TrimSpace(string(out))
		if len(msg) > 240 {
			msg = msg[:240]
		}
		return 0, fmt.Errorf("gitleaks detect: %w (%s)", err, msg)
	}
	return ingestGitleaksReport(reportPath, runID, org, proj, service, root)
}

// scanSecretsGitleaksSandboxed runs gitleaks inside opa-runner-scan with the
// report written to a host-mounted /out directory (preserves detector=gitleaks).
// scmJobID is the cancel label (opa.job); LayoutID/WorkRel come from the checkout
// path so security srun-* ids never become bind identities.
func scanSecretsGitleaksSandboxed(ctx context.Context, scmJobID, root, hostReport string) error {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		return fmt.Errorf("gitleaks sandbox requires absolute root")
	}
	// Path-derived layout identity: checkout lives under
	// OPA_REVIEW_TMP/<scm-job-or-run-id>/{primary|sandbox}.
	layoutID := resolveSandboxJobID("", root)
	workRel := sandboxWorkRel(root)
	// Cancel teardown targets opa.job=<scm child/job id>; fall back to layout.
	jobID := resolveSandboxJobID(scmJobID, root)
	outDir, err := os.MkdirTemp("", "opa-gitleaks-out-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(outDir)
	argv := []string{
		"gitleaks", "detect",
		"--source", ".",
		"--no-git",
		"--no-banner",
		"--report-format", "json",
		"--report-path", "/out/report.json",
		"--exit-code", "0",
		"--timeout", "120",
		"--config", "/etc/opa/gitleaks.toml",
	}
	out, err := runSandboxedArgv(ctx, sandboxExecSpec{
		Phase:       jobPhaseScan,
		JobID:       jobID,
		LayoutID:    layoutID,
		NetworkID:   layoutID,
		HostWorkDir: root,
		WorkRel:     workRel,
		Argv:        argv,
		ReadOnly:    true,
		Network:     "none",
		Image:       sandboxImageForPhase(jobPhaseScan),
		Ephemeral:   true,
		OutHostDir:  outDir,
	})
	if err != nil {
		return fmt.Errorf("sandboxed gitleaks: %w (%s)", err, truncateStr(string(out), 200))
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err != nil {
		// Some gitleaks versions omit the report file when there are zero findings.
		if os.IsNotExist(err) {
			_ = os.WriteFile(hostReport, []byte("[]"), 0o600)
			return nil
		}
		return fmt.Errorf("gitleaks report: %w", err)
	}
	return os.WriteFile(hostReport, raw, 0o600)
}

func ingestGitleaksReport(reportPath, runID, org, proj, service, root string) (int, error) {
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return 0, err
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var findings []gitleaksFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return 0, fmt.Errorf("gitleaks json: %w", err)
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	n := 0
	for _, f := range findings {
		if n >= 2000 {
			break
		}
		file := f.File
		if rel, rerr := filepath.Rel(root, file); rerr == nil && !strings.HasPrefix(rel, "..") {
			file = rel
		}
		rule := nz(f.RuleID, "gitleaks")
		if isLikelySecretFalsePositive(rule, file, f.Match, f.Secret) {
			rememberSecretFP(runID)
			continue
		}
		snippet := f.Match
		if f.Secret != "" && snippet != "" {
			snippet = strings.ReplaceAll(snippet, f.Secret, "***")
		}
		if snippet == "" {
			snippet = f.Description
		}
		snippet = strings.ReplaceAll(snippet, "\n", " ")
		if len(snippet) > 120 {
			snippet = snippet[:120]
		}
		line := f.StartLine
		if line < 0 {
			line = 0
		}
		sev := gitleaksSeverity(rule)
		rememberSecretSeverity(runID, sev)
		insertFindingRow("secret_findings", map[string]interface{}{
			"organization_id": org, "project_id": proj,
			"service": service, "rule": rule, "file": file,
			"line": line, "severity": sev,
			"snippet": snippet, "detector": "gitleaks",
			"security_run_id": runID, "scraped_at": now,
		})
		n++
	}
	return n, nil
}

func scanSecretsLite(runID, org, proj, service, root string) (int, error) {
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, file := range walkScanFiles(root, 5000) {
		st, err := os.Stat(file)
		if err != nil || st.Size() > 2<<20 {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, file)
		lines := strings.Split(string(raw), "\n")
		for _, pat := range secretPatterns {
			for i, line := range lines {
				if !pat.re.MatchString(line) {
					continue
				}
				if isLikelySecretFalsePositive(pat.rule, rel, line, "") {
					rememberSecretFP(runID)
					continue
				}
				snippet := pat.re.ReplaceAllString(line, "***")
				if len(snippet) > 120 {
					snippet = snippet[:120]
				}
				rememberSecretSeverity(runID, pat.severity)
				insertFindingRow("secret_findings", map[string]interface{}{
					"organization_id": org, "project_id": proj,
					"service": service, "rule": pat.rule, "file": rel,
					"line": i + 1, "severity": pat.severity,
					"snippet": snippet, "detector": "embedded-secret-scan",
					"security_run_id": runID, "scraped_at": now,
				})
				n++
			}
		}
	}
	return n, nil
}

func scanSASTLite(runID, org, proj, service, root string) (int, error) {
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, file := range walkScanFiles(root, 5000) {
		ext := strings.ToLower(filepath.Ext(file))
		st, err := os.Stat(file)
		if err != nil || st.Size() > 1.5*1024*1024 {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, file)
		lines := strings.Split(string(raw), "\n")
		for _, rule := range sastRules {
			if !rule.exts[ext] {
				continue
			}
			for i, line := range lines {
				if !rule.re.MatchString(line) {
					continue
				}
				msg := rule.message + ": " + strings.TrimSpace(line)
				if len(msg) > 200 {
					msg = msg[:200]
				}
				insertFindingRow("sast_findings", map[string]interface{}{
					"organization_id": org, "project_id": proj,
					"service": service, "rule": rule.rule, "file": rel,
					"line": i + 1, "severity": rule.severity, "message": msg,
					"security_run_id": runID, "scraped_at": now,
				})
				n++
			}
		}
	}
	return n, nil
}

func scanIaCStub(runID, org, proj, service, root string) (int, error) {
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, file := range walkScanFiles(root, 2000) {
		name := filepath.Base(file)
		ext := strings.ToLower(filepath.Ext(file))
		isDocker := name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.")
		isTF := ext == ".tf"
		if !isDocker && !isTF {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, file)
		text := string(raw)
		if isDocker {
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(strings.ToUpper(line), "FROM ") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) < 2 {
					continue
				}
				image := parts[1]
				sev := "low"
				msg := "FROM " + image
				if image == "latest" || strings.HasSuffix(strings.ToLower(image), ":latest") || !strings.Contains(image, ":") {
					sev = "medium"
					msg = "Unpinned / latest base image: " + image
				}
				insertFindingRow("iac_findings", map[string]interface{}{
					"organization_id": org, "project_id": proj,
					"service": service, "kind": "dockerfile", "rule": "docker-from",
					"file": rel, "severity": sev, "message": msg,
					"security_run_id": runID, "scraped_at": now,
				})
				n++
			}
		}
		if isTF {
			re := regexp.MustCompile(`resource\s+"([^"]+)"\s+"([^"]+)"`)
			for _, m := range re.FindAllStringSubmatch(text, -1) {
				typ, name := m[1], m[2]
				insertFindingRow("iac_findings", map[string]interface{}{
					"organization_id": org, "project_id": proj,
					"service": service, "kind": "terraform", "rule": "tf-resource",
					"file": rel, "severity": "info", "message": fmt.Sprintf(`resource "%s" "%s"`, typ, name),
					"security_run_id": runID, "scraped_at": now,
				})
				n++
				if regexp.MustCompile(`aws_security_group|aws_s3_bucket|google_storage_bucket|azurerm_storage_account`).MatchString(typ) {
					insertFindingRow("iac_findings", map[string]interface{}{
						"organization_id": org, "project_id": proj,
						"service": service, "kind": "terraform", "rule": "tf-sensitive-resource",
						"file": rel, "severity": "low",
						"message": fmt.Sprintf("Review sensitive resource %s.%s (stub)", typ, name),
						"security_run_id": runID, "scraped_at": now,
					})
					n++
				}
			}
		}
	}
	return n, nil
}

func scanContainerStub(runID, org, proj, service, root, image string) (int, error) {
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	img := strings.TrimSpace(image)
	if img == "" {
		img = "app:local"
	}
	add := func(rule, sev, msg string) {
		insertFindingRow("iac_findings", map[string]interface{}{
			"organization_id": org, "project_id": proj,
			"service": service, "kind": "container", "rule": rule,
			"file": img, "severity": sev, "message": msg,
			"security_run_id": runID, "scraped_at": now,
		})
		n++
	}
	if strings.HasSuffix(strings.ToLower(img), ":latest") || !strings.Contains(img, ":") {
		add("floating_tag", "medium", "Image tag is floating (:latest or untagged)")
	}
	if regexp.MustCompile(`(?i)root|admin`).MatchString(img) {
		add("suspicious_name", "low", "Image name suggests privileged role")
	}
	_ = root
	return n, nil
}

func scanSBOMLite(runID, org, proj, service, root string) (int, error) {
	// Seed service_dependencies from package.json / composer.json when present.
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	candidates := []struct {
		name string
		eco  string
	}{
		{"package.json", "npm"},
		{"composer.json", "composer"},
	}
	for _, c := range candidates {
		path := filepath.Join(root, c.name)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var body map[string]interface{}
		if json.Unmarshal(raw, &body) != nil {
			continue
		}
		deps, _ := body["dependencies"].(map[string]interface{})
		for pkg, ver := range deps {
			v := fmt.Sprint(ver)
			insertFindingRow("service_dependencies", map[string]interface{}{
				"organization_id": org, "project_id": proj,
				"service": service, "package_name": pkg, "version": strings.TrimPrefix(v, "^~"),
				"ecosystem": c.eco, "release": "", "scraped_at": now,
			})
			n++
			if n >= 200 {
				break
			}
		}
	}
	_ = runID
	return n, nil
}
