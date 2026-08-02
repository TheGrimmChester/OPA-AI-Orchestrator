package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// checkupBinaryAllowlist is the only set of argv[0] basenames a plan may invoke.
// Always argv slices — never shell strings.
var checkupBinaryAllowlist = map[string]bool{
	"composer": true, "phpunit": true, "phpstan": true, "php-cs-fixer": true,
	"npm": true, "yarn": true, "go": true, "phinx": true,
	"cp": true, "mkdir": true,
}

// checkupDeniedBinaries are refused even if somehow added to an allowlist later.
var checkupDeniedBinaries = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "fish": true,
	"sudo": true, "su": true, "docker": true, "podman": true,
	"curl": true, "wget": true, "nc": true, "ncat": true, "python": true,
	"python3": true, "perl": true, "ruby": true, "node": true, // node via npm scripts only
}

// checkupGrantableSecrets are the only secret NAMES a plan may request.
// Values come from orchestrator credentials — never from the plan body.
var checkupGrantableSecrets = map[string]bool{
	"COMPOSER_AUTH": true,
	"NPM_TOKEN":     true,
	"NPM_AUTH":      true,
	"NODE_AUTH_TOKEN": true,
}

// checkupDeniedSecretNames are always rejected (even if grantable list drifts).
var checkupDeniedSecretNames = map[string]bool{
	"GITHUB_TOKEN":              true,
	"GH_TOKEN":                  true,
	"OPA_GIT_ASKPASS_TOKEN":     true,
	"GIT_ASKPASS":               true,
	"JWT_SECRET":                true,
	"OPA_CONNECTOR_SECRET":      true,
	"OPA_GITHUB_APP_PRIVATE_KEY": true,
	"OPA_GITHUB_WEBHOOK_SECRET": true,
	"CLICKHOUSE_URL":            true,
	"CURSOR_API_KEY":            true,
}

const (
	checkupDefaultStepTimeoutSec = 600
	checkupMaxStepTimeoutSec     = 1800
	checkupDefaultServiceTimeout = 120
	checkupMaxServiceTimeout     = 300
	checkupDefaultJobMemory      = "4g"
	checkupDefaultJobCPUs        = "2"
	checkupDefaultSvcMemory      = "1g"
	checkupDefaultSvcCPUs        = "1"
)

// checkupPolicyResult is the clamped plan plus human-readable drop reasons.
type checkupPolicyResult struct {
	Plan  *checkupPlan
	Drops []string
}

// intersectSpecWithPolicy clamps image/binary/secret/egress/resource and
// structural caps. The capability envelope is non-negotiable; drops are always
// surfaced so a silently truncated plan cannot read as "covered everything".
func intersectSpecWithPolicy(raw *checkupPlan) checkupPolicyResult {
	res := checkupPolicyResult{Drops: []string{}}
	if raw == nil {
		res.Drops = append(res.Drops, "plan: nil input")
		res.Plan = &checkupPlan{Version: 1, Source: "empty"}
		return res
	}
	out := &checkupPlan{
		Version: raw.Version,
		Source:  raw.Source,
		Env:     map[string]string{},
	}
	if out.Version <= 0 {
		out.Version = 1
	}

	// Image — must glob-match OPA_JOB_IMAGE_ALLOW.
	img := strings.TrimSpace(raw.Image)
	if img == "" {
		img = defaultCheckupImage()
		res.Drops = append(res.Drops, "image: empty — using default "+img)
	}
	if !checkupImageAllowed(img) {
		res.Drops = append(res.Drops, "image: denied "+img+" (OPA_JOB_IMAGE_ALLOW)")
		img = ""
	}
	out.Image = img

	// Env — drop secret-looking keys; no egress hosts from plan.
	for k, v := range raw.Env {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		uk := strings.ToUpper(k)
		if envNameLooksSecret(k) || checkupDeniedSecretNames[uk] {
			res.Drops = append(res.Drops, "env: dropped secret-looking "+k)
			continue
		}
		if isEgressEnvKey(uk) {
			res.Drops = append(res.Drops, "env: dropped egress override "+k)
			continue
		}
		out.Env[k] = v
	}

	// Secrets — names only, grantable ∩ ¬denied.
	seenSec := map[string]bool{}
	for _, name := range raw.Secrets {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		uk := strings.ToUpper(name)
		if checkupDeniedSecretNames[uk] || strings.Contains(uk, "GITHUB") && strings.Contains(uk, "TOKEN") {
			res.Drops = append(res.Drops, "secret: denied "+name)
			continue
		}
		if !checkupGrantableSecrets[uk] && !checkupGrantableSecrets[name] {
			res.Drops = append(res.Drops, "secret: not grantable "+name)
			continue
		}
		if seenSec[uk] {
			res.Drops = append(res.Drops, "secret: duplicate "+name)
			continue
		}
		seenSec[uk] = true
		out.Secrets = append(out.Secrets, uk)
	}

	// Services — caps + image allow + key sanity.
	seenSvc := map[string]bool{}
	for i, svc := range raw.Services {
		if len(out.Services) >= checkupPlanMaxServices {
			res.Drops = append(res.Drops, fmt.Sprintf("service: cap %d reached — dropped remaining", checkupPlanMaxServices))
			break
		}
		key := sanitizeServiceKey(svc.Key)
		if key == "" {
			res.Drops = append(res.Drops, fmt.Sprintf("service[%d]: empty/invalid key", i))
			continue
		}
		if seenSvc[key] {
			res.Drops = append(res.Drops, "service: duplicate key "+key)
			continue
		}
		simg := strings.TrimSpace(svc.Image)
		if simg == "" || !checkupImageAllowed(simg) {
			res.Drops = append(res.Drops, "service: denied image for "+key+" ("+simg+")")
			continue
		}
		hs := svc.HealthTimeoutSec
		if hs <= 0 {
			hs = checkupDefaultServiceTimeout
		}
		if hs > checkupMaxServiceTimeout {
			res.Drops = append(res.Drops, fmt.Sprintf("service %s: health timeout clamped %d→%d", key, hs, checkupMaxServiceTimeout))
			hs = checkupMaxServiceTimeout
		}
		healthCmd := filterServiceHealthCmd(svc.HealthCmd, &res.Drops, key)
		svcEnv := map[string]string{}
		for k, v := range svc.Env {
			k = strings.TrimSpace(k)
			if k == "" || envNameLooksSecret(k) {
				if k != "" {
					res.Drops = append(res.Drops, "service "+key+": dropped secret env "+k)
				}
				continue
			}
			svcEnv[k] = v
		}
		seenSvc[key] = true
		out.Services = append(out.Services, checkupService{
			Key: key, Image: simg, Env: svcEnv,
			HealthCmd: healthCmd, HealthTimeoutSec: hs,
			Memory: nz(strings.TrimSpace(svc.Memory), checkupDefaultSvcMemory),
			CPUs:   nz(strings.TrimSpace(svc.CPUs), checkupDefaultSvcCPUs),
		})
	}

	// Steps — binary allowlist, argv-only, post-condition required, acyclic ids.
	seenStep := map[string]bool{}
	for i, step := range raw.Steps {
		if len(out.Steps) >= checkupPlanMaxSteps {
			res.Drops = append(res.Drops, fmt.Sprintf("step: cap %d reached — dropped remaining", checkupPlanMaxSteps))
			break
		}
		id := strings.TrimSpace(step.ID)
		if id == "" {
			id = fmt.Sprintf("step-%d", i+1)
		}
		if seenStep[id] {
			res.Drops = append(res.Drops, "step: duplicate id "+id)
			continue
		}
		if len(step.Argv) == 0 {
			res.Drops = append(res.Drops, "step "+id+": empty argv")
			continue
		}
		// Refuse shell-string shapes: single argv element with spaces that looks like sh -c.
		if looksLikeShellString(step.Argv) {
			res.Drops = append(res.Drops, "step "+id+": refused shell-string argv")
			continue
		}
		bin := checkupArgvBinary(step.Argv[0])
		if bin == "" || checkupDeniedBinaries[bin] || !checkupBinaryAllowlist[bin] {
			res.Drops = append(res.Drops, "step "+id+": binary denied "+step.Argv[0])
			continue
		}
		pc := normalizePostCondition(step.PostCondition, &res.Drops, id)
		if pc.Kind == "" {
			res.Drops = append(res.Drops, "step "+id+": missing post_condition")
			continue
		}
		to := step.TimeoutSec
		if to <= 0 {
			to = checkupDefaultStepTimeoutSec
		}
		if to > checkupMaxStepTimeoutSec {
			res.Drops = append(res.Drops, fmt.Sprintf("step %s: timeout clamped %d→%d", id, to, checkupMaxStepTimeoutSec))
			to = checkupMaxStepTimeoutSec
		}
		wd := strings.TrimSpace(step.WorkingDir)
		if wd != "" {
			wd = filepath.Clean(wd)
			if filepath.IsAbs(wd) || wd == ".." || strings.HasPrefix(wd, ".."+string(os.PathSeparator)) {
				res.Drops = append(res.Drops, "step "+id+": working_dir refused "+step.WorkingDir)
				wd = ""
			}
		}
		stepEnv := map[string]string{}
		for k, v := range step.Env {
			k = strings.TrimSpace(k)
			if k == "" || envNameLooksSecret(k) || isEgressEnvKey(strings.ToUpper(k)) {
				if k != "" {
					res.Drops = append(res.Drops, "step "+id+": dropped env "+k)
				}
				continue
			}
			stepEnv[k] = v
		}
		seenStep[id] = true
		clamped := checkupStep{
			ID: id, Argv: append([]string(nil), step.Argv...),
			TimeoutSec: to, PostCondition: pc, Env: stepEnv, WorkingDir: wd,
		}
		// Prefer vendor/bin/phpstan + checkstyle stdout contract (annotations).
		if checkupArgvBinary(clamped.Argv[0]) == "phpstan" {
			clamped = normalizePHPStanStep(clamped)
			// Re-normalize post after argv rewrite (may upgrade exit0 → checkstyle).
			clamped.PostCondition = normalizePostCondition(clamped.PostCondition, &res.Drops, id)
			if clamped.PostCondition.Kind == "" {
				res.Drops = append(res.Drops, "step "+id+": missing post_condition after phpstan normalize")
				continue
			}
		}
		out.Steps = append(out.Steps, clamped)
	}

	if out.Image == "" && len(out.Steps) > 0 {
		res.Drops = append(res.Drops, "plan: no allowed image — steps cannot run")
		out.Steps = nil
	}
	res.Plan = out
	return res
}

func checkupArgvBinary(argv0 string) string {
	argv0 = strings.TrimSpace(argv0)
	if argv0 == "" {
		return ""
	}
	base := filepath.Base(argv0)
	base = strings.ToLower(base)
	return base
}

func looksLikeShellString(argv []string) bool {
	if len(argv) == 1 && strings.ContainsAny(argv[0], " \t\n;&|") {
		return true
	}
	if len(argv) >= 2 {
		bin := checkupArgvBinary(argv[0])
		if checkupDeniedBinaries[bin] {
			return true
		}
		if bin == "env" || bin == "xargs" {
			return true
		}
		// classic: sh -c "…"
		if len(argv) >= 3 && (argv[1] == "-c" || argv[1] == "-lc") {
			return true
		}
	}
	return false
}

func normalizePostCondition(pc checkupPostCondition, drops *[]string, stepID string) checkupPostCondition {
	kind := strings.ToLower(strings.TrimSpace(pc.Kind))
	switch kind {
	case "exit0", "exit_zero", "exit-code":
		return checkupPostCondition{Kind: "exit0"}
	case "junit":
		path := strings.TrimSpace(pc.Path)
		if path == "" {
			*drops = append(*drops, "step "+stepID+": junit post_condition needs path")
			return checkupPostCondition{}
		}
		if !safeRelArtifactPath(path) {
			*drops = append(*drops, "step "+stepID+": junit path refused")
			return checkupPostCondition{}
		}
		min := pc.MinTests
		if min < 0 {
			min = 0
		}
		return checkupPostCondition{Kind: "junit", Path: path, MinTests: min}
	case "checkstyle":
		path := strings.TrimSpace(pc.Path)
		// checkstyle may be stdout — empty path means parse stdout
		if path != "" && !safeRelArtifactPath(path) {
			*drops = append(*drops, "step "+stepID+": checkstyle path refused")
			return checkupPostCondition{}
		}
		return checkupPostCondition{Kind: "checkstyle", Path: path}
	case "stdout_contains", "stdout":
		if strings.TrimSpace(pc.Contains) == "" {
			*drops = append(*drops, "step "+stepID+": stdout_contains needs contains")
			return checkupPostCondition{}
		}
		return checkupPostCondition{Kind: "stdout_contains", Contains: pc.Contains}
	case "artifact_exists", "artifact":
		path := strings.TrimSpace(pc.Path)
		if path == "" || !safeRelArtifactPath(path) {
			*drops = append(*drops, "step "+stepID+": artifact path refused")
			return checkupPostCondition{}
		}
		return checkupPostCondition{Kind: "artifact_exists", Path: path}
	default:
		if kind != "" {
			*drops = append(*drops, "step "+stepID+": unknown post_condition "+kind)
		}
		return checkupPostCondition{}
	}
}

func safeRelArtifactPath(p string) bool {
	p = filepath.Clean(strings.TrimSpace(p))
	if p == "" || p == "." || filepath.IsAbs(p) {
		return false
	}
	if p == ".." || strings.HasPrefix(p, ".."+string(os.PathSeparator)) {
		return false
	}
	return true
}

func sanitizeServiceKey(key string) string {
	key = strings.TrimSpace(strings.ToLower(key))
	var b strings.Builder
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

func filterServiceHealthCmd(argv []string, drops *[]string, key string) []string {
	if len(argv) == 0 {
		return nil
	}
	if looksLikeShellString(argv) {
		*drops = append(*drops, "service "+key+": health_cmd shell-string refused")
		return nil
	}
	// Health cmds commonly use mysqladmin / redis-cli / which are NOT in the
	// step binary allowlist — allow a narrow health set.
	bin := checkupArgvBinary(argv[0])
	healthOK := map[string]bool{
		"mysqladmin": true, "redis-cli": true, "pg_isready": true,
		"curl": true, "wget": true, // health only, inside service box
		"true": true, "test": true, "ls": true,
	}
	if !healthOK[bin] && !checkupBinaryAllowlist[bin] {
		*drops = append(*drops, "service "+key+": health_cmd binary denied "+argv[0])
		return nil
	}
	return append([]string(nil), argv...)
}

func isEgressEnvKey(uk string) bool {
	switch uk {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
		return true
	}
	return false
}

// checkupImageAllowed reports whether image matches OPA_JOB_IMAGE_ALLOW globs.
// Empty allowlist uses a built-in default so local smoke can opt in safely.
func checkupImageAllowed(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" {
		return false
	}
	low := strings.ToLower(image)
	if strings.HasPrefix(low, "docker:") || strings.Contains(low, "docker:dind") {
		return false
	}
	patterns := checkupImageAllowPatterns()
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if ok, _ := path.Match(pat, image); ok {
			return true
		}
		// Also try basename match for "mysql:8.4" vs "library/mysql:8.4"
		if i := strings.LastIndex(image, "/"); i >= 0 {
			if ok, _ := path.Match(pat, image[i+1:]); ok {
				return true
			}
		}
	}
	return false
}

func checkupImageAllowPatterns() []string {
	raw := strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_ALLOW"))
	if raw == "" {
		return []string{
			"mysql:8.4*", "redis:7*", "node:22*", "golang:1.25*",
			"opa-runner-*", "hebabil/php-8.4-cli*",
			"php:8.4*", "postgres:16*",
		}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
