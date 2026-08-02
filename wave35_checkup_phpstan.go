package main

import (
	"path/filepath"
	"strings"
)

// PHPStan config / baseline filenames commonly committed in PHP trees.
// Baseline inclusion is a neon `includes:` concern — we only detect presence
// for honesty ("new-errors-only best-effort").
var phpstanConfigNames = []string{
	"phpstan.neon",
	"phpstan.neon.dist",
	"phpstan.dist.neon",
}

var phpstanBaselineNames = []string{
	"phpstan-baseline.neon",
	"phpstan-baseline.neon.php",
}

func findPHPStanConfig(treeRoot string) string {
	for _, name := range phpstanConfigNames {
		if fileExists(filepath.Join(treeRoot, name)) {
			return name
		}
	}
	return ""
}

func findPHPStanBaseline(treeRoot string) string {
	for _, name := range phpstanBaselineNames {
		if fileExists(filepath.Join(treeRoot, name)) {
			return name
		}
	}
	return ""
}

func planHasPHPStanStep(plan *checkupPlan) bool {
	if plan == nil {
		return false
	}
	for _, s := range plan.Steps {
		if checkupArgvBinary(s.Argv[0]) == "phpstan" || strings.EqualFold(strings.TrimSpace(s.ID), "phpstan") {
			return true
		}
	}
	return false
}

// phpstanHeuristicStep builds a vendor phpstan analyse step when a neon config
// is present. Post-condition is checkstyle on stdout (phpstan has no --output-file).
// When a baseline file exists and the neon includes it, phpstan itself reports
// only new errors — we document that as best-effort, not a second differ.
func phpstanHeuristicStep(treeRoot string) (checkupStep, bool) {
	cfg := findPHPStanConfig(treeRoot)
	if cfg == "" {
		return checkupStep{}, false
	}
	argv := []string{
		"vendor/bin/phpstan", "analyse",
		"--no-progress",
		"--error-format=checkstyle",
	}
	// Explicit -c when not the default auto-discovered name.
	if cfg != "phpstan.neon" {
		argv = append(argv, "-c", cfg)
	}
	return checkupStep{
		ID:   "phpstan",
		Argv: argv,
		PostCondition: checkupPostCondition{
			Kind: "checkstyle", // empty path → parse step stdout
		},
		TimeoutSec: 1200,
	}, true
}

// normalizePHPStanStep prefers vendor/bin/phpstan, ensures --no-progress and
// checkstyle error format, and upgrades bare exit0 posts to checkstyle so
// annotations can surface. Called during policy intersection.
func normalizePHPStanStep(step checkupStep) checkupStep {
	if len(step.Argv) == 0 || checkupArgvBinary(step.Argv[0]) != "phpstan" {
		return step
	}
	out := step
	out.Argv = append([]string(nil), step.Argv...)

	base := filepath.Base(out.Argv[0])
	if base == "phpstan" && !strings.Contains(out.Argv[0], "vendor"+string(filepath.Separator)+"bin") {
		out.Argv[0] = "vendor/bin/phpstan"
	}

	hasAnalyse := false
	hasNoProgress := false
	hasCheckstyle := false
	for _, a := range out.Argv[1:] {
		switch {
		case a == "analyse" || a == "analyze":
			hasAnalyse = true
		case a == "--no-progress":
			hasNoProgress = true
		case a == "--error-format=checkstyle" || strings.HasPrefix(a, "--error-format=checkstyle"):
			hasCheckstyle = true
		case a == "--error-format" || a == "-error-format":
			// next arg handled below via scan
		}
	}
	for i := 1; i < len(out.Argv)-1; i++ {
		if out.Argv[i] == "--error-format" && strings.EqualFold(out.Argv[i+1], "checkstyle") {
			hasCheckstyle = true
		}
	}

	rest := out.Argv[1:]
	var rebuilt []string
	rebuilt = append(rebuilt, out.Argv[0])
	if !hasAnalyse {
		rebuilt = append(rebuilt, "analyse")
	}
	rebuilt = append(rebuilt, rest...)
	if !hasNoProgress {
		rebuilt = append(rebuilt, "--no-progress")
	}
	if !hasCheckstyle {
		// Drop conflicting --error-format=* so checkstyle wins for annotations.
		cleaned := []string{rebuilt[0]}
		skipNext := false
		for i := 1; i < len(rebuilt); i++ {
			if skipNext {
				skipNext = false
				continue
			}
			a := rebuilt[i]
			if a == "--error-format" {
				skipNext = true
				continue
			}
			if strings.HasPrefix(a, "--error-format=") {
				continue
			}
			cleaned = append(cleaned, a)
		}
		rebuilt = append(cleaned, "--error-format=checkstyle")
	}
	out.Argv = rebuilt

	kind := strings.ToLower(strings.TrimSpace(out.PostCondition.Kind))
	if kind == "" || kind == "exit0" || kind == "exit_zero" || kind == "exit-code" {
		out.PostCondition = checkupPostCondition{Kind: "checkstyle"}
	}
	return out
}

// phpstanNewErrorsHonesty explains how phpstan failures should be read.
func phpstanNewErrorsHonesty(treeRoot string, plan *checkupPlan) string {
	if !planHasPHPStanStep(plan) {
		return ""
	}
	if bl := findPHPStanBaseline(treeRoot); bl != "" {
		return "phpstan: new-errors-only best-effort when neon includes " + bl + " (phpstan exit≠0 ⇒ new errors vs baseline)"
	}
	return "phpstan: full analyse (no baseline file; any reported error fails the check)"
}
