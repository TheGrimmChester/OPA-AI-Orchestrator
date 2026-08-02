package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// checkupPlan is the AI-derived (or heuristically derived) check plan for a PR
// tree. Treat every field as untrusted input — intersectSpecWithPolicy is the
// only path into the runner.
type checkupPlan struct {
	Version  int               `json:"version"`
	Image    string            `json:"image"`
	Steps    []checkupStep     `json:"steps"`
	Services []checkupService  `json:"services"`
	Env      map[string]string `json:"env,omitempty"`     // non-secret only
	Secrets  []string          `json:"secrets,omitempty"` // names only; values never in plan
	Source   string            `json:"source,omitempty"`  // agents.md|heuristic|ai|raw
}

type checkupStep struct {
	ID            string                `json:"id"`
	Argv          []string              `json:"argv"` // never a shell string
	TimeoutSec    int                   `json:"timeout_sec,omitempty"`
	PostCondition checkupPostCondition  `json:"post_condition"`
	Env           map[string]string     `json:"env,omitempty"`
	WorkingDir    string                `json:"working_dir,omitempty"` // rel under work, optional
}

type checkupPostCondition struct {
	// Kind: exit0 | junit | checkstyle | stdout_contains | artifact_exists
	Kind     string `json:"kind"`
	Path     string `json:"path,omitempty"`      // junit/artifact path under work
	MinTests int    `json:"min_tests,omitempty"` // junit: require ≥ N testcases
	Contains string `json:"contains,omitempty"`  // stdout_contains
}

type checkupService struct {
	Key              string            `json:"key"` // network alias (= compose service name)
	Image            string            `json:"image"`
	Env              map[string]string `json:"env,omitempty"`
	HealthCmd        []string          `json:"health_cmd,omitempty"` // argv; required when image has no HEALTHCHECK
	HealthTimeoutSec int               `json:"health_timeout_sec,omitempty"`
	Memory           string            `json:"memory,omitempty"`
	CPUs             string            `json:"cpus,omitempty"`
}

const (
	checkupPlanMaxBytes    = 64 * 1024
	checkupPlanMaxSteps    = 20
	checkupPlanMaxServices = 6
)

// agentInstructionFiles are read (when present) as plan sources. Contents are
// attacker-editable — never trusted beyond the policy envelope.
var agentInstructionFiles = []string{
	"AGENTS.md", "CLAUDE.md", "CURSOR.md",
}

// parseCheckupPlanJSON parses a raw plan blob. Caller must still intersect.
func parseCheckupPlanJSON(raw []byte) (*checkupPlan, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty plan")
	}
	if len(raw) > checkupPlanMaxBytes {
		return nil, fmt.Errorf("plan exceeds %d bytes", checkupPlanMaxBytes)
	}
	var p checkupPlan
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("plan json: %w", err)
	}
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Source == "" {
		p.Source = "raw"
	}
	return &p, nil
}

// deriveCheckupPlan builds an untrusted candidate plan from the PR tree.
// Prefers an ```opa-checkup-plan JSON fence in AGENTS.md / CLAUDE.md /
// CURSOR.md / .cursor/rules; otherwise a conservative heuristic from
// composer.json / package.json / phpunit.xml / go.mod.
func deriveCheckupPlan(treeRoot string) (*checkupPlan, error) {
	treeRoot = filepath.Clean(strings.TrimSpace(treeRoot))
	if treeRoot == "" {
		return nil, fmt.Errorf("empty tree root")
	}
	if p := extractPlanFromInstructionFiles(treeRoot); p != nil {
		return p, nil
	}
	return heuristicCheckupPlan(treeRoot), nil
}

func extractPlanFromInstructionFiles(treeRoot string) *checkupPlan {
	var blobs []string
	for _, name := range agentInstructionFiles {
		raw, err := os.ReadFile(filepath.Join(treeRoot, name))
		if err == nil && len(raw) > 0 {
			blobs = append(blobs, string(raw))
		}
	}
	rulesDir := filepath.Join(treeRoot, ".cursor", "rules")
	_ = filepath.WalkDir(rulesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(treeRoot, path)
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr == nil && len(raw) > 0 && len(raw) < checkupPlanMaxBytes {
			blobs = append(blobs, string(raw))
		}
		return nil
	})
	for _, blob := range blobs {
		if raw := extractOPACheckupFence(blob); len(raw) > 0 {
			p, err := parseCheckupPlanJSON(raw)
			if err != nil {
				continue
			}
			p.Source = "agents.md"
			return p
		}
	}
	return nil
}

func extractOPACheckupFence(md string) []byte {
	const open = "```opa-checkup-plan"
	i := strings.Index(md, open)
	if i < 0 {
		// also accept json language tag with marker comment
		const alt = "```json"
		j := strings.Index(md, alt)
		for j >= 0 {
			rest := md[j+len(alt):]
			nl := strings.IndexByte(rest, '\n')
			if nl < 0 {
				break
			}
			body := rest[nl+1:]
			closeIdx := strings.Index(body, "```")
			if closeIdx < 0 {
				break
			}
			chunk := strings.TrimSpace(body[:closeIdx])
			if strings.Contains(chunk, `"steps"`) && strings.Contains(chunk, `"argv"`) {
				return []byte(chunk)
			}
			next := strings.Index(md[j+1:], alt)
			if next < 0 {
				break
			}
			j = j + 1 + next
		}
		return nil
	}
	rest := md[i+len(open):]
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return nil
	}
	body := rest[nl+1:]
	closeIdx := strings.Index(body, "```")
	if closeIdx < 0 {
		return nil
	}
	return []byte(strings.TrimSpace(body[:closeIdx]))
}

// heuristicCheckupPlan produces a minimal safe-looking candidate. Policy still
// clamps image/binary/secrets before anything runs.
func heuristicCheckupPlan(treeRoot string) *checkupPlan {
	p := &checkupPlan{
		Version: 1,
		Source:  "heuristic",
		Image:   defaultCheckupImage(),
		Env:     map[string]string{},
	}
	hasComposer := fileExists(filepath.Join(treeRoot, "composer.json"))
	hasPHPUnit := fileExists(filepath.Join(treeRoot, "phpunit.xml")) ||
		fileExists(filepath.Join(treeRoot, "phpunit.xml.dist"))
	hasPackage := fileExists(filepath.Join(treeRoot, "package.json"))
	hasGoMod := fileExists(filepath.Join(treeRoot, "go.mod"))

	if hasComposer {
		p.Image = defaultPHPCheckupImage()
		p.Steps = append(p.Steps, checkupStep{
			ID:   "composer-install",
			Argv: []string{"composer", "install", "--no-interaction", "--prefer-dist", "--no-scripts", "--no-plugins"},
			PostCondition: checkupPostCondition{
				Kind: "artifact_exists", Path: "vendor/autoload.php",
			},
			TimeoutSec: 900,
		})
		p.Secrets = append(p.Secrets, "COMPOSER_AUTH")
	}
	if hasComposer && hasPHPUnit {
		// Prefer vendored binary (basename still allowlisted as phpunit).
		p.Steps = append(p.Steps, checkupStep{
			ID: "phpunit-unit",
			Argv: []string{
				"vendor/bin/phpunit", "--testsuite", "Unit Tests",
				"--log-junit", "build/junit-unit.xml",
			},
			PostCondition: checkupPostCondition{
				Kind: "junit", Path: "build/junit-unit.xml", MinTests: 1,
			},
			TimeoutSec: 1200,
		})
	}
	if hasComposer {
		if stan, ok := phpstanHeuristicStep(treeRoot); ok {
			p.Steps = append(p.Steps, stan)
		}
	}
	if hasPackage {
		lock := "package-lock.json"
		argv := []string{"npm", "ci"}
		if fileExists(filepath.Join(treeRoot, "yarn.lock")) {
			argv = []string{"yarn", "install", "--immutable"}
		} else if !fileExists(filepath.Join(treeRoot, lock)) {
			argv = []string{"npm", "install", "--no-fund", "--no-audit"}
		}
		p.Steps = append(p.Steps, checkupStep{
			ID:            "node-install",
			Argv:          argv,
			PostCondition: checkupPostCondition{Kind: "artifact_exists", Path: "node_modules"},
			TimeoutSec:    900,
		})
		p.Image = nz(os.Getenv("OPA_JOB_IMAGE_NODE"), "node:22")
	}
	if hasGoMod {
		p.Steps = append(p.Steps, checkupStep{
			ID:            "go-test",
			Argv:          []string{"go", "test", "./..."},
			PostCondition: checkupPostCondition{Kind: "exit0"},
			TimeoutSec:    1200,
		})
		p.Image = defaultGoCheckupImage()
	}
	if len(p.Steps) == 0 {
		// Empty plan is valid — runner records honesty "no checkup steps derived".
		p.Steps = nil
	}
	return p
}

func defaultCheckupImage() string {
	if v := strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_CHECKUP")); v != "" {
		return v
	}
	tag := nz(strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_TAG")), "smoke")
	return "opa-runner-ai:" + tag
}

// defaultGoCheckupImage picks a Go toolchain image (opa-runner-git has git only).
func defaultGoCheckupImage() string {
	if v := strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_GO")); v != "" {
		return v
	}
	return "golang:1.25"
}

// defaultPHPCheckupImage is the checkup box for composer/phpunit trees.
// OPA_JOB_IMAGE_PHP overrides; else opa-runner-php:<tag>. Operators may point
// OPA_JOB_IMAGE_PHP at an allowlisted org image (e.g. hebabil/php-8.4-cli)
// when a fleet needs extensions beyond the shipped runner.
func defaultPHPCheckupImage() string {
	if v := strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_PHP")); v != "" {
		return v
	}
	tag := nz(strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_TAG")), "smoke")
	return "opa-runner-php:" + tag
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st != nil
}

// checkupPlanDiffSummarizes changes vs a prior plan for the check-run summary.
func checkupPlanDiffSummary(prev, cur *checkupPlan) string {
	if prev == nil && cur == nil {
		return ""
	}
	if prev == nil {
		return "plan: first run"
	}
	if cur == nil {
		return "plan: cleared"
	}
	var notes []string
	if prev.Image != cur.Image {
		notes = append(notes, fmt.Sprintf("image %s → %s", prev.Image, cur.Image))
	}
	if len(prev.Steps) != len(cur.Steps) {
		notes = append(notes, fmt.Sprintf("steps %d → %d", len(prev.Steps), len(cur.Steps)))
	}
	prevIDs := map[string]bool{}
	for _, s := range prev.Steps {
		prevIDs[s.ID] = true
	}
	for _, s := range cur.Steps {
		if !prevIDs[s.ID] {
			notes = append(notes, "added step "+s.ID)
		}
	}
	if len(notes) == 0 {
		return "plan: unchanged"
	}
	return "plan changed: " + strings.Join(notes, "; ")
}
