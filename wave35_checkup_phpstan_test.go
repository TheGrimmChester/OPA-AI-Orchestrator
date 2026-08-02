package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPHPStanHeuristicStepAndHonesty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"name":"acme/app"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "phpstan.neon"), []byte("parameters:\n  level: 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := heuristicCheckupPlan(dir)
	var stan *checkupStep
	for i := range p.Steps {
		if p.Steps[i].ID == "phpstan" {
			stan = &p.Steps[i]
			break
		}
	}
	if stan == nil {
		t.Fatalf("want phpstan step, got %+v", p.Steps)
	}
	if stan.Argv[0] != "vendor/bin/phpstan" {
		t.Fatalf("argv0=%q", stan.Argv[0])
	}
	joined := strings.Join(stan.Argv, " ")
	if !strings.Contains(joined, "--no-progress") || !strings.Contains(joined, "--error-format=checkstyle") {
		t.Fatalf("want --no-progress + checkstyle, got %v", stan.Argv)
	}
	if stan.PostCondition.Kind != "checkstyle" {
		t.Fatalf("post=%+v", stan.PostCondition)
	}
	note := phpstanNewErrorsHonesty(dir, p)
	if !strings.Contains(note, "full analyse") {
		t.Fatalf("without baseline want full-analyse honesty, got %q", note)
	}

	if err := os.WriteFile(filepath.Join(dir, "phpstan-baseline.neon"), []byte("parameters:\n  ignoreErrors: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	note = phpstanNewErrorsHonesty(dir, p)
	if !strings.Contains(note, "new-errors-only") || !strings.Contains(note, "phpstan-baseline.neon") {
		t.Fatalf("with baseline want new-errors-only honesty, got %q", note)
	}
}

func TestNormalizePHPStanStep(t *testing.T) {
	in := checkupStep{
		ID:            "lint",
		Argv:          []string{"phpstan", "src"},
		PostCondition: checkupPostCondition{Kind: "exit0"},
	}
	out := normalizePHPStanStep(in)
	if out.Argv[0] != "vendor/bin/phpstan" {
		t.Fatalf("argv0=%q", out.Argv[0])
	}
	joined := strings.Join(out.Argv, " ")
	if !strings.Contains(joined, "analyse") || !strings.Contains(joined, "--no-progress") {
		t.Fatalf("argv=%v", out.Argv)
	}
	if !strings.Contains(joined, "--error-format=checkstyle") {
		t.Fatalf("missing checkstyle format: %v", out.Argv)
	}
	if out.PostCondition.Kind != "checkstyle" {
		t.Fatalf("post kind=%q", out.PostCondition.Kind)
	}

	// Conflicting format is replaced.
	in2 := checkupStep{
		ID:   "lint",
		Argv: []string{"vendor/bin/phpstan", "analyse", "--error-format=json", "app"},
		PostCondition: checkupPostCondition{Kind: "checkstyle"},
	}
	out2 := normalizePHPStanStep(in2)
	joined2 := strings.Join(out2.Argv, " ")
	if strings.Contains(joined2, "--error-format=json") {
		t.Fatalf("json format should be dropped: %v", out2.Argv)
	}
	if !strings.Contains(joined2, "--error-format=checkstyle") {
		t.Fatalf("want checkstyle: %v", out2.Argv)
	}
}

func TestIntersectPolicyNormalizesPHPStan(t *testing.T) {
	t.Setenv("OPA_JOB_IMAGE_ALLOW", "opa-runner-*")
	raw := &checkupPlan{
		Version: 1,
		Image:   "opa-runner-php:smoke",
		Steps: []checkupStep{{
			ID:            "stan",
			Argv:          []string{"phpstan", "analyse", "src"},
			PostCondition: checkupPostCondition{Kind: "exit0"},
		}},
	}
	res := intersectSpecWithPolicy(raw)
	if len(res.Plan.Steps) != 1 {
		t.Fatalf("steps=%v drops=%v", res.Plan.Steps, res.Drops)
	}
	s := res.Plan.Steps[0]
	if s.Argv[0] != "vendor/bin/phpstan" {
		t.Fatalf("argv0=%q", s.Argv[0])
	}
	if s.PostCondition.Kind != "checkstyle" {
		t.Fatalf("post=%+v", s.PostCondition)
	}
}

func TestFindPHPStanConfigDist(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "phpstan.dist.neon"), []byte("parameters:\n  level: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := findPHPStanConfig(dir)
	if cfg != "phpstan.dist.neon" {
		t.Fatalf("cfg=%q", cfg)
	}
	step, ok := phpstanHeuristicStep(dir)
	if !ok {
		t.Fatal("expected step")
	}
	joined := strings.Join(step.Argv, " ")
	if !strings.Contains(joined, "-c") || !strings.Contains(joined, "phpstan.dist.neon") {
		t.Fatalf("want -c dist neon, got %v", step.Argv)
	}
}
