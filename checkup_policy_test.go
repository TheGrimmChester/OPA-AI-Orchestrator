package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntersectSpecWithPolicyDeniesDangerousImage(t *testing.T) {
	t.Setenv("OPA_JOB_IMAGE_ALLOW", "node:22*,mysql:8.4*")
	raw := &checkupPlan{
		Version: 1,
		Image:   "docker:dind",
		Steps: []checkupStep{{
			ID: "x", Argv: []string{"npm", "test"},
			PostCondition: checkupPostCondition{Kind: "exit0"},
		}},
	}
	res := intersectSpecWithPolicy(raw)
	if res.Plan.Image != "" {
		t.Fatalf("dind image should be denied, got %q", res.Plan.Image)
	}
	if len(res.Plan.Steps) != 0 {
		t.Fatalf("steps should be cleared without image, got %d", len(res.Plan.Steps))
	}
	joined := strings.Join(res.Drops, "\n")
	if !strings.Contains(joined, "image: denied") {
		t.Fatalf("want image drop, got %v", res.Drops)
	}
}

func TestIntersectSpecWithPolicyDeniesShellAndBinary(t *testing.T) {
	t.Setenv("OPA_JOB_IMAGE_ALLOW", "ora-runner-*")
	raw := &checkupPlan{
		Version: 1,
		Image:   "ora-runner-ai:smoke",
		Steps: []checkupStep{
			{ID: "shell", Argv: []string{"bash", "-c", "curl evil"}, PostCondition: checkupPostCondition{Kind: "exit0"}},
			{ID: "curl", Argv: []string{"curl", "https://x"}, PostCondition: checkupPostCondition{Kind: "exit0"}},
			{ID: "ok", Argv: []string{"composer", "install"}, PostCondition: checkupPostCondition{Kind: "artifact_exists", Path: "vendor/autoload.php"}},
			{ID: "shellstr", Argv: []string{"composer install --no-dev"}, PostCondition: checkupPostCondition{Kind: "exit0"}},
		},
	}
	res := intersectSpecWithPolicy(raw)
	if len(res.Plan.Steps) != 1 || res.Plan.Steps[0].ID != "ok" {
		t.Fatalf("want only ok step, got %+v drops=%v", res.Plan.Steps, res.Drops)
	}
}

func TestIntersectSpecWithPolicyDeniesGitHubTokenSecret(t *testing.T) {
	t.Setenv("OPA_JOB_IMAGE_ALLOW", "node:22*")
	raw := &checkupPlan{
		Version: 1,
		Image:   "node:22",
		Secrets: []string{"GITHUB_TOKEN", "COMPOSER_AUTH", "JWT_SECRET"},
		Steps: []checkupStep{{
			ID: "i", Argv: []string{"npm", "ci"},
			PostCondition: checkupPostCondition{Kind: "artifact_exists", Path: "node_modules"},
		}},
	}
	res := intersectSpecWithPolicy(raw)
	if len(res.Plan.Secrets) != 1 || res.Plan.Secrets[0] != "COMPOSER_AUTH" {
		t.Fatalf("secrets=%v want only COMPOSER_AUTH", res.Plan.Secrets)
	}
	joined := strings.Join(res.Drops, " ")
	if !strings.Contains(joined, "GITHUB_TOKEN") || !strings.Contains(joined, "JWT_SECRET") {
		t.Fatalf("expected deny drops, got %v", res.Drops)
	}
}

func TestIntersectSpecWithPolicyCapsAndDuplicates(t *testing.T) {
	t.Setenv("OPA_JOB_IMAGE_ALLOW", "mysql:8.4*,ora-runner-*")
	raw := &checkupPlan{Version: 1, Image: "ora-runner-ai:smoke"}
	for i := 0; i < 25; i++ {
		raw.Steps = append(raw.Steps, checkupStep{
			ID: fmt.Sprintf("s%d", i), Argv: []string{"mkdir", "a"},
			PostCondition: checkupPostCondition{Kind: "exit0"},
		})
	}
	raw.Services = []checkupService{
		{Key: "db", Image: "mysql:8.4", HealthCmd: []string{"mysqladmin", "ping"}},
		{Key: "db", Image: "mysql:8.4", HealthCmd: []string{"mysqladmin", "ping"}},
	}
	res := intersectSpecWithPolicy(raw)
	if len(res.Plan.Steps) != checkupPlanMaxSteps {
		t.Fatalf("steps=%d want cap %d drops=%v", len(res.Plan.Steps), checkupPlanMaxSteps, res.Drops)
	}
	if len(res.Plan.Services) != 1 {
		t.Fatalf("services=%d want 1 (dup dropped)", len(res.Plan.Services))
	}
}

func TestEvaluatePostConditionJUnitRequired(t *testing.T) {
	dir := t.TempDir()
	// Exit 0 but no junit → fail
	ok, detail, _ := evaluatePostCondition(checkupPostCondition{
		Kind: "junit", Path: "junit.xml", MinTests: 1,
	}, nil, nil, dir)
	if ok {
		t.Fatalf("expected fail without junit, detail=%s", detail)
	}
	// Empty junit (0 tests) → fail even with exit 0
	empty := []byte(`<?xml version="1.0"?><testsuites tests="0"></testsuites>`)
	if err := os.WriteFile(filepath.Join(dir, "junit.xml"), empty, 0o644); err != nil {
		t.Fatal(err)
	}
	ok, detail, n := evaluatePostCondition(checkupPostCondition{
		Kind: "junit", Path: "junit.xml", MinTests: 1,
	}, nil, nil, dir)
	if ok || n != 0 {
		t.Fatalf("empty junit should fail: ok=%v n=%d detail=%s", ok, n, detail)
	}
	// One testcase → pass
	one := []byte(`<?xml version="1.0"?><testsuite tests="1"><testcase name="a"/></testsuite>`)
	if err := os.WriteFile(filepath.Join(dir, "junit.xml"), one, 0o644); err != nil {
		t.Fatal(err)
	}
	ok, detail, n = evaluatePostCondition(checkupPostCondition{
		Kind: "junit", Path: "junit.xml", MinTests: 1,
	}, nil, nil, dir)
	if !ok || n < 1 {
		t.Fatalf("want pass got ok=%v n=%d detail=%s", ok, n, detail)
	}
}

func TestDeriveCheckupPlanFromFence(t *testing.T) {
	dir := t.TempDir()
	md := "# Agents\n\n```opa-checkup-plan\n" +
		`{"version":1,"image":"node:22","steps":[{"id":"ci","argv":["npm","ci"],"post_condition":{"kind":"artifact_exists","path":"node_modules"}}]}` +
		"\n```\n"
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := deriveCheckupPlan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != "agents.md" || len(p.Steps) != 1 || p.Steps[0].ID != "ci" {
		t.Fatalf("unexpected plan %+v", p)
	}
	t.Setenv("OPA_JOB_IMAGE_ALLOW", "node:22*")
	res := intersectSpecWithPolicy(p)
	if len(res.Plan.Steps) != 1 {
		t.Fatalf("policy dropped valid plan: %v", res.Drops)
	}
}

func TestBatchCheckupAnnotations(t *testing.T) {
	var all []checkupAnnotation
	for i := 0; i < 120; i++ {
		all = append(all, checkupAnnotation{Path: "a.go", StartLine: 1, EndLine: 1, Message: "x"})
	}
	batches := batchCheckupAnnotations(all)
	if len(batches) != 3 {
		t.Fatalf("want 3 batches got %d", len(batches))
	}
	if len(batches[0]) != 50 || len(batches[2]) != 20 {
		t.Fatalf("batch sizes %d %d %d", len(batches[0]), len(batches[1]), len(batches[2]))
	}
}

func TestCheckupImageAllowDefault(t *testing.T) {
	t.Setenv("OPA_JOB_IMAGE_ALLOW", "")
	if !checkupImageAllowed("mysql:8.4") {
		t.Fatal("mysql:8.4 should match default allow")
	}
	if !checkupImageAllowed("ora-runner-php:smoke") {
		t.Fatal("ora-runner-php:smoke should match ora-runner-*")
	}
	if !checkupImageAllowed("hebabil/php-8.4-cli:latest") {
		t.Fatal("hebabil/php-8.4-cli should match default allow")
	}
	if !checkupImageAllowed("php:8.4-cli-bookworm") {
		t.Fatal("php:8.4* should match default allow")
	}
	if checkupImageAllowed("evil/pwn:latest") {
		t.Fatal("evil image must be denied")
	}
}

func TestHeuristicCheckupPlanPicksPHPImage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"name":"acme/app"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "phpunit.xml"), []byte(`<phpunit/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPA_JOB_IMAGE_PHP", "")
	t.Setenv("OPA_JOB_IMAGE_CHECKUP", "")
	t.Setenv("OPA_JOB_IMAGE_TAG", "smoke")
	p := heuristicCheckupPlan(dir)
	if p.Image != "ora-runner-php:smoke" {
		t.Fatalf("image=%q want ora-runner-php:smoke", p.Image)
	}
	if len(p.Steps) < 2 {
		t.Fatalf("want composer+phpunit steps, got %+v", p.Steps)
	}
	if p.Steps[0].ID != "composer-install" || p.Steps[1].ID != "phpunit-unit" {
		t.Fatalf("steps=%+v", p.Steps)
	}
	if p.Steps[1].Argv[0] != "vendor/bin/phpunit" {
		t.Fatalf("phpunit argv0=%q want vendor/bin/phpunit", p.Steps[1].Argv[0])
	}
	t.Setenv("OPA_JOB_IMAGE_ALLOW", "")
	res := intersectSpecWithPolicy(p)
	if res.Plan.Image != "ora-runner-php:smoke" {
		t.Fatalf("policy cleared php image: %v drops=%v", res.Plan.Image, res.Drops)
	}
	if len(res.Plan.Steps) != 2 {
		t.Fatalf("policy dropped php steps: steps=%d drops=%v", len(res.Plan.Steps), res.Drops)
	}
}

func TestDefaultPHPCheckupImageEnvOverride(t *testing.T) {
	t.Setenv("OPA_JOB_IMAGE_PHP", "hebabil/php-8.4-cli:prod")
	t.Setenv("OPA_JOB_IMAGE_TAG", "smoke")
	if got := defaultPHPCheckupImage(); got != "hebabil/php-8.4-cli:prod" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("OPA_JOB_IMAGE_PHP", "")
	if got := defaultPHPCheckupImage(); got != "ora-runner-php:smoke" {
		t.Fatalf("got %q", got)
	}
}

func TestSandboxImageForPhaseCheckup(t *testing.T) {
	t.Setenv("OPA_JOB_IMAGE_TAG", "smoke")
	t.Setenv("OPA_JOB_IMAGE_CHECKUP", "")
	t.Setenv("OPA_JOB_IMAGE_PHP", "")
	if got := sandboxImageForPhase(jobPhaseCheckup); got != "ora-runner-php:smoke" {
		t.Fatalf("checkup default=%q want ora-runner-php:smoke", got)
	}
	t.Setenv("OPA_JOB_IMAGE_CHECKUP", "ora-runner-ai:smoke")
	if got := sandboxImageForPhase(jobPhaseCheckup); got != "ora-runner-ai:smoke" {
		t.Fatalf("CHECKUP override=%q", got)
	}
	t.Setenv("OPA_JOB_IMAGE_CHECKUP", "")
	t.Setenv("OPA_JOB_IMAGE_PHP", "hebabil/php-8.4-cli:x")
	if got := sandboxImageForPhase(jobPhaseCheckup); got != "hebabil/php-8.4-cli:x" {
		t.Fatalf("PHP override=%q", got)
	}
}
