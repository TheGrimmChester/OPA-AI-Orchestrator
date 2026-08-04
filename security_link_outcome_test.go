package main

import (
	"strings"
	"testing"
)

// The AppSec check must never present a gate that could not run as a clean scan.
// Regression: a peer failure produced "AppSec Gate failed" with an empty reasons
// list and no finding data, which read as "scanned, 0 findings".

func TestAppSecCheckOutcomeNotEvaluated(t *testing.T) {
	gate := gateNotRun("srun-1", "high", "peer_unavailable", "OSA gate call failed")

	conclusion, title, summary := appSecCheckOutcome(gate, "srun-1")
	if conclusion != "failure" {
		t.Fatalf("a gate that could not run must fail closed, got %q", conclusion)
	}
	if !strings.Contains(title, "could not run") {
		t.Fatalf("title must say the gate could not run, got %q", title)
	}
	if !strings.Contains(summary, "not evaluated") {
		t.Fatalf("summary must mark the result not evaluated, got %q", summary)
	}
	if strings.Contains(summary, "no findings") {
		t.Fatalf("summary must not imply a clean scan, got %q", summary)
	}
	if gateStatusLabel(gate) != "not_evaluated" {
		t.Fatalf("gate status label = %q, want not_evaluated", gateStatusLabel(gate))
	}
}

func TestAppSecCheckOutcomeEvaluatedClean(t *testing.T) {
	gate := map[string]interface{}{
		"status": "pass", "fail": false, "evaluated": true,
		"reasons": []string{}, "scope": "security_run", "min_severity": "high",
	}

	conclusion, title, summary := appSecCheckOutcome(gate, "srun-2")
	if conclusion != "success" {
		t.Fatalf("conclusion = %q, want success", conclusion)
	}
	if !strings.Contains(title, "passed") {
		t.Fatalf("title = %q, want passed", title)
	}
	if !strings.Contains(summary, "no findings at or above high") {
		t.Fatalf("summary must state what was cleared, got %q", summary)
	}
	if !strings.Contains(summary, "evaluated") {
		t.Fatalf("summary must mark the result evaluated, got %q", summary)
	}
}

func TestAppSecCheckOutcomeEvaluatedFail(t *testing.T) {
	gate := map[string]interface{}{
		"status": "fail", "fail": true, "evaluated": true,
		"reasons": []string{"sast_findings present"}, "scope": "security_run",
		"min_severity": "high",
	}

	conclusion, title, summary := appSecCheckOutcome(gate, "srun-3")
	if conclusion != "failure" {
		t.Fatalf("conclusion = %q, want failure", conclusion)
	}
	if strings.Contains(title, "could not run") {
		t.Fatalf("a real finding must not read as a broken gate, got %q", title)
	}
	if !strings.Contains(summary, "sast_findings present") {
		t.Fatalf("summary must carry the blocking reason, got %q", summary)
	}
}

// Gate results persisted before "evaluated" existed, and the synthetic ai_only
// result, carry no evaluated key and must keep their old meaning.
func TestAppSecCheckOutcomeLegacyGateTreatedAsEvaluated(t *testing.T) {
	legacy := map[string]interface{}{
		"status": "pass", "fail": false,
		"reasons": []string{}, "scope": "security_run", "min_severity": "high",
	}
	if !gateWasEvaluated(legacy) {
		t.Fatal("gate without evaluated key must be treated as evaluated")
	}
	if conclusion, _, _ := appSecCheckOutcome(legacy, "srun-4"); conclusion != "success" {
		t.Fatalf("legacy pass conclusion = %q, want success", conclusion)
	}

	aiOnly := map[string]interface{}{
		"status": "pass", "fail": false, "reasons": []string{"ai_only"},
		"scope": "security_run", "min_severity": "high",
	}
	if conclusion, _, _ := appSecCheckOutcome(aiOnly, "srun-5"); conclusion != "success" {
		t.Fatalf("ai_only conclusion = %q, want success", conclusion)
	}
}

// evaluateScopedGate with no peer configured must report not-evaluated, not a pass.
func TestEvaluateScopedGateWithoutPeerIsNotEvaluated(t *testing.T) {
	t.Setenv("PEER_OSA_URL", "")

	gate := evaluateScopedGate("org-1", "srun-6", "high")
	if gateWasEvaluated(gate) {
		t.Fatal("gate with no peer configured must not claim to be evaluated")
	}
	if gate["fail"] != true {
		t.Fatal("gate with no peer configured must fail closed")
	}
}

// A scan that was never dispatched must not leave the caller free to read an
// empty finding set as a pass.
func TestRunSecurityScanJobWithoutPeerReturnsError(t *testing.T) {
	t.Setenv("PEER_OSA_URL", "")

	err := runSecurityScanJob("srun-7", "org-1", "proj-1", "svc", "auto",
		[]string{"secrets"}, "/tmp/x", "", "owner/repo", 1, "sha", "job-1")
	if err == nil {
		t.Fatal("expected an error when no AppSec scan was dispatched")
	}
}
