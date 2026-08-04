package main

import (
	"strings"
	"testing"
)

// An unreachable security service must never look like a policy violation.
func TestGateCheckOutcomeUnavailableIsNeutral(t *testing.T) {
	v := gateUnavailable("srun-1", "high", "peer_unavailable", "could not reach the OSA AppSec gate")
	v["error"] = "peer GET /api/security/gate: 401 Unauthorized: invalid token"

	if v["fail"] == true {
		t.Fatal("unavailable verdict must not set fail=true")
	}
	conclusion, title := gateCheckOutcome(v)
	if conclusion != "neutral" {
		t.Errorf("conclusion = %q, want neutral", conclusion)
	}
	if !strings.Contains(title, "could not evaluate") {
		t.Errorf("title = %q, want a could-not-evaluate title", title)
	}
	sum := gateCheckSummary(v, "srun-1")
	if !strings.Contains(sum, "not a policy violation") {
		t.Errorf("summary must say it is not a violation: %s", sum)
	}
	if !strings.Contains(sum, "401") {
		t.Errorf("summary must carry the underlying cause: %s", sum)
	}
}

func TestGateCheckOutcomeFailAndPass(t *testing.T) {
	fail := map[string]interface{}{
		"status": gateStatusFail, "fail": true,
		"reasons": []string{"secret_findings findings present"},
		"scope":   "security_run",
	}
	if c, title := gateCheckOutcome(fail); c != "failure" || title != "AppSec Gate failed" {
		t.Errorf("blocking findings: got (%q, %q), want (failure, AppSec Gate failed)", c, title)
	}

	pass := map[string]interface{}{
		"status": gateStatusPass, "fail": false,
		"reasons": []string{}, "scope": "security_run",
	}
	if c, title := gateCheckOutcome(pass); c != "success" || title != "AppSec Gate passed" {
		t.Errorf("clean run: got (%q, %q), want (success, AppSec Gate passed)", c, title)
	}
}

// Legacy status=error verdicts persisted on older jobs must also read as neutral.
func TestGateIsUnavailableLegacyErrorStatus(t *testing.T) {
	if !gateIsUnavailable(map[string]interface{}{"status": "error", "fail": true}) {
		t.Error("status=error should be treated as unavailable")
	}
	if !gateIsUnavailable(nil) {
		t.Error("nil verdict should be treated as unavailable")
	}
	if gateIsUnavailable(map[string]interface{}{"status": gateStatusFail, "fail": true}) {
		t.Error("a real failing verdict must not be unavailable")
	}
}

func TestEvaluateScopedGateWithoutPeerIsUnavailable(t *testing.T) {
	t.Setenv("PEER_OSA_URL", "")
	v := evaluateScopedGate("default-org", "srun-2", "high")
	if v["fail"] == true {
		t.Fatal("no configured peer must not fail the gate")
	}
	if c, _ := gateCheckOutcome(v); c != "neutral" {
		t.Errorf("conclusion = %q, want neutral", c)
	}
	if got := v["reasons"]; !strings.Contains(strings.ToLower(strings.Trim(strings.Join(toStrings(got), ","), "[]")), "peer_not_configured") {
		t.Errorf("reasons = %v, want peer_not_configured", got)
	}
}

// gateAfterScan turns a failed hand-off into an unavailable verdict rather than
// reading findings from a run that never started.
func TestGateAfterScanStartErrorIsUnavailable(t *testing.T) {
	t.Setenv("PEER_OSA_URL", "http://osa-api:8093")
	v := gateAfterScan("default-org", "srun-3", "high", errFake("create run: 500"))
	if v["fail"] == true {
		t.Fatal("failed scan hand-off must not fail the gate")
	}
	if c, _ := gateCheckOutcome(v); c != "neutral" {
		t.Errorf("conclusion = %q, want neutral", c)
	}
	if !strings.Contains(strings.Join(toStrings(v["reasons"]), ","), "scan_not_started") {
		t.Errorf("reasons = %v, want scan_not_started", v["reasons"])
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }

func toStrings(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
