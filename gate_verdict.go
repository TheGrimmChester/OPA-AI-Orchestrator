package main

import (
	"fmt"
	"strings"
)

// A gate has three outcomes, not two. "Findings block the merge" and "the gate
// could not be evaluated" are different facts and must not share a check-run
// conclusion: reporting an unreachable scanner as a policy violation trains
// reviewers to merge past red checks, which is worse than no gate at all.
//
// Unavailable verdicts carry fail=false and unavailable=true, and the check run
// reports neutral so the pull request shows "could not evaluate" instead of
// "failed".

const (
	gateStatusPass        = "pass"
	gateStatusFail        = "fail"
	gateStatusUnavailable = "unavailable"
)

// gateUnavailable builds the verdict used whenever the gate cannot reach a
// decision. reason is a short machine token (peer_unavailable,
// peer_not_configured, scan_incomplete); detail carries the operator-facing
// cause.
func gateUnavailable(runID, minSev, reason, detail string) map[string]interface{} {
	out := map[string]interface{}{
		"status":          gateStatusUnavailable,
		"fail":            false,
		"unavailable":     true,
		"reasons":         []string{reason},
		"scope":           "security_run",
		"security_run_id": runID,
		"min_severity":    minSev,
	}
	if detail != "" {
		out["honesty"] = detail
	}
	return out
}

// gateIsUnavailable reports whether a verdict means "could not evaluate".
func gateIsUnavailable(gate map[string]interface{}) bool {
	if gate == nil {
		return true
	}
	if v, ok := gate["unavailable"].(bool); ok && v {
		return true
	}
	if s, _ := gate["status"].(string); s == gateStatusUnavailable || s == "error" {
		return true
	}
	return false
}

// gateCheckOutcome maps a verdict to a GitHub check-run conclusion and title.
// Only a real policy decision produces failure.
func gateCheckOutcome(gate map[string]interface{}) (conclusion, title string) {
	if gateIsUnavailable(gate) {
		return "neutral", "AppSec Gate could not evaluate"
	}
	if gate["fail"] == true {
		return "failure", "AppSec Gate failed"
	}
	return "success", "AppSec Gate passed"
}

// gateCheckSummary renders the verdict for the check-run body, naming the cause
// when the gate could not run so an operator can fix it without opening logs.
func gateCheckSummary(gate map[string]interface{}, runID string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "scope=%v reasons=%v security_run_id=%s", gate["scope"], gate["reasons"], runID)
	if gateIsUnavailable(gate) {
		b.WriteString("\n\nThe AppSec gate did not evaluate this commit — this is not a policy violation.")
		if h, _ := gate["honesty"].(string); h != "" {
			b.WriteString("\ncause: " + h)
		}
		if e, _ := gate["error"].(string); e != "" {
			b.WriteString("\ndetail: " + truncateStr(strings.TrimSpace(e), 300))
		}
		b.WriteString("\nRe-run the review once the security service is reachable to get a verdict.")
		return b.String()
	}
	if notes, ok := gate["soft_notes"].([]interface{}); ok && len(notes) > 0 {
		for _, n := range notes {
			fmt.Fprintf(&b, "\nnote: %v", n)
		}
	}
	return b.String()
}
