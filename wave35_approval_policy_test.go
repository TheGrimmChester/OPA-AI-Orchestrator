package main

import (
	"strings"
	"testing"
)

func TestParseApprovalPolicyRejectsWiden(t *testing.T) {
	if _, err := parseApprovalPolicy(`{"version":1,"approve_if":{"any":true}}`); err == nil {
		t.Fatal("expected reject of approve_if")
	}
	if _, err := parseApprovalPolicy(`{"version":1,"require":["security"],"mystery":true}`); err == nil {
		t.Fatal("expected reject of unknown key")
	}
	p, err := parseApprovalPolicy(`{"version":1,"require":["security"],"block_if":{"security_min_severity":"high"},"on_fail":"COMMENT"}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Require) != 1 || p.Require[0] != "security" {
		t.Fatalf("require parse: %+v", p.Require)
	}
}

func TestEvaluateApprovalConfidenceVetoOnly(t *testing.T) {
	clean := aiReviewResult{Status: "ok", AutoMergeConfidence: 95, Verdict: "approve"}
	// High confidence alone must not grant APPROVE when auto_approve is off.
	d := evaluateApproval(approvalEvidence{Bugbot: clean, BugbotOK: true, Prefs: agentPrefs{AutoApprove: false}})
	if d.Event != "COMMENT" {
		t.Fatalf("auto off want COMMENT got %s", d.Event)
	}
	// MinScore > 0 without AutoApprove must not grant APPROVE.
	d = evaluateApproval(approvalEvidence{
		Bugbot: clean, BugbotOK: true, Prefs: agentPrefs{AutoApprove: false}, MinScore: 70,
	})
	if d.Event != "COMMENT" {
		t.Fatalf("minScore alone want COMMENT got %s", d.Event)
	}
	// Degraded never APPROVE even with high confidence + auto on.
	d = evaluateApproval(approvalEvidence{
		Bugbot: clean, BugbotOK: true, Prefs: agentPrefs{AutoApprove: true}, MinScore: 70,
		Degraded: []string{"bugbot incomplete"},
	})
	if d.Event != "COMMENT" || d.Honesty == "" {
		t.Fatalf("degraded want COMMENT+honesty got %+v", d)
	}
	// Low confidence vetoes to REQUEST_CHANGES.
	low := aiReviewResult{Status: "ok", AutoMergeConfidence: 20, Verdict: "approve"}
	d = evaluateApproval(approvalEvidence{
		Bugbot: low, BugbotOK: true, Prefs: agentPrefs{AutoApprove: true}, MinScore: 70,
	})
	if d.Event != "REQUEST_CHANGES" {
		t.Fatalf("low conf want REQUEST_CHANGES got %s", d.Event)
	}
	// Security gate failure blocks APPROVE.
	d = evaluateApproval(approvalEvidence{
		Bugbot: clean, BugbotOK: true, Prefs: agentPrefs{AutoApprove: true}, MinScore: 70,
		SecurityFail: true, SecurityOK: false,
	})
	if d.Event != "REQUEST_CHANGES" {
		t.Fatalf("gate fail want REQUEST_CHANGES got %s", d.Event)
	}
	// Conjunction satisfied → APPROVE (confidence did not grant; evidence did).
	d = evaluateApproval(approvalEvidence{
		Bugbot: clean, BugbotOK: true, SecurityOK: true,
		Prefs: agentPrefs{AutoApprove: true}, MinScore: 70,
	})
	if d.Event != "APPROVE" {
		t.Fatalf("clean conjunction want APPROVE got %s (%s)", d.Event, d.Honesty)
	}
	// Policy require security not OK → on_fail COMMENT.
	d = evaluateApproval(approvalEvidence{
		Bugbot: clean, BugbotOK: true, SecurityOK: false,
		Prefs: agentPrefs{AutoApprove: true}, MinScore: 70,
		Policy: &approvalPolicy{Version: 1, Require: []string{"security"}, OnFail: "COMMENT"},
	})
	if d.Event != "COMMENT" {
		t.Fatalf("require miss want COMMENT got %s", d.Event)
	}
	// Unparseable policy honesty → never APPROVE.
	d = evaluateApproval(approvalEvidence{
		Bugbot: clean, BugbotOK: true, Prefs: agentPrefs{AutoApprove: true}, MinScore: 70,
		PolicyHonesty: "policy unparseable: bad",
	})
	if d.Event != "COMMENT" {
		t.Fatalf("bad policy want COMMENT got %s", d.Event)
	}
	// Cloud child pending → COMMENT.
	d = evaluateApproval(approvalEvidence{
		Bugbot: clean, BugbotOK: true, SecurityOK: true,
		Prefs: agentPrefs{AutoApprove: true}, MinScore: 70, CloudChildExists: true,
	})
	if d.Event != "COMMENT" {
		t.Fatalf("pending autofix want COMMENT got %s", d.Event)
	}
}

func TestMaskFindingBody(t *testing.T) {
	masked := maskFindingBody("token=AKIA1234567890ABCDEFGH_extra_long_secret_value_here_xx")
	if strings.Contains(masked, "AKIA123") {
		t.Fatalf("AKIA not masked: %s", masked)
	}
	if !strings.Contains(masked, "AKIA***") {
		t.Fatalf("expected AKIA*** got %s", masked)
	}
	f := agentFinding{Key: "k1", Severity: "high", Rule: "aws-key", Message: "sk-abcdefghijklmnopqrstuvwxyz012345"}
	body := formatMaskedSecurityInline(f)
	if !strings.Contains(body, "opa-review:finding:k1") {
		t.Fatal("missing marker")
	}
	if !strings.Contains(body, "[security:high]") {
		t.Fatal("missing severity tag")
	}
	if strings.Contains(body, "sk-abcdefghijklmnopqrstuvwxyz012345") {
		t.Fatal("secret leaked in inline body")
	}
}

func TestComputeCarriedForwardKeys(t *testing.T) {
	touched := map[string]struct{}{"a.go": {}}
	priorKeys := []string{"k-a", "k-b"}
	files := map[string]string{"k-a": "a.go", "k-b": "b.go"}
	got := computeCarriedForwardKeys(priorKeys, files, touched)
	if len(got) != 1 || got[0] != "k-b" {
		t.Fatalf("want [k-b] got %v", got)
	}
	diff := "diff --git a/x.go b/x.go\n+++ b/x.go\n+line\n"
	paths := diffPathsFromUnified(diff)
	if _, ok := paths["x.go"]; !ok {
		t.Fatalf("expected x.go in %v", paths)
	}
}

func TestPlanOPAReviewCommentActionsCarried(t *testing.T) {
	findings := []map[string]interface{}{
		{"file": "a.go", "line": 3, "severity": "high", "message": "oops", "rule": "r1"},
	}
	keyKeep := opaReviewFindingKey(findings[0])
	keyCarried := opaReviewFindingKey(map[string]interface{}{
		"file": "untouched.go", "message": "still open", "rule": "old",
	})
	prior := []opaReviewPriorComment{
		{ID: 1, Key: keyKeep, Path: "a.go", Line: 3, Body: embedOPAReviewFindingMarker("old", keyKeep)},
		{ID: 2, Key: keyCarried, Path: "untouched.go", Line: 1, Body: embedOPAReviewFindingMarker("carried", keyCarried)},
	}
	carried := map[string]struct{}{keyCarried: {}}
	plan := planOPAReviewCommentActions(findings, prior, carried)
	for _, c := range plan.Close {
		if c.Key == keyCarried {
			t.Fatal("carried key must not be Closed")
		}
	}
}
