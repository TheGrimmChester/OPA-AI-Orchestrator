package main

import "testing"

func TestDecideOPAReviewEvent(t *testing.T) {
	clean := aiReviewResult{Status: "ok", AutoMergeConfidence: 85, Verdict: "approve"}
	if got := decideOPAReviewEvent(clean, 0); got != "COMMENT" {
		t.Fatalf("minScore=0 want COMMENT got %s", got)
	}
	// MinScore alone must never grant APPROVE (veto-only; AutoApprove stays off).
	if got := decideOPAReviewEvent(clean, 70); got != "COMMENT" {
		t.Fatalf("high score alone want COMMENT got %s", got)
	}
	low := aiReviewResult{Status: "ok", AutoMergeConfidence: 40, Verdict: "approve"}
	// Without AutoApprove, low confidence also stays COMMENT (veto path not reached as grant).
	if got := decideOPAReviewEvent(low, 70); got != "COMMENT" {
		t.Fatalf("low score without auto_approve want COMMENT got %s", got)
	}
	findings := aiReviewResult{
		Status: "findings", AutoMergeConfidence: 90, Verdict: "approve",
		Findings: []map[string]interface{}{{"severity": "high", "file": "a.go", "line": 1}},
	}
	if got := decideOPAReviewEvent(findings, 70); got != "COMMENT" {
		t.Fatalf("findings without auto_approve want COMMENT got %s", got)
	}
	skipped := aiReviewResult{Status: "skipped", AutoMergeConfidence: 0}
	if got := decideOPAReviewEvent(skipped, 70); got != "COMMENT" {
		t.Fatalf("skipped want COMMENT got %s", got)
	}
}
