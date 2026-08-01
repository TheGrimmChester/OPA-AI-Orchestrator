package main

import "testing"

func TestDecideOPAReviewEvent(t *testing.T) {
	clean := aiReviewResult{Status: "ok", AutoMergeConfidence: 85, Verdict: "approve"}
	if got := decideOPAReviewEvent(clean, 0); got != "COMMENT" {
		t.Fatalf("minScore=0 want COMMENT got %s", got)
	}
	if got := decideOPAReviewEvent(clean, 70); got != "APPROVE" {
		t.Fatalf("high score want APPROVE got %s", got)
	}
	low := aiReviewResult{Status: "ok", AutoMergeConfidence: 40, Verdict: "approve"}
	if got := decideOPAReviewEvent(low, 70); got != "REQUEST_CHANGES" {
		t.Fatalf("low score want REQUEST_CHANGES got %s", got)
	}
	findings := aiReviewResult{
		Status: "findings", AutoMergeConfidence: 90, Verdict: "approve",
		Findings: []map[string]interface{}{{"severity": "high", "file": "a.go", "line": 1}},
	}
	if got := decideOPAReviewEvent(findings, 70); got != "REQUEST_CHANGES" {
		t.Fatalf("high findings want REQUEST_CHANGES got %s", got)
	}
	skipped := aiReviewResult{Status: "skipped", AutoMergeConfidence: 0}
	if got := decideOPAReviewEvent(skipped, 70); got != "COMMENT" {
		t.Fatalf("skipped want COMMENT got %s", got)
	}
}
