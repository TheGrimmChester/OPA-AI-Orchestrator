package main

import (
	"strings"
	"testing"
)

func TestEmbedOPAReviewDecisionMarker(t *testing.T) {
	got := embedOPAReviewDecisionMarker("**OPA Review**\n\nConfidence **25/100**.")
	if !strings.Contains(got, opaReviewDecisionMarker) {
		t.Fatalf("missing marker: %q", got)
	}
	again := embedOPAReviewDecisionMarker(got)
	if strings.Count(again, opaReviewDecisionMarker) != 1 {
		t.Fatalf("marker duplicated: %q", again)
	}
}

func TestReviewStateMatchesEvent(t *testing.T) {
	if !reviewStateMatchesEvent("CHANGES_REQUESTED", "REQUEST_CHANGES") {
		t.Fatal("CHANGES_REQUESTED should match REQUEST_CHANGES")
	}
	if !reviewStateMatchesEvent("APPROVED", "APPROVE") {
		t.Fatal("APPROVED should match APPROVE")
	}
	if reviewStateMatchesEvent("COMMENTED", "REQUEST_CHANGES") {
		t.Fatal("COMMENTED must not match REQUEST_CHANGES")
	}
}

func TestFindFirstOPADecisionReview(t *testing.T) {
	t.Setenv("OPA_GITHUB_APP_SLUG", "ora")
	reviews := []githubPRReview{
		{ID: 1, User: "someone", Body: "**OPA Review**", State: "COMMENTED"},
		{ID: 2, User: "ora[bot]", Body: "noise", State: "COMMENTED"},
		{ID: 3, User: "ora[bot]", Body: "**OPA Review**\n\nConfidence **25/100**.", State: "COMMENTED"},
		{ID: 4, User: "ora[bot]", Body: opaReviewDecisionMarker + "\nlater", State: "CHANGES_REQUESTED"},
	}
	first := findFirstOPADecisionReview(reviews)
	if first == nil || first.ID != 3 {
		t.Fatalf("want first matching OPA Review body id=3, got %#v", first)
	}
}

func TestPublishOPADecisionReviewSkipsCommentWithoutPrior(t *testing.T) {
	job := &scmJob{ID: "j1", PRNumber: 26, CommitSHA: "abc"}
	if err := publishOPADecisionReview(nil, "o", "r", job, "**OPA Review**", "COMMENT"); err != nil {
		t.Fatalf("COMMENT with no prior should no-op: %v", err)
	}
}
