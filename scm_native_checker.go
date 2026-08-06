package main

import (
	"encoding/json"
	"strings"
)

const (
	oraCheckerReview        = "review"
	oraCheckerReviewRunName = "OPA Review"
)

func checksInclude(checks []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, c := range checks {
		if strings.ToLower(strings.TrimSpace(c)) == want {
			return true
		}
	}
	return false
}

func oraReviewActionableEvent(eventType string) bool {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "pull_request.opened", "pull_request.synchronize", "pull_request.reopened", "pull_request.ready_for_review":
		return true
	default:
		return false
	}
}

func extractPRMergedFromRaw(raw []byte) (merged bool, mergedAt, state string) {
	if len(raw) == 0 {
		return false, "", ""
	}
	var payload struct {
		PullRequest struct {
			Merged   bool   `json:"merged"`
			MergedAt string `json:"merged_at"`
			State    string `json:"state"`
		} `json:"pull_request"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return false, "", ""
	}
	return payload.PullRequest.Merged, payload.PullRequest.MergedAt, payload.PullRequest.State
}

// evaluateORAReviewChecker decides whether the native ora:review checker should
// run for this envelope — same gates as PR webhook ingress (actionable events,
// skip merged/already-reviewed).
func evaluateORAReviewChecker(env *scmEventEnvelope, raw []byte) peerCheckerDecl {
	out := peerCheckerDecl{
		ID:           oraCheckerReview,
		CheckRunName: oraCheckerReviewRunName,
		ShouldRun:    false,
		Reason:       "review checker not applicable for this event",
	}
	if env == nil {
		return out
	}
	if len(env.Checks) > 0 && !checksInclude(env.Checks, "ora:review") {
		out.Reason = "ora:review not requested in checks filter"
		return out
	}
	if env.PRNumber <= 0 {
		out.Reason = "no pull request number — review is PR-scoped"
		return out
	}
	if !oraReviewActionableEvent(env.EventType) {
		out.Reason = "PR action not actionable (only opened/synchronize/reopened/ready_for_review)"
		return out
	}
	merged, mergedAt, state := extractPRMergedFromRaw(raw)
	if scmPRIsMerged(merged, mergedAt, state) {
		out.Reason = "pull request is already merged"
		return out
	}
	if priorID, already := lookupSuccessfulAIReviewForSHA(env.RepoFullName, env.CommitSHA, ""); already {
		out.Reason = "commit already reviewed successfully"
		if priorID != "" {
			out.Reason += " (prior job " + priorID + ")"
		}
		return out
	}
	out.ShouldRun = true
	out.Reason = "PR event " + env.EventType
	return out
}

func evaluateORANativeCheckers(env *scmEventEnvelope, checks []string, raw []byte) []peerCheckerWithProduct {
	if env == nil || !wantsORAReview(checks) {
		return nil
	}
	if len(env.Checks) == 0 {
		env.Checks = checks
	}
	decl := evaluateORAReviewChecker(env, raw)
	return []peerCheckerWithProduct{{Product: "ora", peerCheckerDecl: decl}}
}
