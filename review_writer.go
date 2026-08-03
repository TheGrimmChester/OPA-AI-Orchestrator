package main

import (
	"fmt"
	"strings"
)

const opaReviewDecisionMarker = "<!-- opa-review:decision -->"

// publishPRReview is the ONLY caller of githubCreatePRReview with comments or a
// decision event. Bugbot records the plan and publishes its own immediate signals
// (résumé + check run); approval (or the finalizer) calls this once so humans get
// a single review notification.
//
// Decision-only COMMENT reviews are not created — they stacked noisy
// "Confidence / Verdict / pending_autofix" cards. APPROVE / REQUEST_CHANGES upsert
// the first OPA decision review body; a new review is posted only when GitHub's
// immutable review state must change.
func publishPRReview(conn *opaConnector, owner, repo string, job *scmJob, body, event string, comments []githubPRReviewCommentSpec) error {
	if job == nil || job.PRNumber <= 0 {
		return nil
	}
	if scmJobIsCancelled(job.ID) || (job.RunID != "" && scmJobIsCancelled(job.RunID)) {
		return fmt.Errorf("refusing publishPRReview: job/run cancelled")
	}
	if event == "" {
		event = "COMMENT"
	}
	if len(comments) > 0 {
		// Inline findings still need a review container; keep body minimal.
		if strings.TrimSpace(body) == "" {
			body = "OPA Review — inline findings updated."
		}
		return githubCreatePRReview(conn, owner, repo, job.PRNumber, job.CommitSHA, body, event, comments)
	}
	return publishOPADecisionReview(conn, owner, repo, job, body, event)
}

// publishOPADecisionReview upserts the first OPA decision review. Pure COMMENT
// decisions are skipped (résumé issue comment already carries the narrative).
func publishOPADecisionReview(conn *opaConnector, owner, repo string, job *scmJob, body, event string) error {
	event = strings.ToUpper(strings.TrimSpace(event))
	if event == "" {
		event = "COMMENT"
	}
	body = embedOPAReviewDecisionMarker(body)

	reviews, err := githubListPRReviews(conn, owner, repo, job.PRNumber)
	if err != nil {
		// Fall through to create when listing fails for non-COMMENT events.
		reviews = nil
	}
	first := findFirstOPADecisionReview(reviews)

	if event == "COMMENT" {
		if first != nil {
			return githubUpdatePRReviewBody(conn, owner, repo, job.PRNumber, first.ID, body)
		}
		// No prior card and nothing to gate — do not spam a new COMMENT review.
		return nil
	}

	if first != nil {
		if err := githubUpdatePRReviewBody(conn, owner, repo, job.PRNumber, first.ID, body); err != nil {
			return err
		}
		if reviewStateMatchesEvent(first.State, event) {
			return nil
		}
	}
	return githubCreatePRReview(conn, owner, repo, job.PRNumber, job.CommitSHA, body, event, nil)
}

func embedOPAReviewDecisionMarker(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		body = "**OPA Review**"
	}
	if strings.Contains(body, opaReviewDecisionMarker) {
		return body
	}
	return opaReviewDecisionMarker + "\n" + body
}

func isOPABotReviewLogin(login string) bool {
	login = strings.ToLower(strings.TrimSpace(login))
	login = strings.TrimSuffix(login, "[bot]")
	slug := strings.ToLower(strings.TrimSpace(githubAppReviewerLogin()))
	return login != "" && login == slug
}

func findFirstOPADecisionReview(reviews []githubPRReview) *githubPRReview {
	for i := range reviews {
		r := &reviews[i]
		if r.State == "PENDING" || r.State == "DISMISSED" {
			continue
		}
		if !isOPABotReviewLogin(r.User) {
			continue
		}
		if strings.Contains(r.Body, opaReviewDecisionMarker) ||
			strings.Contains(r.Body, "**OPA Review") ||
			strings.Contains(r.Body, "OPA Review —") {
			return r
		}
	}
	return nil
}

func reviewStateMatchesEvent(state, event string) bool {
	state = strings.ToUpper(strings.TrimSpace(state))
	event = strings.ToUpper(strings.TrimSpace(event))
	switch event {
	case "APPROVE":
		return state == "APPROVED"
	case "REQUEST_CHANGES":
		return state == "CHANGES_REQUESTED"
	case "COMMENT":
		return state == "COMMENTED"
	default:
		return false
	}
}

// submitOPAReviewDecision posts a decision-only review through the chokepoint.
func submitOPAReviewDecision(conn *opaConnector, owner, repo string, job *scmJob, res aiReviewResult, event string, minScore int) error {
	if job == nil || event == "" || event == "COMMENT" {
		return nil
	}
	body := formatOPAReviewDecisionBody(res, event, minScore)
	return publishPRReview(conn, owner, repo, job, body, event, nil)
}
