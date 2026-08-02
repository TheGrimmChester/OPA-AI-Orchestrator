package main

// publishPRReview is the ONLY caller of githubCreatePRReview with comments or a
// decision event. Bugbot records the plan and publishes its own immediate signals
// (résumé + check run); approval (or the finalizer) calls this once so humans get
// a single review notification.
func publishPRReview(conn *opaConnector, owner, repo string, job *scmJob, body, event string, comments []githubPRReviewCommentSpec) error {
	if job == nil || job.PRNumber <= 0 {
		return nil
	}
	if event == "" {
		event = "COMMENT"
	}
	return githubCreatePRReview(conn, owner, repo, job.PRNumber, job.CommitSHA, body, event, comments)
}

// submitOPAReviewDecision posts a decision-only review through the chokepoint.
func submitOPAReviewDecision(conn *opaConnector, owner, repo string, job *scmJob, res aiReviewResult, event string, minScore int) error {
	if job == nil || event == "" || event == "COMMENT" {
		return nil
	}
	body := formatOPAReviewDecisionBody(res, event, minScore)
	return publishPRReview(conn, owner, repo, job, body, event, nil)
}
