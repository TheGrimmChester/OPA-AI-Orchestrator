package main

import "strings"

// scmRunSkipGate is the shared prologue skip logic for run-graph and continuous paths.
// Returns skip=true with a reason (and optional prior reviewed job id).
func scmRunSkipGate(job *scmJob) (skip bool, reason, priorID string) {
	if job == nil {
		return true, "missing job", ""
	}
	switch agentKind(job.Kind) {
	case kindIssueRun:
		// Issue parents are not PR review jobs — skip merge/SHA gates.
		return false, "", ""
	}
	// Defense-in-depth: never start AppSec/AI on an already-merged PR —
	// unless ForceAI (explicit Retry / manual re-pass from the dashboard).
	if !job.ForceAI && shouldSkipSCMJobForMergedPR(job) {
		return true, "pull request is already merged", ""
	}
	if prior, ok := shouldSkipSCMJobForAlreadyReviewed(job); ok {
		return true, "commit already reviewed successfully", prior
	}
	return false, "", ""
}

// shouldEnqueuePRRun reports whether a new job should be a kind=run parent with
// agent children. Push/cron continuous events stay on the continuous path.
func shouldEnqueuePRRun(event string, pr int) bool {
	ev := strings.ToLower(strings.TrimSpace(event))
	if strings.HasPrefix(ev, "push.") || strings.HasPrefix(ev, "cron.") {
		return false
	}
	if pr > 0 {
		return true
	}
	// Simulate with pr=0 still exercises the graph (smoke / local).
	return strings.HasPrefix(ev, "simulate")
}

func prRunID(org, proj, repo, sha string, pr int) string {
	return loadID("prrun", org, proj, repo, sha, itoa(pr))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
