package main

import "strings"

// scmRunSkipGate is the shared prologue skip logic for legacy and run-graph paths.
// Returns skip=true with a reason (and optional prior reviewed job id).
func scmRunSkipGate(job *scmJob) (skip bool, reason, priorID string) {
	if job == nil {
		return true, "missing job", ""
	}
	// Defense-in-depth: never start AppSec/AI on an already-merged PR.
	if shouldSkipSCMJobForMergedPR(job) {
		return true, "pull request is already merged", ""
	}
	if prior, ok := shouldSkipSCMJobForAlreadyReviewed(job); ok {
		return true, "commit already reviewed successfully", prior
	}
	return false, "", ""
}

func agentsRunGraphEnabled() bool {
	return envOr("OPA_AGENTS_RUN_GRAPH", "1") != "0"
}

// shouldEnqueuePRRun reports whether a new job should be a kind=run parent with
// agent children. Stacks and non-PR continuous events stay on the legacy path.
func shouldEnqueuePRRun(event string, pr int) bool {
	if !agentsRunGraphEnabled() {
		return false
	}
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
