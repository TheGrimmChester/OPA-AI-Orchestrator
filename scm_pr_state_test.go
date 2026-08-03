package main

import "testing"

func TestScmPRIsMerged(t *testing.T) {
	cases := []struct {
		name     string
		merged   bool
		mergedAt string
		state    string
		want     bool
	}{
		{"open", false, "", "open", false},
		{"closed_not_merged", false, "", "closed", false},
		{"merged_flag", true, "", "closed", true},
		{"merged_at", false, "2026-08-01T12:00:00Z", "closed", true},
		{"merged_flag_and_at", true, "2026-08-01T12:00:00Z", "closed", true},
		{"whitespace_merged_at", false, "  ", "closed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scmPRIsMerged(tc.merged, tc.mergedAt, tc.state)
			if got != tc.want {
				t.Fatalf("scmPRIsMerged(%v, %q, %q) = %v want %v", tc.merged, tc.mergedAt, tc.state, got, tc.want)
			}
		})
	}
}

func TestShouldSkipSCMJobForMergedPR_NonPREvents(t *testing.T) {
	if shouldSkipSCMJobForMergedPR(&scmJob{PRNumber: 1, Event: "push.default"}) {
		t.Fatal("push jobs must not skip for merged PR")
	}
	if shouldSkipSCMJobForMergedPR(&scmJob{PRNumber: 1, Event: "cron.full"}) {
		t.Fatal("cron jobs must not skip for merged PR")
	}
	if shouldSkipSCMJobForMergedPR(&scmJob{PRNumber: 1, Event: "simulate"}) {
		t.Fatal("simulate jobs must not skip for merged PR")
	}
	if shouldSkipSCMJobForMergedPR(&scmJob{PRNumber: 0, Event: "pull_request.synchronize"}) {
		t.Fatal("jobs without PR number must not skip")
	}
	if shouldSkipSCMJobForMergedPR(nil) {
		t.Fatal("nil job must not skip")
	}
}

func TestScmAIReviewSucceeded(t *testing.T) {
	for _, st := range []string{"clean", "findings", "ok", "CLEAN", " Findings "} {
		if !scmAIReviewSucceeded(st) {
			t.Fatalf("%q should count as successful AI review", st)
		}
	}
	for _, st := range []string{"skipped", "error", "pending", "", "cancelled"} {
		if scmAIReviewSucceeded(st) {
			t.Fatalf("%q must not count as successful AI review", st)
		}
	}
}

func TestScmSHAEqual(t *testing.T) {
	if !scmSHAEqual("abcDEF", "abcdef") {
		t.Fatal("case-insensitive equal")
	}
	if !scmSHAEqual("abcdef0123456789", "abcdef") {
		t.Fatal("prefix match")
	}
	if scmSHAEqual("", "abc") || scmSHAEqual("abc", "") {
		t.Fatal("empty must not match")
	}
}

func TestLookupSuccessfulAIReviewForSHA(t *testing.T) {
	const repo = "acme/already-reviewed-test"
	const sha = "deadbeefcafebabe0123456789abcdef01234567"
	prior := &scmJob{
		ID: "prior-ok", RepoFullName: repo, CommitSHA: sha, Status: "completed",
		FinishedAt: "2026-08-01 10:00:00.000",
		Summary:    map[string]interface{}{"ai": map[string]interface{}{"status": "clean"}, "analyzed_sha": sha},
	}
	failedAI := &scmJob{
		ID: "prior-skip", RepoFullName: repo, CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Status: "completed", FinishedAt: "2026-08-01 09:00:00.000",
		Summary: map[string]interface{}{"ai": map[string]interface{}{"status": "skipped"}},
	}
	scmJobLive.Store(prior.ID, prior)
	scmJobLive.Store(failedAI.ID, failedAI)
	recordSuccessfulAIReview(prior, sha, "clean")
	t.Cleanup(func() {
		scmJobLive.Delete(prior.ID)
		scmJobLive.Delete(failedAI.ID)
		scmSuccessfulAIReviewBySHA.Delete(scmReviewedSHAKey(repo, sha))
		scmSuccessfulAIReviewBySHA.Delete(scmReviewedSHAKey(repo, failedAI.CommitSHA))
	})

	id, ok := lookupSuccessfulAIReviewForSHA(repo, sha, "new-job")
	if !ok || id != prior.ID {
		t.Fatalf("expected prior job %s, got %q ok=%v", prior.ID, id, ok)
	}
	// Same job looking itself up must not self-match.
	if _, ok := lookupSuccessfulAIReviewForSHA(repo, sha, prior.ID); ok {
		t.Fatal("excludeJobID must ignore the prior job itself")
	}
	// Skipped AI does not count.
	if _, ok := lookupSuccessfulAIReviewForSHA(repo, failedAI.CommitSHA, ""); ok {
		t.Fatal("skipped AI must not count as already reviewed")
	}
	// Placeholder SHAs never match.
	if _, ok := lookupSuccessfulAIReviewForSHA(repo, "manual-abc", ""); ok {
		t.Fatal("placeholder SHA must not match")
	}
}

func TestShouldSkipSCMJobForAlreadyReviewed(t *testing.T) {
	const repo = "acme/skip-already-reviewed"
	const sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	prior := &scmJob{
		ID: "skip-prior", RepoFullName: repo, CommitSHA: sha, Status: "completed",
		FinishedAt: "2026-08-01 11:00:00.000",
		Summary:    map[string]interface{}{"ai": aiReviewResult{Status: "findings"}, "analyzed_sha": sha},
	}
	scmJobLive.Store(prior.ID, prior)
	recordSuccessfulAIReview(prior, sha, "findings")
	t.Cleanup(func() {
		scmJobLive.Delete(prior.ID)
		scmSuccessfulAIReviewBySHA.Delete(scmReviewedSHAKey(repo, sha))
	})

	if _, skip := shouldSkipSCMJobForAlreadyReviewed(&scmJob{
		ID: "j-new", RepoFullName: repo, CommitSHA: sha, Event: "pull_request.synchronize",
	}); !skip {
		t.Fatal("PR synchronize with already-reviewed SHA must skip")
	}
	if _, skip := shouldSkipSCMJobForAlreadyReviewed(&scmJob{
		ID: "j-push", RepoFullName: repo, CommitSHA: sha, Event: "push.default",
	}); skip {
		t.Fatal("push jobs must not skip for already-reviewed")
	}
	if _, skip := shouldSkipSCMJobForAlreadyReviewed(&scmJob{
		ID: "j-sim", RepoFullName: repo, CommitSHA: sha, Event: "simulate",
	}); skip {
		t.Fatal("simulate jobs must not skip for already-reviewed")
	}
	if _, skip := shouldSkipSCMJobForAlreadyReviewed(&scmJob{
		ID: "j-manual", RepoFullName: repo, CommitSHA: "manual-xyz", Event: "manual.ai_review",
	}); skip {
		t.Fatal("placeholder SHA must not skip")
	}
	if _, skip := shouldSkipSCMJobForAlreadyReviewed(nil); skip {
		t.Fatal("nil job must not skip")
	}
}

func TestGateFailedJobStillCountsAsReviewed(t *testing.T) {
	const repo = "acme/gate-failed-reviewed"
	const sha = "cccccccccccccccccccccccccccccccccccccccc"
	prior := &scmJob{
		ID: "gate-fail", RepoFullName: repo, CommitSHA: sha, Status: "failed",
		FinishedAt: "2026-08-01 12:00:00.000",
		Summary:    map[string]interface{}{"ai": map[string]interface{}{"status": "clean"}, "analyzed_sha": sha},
	}
	scmJobLive.Store(prior.ID, prior)
	t.Cleanup(func() {
		scmJobLive.Delete(prior.ID)
		scmSuccessfulAIReviewBySHA.Delete(scmReviewedSHAKey(repo, sha))
	})
	// Cold index — rely on live scan.
	id, ok := lookupSuccessfulAIReviewForSHA(repo, sha, "")
	if !ok || id != prior.ID {
		t.Fatalf("gate-failed job with successful AI must count; got %q ok=%v", id, ok)
	}
}

func TestForceAIBypassesAlreadyReviewedSkip(t *testing.T) {
	const repo = "acme/force-rereview"
	const sha = "dddddddddddddddddddddddddddddddddddddddd"
	prior := &scmJob{
		ID: "prior-force", RepoFullName: repo, CommitSHA: sha, Status: "completed",
		FinishedAt: "2026-08-01 13:00:00.000",
		Summary:    map[string]interface{}{"ai": map[string]interface{}{"status": "findings"}, "analyzed_sha": sha},
	}
	scmJobLive.Store(prior.ID, prior)
	recordSuccessfulAIReview(prior, sha, "findings")
	t.Cleanup(func() {
		scmJobLive.Delete(prior.ID)
		scmSuccessfulAIReviewBySHA.Delete(scmReviewedSHAKey(repo, sha))
	})
	job := &scmJob{ID: "follow-up", RepoFullName: repo, CommitSHA: sha, Event: "manual.ai_only", ForceAI: true}
	if _, skip := shouldSkipSCMJobForAlreadyReviewed(job); skip {
		t.Fatal("ForceAI follow-up must not skip already-reviewed SHA")
	}
	job.ForceAI = false
	if _, skip := shouldSkipSCMJobForAlreadyReviewed(job); !skip {
		t.Fatal("non-force job must still skip already-reviewed SHA")
	}
}

func TestCancelInFlightJobsForMergedPR(t *testing.T) {
	const repo = "acme/merge-cancel"
	running := &scmJob{ID: "run-1", RepoFullName: repo, PRNumber: 42, Status: "running", Event: "pull_request.synchronize"}
	queued := &scmJob{ID: "q-1", RepoFullName: repo, PRNumber: 42, Status: "queued", Event: "manual.ai_only"}
	otherPR := &scmJob{ID: "other", RepoFullName: repo, PRNumber: 99, Status: "running", Event: "pull_request.opened"}
	done := &scmJob{ID: "done", RepoFullName: repo, PRNumber: 42, Status: "completed", Event: "pull_request.opened"}
	scmJobLive.Store(running.ID, running)
	scmJobLive.Store(queued.ID, queued)
	scmJobLive.Store(otherPR.ID, otherPR)
	scmJobLive.Store(done.ID, done)
	t.Cleanup(func() {
		scmJobLive.Delete(running.ID)
		scmJobLive.Delete(queued.ID)
		scmJobLive.Delete(otherPR.ID)
		scmJobLive.Delete(done.ID)
	})
	ids := cancelInFlightJobsForMergedPR(repo, 42, "pull request merged")
	if len(ids) != 2 {
		t.Fatalf("want 2 cancelled, got %v", ids)
	}
	if getSCMJob("run-1").Status != "cancelled" || getSCMJob("q-1").Status != "cancelled" {
		t.Fatal("in-flight jobs for merged PR must be cancelled")
	}
	if getSCMJob("other").Status != "running" {
		t.Fatal("other PR jobs must stay running")
	}
	if getSCMJob("done").Status != "completed" {
		t.Fatal("completed jobs must stay completed")
	}
}
