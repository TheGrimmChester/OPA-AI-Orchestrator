package main

import (
	"strings"
	"testing"
)

func TestSupersedeInFlightPRJobsCancelsIntermediateCommits(t *testing.T) {
	const repo = "acme/supersede-commits"
	const pr = 77
	shaA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaC := "cccccccccccccccccccccccccccccccccccccccc"

	runA := &scmJob{
		ID: "run-a", RepoFullName: repo, PRNumber: pr, CommitSHA: shaA,
		Status: "running", Kind: string(kindRun), RunID: "run-a", Event: "pull_request.synchronize",
		StartedAt: "2026-08-01 10:00:00.000", Summary: map[string]interface{}{},
	}
	childA := &scmJob{
		ID: "child-a", RepoFullName: repo, PRNumber: pr, CommitSHA: shaA,
		Status: "running", Kind: string(kindPrepare), RunID: "run-a", ParentID: "run-a",
		Event: "pull_request.synchronize", Summary: map[string]interface{}{},
	}
	runB := &scmJob{
		ID: "run-b", RepoFullName: repo, PRNumber: pr, CommitSHA: shaB,
		Status: "queued", Kind: string(kindRun), RunID: "run-b", Event: "pull_request.synchronize",
		StartedAt: "2026-08-01 10:01:00.000", Summary: map[string]interface{}{},
	}
	otherPR := &scmJob{
		ID: "run-other", RepoFullName: repo, PRNumber: 99, CommitSHA: shaA,
		Status: "running", Kind: string(kindRun), RunID: "run-other", Event: "pull_request.opened",
		Summary: map[string]interface{}{},
	}
	scmJobLive.Store(runA.ID, runA)
	scmJobLive.Store(childA.ID, childA)
	scmJobLive.Store(runB.ID, runB)
	scmJobLive.Store(otherPR.ID, otherPR)
	runA.Summary["child_ids"] = []string{childA.ID}
	t.Cleanup(func() {
		for _, id := range []string{runA.ID, childA.ID, runB.ID, otherPR.ID} {
			scmJobLive.Delete(id)
		}
		prRunIndexMu.Lock()
		delete(prRunIndex, prRunIndexKey(repo, pr))
		prRunIndexMu.Unlock()
	})

	ids := supersedeInFlightPRJobs(repo, pr, shaC)
	if len(ids) < 2 {
		t.Fatalf("want at least parents A+B cancelled, got %v", ids)
	}
	if getSCMJob(runA.ID).Status != "cancelled" || getSCMJob(runB.ID).Status != "cancelled" {
		t.Fatalf("intermediate commits must be cancelled; A=%s B=%s", getSCMJob(runA.ID).Status, getSCMJob(runB.ID).Status)
	}
	if getSCMJob(childA.ID).Status != "cancelled" {
		t.Fatalf("child of superseded run must cascade cancel, got %s", getSCMJob(childA.ID).Status)
	}
	if getSCMJob(otherPR.ID).Status != "running" {
		t.Fatal("other PR must stay running")
	}
	if reason, _ := getSCMJob(runA.ID).Summary["cancel_reason"].(string); !strings.Contains(reason, shaC) {
		t.Fatalf("cancel reason should mention new SHA, got %q", reason)
	}
}

func TestEnqueuePRRunCancelsPriorAndRemembersLatest(t *testing.T) {
	const repo = "acme/enqueue-supersede"
	const pr = 12
	shaOld := "1111111111111111111111111111111111111111"
	shaNew := "2222222222222222222222222222222222222222"

	prior := &scmJob{
		ID: "prior-run", RepoFullName: repo, PRNumber: pr, CommitSHA: shaOld,
		Status: "running", Kind: string(kindRun), RunID: "prior-run",
		Event: "pull_request.opened", Summary: map[string]interface{}{"child_ids": []string{}},
		StartedAt: "2026-08-01 09:00:00.000",
	}
	scmJobLive.Store(prior.ID, prior)
	rememberPRRun(repo, pr, prior.ID)
	t.Cleanup(func() {
		scmJobLive.Range(func(k, v interface{}) bool {
			if j, ok := v.(*scmJob); ok && j != nil && strings.EqualFold(j.RepoFullName, repo) && j.PRNumber == pr {
				scmJobLive.Delete(k)
			}
			return true
		})
		prRunIndexMu.Lock()
		delete(prRunIndex, prRunIndexKey(repo, pr))
		prRunIndexMu.Unlock()
	})

	job := enqueuePRRun(nil, nil, repo, pr, shaNew, "pull_request.synchronize", false, "t", "")
	if job == nil || job.CommitSHA != shaNew {
		t.Fatal("expected new run for latest SHA")
	}
	if getSCMJob(prior.ID).Status != "cancelled" {
		t.Fatalf("prior run must be cancelled, got %s", getSCMJob(prior.ID).Status)
	}
	if currentPRRun(repo, pr) != job.ID {
		t.Fatalf("index must point at latest run; got %q want %q", currentPRRun(repo, pr), job.ID)
	}
	if job.Status != "queued" && job.Status != "skipped" {
		t.Fatalf("new job should be queued/skipped, got %s", job.Status)
	}
}

func TestPruneSupersededInFlightPRRunsKeepsNewest(t *testing.T) {
	const repo = "acme/prune-supersede"
	const pr = 5
	older := &scmJob{
		ID: "old", RepoFullName: repo, PRNumber: pr, CommitSHA: "oldsha",
		Status: "queued", Kind: string(kindRun), RunID: "old",
		StartedAt: "2026-08-01 08:00:00.000", Summary: map[string]interface{}{},
	}
	newer := &scmJob{
		ID: "new", RepoFullName: repo, PRNumber: pr, CommitSHA: "newsha",
		Status: "queued", Kind: string(kindRun), RunID: "new",
		StartedAt: "2026-08-01 09:00:00.000", Summary: map[string]interface{}{},
	}
	scmJobLive.Store(older.ID, older)
	scmJobLive.Store(newer.ID, newer)
	t.Cleanup(func() {
		scmJobLive.Delete(older.ID)
		scmJobLive.Delete(newer.ID)
		prRunIndexMu.Lock()
		delete(prRunIndex, prRunIndexKey(repo, pr))
		prRunIndexMu.Unlock()
	})

	n := pruneSupersededInFlightPRRuns()
	if n != 1 {
		t.Fatalf("want 1 pruned, got %d", n)
	}
	if getSCMJob(older.ID).Status != "cancelled" {
		t.Fatal("older must be cancelled")
	}
	if getSCMJob(newer.ID).Status != "queued" {
		t.Fatalf("newest must stay queued, got %s", getSCMJob(newer.ID).Status)
	}
	if currentPRRun(repo, pr) != newer.ID {
		t.Fatalf("index should remember newest, got %q", currentPRRun(repo, pr))
	}
}

func TestRebuildPRRunIndexFromLive(t *testing.T) {
	const repo = "acme/rebuild-index"
	const pr = 3
	run := &scmJob{
		ID: "live-run", RepoFullName: repo, PRNumber: pr, CommitSHA: "abc",
		Status: "running", Kind: string(kindRun), RunID: "live-run",
		StartedAt: "2026-08-01 10:00:00.000",
	}
	scmJobLive.Store(run.ID, run)
	prRunIndexMu.Lock()
	prRunIndex = map[string]string{}
	prRunIndexMu.Unlock()
	t.Cleanup(func() {
		scmJobLive.Delete(run.ID)
		prRunIndexMu.Lock()
		delete(prRunIndex, prRunIndexKey(repo, pr))
		prRunIndexMu.Unlock()
	})

	n := rebuildPRRunIndexFromLive()
	if n < 1 {
		t.Fatalf("expected at least 1 indexed run, got %d", n)
	}
	if currentPRRun(repo, pr) != run.ID {
		t.Fatalf("rebuild missed live run; got %q", currentPRRun(repo, pr))
	}
}
