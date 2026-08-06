package main

import (
	"encoding/json"
	"testing"
)

func TestEvaluateORAReviewCheckerActionable(t *testing.T) {
	env := &scmEventEnvelope{
		EventType: "pull_request.opened", RepoFullName: "acme/app",
		PRNumber: 3, CommitSHA: "abc123def",
		Checks: []string{"ora:review"},
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"action": "opened",
		"pull_request": map[string]interface{}{
			"merged": false, "state": "open",
		},
	})
	decl := evaluateORAReviewChecker(env, raw)
	if !decl.ShouldRun {
		t.Fatalf("expected should_run, got reason=%q", decl.Reason)
	}
	if decl.ID != oraCheckerReview || decl.CheckRunName != oraCheckerReviewRunName {
		t.Fatalf("decl=%+v", decl)
	}
}

func TestEvaluateORAReviewCheckerSkipMerged(t *testing.T) {
	env := &scmEventEnvelope{
		EventType: "pull_request.opened", RepoFullName: "acme/app",
		PRNumber: 3, CommitSHA: "abc123",
		Checks: []string{"ora:review"},
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"pull_request": map[string]interface{}{
			"merged": true, "merged_at": "2026-01-01T00:00:00Z",
		},
	})
	decl := evaluateORAReviewChecker(env, raw)
	if decl.ShouldRun {
		t.Fatalf("expected skip merged, decl=%+v", decl)
	}
	if decl.Reason == "" || decl.Reason == "PR event pull_request.opened" {
		t.Fatalf("reason=%q", decl.Reason)
	}
}

func TestEvaluateORAReviewCheckerSkipAlreadyReviewed(t *testing.T) {
	repo := "acme/reviewed-" + newRandomHex(4)
	sha := "deadbeef" + newRandomHex(4)
	recordSuccessfulAIReview(&scmJob{
		ID: "prior-review", RepoFullName: repo, CommitSHA: sha,
	}, sha, "clean")

	env := &scmEventEnvelope{
		EventType: "pull_request.synchronize", RepoFullName: repo,
		PRNumber: 5, CommitSHA: sha, Checks: []string{"ora:review"},
	}
	decl := evaluateORAReviewChecker(env, nil)
	if decl.ShouldRun {
		t.Fatalf("expected skip already reviewed, decl=%+v", decl)
	}
}

func TestEvaluateORAReviewCheckerSkipNonActionable(t *testing.T) {
	env := &scmEventEnvelope{
		EventType: "pull_request.labeled", RepoFullName: "acme/app",
		PRNumber: 1, CommitSHA: "abc", Checks: []string{"ora:review"},
	}
	decl := evaluateORAReviewChecker(env, nil)
	if decl.ShouldRun {
		t.Fatalf("expected skip non-actionable, decl=%+v", decl)
	}
}

func TestEvaluateORAReviewCheckerChecksFilter(t *testing.T) {
	env := &scmEventEnvelope{
		EventType: "pull_request.opened", RepoFullName: "acme/app",
		PRNumber: 1, CommitSHA: "abc", Checks: []string{"osa:dependencies"},
	}
	decl := evaluateORAReviewChecker(env, nil)
	if decl.ShouldRun {
		t.Fatalf("expected filtered out, decl=%+v", decl)
	}
}

func TestDispatchSCMCheckersNativeReviewPublish(t *testing.T) {
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	t.Setenv("OPA_SCM_SKIP_CHECK_RUNS", "1")
	t.Setenv("PEER_OSA_URL", "")
	t.Setenv("PEER_OPL_URL", "")
	t.Setenv("PEER_OPM_URL", "")

	conn := &opaConnector{Kind: "github_pat", TokenRef: "ghp_fake_token_for_mock_test_only"}
	env := &scmEventEnvelope{
		ID: "env-review", EventType: "pull_request.opened",
		RepoFullName: "acme/app", PRNumber: 2, CommitSHA: "sha-review",
		SCMJobID: "job-review", Checks: []string{"ora:review"},
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"pull_request": map[string]interface{}{"merged": false, "state": "open"},
	})
	ids := dispatchSCMCheckers(conn, env, env.Checks, raw)
	if len(ids) != 0 {
		// mock github returns commit_status mode with id 0 — key may be absent
		t.Logf("checker ids=%v (mock may omit id)", ids)
	}
	decls := evaluateORANativeCheckers(env, env.Checks, raw)
	if len(decls) != 1 || !decls[0].ShouldRun {
		t.Fatalf("native decls=%+v", decls)
	}
	key := checkerStatusKey("ora", oraCheckerReview)
	if key != "ora:review" {
		t.Fatalf("key=%q", key)
	}
	_, mode, err := publishCheckerResult(conn, "acme", "app", checkerPublishMeta{
		Key: key, Name: oraCheckerReviewRunName, SHA: env.CommitSHA,
		Status: "queued", Title: oraCheckerReviewRunName, Summary: "Peer checker queued",
	})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "commit_status" && mode != "check_run" {
		t.Fatalf("mode=%q", mode)
	}
}

func TestOraReviewActionableEvent(t *testing.T) {
	for _, ev := range []string{"pull_request.opened", "pull_request.synchronize", "pull_request.reopened", "pull_request.ready_for_review"} {
		if !oraReviewActionableEvent(ev) {
			t.Fatalf("expected actionable: %s", ev)
		}
	}
	if oraReviewActionableEvent("pull_request.labeled") || oraReviewActionableEvent("push.default") {
		t.Fatal("expected non-actionable events")
	}
}
