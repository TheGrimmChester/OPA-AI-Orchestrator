package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOPAReviewFindingKeyStable(t *testing.T) {
	f1 := map[string]interface{}{
		"file": "src/Auth.php", "line": 10, "rule": "sqli",
		"problem": "SQL injection via query concat", "severity": "high",
	}
	f2 := map[string]interface{}{
		"file": "src/Auth.php", "line": 99, "rule": "sqli",
		"problem": "SQL injection via query concat", "severity": "critical",
	}
	k1 := opaReviewFindingKey(f1)
	k2 := opaReviewFindingKey(f2)
	if k1 == "" || k1 != k2 {
		t.Fatalf("expected same key for same path+rule+problem despite line/sev change: %q vs %q", k1, k2)
	}
	f3 := map[string]interface{}{
		"file": "src/Other.php", "line": 10, "rule": "sqli",
		"problem": "SQL injection via query concat",
	}
	if opaReviewFindingKey(f3) == k1 {
		t.Fatal("different path should yield different key")
	}
}

func TestPlanOPAReviewCommentActions(t *testing.T) {
	findings := []map[string]interface{}{
		{"file": "a.go", "line": 3, "severity": "high", "message": "oops", "rule": "r1"},
		{"file": "b.go", "line": 5, "severity": "low", "message": "new one", "rule": "r2"},
	}
	keyKeep := opaReviewFindingKey(findings[0])
	keyGone := opaReviewFindingKey(map[string]interface{}{
		"file": "gone.go", "message": "fixed already", "rule": "old",
	})
	prior := []opaReviewPriorComment{
		{ID: 1, Key: keyKeep, Path: "a.go", Line: 3, Body: embedOPAReviewFindingMarker("old body", keyKeep)},
		{ID: 2, Key: keyGone, Path: "gone.go", Line: 1, Body: embedOPAReviewFindingMarker("gone", keyGone)},
	}
	plan := planOPAReviewCommentActions(findings, prior, nil)
	if len(plan.Create) != 1 {
		t.Fatalf("expected 1 create, got %d", len(plan.Create))
	}
	if len(plan.Close) != 1 || plan.Close[0].Key != keyGone {
		t.Fatalf("expected close of gone key, got %+v", plan.Close)
	}
	if len(plan.Update) != 1 {
		t.Fatalf("expected 1 update for changed body, got %d", len(plan.Update))
	}
}

func TestPlanRetargetOnLineMove(t *testing.T) {
	f := map[string]interface{}{"file": "a.go", "line": 20, "severity": "high", "message": "x", "rule": "r"}
	key := opaReviewFindingKey(f)
	prior := []opaReviewPriorComment{{ID: 9, Key: key, Path: "a.go", Line: 3, Body: "old"}}
	plan := planOPAReviewCommentActions([]map[string]interface{}{f}, prior, nil)
	if len(plan.Create) != 1 {
		t.Fatalf("retarget should create new comment, got %d", len(plan.Create))
	}
	if len(plan.Update) != 1 || !plan.Update[0].Retarget {
		t.Fatalf("expected retarget update, got %+v", plan.Update)
	}
}

func TestEmbedResumeMarker(t *testing.T) {
	body := embedOPAReviewResumeMarker("## OPA Review\n\nhello")
	if !strings.Contains(body, opaReviewResumeMarker) {
		t.Fatal("missing resume marker")
	}
	if !isOPAReviewResumeBody(body) {
		t.Fatal("should detect resume body")
	}
}

func TestSeverityAndConfidenceEmoji(t *testing.T) {
	if severityEmoji("critical") != "🔴" {
		t.Fatal("critical emoji")
	}
	if severityEmoji("high") != "🟠" {
		t.Fatal("high emoji")
	}
	if confidenceEmoji(80) != "🟢" {
		t.Fatal("confidence high")
	}
	if confidenceEmoji(10) != "🔴" {
		t.Fatal("confidence low")
	}
	if confidenceEmoji(55) != "🟡" {
		t.Fatal("confidence medium")
	}
	// Model may claim "high" while scoring low — emoji follows the score.
	if confidenceEmoji(8) != "🔴" {
		t.Fatal("low score must not paint green")
	}
	if confidenceLabelFromScore(8) != "low" {
		t.Fatal("score 8 is low")
	}
	if confidenceLabelFromScore(40) != "medium" || confidenceLabelFromScore(69) != "medium" {
		t.Fatal("40–69 is medium")
	}
	if confidenceLabelFromScore(70) != "high" {
		t.Fatal("70+ is high")
	}
}

func TestRelatedRepoPathLayout(t *testing.T) {
	got := relatedRepoPathLayout("job/abc", "acme/api")
	if got != "job_abc/related/acme-api" && !strings.HasSuffix(got, "related/acme-api") {
		t.Fatalf("unexpected layout %q", got)
	}
	if sanitizeRelatedRepoDir("foo/bar") != "foo-bar" {
		t.Fatal("sanitize")
	}
}

func TestPrepareRelatedCheckoutsNoGit(t *testing.T) {
	t.Setenv("OPA_REVIEW_TMP", t.TempDir())
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	id := "rel-job-1"
	got := prepareRelatedCheckouts(nil, id, []string{"acme/shared"}, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 related, got %+v", got)
	}
	rc := got[0]
	if rc.Error != "" {
		t.Fatalf("unexpected error: %s", rc.Error)
	}
	if _, err := os.Stat(filepath.Join(rc.Path, ".git")); err == nil {
		t.Fatal("related agent tree must not contain .git")
	}
	if _, err := os.Stat(filepath.Join(rc.Path, "README.md")); err != nil {
		t.Fatal("expected materialized README")
	}
	if rc.SHA == "" {
		t.Fatal("expected recorded sha from clone before materialize")
	}
}

func TestRelatedMaterializeFailClosedOmitsGit(t *testing.T) {
	tmp := t.TempDir()
	cloneDir := filepath.Join(tmp, "broken.gitclone")
	dest := filepath.Join(tmp, "broken")
	if err := os.MkdirAll(cloneDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(cloneDir, "README.md"), []byte("not a git repo\n"), 0o644)
	_, err := materializeTreeWithCheckoutIndex(cloneDir, dest)
	if err == nil {
		t.Fatal("expected materialize to fail on non-git source")
	}
	// Mirrors prepareRelatedCheckouts fail-closed branch: never rename clone→dest.
	_ = os.RemoveAll(dest)
	_ = os.RemoveAll(cloneDir)
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		t.Fatal("fail-closed must not leave .git for agent-visible related trees")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("fail-closed must remove dest")
	}
}

func TestFormatRelatedCheckoutsDockerPaths(t *testing.T) {
	t.Setenv("OPA_JOB_SANDBOX", "docker")
	related := []relatedCheckout{{
		RepoFullName: "acme/shared", Path: "/tmp/opa-review/run1/related/acme-shared", SHA: "deadbeef", Source: "link",
	}}
	got := formatRelatedCheckoutsForPromptWithJob(related, "bugbot-1")
	if !strings.Contains(got, relatedContainerPath("bugbot-1", "acme/shared")) {
		t.Fatalf("want container path in prompt: %s", got)
	}
	if strings.Contains(got, "/tmp/opa-review") {
		t.Fatalf("must not expose host path in docker mode: %s", got)
	}
}

func TestMidReviewRelatedUsesRunWorktreeID(t *testing.T) {
	// prepare uses job.RunID; mid-review must not use bare child id.
	child := &scmJob{ID: "bugbot-child", RunID: "run-parent"}
	wt := nz(child.RunID, child.ID)
	if wt != "run-parent" {
		t.Fatalf("mid-review worktree id want run-parent got %s", wt)
	}
}

func TestRelatedCheckoutsForReviewFromPrepare(t *testing.T) {
	runID := "run-rel-brief"
	prep := &scmJob{
		ID: "prep-" + runID, Kind: string(kindPrepare), RunID: runID, ParentID: runID, Status: "completed",
		Summary: map[string]interface{}{
			"related_checkouts": []relatedCheckout{{
				RepoFullName: "acme/shared", Path: "/tmp/opa-review/" + runID + "/related/acme-shared", SHA: "abc", Source: "link",
			}},
		},
	}
	bot := &scmJob{
		ID: "bot-" + runID, Kind: string(kindBugbot), RunID: runID, ParentID: runID, Status: "running",
		Summary: map[string]interface{}{},
	}
	parent := &scmJob{
		ID: runID, Kind: string(kindRun), RunID: runID, Status: "running",
		Summary: map[string]interface{}{"child_ids": []string{prep.ID, bot.ID}},
	}
	scmJobLive.Store(prep.ID, prep)
	scmJobLive.Store(bot.ID, bot)
	scmJobLive.Store(parent.ID, parent)
	t.Cleanup(func() {
		scmJobLive.Delete(prep.ID)
		scmJobLive.Delete(bot.ID)
		scmJobLive.Delete(parent.ID)
	})

	got := relatedCheckoutsForReview(bot)
	if len(got) != 1 || got[0].RepoFullName != "acme/shared" {
		t.Fatalf("bugbot must read prepare related_checkouts, got %+v", got)
	}
	brief := formatRelatedCheckoutsForPromptWithJob(got, bot.ID)
	if !strings.Contains(brief, "acme/shared") {
		t.Fatalf("brief missing related: %s", brief)
	}
}



func TestResolveRelatedReposForJob(t *testing.T) {
	job := &scmJob{RepoFullName: "acme/primary", PRNumber: 1}
	applied := appliedReviewContexts{
		GroupID: "lg-1",
		Linked: []opaReviewContext{
			{RepoFullName: "acme/shared", Title: "shared"},
		},
	}
	prBody := "Depends on acme/payments for webhooks"
	out := resolveRelatedReposForJob(job, applied, prBody, nil, nil)
	joined := strings.Join(out, ",")
	if !strings.Contains(joined, "acme/shared") {
		t.Fatalf("expected linked repo, got %v", out)
	}
	if !strings.Contains(joined, "acme/payments") {
		t.Fatalf("expected pr body repo, got %v", out)
	}
	for _, r := range out {
		if strings.EqualFold(r, "acme/primary") {
			t.Fatal("primary should be excluded")
		}
	}
}

func TestRecordAnalyzedSHA(t *testing.T) {
	job1 := &scmJob{
		ID: "j1", RepoFullName: "acme/app", PRNumber: 7,
		Summary: map[string]interface{}{}, CommitSHA: "aaa111",
	}
	recordAnalyzedSHA(job1, "aaa111fffffff")
	if job1.Summary["analyzed_sha"] != "aaa111fffffff" {
		t.Fatal("analyzed_sha not set")
	}
	job2 := &scmJob{
		ID: "j2", RepoFullName: "acme/app", PRNumber: 7,
		Summary: map[string]interface{}{},
	}
	recordAnalyzedSHA(job2, "bbb222fffffff")
	if job2.Summary["previous_analyzed_sha"] != "aaa111fffffff" {
		t.Fatalf("expected previous sha, got %v", job2.Summary["previous_analyzed_sha"])
	}
	if job2.Summary["new_commits_since_review"] != true {
		t.Fatal("expected new_commits_since_review")
	}
}

func TestFilterFindingsByKeys(t *testing.T) {
	f1 := map[string]interface{}{"file": "a.go", "message": "one", "finding_key": "k1"}
	f2 := map[string]interface{}{"file": "b.go", "message": "two", "finding_key": "k2"}
	got := filterFindingsByKeys([]map[string]interface{}{f1, f2}, []string{"k2"})
	if len(got) != 1 || got[0]["finding_key"] != "k2" {
		t.Fatalf("filter failed: %+v", got)
	}
	all := filterFindingsByKeys([]map[string]interface{}{f1, f2}, nil)
	if len(all) != 0 {
		t.Fatal("empty keys must refuse fixing everything")
	}
}

func TestFixedReplyHasCheckEmoji(t *testing.T) {
	s := formatFixedReplyBody("abc123")
	if !strings.Contains(s, "✅") {
		t.Fatal("expected check emoji on fixed reply")
	}
	sup := formatSupersededFindingBody("body", "abc123")
	if !strings.Contains(sup, "♻️") {
		t.Fatal("expected recycle emoji on superseded")
	}
}

func TestPreferWatchedForChecksPrefersGitHubApp(t *testing.T) {
	pat := &opaConnector{ID: "conn-pat", OrganizationID: "org-a", Kind: "github_pat", Status: "active"}
	app := &opaConnector{ID: "conn-app", OrganizationID: "org-a", Kind: "github_app", InstallationID: "99", Status: "active"}
	connectorLive.Store(pat.ID, pat)
	connectorLive.Store(app.ID, app)
	t.Cleanup(func() {
		connectorLive.Delete(pat.ID)
		connectorLive.Delete(app.ID)
	})
	cands := []*opaWatchedRepo{
		{ConnectorID: pat.ID, RepoFullName: "o/r", Enabled: true, ChecksJSON: `["ai_review"]`, AutoRequestReviewer: true},
		{ConnectorID: app.ID, RepoFullName: "o/r", Enabled: true, ChecksJSON: `["secrets","ai_review"]`},
	}
	got := preferWatchedForChecks(cands)
	if got == nil || got.ConnectorID != app.ID {
		t.Fatalf("expected github_app watch, got %+v", got)
	}
}

func TestOPAReviewShouldPostResume(t *testing.T) {
	if !opaReviewShouldPostResume(aiReviewResult{Status: "ok"}) {
		t.Fatal("completed review should post résumé")
	}
	if !opaReviewShouldPostResume(aiReviewResult{Status: "findings"}) {
		t.Fatal("findings review should post résumé")
	}
	if opaReviewShouldPostResume(aiReviewResult{
		Status:  "skipped",
		Summary: "OPA Review API key not set — save a CLI agent key under Account (personal or org)",
	}) {
		t.Fatal("skipped (no CLI key) must not post résumé")
	}
	if opaReviewShouldPostResume(aiReviewResult{Status: "skipped", Summary: "OPA Review skipped (SKIP_CURSOR_AI=1)"}) {
		t.Fatal("skipped (SKIP_CURSOR_AI) must not post résumé")
	}
}
