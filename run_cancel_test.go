package main

import (
	"strings"
	"testing"
	"time"
)

func TestCancelRunCascadesChildren(t *testing.T) {
	parent := &scmJob{
		ID: "run-cancel-1", Kind: string(kindRun), RunID: "run-cancel-1",
		Status: "running", Summary: map[string]interface{}{},
	}
	bot := &scmJob{
		ID: "bot-cancel-1", Kind: string(kindBugbot), RunID: parent.ID, ParentID: parent.ID,
		Status: "running", Summary: map[string]interface{}{},
	}
	apr := &scmJob{
		ID: "apr-cancel-1", Kind: string(kindApproval), RunID: parent.ID, ParentID: parent.ID,
		Status: "queued", Summary: map[string]interface{}{},
	}
	cloud := &scmJob{
		ID: "cloud-cancel-1", Kind: string(kindCloud), RunID: parent.ID, ParentID: parent.ID,
		Status: "running", Summary: map[string]interface{}{},
	}
	parent.Summary["child_ids"] = []string{bot.ID, apr.ID, cloud.ID}
	scmJobLive.Store(parent.ID, parent)
	scmJobLive.Store(bot.ID, bot)
	scmJobLive.Store(apr.ID, apr)
	scmJobLive.Store(cloud.ID, cloud)
	defer func() {
		scmJobLive.Delete(parent.ID)
		scmJobLive.Delete(bot.ID)
		scmJobLive.Delete(apr.ID)
		scmJobLive.Delete(cloud.ID)
	}()

	got, errMsg, code := cancelSCMJobWithReason(parent.ID, "test cancel")
	if errMsg != "" || code != 0 || got == nil || got.Status != "cancelled" {
		t.Fatalf("parent cancel: got=%v err=%q code=%d", got, errMsg, code)
	}
	if bot = getSCMJob(bot.ID); bot == nil || bot.Status != "cancelled" {
		t.Fatalf("bugbot should be cancelled, got %+v", bot)
	}
	if apr = getSCMJob(apr.ID); apr == nil || apr.Status != "cancelled" {
		t.Fatalf("approval should be cancelled, got %+v", apr)
	}
	cloud = getSCMJob(cloud.ID)
	if cloud == nil || cloud.Status != "running" {
		t.Fatalf("cloud mid-push should drain (stay running), got %+v", cloud)
	}
	if cloud.Summary["supersede_drain"] != true && cloud.Summary["cancel_drain"] == nil {
		t.Fatalf("cloud should be marked drain: %+v", cloud.Summary)
	}
}

func TestPublishPRReviewRefusesCancelled(t *testing.T) {
	job := &scmJob{
		ID: "j-pub-1", RunID: "run-pub-1", PRNumber: 3, Status: "cancelled",
		CommitSHA: "abc", Summary: map[string]interface{}{},
	}
	scmJobLive.Store(job.ID, job)
	scmJobLive.Store(job.RunID, &scmJob{ID: job.RunID, Kind: string(kindRun), Status: "cancelled"})
	defer func() {
		scmJobLive.Delete(job.ID)
		scmJobLive.Delete(job.RunID)
	}()
	err := publishPRReview(nil, "acme", "demo", job, "body", "APPROVE", nil)
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("want refuse cancelled, got %v", err)
	}
}

func TestWaitRunChildrenTerminal(t *testing.T) {
	runID := "run-wait-1"
	child := &scmJob{ID: "c-wait-1", Kind: string(kindBugbot), RunID: runID, ParentID: runID, Status: "completed"}
	parent := &scmJob{ID: runID, Kind: string(kindRun), RunID: runID, Summary: map[string]interface{}{"child_ids": []string{child.ID}}}
	scmJobLive.Store(runID, parent)
	scmJobLive.Store(child.ID, child)
	defer func() {
		scmJobLive.Delete(runID)
		scmJobLive.Delete(child.ID)
	}()
	start := time.Now()
	waitRunChildrenTerminal(runID, 2*time.Second)
	if time.Since(start) > time.Second {
		t.Fatal("should return immediately when children terminal")
	}
}
