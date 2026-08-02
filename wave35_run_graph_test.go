package main

import "testing"

func TestReadyChildrenDerivedBarrier(t *testing.T) {
	parent := &scmJob{
		ID: "run-1", Kind: string(kindRun), RunID: "run-1", Status: "running",
		Summary: map[string]interface{}{},
	}
	prep := &scmJob{ID: "c-prep", Kind: string(kindPrepare), RunID: "run-1", ParentID: "run-1", Status: "queued"}
	sec := &scmJob{ID: "c-sec", Kind: string(kindSecurity), RunID: "run-1", ParentID: "run-1", Status: "queued"}
	bot := &scmJob{ID: "c-bot", Kind: string(kindBugbot), RunID: "run-1", ParentID: "run-1", Status: "queued"}
	apr := &scmJob{ID: "c-apr", Kind: string(kindApproval), RunID: "run-1", ParentID: "run-1", Status: "queued"}
	parent.Summary["child_ids"] = []string{prep.ID, sec.ID, bot.ID, apr.ID}
	scmJobLive.Store(parent.ID, parent)
	scmJobLive.Store(prep.ID, prep)
	scmJobLive.Store(sec.ID, sec)
	scmJobLive.Store(bot.ID, bot)
	scmJobLive.Store(apr.ID, apr)
	defer func() {
		for _, id := range []string{parent.ID, prep.ID, sec.ID, bot.ID, apr.ID} {
			scmJobLive.Delete(id)
		}
	}()

	ready := readyChildren("run-1")
	if len(ready) != 1 || agentKind(ready[0].Kind) != kindPrepare {
		t.Fatalf("expected only prepare ready, got %#v", kindsOf(ready))
	}

	prep.Status = "completed"
	ready = readyChildren("run-1")
	got := map[agentKind]bool{}
	for _, c := range ready {
		got[agentKind(c.Kind)] = true
	}
	if !got[kindSecurity] || !got[kindBugbot] || got[kindApproval] {
		t.Fatalf("after prepare: want security+bugbot, got %#v", kindsOf(ready))
	}

	sec.Status = "completed"
	bot.Status = "completed"
	ready = readyChildren("run-1")
	if len(ready) != 1 || agentKind(ready[0].Kind) != kindApproval {
		t.Fatalf("after parents: want approval, got %#v", kindsOf(ready))
	}
}

func TestEnsureRunChildrenIdempotent(t *testing.T) {
	parent := &scmJob{
		ID: "run-2", Kind: string(kindRun), RunID: "run-2", Status: "running",
		OrganizationID: "o", ProjectID: "p", RepoFullName: "o/r", CommitSHA: "abc",
		Summary: map[string]interface{}{},
	}
	scmJobLive.Store(parent.ID, parent)
	defer func() {
		for _, c := range listRunChildren(parent.ID) {
			scmJobLive.Delete(c.ID)
		}
		scmJobLive.Delete(parent.ID)
	}()

	first := ensureRunChildren(parent)
	if len(first) < 2 {
		t.Fatalf("expected children, got %d", len(first))
	}
	ids := map[string]bool{}
	for _, c := range first {
		ids[c.ID] = true
	}
	second := ensureRunChildren(parent)
	if len(second) != len(first) {
		t.Fatalf("restart duplicated children: %d -> %d", len(first), len(second))
	}
	for _, c := range second {
		if !ids[c.ID] {
			t.Fatalf("new child id on re-ensure: %s", c.ID)
		}
	}
}

func TestTriggerModeAdmits(t *testing.T) {
	if !triggerModeAdmits("every_push", "pull_request.synchronize") {
		t.Fatal("every_push should admit synchronize")
	}
	if triggerModeAdmits("pr_open", "pull_request.synchronize") {
		t.Fatal("pr_open should not admit synchronize")
	}
	if !triggerModeAdmits("pr_open", "pull_request.opened") {
		t.Fatal("pr_open should admit opened")
	}
	if !triggerModeAdmits("on_demand", "simulate") {
		t.Fatal("on_demand should admit simulate")
	}
}

func kindsOf(jobs []*scmJob) []string {
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.Kind+":"+j.Status)
	}
	return out
}
