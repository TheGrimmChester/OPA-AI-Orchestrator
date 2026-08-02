package main

import (
	"strings"
	"testing"
)

func TestAllAgentChildKindsDispatched(t *testing.T) {
	for k := range agentDependsOn {
		if !isAgentChildKind(k) {
			t.Fatalf("kind %q is in agentDependsOn but not isAgentChildKind — processSCMJob would fail-closed", k)
		}
	}
	if isAgentChildKind(kindRun) || isAgentChildKind(kindContinuous) {
		t.Fatal("run/continuous must not be agent children")
	}
	if !isAgentChildKind(kindCheckup) {
		t.Fatal("checkup must dispatch to processAgentChild")
	}
}

func TestProcessSCMJobDispatchesAgentChildren(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())

	// Pure routing table — mirrors processSCMJob's switch.
	cases := []struct {
		kind agentKind
		want string
	}{
		{kindRun, "run"},
		{kindPrepare, "agent"},
		{kindSecurity, "agent"},
		{kindBugbot, "agent"},
		{kindCheckup, "agent"},
		{kindApproval, "agent"},
		{kindCloud, "agent"},
		{kindContinuous, "continuous"},
		{agentKind(""), "unknown"},
		{agentKind("unknown"), "unknown"},
	}
	for _, tc := range cases {
		if got := scmJobProcessor(tc.kind); got != tc.want {
			t.Fatalf("scmJobProcessor(%q)=%q want %q", tc.kind, got, tc.want)
		}
	}
	if scmJobProcessor(kindCheckup) == "continuous" || scmJobProcessor(kindCheckup) == "unknown" {
		t.Fatal("checkup must not route to continuous/unknown")
	}

	// Runtime: call processSCMJob with incomplete deps so processAgentChild
	// returns early (status stays queued). Continuous would mark the job running.
	runID := "dispatch-run-1"
	parent := &scmJob{
		ID: runID, Kind: string(kindRun), RunID: runID, Status: "running",
		Summary: map[string]interface{}{},
	}
	agentKinds := []agentKind{kindPrepare, kindSecurity, kindBugbot, kindCheckup, kindApproval, kindCloud}
	ids := make([]string, 0, len(agentKinds))
	jobs := map[agentKind]*scmJob{}
	for _, k := range agentKinds {
		id := "dispatch-" + string(k)
		j := &scmJob{
			ID: id, Kind: string(k), RunID: runID, ParentID: runID, Status: "queued",
			Summary: map[string]interface{}{},
		}
		jobs[k] = j
		ids = append(ids, id)
		scmJobLive.Store(id, j)
	}
	// Leave prepare queued so dependents are not ready.
	parent.Summary["child_ids"] = ids
	scmJobLive.Store(parent.ID, parent)
	defer func() {
		scmJobLive.Delete(parent.ID)
		for _, id := range ids {
			scmJobLive.Delete(id)
			scmProcessing.Delete(id)
		}
		scmProcessing.Delete(parent.ID)
	}()

	for _, k := range []agentKind{kindSecurity, kindBugbot, kindCheckup, kindApproval, kindCloud} {
		processSCMJob(jobs[k].ID)
		got := getSCMJob(jobs[k].ID)
		if got == nil || got.Status != "queued" {
			t.Fatalf("%s: want stay queued (agent early-return), got status=%v", k, got)
		}
	}

	// Prepare has no deps — pre-mark cancelled so processAgentChild exits
	// before runPrepareAgent without continuous side effects.
	jobs[kindPrepare].Status = "cancelled"
	processSCMJob(jobs[kindPrepare].ID)
	if got := getSCMJob(jobs[kindPrepare].ID); got == nil || got.Status != "cancelled" {
		t.Fatalf("prepare cancelled path: got %#v", got)
	}
}

func TestProcessSCMJobFailClosedUnknownKind(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	job := &scmJob{
		ID: "fail-unknown-1", Kind: "", Event: "pull_request.opened", Status: "queued",
		Summary: map[string]interface{}{},
	}
	scmJobLive.Store(job.ID, job)
	defer scmJobLive.Delete(job.ID)

	processSCMJob(job.ID)
	got := getSCMJob(job.ID)
	if got == nil || got.Status != "failed" {
		t.Fatalf("empty kind PR job want failed, got %#v", got)
	}
	if got.Error == "" {
		t.Fatal("want fail-closed error message")
	}
}

func TestProcessSCMJobUpgradesEmptyPushToContinuous(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	// Skip gate will mark skipped for already-reviewed / missing connector —
	// we only assert the kind upgrade happens before dispatch. Use cancelled
	// so processContinuousSCMJob returns early after kind upgrade.
	job := &scmJob{
		ID: "upgrade-push-1", Kind: "", Event: "push.default", Status: "cancelled",
		Summary: map[string]interface{}{},
	}
	scmJobLive.Store(job.ID, job)
	defer func() {
		scmJobLive.Delete(job.ID)
		scmProcessing.Delete(job.ID)
	}()

	processSCMJob(job.ID)
	got := getSCMJob(job.ID)
	if got == nil || got.Kind != string(kindContinuous) {
		t.Fatalf("empty push kind want continuous, got %#v", got)
	}
}

func TestProcessSCMJobUpgradesEmptyPullRequestKindToRun(t *testing.T) {
	job := &scmJob{
		ID: "upgrade-pr-1", Kind: "", Event: "pull_request.synchronize", PRNumber: 7,
		Status: "cancelled", Summary: map[string]interface{}{},
	}
	scmJobLive.Store(job.ID, job)
	defer func() {
		scmJobLive.Delete(job.ID)
		scmProcessing.Delete(job.ID)
	}()

	processSCMJob(job.ID)
	got := getSCMJob(job.ID)
	if got == nil || got.Kind != string(kindRun) {
		t.Fatalf("empty PR kind want run, got %#v", got)
	}
	if got.RunID != job.ID {
		t.Fatalf("RunID want %s, got %q", job.ID, got.RunID)
	}
}

func TestShouldEnqueuePRRun(t *testing.T) {
	if !shouldEnqueuePRRun("pull_request.opened", 1) {
		t.Fatal("PR events must enqueue run graph")
	}
	if shouldEnqueuePRRun("push.default", 0) {
		t.Fatal("push must stay continuous")
	}
	if shouldEnqueuePRRun("cron.full", 0) {
		t.Fatal("cron must stay continuous")
	}
	if !shouldEnqueuePRRun("simulate", 0) {
		t.Fatal("simulate must enqueue run graph")
	}
	if !shouldEnqueuePRRun("manual.ai_review", 42) {
		t.Fatal("manual with PR must enqueue run graph")
	}
}

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

func TestReadyChildrenIncludesCheckupSibling(t *testing.T) {
	parent := &scmJob{
		ID: "run-chk", Kind: string(kindRun), RunID: "run-chk", Status: "running",
		Summary: map[string]interface{}{},
	}
	prep := &scmJob{ID: "chk-prep", Kind: string(kindPrepare), RunID: "run-chk", ParentID: "run-chk", Status: "queued"}
	sec := &scmJob{ID: "chk-sec", Kind: string(kindSecurity), RunID: "run-chk", ParentID: "run-chk", Status: "queued"}
	bot := &scmJob{ID: "chk-bot", Kind: string(kindBugbot), RunID: "run-chk", ParentID: "run-chk", Status: "queued"}
	chk := &scmJob{ID: "chk-up", Kind: string(kindCheckup), RunID: "run-chk", ParentID: "run-chk", Status: "queued"}
	apr := &scmJob{ID: "chk-apr", Kind: string(kindApproval), RunID: "run-chk", ParentID: "run-chk", Status: "queued"}
	parent.Summary["child_ids"] = []string{prep.ID, sec.ID, bot.ID, chk.ID, apr.ID}
	for _, j := range []*scmJob{parent, prep, sec, bot, chk, apr} {
		scmJobLive.Store(j.ID, j)
	}
	defer func() {
		for _, j := range []*scmJob{parent, prep, sec, bot, chk, apr} {
			scmJobLive.Delete(j.ID)
		}
	}()

	prep.Status = "completed"
	ready := readyChildren("run-chk")
	got := map[agentKind]bool{}
	for _, c := range ready {
		got[agentKind(c.Kind)] = true
	}
	if !got[kindSecurity] || !got[kindBugbot] || !got[kindCheckup] {
		t.Fatalf("after prepare: want security+bugbot+checkup, got %#v", kindsOf(ready))
	}
	if got[kindApproval] {
		t.Fatalf("approval must wait for security+bugbot, got %#v", kindsOf(ready))
	}
}

func TestPlanRunChildrenCheckupGating(t *testing.T) {
	parent := &scmJob{
		ID: "plan-run", OrganizationID: "o", ProjectID: "p",
		RepoFullName: "o/r", CommitSHA: "abc", Kind: string(kindRun), RunID: "plan-run",
	}
	prefs := builtinAgentPrefs()
	prefs.CheckupEnabled = true

	t.Setenv("OPA_JOB_SANDBOX", "docker")
	children := planRunChildren(parent, prefs, false, "")
	var chk *scmJob
	for _, c := range children {
		if agentKind(c.Kind) == kindCheckup {
			chk = c
		}
	}
	if chk == nil {
		t.Fatal("CheckupEnabled+docker: expected checkup child")
	}
	if chk.Status != "queued" {
		t.Fatalf("checkup want queued, got %s (%v)", chk.Status, chk.Summary)
	}

	t.Setenv("OPA_JOB_SANDBOX", "off")
	children = planRunChildren(parent, prefs, false, "")
	chk = nil
	for _, c := range children {
		if agentKind(c.Kind) == kindCheckup {
			chk = c
		}
	}
	if chk == nil {
		t.Fatal("CheckupEnabled+sandbox off: checkup child should still exist (skipped)")
	}
	if chk.Status != "skipped" {
		t.Fatalf("sandbox off: want skipped, got %s", chk.Status)
	}
	reason, _ := chk.Summary["skip_reason"].(string)
	if !strings.Contains(reason, "OPA_JOB_SANDBOX=docker") {
		t.Fatalf("honesty reason want OPA_JOB_SANDBOX=docker, got %q", reason)
	}

	prefs.CheckupEnabled = false
	t.Setenv("OPA_JOB_SANDBOX", "docker")
	children = planRunChildren(parent, prefs, false, "")
	for _, c := range children {
		if agentKind(c.Kind) == kindCheckup {
			t.Fatal("CheckupEnabled=false must not enqueue checkup child")
		}
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
