package main

import "testing"

func TestJobTerminalWebhookOutcome(t *testing.T) {
	cases := []struct {
		status string
		want   string
		ok     bool
	}{
		{"completed", "ok", true},
		{"failed", "error", true},
		{"error", "error", true},
		{"cancelled", "skipped", true},
		{"skipped", "skipped", true},
		{"queued", "", false},
		{"running", "", false},
		{"waiting", "", false},
	}
	for _, tc := range cases {
		out, _, ok := jobTerminalWebhookOutcome(&scmJob{Status: tc.status})
		if ok != tc.ok || out != tc.want {
			t.Fatalf("status=%q → outcome=%q ok=%v; want %q ok=%v", tc.status, out, ok, tc.want, tc.ok)
		}
	}
	if _, _, ok := jobTerminalWebhookOutcome(nil); ok {
		t.Fatal("nil job should not be terminal")
	}
}

func TestReconcileSCMWebhookWithJob(t *testing.T) {
	job := &scmJob{ID: "scmjob-reconcile-test", Status: "completed"}
	scmJobLive.Store(job.ID, job)
	defer scmJobLive.Delete(job.ID)

	rec := &scmWebhookReceipt{ID: "scmwh-reconcile-test", Outcome: "queued", JobID: job.ID, Honesty: "PR job queued."}
	scmWebhookLive.Store(rec.ID, rec)
	defer scmWebhookLive.Delete(rec.ID)

	if !reconcileSCMWebhookWithJob(rec) {
		t.Fatal("expected reconcile")
	}
	if rec.Outcome != "ok" {
		t.Fatalf("outcome=%q want ok", rec.Outcome)
	}
	if !reconcileSCMWebhookWithJob(rec) {
		// already ok — should no-op
	} else if rec.Outcome != "ok" {
		t.Fatal("second reconcile should leave ok")
	}
}
