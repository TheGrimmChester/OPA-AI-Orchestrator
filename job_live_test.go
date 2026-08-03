package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveOutputSinkWritesArtifactAndSummary(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	jobID := "scmjob-live-test-1"
	job := &scmJob{
		ID:     jobID,
		Status: "running",
		Summary: map[string]interface{}{
			"kind": "bugbot",
		},
	}
	scmJobLive.Store(jobID, job)
	defer scmJobLive.Delete(jobID)

	sink := newLiveOutputSink(jobID, "review", "pkg-ui", "supersecret-key-value-xx")
	if sink == nil {
		t.Fatal("expected sink")
	}
	chunk := []byte("hello agent\nsecret=supersecret-key-value-xx\nmore output\n")
	if _, err := sink.Write(chunk); err != nil {
		t.Fatal(err)
	}
	// Force throttle boundary.
	sink.sincePersist = livePersistBytes
	sink.Flush(true)
	sink.Close()

	raw, err := readJobArtifact(jobID, "live.log")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, "hello agent") {
		t.Fatalf("live.log missing output: %s", body)
	}
	if strings.Contains(body, "supersecret-key-value-xx") {
		t.Fatal("secret leaked into live.log")
	}
	if !strings.Contains(body, "***") {
		t.Fatal("expected redacted secret marker")
	}
	unitRaw, err := readJobArtifact(jobID, "live-pkg-ui.log")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unitRaw), "hello agent") {
		t.Fatalf("unit log missing output: %s", unitRaw)
	}

	got := getSCMJob(jobID)
	if got == nil {
		t.Fatal("job missing")
	}
	live, _ := got.Summary["live"].(map[string]interface{})
	if live == nil {
		t.Fatalf("summary.live missing: %#v", got.Summary)
	}
	if live["phase"] != "review" {
		t.Fatalf("phase=%v", live["phase"])
	}
	if live["unit"] != "pkg-ui" {
		t.Fatalf("unit=%v", live["unit"])
	}
	if live["artifact"] != "live.log" {
		t.Fatalf("artifact=%v", live["artifact"])
	}
	tail, _ := live["tail"].(string)
	if !strings.Contains(tail, "hello agent") {
		t.Fatalf("tail=%q", tail)
	}
	path := filepath.Join(jobArtifactsDir(jobID), "live.log")
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 {
		t.Fatalf("artifact file: %v %#v", err, st)
	}
}

func TestLiveOutputSinkGrowsAcrossWrites(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	jobID := "scmjob-live-test-2"
	job := &scmJob{ID: jobID, Status: "running", Summary: map[string]interface{}{}}
	scmJobLive.Store(jobID, job)
	defer scmJobLive.Delete(jobID)

	sink := newLiveOutputSink(jobID, "autofix", "", "")
	defer sink.Close()
	for i := 0; i < 5; i++ {
		_, _ = sink.Write([]byte("line-" + strings.Repeat("x", 200) + "\n"))
		time.Sleep(10 * time.Millisecond)
	}
	sink.Flush(true)
	raw, err := readJobArtifact(jobID, "live.log")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 800 {
		t.Fatalf("expected growing log, got %d bytes", len(raw))
	}
	live, _ := getSCMJob(jobID).Summary["live"].(map[string]interface{})
	if live == nil {
		t.Fatal("missing live summary")
	}
	bytesVal, _ := live["bytes"].(int)
	if bytesVal < 800 {
		// JSON numbers may be float64 after round-trip; accept both.
		if f, ok := live["bytes"].(float64); !ok || f < 800 {
			t.Fatalf("bytes=%v", live["bytes"])
		}
	}
}

func TestLiveOutputSinkDoesNotPersistEveryWrite(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	jobID := "scmjob-live-throttle"
	job := &scmJob{ID: jobID, Status: "running", Summary: map[string]interface{}{}}
	scmJobLive.Store(jobID, job)
	defer scmJobLive.Delete(jobID)

	sink := newLiveOutputSink(jobID, "review", "", "")
	defer sink.Close()
	// Header Write may persist once if interval already elapsed; reset counters.
	sink.mu.Lock()
	sink.sincePersist = 0
	sink.lastPersist = time.Now()
	delete(job.Summary, "live")
	sink.mu.Unlock()

	for i := 0; i < 20; i++ {
		_, _ = sink.Write([]byte("x"))
	}
	if _, ok := job.Summary["live"]; ok {
		t.Fatal("small writes within interval must not persist summary.live")
	}
	sink.Flush(true)
	if job.Summary["live"] == nil {
		t.Fatal("Flush must persist")
	}
}

func TestPhaseWantsLiveCapture(t *testing.T) {
	if !phaseWantsLiveCapture(jobPhaseReview) || !phaseWantsLiveCapture(jobPhaseAutofix) {
		t.Fatal("review/autofix should capture")
	}
	if phaseWantsLiveCapture(jobPhaseScan) || phaseWantsLiveCapture(jobPhaseCheckup) {
		t.Fatal("scan/checkup should not capture")
	}
}

func TestLiveSinkForSpecNilWhenNoJob(t *testing.T) {
	if liveSinkForSpec(sandboxExecSpec{Phase: jobPhaseReview, JobID: ""}) != nil {
		t.Fatal("empty job id")
	}
	if liveSinkForSpec(sandboxExecSpec{Phase: jobPhaseScan, JobID: "x"}) != nil {
		t.Fatal("scan phase")
	}
}
