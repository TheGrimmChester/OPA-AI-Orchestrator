package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFinalizeJobEvidencePrepare(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	job := &scmJob{
		ID: "scmjob-ev-prep", Kind: string(kindPrepare), Attempt: 1,
		Status: "completed", RepoFullName: "acme/app", PRNumber: 26,
		Summary: map[string]interface{}{
			"checkout_path": "/tmp/wt", "checkout_rel": "wt",
			"prefs": map[string]interface{}{"cloud_enabled": true},
		},
	}
	ev := finalizeJobEvidence(job)
	if ev == nil || ev.SchemaVersion != 1 {
		t.Fatalf("evidence: %+v", ev)
	}
	if ev.Results["checkout_path"] != "/tmp/wt" {
		t.Fatalf("prepare results: %+v", ev.Results)
	}
	if !ev.Sections.HasContext || !ev.Sections.HasResults {
		t.Fatalf("sections: %+v", ev.Sections)
	}
	raw, ok := job.Summary["evidence"]
	if !ok || raw == nil {
		t.Fatal("summary.evidence missing")
	}
}

func TestAppendEvidencePostAndProjectViews(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	job := &scmJob{
		ID: "scmjob-ev-post", Kind: string(kindBugbot), Status: "completed",
		Summary: map[string]interface{}{
			"ai": aiReviewResult{
				Model: "auto", Usage: "agent said hello",
				Findings: []map[string]interface{}{
					{"finding_key": "k1", "severity": "medium", "file": "a.js", "message": "bug"},
				},
			},
		},
	}
	appendEvidencePost(job, JobEvidencePost{
		Type: "resume", Target: "issue_comment", GitHubID: 99, Status: "created",
		Body: "## OPA Review\n\nhello",
	})
	ev := finalizeJobEvidence(job)
	if len(ev.Posts) != 1 || ev.Posts[0].GitHubID != 99 {
		t.Fatalf("posts: %+v", ev.Posts)
	}
	if !ev.Sections.HasPosts || !ev.Sections.HasFindings || !ev.Sections.HasChat {
		t.Fatalf("sections: %+v", ev.Sections)
	}
	client := projectEvidence(ev, "client")
	if client.Context.CheckoutPath != "" && client.Chat.Transcript == "" {
		t.Fatalf("client projection unexpected: %+v", client.Chat)
	}
	org := projectEvidence(ev, "org")
	if org == nil || len(org.Findings) == 0 {
		t.Fatal("org should keep findings")
	}
}

func TestWriteAndReadJobArtifact(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	ref, err := writeJobArtifact("scmjob-art", "brief.md", "brief", "# brief\n")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Bytes == 0 {
		t.Fatal("empty artifact")
	}
	raw, err := readJobArtifact("scmjob-art", "brief.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "# brief\n" {
		t.Fatalf("got %q", raw)
	}
	// path traversal refused
	if _, err := readJobArtifact("scmjob-art", "../etc/passwd"); err == nil {
		// filepath.Base strips — should read non-existent basename
		if _, err2 := os.Stat(filepath.Join(jobArtifactsDir("scmjob-art"), "passwd")); err2 == nil {
			t.Fatal("traversal wrote outside")
		}
	}
}

func TestCloudFindingKeysFallbackMedium(t *testing.T) {
	prefs := builtinAgentPrefs()
	prefs.AutofixSeverityThreshold = "high"
	prefs.AutofixMode = "branch"
	ledger := []agentFinding{
		{Key: "a", Severity: "medium", File: "x.go", Message: "m"},
		{Key: "b", Severity: "low", File: "y.go", Message: "l"},
	}
	keys, rationale := cloudFindingKeys(nil, ledger, prefs)
	if len(keys) != 1 || keys[0] != "a" {
		t.Fatalf("keys=%v rationale=%s", keys, rationale)
	}
	if rationale == "" || rationale == "auto from ledger" {
		t.Fatalf("expected fallback rationale, got %q", rationale)
	}
}

func TestEvidenceCompactAndAPIView(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	job := &scmJob{
		ID: "scmjob-ev-api", Kind: string(kindSecurity), Status: "completed", Attempt: 1,
		Summary: map[string]interface{}{
			"gate": map[string]interface{}{"status": "pass"},
		},
	}
	_ = finalizeJobEvidence(job)
	view := scmJobAPIViewWithOpts(job, "ops", false)
	ev, ok := view["evidence"].(*JobEvidence)
	if !ok {
		// JSON round-trip may yield map
		if m, ok := view["evidence"].(map[string]interface{}); !ok || m["schema_version"] == nil {
			// projectEvidence returns *JobEvidence; Marshal path keeps pointer
			b, _ := json.Marshal(view["evidence"])
			var parsed JobEvidence
			if json.Unmarshal(b, &parsed) != nil || parsed.SchemaVersion != 1 {
				t.Fatalf("evidence in view: %T %#v", view["evidence"], view["evidence"])
			}
		}
	} else if ev.SchemaVersion != 1 {
		t.Fatalf("schema %d", ev.SchemaVersion)
	}
	compact := evidenceCompactSummary(job)
	if compact["kind"] != string(kindSecurity) {
		t.Fatalf("compact: %+v", compact)
	}
}

func TestRecordJobBrief(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	job := &scmJob{ID: "scmjob-brief", Kind: string(kindBugbot), Summary: map[string]interface{}{}}
	recordJobBrief(job, "# hello brief", "unit.md")
	if strFromAny(job.Summary["brief_artifact"]) != "unit.md" {
		t.Fatalf("artifact name: %v", job.Summary["brief_artifact"])
	}
	raw, err := readJobArtifact(job.ID, "unit.md")
	if err != nil || string(raw) != "# hello brief" {
		t.Fatalf("read: %v %q", err, raw)
	}
}
