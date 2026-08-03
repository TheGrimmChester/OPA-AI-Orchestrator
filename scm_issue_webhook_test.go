package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIssuesWebhookAILabelEnqueues(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	t.Setenv("OPA_SCM_ALLOW_UNSIGNED", "1")
	t.Setenv("OPA_GITHUB_WEBHOOK_SECRET", "")
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")

	now := "2026-01-01 00:00:00.000"
	conn := &opaConnector{
		ID: "conn-ai", Kind: "github_app", InstallationID: "1", Status: "active",
		OrganizationID: "default-org", ProjectID: "default-project",
		CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(conn.ID, conn)
	wr := &opaWatchedRepo{
		ID: "w1", OrganizationID: "default-org", ProjectID: "default-project",
		ConnectorID: conn.ID, RepoFullName: "acme/demo", Enabled: true,
		UpdatedAt: now,
	}
	watchedLive.Store(conn.ID+"|acme/demo", wr)

	payload := map[string]interface{}{
		"action": "labeled",
		"issue": map[string]interface{}{
			"number": 42, "title": "Fix crash", "body": "details",
			"labels": []map[string]string{{"name": "AI"}},
		},
		"label":        map[string]string{"name": "AI"},
		"repository":   map[string]string{"full_name": "acme/demo"},
		"installation": map[string]interface{}{"id": 1},
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/scm/github/webhook", bytes.NewReader(raw))
	req.Header.Set("X-GitHub-Event", "issues")
	req.Header.Set("X-GitHub-Delivery", "test-delivery-ai-"+newRandomHex(4))
	rr := httptest.NewRecorder()
	handleGitHubWebhook(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["job_id"] == nil || out["job_id"] == "" {
		t.Fatalf("expected job_id, got %v", out)
	}
	job := getSCMJob(strFromAny(out["job_id"]))
	if job == nil || agentKind(job.Kind) != kindIssueRun {
		t.Fatalf("job=%+v", job)
	}
	if job.PRNumber != 42 {
		t.Fatalf("issue number want 42 got %d", job.PRNumber)
	}
}

func TestIssuesWebhookWithoutAILabelIgnored(t *testing.T) {
	t.Setenv("OPA_SCM_STATE_DIR", t.TempDir())
	t.Setenv("OPA_SCM_ALLOW_UNSIGNED", "1")
	t.Setenv("OPA_GITHUB_WEBHOOK_SECRET", "")

	now := "2026-01-01 00:00:00.000"
	conn := &opaConnector{
		ID: "conn-ai2", Kind: "github_app", InstallationID: "2", Status: "active",
		OrganizationID: "default-org", ProjectID: "default-project",
		CreatedAt: now, UpdatedAt: now,
	}
	connectorLive.Store(conn.ID, conn)
	wr := &opaWatchedRepo{
		ID: "w2", OrganizationID: "default-org", ProjectID: "default-project",
		ConnectorID: conn.ID, RepoFullName: "acme/demo2", Enabled: true,
		UpdatedAt: now,
	}
	watchedLive.Store(conn.ID+"|acme/demo2", wr)

	payload := map[string]interface{}{
		"action": "labeled",
		"issue": map[string]interface{}{
			"number": 7, "title": "No AI", "body": "",
			"labels": []map[string]string{{"name": "bug"}},
		},
		"label":        map[string]string{"name": "bug"},
		"repository":   map[string]string{"full_name": "acme/demo2"},
		"installation": map[string]interface{}{"id": 2},
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/scm/github/webhook", bytes.NewReader(raw))
	req.Header.Set("X-GitHub-Event", "issues")
	req.Header.Set("X-GitHub-Delivery", "test-delivery-noai-"+newRandomHex(4))
	rr := httptest.NewRecorder()
	handleGitHubWebhook(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["job_id"] != nil && out["job_id"] != "" {
		t.Fatalf("want ignored without AI label, got %v", out)
	}
}
