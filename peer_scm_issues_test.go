package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestDecodeGitHubIssueFields(t *testing.T) {
	raw := []byte(`{
		"number": 12, "title": "Sync me", "body": "desc", "state": "closed",
		"html_url": "https://github.com/acme/demo/issues/12",
		"labels": [{"name": "bug"}, {"name": ""}, {"name": "opm"}],
		"milestone": {"number": 4, "title": "M4"},
		"assignees": [{"login": "alice"}, {"login": ""}],
		"updated_at": "2026-08-04T10:00:00Z"
	}`)
	m, err := decodeGitHubIssue(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m.Number != 12 || m.Title != "Sync me" || m.State != "closed" {
		t.Fatalf("core fields wrong: %+v", m)
	}
	if len(m.Labels) != 2 || m.Labels[0] != "bug" || m.Labels[1] != "opm" {
		t.Fatalf("labels should drop blanks: %v", m.Labels)
	}
	if m.Milestone != 4 || m.MilestoneTitle != "M4" {
		t.Fatalf("milestone wrong: %d %q", m.Milestone, m.MilestoneTitle)
	}
	if len(m.Assignees) != 1 || m.Assignees[0] != "alice" {
		t.Fatalf("assignees should drop blanks: %v", m.Assignees)
	}
	if m.UpdatedAt != "2026-08-04T10:00:00Z" {
		t.Fatalf("updated_at wrong: %q", m.UpdatedAt)
	}
}

func TestGitHubIssueAPIErrorClassification(t *testing.T) {
	missing := newGitHubIssueAPIError("get issue #7", http.StatusNotFound, []byte(`{"message":"Not Found"}`))
	if !missing.IssueMissing() || missing.Forbidden() {
		t.Fatalf("404 should classify as missing only: %+v", missing)
	}
	forbidden := newGitHubIssueAPIError("update issue #7", http.StatusForbidden, []byte(`{"message":"Resource not accessible by integration"}`))
	if forbidden.IssueMissing() || !forbidden.Forbidden() {
		t.Fatalf("403 should classify as forbidden only: %+v", forbidden)
	}
	unauth := newGitHubIssueAPIError("update issue #7", http.StatusUnauthorized, nil)
	if !unauth.Forbidden() {
		t.Fatal("401 should classify as forbidden")
	}
	// The message must carry the upstream body so operators see the real reason.
	if got := forbidden.Error(); !strings.Contains(got, "Resource not accessible by integration") {
		t.Fatalf("error text must include upstream body, got %q", got)
	}
}

// peerIssueError must translate GitHub failures into machine-readable statuses
// so OPM can report the concrete cause instead of a silent no-op.
func TestPeerIssueErrorStatuses(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantStat string
	}{
		{"missing", newGitHubIssueAPIError("get issue #9", http.StatusNotFound, []byte(`{"message":"Not Found"}`)),
			http.StatusNotFound, issueStatusNotFound},
		{"forbidden", newGitHubIssueAPIError("update issue #9", http.StatusForbidden, []byte(`{"message":"nope"}`)),
			http.StatusForbidden, issueStatusMissingPermission},
		{"other", newGitHubIssueAPIError("update issue #9", http.StatusInternalServerError, []byte(`boom`)),
			http.StatusBadGateway, issueStatusUpstreamError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			peerIssueError(rec, nil, tc.err)
			if rec.Code != tc.wantCode {
				t.Fatalf("code want %d got %d", tc.wantCode, rec.Code)
			}
			var out map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("body not json: %v", err)
			}
			if out["status"] != tc.wantStat {
				t.Fatalf("status want %q got %v", tc.wantStat, out["status"])
			}
			if ok, _ := out["ok"].(bool); ok {
				t.Fatal("ok must be false on failure")
			}
			if s, _ := out["error"].(string); s == "" {
				t.Fatal("error message must not be empty")
			}
		})
	}
}

func TestPeerIssuePayloadNeverNilSlices(t *testing.T) {
	p := peerIssuePayload(&githubIssueMeta{Number: 3, State: "open"})
	if l, ok := p["labels"].([]string); !ok || l == nil || len(l) != 0 {
		t.Fatalf("labels must be empty slice not null: %#v", p["labels"])
	}
	if a, ok := p["assignees"].([]string); !ok || a == nil || len(a) != 0 {
		t.Fatalf("assignees must be empty slice not null: %#v", p["assignees"])
	}
	if peerIssuePayload(nil) != nil {
		t.Fatal("nil meta should yield nil payload")
	}
}

// githubUpdateIssue reports which fields it actually sent; milestone uses
// >0 set / <0 clear / 0 leave-alone so a push can touch one field at a time.
func TestGitHubUpdateIssueAppliedFields(t *testing.T) {
	t.Setenv("OPA_SCM_MOCK_GITHUB", "1")
	c := &opaConnector{ID: "c1", Kind: "github_app"}

	_, applied, err := githubUpdateIssue(c, "acme", "demo", 5, "New title", "", "", 0, nil)
	if err != nil {
		t.Fatalf("title-only update: %v", err)
	}
	if len(applied) != 1 || applied[0] != "title" {
		t.Fatalf("title-only should apply just title, got %v", applied)
	}

	_, applied, err = githubUpdateIssue(c, "acme", "demo", 5, "", "", "closed", -1, []string{"opm"})
	if err != nil {
		t.Fatalf("state+clear-milestone update: %v", err)
	}
	if !slices.Contains(applied, "state") || !slices.Contains(applied, "milestone") || !slices.Contains(applied, "labels") {
		t.Fatalf("want state+milestone+labels, got %v", applied)
	}

	if _, _, err := githubUpdateIssue(c, "acme", "demo", 5, "", "", "", 0, nil); err == nil {
		t.Fatal("empty patch must be refused, not silently accepted")
	}
	if _, _, err := githubUpdateIssue(c, "acme", "demo", 5, "t", "", "weird", 0, nil); err == nil {
		t.Fatal("invalid state must be refused")
	}
	if _, _, err := githubUpdateIssue(c, "acme", "demo", 0, "t", "", "", 0, nil); err == nil {
		t.Fatal("issue number 0 must be refused")
	}
}
