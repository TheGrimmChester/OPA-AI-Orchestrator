package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// stubGraphQL is a fake GitHub GraphQL endpoint. Every call is recorded with its
// query and variables so a test can assert exactly what ORA sent on the wire —
// the point being that the title refresh now genuinely calls GitHub.
type stubGraphQL struct {
	server  *httptest.Server
	calls   []stubGraphQLCall
	resolve func(vars map[string]interface{}) (int, string)
	mutate  func(vars map[string]interface{}) (int, string)
}

type stubGraphQLCall struct {
	Query string
	Vars  map[string]interface{}
}

func newStubGraphQL(t *testing.T) *stubGraphQL {
	t.Helper()
	s := &stubGraphQL{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query     string                 `json:"query"`
			Variables map[string]interface{} `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.calls = append(s.calls, stubGraphQLCall{Query: in.Query, Vars: in.Variables})

		code, body := 0, ""
		switch {
		case strings.Contains(in.Query, "updateProjectV2DraftIssue"):
			if s.mutate != nil {
				code, body = s.mutate(in.Variables)
			}
		case strings.Contains(in.Query, "ProjectV2Item"):
			if s.resolve != nil {
				code, body = s.resolve(in.Variables)
			}
		}
		if body == "" {
			code, body = http.StatusNotImplemented, `{"errors":[{"message":"stub: unexpected query"}]}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.server.Close)
	t.Setenv("OPA_GITHUB_GRAPHQL_URL", s.server.URL)
	t.Setenv("OPA_SCM_MOCK_GITHUB", "0")
	return s
}

// stubPATConnector is a PAT connector so githubAccessToken resolves locally and no
// installation-token round trip is attempted.
func stubPATConnector() *opaConnector {
	return &opaConnector{
		ID: "c-stub", Kind: "github_pat", TokenRef: "stub-token",
		OrganizationID: "default-org", ProjectID: "default-project",
		Status: "active", Scope: credScopeOrg,
	}
}

func projectsErrStatus(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	var pe *githubProjectsAPIError
	if !errors.As(err, &pe) {
		t.Fatalf("want *githubProjectsAPIError, got %T: %v", err, err)
	}
	return pe.Status
}

// --- githubUpdateProjectV2DraftIssue -----------------------------------------

func TestUpdateProjectV2DraftIssueUpdatesTitle(t *testing.T) {
	s := newStubGraphQL(t)
	s.resolve = func(vars map[string]interface{}) (int, string) {
		if vars["id"] != "PVTI_item1" {
			return http.StatusBadRequest, `{"errors":[{"message":"unexpected item id"}]}`
		}
		return http.StatusOK, `{"data":{"node":{"id":"PVTI_item1","type":"DRAFT_ISSUE","content":{"id":"DI_draft1"}}}}`
	}
	s.mutate = func(vars map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"updateProjectV2DraftIssue":{"draftIssue":{"id":"DI_draft1","title":"Renamed"}}}}`
	}

	if err := githubUpdateProjectV2DraftIssue(stubPATConnector(), "PVTI_item1", "Renamed", "New body"); err != nil {
		t.Fatalf("want success, got %v", err)
	}

	// Two round trips: resolve item -> draft content id, then mutate.
	if len(s.calls) != 2 {
		t.Fatalf("want 2 GraphQL calls (resolve+mutate), got %d", len(s.calls))
	}
	if !strings.Contains(s.calls[1].Query, "updateProjectV2DraftIssue") {
		t.Fatalf("second call is not the mutation: %s", s.calls[1].Query)
	}
	mv := s.calls[1].Vars
	// The mutation must carry the resolved DraftIssue id, never the ProjectV2Item id.
	if got := mv["draftIssueId"]; got != "DI_draft1" {
		t.Fatalf("draftIssueId=%v, want DI_draft1", got)
	}
	if got := mv["title"]; got != "Renamed" {
		t.Fatalf("title=%v", got)
	}
	if got := mv["body"]; got != "New body" {
		t.Fatalf("body=%v", got)
	}
}

func TestUpdateProjectV2DraftIssueTitleOnlyLeavesBodyUnsent(t *testing.T) {
	s := newStubGraphQL(t)
	s.resolve = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"node":{"id":"PVTI_item1","type":"DRAFT_ISSUE","content":{"id":"DI_draft1"}}}}`
	}
	s.mutate = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"updateProjectV2DraftIssue":{"draftIssue":{"id":"DI_draft1","title":"Only title"}}}}`
	}
	if err := githubUpdateProjectV2DraftIssue(stubPATConnector(), "PVTI_item1", "Only title", ""); err != nil {
		t.Fatalf("want success, got %v", err)
	}
	if _, present := s.calls[1].Vars["body"]; present {
		t.Fatal("blank body must be omitted so GitHub leaves it unchanged")
	}
}

func TestUpdateProjectV2DraftIssueMissingPermission(t *testing.T) {
	s := newStubGraphQL(t)
	// GitHub answers a Projects v2 permission gap with a GraphQL error, not a 403.
	s.resolve = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"errors":[{"message":"Resource not accessible by integration"}]}`
	}
	err := githubUpdateProjectV2DraftIssue(stubPATConnector(), "PVTI_item1", "Renamed", "")
	if got := projectsErrStatus(t, err); got != projectsStatusMissingPermission {
		t.Fatalf("status=%s, want %s", got, projectsStatusMissingPermission)
	}
	if len(s.calls) != 1 {
		t.Fatalf("must not attempt the mutation after a failed resolve, got %d calls", len(s.calls))
	}
}

func TestUpdateProjectV2DraftIssueUnsupportedForRealIssue(t *testing.T) {
	s := newStubGraphQL(t)
	// A card backed by a real Issue: Projects v2 cannot rename it.
	s.resolve = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"node":{"id":"PVTI_item2","type":"ISSUE","content":{"id":"I_iss1","number":7}}}}`
	}
	err := githubUpdateProjectV2DraftIssue(stubPATConnector(), "PVTI_item2", "Renamed", "")
	if got := projectsErrStatus(t, err); got != projectsStatusTitleUnsupported {
		t.Fatalf("status=%s, want %s", got, projectsStatusTitleUnsupported)
	}
	if !strings.Contains(err.Error(), "ISSUE") {
		t.Fatalf("error should name the item type: %v", err)
	}
	if len(s.calls) != 1 {
		t.Fatalf("must not attempt the mutation for a non-draft item, got %d calls", len(s.calls))
	}
}

func TestUpdateProjectV2DraftIssueItemNotFound(t *testing.T) {
	s := newStubGraphQL(t)
	s.resolve = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"node":null}}`
	}
	err := githubUpdateProjectV2DraftIssue(stubPATConnector(), "PVTI_gone", "Renamed", "")
	if got := projectsErrStatus(t, err); got != projectsStatusItemNotFound {
		t.Fatalf("status=%s, want %s", got, projectsStatusItemNotFound)
	}
	_ = s
}

func TestUpdateProjectV2DraftIssueUpstreamError(t *testing.T) {
	newStubGraphQL(t)
	err := githubUpdateProjectV2DraftIssue(stubPATConnector(), "PVTI_item1", "Renamed", "")
	// The stub returns 501 for an unrecognised query.
	if got := projectsErrStatus(t, err); got != projectsStatusUpstreamError {
		t.Fatalf("status=%s, want %s", got, projectsStatusUpstreamError)
	}
}

func TestUpdateProjectV2DraftIssueNothingToSync(t *testing.T) {
	s := newStubGraphQL(t)
	err := githubUpdateProjectV2DraftIssue(stubPATConnector(), "PVTI_item1", "   ", "")
	if got := projectsErrStatus(t, err); got != projectsStatusNothingToSync {
		t.Fatalf("status=%s, want %s", got, projectsStatusNothingToSync)
	}
	if len(s.calls) != 0 {
		t.Fatalf("no fields to sync must not touch GitHub, got %d calls", len(s.calls))
	}
}

func TestUpdateProjectV2DraftIssueRejectsEmptyItemID(t *testing.T) {
	s := newStubGraphQL(t)
	err := githubUpdateProjectV2DraftIssue(stubPATConnector(), "  ", "Renamed", "")
	if got := projectsErrStatus(t, err); got != projectsStatusItemNotFound {
		t.Fatalf("status=%s, want %s", got, projectsStatusItemNotFound)
	}
	if len(s.calls) != 0 {
		t.Fatalf("want no GitHub calls, got %d", len(s.calls))
	}
}

func TestClassifyProjectsGraphQLError(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"graphql 403: forbidden", projectsStatusMissingPermission},
		{"graphql: Resource not accessible by integration", projectsStatusMissingPermission},
		{"graphql: your token has not been granted the required scopes", projectsStatusMissingPermission},
		{"graphql: Could not resolve to a node with the global id of 'X'", projectsStatusItemNotFound},
		{"graphql 500: boom", projectsStatusUpstreamError},
	}
	for _, c := range cases {
		got := projectsSyncStatus(classifyProjectsGraphQLError("op", errors.New(c.msg)))
		if got != c.want {
			t.Fatalf("%q -> %s, want %s", c.msg, got, c.want)
		}
	}
	if projectsSyncStatus(nil) != projectsStatusOK {
		t.Fatal("nil error must be ok")
	}
}

// --- peer boundary: the error is no longer discarded -------------------------

func peerPMRequest(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("OPEN_SERVICE_JWT_SECRET", "test-secret")
	tok, err := openauth.MintServiceJWTWithOrg([]byte("test-secret"), "opm-api", "ora-api", "scm:pm", "default-org", 0)
	if err != nil {
		t.Fatalf("mint service jwt: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/peer/scm/projects/items/upsert", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handlePeerProjectItemUpsert(rec, req)
	return rec
}

func withStubConnector(t *testing.T, c *opaConnector) {
	t.Helper()
	connectorLive.Store(c.ID, c)
	t.Cleanup(func() { connectorLive.Delete(c.ID) })
}

// The regression this whole change exists for: a rename that did not reach the
// board must not come back looking like success.
func TestPeerProjectItemUpsertSurfacesTitleFailure(t *testing.T) {
	s := newStubGraphQL(t)
	s.resolve = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"node":{"id":"PVTI_item9","type":"ISSUE","content":{"id":"I_1","number":3}}}}`
	}
	withStubConnector(t, stubPATConnector())

	rec := peerPMRequest(t, `{"connector_id":"c-stub","project_id":"PVT_1","item_id":"PVTI_item9","title":"Renamed"}`)

	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if synced, _ := out["title_synced"].(bool); synced {
		t.Fatalf("title_synced must be false when the board was not updated: %v", out)
	}
	if got := strFromAny(out["title_status"]); got != projectsStatusTitleUnsupported {
		t.Fatalf("title_status=%q, want %s", got, projectsStatusTitleUnsupported)
	}
	if note := strFromAny(out["title_note"]); note == "" || !strings.Contains(note, "ISSUE") {
		t.Fatalf("title_note must explain the failure, got %q", note)
	}
}

func TestPeerProjectItemUpsertReportsTitleSynced(t *testing.T) {
	s := newStubGraphQL(t)
	s.resolve = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"node":{"id":"PVTI_item1","type":"DRAFT_ISSUE","content":{"id":"DI_draft1"}}}}`
	}
	s.mutate = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"updateProjectV2DraftIssue":{"draftIssue":{"id":"DI_draft1","title":"Renamed"}}}}`
	}
	withStubConnector(t, stubPATConnector())

	rec := peerPMRequest(t, `{"connector_id":"c-stub","project_id":"PVT_1","item_id":"PVTI_item1","title":"Renamed"}`)

	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if synced, _ := out["title_synced"].(bool); !synced {
		t.Fatalf("want title_synced true: %v", out)
	}
	if got := strFromAny(out["title_status"]); got != projectsStatusOK {
		t.Fatalf("title_status=%q, want %s", got, projectsStatusOK)
	}
}

// A brand-new draft carries the title we sent, so creation counts as synced.
func TestPeerProjectItemUpsertCreateReportsTitleSynced(t *testing.T) {
	s := newStubGraphQL(t)
	s.mutate = func(map[string]interface{}) (int, string) {
		return http.StatusOK, `{"data":{"addProjectV2DraftIssue":{"projectItem":{"id":"PVTI_new"}}}}`
	}
	// addProjectV2DraftIssue is a mutation but not the update one; route it explicitly.
	s.resolve = nil
	s.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query     string                 `json:"query"`
			Variables map[string]interface{} `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.calls = append(s.calls, stubGraphQLCall{Query: in.Query, Vars: in.Variables})
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(in.Query, "addProjectV2DraftIssue") {
			_, _ = w.Write([]byte(`{"data":{"addProjectV2DraftIssue":{"projectItem":{"id":"PVTI_new"}}}}`))
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"errors":[{"message":"stub: unexpected query"}]}`))
	})
	withStubConnector(t, stubPATConnector())

	rec := peerPMRequest(t, `{"connector_id":"c-stub","project_id":"PVT_1","title":"Fresh card"}`)

	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if got := strFromAny(out["item_id"]); got != "PVTI_new" {
		t.Fatalf("item_id=%q", got)
	}
	if synced, _ := out["title_synced"].(bool); !synced {
		t.Fatalf("a created draft carries the title: %v", out)
	}
}

// The pre-existing permission gap: an App installation without organization
// projects must get an explicit, grantable status — never a silent nil.
func TestPeerProjectItemUpsertMissingOrganizationProjects(t *testing.T) {
	newStubGraphQL(t)
	resetInstallationPermCacheForTest()
	t.Cleanup(resetInstallationPermCacheForTest)
	setInstallationPermCacheForTest("inst-noproj", map[string]string{
		"contents": "write", "metadata": "read", "pull_requests": "write",
		"issues": "write", "checks": "write",
	})
	withStubConnector(t, &opaConnector{
		ID: "c-stub", Kind: "github_app", InstallationID: "inst-noproj",
		OrganizationID: "default-org", ProjectID: "default-project",
		Status: "active", Scope: credScopeOrg,
	})

	rec := peerPMRequest(t, `{"connector_id":"c-stub","project_id":"PVT_1","item_id":"PVTI_item1","title":"Renamed"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := strFromAny(out["status"]); got != projectsStatusMissingPermission {
		t.Fatalf("status=%q, want %s", got, projectsStatusMissingPermission)
	}
	if ok, _ := out["ok"].(bool); ok {
		t.Fatal("ok must be false")
	}
	if note := strFromAny(out["note"]); !strings.Contains(strings.ToLower(note), "projects") {
		t.Fatalf("note must name the permission to grant, got %q", note)
	}
}
