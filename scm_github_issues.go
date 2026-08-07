package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// GitHub Issues / milestones REST helpers for AI Issues and scm:pm peers.

// githubIssueAPIError carries the upstream HTTP status so callers can tell a
// deleted/renumbered issue (404) apart from a missing permission (403) and
// report the concrete reason instead of a generic upstream failure.
type githubIssueAPIError struct {
	Code int
	Op   string
	Body string
}

func (e *githubIssueAPIError) Error() string {
	return fmt.Sprintf("%s: github returned %d: %s", e.Op, e.Code, e.Body)
}

// IssueMissing is true when GitHub says the issue does not exist. GitHub also
// answers 404 when the token cannot see the repository at all, which the peer
// layer disambiguates with the installation permission probe.
func (e *githubIssueAPIError) IssueMissing() bool { return e.Code == http.StatusNotFound }

// Forbidden is true when the token exists but lacks Issues write.
func (e *githubIssueAPIError) Forbidden() bool {
	return e.Code == http.StatusForbidden || e.Code == http.StatusUnauthorized
}

func newGitHubIssueAPIError(op string, code int, raw []byte) *githubIssueAPIError {
	return &githubIssueAPIError{Code: code, Op: op, Body: truncateStr(string(raw), 300)}
}

type githubIssueMeta struct {
	Number         int      `json:"number"`
	Title          string   `json:"title"`
	Body           string   `json:"body"`
	State          string   `json:"state"`
	HTMLURL        string   `json:"html_url"`
	Labels         []string `json:"labels"`
	Milestone      int      `json:"milestone"`
	MilestoneTitle string   `json:"milestone_title,omitempty"`
	Assignees      []string `json:"assignees,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

type githubMilestoneMeta struct {
	Number      int    `json:"number"`
	Title       string `json:"title"`
	Description string `json:"description"`
	State       string `json:"state"`
	HTMLURL     string `json:"html_url"`
}

func githubGetIssue(c *opaConnector, owner, repo string, number int) (*githubIssueMeta, error) {
	if c == nil || number <= 0 {
		return nil, fmt.Errorf("missing connector or issue number")
	}
	if githubUseMockAPI(c) {
		return &githubIssueMeta{
			Number: number, Title: "mock issue", Body: "mock body", State: "open",
			HTMLURL: fmt.Sprintf("https://github.com/%s/%s/issues/%d", owner, repo, number),
			Labels:  []string{"AI"},
		}, nil
	}
	raw, code, err := githubAPIScoped(c, owner, repo, githubPermsIssuesWrite(), http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/issues/%d", owner, repo, number), nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, newGitHubIssueAPIError(fmt.Sprintf("get issue #%d", number), code, raw)
	}
	return decodeGitHubIssue(raw)
}

func decodeGitHubIssue(raw []byte) (*githubIssueMeta, error) {
	var payload struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		Body    string `json:"body"`
		State   string `json:"state"`
		HTMLURL string `json:"html_url"`
		Labels  []struct {
			Name string `json:"name"`
		} `json:"labels"`
		Milestone *struct {
			Number int    `json:"number"`
			Title  string `json:"title"`
		} `json:"milestone"`
		Assignees []struct {
			Login string `json:"login"`
		} `json:"assignees"`
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	out := &githubIssueMeta{
		Number: payload.Number, Title: payload.Title, Body: payload.Body,
		State: payload.State, HTMLURL: payload.HTMLURL, UpdatedAt: payload.UpdatedAt,
	}
	for _, l := range payload.Labels {
		if l.Name != "" {
			out.Labels = append(out.Labels, l.Name)
		}
	}
	if payload.Milestone != nil {
		out.Milestone = payload.Milestone.Number
		out.MilestoneTitle = payload.Milestone.Title
	}
	for _, a := range payload.Assignees {
		if a.Login != "" {
			out.Assignees = append(out.Assignees, a.Login)
		}
	}
	return out, nil
}

// githubUpdateIssue patches title/body/state/milestone/labels on an existing
// issue. Empty string / nil fields are left untouched so callers can push a
// single field. milestone < 0 clears the milestone; milestone == 0 is "no change".
func githubUpdateIssue(c *opaConnector, owner, repo string, number int, title, body, state string, milestone int, labels []string) (*githubIssueMeta, []string, error) {
	if c == nil || number <= 0 {
		return nil, nil, fmt.Errorf("missing connector or issue number")
	}
	if state != "" && state != "open" && state != "closed" {
		return nil, nil, fmt.Errorf("state must be open or closed")
	}
	payload := map[string]interface{}{}
	applied := []string{}
	if strings.TrimSpace(title) != "" {
		payload["title"] = title
		applied = append(applied, "title")
	}
	if body != "" {
		payload["body"] = body
		applied = append(applied, "body")
	}
	if state != "" {
		payload["state"] = state
		applied = append(applied, "state")
	}
	if milestone > 0 {
		payload["milestone"] = milestone
		applied = append(applied, "milestone")
	} else if milestone < 0 {
		payload["milestone"] = nil
		applied = append(applied, "milestone")
	}
	if labels != nil {
		payload["labels"] = labels
		applied = append(applied, "labels")
	}
	if len(payload) == 0 {
		return nil, nil, fmt.Errorf("nothing to update")
	}
	if githubUseMockAPI(c) {
		return &githubIssueMeta{
			Number: number, Title: nz(title, "mock issue"), Body: body,
			State: nz(state, "open"), Labels: labels, Milestone: milestone,
			HTMLURL: fmt.Sprintf("https://github.com/%s/%s/issues/%d", owner, repo, number),
		}, applied, nil
	}
	rawBody, _ := json.Marshal(payload)
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsIssuesWrite(), http.MethodPatch,
		fmt.Sprintf("/repos/%s/%s/issues/%d", owner, repo, number), strings.NewReader(string(rawBody)))
	if err != nil {
		return nil, nil, err
	}
	if code >= 300 {
		return nil, nil, newGitHubIssueAPIError(fmt.Sprintf("update issue #%d", number), code, raw)
	}
	meta, err := decodeGitHubIssue(raw)
	if err != nil {
		return nil, nil, err
	}
	return meta, applied, nil
}

func githubCreateIssue(c *opaConnector, owner, repo, title, body string, labels []string, milestone int) (*githubIssueMeta, error) {
	if c == nil || strings.TrimSpace(title) == "" {
		return nil, fmt.Errorf("missing connector or title")
	}
	if githubUseMockAPI(c) {
		n := 9000 + len(title)%97
		return &githubIssueMeta{
			Number: n, Title: title, Body: body, State: "open", Labels: labels, Milestone: milestone,
			HTMLURL: fmt.Sprintf("https://github.com/%s/%s/issues/%d", owner, repo, n),
		}, nil
	}
	payload := map[string]interface{}{"title": title, "body": body}
	if len(labels) > 0 {
		payload["labels"] = labels
	}
	if milestone > 0 {
		payload["milestone"] = milestone
	}
	rawBody, _ := json.Marshal(payload)
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsIssuesWrite(), http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues", owner, repo), strings.NewReader(string(rawBody)))
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, newGitHubIssueAPIError("create issue", code, raw)
	}
	return decodeGitHubIssue(raw)
}

func githubSetIssueLabels(c *opaConnector, owner, repo string, number int, labels []string) error {
	if c == nil || number <= 0 {
		return fmt.Errorf("missing connector or issue number")
	}
	if githubUseMockAPI(c) {
		return nil
	}
	payload, _ := json.Marshal(map[string]interface{}{"labels": labels})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsIssuesWrite(), http.MethodPut,
		fmt.Sprintf("/repos/%s/%s/issues/%d/labels", owner, repo, number), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("set labels %d: %s", code, truncateStr(string(raw), 200))
	}
	return nil
}

func githubAddIssueLabels(c *opaConnector, owner, repo string, number int, labels []string) error {
	if c == nil || number <= 0 || len(labels) == 0 {
		return nil
	}
	if githubUseMockAPI(c) {
		return nil
	}
	payload, _ := json.Marshal(labels)
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsIssuesWrite(), http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues/%d/labels", owner, repo, number), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("add labels %d: %s", code, truncateStr(string(raw), 200))
	}
	return nil
}

func githubIssueCommentCreateNum(c *opaConnector, owner, repo string, number int, body string) (int64, error) {
	return githubPRCommentCreate(c, owner, repo, number, body)
}

func githubListMilestones(c *opaConnector, owner, repo string) ([]githubMilestoneMeta, error) {
	if c == nil {
		return nil, fmt.Errorf("no connector")
	}
	if githubUseMockAPI(c) {
		return []githubMilestoneMeta{{Number: 1, Title: "Mock Milestone", State: "open"}}, nil
	}
	raw, code, err := githubAPIScoped(c, owner, repo, githubPermsIssuesWrite(), http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/milestones?state=all&per_page=100", owner, repo), nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("list milestones %d: %s", code, truncateStr(string(raw), 200))
	}
	var batch []struct {
		Number      int    `json:"number"`
		Title       string `json:"title"`
		Description string `json:"description"`
		State       string `json:"state"`
		HTMLURL     string `json:"html_url"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil {
		return nil, err
	}
	out := make([]githubMilestoneMeta, 0, len(batch))
	for _, m := range batch {
		out = append(out, githubMilestoneMeta{
			Number: m.Number, Title: m.Title, Description: m.Description,
			State: m.State, HTMLURL: m.HTMLURL,
		})
	}
	return out, nil
}

func githubCreateMilestone(c *opaConnector, owner, repo, title, description string) (*githubMilestoneMeta, error) {
	if c == nil || strings.TrimSpace(title) == "" {
		return nil, fmt.Errorf("missing connector or title")
	}
	if githubUseMockAPI(c) {
		return &githubMilestoneMeta{
			Number: 42, Title: title, Description: description, State: "open",
			HTMLURL: fmt.Sprintf("https://github.com/%s/%s/milestone/42", owner, repo),
		}, nil
	}
	payload, _ := json.Marshal(map[string]string{"title": title, "description": description, "state": "open"})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsIssuesWrite(), http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/milestones", owner, repo), strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("create milestone %d: %s", code, truncateStr(string(raw), 200))
	}
	var m struct {
		Number      int    `json:"number"`
		Title       string `json:"title"`
		Description string `json:"description"`
		State       string `json:"state"`
		HTMLURL     string `json:"html_url"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &githubMilestoneMeta{
		Number: m.Number, Title: m.Title, Description: m.Description,
		State: m.State, HTMLURL: m.HTMLURL,
	}, nil
}

func githubFindOrCreateMilestone(c *opaConnector, owner, repo, title, description string) (*githubMilestoneMeta, error) {
	title = strings.TrimSpace(title)
	existing, err := githubListMilestones(c, owner, repo)
	if err == nil {
		for i := range existing {
			if strings.EqualFold(existing[i].Title, title) {
				return &existing[i], nil
			}
		}
	}
	return githubCreateMilestone(c, owner, repo, title, description)
}

func githubUpdateMilestone(c *opaConnector, owner, repo string, number int, title, description, state string) (*githubMilestoneMeta, error) {
	if c == nil || number <= 0 {
		return nil, fmt.Errorf("missing connector or milestone number")
	}
	if githubUseMockAPI(c) {
		out := &githubMilestoneMeta{
			Number: number, Title: nz(title, "Mock Milestone"), Description: description,
			State: nz(state, "open"),
			HTMLURL: fmt.Sprintf("https://github.com/%s/%s/milestone/%d", owner, repo, number),
		}
		return out, nil
	}
	payload := map[string]interface{}{}
	if strings.TrimSpace(title) != "" {
		payload["title"] = strings.TrimSpace(title)
	}
	if description != "" || title != "" {
		payload["description"] = description
	}
	if state == "open" || state == "closed" {
		payload["state"] = state
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("nothing to update")
	}
	rawBody, _ := json.Marshal(payload)
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsIssuesWrite(), http.MethodPatch,
		fmt.Sprintf("/repos/%s/%s/milestones/%d", owner, repo, number), strings.NewReader(string(rawBody)))
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("update milestone %d: %s", code, truncateStr(string(raw), 200))
	}
	var m struct {
		Number      int    `json:"number"`
		Title       string `json:"title"`
		Description string `json:"description"`
		State       string `json:"state"`
		HTMLURL     string `json:"html_url"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &githubMilestoneMeta{
		Number: m.Number, Title: m.Title, Description: m.Description,
		State: m.State, HTMLURL: m.HTMLURL,
	}, nil
}

// mergeIssueLabels unions existing + add without duplicates (case-insensitive).
func mergeIssueLabels(existing, add []string) []string {
	seen := map[string]string{}
	for _, l := range existing {
		k := strings.ToLower(strings.TrimSpace(l))
		if k == "" {
			continue
		}
		seen[k] = strings.TrimSpace(l)
	}
	for _, l := range add {
		k := strings.ToLower(strings.TrimSpace(l))
		if k == "" {
			continue
		}
		if _, ok := seen[k]; !ok {
			seen[k] = strings.TrimSpace(l)
		}
	}
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out
}
