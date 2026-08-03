package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// GitHub Issues / milestones REST helpers for AI Issues + roadmap publish.

type githubIssueMeta struct {
	Number    int      `json:"number"`
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	State     string   `json:"state"`
	HTMLURL   string   `json:"html_url"`
	Labels    []string `json:"labels"`
	Milestone int      `json:"milestone"`
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
		return nil, fmt.Errorf("get issue %d: %s", code, truncateStr(string(raw), 200))
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
			Number int `json:"number"`
		} `json:"milestone"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	out := &githubIssueMeta{
		Number: payload.Number, Title: payload.Title, Body: payload.Body,
		State: payload.State, HTMLURL: payload.HTMLURL,
	}
	for _, l := range payload.Labels {
		if l.Name != "" {
			out.Labels = append(out.Labels, l.Name)
		}
	}
	if payload.Milestone != nil {
		out.Milestone = payload.Milestone.Number
	}
	return out, nil
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
		return nil, fmt.Errorf("create issue %d: %s", code, truncateStr(string(raw), 200))
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
