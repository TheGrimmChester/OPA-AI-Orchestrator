package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Pull-request creation for the code-delivery peer surface.
//
// This lives apart from the generic helpers in scm_github.go because a delivery
// has to tell four outcomes apart and report each one honestly:
//   - the installation cannot write pull requests (403)
//   - the head branch was never pushed (422)
//   - head and base are identical, so there is nothing to open (422)
//   - a pull request for head → base is already open (422, and the existing one
//     is then resolved and returned instead of reporting a failure)
// A single fmt.Errorf would collapse all four into "upstream error".

// githubPullAPIError carries GitHub's status code and body for a PR call.
type githubPullAPIError struct {
	Code int
	Op   string
	Body string
}

func (e *githubPullAPIError) Error() string {
	return fmt.Sprintf("%s: github returned %d: %s", e.Op, e.Code, e.Body)
}

// Forbidden is true when the token exists but may not write pull requests.
func (e *githubPullAPIError) Forbidden() bool {
	return e.Code == http.StatusForbidden || e.Code == http.StatusUnauthorized
}

// NotFound is true when GitHub cannot see the repository at all.
func (e *githubPullAPIError) NotFound() bool { return e.Code == http.StatusNotFound }

// Unprocessable is GitHub's 422 for a semantically rejected PR.
func (e *githubPullAPIError) Unprocessable() bool { return e.Code == http.StatusUnprocessableEntity }

// NoCommits is true when head carries no commits base does not already have.
func (e *githubPullAPIError) NoCommits() bool {
	return e.Unprocessable() && strings.Contains(strings.ToLower(e.Body), "no commits between")
}

// HeadMissing is true when the head branch does not exist on the remote.
func (e *githubPullAPIError) HeadMissing() bool {
	low := strings.ToLower(e.Body)
	return e.Unprocessable() && (strings.Contains(low, "field: \"head\"") ||
		strings.Contains(low, "\"field\":\"head\"") ||
		strings.Contains(low, "head sha") ||
		strings.Contains(low, "head repository"))
}

// AlreadyExists is true when a pull request for head → base is already open.
func (e *githubPullAPIError) AlreadyExists() bool {
	return e.Unprocessable() && strings.Contains(strings.ToLower(e.Body), "already exists")
}

func newGitHubPullAPIError(op string, code int, raw []byte) *githubPullAPIError {
	return &githubPullAPIError{Code: code, Op: op, Body: truncateStr(string(raw), 400)}
}

// githubDeliveryPull is the normalized pull request returned to peers.
type githubDeliveryPull struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	Title   string `json:"title"`
	HeadRef string `json:"head_ref"`
	BaseRef string `json:"base_ref"`
	Draft   bool   `json:"draft"`
}

func decodeGitHubDeliveryPull(raw []byte) (*githubDeliveryPull, error) {
	var payload struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		State   string `json:"state"`
		Title   string `json:"title"`
		Draft   bool   `json:"draft"`
		Head    struct {
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if payload.Number <= 0 {
		return nil, fmt.Errorf("github returned a pull request without a number")
	}
	return &githubDeliveryPull{
		Number: payload.Number, HTMLURL: payload.HTMLURL, State: payload.State,
		Title: payload.Title, Draft: payload.Draft,
		HeadRef: payload.Head.Ref, BaseRef: payload.Base.Ref,
	}, nil
}

// mockDeliveryPullNumber keeps the smoke-mock PR number stable per branch so a
// mocked delivery reads back the same number it reported.
func mockDeliveryPullNumber(head string) int {
	sum := 0
	for _, r := range head {
		sum = (sum*31 + int(r)) % 8000
	}
	return 1000 + sum
}

// githubOpenPullRequest opens a PR from head into base. When GitHub reports one
// is already open for that pair it resolves and returns the existing PR with
// alreadyExisted=true, so re-running a delivery is idempotent rather than a
// hard failure the operator has to interpret.
func githubOpenPullRequest(c *opaConnector, owner, repo, title, body, head, base string, draft bool) (pull *githubDeliveryPull, alreadyExisted bool, err error) {
	if c == nil {
		return nil, false, fmt.Errorf("no connector")
	}
	head = strings.TrimSpace(head)
	base = strings.TrimSpace(base)
	title = strings.TrimSpace(title)
	if head == "" || base == "" {
		return nil, false, fmt.Errorf("head and base branch required")
	}
	if head == base {
		return nil, false, fmt.Errorf("head and base are the same branch (%s)", head)
	}
	if title == "" {
		return nil, false, fmt.Errorf("title required")
	}
	if githubUseMockAPI(c) {
		n := mockDeliveryPullNumber(head)
		return &githubDeliveryPull{
			Number: n, HTMLURL: fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, n),
			State: "open", Title: title, HeadRef: head, BaseRef: base, Draft: draft,
		}, false, nil
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"title": title, "body": body, "head": head, "base": base, "draft": draft,
	})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsCreatePR(), http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/pulls", owner, repo), strings.NewReader(string(payload)))
	if err != nil {
		return nil, false, err
	}
	if code >= 300 {
		apiErr := newGitHubPullAPIError("create pull request", code, raw)
		if apiErr.AlreadyExists() {
			if existing, lerr := githubFindOpenPullForHead(c, owner, repo, head); lerr == nil && existing != nil {
				return existing, true, nil
			}
		}
		return nil, false, apiErr
	}
	pull, err = decodeGitHubDeliveryPull(raw)
	if err != nil {
		return nil, false, err
	}
	return pull, false, nil
}

// githubFindOpenPullForHead resolves the open PR whose head is the given branch.
func githubFindOpenPullForHead(c *opaConnector, owner, repo, head string) (*githubDeliveryPull, error) {
	if c == nil || strings.TrimSpace(head) == "" {
		return nil, fmt.Errorf("no connector or head branch")
	}
	if githubUseMockAPI(c) {
		n := mockDeliveryPullNumber(head)
		return &githubDeliveryPull{
			Number: n, HTMLURL: fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, n),
			State: "open", HeadRef: head, BaseRef: "main",
		}, nil
	}
	raw, code, err := githubAPIScoped(c, owner, repo, githubPermsPRRead(), http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/pulls?state=open&head=%s:%s&per_page=1", owner, repo, owner, head), nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, newGitHubPullAPIError("list pulls for head", code, raw)
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no open pull request found for head %s", head)
	}
	return decodeGitHubDeliveryPull(list[0])
}

// githubMergePullRequest merges an open pull request. mergeMethod defaults to
// "squash" when empty. When the PR is already merged, current meta is returned
// so a re-driven autopilot merge converges instead of erroring.
func githubMergePullRequest(c *opaConnector, owner, repo string, number int, mergeMethod string) (*githubDeliveryPull, error) {
	if c == nil {
		return nil, fmt.Errorf("no connector")
	}
	if number <= 0 {
		return nil, fmt.Errorf("pull request number required")
	}
	mergeMethod = strings.ToLower(strings.TrimSpace(mergeMethod))
	switch mergeMethod {
	case "", "squash":
		mergeMethod = "squash"
	case "merge", "rebase":
		// allowed
	default:
		return nil, fmt.Errorf("unsupported merge_method %q (use squash, merge, or rebase)", mergeMethod)
	}
	if githubUseMockAPI(c) {
		return &githubDeliveryPull{
			Number: number,
			HTMLURL: fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, number),
			State: "merged", Title: "merged",
		}, nil
	}

	if existing, err := githubGetPull(c, owner, repo, number); err == nil && existing != nil {
		if existing.Merged || strings.EqualFold(existing.State, "merged") {
			return &githubDeliveryPull{
				Number: existing.Number,
				HTMLURL: fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, existing.Number),
				State: "merged", Title: existing.Title,
				HeadRef: existing.HeadRef, BaseRef: existing.BaseRef, Draft: existing.Draft,
			}, nil
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"merge_method": mergeMethod,
	})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsCreatePR(), http.MethodPut,
		fmt.Sprintf("/repos/%s/%s/pulls/%d/merge", owner, repo, number), strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, newGitHubPullAPIError("merge pull request", code, raw)
	}
	meta, err := githubGetPull(c, owner, repo, number)
	if err != nil {
		return &githubDeliveryPull{
			Number: number,
			HTMLURL: fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, number),
			State: "merged",
		}, nil
	}
	return &githubDeliveryPull{
		Number: meta.Number,
		HTMLURL: fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, meta.Number),
		State: "merged", Title: meta.Title,
		HeadRef: meta.HeadRef, BaseRef: meta.BaseRef, Draft: meta.Draft,
	}, nil
}

