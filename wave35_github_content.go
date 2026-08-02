package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// githubGetContentAtRef fetches a file blob at a specific git ref (branch/tag/SHA).
// Used for approval policy — always the base ref, never the PR head (self-approval).
func githubGetContentAtRef(c *opaConnector, owner, repo, filePath, ref string) (string, error) {
	filePath = strings.TrimPrefix(strings.TrimSpace(filePath), "/")
	ref = strings.TrimSpace(ref)
	if filePath == "" {
		return "", fmt.Errorf("empty path")
	}
	if githubUseMockAPI(c) {
		if strings.Contains(filePath, "approval-policy") {
			return `{"version":1,"require":["security","bugbot"],"block_if":{"security_min_severity":"high"},"on_fail":"COMMENT"}`, nil
		}
		return githubGetRepoFile(c, owner, repo, filePath)
	}
	q := ""
	if ref != "" {
		q = "?ref=" + url.QueryEscape(ref)
	}
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s%s", owner, repo, filePath, q)
	raw, code, err := githubAPI(c, http.MethodGet, apiPath, nil)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("contents %d: %s", code, truncateStr(string(raw), 160))
	}
	var body struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		Type     string `json:"type"`
		Size     int    `json:"size"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return "", fmt.Errorf("bad contents json")
	}
	if body.Type != "" && body.Type != "file" {
		return "", fmt.Errorf("not a file")
	}
	if body.Size > 64*1024 {
		return "", fmt.Errorf("file exceeds 64KiB policy cap")
	}
	if body.Encoding == "base64" {
		decoded, err := decodeBase64Flexible(body.Content)
		if err != nil {
			return "", err
		}
		if len(decoded) > 64*1024 {
			return "", fmt.Errorf("decoded file exceeds 64KiB policy cap")
		}
		return string(decoded), nil
	}
	if len(body.Content) > 64*1024 {
		return "", fmt.Errorf("file exceeds 64KiB policy cap")
	}
	return body.Content, nil
}

// githubCompareDiff returns the unified diff for base...head (same Accept as githubPRDiff).
func githubCompareDiff(c *opaConnector, owner, repo, base, head string) (string, error) {
	base = strings.TrimSpace(base)
	head = strings.TrimSpace(head)
	if base == "" || head == "" {
		return "", fmt.Errorf("base and head required")
	}
	if githubUseMockAPI(c) {
		return "diff --git a/example.js b/example.js\n+eval(userInput)\n", nil
	}
	tok, err := githubAccessTokenFor(c, owner+"/"+repo, githubPermsPRRead())
	if err != nil {
		return "", err
	}
	u := fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s...%s",
		owner, repo, url.PathEscape(base), url.PathEscape(head))
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github.v3.diff")
	resp, err := githubHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("compare %d: %s", resp.StatusCode, truncateStr(string(raw), 160))
	}
	return string(raw), nil
}

// safePolicyPath ensures a policy path stays inside the repo (no .. escape).
func safePolicyPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		p = ".opa/approval-policy.json"
	}
	p = path.Clean("/" + p)
	p = strings.TrimPrefix(p, "/")
	if p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") {
		return "", fmt.Errorf("policy path escapes repo")
	}
	if strings.HasPrefix(p, ".git/") || p == ".git" {
		return "", fmt.Errorf("policy path refused")
	}
	return p, nil
}

// keep decode available for content helper (also used by githubGetRepoFile).
var _ = base64.StdEncoding
