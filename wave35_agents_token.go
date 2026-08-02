package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Permission maps for least-privilege installation tokens. workflows is never
// requested (Zero Workflow Changes); stripWorkflowsPerm is a belt-and-braces guard.

func githubPermsCloneRead() map[string]string {
	return map[string]string{"contents": "read", "metadata": "read"}
}

// githubPermsPRRead is least-privilege for PR metadata / unified diffs / compare.
func githubPermsPRRead() map[string]string {
	return map[string]string{
		"contents":      "read",
		"pull_requests": "read",
		"metadata":      "read",
	}
}

func githubPermsChecksWrite() map[string]string {
	return map[string]string{"checks": "write", "metadata": "read"}
}

func githubPermsPRWrite() map[string]string {
	return map[string]string{
		"pull_requests": "write",
		"issues":        "write",
		"metadata":      "read",
	}
}

func githubPermsPush() map[string]string {
	// contents:write for git push / create blob; never workflows.
	return map[string]string{"contents": "write", "metadata": "read"}
}

func githubPermsCreatePR() map[string]string {
	return map[string]string{
		"pull_requests": "write",
		"contents":      "write",
		"metadata":      "read",
	}
}

// stripWorkflowsPerm copies perms without a workflows key.
func stripWorkflowsPerm(perms map[string]string) map[string]string {
	if len(perms) == 0 {
		return perms
	}
	out := make(map[string]string, len(perms))
	for k, v := range perms {
		if strings.EqualFold(k, "workflows") {
			continue
		}
		out[k] = v
	}
	return out
}

// githubInstallationTokenRequestPayload builds the POST body for a scoped
// installation token. Empty repos+perms → nil (legacy full-scope).
func githubInstallationTokenRequestPayload(repos []string, perms map[string]string) map[string]interface{} {
	perms = stripWorkflowsPerm(perms)
	if len(repos) == 0 && len(perms) == 0 {
		return nil
	}
	payload := map[string]interface{}{}
	if len(repos) > 0 {
		payload["repositories"] = repos
	}
	if len(perms) > 0 {
		payload["permissions"] = perms
	}
	return payload
}

// githubInstallationTokenScoped mints an installation access token narrowed to
// the given repositories and permissions. Passing nil/empty for both preserves
// the historical "full installation scope" behaviour used by legacy call sites.
func githubInstallationTokenScoped(installationID string, repos []string, perms map[string]string) (string, error) {
	jwtStr, err := githubAppJWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installationID)

	var body io.Reader
	if payload := githubInstallationTokenRequestPayload(repos, perms); payload != nil {
		raw, _ := json.Marshal(payload)
		body = strings.NewReader(string(raw))
	}

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := githubHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("installation token %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Token == "" {
		return "", fmt.Errorf("no token in response")
	}
	return out.Token, nil
}

// installationPermCache stores permissions granted to an installation, probed
// once at first use. Asking for an ungranted permission returns 422 from GitHub;
// we refuse rather than silently widening.
var (
	installationPermMu    sync.Mutex
	installationPermCache = map[string]map[string]string{}
)

func resetInstallationPermCacheForTest() {
	installationPermMu.Lock()
	installationPermCache = map[string]map[string]string{}
	installationPermMu.Unlock()
}

func setInstallationPermCacheForTest(installationID string, perms map[string]string) {
	installationPermMu.Lock()
	installationPermCache[installationID] = perms
	installationPermMu.Unlock()
}

func probeGitHubInstallationPermissions(installationID string) (map[string]string, error) {
	installationID = strings.TrimSpace(installationID)
	if installationID == "" {
		return nil, fmt.Errorf("empty installation id")
	}
	installationPermMu.Lock()
	if cached, ok := installationPermCache[installationID]; ok {
		installationPermMu.Unlock()
		return cached, nil
	}
	installationPermMu.Unlock()

	jwtStr, err := githubAppJWT()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://api.github.com/app/installations/%s", installationID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := githubHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("installation probe %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.Permissions == nil {
		out.Permissions = map[string]string{}
	}
	installationPermMu.Lock()
	installationPermCache[installationID] = out.Permissions
	installationPermMu.Unlock()
	return out.Permissions, nil
}

// filterGrantedPerms drops permission keys the installation was not granted.
// Returns the filtered map and any dropped keys (for honesty strings).
func filterGrantedPerms(installationID string, want map[string]string) (map[string]string, []string, error) {
	granted, err := probeGitHubInstallationPermissions(installationID)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]string{}
	var dropped []string
	for k, v := range want {
		g, ok := granted[k]
		if !ok || g == "" {
			dropped = append(dropped, k)
			continue
		}
		// Requested level must not exceed granted (write > read).
		if v == "write" && g == "read" {
			dropped = append(dropped, k+"(write>read)")
			continue
		}
		out[k] = v
	}
	return out, dropped, nil
}

// requireGrantedPerms is filterGrantedPerms that refuses when any required
// permission is missing — callers must not fall back to a full-scope token.
func requireGrantedPerms(installationID string, want map[string]string) (map[string]string, error) {
	want = stripWorkflowsPerm(want)
	if len(want) == 0 {
		return map[string]string{}, nil
	}
	out, dropped, err := filterGrantedPerms(installationID, want)
	if err != nil {
		return nil, err
	}
	if len(dropped) > 0 {
		return nil, fmt.Errorf("installation lacks required permissions %v — refusing full-scope fallback", dropped)
	}
	return out, nil
}

// githubInstallationTokenFor mints a repo-scoped installation token with the
// given permissions after probing the installation. On ungranted perms or HTTP
// 422 it refuses with an honesty error — never silently widens to full scope.
func githubInstallationTokenFor(installationID, repoFullName string, want map[string]string) (string, error) {
	installationID = strings.TrimSpace(installationID)
	if installationID == "" {
		return "", fmt.Errorf("empty installation id")
	}
	want = stripWorkflowsPerm(want)
	var repos []string
	if short := githubRepoShortName(repoFullName); short != "" {
		repos = []string{short}
	}
	if len(want) > 0 {
		filtered, err := requireGrantedPerms(installationID, want)
		if err != nil {
			return "", err
		}
		want = filtered
	}
	tok, err := githubInstallationTokenScoped(installationID, repos, want)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "422") || strings.Contains(errStr, " installation token 422") {
			return "", fmt.Errorf("installation token 422 (ungranted perms) — refusing full-scope fallback: %w", err)
		}
		return "", err
	}
	return tok, nil
}

// githubAccessTokenFor returns a PAT verbatim or a scoped App installation token.
// PAT write gating is separate (authorizeGitHubWrite); this only mints credentials.
func githubAccessTokenFor(c *opaConnector, repoFullName string, perms map[string]string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("no connector")
	}
	if c.Kind == "github_pat" && c.TokenRef != "" {
		return c.TokenRef, nil
	}
	if c.InstallationID != "" {
		return githubInstallationTokenFor(c.InstallationID, repoFullName, perms)
	}
	return "", fmt.Errorf("no credentials on connector")
}

// githubRepoShortName returns the repo name without owner for installation token
// "repositories" payloads (GitHub expects short names, not owner/repo).
func githubRepoShortName(fullName string) string {
	_, repo := splitOwnerRepo(fullName)
	return repo
}
