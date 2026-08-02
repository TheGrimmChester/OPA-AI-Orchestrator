package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

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
	if len(repos) > 0 || len(perms) > 0 {
		payload := map[string]interface{}{}
		if len(repos) > 0 {
			payload["repositories"] = repos
		}
		if len(perms) > 0 {
			payload["permissions"] = perms
		}
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

// githubRepoShortName returns the repo name without owner for installation token
// "repositories" payloads (GitHub expects short names, not owner/repo).
func githubRepoShortName(fullName string) string {
	_, repo := splitOwnerRepo(fullName)
	return repo
}
