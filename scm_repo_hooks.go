package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func ensureWatchedRepoWebhookColumns() {
	if queryClient == nil {
		return
	}
	for _, q := range []string{
		`ALTER TABLE opa.watched_repos ADD COLUMN IF NOT EXISTS github_hook_id Int64 DEFAULT 0`,
		`ALTER TABLE opa.watched_repos ADD COLUMN IF NOT EXISTS webhook_secret_ref String DEFAULT ''`,
		`ALTER TABLE opa.watched_repos ADD COLUMN IF NOT EXISTS webhook_mode LowCardinality(String) DEFAULT 'app'`,
	} {
		if err := queryClient.Execute(q); err != nil {
			log.Printf("[WARN] ensureWatchedRepoWebhookColumns: %v", err)
		}
	}
}

func newWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func decryptWebhookSecret(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("empty webhook secret ref")
	}
	if isEncryptedSecret(ref) {
		return decryptSecret(ref)
	}
	return ref, nil
}

func webhookURLForConnector(connectorID string) string {
	public := strings.TrimRight(envOr("OPA_PUBLIC_URL", "http://127.0.0.1:8080"), "/")
	return public + "/v1/scm/github/webhook/" + strings.TrimSpace(connectorID)
}

func syncWatchedRepoWebhook(c *opaConnector, wr *opaWatchedRepo, enable bool) error {
	if c == nil || wr == nil {
		return nil
	}
	if c.Kind != "github_pat" {
		if enable && wr.WebhookMode == "" {
			wr.WebhookMode = "app"
		}
		return nil
	}
	owner, repo := splitOwnerRepo(wr.RepoFullName)
	if owner == "" || repo == "" {
		return fmt.Errorf("invalid repo_full_name")
	}
	if !enable {
		return deleteRepoWebhook(c, wr, owner, repo)
	}
	return createOrUpdateRepoWebhook(c, wr, owner, repo)
}

func createOrUpdateRepoWebhook(c *opaConnector, wr *opaWatchedRepo, owner, repo string) error {
	if githubUseMockAPI(c) {
		if wr.GithubHookID == 0 {
			wr.GithubHookID = 900000 + int64(len(wr.RepoFullName))
		}
		if wr.WebhookSecretRef == "" {
			secret, _ := newWebhookSecret()
			enc, err := encryptSecret(secret)
			if err != nil {
				return err
			}
			wr.WebhookSecretRef = enc
		}
		wr.WebhookMode = "repo"
		persistWatched(wr)
		return nil
	}
	if wr.GithubHookID != 0 {
		wr.WebhookMode = "repo"
		persistWatched(wr)
		return nil
	}
	secret, err := newWebhookSecret()
	if err != nil {
		return err
	}
	enc, err := encryptSecret(secret)
	if err != nil {
		return err
	}
	body := map[string]interface{}{
		"name":   "web",
		"active": true,
		"events": []string{"pull_request", "push"},
		"config": map[string]interface{}{
			"url":          webhookURLForConnector(c.ID),
			"content_type": "json",
			"secret":       secret,
			"insecure_ssl": "0",
		},
	}
	payload, _ := json.Marshal(body)
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsAdminRepoHook(), http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/hooks", owner, repo), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("create hook %d: %s", code, string(raw))
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(raw, &resp)
	wr.GithubHookID = resp.ID
	wr.WebhookSecretRef = enc
	wr.WebhookMode = "repo"
	persistWatched(wr)
	log.Printf("[INFO] repo webhook registered %s hook_id=%d connector=%s", wr.RepoFullName, resp.ID, c.ID)
	return nil
}

func deleteRepoWebhook(c *opaConnector, wr *opaWatchedRepo, owner, repo string) error {
	if wr.GithubHookID == 0 {
		wr.WebhookSecretRef = ""
		wr.WebhookMode = "app"
		persistWatched(wr)
		return nil
	}
	if !githubUseMockAPI(c) {
		_, code, err := githubWriteAPI(c, owner, repo, githubPermsAdminRepoHook(), http.MethodDelete,
			fmt.Sprintf("/repos/%s/%s/hooks/%d", owner, repo, wr.GithubHookID), nil)
		if err != nil {
			return err
		}
		if code >= 300 && code != 404 {
			return fmt.Errorf("delete hook %d", code)
		}
	}
	wr.GithubHookID = 0
	wr.WebhookSecretRef = ""
	wr.WebhookMode = "app"
	persistWatched(wr)
	log.Printf("[INFO] repo webhook deleted %s connector=%s", wr.RepoFullName, c.ID)
	return nil
}

func githubPermsAdminRepoHook() map[string]string {
	return map[string]string{"admin:repo_hook": "write", "metadata": "read"}
}

func verifyRepoWebhookSignature(wr *opaWatchedRepo, body []byte, sigHeader string) bool {
	if wr == nil {
		return false
	}
	secret, err := decryptWebhookSecret(wr.WebhookSecretRef)
	if err != nil || secret == "" {
		return envOr("OPA_SCM_ALLOW_UNSIGNED", "0") == "1"
	}
	return verifyGitHubSignature(secret, body, sigHeader)
}

func findWatchedForConnectorRepo(connectorID, repo string) *opaWatchedRepo {
	connectorID = strings.TrimSpace(connectorID)
	repo = strings.TrimSpace(repo)
	if connectorID == "" || repo == "" {
		return nil
	}
	if v, ok := watchedLive.Load(connectorID + "|" + repo); ok {
		if wr, ok := v.(*opaWatchedRepo); ok {
			return wr
		}
	}
	return nil
}

func watchedHookIDFromRow(row map[string]interface{}) int64 {
	switch v := row["github_hook_id"].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	default:
		return 0
	}
}

func readWebhookBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 8<<20))
}
