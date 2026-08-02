package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func githubHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func githubAppJWT() (string, error) {
	appID := strings.TrimSpace(os.Getenv("OPA_GITHUB_APP_ID"))
	pemStr := strings.TrimSpace(os.Getenv("OPA_GITHUB_APP_PRIVATE_KEY"))
	if appID == "" || pemStr == "" {
		return "", fmt.Errorf("OPA_GITHUB_APP_ID / OPA_GITHUB_APP_PRIVATE_KEY not set")
	}
	pemStr = strings.ReplaceAll(pemStr, `\n`, "\n")
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("invalid PEM private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", err
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("not RSA private key")
		}
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	})
	return tok.SignedString(key)
}

func githubInstallationToken(installationID string) (string, error) {
	// Legacy full-installation scope. Prefer githubInstallationTokenScoped with
	// an explicit repos+perms allowlist for new call sites.
	return githubInstallationTokenScoped(installationID, nil, nil)
}

func githubAccessToken(c *opaConnector) (string, error) {
	if c == nil {
		return "", fmt.Errorf("no connector")
	}
	if c.Kind == "github_pat" && c.TokenRef != "" {
		return c.TokenRef, nil
	}
	if c.InstallationID != "" {
		return githubInstallationToken(c.InstallationID)
	}
	return "", fmt.Errorf("no credentials on connector")
}

func githubAPI(c *opaConnector, method, path string, body io.Reader) ([]byte, int, error) {
	tok, err := githubAccessToken(c)
	if err != nil {
		return nil, 0, err
	}
	return githubAPIWithToken(tok, method, path, body)
}

// githubAPIWithToken performs a GitHub REST call with an already-minted token.
func githubAPIWithToken(tok, method, path string, body io.Reader) ([]byte, int, error) {
	url := path
	if !strings.HasPrefix(path, "http") {
		url = "https://api.github.com" + path
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := githubHTTPClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return raw, resp.StatusCode, nil
}

// githubAPIScoped mints a repo-scoped App token (or PAT) for the given perms
// and performs the request. Used by write/publish call sites.
func githubAPIScoped(c *opaConnector, owner, repo string, perms map[string]string, method, path string, body io.Reader) ([]byte, int, error) {
	full := strings.Trim(owner+"/"+repo, "/")
	tok, err := githubAccessTokenFor(c, full, perms)
	if err != nil {
		return nil, 0, err
	}
	return githubAPIWithToken(tok, method, path, body)
}

// githubWriteAPI is githubAPIScoped after authorizeGitHubWrite (fail closed for PAT).
func githubWriteAPI(c *opaConnector, owner, repo string, perms map[string]string, method, path string, body io.Reader) ([]byte, int, error) {
	if _, err := authorizeGitHubWrite(c); err != nil {
		return nil, 0, err
	}
	return githubAPIScoped(c, owner, repo, perms, method, path, body)
}

// githubLooksLikeRealToken detects classic / fine-grained / OAuth GitHub tokens.
// Smoke fakes (ghp_fake, empty, random strings) return false so OPA_SCM_MOCK_GITHUB can apply.
func githubLooksLikeRealToken(tok string) bool {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return false
	}
	low := strings.ToLower(tok)
	if strings.Contains(low, "fake") || strings.Contains(low, "smoke") || strings.Contains(low, "example") {
		return false
	}
	for _, p := range []string{"ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_"} {
		if strings.HasPrefix(tok, p) && len(tok) > len(p)+12 {
			return true
		}
	}
	return false
}

// githubUseMockAPI is true when compose smoke mock is on AND credentials are not a real PAT.
// Real ghp_ / github_pat_ tokens always call GitHub even if OPA_SCM_MOCK_GITHUB=1.
func githubUseMockAPI(c *opaConnector) bool {
	if envOr("OPA_SCM_MOCK_GITHUB", "0") != "1" {
		return false
	}
	if c != nil && c.Kind == "github_pat" && githubLooksLikeRealToken(c.TokenRef) {
		return false
	}
	return true
}

func githubExplainReposHTTP(code int, raw []byte) error {
	body := strings.TrimSpace(string(raw))
	if len(body) > 280 {
		body = body[:280] + "…"
	}
	switch code {
	case 401:
		return fmt.Errorf("github 401 unauthorized — PAT invalid/expired, or missing Authorization (%s)", body)
	case 403:
		low := strings.ToLower(body)
		if strings.Contains(low, "saml") || strings.Contains(low, "sso") {
			return fmt.Errorf("github 403 SSO — authorize the PAT for the org (GitHub → Settings → Applications → SSO) (%s)", body)
		}
		return fmt.Errorf("github 403 forbidden — classic PAT needs `repo` scope; fine-grained needs Repository access + Metadata (and Contents to clone) (%s)", body)
	case 404:
		return fmt.Errorf("github 404 — token cannot see repos (wrong account or fine-grained resource owner) (%s)", body)
	case 301, 302, 307, 308:
		// Rare for api.github.com (client follows redirects); usually wrong API host / renamed org path.
		return fmt.Errorf("github %d moved — API redirected (check enterprise host / renamed org; %s)", code, body)
	default:
		return fmt.Errorf("github repos %d: %s", code, body)
	}
}

func githubListRepos(c *opaConnector) ([]map[string]interface{}, error) {
	// Compose smoke uses mock for fake/empty tokens; real PATs always hit GitHub.
	if githubUseMockAPI(c) {
		return githubMockListRepos(c), nil
	}
	var path string
	if c.Kind == "github_pat" {
		path = "/user/repos?per_page=100&affiliation=owner,organization_member"
	} else {
		path = fmt.Sprintf("/installation/repositories?per_page=100")
	}
	raw, code, err := githubAPI(c, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, githubExplainReposHTTP(code, raw)
	}
	out := []map[string]interface{}{}
	if c.Kind == "github_pat" {
		var repos []struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
			Private  bool   `json:"private"`
		}
		if json.Unmarshal(raw, &repos) != nil {
			return nil, fmt.Errorf("decode repos")
		}
		for _, r := range repos {
			out = append(out, map[string]interface{}{
				"id": strconv.FormatInt(r.ID, 10), "full_name": r.FullName, "private": r.Private,
			})
		}
		return out, nil
	}
	var wrap struct {
		Repositories []struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
			Private  bool   `json:"private"`
		} `json:"repositories"`
	}
	if json.Unmarshal(raw, &wrap) != nil {
		return nil, fmt.Errorf("decode installation repos")
	}
	for _, r := range wrap.Repositories {
		out = append(out, map[string]interface{}{
			"id": strconv.FormatInt(r.ID, 10), "full_name": r.FullName, "private": r.Private,
		})
	}
	return out, nil
}

// githubMockListRepos returns installable repos for OPA_SCM_MOCK_GITHUB=1.
func githubMockListRepos(c *opaConnector) []map[string]interface{} {
	seen := map[string]bool{}
	out := []map[string]interface{}{}
	add := func(name, id string, private bool) {
		name = strings.TrimSpace(name)
		if name == "" || seen[strings.ToLower(name)] {
			return
		}
		seen[strings.ToLower(name)] = true
		out = append(out, map[string]interface{}{
			"id": id, "full_name": name, "private": private, "mock": true,
		})
	}
	add("local/smoke-repo", "mock-1", false)
	add("local/demo-app", "mock-2", false)
	if c != nil && strings.TrimSpace(c.AccountLogin) != "" {
		add(c.AccountLogin+"/opa-workspace", "mock-3", true)
	}
	if c != nil {
		watchedLive.Range(func(_, v interface{}) bool {
			wr, ok := v.(*opaWatchedRepo)
			if ok && wr.ConnectorID == c.ID {
				add(wr.RepoFullName, nz(wr.RepoID, "mock-w"), false)
			}
			return true
		})
	}
	return out
}

// scmJobDashboardURL returns the OPA Dashboard job page URL for a SCM job.
// Matches Dashboard scmJobHref: /security/jobs/:jobId
func scmJobDashboardURL(jobID string) string {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return ""
	}
	base := strings.TrimRight(envOr("OPA_DASHBOARD_URL", "http://127.0.0.1:8088"), "/")
	return base + "/security/jobs/" + jobID
}

// checkRunSummaryWithJobLink appends a markdown link to the Dashboard job page.
func checkRunSummaryWithJobLink(summary, jobID string) string {
	u := scmJobDashboardURL(jobID)
	if u == "" {
		return summary
	}
	link := fmt.Sprintf("[View in OPA Dashboard](%s)", u)
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return link
	}
	return summary + "\n\n" + link
}

// scmCancelReasonIsSupersede is true when a job was dropped because a newer PR
// commit arrived (cancel-and-supersede), as opposed to manual/merge cancel.
func scmCancelReasonIsSupersede(reason string) bool {
	r := strings.ToLower(strings.TrimSpace(reason))
	return strings.HasPrefix(r, "superseded by")
}

// githubCheckFieldsForCancelReason maps an internal cancel reason to a GitHub
// Check Run conclusion. Superseded commits use "skipped" so the PR checks UI
// shows Skipped rather than Cancelled / failure-looking red.
func githubCheckFieldsForCancelReason(reason string) (conclusion, title, summary string) {
	reason = strings.TrimSpace(reason)
	if scmCancelReasonIsSupersede(reason) {
		return "skipped", "Skipped", nz(reason, "Superseded by newer push")
	}
	return "cancelled", "Cancelled", nz(reason, "Job cancelled")
}

func githubCheckFieldsForJobCancel(job *scmJob) (conclusion, title, summary string) {
	reason := ""
	if job != nil {
		if job.Summary != nil {
			reason, _ = job.Summary["cancel_reason"].(string)
		}
		if reason == "" {
			reason = job.Error
		}
	}
	return githubCheckFieldsForCancelReason(reason)
}

// closeSCMJobGitHubChecks completes any Check Runs already opened for this job.
// Best-effort: missing connector / mock / PAT-skip are no-ops.
// When the cancel is a supersede and no checks exist yet (job still queued),
// top-level jobs get completed/skipped stub checks so GitHub shows Skipped.
func closeSCMJobGitHubChecks(job *scmJob, reason string) {
	if job == nil {
		return
	}
	conn := getOrHydrateConnector(job.ConnectorID)
	if conn == nil {
		_, conn = findWatched(job.RepoFullName)
	}
	if conn == nil {
		return
	}
	owner, repo := splitOwnerRepo(job.RepoFullName)
	if owner == "" || repo == "" {
		return
	}
	conclusion, title, summary := githubCheckFieldsForCancelReason(reason)
	dashID := nz(job.RunID, job.ID)
	details := scmJobDashboardURL(dashID)
	linkSum := checkRunSummaryWithJobLink(summary, dashID)

	closed := 0
	for _, checkID := range job.CheckRunIDs {
		if checkID == 0 {
			continue
		}
		_ = githubUpdateCheckRun(conn, owner, repo, checkID, "completed", conclusion, title, linkSum, details, nil)
		closed++
	}
	if closed > 0 || !scmCancelReasonIsSupersede(reason) {
		return
	}
	// Child agents: parent/cascade owns stub creation for the commit.
	if strings.TrimSpace(job.ParentID) != "" {
		return
	}
	if agentKind(job.Kind) == kindRun {
		for _, c := range listRunChildren(job.ID) {
			if c == nil {
				continue
			}
			for _, checkID := range c.CheckRunIDs {
				if checkID == 0 {
					continue
				}
				_ = githubUpdateCheckRun(conn, owner, repo, checkID, "completed", conclusion, title, linkSum, details, nil)
				closed++
			}
		}
		if closed > 0 {
			return
		}
	}
	sha := strings.TrimSpace(job.CommitSHA)
	if sha == "" || strings.HasPrefix(sha, "manual-") || strings.HasPrefix(sha, "cron-") {
		return
	}
	// No checks were opened before supersede — post skipped stubs on this SHA.
	if job.CheckRunIDs == nil {
		job.CheckRunIDs = map[string]int64{}
	}
	if id, err := githubCreateCheckRun(conn, owner, repo, "OPA AppSec Gate", sha, "completed", conclusion, title, linkSum, details, nil); err == nil && id != 0 {
		job.CheckRunIDs["appsec"] = id
	}
	if id, err := githubCreateCheckRun(conn, owner, repo, "OPA Review", sha, "completed", conclusion, title, linkSum, details, nil); err == nil && id != 0 {
		job.CheckRunIDs["ai"] = id
	}
	persistSCMJob(job)
}

// githubCompleteCheckRunForCancel updates one check id using the job's cancel reason
// (skipped for supersede, cancelled otherwise). Used by in-flight processors.
func githubCompleteCheckRunForCancel(conn *opaConnector, owner, repo string, checkID int64, job *scmJob, detailsURL string) {
	if checkID == 0 || job == nil {
		return
	}
	conclusion, title, summary := githubCheckFieldsForJobCancel(job)
	dashID := nz(job.RunID, job.ID)
	_ = githubUpdateCheckRun(conn, owner, repo, checkID, "completed", conclusion, title,
		checkRunSummaryWithJobLink(summary, dashID), detailsURL, nil)
}

func githubCreateCheckRun(c *opaConnector, owner, repo, name, headSHA, status, conclusion, title, summary, detailsURL string, annotations []map[string]interface{}) (int64, error) {
	if c == nil || githubUseMockAPI(c) || c.Kind == "github_pat" && envOr("OPA_SCM_SKIP_CHECK_RUNS", "1") == "1" {
		return time.Now().Unix(), nil // mock id
	}
	body := map[string]interface{}{
		"name":     name,
		"head_sha": headSHA,
		"status":   status,
		"output": map[string]interface{}{
			"title":   title,
			"summary": summary,
		},
	}
	if conclusion != "" {
		body["conclusion"] = conclusion
	}
	if detailsURL != "" {
		body["details_url"] = detailsURL
	}
	if len(annotations) > 0 {
		if out, ok := body["output"].(map[string]interface{}); ok {
			if len(annotations) > 50 {
				annotations = annotations[:50]
			}
			out["annotations"] = annotations
		}
	}
	payload, _ := json.Marshal(body)
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsChecksWrite(), http.MethodPost, fmt.Sprintf("/repos/%s/%s/check-runs", owner, repo), strings.NewReader(string(payload)))
	if err != nil {
		return 0, err
	}
	if code >= 300 {
		return 0, fmt.Errorf("check-run %d: %s", code, string(raw))
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(raw, &resp)
	return resp.ID, nil
}

func githubUpdateCheckRun(c *opaConnector, owner, repo string, checkID int64, status, conclusion, title, summary, detailsURL string, annotations []map[string]interface{}) error {
	if checkID == 0 || githubUseMockAPI(c) || c != nil && c.Kind == "github_pat" && envOr("OPA_SCM_SKIP_CHECK_RUNS", "1") == "1" {
		return nil
	}
	body := map[string]interface{}{
		"status": status,
		"output": map[string]interface{}{"title": title, "summary": summary},
	}
	if conclusion != "" {
		body["conclusion"] = conclusion
	}
	if detailsURL != "" {
		body["details_url"] = detailsURL
	}
	if len(annotations) > 0 {
		if out, ok := body["output"].(map[string]interface{}); ok {
			if len(annotations) > 50 {
				annotations = annotations[:50]
			}
			out["annotations"] = annotations
		}
	}
	payload, _ := json.Marshal(body)
	_, code, err := githubWriteAPI(c, owner, repo, githubPermsChecksWrite(), http.MethodPatch, fmt.Sprintf("/repos/%s/%s/check-runs/%d", owner, repo, checkID), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("update check-run %d", code)
	}
	return nil
}

func githubPRComment(c *opaConnector, owner, repo string, pr int, body string) error {
	_, err := githubPRCommentCreate(c, owner, repo, pr, body)
	return err
}

// githubPRCommentCreate posts an issue comment and returns its id.
func githubPRCommentCreate(c *opaConnector, owner, repo string, pr int, body string) (int64, error) {
	if c == nil || pr <= 0 || githubUseMockAPI(c) {
		return 0, nil
	}
	payload, _ := json.Marshal(map[string]string{"body": body})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsPRWrite(), http.MethodPost, fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, pr), strings.NewReader(string(payload)))
	if err != nil {
		return 0, err
	}
	if code >= 300 {
		return 0, fmt.Errorf("comment %d", code)
	}
	var out struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.ID, nil
}

func githubUpdateIssueComment(c *opaConnector, owner, repo string, commentID int64, body string) error {
	if c == nil || commentID == 0 || githubUseMockAPI(c) {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"body": body})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsPRWrite(), http.MethodPatch, fmt.Sprintf("/repos/%s/%s/issues/comments/%d", owner, repo, commentID), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("update issue comment %d: %s", code, truncateStr(string(raw), 200))
	}
	return nil
}

type githubIssueComment struct {
	ID   int64
	Body string
	User string
}

func githubListIssueComments(c *opaConnector, owner, repo string, pr int) ([]githubIssueComment, error) {
	if c == nil || pr <= 0 {
		return nil, nil
	}
	if githubUseMockAPI(c) {
		return nil, nil
	}
	out := []githubIssueComment{}
	page := 1
	for page <= 5 {
		raw, code, err := githubAPI(c, http.MethodGet, fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100&page=%d", owner, repo, pr, page), nil)
		if err != nil {
			return out, err
		}
		if code >= 300 {
			return out, fmt.Errorf("list issue comments %d", code)
		}
		var batch []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
			User struct {
				Login string `json:"login"`
			} `json:"user"`
		}
		if json.Unmarshal(raw, &batch) != nil || len(batch) == 0 {
			break
		}
		for _, row := range batch {
			out = append(out, githubIssueComment{ID: row.ID, Body: row.Body, User: row.User.Login})
		}
		if len(batch) < 100 {
			break
		}
		page++
	}
	return out, nil
}

type githubReviewComment struct {
	ID        int64
	Body      string
	Path      string
	Line      int
	Original  int
	CommitID  string
	User      string
	InReplyTo int64
}

func githubListPRReviewComments(c *opaConnector, owner, repo string, pr int) ([]githubReviewComment, error) {
	if c == nil || pr <= 0 {
		return nil, nil
	}
	if githubUseMockAPI(c) {
		return nil, nil
	}
	out := []githubReviewComment{}
	page := 1
	for page <= 10 {
		raw, code, err := githubAPI(c, http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls/%d/comments?per_page=100&page=%d", owner, repo, pr, page), nil)
		if err != nil {
			return out, err
		}
		if code >= 300 {
			return out, fmt.Errorf("list review comments %d", code)
		}
		var batch []struct {
			ID               int64  `json:"id"`
			Body             string `json:"body"`
			Path             string `json:"path"`
			Line             int    `json:"line"`
			OriginalLine     int    `json:"original_line"`
			CommitID         string `json:"commit_id"`
			InReplyTo        int64  `json:"in_reply_to_id"`
			User             struct {
				Login string `json:"login"`
			} `json:"user"`
		}
		if json.Unmarshal(raw, &batch) != nil || len(batch) == 0 {
			break
		}
		for _, row := range batch {
			line := row.Line
			if line < 1 {
				line = row.OriginalLine
			}
			out = append(out, githubReviewComment{
				ID: row.ID, Body: row.Body, Path: row.Path, Line: line,
				Original: row.OriginalLine, CommitID: row.CommitID,
				User: row.User.Login, InReplyTo: row.InReplyTo,
			})
		}
		if len(batch) < 100 {
			break
		}
		page++
	}
	return out, nil
}

func githubUpdatePRReviewComment(c *opaConnector, owner, repo string, commentID int64, body string) error {
	if c == nil || commentID == 0 || githubUseMockAPI(c) {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"body": body})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsPRWrite(), http.MethodPatch, fmt.Sprintf("/repos/%s/%s/pulls/comments/%d", owner, repo, commentID), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("update review comment %d: %s", code, truncateStr(string(raw), 200))
	}
	return nil
}

func githubReplyPRReviewComment(c *opaConnector, owner, repo string, pr int, commitSHA string, inReplyTo int64, body string) error {
	if c == nil || pr <= 0 || inReplyTo == 0 || githubUseMockAPI(c) {
		return nil
	}
	payload := map[string]interface{}{
		"body":        body,
		"in_reply_to": inReplyTo,
	}
	if commitSHA != "" {
		payload["commit_id"] = commitSHA
	}
	raw, _ := json.Marshal(payload)
	resp, code, err := githubWriteAPI(c, owner, repo, githubPermsPRWrite(), http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls/%d/comments", owner, repo, pr), strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("reply review comment %d: %s", code, truncateStr(string(resp), 200))
	}
	return nil
}

// githubPRInlineComment posts a single pull-request review comment on a line.
// Requires commit_id + path + line (RIGHT side of the diff).
func githubPRInlineComment(c *opaConnector, owner, repo string, pr int, commitSHA, path string, line int, body string) error {
	if c == nil || pr <= 0 || githubUseMockAPI(c) {
		return nil
	}
	if commitSHA == "" || path == "" || line < 1 || strings.TrimSpace(body) == "" {
		return fmt.Errorf("commit_id, path, line, and body required")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"body":      body,
		"commit_id": commitSHA,
		"path":      path,
		"line":      line,
		"side":      "RIGHT",
	})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsPRWrite(), http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls/%d/comments", owner, repo, pr), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("inline comment %d: %s", code, truncateStr(string(raw), 240))
	}
	return nil
}

type githubPRReviewCommentSpec struct {
	Path string
	Line int
	Body string
}

// githubCreatePRReview creates a PR review with a short résumé body and optional
// inline comments. event is COMMENT, APPROVE, or REQUEST_CHANGES.
func githubCreatePRReview(c *opaConnector, owner, repo string, pr int, commitSHA, body, event string, comments []githubPRReviewCommentSpec) error {
	if c == nil || pr <= 0 || githubUseMockAPI(c) {
		return nil
	}
	if event == "" {
		event = "COMMENT"
	}
	payload := map[string]interface{}{
		"commit_id": commitSHA,
		"body":      body,
		"event":     event,
	}
	if len(comments) > 0 {
		arr := make([]map[string]interface{}, 0, len(comments))
		for _, cmt := range comments {
			if cmt.Path == "" || cmt.Line < 1 || strings.TrimSpace(cmt.Body) == "" {
				continue
			}
			arr = append(arr, map[string]interface{}{
				"path": cmt.Path, "line": cmt.Line, "side": "RIGHT", "body": cmt.Body,
			})
		}
		if len(arr) > 0 {
			payload["comments"] = arr
		}
	}
	raw, _ := json.Marshal(payload)
	resp, code, err := githubWriteAPI(c, owner, repo, githubPermsPRWrite(), http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews", owner, repo, pr), strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("pr review %d: %s", code, truncateStr(string(resp), 240))
	}
	return nil
}

// githubUpdatePullBody PATCHes a pull request description. Used for the OPA
// summary fence — never for decision events.
func githubUpdatePullBody(c *opaConnector, owner, repo string, pr int, body string) error {
	if c == nil || pr <= 0 {
		return nil
	}
	if githubUseMockAPI(c) {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"body": body})
	resp, code, err := githubWriteAPI(c, owner, repo, githubPermsPRWrite(), http.MethodPatch, fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, pr), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("update pull body %d: %s", code, truncateStr(string(resp), 200))
	}
	return nil
}

// githubRequestPRReviewers asks GitHub to request reviewers on a PR.
// For GitHub Apps, pass the app slug (OPA_GITHUB_APP_SLUG) as a reviewer login.
func githubRequestPRReviewers(c *opaConnector, owner, repo string, pr int, reviewers []string) error {
	return githubRequestPRReviewersEx(c, owner, repo, pr, reviewers, nil)
}

func githubRequestPRReviewersEx(c *opaConnector, owner, repo string, pr int, reviewers, teamReviewers []string) error {
	if c == nil || pr <= 0 || githubUseMockAPI(c) {
		return nil
	}
	cleaned := make([]string, 0, len(reviewers))
	seen := map[string]struct{}{}
	for _, r := range reviewers {
		r = strings.TrimSpace(r)
		r = strings.TrimSuffix(r, "[bot]")
		if r == "" {
			continue
		}
		key := strings.ToLower(r)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		cleaned = append(cleaned, r)
	}
	teams := make([]string, 0, len(teamReviewers))
	teamSeen := map[string]struct{}{}
	for _, t := range teamReviewers {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		key := strings.ToLower(t)
		if _, ok := teamSeen[key]; ok {
			continue
		}
		teamSeen[key] = struct{}{}
		teams = append(teams, t)
	}
	if len(cleaned) == 0 && len(teams) == 0 {
		return nil
	}
	payloadMap := map[string]interface{}{}
	if len(cleaned) > 0 {
		payloadMap["reviewers"] = cleaned
	}
	if len(teams) > 0 {
		payloadMap["team_reviewers"] = teams
	}
	payload, _ := json.Marshal(payloadMap)
	resp, code, err := githubWriteAPI(c, owner, repo, githubPermsPRWrite(), http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls/%d/requested_reviewers", owner, repo, pr), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	// 422 often means already requested — treat as soft success.
	if code == 422 {
		return nil
	}
	if code >= 300 {
		return fmt.Errorf("request reviewers %d: %s", code, truncateStr(string(resp), 240))
	}
	return nil
}

func githubAppReviewerLogin() string {
	slug := strings.TrimSpace(os.Getenv("OPA_GITHUB_APP_SLUG"))
	if slug == "" {
		slug = "opa-ai-orchestrator"
	}
	return slug
}

func githubPRDiff(c *opaConnector, owner, repo string, pr int) (string, error) {
	if githubUseMockAPI(c) {
		return "diff --git a/example.js b/example.js\n+eval(userInput)\n", nil
	}
	tok, err := githubAccessTokenFor(c, owner+"/"+repo, githubPermsPRRead())
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", owner, repo, pr)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github.v3.diff")
	resp, err := githubHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("diff %d", resp.StatusCode)
	}
	return string(raw), nil
}

type githubPullMeta struct {
	Number   int
	Title    string
	Body     string
	Draft    bool
	HeadSHA  string
	HeadRef  string
	BaseRef  string
	State    string
	Merged   bool
	MergedAt string
}

func githubGetPull(c *opaConnector, owner, repo string, pr int) (*githubPullMeta, error) {
	if pr <= 0 {
		return nil, fmt.Errorf("invalid pr")
	}
	if githubUseMockAPI(c) {
		return &githubPullMeta{
			Number: pr, Title: fmt.Sprintf("Mock PR #%d", pr), Body: "mock body",
			Draft: false, HeadSHA: "mocksha" + newRandomHex(6), HeadRef: "feature/mock", BaseRef: "main", State: "open",
		}, nil
	}
	raw, code, err := githubAPI(c, http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, pr), nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("pull %d: %s", code, truncateStr(string(raw), 200))
	}
	var body struct {
		Number   int    `json:"number"`
		Title    string `json:"title"`
		Body     string `json:"body"`
		Draft    bool   `json:"draft"`
		State    string `json:"state"`
		Merged   bool   `json:"merged"`
		MergedAt string `json:"merged_at"`
		Head     struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return nil, fmt.Errorf("bad pull json")
	}
	return &githubPullMeta{
		Number: body.Number, Title: body.Title, Body: body.Body,
		Draft: body.Draft, HeadSHA: body.Head.SHA, HeadRef: body.Head.Ref,
		BaseRef: body.Base.Ref, State: body.State,
		Merged: body.Merged, MergedAt: body.MergedAt,
	}, nil
}

func githubListPulls(c *opaConnector, owner, repo string) ([]map[string]interface{}, error) {
	if githubUseMockAPI(c) {
		return []map[string]interface{}{
			{"number": 1, "title": "Mock: add smoke fixture", "draft": false, "state": "open", "head": map[string]interface{}{"sha": "mocksha111"}},
			{"number": 42, "title": "Mock: security harden", "draft": false, "state": "open", "head": map[string]interface{}{"sha": "mocksha222"}},
		}, nil
	}
	raw, code, err := githubAPI(c, http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls?state=open&per_page=30", owner, repo), nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("pulls %d: %s", code, truncateStr(string(raw), 200))
	}
	var list []map[string]interface{}
	if json.Unmarshal(raw, &list) != nil {
		return nil, fmt.Errorf("bad pulls json")
	}
	out := []map[string]interface{}{}
	for _, p := range list {
		num, _ := p["number"].(float64)
		title, _ := p["title"].(string)
		draft, _ := p["draft"].(bool)
		state, _ := p["state"].(string)
		head, _ := p["head"].(map[string]interface{})
		sha := ""
		if head != nil {
			sha, _ = head["sha"].(string)
		}
		out = append(out, map[string]interface{}{
			"number": int(num), "title": title, "draft": draft, "state": state,
			"head": map[string]interface{}{"sha": sha},
		})
	}
	return out, nil
}

func githubGetRepoFile(c *opaConnector, owner, repo, path string) (string, error) {
	if githubUseMockAPI(c) {
		switch path {
		case "README.md":
			return "# Mock repo\n\nAppSec smoke fixture with eval() for scanners.\n", nil
		case "ARCHITECTURE.md":
			return "# Architecture\n\nNode service behind API gateway. Secrets in env.\n", nil
		default:
			return "", fmt.Errorf("not found")
		}
	}
	raw, code, err := githubAPI(c, http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path), nil)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("contents %d", code)
	}
	var body struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return "", fmt.Errorf("bad contents json")
	}
	if body.Encoding == "base64" {
		decoded, err := decodeBase64Flexible(body.Content)
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}
	return body.Content, nil
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func handleConnectorPulls(w http.ResponseWriter, r *http.Request, id string) {
	repo := strings.TrimSpace(r.URL.Query().Get("repo"))
	if repo == "" {
		http.Error(w, "repo query required (owner/name)", 400)
		return
	}
	c := getOrHydrateConnector(id)
	if denyConnectorIfInvisible(w, r, c) {
		return
	}
	owner, name := splitOwnerRepo(repo)
	pulls, err := githubListPulls(c, owner, name)
	if err != nil {
		writeJSON(w, map[string]interface{}{"pulls": []interface{}{}, "error": err.Error()})
		return
	}
	out := map[string]interface{}{"pulls": pulls, "repo": repo}
	if githubUseMockAPI(c) {
		out["mock"] = true
	}
	writeJSON(w, out)
}

// githubCreatePullRequest opens a PR. Returns number, html_url.
func githubCreatePullRequest(c *opaConnector, owner, repo, title, body, head, base string, draft bool) (int, string, error) {
	if githubUseMockAPI(c) {
		return 0, fmt.Sprintf("https://github.com/%s/%s/pull/0", owner, repo), nil
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"title": title, "body": body, "head": head, "base": base, "draft": draft,
	})
	raw, code, err := githubWriteAPI(c, owner, repo, githubPermsCreatePR(), http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls", owner, repo), strings.NewReader(string(payload)))
	if err != nil {
		return 0, "", err
	}
	if code >= 300 {
		return 0, "", fmt.Errorf("create pull %d: %s", code, truncateStr(string(raw), 240))
	}
	var out struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Number, out.HTMLURL, nil
}

func splitOwnerRepo(full string) (string, string) {
	parts := strings.SplitN(full, "/", 2)
	if len(parts) != 2 {
		return "", full
	}
	return parts[0], parts[1]
}
