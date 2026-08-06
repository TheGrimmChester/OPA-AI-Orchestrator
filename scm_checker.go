package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type checkerPublishMeta struct {
	Key        string
	Name       string
	SHA        string
	Status     string
	Conclusion string
	Title      string
	Summary    string
	DetailsURL string
}

// publishCheckerResult posts a GitHub Check Run when the connector can, otherwise
// falls back to commit status with context {product}/{checker_id}.
func publishCheckerResult(conn *opaConnector, owner, repo string, meta checkerPublishMeta) (id int64, mode string, err error) {
	if conn == nil || strings.TrimSpace(meta.SHA) == "" {
		return 0, "", fmt.Errorf("connector and commit sha required")
	}
	if meta.Name == "" {
		meta.Name = meta.Key
	}
	if meta.Title == "" {
		meta.Title = meta.Name
	}
	if meta.Summary == "" {
		meta.Summary = meta.Title
	}
	status := nz(meta.Status, "completed")
	conclusion := meta.Conclusion
	if status != "completed" && conclusion == "" {
		conclusion = ""
	} else if conclusion == "" && status == "completed" {
		conclusion = "neutral"
	}

	useCheckRun := conn.Kind == "github_app" && conn.InstallationID != ""
	if conn.Kind == "github_pat" && envOr("OPA_SCM_SKIP_CHECK_RUNS", "1") == "1" {
		useCheckRun = false
	}
	if useCheckRun && !githubUseMockAPI(conn) {
		if status == "completed" {
			id, err = githubCreateCheckRun(conn, owner, repo, meta.Name, meta.SHA, status, conclusion, meta.Title, meta.Summary, meta.DetailsURL, nil)
		} else {
			id, err = githubCreateCheckRun(conn, owner, repo, meta.Name, meta.SHA, status, "", meta.Title, meta.Summary, meta.DetailsURL, nil)
		}
		if err == nil {
			return id, "check_run", nil
		}
	}

	product, checkerID := splitCheckerKey(meta.Key)
	ctxName := strings.Trim(product, "/") + "/" + strings.Trim(checkerID, "/")
	state := mapCheckerConclusionToCommitState(conclusion, status)
	if err := githubCreateCommitStatus(conn, owner, repo, meta.SHA, state, ctxName, meta.Title, meta.DetailsURL); err != nil {
		return 0, "commit_status", err
	}
	return 0, "commit_status", nil
}

func mapCheckerConclusionToCommitState(conclusion, status string) string {
	if status != "completed" {
		return "pending"
	}
	switch strings.ToLower(strings.TrimSpace(conclusion)) {
	case "success":
		return "success"
	case "failure", "cancelled", "timed_out", "action_required":
		return "failure"
	case "error":
		return "error"
	default:
		return "success"
	}
}

func githubCreateCommitStatus(c *opaConnector, owner, repo, sha, state, context, description, targetURL string) error {
	if c == nil || githubUseMockAPI(c) {
		return nil
	}
	body := map[string]interface{}{
		"state":       state,
		"context":     context,
		"description": truncateStr(description, 140),
	}
	if targetURL != "" {
		body["target_url"] = targetURL
	}
	payload, _ := json.Marshal(body)
	_, code, err := githubWriteAPI(c, owner, repo, githubPermsStatusWrite(), http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/statuses/%s", owner, repo, sha), strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("commit status %d", code)
	}
	return nil
}

func githubPermsStatusWrite() map[string]string {
	return map[string]string{"statuses": "write", "contents": "read", "metadata": "read"}
}

func mergeCheckerRunIDs(job *scmJob, ids map[string]int64) {
	if job == nil || len(ids) == 0 {
		return
	}
	if job.CheckRunIDs == nil {
		job.CheckRunIDs = map[string]int64{}
	}
	for k, v := range ids {
		job.CheckRunIDs[k] = v
	}
}
