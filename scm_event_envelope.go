package main

import (
	"encoding/json"
	"strings"
)

// scmEventEnvelope is the family contract payload fan-out to peer products.
type scmEventEnvelope struct {
	ID             string   `json:"id,omitempty"`
	EventType      string   `json:"event_type"`
	OrganizationID string   `json:"organization_id"`
	ProjectID      string   `json:"project_id"`
	ConnectorID    string   `json:"connector_id"`
	RepoFullName   string   `json:"repo_full_name"`
	Ref            string   `json:"ref,omitempty"`
	DefaultBranch  string   `json:"default_branch,omitempty"`
	PRNumber       int      `json:"pr_number,omitempty"`
	CommitSHA      string   `json:"commit_sha"`
	SCMJobID       string   `json:"scm_job_id,omitempty"`
	ChangedPaths   []string `json:"changed_paths"`
	Checks         []string `json:"checks"`
	Dispatch       *bool    `json:"dispatch,omitempty"`
}

func buildSCMEventEnvelope(rec *scmWebhookReceipt, job *scmJob, wr *opaWatchedRepo, raw []byte, event string) *scmEventEnvelope {
	dispatch := true
	idSeed := event
	if rec != nil {
		idSeed = rec.ID
	}
	env := &scmEventEnvelope{
		ID:           loadID("scmenv", idSeed, event),
		EventType:    normalizeSCMEnvelopeEvent(event, rec),
		Dispatch:     &dispatch,
	}
	if rec != nil {
		env.RepoFullName = rec.RepoFullName
		env.PRNumber = rec.PRNumber
		env.CommitSHA = rec.CommitSHA
		env.OrganizationID = rec.OrganizationID
		env.ProjectID = rec.ProjectID
		env.ConnectorID = rec.ConnectorID
	}
	if job != nil {
		env.SCMJobID = job.ID
		if env.OrganizationID == "" {
			env.OrganizationID = job.OrganizationID
		}
		if env.ProjectID == "" {
			env.ProjectID = job.ProjectID
		}
		if env.ConnectorID == "" {
			env.ConnectorID = job.ConnectorID
		}
	}
	if wr != nil {
		env.Checks = parseWatchedChecks(wr.ChecksJSON)
		if env.OrganizationID == "" {
			env.OrganizationID = wr.OrganizationID
		}
		if env.ProjectID == "" {
			env.ProjectID = wr.ProjectID
		}
		if env.ConnectorID == "" {
			env.ConnectorID = wr.ConnectorID
		}
	}
	env.Ref, env.DefaultBranch = extractWebhookRefDefaultBranch(raw, event)
	env.ChangedPaths = extractChangedPaths(raw, event)
	return env
}

func extractWebhookRefDefaultBranch(raw []byte, event string) (ref, defaultBranch string) {
	if len(raw) == 0 {
		return "", ""
	}
	switch strings.TrimSpace(event) {
	case "pull_request":
		var payload struct {
			PullRequest struct {
				Head struct {
					Ref string `json:"ref"`
				} `json:"head"`
			} `json:"pull_request"`
			Repository struct {
				DefaultBranch string `json:"default_branch"`
			} `json:"repository"`
		}
		if json.Unmarshal(raw, &payload) == nil {
			ref = payload.PullRequest.Head.Ref
			defaultBranch = payload.Repository.DefaultBranch
		}
	case "push":
		var payload struct {
			Ref string `json:"ref"`
			Repository struct {
				DefaultBranch string `json:"default_branch"`
			} `json:"repository"`
		}
		if json.Unmarshal(raw, &payload) == nil {
			ref = payload.Ref
			defaultBranch = payload.Repository.DefaultBranch
		}
	}
	return ref, defaultBranch
}

func normalizeSCMEnvelopeEvent(event string, rec *scmWebhookReceipt) string {
	event = strings.TrimSpace(event)
	switch event {
	case "pull_request":
		action := strings.TrimSpace(rec.Action)
		if action == "" {
			action = "unknown"
		}
		return "pull_request." + action
	case "push":
		if rec != nil && strings.TrimSpace(rec.Action) == "default" {
			return "push.default"
		}
		return "push"
	default:
		return event
	}
}

func extractChangedPaths(raw []byte, event string) []string {
	if len(raw) == 0 {
		return nil
	}
	switch strings.TrimSpace(event) {
	case "pull_request":
		var payload struct {
			PullRequest struct {
				Added    []string `json:"added"`
				Modified []string `json:"modified"`
				Removed  []string `json:"removed"`
			} `json:"pull_request"`
		}
		if json.Unmarshal(raw, &payload) != nil {
			return nil
		}
		return dedupePaths(append(append(payload.PullRequest.Added, payload.PullRequest.Modified...), payload.PullRequest.Removed...))
	case "push":
		var payload struct {
			Commits []struct {
				Added    []string `json:"added"`
				Modified []string `json:"modified"`
				Removed  []string `json:"removed"`
			} `json:"commits"`
			HeadCommit struct {
				Added    []string `json:"added"`
				Modified []string `json:"modified"`
				Removed  []string `json:"removed"`
			} `json:"head_commit"`
		}
		if json.Unmarshal(raw, &payload) != nil {
			return nil
		}
		var paths []string
		for _, c := range payload.Commits {
			paths = append(paths, c.Added...)
			paths = append(paths, c.Modified...)
			paths = append(paths, c.Removed...)
		}
		paths = append(paths, payload.HeadCommit.Added...)
		paths = append(paths, payload.HeadCommit.Modified...)
		paths = append(paths, payload.HeadCommit.Removed...)
		return dedupePaths(paths)
	default:
		return nil
	}
}

func dedupePaths(paths []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func parseWatchedChecks(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultWatchedChecks()
	}
	var checks []string
	if json.Unmarshal([]byte(raw), &checks) != nil || len(checks) == 0 {
		return defaultWatchedChecks()
	}
	return normalizeProductChecks(checks)
}

func normalizeProductChecks(checks []string) []string {
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		switch c {
		case "ai_review":
			out = append(out, "ora:review")
		default:
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return defaultWatchedChecks()
	}
	return out
}

func wantsORAReview(checks []string) bool {
	for _, c := range checks {
		switch c {
		case "ora:review", "ai_review":
			return true
		}
	}
	return false
}

func wantsLegacySecurityScan(checks []string) bool {
	for _, c := range checks {
		switch c {
		case "secrets", "sast", "iac", "sbom", "container":
			return true
		}
	}
	return false
}

func checkerStatusKey(product, checkerID string) string {
	return strings.TrimSpace(product) + ":" + strings.TrimSpace(checkerID)
}

func splitCheckerKey(key string) (product, checkerID string) {
	key = strings.TrimSpace(key)
	if i := strings.Index(key, ":"); i > 0 {
		return key[:i], key[i+1:]
	}
	return "ora", key
}
