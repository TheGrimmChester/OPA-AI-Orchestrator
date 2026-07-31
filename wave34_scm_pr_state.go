package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// In-memory PR review state: last analyzed SHA per repo#pr (survives across jobs in-process).
var scmPRReviewState sync.Map // key → scmPRAnalyzedState

type scmPRAnalyzedState struct {
	RepoFullName string `json:"repo_full_name"`
	PRNumber     int    `json:"pr_number"`
	AnalyzedSHA  string `json:"analyzed_sha"`
	AnalyzedAt   string `json:"analyzed_at"`
	JobID        string `json:"job_id,omitempty"`
}

func scmPRStateKey(repo string, pr int) string {
	return strings.ToLower(strings.TrimSpace(repo)) + "#" + fmt.Sprintf("%d", pr)
}

func lookupPreviousAnalyzedSHA(repo string, pr int, excludeJobID string) (sha, at, fromJob string) {
	if pr <= 0 || repo == "" {
		return "", "", ""
	}
	key := scmPRStateKey(repo, pr)
	if v, ok := scmPRReviewState.Load(key); ok {
		if st, ok := v.(scmPRAnalyzedState); ok && st.AnalyzedSHA != "" && st.JobID != excludeJobID {
			return st.AnalyzedSHA, st.AnalyzedAt, st.JobID
		}
	}
	// Fall back: latest completed job for same repo+PR with analyzed_sha / commit.
	var best *scmJob
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || j == nil || j.ID == excludeJobID {
			return true
		}
		if !strings.EqualFold(j.RepoFullName, repo) || j.PRNumber != pr {
			return true
		}
		st := strings.ToLower(j.Status)
		if st != "completed" && st != "failed" {
			return true
		}
		if best == nil || j.FinishedAt > best.FinishedAt || (j.FinishedAt == "" && j.StartedAt > best.StartedAt) {
			best = j
		}
		return true
	})
	if best == nil || best.Summary == nil {
		return "", "", ""
	}
	sha = strFromAny(best.Summary["analyzed_sha"])
	at = strFromAny(best.Summary["analyzed_at"])
	if sha == "" {
		sha = best.CommitSHA
	}
	return sha, at, best.ID
}

func recordAnalyzedSHA(job *scmJob, sha string) {
	if job == nil {
		return
	}
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	prev := strFromAny(job.Summary["analyzed_sha"])
	if prev == "" {
		prevSHA, prevAt, prevJob := lookupPreviousAnalyzedSHA(job.RepoFullName, job.PRNumber, job.ID)
		if prevSHA != "" {
			job.Summary["previous_analyzed_sha"] = prevSHA
			if prevAt != "" {
				job.Summary["previous_analyzed_at"] = prevAt
			}
			if prevJob != "" {
				job.Summary["previous_analyzed_job_id"] = prevJob
			}
			if !strings.EqualFold(prevSHA, sha) {
				job.Summary["commits_since_previous"] = true
				job.Summary["new_commits_since_review"] = true
			} else {
				job.Summary["commits_since_previous"] = false
				job.Summary["new_commits_since_review"] = false
			}
		}
	} else if !strings.EqualFold(prev, sha) {
		job.Summary["previous_analyzed_sha"] = prev
		job.Summary["commits_since_previous"] = true
		job.Summary["new_commits_since_review"] = true
	}
	job.Summary["analyzed_sha"] = sha
	job.Summary["analyzed_at"] = now
	job.CommitSHA = sha
	if job.PRNumber > 0 && job.RepoFullName != "" {
		scmPRReviewState.Store(scmPRStateKey(job.RepoFullName, job.PRNumber), scmPRAnalyzedState{
			RepoFullName: job.RepoFullName,
			PRNumber:     job.PRNumber,
			AnalyzedSHA:  sha,
			AnalyzedAt:   now,
			JobID:        job.ID,
		})
	}
}
