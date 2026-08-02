package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// scmPRIsMerged reports whether a pull request is already merged.
// Prefer the explicit merged flag or a non-empty merged_at; state=closed alone
// is not enough (closed without merge = declined / withdrawn).
func scmPRIsMerged(merged bool, mergedAt, state string) bool {
	if merged {
		return true
	}
	if strings.TrimSpace(mergedAt) != "" {
		return true
	}
	// closed + merged is covered by the merged flag; ignore bare closed.
	_ = state
	return false
}

// In-memory index of commit SHAs that already had a successful OPA Review
// (repo + SHA uniqueness — same tree is not re-reviewed).
var scmSuccessfulAIReviewBySHA sync.Map // key → scmSuccessfulAIReview

type scmSuccessfulAIReview struct {
	RepoFullName string `json:"repo_full_name"`
	CommitSHA    string `json:"commit_sha"`
	JobID        string `json:"job_id"`
	ReviewedAt   string `json:"reviewed_at"`
	AIStatus     string `json:"ai_status"`
}

func scmReviewedSHAKey(repo, sha string) string {
	return strings.ToLower(strings.TrimSpace(repo)) + "@" + strings.ToLower(strings.TrimSpace(sha))
}

// scmSHAEqual compares commit SHAs case-insensitively and accepts prefix matches
// (full 40-char vs abbreviated) when both sides are non-empty.
func scmSHAEqual(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// scmPlaceholderCommitSHA is true for synthetic SHAs that must not participate
// in already-reviewed dedupe (manual/cron placeholders before resolve).
func scmPlaceholderCommitSHA(sha string) bool {
	sha = strings.TrimSpace(sha)
	return sha == "" || strings.HasPrefix(sha, "manual-") || strings.HasPrefix(sha, "cron-")
}

// scmAIReviewSucceeded reports whether an OPA Review AI result status means the
// agent actually ran successfully (findings or clean). skipped/error/pending do not.
func scmAIReviewSucceeded(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "clean", "findings", "ok":
		return true
	default:
		return false
	}
}

func scmJobAIStatus(job *scmJob) string {
	if job == nil || job.Summary == nil {
		return ""
	}
	raw, ok := job.Summary["ai"]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case aiReviewResult:
		return v.Status
	case *aiReviewResult:
		if v == nil {
			return ""
		}
		return v.Status
	case map[string]interface{}:
		return strFromAny(v["status"])
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		m := map[string]interface{}{}
		if json.Unmarshal(b, &m) != nil {
			return ""
		}
		return strFromAny(m["status"])
	}
}

func scmJobReviewedSHA(job *scmJob) string {
	if job == nil {
		return ""
	}
	if job.Summary != nil {
		if sha := strFromAny(job.Summary["analyzed_sha"]); !scmPlaceholderCommitSHA(sha) {
			return strings.TrimSpace(sha)
		}
	}
	return strings.TrimSpace(job.CommitSHA)
}

// lookupSuccessfulAIReviewForSHA finds a prior job that successfully AI-reviewed
// this exact commit in the repo (repo + SHA). excludeJobID is the current job.
func lookupSuccessfulAIReviewForSHA(repo, sha, excludeJobID string) (priorJobID string, ok bool) {
	repo = strings.TrimSpace(repo)
	sha = strings.TrimSpace(sha)
	if repo == "" || scmPlaceholderCommitSHA(sha) {
		return "", false
	}
	key := scmReviewedSHAKey(repo, sha)
	if v, loaded := scmSuccessfulAIReviewBySHA.Load(key); loaded {
		if st, ok := v.(scmSuccessfulAIReview); ok && st.JobID != "" && st.JobID != excludeJobID {
			return st.JobID, true
		}
	}
	// Prefix / abbreviated SHA or cold index: scan live jobs.
	var best *scmJob
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || j == nil || j.ID == excludeJobID {
			return true
		}
		if !strings.EqualFold(j.RepoFullName, repo) {
			return true
		}
		jobSHA := scmJobReviewedSHA(j)
		if scmPlaceholderCommitSHA(jobSHA) || !scmSHAEqual(jobSHA, sha) {
			return true
		}
		if !scmAIReviewSucceeded(scmJobAIStatus(j)) {
			return true
		}
		// Accept completed, and failed (AppSec gate fail with successful AI).
		st := strings.ToLower(j.Status)
		if st != "completed" && st != "failed" {
			return true
		}
		if best == nil || j.FinishedAt > best.FinishedAt || (j.FinishedAt == "" && j.StartedAt > best.StartedAt) {
			best = j
		}
		return true
	})
	if best == nil {
		return "", false
	}
	recordSuccessfulAIReview(best, scmJobReviewedSHA(best), scmJobAIStatus(best))
	return best.ID, true
}

// recordSuccessfulAIReview indexes a repo+SHA after a successful OPA Review.
func recordSuccessfulAIReview(job *scmJob, sha, aiStatus string) {
	if job == nil || !scmAIReviewSucceeded(aiStatus) {
		return
	}
	sha = strings.TrimSpace(sha)
	if scmPlaceholderCommitSHA(sha) || strings.TrimSpace(job.RepoFullName) == "" {
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	if job.FinishedAt != "" {
		now = job.FinishedAt
	}
	scmSuccessfulAIReviewBySHA.Store(scmReviewedSHAKey(job.RepoFullName, sha), scmSuccessfulAIReview{
		RepoFullName: job.RepoFullName,
		CommitSHA:    sha,
		JobID:        job.ID,
		ReviewedAt:   now,
		AIStatus:     strings.ToLower(strings.TrimSpace(aiStatus)),
	})
}

// rebuildSuccessfulAIReviewIndex populates the repo+SHA index from hydrated jobs.
func rebuildSuccessfulAIReviewIndex() {
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || j == nil {
			return true
		}
		st := strings.ToLower(j.Status)
		if st != "completed" && st != "failed" {
			return true
		}
		aiSt := scmJobAIStatus(j)
		if !scmAIReviewSucceeded(aiSt) {
			return true
		}
		sha := scmJobReviewedSHA(j)
		if scmPlaceholderCommitSHA(sha) {
			return true
		}
		recordSuccessfulAIReview(j, sha, aiSt)
		return true
	})
}

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
