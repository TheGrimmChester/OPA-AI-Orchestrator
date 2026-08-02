package main

import "strings"

// populateCarriedFindingKeys computes finding keys outside the incremental
// compare window and stores them on job.Summary so planOPAReviewCommentActions
// will not mass-Close them.
func populateCarriedFindingKeys(job *scmJob, conn *opaConnector, owner, repo string, prefs agentPrefs) {
	if job == nil || !prefs.IncrementalReview || job.PRNumber <= 0 {
		return
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	prev := strFromAny(job.Summary["previous_analyzed_sha"])
	if prev == "" {
		if prep := childByKind(job.RunID, kindPrepare); prep != nil && prep.Summary != nil {
			prev = strFromAny(prep.Summary["previous_analyzed_sha"])
		}
	}
	if prev == "" {
		if parent := getSCMJob(job.RunID); parent != nil && parent.Summary != nil {
			prev = strFromAny(parent.Summary["previous_analyzed_sha"])
		}
	}
	head := strings.TrimSpace(job.CommitSHA)
	if head == "" {
		head = strFromAny(job.Summary["analyzed_sha"])
	}
	if prev == "" || head == "" || strings.EqualFold(prev, head) {
		return
	}
	diff, err := githubCompareDiff(conn, owner, repo, prev, head)
	if err != nil || diff == "" {
		return
	}
	touched := diffPathsFromUnified(diff)
	prior := collectPriorOPAReviewComments(conn, owner, repo, job.PRNumber)
	priorKeys := make([]string, 0, len(prior))
	priorFileByKey := map[string]string{}
	for _, p := range prior {
		if p.Key == "" {
			continue
		}
		priorKeys = append(priorKeys, p.Key)
		priorFileByKey[p.Key] = p.Path
	}
	carried := computeCarriedForwardKeys(priorKeys, priorFileByKey, touched)
	job.Summary["carried_finding_keys"] = carried
	job.Summary["previous_analyzed_sha"] = prev
	job.Summary["incremental_base_sha"] = prev
}

// carriedForwardKeysFromJob returns finding keys that must not be Closed when an
// incremental (narrowed) review omits untouched files. Without this, the first
// incremental run mass-marks prior findings as "Fixed in later commits".
func carriedForwardKeysFromJob(job *scmJob) map[string]struct{} {
	out := map[string]struct{}{}
	if job == nil || job.Summary == nil {
		return out
	}
	raw, ok := job.Summary["carried_finding_keys"]
	if !ok || raw == nil {
		return out
	}
	switch v := raw.(type) {
	case []string:
		for _, k := range v {
			if k = strings.TrimSpace(k); k != "" {
				out[k] = struct{}{}
			}
		}
	case []interface{}:
		for _, x := range v {
			if s, ok := x.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out[s] = struct{}{}
				}
			}
		}
	}
	return out
}

// computeCarriedForwardKeys unions prior finding keys whose files are outside
// the incremental diff path set.
func computeCarriedForwardKeys(priorKeys []string, priorFileByKey map[string]string, touchedFiles map[string]struct{}) []string {
	out := []string{}
	for _, k := range priorKeys {
		file := priorFileByKey[k]
		if file == "" {
			continue
		}
		if _, touched := touchedFiles[file]; touched {
			continue
		}
		out = append(out, k)
	}
	return out
}

func diffPathsFromUnified(diff string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			p := strings.TrimPrefix(line, "+++ b/")
			p = strings.TrimSpace(p)
			if p != "" && p != "/dev/null" {
				out[p] = struct{}{}
			}
		}
		if strings.HasPrefix(line, "diff --git ") {
			// diff --git a/foo b/foo
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				b := strings.TrimPrefix(parts[3], "b/")
				if b != "" {
					out[b] = struct{}{}
				}
			}
		}
	}
	return out
}
