package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Related-repo sibling checkouts live next to the primary PR tree:
//
//	$OPA_REVIEW_TMP/{job_id}/
//	  primary/                 — PR checkout (scanner + agent cwd)
//	  related/{owner-repo}/    — shallow sibling clones
type relatedCheckout struct {
	RepoFullName string `json:"repo_full_name"`
	Path         string `json:"path"`
	SHA          string `json:"sha,omitempty"`
	Source       string `json:"source"` // link | pr_body | context | mid_review | stack
	Error        string `json:"error,omitempty"`
}

func opaReviewRelatedMax() int {
	n := atoiDefault(envOr("OPA_REVIEW_RELATED_MAX", "5"), 5)
	if n < 0 {
		n = 0
	}
	if n > 12 {
		n = 12
	}
	return n
}

func sanitizeRelatedRepoDir(fullName string) string {
	fullName = strings.TrimSpace(fullName)
	fullName = strings.ReplaceAll(fullName, "..", "_")
	fullName = strings.ReplaceAll(fullName, "/", "-")
	fullName = strings.ReplaceAll(fullName, " ", "_")
	if fullName == "" {
		fullName = "unknown"
	}
	if len(fullName) > 120 {
		fullName = fullName[:120]
	}
	return fullName
}

func scmJobContainerAbs(worktreeID string) string {
	return filepath.Join(opaReviewTmpRoot(), sanitizeWorktreeID(worktreeID))
}

func scmPrimaryCheckoutAbs(worktreeID string) string {
	return filepath.Join(scmJobContainerAbs(worktreeID), "primary")
}

func scmRelatedDirAbs(worktreeID string) string {
	return filepath.Join(scmJobContainerAbs(worktreeID), "related")
}

func scmRelatedRepoAbs(worktreeID, fullName string) string {
	return filepath.Join(scmRelatedDirAbs(worktreeID), sanitizeRelatedRepoDir(fullName))
}

// relatedRepoPathLayout returns the on-disk relative layout used in honesty/docs/tests.
func relatedRepoPathLayout(worktreeID, fullName string) string {
	id := sanitizeWorktreeID(worktreeID)
	return filepath.Join(id, "related", sanitizeRelatedRepoDir(fullName))
}

var githubRepoFullNameRe = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\b`)

// resolveRelatedReposForJob collects sibling repos from context links, applied
// contexts, PR body mentions, and optional mid-review discoveries — capped.
func resolveRelatedReposForJob(job *scmJob, applied appliedReviewContexts, prBody string, extra []string, already []string) []string {
	if job == nil {
		return nil
	}
	primary := strings.TrimSpace(job.RepoFullName)
	seen := map[string]struct{}{}
	if primary != "" {
		seen[strings.ToLower(primary)] = struct{}{}
	}
	for _, a := range already {
		a = strings.TrimSpace(a)
		if a != "" {
			seen[strings.ToLower(a)] = struct{}{}
		}
	}
	out := []string{}
	add := func(name, _ string) {
		name = strings.TrimSpace(name)
		if name == "" || name == "*" {
			return
		}
		owner, repo := splitOwnerRepo(name)
		if owner == "" || repo == "" || strings.Contains(repo, " ") {
			return
		}
		// Skip obvious non-repos (URLs fragments, versions).
		if strings.Contains(name, "http") || strings.Count(name, "/") != 1 {
			return
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return
		}
		if len(out) >= opaReviewRelatedMax() {
			return
		}
		seen[key] = struct{}{}
		out = append(out, owner+"/"+repo)
	}

	for _, rc := range applied.Linked {
		add(rc.RepoFullName, "link")
	}
	// Watched repos sharing the link group (even without a context doc).
	if applied.GroupID != "" {
		watchedLive.Range(func(_, v interface{}) bool {
			wr, ok := v.(*opaWatchedRepo)
			if !ok || wr.LinkGroupID != applied.GroupID {
				return true
			}
			add(wr.RepoFullName, "link")
			return true
		})
	}
	for _, rc := range applied.Primary {
		for _, m := range githubRepoFullNameRe.FindAllString(rc.BodyMarkdown, -1) {
			add(m, "context")
		}
	}
	for _, rc := range applied.Linked {
		for _, m := range githubRepoFullNameRe.FindAllString(rc.BodyMarkdown, -1) {
			add(m, "context")
		}
	}
	for _, m := range githubRepoFullNameRe.FindAllString(prBody, -1) {
		add(m, "pr_body")
	}
	for _, e := range extra {
		add(e, "mid_review")
	}
	sort.Strings(out)
	return out
}

// extractRelatedReposFromText pulls owner/repo mentions from synthesis/findings text.
func extractRelatedReposFromText(texts ...string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, t := range texts {
		for _, m := range githubRepoFullNameRe.FindAllString(t, -1) {
			owner, repo := splitOwnerRepo(m)
			if owner == "" || repo == "" {
				continue
			}
			name := owner + "/" + repo
			key := strings.ToLower(name)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

// prepareRelatedCheckouts shallow-clones related repos under job related/.
func prepareRelatedCheckouts(c *opaConnector, worktreeID string, repos []string, sourceByRepo map[string]string) []relatedCheckout {
	out := []relatedCheckout{}
	if worktreeID == "" || len(repos) == 0 {
		return out
	}
	max := opaReviewRelatedMax()
	_ = os.MkdirAll(scmRelatedDirAbs(worktreeID), 0o755)
	for _, fullName := range repos {
		if len(out) >= max {
			break
		}
		fullName = strings.TrimSpace(fullName)
		if fullName == "" {
			continue
		}
		src := "link"
		if sourceByRepo != nil {
			if s := sourceByRepo[strings.ToLower(fullName)]; s != "" {
				src = s
			}
		}
		dest := scmRelatedRepoAbs(worktreeID, fullName)
		rc := relatedCheckout{RepoFullName: fullName, Path: dest, Source: src}
		if st, err := os.Stat(filepath.Join(dest, ".git")); err == nil && st != nil {
			rc.SHA = gitRevParse(dest)
			out = append(out, rc)
			continue
		}
		_ = os.RemoveAll(dest)
		if err := shallowCloneRelated(c, fullName, dest); err != nil {
			rc.Error = truncateStr(err.Error(), 200)
			out = append(out, rc)
			continue
		}
		rc.SHA = gitRevParse(dest)
		out = append(out, rc)
	}
	return out
}

func shallowCloneRelated(c *opaConnector, fullName, dest string) error {
	if githubUseMockAPI(c) || c == nil || (c.TokenRef == "" && c.InstallationID == "") {
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return err
		}
		_ = os.WriteFile(filepath.Join(dest, "README.md"), []byte("# mock related: "+fullName+"\n"), 0o644)
		init := exec.Command("git", "init")
		init.Dir = dest
		_ = init.Run()
		_ = exec.Command("git", "-C", dest, "config", "user.email", "opa@localhost").Run()
		_ = exec.Command("git", "-C", dest, "config", "user.name", "OPA").Run()
		_ = exec.Command("git", "-C", dest, "add", "-A").Run()
		_ = exec.Command("git", "-C", dest, "commit", "-m", "mock related", "--allow-empty").Run()
		return nil
	}
	tok, err := githubAccessToken(c)
	if err != nil {
		return err
	}
	askEnv, cleanup, aerr := gitAskPassEnv(tok)
	if aerr != nil {
		return aerr
	}
	defer cleanup()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	cloneURL := fmt.Sprintf("https://github.com/%s.git", fullName)
	cmd := exec.Command("git", "clone", "--depth", "50", "--single-branch", cloneURL, dest)
	cmd.Env = askEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("related clone %s: %v (%s)", fullName, err, truncateStr(string(out), 200))
	}
	return nil
}

func formatRelatedCheckoutsForPrompt(related []relatedCheckout) string {
	ok := []relatedCheckout{}
	for _, r := range related {
		if r.Error == "" && r.Path != "" {
			ok = append(ok, r)
		}
	}
	if len(ok) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Related checkouts\n\n")
	b.WriteString("Sibling clones for cross-repo context (read files here when contracts/APIs/shared packages matter). Findings must still cite paths in the **primary** PR checkout.\n\n")
	for _, r := range ok {
		sha := r.SHA
		if sha == "" {
			sha = "—"
		}
		fmt.Fprintf(&b, "- `%s` → `%s` (sha `%s`, source=%s)\n", r.RepoFullName, r.Path, truncateStr(sha, 12), r.Source)
	}
	b.WriteString("\n")
	return b.String()
}

func relatedCheckoutsFromJobSummary(job *scmJob) []relatedCheckout {
	if job == nil || job.Summary == nil {
		return nil
	}
	raw, ok := job.Summary["related_checkouts"]
	if !ok || raw == nil {
		return nil
	}
	switch t := raw.(type) {
	case []relatedCheckout:
		return t
	case []interface{}:
		out := []relatedCheckout{}
		for _, item := range t {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			out = append(out, relatedCheckout{
				RepoFullName: strFromAny(m["repo_full_name"]),
				Path:         strFromAny(m["path"]),
				SHA:          strFromAny(m["sha"]),
				Source:       strFromAny(m["source"]),
				Error:        strFromAny(m["error"]),
			})
		}
		return out
	}
	return nil
}

func relatedRepoNames(related []relatedCheckout) []string {
	out := []string{}
	for _, r := range related {
		if r.RepoFullName != "" {
			out = append(out, r.RepoFullName)
		}
	}
	return out
}
