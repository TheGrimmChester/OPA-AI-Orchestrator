package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// validateGitHubRepoFullName accepts only owner/repo with safe characters so an
// AI-derived related-repo name cannot become a URL injection into git clone.
var githubRepoFullNameExactRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func validateGitHubRepoFullName(fullName string) error {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return fmt.Errorf("empty repo name")
	}
	if strings.Contains(fullName, "..") || strings.ContainsAny(fullName, " \t\n\r\\\"'`$;&|<>(){}") {
		return fmt.Errorf("invalid repo name characters")
	}
	if !githubRepoFullNameExactRe.MatchString(fullName) {
		return fmt.Errorf("repo name must be owner/repo")
	}
	owner, repo := splitOwnerRepo(fullName)
	if owner == "" || repo == "" || strings.HasSuffix(repo, ".git") {
		return fmt.Errorf("invalid owner/repo")
	}
	// Reject path-like segments that filepath would still accept.
	if filepath.Base(owner) != owner || filepath.Base(repo) != repo {
		return fmt.Errorf("invalid owner/repo path segments")
	}
	return nil
}

func githubHTTPSCloneURL(fullName string) (string, error) {
	if err := validateGitHubRepoFullName(fullName); err != nil {
		return "", err
	}
	return fmt.Sprintf("https://github.com/%s.git", fullName), nil
}
