package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Peer code-delivery surface: push credentials + pull-request create/merge.
//
// Scope `scm:pr` is deliberately narrower than `scm:pm`: it is the only scope
// that can obtain a write-capable git credential, open a pull request, or merge
// one, so a peer that only syncs issues and milestones can never push code.
//
// GitHub App/PAT secrets never leave ORA. The push credential is a short-lived,
// repo-scoped installation token minted per request; ORA does not persist it and
// does not log it.
//
// Required GitHub App permissions:
//
//	push-credentials     — Contents: Read and write, Metadata: Read
//	pull-requests/create — Pull requests: Read and write, Contents: Read and
//	                       write, Metadata: Read
//	pull-requests/merge  — same as create (Contents write to land the merge)
//
// Workflows is never requested, so a delivery cannot touch .github/workflows.
//
// Every failure carries a machine-readable `status` so the caller reports the
// concrete cause instead of degrading into a silent no-op:
//
//	missing_pull_requests_permission — installation cannot write pull requests
//	missing_contents_permission      — installation cannot push commits
//	head_branch_not_found            — the branch was never pushed
//	no_commits_between               — head has nothing base does not have
//	repo_not_found                   — the connector cannot see the repository
//	upstream_error                   — anything else GitHub returned
const (
	prStatusMissingPRPermission       = "missing_pull_requests_permission"
	prStatusMissingContentsPermission = "missing_contents_permission"
	prStatusHeadBranchNotFound        = "head_branch_not_found"
	prStatusNoCommitsBetween          = "no_commits_between"
	prStatusRepoNotFound              = "repo_not_found"
	prStatusUpstreamError             = "upstream_error"
)

// peerPRScope is the single service-JWT scope guarding the delivery surface.
const peerPRScope = "scm:pr"

// pushCredentialTTL mirrors the GitHub installation-token lifetime advertised to
// peers. Peers must treat it as request-scoped and discard it with the workspace.
const pushCredentialTTL = 10 * time.Minute

func registerPeerSCMPRMux(mux *http.ServeMux) {
	mux.HandleFunc("/api/peer/scm/push-credentials", handlePeerPushCredentials)
	mux.HandleFunc("/api/peer/scm/pull-requests/create", handlePeerPullRequestCreate)
	mux.HandleFunc("/api/peer/scm/pull-requests/merge", handlePeerPullRequestMerge)
}

// writePeerPRStatus writes a JSON body with an explicit HTTP status.
func writePeerPRStatus(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// peerDeliveryPreflight refuses the call when the installation demonstrably
// lacks a permission the delivery needs, so the peer is told "grant Contents
// write" rather than being handed a 502 from GitHub. PAT connectors cannot be
// probed: they fall through and surface GitHub's own answer verbatim.
func peerDeliveryPreflight(w http.ResponseWriter, c *opaConnector, wantPullRequests bool) bool {
	if c == nil || c.Kind != "github_app" {
		return true
	}
	if githubUseMockAPI(c) {
		return true
	}
	health := assessInstallationPermHealth(c)
	for _, m := range health.Missing {
		status, message := "", ""
		switch {
		case strings.HasPrefix(m, "contents"):
			status = prStatusMissingContentsPermission
			message = "GitHub App installation is missing Contents write on this repository"
		case wantPullRequests && strings.HasPrefix(m, "pull_requests"):
			status = prStatusMissingPRPermission
			message = "GitHub App installation is missing Pull requests write on this repository"
		default:
			continue
		}
		writePeerPRStatus(w, http.StatusForbidden, map[string]interface{}{
			"ok": false, "status": status, "error": message,
			"missing": health.Missing, "granted": health.Granted,
			"note": "Grant Contents: Read and write and Pull requests: Read and write on the GitHub App, then re-accept the installation permissions.",
		})
		return false
	}
	return true
}

// peerPullRequestError maps a PR failure onto an honest status + HTTP code.
func peerPullRequestError(w http.ResponseWriter, c *opaConnector, err error) {
	var apiErr *githubPullAPIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.NoCommits():
			writePeerPRStatus(w, http.StatusUnprocessableEntity, map[string]interface{}{
				"ok": false, "status": prStatusNoCommitsBetween,
				"error":  "the head branch has no commits the base branch does not already contain",
				"detail": apiErr.Error(),
			})
			return
		case apiErr.HeadMissing():
			writePeerPRStatus(w, http.StatusUnprocessableEntity, map[string]interface{}{
				"ok": false, "status": prStatusHeadBranchNotFound,
				"error":  "the head branch does not exist on the remote — push it before opening a pull request",
				"detail": apiErr.Error(),
			})
			return
		case apiErr.NotFound():
			writePeerPRStatus(w, http.StatusNotFound, map[string]interface{}{
				"ok": false, "status": prStatusRepoNotFound,
				"error":  "the repository is not reachable with this connector",
				"detail": apiErr.Error(),
			})
			return
		case apiErr.Forbidden():
			payload := map[string]interface{}{
				"ok": false, "status": prStatusMissingPRPermission,
				"error":  "GitHub refused the pull-request call for this connector",
				"detail": apiErr.Error(),
				"note":   "Grant Pull requests: Read and write plus Contents: Read and write on the GitHub App (or repo scope on a PAT), then retry.",
			}
			if c != nil && c.Kind == "github_app" && !githubUseMockAPI(c) {
				h := assessInstallationPermHealth(c)
				payload["missing"] = h.Missing
				payload["granted"] = h.Granted
			}
			writePeerPRStatus(w, http.StatusForbidden, payload)
			return
		case apiErr.Unprocessable():
			writePeerPRStatus(w, http.StatusUnprocessableEntity, map[string]interface{}{
				"ok": false, "status": prStatusUpstreamError,
				"error": "GitHub rejected the pull request", "detail": apiErr.Error(),
			})
			return
		}
	}
	writePeerPRStatus(w, http.StatusBadGateway, map[string]interface{}{
		"ok": false, "status": prStatusUpstreamError, "error": err.Error(),
	})
}

// peerDeliveryRepo decodes the connector + owner/repo shared by both endpoints.
func peerDeliveryRepo(w http.ResponseWriter, claims *peerSCMClaims, connectorID, repoFullName string) (*opaConnector, string, string, bool) {
	c := peerResolveConnector(w, claims, connectorID)
	if c == nil {
		return nil, "", "", false
	}
	owner, repo, ok := peerOwnerRepo(repoFullName)
	if !ok {
		http.Error(w, "repo_full_name (owner/repo) required", 400)
		return nil, "", "", false
	}
	return c, owner, repo, true
}

// handlePeerPushCredentials mints a short-lived Contents-write credential so a
// peer can push a delivery branch. The token is returned once and never stored.
func handlePeerPushCredentials(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, peerPRScope)
	if !ok {
		return
	}
	var body struct {
		ConnectorID  string `json:"connector_id"`
		RepoFullName string `json:"repo_full_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c, _, _, ok := peerDeliveryRepo(w, claims, body.ConnectorID, body.RepoFullName)
	if !ok {
		return
	}
	if !peerDeliveryPreflight(w, c, false) {
		return
	}
	if _, err := authorizeGitHubWrite(c); err != nil {
		writePeerPRStatus(w, http.StatusForbidden, map[string]interface{}{
			"ok": false, "status": prStatusMissingContentsPermission,
			"error": "this connector is not authorized for GitHub writes: " + err.Error(),
		})
		return
	}

	repoFullName := strings.TrimSpace(body.RepoFullName)
	out := map[string]interface{}{
		"ok":             true,
		"connector_id":   c.ID,
		"repo_full_name": repoFullName,
		"clone_url":      "https://github.com/" + repoFullName + ".git",
		"permissions":    githubPermsPush(),
		"expires_at":     time.Now().UTC().Add(pushCredentialTTL).Format(time.RFC3339),
		"note":           "Short-lived Contents-write credential for one delivery push. Do not persist or log it. Prefer GIT_ASKPASS over embedding it in a URL.",
	}
	if githubUseMockAPI(c) {
		// Smoke mock: hand back a token that cannot authenticate anywhere, and
		// label it, so a mocked run can never be mistaken for a real push.
		out["token"] = "mock-push-token-not-usable"
		out["mock"] = true
		writeJSON(w, out)
		return
	}
	tok, err := githubAccessTokenFor(c, repoFullName, githubPermsPush())
	if err != nil {
		writePeerPRStatus(w, http.StatusBadGateway, map[string]interface{}{
			"ok": false, "status": prStatusUpstreamError,
			"error": "push credentials unavailable: " + err.Error(),
		})
		return
	}
	out["token"] = tok
	writeJSON(w, out)
}

// handlePeerPullRequestCreate opens the delivery pull request. An already-open
// pull request for the same head is reported as already_existed=true rather than
// as a failure, so re-delivering a branch converges instead of erroring.
func handlePeerPullRequestCreate(w http.ResponseWriter, r *http.Request) {
	claims, ok := peerSCMAuth(w, r, peerPRScope)
	if !ok {
		return
	}
	var body struct {
		ConnectorID  string `json:"connector_id"`
		RepoFullName string `json:"repo_full_name"`
		Title        string `json:"title"`
		Body         string `json:"body"`
		Head         string `json:"head"`
		Base         string `json:"base"`
		Draft        bool   `json:"draft"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c, owner, repo, ok := peerDeliveryRepo(w, claims, body.ConnectorID, body.RepoFullName)
	if !ok {
		return
	}
	body.Title = strings.TrimSpace(body.Title)
	body.Head = strings.TrimSpace(body.Head)
	body.Base = strings.TrimSpace(body.Base)
	if body.Title == "" {
		http.Error(w, "title required", 400)
		return
	}
	if body.Head == "" || body.Base == "" {
		http.Error(w, "head and base required", 400)
		return
	}
	if body.Head == body.Base {
		writePeerPRStatus(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"ok": false, "status": prStatusNoCommitsBetween,
			"error": "head and base are the same branch (" + body.Head + ")",
		})
		return
	}
	if !peerDeliveryPreflight(w, c, true) {
		return
	}

	pull, existed, err := githubOpenPullRequest(c, owner, repo,
		body.Title, body.Body, body.Head, body.Base, body.Draft)
	if err != nil {
		peerPullRequestError(w, c, err)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "repo_full_name": body.RepoFullName,
		"already_existed": existed, "pull_request": pull,
	})
}

// handlePeerPullRequestMerge merges an open delivery pull request. OPM autopilot
// calls this after review PASS; without it the peer surface returns Go's plain
// "404 page not found" and the task is left for a human.
func handlePeerPullRequestMerge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := peerSCMAuth(w, r, peerPRScope)
	if !ok {
		return
	}
	var body struct {
		ConnectorID  string `json:"connector_id"`
		RepoFullName string `json:"repo_full_name"`
		Number       int    `json:"number"`
		MergeMethod  string `json:"merge_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	c, owner, repo, ok := peerDeliveryRepo(w, claims, body.ConnectorID, body.RepoFullName)
	if !ok {
		return
	}
	if body.Number <= 0 {
		http.Error(w, "number required", 400)
		return
	}
	if !peerDeliveryPreflight(w, c, true) {
		return
	}

	pull, err := githubMergePullRequest(c, owner, repo, body.Number, body.MergeMethod)
	if err != nil {
		peerPullRequestError(w, c, err)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "connector_id": c.ID, "repo_full_name": body.RepoFullName,
		"pull_request": pull,
	})
}
