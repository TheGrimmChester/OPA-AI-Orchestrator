package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Wave 34 — per-repo reviewer contexts + link groups for multi-context AI packs.

const (
	reviewCtxPrimaryCap = 8000
	reviewCtxLinkedCap  = 2000
	reviewCtxLinkedMax  = 6000
	reviewCtxOrgCap     = 3000
)

var reviewContextLive sync.Map // id -> *opaReviewContext

type opaReviewContext struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organization_id"`
	ProjectID      string   `json:"project_id"`
	ConnectorID    string   `json:"connector_id"`
	RepoFullName   string   `json:"repo_full_name"` // "*" = org-level
	Title          string   `json:"title"`
	BodyMarkdown   string   `json:"body_markdown"`
	TagsJSON       string   `json:"tags_json"`
	LinkGroupID    string   `json:"link_group_id"`
	Source         string   `json:"source"` // manual | cursor | draft | learned
	Kind           string   `json:"kind,omitempty"`   // must | should | note
	Status         string   `json:"status,omitempty"` // active | candidate | rejected
	UpdatedAt      string   `json:"updated_at"`
	CreatedAt      string   `json:"created_at"`
	Deleted        bool     `json:"deleted,omitempty"`
}

type appliedReviewContexts struct {
	Primary []opaReviewContext `json:"primary"`
	Linked  []opaReviewContext `json:"linked"`
	Org     []opaReviewContext `json:"org"`
	GroupID string             `json:"link_group_id,omitempty"`
}

func handleReviewContexts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleReviewContextsList(w, r)
	case http.MethodPost:
		handleReviewContextCreate(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleReviewContextsList(w http.ResponseWriter, r *http.Request) {
	repo := strings.TrimSpace(r.URL.Query().Get("repo_full_name"))
	group := strings.TrimSpace(r.URL.Query().Get("link_group_id"))
	forRepo := strings.TrimSpace(r.URL.Query().Get("for_repo")) // expand primary+linked+org
	if forRepo != "" {
		ctx, _ := ExtractTenantContext(r, queryClient)
		org, proj := ctx.WriteTenant()
		applied := resolveReviewContextsForRepo(org, proj, forRepo)
		writeJSON(w, map[string]interface{}{
			"for_repo": forRepo,
			"applied":  applied,
			"summary":  summarizeAppliedContexts(applied),
		})
		return
	}
	list := listReviewContexts(repo, group)
	writeJSON(w, map[string]interface{}{"contexts": list})
}

func handleReviewContextCreate(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	var body struct {
		ConnectorID  string   `json:"connector_id"`
		RepoFullName string   `json:"repo_full_name"`
		Title        string   `json:"title"`
		BodyMarkdown string   `json:"body_markdown"`
		Tags         []string `json:"tags"`
		LinkGroupID  string   `json:"link_group_id"`
		Source       string   `json:"source"`
		Kind         string   `json:"kind"`
		Status       string   `json:"status"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	repo := strings.TrimSpace(nz(body.RepoFullName, "*"))
	title := strings.TrimSpace(body.Title)
	if title == "" {
		http.Error(w, "title required", 400)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	if body.ConnectorID != "" {
		if c := getOrHydrateConnector(body.ConnectorID); c != nil {
			org, proj = c.OrganizationID, c.ProjectID
		}
	}
	tagsJSON, _ := json.Marshal(body.Tags)
	if body.Tags == nil {
		tagsJSON = []byte("[]")
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	id := loadID("rctx", org, proj, repo, title, newRandomHex(4))
	rc := &opaReviewContext{
		ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: body.ConnectorID,
		RepoFullName: repo, Title: title, BodyMarkdown: body.BodyMarkdown,
		TagsJSON: string(tagsJSON), LinkGroupID: strings.TrimSpace(body.LinkGroupID),
		Source: nz(body.Source, "manual"), CreatedAt: now, UpdatedAt: now,
	}
	applyRuleFieldsFromCreate(rc, body.Kind, body.Status)
	// Inherit link group from watched repo when unset.
	if rc.LinkGroupID == "" && repo != "*" {
		rc.LinkGroupID = linkGroupForRepo(repo)
	}
	reviewContextLive.Store(id, rc)
	persistReviewContext(rc)
	writeJSON(w, map[string]interface{}{"ok": true, "context": rc})
}

func handleReviewContextSub(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scm/contexts/")
	path = strings.Trim(path, "/")
	if path == "" || path == "generate" {
		http.Error(w, "not found", 404)
		return
	}
	id := strings.Split(path, "/")[0]
	rest := ""
	if parts := strings.SplitN(path, "/", 2); len(parts) == 2 {
		rest = parts[1]
	}
	if rest != "" && maybeHandleRuleAction(w, r, id, rest) {
		return
	}
	rc := getReviewContext(id)
	if rc == nil || rc.Deleted {
		http.Error(w, "not found", 404)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"context": rc})
	case http.MethodPatch, http.MethodPut:
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		var body struct {
			Title        *string  `json:"title"`
			BodyMarkdown *string  `json:"body_markdown"`
			Tags         []string `json:"tags"`
			LinkGroupID  *string  `json:"link_group_id"`
			RepoFullName *string  `json:"repo_full_name"`
			Source       *string  `json:"source"`
		}
		if json.Unmarshal(raw, &body) != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if body.Title != nil {
			rc.Title = strings.TrimSpace(*body.Title)
		}
		if body.BodyMarkdown != nil {
			rc.BodyMarkdown = *body.BodyMarkdown
		}
		if body.Tags != nil {
			tj, _ := json.Marshal(body.Tags)
			rc.TagsJSON = string(tj)
		}
		if body.LinkGroupID != nil {
			rc.LinkGroupID = strings.TrimSpace(*body.LinkGroupID)
		}
		if body.RepoFullName != nil {
			rc.RepoFullName = strings.TrimSpace(*body.RepoFullName)
		}
		if body.Source != nil {
			rc.Source = strings.TrimSpace(*body.Source)
		}
		decodeRulePatchExtras(raw, rc)
		rc.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
		persistReviewContext(rc)
		writeJSON(w, map[string]interface{}{"ok": true, "context": rc})
	case http.MethodDelete:
		rc.Deleted = true
		rc.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
		persistReviewContext(rc)
		reviewContextLive.Delete(id)
		writeJSON(w, map[string]interface{}{"ok": true, "deleted": id})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// PUT /api/scm/context-links — link watched repos into a shared group for multi-context packs.
func handleContextLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		RepoFullNames []string `json:"repo_full_names"`
		LinkGroupID   string   `json:"link_group_id"`
		Clear         bool     `json:"clear"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if len(body.RepoFullNames) == 0 {
		http.Error(w, "repo_full_names required", 400)
		return
	}
	groupID := strings.TrimSpace(body.LinkGroupID)
	if body.Clear {
		groupID = ""
	} else if groupID == "" {
		groupID = "lg-" + newRandomHex(8)
	}
	updated := []map[string]interface{}{}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, repo := range body.RepoFullNames {
		repo = strings.TrimSpace(repo)
		if repo == "" {
			continue
		}
		n := 0
		watchedLive.Range(func(_, v interface{}) bool {
			wr, ok := v.(*opaWatchedRepo)
			if !ok || wr.RepoFullName != repo {
				return true
			}
			wr.LinkGroupID = groupID
			wr.UpdatedAt = now
			persistWatched(wr)
			n++
			updated = append(updated, map[string]interface{}{
				"repo_full_name": wr.RepoFullName, "connector_id": wr.ConnectorID,
				"link_group_id": wr.LinkGroupID,
			})
			return true
		})
		_ = n
		// Also stamp matching review contexts.
		reviewContextLive.Range(func(_, v interface{}) bool {
			rc, ok := v.(*opaReviewContext)
			if !ok || rc.Deleted || rc.RepoFullName != repo {
				return true
			}
			rc.LinkGroupID = groupID
			rc.UpdatedAt = now
			persistReviewContext(rc)
			return true
		})
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "link_group_id": groupID, "repos": updated, "cleared": body.Clear,
	})
}

func handleReviewContextGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		RepoFullName string `json:"repo_full_name"`
		ConnectorID  string `json:"connector_id"`
		PRNumber     int    `json:"pr_number"`
		SaveDraft    bool   `json:"save_draft"`
		Title        string `json:"title"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	repo := strings.TrimSpace(body.RepoFullName)
	if repo == "" {
		http.Error(w, "repo_full_name required", 400)
		return
	}
	if envOr("SKIP_CURSOR_AI", "0") == "1" {
		writeJSON(w, map[string]interface{}{
			"ok": true, "status": "skipped", "reason": "SKIP_CURSOR_AI=1",
			"draft": map[string]interface{}{
				"title":         nz(body.Title, "Generated reviewer context"),
				"body_markdown": "",
				"source":        "skipped",
			},
			"honesty": "SKIP_CURSOR_AI=1 — no AI agent call; empty draft returned.",
		})
		return
	}
	a := actorFromRequest(r)
	ctxTenant, _ := ExtractTenantContext(r, queryClient)
	if ctxTenant == nil {
		ctxTenant = &TenantContext{}
	}
	orgKey, projKey := a.OrganizationID, a.ProjectID
	if orgKey == "" {
		orgKey, projKey = ctxTenant.WriteTenant()
	} else if projKey == "" || projKey == tenantAll {
		_, projKey = ctxTenant.WriteTenant()
	}
	userID := strings.TrimSpace(a.Username)
	key := resolveCursorAPIKey(orgKey, projKey, userID)
	if key == "" {
		writeJSON(w, map[string]interface{}{
			"ok": true, "status": "skipped", "reason": "cli_agent_api_key_not_set",
			"draft": map[string]interface{}{
				"title":         nz(body.Title, "Generated reviewer context"),
				"body_markdown": "",
				"source":        "skipped",
			},
			"honesty": "No CLI agent API key for this user/org — save one under Account (personal or org). Resolution is user → org → fail closed (never admin/env).",
		})
		return
	}

	var conn *opaConnector
	if body.ConnectorID != "" {
		conn = getOrHydrateConnector(body.ConnectorID)
	}
	if conn == nil {
		if wr, c := findWatched(repo); c != nil {
			conn = c
			_ = wr
		}
	}
	owner, name := splitOwnerRepo(repo)
	wtID := "ctxgen-" + newRandomHex(8)
	absWT, _, wtMeta, wtErr := prepareSCMWorktree(conn, repo, "", body.PRNumber, wtID)
	useMock := githubUseMockAPI(conn) || conn == nil || (conn != nil && conn.TokenRef == "" && conn.InstallationID == "")
	if wtErr != nil && !useMock {
		writeJSON(w, map[string]interface{}{
			"ok": false, "status": "error",
			"error":   "git checkout failed: " + wtErr.Error(),
			"honesty": "Context generate fail-closed on checkout with real credentials (GIT_ASKPASS; no token in URL).",
			"worktree": wtMeta,
		})
		if absWT != "" {
			removeSCMWorktree(absWT, repo)
		}
		return
	}
	seed := gatherRepoContextSeed(conn, owner, name, body.PRNumber)
	if absWT != "" {
		// Prefer on-disk README/ARCHITECTURE from the worktree when present.
		seed = gatherWorktreeSeed(absWT, seed)
	}
	markdown, usage, genErr := runCursorContextGenerate(key, repo, seed, absWT)
	checkoutPath := absWT
	resolvedSHA := ""
	if wtMeta != nil {
		if rs, _ := wtMeta["resolved_sha"].(string); rs != "" {
			resolvedSHA = rs
		}
	}
	_ = wtErr
	defer func() {
		if absWT != "" {
			removeSCMWorktree(absWT, repo)
		}
	}()
	status := "generated"
	if genErr != nil {
		status = "heuristic"
		markdown = heuristicReviewerContext(repo, seed)
	}
	if designSec := generateDesignEnforcementSection(absWT, seed); designSec != "" {
		if !strings.Contains(markdown, "Design enforcement") {
			markdown = strings.TrimSpace(markdown) + "\n\n" + designSec
		}
	}
	title := nz(body.Title, "Reviewer context — "+repo)
	tags := []string{"generated"}
	if worktreeLooksFrontend(absWT) || strings.Contains(strings.ToLower(markdown), "design enforcement") {
		tags = append(tags, "design", "ui")
	}
	tagsJSON, _ := json.Marshal(tags)
	draft := map[string]interface{}{
		"title": title, "body_markdown": markdown, "source": "cursor",
		"repo_full_name": repo, "connector_id": body.ConnectorID, "tags": tags,
	}
	out := map[string]interface{}{
		"ok": true, "status": status, "draft": draft, "cursor_usage": truncateStr(usage, 1500),
		"checkout_path": checkoutPath, "resolved_sha": resolvedSHA,
	}
	if genErr != nil {
		out["generate_error"] = genErr.Error()
		out["honesty"] = "AI agent failed or unparseable — heuristic draft from README/ARCHITECTURE (+ design section when frontend)."
	}
	if body.SaveDraft {
		ctx, _ := ExtractTenantContext(r, queryClient)
		org, proj := ctx.WriteTenant()
		if conn != nil {
			org, proj = conn.OrganizationID, conn.ProjectID
		}
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		id := loadID("rctx", org, proj, repo, "gen", newRandomHex(4))
		rc := &opaReviewContext{
			ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: body.ConnectorID,
			RepoFullName: repo, Title: title, BodyMarkdown: markdown,
			TagsJSON: string(tagsJSON), LinkGroupID: linkGroupForRepo(repo),
			Source: "cursor", CreatedAt: now, UpdatedAt: now,
		}
		reviewContextLive.Store(id, rc)
		persistReviewContext(rc)
		out["context"] = rc
		out["saved"] = true
	}
	writeJSON(w, out)
}

func gatherRepoContextSeed(conn *opaConnector, owner, repo string, pr int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Repo: %s/%s\n\n", owner, repo)
	for _, path := range []string{"README.md", "ARCHITECTURE.md", "docs/ARCHITECTURE.md", "CONTRIBUTING.md", "SECURITY.md"} {
		if txt, err := githubGetRepoFile(conn, owner, repo, path); err == nil && txt != "" {
			fmt.Fprintf(&b, "## File: %s\n%s\n\n", path, truncateStr(txt, 4000))
		}
	}
	if pulls, err := githubListPulls(conn, owner, repo); err == nil && len(pulls) > 0 {
		b.WriteString("## Recent open PRs\n")
		for i, p := range pulls {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&b, "- #%v %v\n", p["number"], p["title"])
		}
		b.WriteString("\n")
	}
	if pr > 0 {
		if meta, err := githubGetPull(conn, owner, repo, pr); err == nil && meta != nil {
			fmt.Fprintf(&b, "## Focus PR #%d\nTitle: %s\n%s\n\n", meta.Number, meta.Title, truncateStr(meta.Body, 1500))
		}
	}
	return b.String()
}

func gatherWorktreeSeed(absRoot, apiSeed string) string {
	var b strings.Builder
	b.WriteString(apiSeed)
	b.WriteString("\n## Worktree files\n")
	for _, path := range []string{"README.md", "ARCHITECTURE.md", "docs/ARCHITECTURE.md", "CONTRIBUTING.md", "SECURITY.md"} {
		p := filepath.Join(absRoot, path)
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "### %s\n%s\n\n", path, truncateStr(string(raw), 4000))
	}
	return b.String()
}

func runCursorContextGenerate(apiKey, repo, seed, worktreeAbs string) (string, string, error) {
	promptPath := filepath.Join(os.TempDir(), "opa-ctx-gen-"+newRandomHex(6)+".md")
	wtHint := worktreeAbs
	if wtHint == "" {
		wtHint = "(no local worktree — seed from GitHub API only)"
	}
	brief := fmt.Sprintf(`# Generate OPA reviewer context

You are drafting a **senior-engineer reviewer context** for repository %s.

Worktree path: %s
Working directory is this full git tree under OPA_REVIEW_TMP. Explore the tree — architecture, modules, callers, interfaces, tests, risk areas — **do not skim README alone**.

Output ONLY markdown (no JSON fences) using these exact section headings (senior-engineer template):

## System
Product/service purpose and role in the stack.

## PR intent
What kinds of changes are typical; what "done" looks like.

## Scope
Modules/directories that matter for this repo.

## Important invariants
Rules that must not break (authz, tenancy, data integrity, API contracts).

## Risk areas
Auth, secrets, migrations, CI/CD, API compatibility, performance, hot-path complexity (nested loops, N+1), rollout, common footguns.

## Testing context
What tests must prove; known gaps; where tests live.

## Operational
Deploy impact, feature flags, rollout/rollback notes.

If this is a frontend/UI repo, also include:

## Design enforcement
Document findable tokens, components/ui primitives, forbidden one-off patterns, and required citations — only what exists in the worktree; never invent a brand system.

Do not commit or push. Do not invent vendor product names.

## Seed (hints only — verify against the tree)
%s
`, repo, wtHint, truncateStr(seed, 14000))
	_ = os.WriteFile(promptPath, []byte(brief), 0o600)
	defer os.Remove(promptPath)

	agentBin, model := "", ""
	force := false
	_, agentBin, model, force = resolveCLICursorConfig("", "")
	args := []string{"-p", "--trust", "--output-format", "text", "--model", model}
	if force {
		args = append(args, "--force")
	}
	args = append(args, fmt.Sprintf(
		"Working directory is the full repo checkout at %s. Explore architecture, invariants, tests, and risk areas in this tree — do not limit yourself to README. Read %s and write the senior-engineer reviewer context markdown with the required sections.",
		wtHint, promptPath,
	))
	_ = agentBin
	out, err := launchAgentSandbox(agentLaunchSpec{
		Phase: jobPhaseContext, Args: args, Dir: worktreeAbs, WorktreeRoot: worktreeAbs,
		APIKey: apiKey, Timeout: 900 * time.Second,
	})
	usage := string(out)
	if err != nil {
		return "", usage, err
	}
	md := strings.TrimSpace(usage)
	// Strip accidental fence wrappers
	if strings.HasPrefix(md, "```") {
		md = strings.TrimPrefix(md, "```markdown")
		md = strings.TrimPrefix(md, "```md")
		md = strings.TrimPrefix(md, "```")
		if idx := strings.LastIndex(md, "```"); idx >= 0 {
			md = md[:idx]
		}
		md = strings.TrimSpace(md)
	}
	if len(md) < 40 {
		return "", usage, fmt.Errorf("empty or tiny agent output")
	}
	return md, usage, nil
}

func heuristicReviewerContext(repo, seed string) string {
	base := defaultReviewContextTemplate(repo)
	return base + fmt.Sprintf(`
## Seed excerpt (from worktree docs)
%s
`, truncateStr(seed, 2500))
}

// runOPAReviewUnderstandingPass is Step 1 for larger/riskier diffs: data flow,
// control flow, and assumptions — no adversarial findings yet.
func runOPAReviewUnderstandingPass(job *scmJob, key, agentBin string, baseArgs []string, checkoutRoot, securityRunID, service string, applied appliedReviewContexts, diff string, mcpPlan reviewMCPPlan) string {
	var b strings.Builder
	b.WriteString("# OPA Review — Step 1 understanding pass (large/risky PR)\n\n")
	b.WriteString(opaReviewRolePreamble)
	b.WriteString("This is **Step 1 only** (no findings yet). Build understanding: data flow, control flow, assumptions, what must not break, and risk hotspots. Do not invent defects here.\n\n")
	writeOPAReviewContextFields(&b, job, filterContextsForUI(applied, diffTouchesUI(diff)), opaReviewScopeFromDiff(diff), false)
	fmt.Fprintf(&b, "## Diff (truncated)\n```\n%s\n```\n\n", truncateStr(diff, 20000))
	b.WriteString("## Required JSON\n{\"understanding\":[\"data/control flow…\",\"assumptions…\",\"risk hotspots…\"],\"summary\":\"…\",\"verdict\":\"needs_context\",\"findings\":[]}\n")
	promptPath := filepath.Join(os.TempDir(), fmt.Sprintf("opa-review-understand-%s.md", job.ID))
	_ = os.WriteFile(promptPath, []byte(b.String()), 0o600)
	defer os.Remove(promptPath)
	prompt := fmt.Sprintf("%s Full PR tree at %s. Explore surrounding code as needed. Read %s. Output ONLY JSON with understanding (3-5 bullets covering data flow, control flow, assumptions) and summary. No findings yet — Step 2 will review aggressively.",
		opaReviewCompactScaffold, checkoutRoot, promptPath)
	args := append(append([]string{}, baseArgs...), prompt)
	_ = agentBin
	parent := context.Background()
	if job != nil {
		parent = scmJobContext(job.ID)
	}
	out, err := launchAgentSandbox(agentLaunchSpec{
		Phase: jobPhaseContext, Args: args, Dir: checkoutRoot, WorktreeRoot: checkoutRoot,
		APIKey: key, Parent: parent,
	})
	if err != nil {
		return ""
	}
	parsed := parseAIReviewJSON(string(out))
	return parsed.Summary
}

func getReviewContext(id string) *opaReviewContext {
	if v, ok := reviewContextLive.Load(id); ok {
		if rc, ok := v.(*opaReviewContext); ok {
			return rc
		}
	}
	if queryClient == nil || id == "" {
		return nil
	}
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT id, organization_id, project_id, connector_id, repo_full_name, title, body_markdown,
		       tags_json, link_group_id, source, updated_at, created_at, deleted
		FROM opa.review_contexts WHERE id = '%s' ORDER BY updated_at DESC LIMIT 1`, escapeSQL(id)))
	if err != nil || len(rows) == 0 {
		return nil
	}
	rc := reviewContextFromRow(rows[0])
	if rc != nil && !rc.Deleted {
		reviewContextLive.Store(rc.ID, rc)
	}
	return rc
}

func listReviewContexts(repoFilter, groupFilter string) []opaReviewContext {
	seen := map[string]struct{}{}
	out := []opaReviewContext{}
	reviewContextLive.Range(func(_, v interface{}) bool {
		rc, ok := v.(*opaReviewContext)
		if !ok || rc.Deleted {
			return true
		}
		if repoFilter != "" && rc.RepoFullName != repoFilter {
			return true
		}
		if groupFilter != "" && rc.LinkGroupID != groupFilter {
			return true
		}
		out = append(out, *rc)
		seen[rc.ID] = struct{}{}
		return true
	})
	if queryClient != nil {
		q := `SELECT id, organization_id, project_id, connector_id, repo_full_name, title, body_markdown,
		             tags_json, link_group_id, source, updated_at, created_at, deleted
		      FROM opa.review_contexts WHERE deleted = 0`
		if repoFilter != "" {
			q += fmt.Sprintf(` AND repo_full_name = '%s'`, escapeSQL(repoFilter))
		}
		if groupFilter != "" {
			q += fmt.Sprintf(` AND link_group_id = '%s'`, escapeSQL(groupFilter))
		}
		q += ` ORDER BY updated_at DESC LIMIT 200`
		if rows, err := queryClient.Query(q); err == nil {
			for _, row := range rows {
				rc := reviewContextFromRow(row)
				if rc == nil || rc.Deleted {
					continue
				}
				if _, ok := seen[rc.ID]; ok {
					continue
				}
				out = append(out, *rc)
				reviewContextLive.Store(rc.ID, rc)
			}
		}
	}
	return out
}

func reviewContextFromRow(row map[string]interface{}) *opaReviewContext {
	if row == nil {
		return nil
	}
	str := func(k string) string {
		if s, ok := row[k].(string); ok {
			return s
		}
		return ""
	}
	id := str("id")
	if id == "" {
		return nil
	}
	del := false
	switch v := row["deleted"].(type) {
	case uint8:
		del = v != 0
	case int64:
		del = v != 0
	case float64:
		del = v != 0
	case bool:
		del = v
	}
	return &opaReviewContext{
		ID: id, OrganizationID: str("organization_id"), ProjectID: str("project_id"),
		ConnectorID: str("connector_id"), RepoFullName: str("repo_full_name"),
		Title: str("title"), BodyMarkdown: str("body_markdown"), TagsJSON: nz(str("tags_json"), "[]"),
		LinkGroupID: str("link_group_id"), Source: nz(str("source"), "manual"),
		Kind: normalizeRuleKind(str("kind")), Status: normalizeRuleStatus(str("status")),
		UpdatedAt: str("updated_at"), CreatedAt: str("created_at"), Deleted: del,
	}
}

func persistReviewContext(rc *opaReviewContext) {
	if writer == nil || rc == nil {
		return
	}
	del := uint8(0)
	if rc.Deleted {
		del = 1
	}
	if rc.Kind == "" {
		rc.Kind = ruleKindNote
	}
	if rc.Status == "" {
		rc.Status = ruleStatusActive
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"id": rc.ID, "organization_id": rc.OrganizationID, "project_id": rc.ProjectID,
		"connector_id": rc.ConnectorID, "repo_full_name": rc.RepoFullName,
		"title": rc.Title, "body_markdown": rc.BodyMarkdown, "tags_json": nz(rc.TagsJSON, "[]"),
		"link_group_id": rc.LinkGroupID, "source": nz(rc.Source, "manual"),
		"kind": rc.Kind, "status": rc.Status,
		"updated_at": rc.UpdatedAt, "created_at": rc.CreatedAt, "deleted": del,
	})
	writer.insertAsync("review_contexts", append(payload, '\n'))
}

func linkGroupForRepo(repo string) string {
	var found string
	watchedLive.Range(func(_, v interface{}) bool {
		wr, ok := v.(*opaWatchedRepo)
		if ok && wr.RepoFullName == repo && wr.LinkGroupID != "" {
			found = wr.LinkGroupID
			return false
		}
		return true
	})
	return found
}

func resolveReviewContextsForRepo(org, proj, repo string) appliedReviewContexts {
	_ = org
	_ = proj
	applied := appliedReviewContexts{
		Primary: []opaReviewContext{}, Linked: []opaReviewContext{}, Org: []opaReviewContext{},
		GroupID: linkGroupForRepo(repo),
	}
	all := listReviewContexts("", "")
	for _, rc := range all {
		if rc.RepoFullName == "*" || rc.RepoFullName == "" {
			applied.Org = append(applied.Org, rc)
			continue
		}
		if rc.RepoFullName == repo {
			applied.Primary = append(applied.Primary, rc)
			continue
		}
		if applied.GroupID != "" && rc.LinkGroupID == applied.GroupID {
			applied.Linked = append(applied.Linked, rc)
		}
	}
	// Also include contexts from other watched repos in the same group that may not have stamped link_group_id on the context yet.
	if applied.GroupID != "" {
		reposInGroup := map[string]struct{}{}
		watchedLive.Range(func(_, v interface{}) bool {
			wr, ok := v.(*opaWatchedRepo)
			if ok && wr.LinkGroupID == applied.GroupID {
				reposInGroup[wr.RepoFullName] = struct{}{}
			}
			return true
		})
		have := map[string]struct{}{}
		for _, rc := range applied.Linked {
			have[rc.ID] = struct{}{}
		}
		for _, rc := range all {
			if _, ok := have[rc.ID]; ok {
				continue
			}
			if rc.RepoFullName == repo || rc.RepoFullName == "*" {
				continue
			}
			if _, ok := reposInGroup[rc.RepoFullName]; ok {
				applied.Linked = append(applied.Linked, rc)
			}
		}
	}
	return applied
}

func summarizeAppliedContexts(a appliedReviewContexts) []map[string]interface{} {
	out := []map[string]interface{}{}
	add := func(role string, rc opaReviewContext) {
		if isDesignContext(rc) {
			role = role + "+design"
		}
		out = append(out, map[string]interface{}{
			"id": rc.ID, "role": role, "repo_full_name": rc.RepoFullName,
			"title": rc.Title, "chars": len(rc.BodyMarkdown), "link_group_id": rc.LinkGroupID,
			"tags": reviewContextTags(rc),
		})
	}
	for _, rc := range a.Primary {
		add("primary", rc)
	}
	for _, rc := range a.Linked {
		add("linked", rc)
	}
	for _, rc := range a.Org {
		add("org", rc)
	}
	return out
}

func formatAppliedContextsForPrompt(a appliedReviewContexts, uiTouched bool) string {
	return formatAppliedContextsForPromptCaps(a, uiTouched, reviewCtxPrimaryCap, reviewCtxLinkedCap, reviewCtxLinkedMax)
}

// formatAppliedContextsForPromptUnit keeps full primary context and shorter linked
// awareness for per-file/independent unit reviews (cross-repo contracts still visible).
func formatAppliedContextsForPromptUnit(a appliedReviewContexts, uiTouched bool) string {
	return formatAppliedContextsForPromptCaps(a, uiTouched, reviewCtxPrimaryCap, 1200, 3600)
}

func formatAppliedContextsForPromptCaps(a appliedReviewContexts, uiTouched bool, primaryCap, linkedPerCap, linkedBudgetMax int) string {
	var b strings.Builder
	b.WriteString("## Reviewer contexts\n\n")
	b.WriteString("Primary contexts are **full** for the PR’s repo. Linked repos are **awareness** (may be size-capped, never omitted).\n\n")
	if uiTouched {
		b.WriteString("UI files changed — design/ui-tagged contexts are prioritized below.\n\n")
	}
	labelPrimary := "this-repo — primary"
	labelLinked := "linked — awareness"
	labelOrg := "org — awareness"
	writeLabeled := func(label string, rc opaReviewContext, body string) {
		tag := label
		if isDesignContext(rc) {
			tag = label + " | design"
		}
		fmt.Fprintf(&b, "### [%s] %s — %s\n%s\n\n", tag, rc.RepoFullName, rc.Title, body)
	}
	// Primary: full (capped only by primaryCap — never dropped).
	for _, rc := range a.Primary {
		body := rc.BodyMarkdown
		if primaryCap > 0 && len(body) > primaryCap {
			body = truncateStr(body, primaryCap)
		}
		writeLabeled(labelPrimary, rc, body)
	}
	linkedBudget := linkedBudgetMax
	for _, rc := range a.Linked {
		stub := fmt.Sprintf("_(awareness stub — size budget exhausted; title retained for cross-repo contracts)_\n\nRepo: `%s`", rc.RepoFullName)
		if linkedBudget <= 0 {
			writeLabeled(labelLinked, rc, stub)
			continue
		}
		chunk := truncateStr(rc.BodyMarkdown, linkedPerCap)
		if len(chunk) > linkedBudget {
			chunk = truncateStr(chunk, linkedBudget)
		}
		if strings.TrimSpace(chunk) == "" {
			chunk = stub
		}
		writeLabeled(labelLinked, rc, chunk)
		linkedBudget -= len(chunk)
	}
	for _, rc := range a.Org {
		writeLabeled(labelOrg, rc, truncateStr(rc.BodyMarkdown, reviewCtxOrgCap))
	}
	return b.String()
}
