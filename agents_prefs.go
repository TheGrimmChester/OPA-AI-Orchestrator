package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type triggerMode string

const (
	triggerEveryPush triggerMode = "every_push"
	triggerPROpen    triggerMode = "pr_open"
	triggerOnDemand  triggerMode = "on_demand"
	triggerCron      triggerMode = "cron"
)

// agentPrefs is the resolved (non-tri-state) preference snapshot frozen on a run.
type agentPrefs struct {
	RepositoryRules          bool   `json:"repository_rules"`
	LearnedRules             bool   `json:"learned_rules"`
	TriggerMode              string `json:"trigger_mode"`
	ReviewDraftPRs           bool   `json:"review_draft_prs"`
	PRSummaries              bool   `json:"pr_summaries"`
	PostPRRiskScore          bool   `json:"post_pr_risk_score"`
	AutofixMode              string `json:"autofix_mode"` // off|suggest|branch
	AutofixSeverityThreshold string `json:"autofix_severity_threshold"`
	IncrementalReview        bool   `json:"incremental_review"`
	SecurityAutoPRReviews    bool   `json:"security_auto_pr_reviews"`
	ContextAwareAnalysis     bool   `json:"context_aware_analysis"`
	InlineFindings           bool   `json:"inline_findings"`
	AutoApprove              bool   `json:"auto_approve"`
	ReviewerRouting          bool   `json:"reviewer_routing"`
	PolicyFilePath           string `json:"policy_file_path"`
	AIReviewerAware          bool   `json:"ai_reviewer_aware"`
	BugbotMaxUnits           int    `json:"bugbot_max_units"`
	CloudEnabled             bool   `json:"cloud_enabled"`
	CloudRunTests            bool   `json:"cloud_run_tests"`
	CheckupEnabled           bool   `json:"checkup_enabled"`
	// AI Issues / roadmap (Aperant-style autonomy). Fail-closed capabilities.
	AIIssueLabels            []string `json:"ai_issue_labels"`
	IssueAutoImplement       bool     `json:"issue_auto_implement"`
	RoadmapProjectsV2        bool     `json:"roadmap_projects_v2"`
	RequireHumanBeforeCoding bool     `json:"require_human_before_coding"`
	AIIssuesEnabled          bool     `json:"ai_issues_enabled"`
}

func builtinAgentPrefs() agentPrefs {
	return agentPrefs{
		RepositoryRules:          true,
		LearnedRules:             false,
		TriggerMode:              string(triggerEveryPush),
		ReviewDraftPRs:           true,
		PRSummaries:              true,
		PostPRRiskScore:          true,
		AutofixMode:              "branch",
		AutofixSeverityThreshold: "high",
		IncrementalReview:        true,
		SecurityAutoPRReviews:    true,
		ContextAwareAnalysis:     true,
		InlineFindings:           false,
		AutoApprove:              false,
		ReviewerRouting:          false,
		PolicyFilePath:           ".opa/approval-policy.json",
		AIReviewerAware:          true,
		BugbotMaxUnits:           10,
		CloudEnabled:             true,
		CloudRunTests:            false,
		CheckupEnabled:           false,
		AIIssueLabels:            []string{"AI"},
		IssueAutoImplement:       false,
		RoadmapProjectsV2:        false,
		RequireHumanBeforeCoding: true,
		AIIssuesEnabled:          true,
	}
}

// capability fields fail closed on inherit (false unless explicitly set).
var agentPrefsCapabilityFields = map[string]bool{
	"cloud_enabled": true, "cloud_run_tests": true, "autofix_mode": true,
	"auto_approve": true, "learned_rules": true, "checkup_enabled": true,
	"issue_auto_implement": true, "roadmap_projects_v2": true,
	"ai_issues_enabled": true,
}

type agentPrefsRow struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	Level          string `json:"level"` // org|installation|repo
	ScopeKey       string `json:"scope_key"`
	PrefsJSON      string `json:"prefs_json"`
	UpdatedAt      string `json:"updated_at"`
	UpdatedBy      string `json:"updated_by"`
	Deleted        bool   `json:"deleted"`
}

var (
	agentPrefsMu   sync.RWMutex
	agentPrefsLive = map[string]*agentPrefsRow{} // key: org|proj|level|scope
)

func agentPrefsKey(org, proj, level, scope string) string {
	return org + "|" + proj + "|" + level + "|" + scope
}

func triggerModeAdmits(mode, event string) bool {
	ev := strings.ToLower(strings.TrimSpace(event))
	switch triggerMode(strings.TrimSpace(mode)) {
	case triggerOnDemand:
		return strings.HasPrefix(ev, "manual.") || strings.HasPrefix(ev, "simulate")
	case triggerPROpen:
		return strings.Contains(ev, "opened") || strings.Contains(ev, "ready_for_review") ||
			strings.HasPrefix(ev, "manual.") || strings.HasPrefix(ev, "simulate")
	case triggerCron:
		return strings.HasPrefix(ev, "cron.") || strings.HasPrefix(ev, "manual.") || strings.HasPrefix(ev, "simulate")
	default: // every_push
		return true
	}
}

// resolveAgentPrefs merges builtin → org → installation → repo. Returns effective
// prefs and a per-field source map for Dashboard provenance.
func resolveAgentPrefs(org, proj, connectorID, repo string) (agentPrefs, map[string]string) {
	out := builtinAgentPrefs()
	sources := map[string]string{}
	setSource := func(field, src string) { sources[field] = src }

	apply := func(raw string, level string) {
		if strings.TrimSpace(raw) == "" || raw == "{}" {
			return
		}
		var patch map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &patch) != nil {
			return
		}
		applyPrefsPatch(&out, sources, patch, level)
	}

	apply(loadAgentPrefsJSON(org, proj, "org", org+"/"+proj), "org")
	if connectorID != "" {
		apply(loadAgentPrefsJSON(org, proj, "installation", connectorID), "installation")
	}
	if repo != "" {
		apply(loadAgentPrefsJSON(org, proj, "repo", repo), "repo")
	}
	for field := range agentPrefsCapabilityFields {
		if _, ok := sources[field]; !ok {
			setSource(field, "builtin")
		}
	}
	return out, sources
}

func applyPrefsPatch(out *agentPrefs, sources map[string]string, patch map[string]json.RawMessage, level string) {
	takeBool := func(field string, dest *bool) {
		raw, ok := patch[field]
		if !ok || string(raw) == "null" {
			return
		}
		var v bool
		if json.Unmarshal(raw, &v) != nil {
			return
		}
		*dest = v
		sources[field] = level
	}
	takeString := func(field string, dest *string) {
		raw, ok := patch[field]
		if !ok || string(raw) == "null" {
			return
		}
		var v string
		if json.Unmarshal(raw, &v) != nil || v == "" {
			return
		}
		*dest = v
		sources[field] = level
	}
	takeInt := func(field string, dest *int) {
		raw, ok := patch[field]
		if !ok || string(raw) == "null" {
			return
		}
		var v int
		if json.Unmarshal(raw, &v) != nil {
			return
		}
		*dest = v
		sources[field] = level
	}
	takeBool("repository_rules", &out.RepositoryRules)
	takeBool("learned_rules", &out.LearnedRules)
	takeString("trigger_mode", &out.TriggerMode)
	takeBool("review_draft_prs", &out.ReviewDraftPRs)
	takeBool("pr_summaries", &out.PRSummaries)
	takeBool("post_pr_risk_score", &out.PostPRRiskScore)
	takeString("autofix_mode", &out.AutofixMode)
	takeString("autofix_severity_threshold", &out.AutofixSeverityThreshold)
	takeBool("incremental_review", &out.IncrementalReview)
	takeBool("security_auto_pr_reviews", &out.SecurityAutoPRReviews)
	takeBool("context_aware_analysis", &out.ContextAwareAnalysis)
	takeBool("inline_findings", &out.InlineFindings)
	takeBool("auto_approve", &out.AutoApprove)
	takeBool("reviewer_routing", &out.ReviewerRouting)
	takeString("policy_file_path", &out.PolicyFilePath)
	takeBool("ai_reviewer_aware", &out.AIReviewerAware)
	takeInt("bugbot_max_units", &out.BugbotMaxUnits)
	takeBool("cloud_enabled", &out.CloudEnabled)
	takeBool("cloud_run_tests", &out.CloudRunTests)
	takeBool("checkup_enabled", &out.CheckupEnabled)
	takeBool("issue_auto_implement", &out.IssueAutoImplement)
	takeBool("roadmap_projects_v2", &out.RoadmapProjectsV2)
	takeBool("require_human_before_coding", &out.RequireHumanBeforeCoding)
	takeBool("ai_issues_enabled", &out.AIIssuesEnabled)
	if raw, ok := patch["ai_issue_labels"]; ok && string(raw) != "null" {
		var labels []string
		if json.Unmarshal(raw, &labels) == nil && labels != nil {
			out.AIIssueLabels = labels
			sources["ai_issue_labels"] = level
		}
	}
}

// issueLabelMatchesPrefs reports whether any of the issue's labels is in the
// configured AI gate list (case-insensitive). Empty prefs list defaults to
// matching the literal label "AI".
func issueLabelMatchesPrefs(prefs agentPrefs, labels []string) bool {
	want := prefs.AIIssueLabels
	if len(want) == 0 {
		want = []string{"AI"}
	}
	for _, l := range labels {
		ln := strings.TrimSpace(l)
		if ln == "" {
			continue
		}
		for _, w := range want {
			if strings.EqualFold(ln, strings.TrimSpace(w)) {
				return true
			}
		}
	}
	return false
}

func loadAgentPrefsJSON(org, proj, level, scope string) string {
	key := agentPrefsKey(org, proj, level, scope)
	agentPrefsMu.RLock()
	row := agentPrefsLive[key]
	agentPrefsMu.RUnlock()
	if row != nil && !row.Deleted {
		return row.PrefsJSON
	}
	if p := loadAgentPrefsFile(org, proj, level, scope); p != nil && !p.Deleted {
		agentPrefsMu.Lock()
		agentPrefsLive[key] = p
		agentPrefsMu.Unlock()
		return p.PrefsJSON
	}
	return ""
}

func agentPrefsDir() string {
	return filepath.Join(scmStateDir(), "prefs")
}

func agentPrefsFilePath(org, proj, level, scope string) string {
	safe := strings.NewReplacer("/", "_", "|", "_", " ", "_").Replace(org + "__" + proj + "__" + level + "__" + scope)
	return filepath.Join(agentPrefsDir(), safe+".json")
}

func loadAgentPrefsFile(org, proj, level, scope string) *agentPrefsRow {
	raw, err := os.ReadFile(agentPrefsFilePath(org, proj, level, scope))
	if err != nil {
		return nil
	}
	var row agentPrefsRow
	if json.Unmarshal(raw, &row) != nil {
		return nil
	}
	return &row
}

func persistAgentPrefsRow(row *agentPrefsRow) error {
	if row == nil {
		return nil
	}
	_ = os.MkdirAll(agentPrefsDir(), 0o700)
	row.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	raw, _ := json.MarshalIndent(row, "", "  ")
	path := agentPrefsFilePath(row.OrganizationID, row.ProjectID, row.Level, row.ScopeKey)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	key := agentPrefsKey(row.OrganizationID, row.ProjectID, row.Level, row.ScopeKey)
	agentPrefsMu.Lock()
	agentPrefsLive[key] = row
	agentPrefsMu.Unlock()
	if writer != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"organization_id": row.OrganizationID, "project_id": row.ProjectID,
			"level": row.Level, "scope_key": row.ScopeKey, "prefs_json": row.PrefsJSON,
			"updated_at": row.UpdatedAt, "updated_by": row.UpdatedBy,
			"deleted": boolToU8(row.Deleted),
		})
		writer.insertAsync("agent_prefs", append(payload, '\n'))
	}
	return nil
}

func boolToU8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

func ensureAgentsTables() {
	if queryClient == nil {
		return
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS opa.agent_prefs (
			organization_id String, project_id String,
			level LowCardinality(String), scope_key String,
			prefs_json String DEFAULT '{}',
			updated_at DateTime64(3) DEFAULT now64(3),
			updated_by String DEFAULT '', deleted UInt8 DEFAULT 0
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY (organization_id, project_id, level, scope_key)`,
		`ALTER TABLE opa.scm_jobs ADD COLUMN IF NOT EXISTS kind LowCardinality(String) DEFAULT ''`,
		`ALTER TABLE opa.scm_jobs ADD COLUMN IF NOT EXISTS run_id String DEFAULT ''`,
		`ALTER TABLE opa.scm_jobs ADD COLUMN IF NOT EXISTS attempt UInt8 DEFAULT 0`,
		`ALTER TABLE opa.review_contexts ADD COLUMN IF NOT EXISTS kind LowCardinality(String) DEFAULT 'note'`,
		`ALTER TABLE opa.review_contexts ADD COLUMN IF NOT EXISTS status LowCardinality(String) DEFAULT 'active'`,
	} {
		if err := queryClient.Execute(q); err != nil {
			log.Printf("[WARN] ensureAgentsTables: %v", err)
		}
	}
}

func hydrateAgentPrefsOnBoot() int {
	_ = os.MkdirAll(agentPrefsDir(), 0o700)
	n := 0
	entries, _ := os.ReadDir(agentPrefsDir())
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(agentPrefsDir(), e.Name()))
		if err != nil {
			continue
		}
		var row agentPrefsRow
		if json.Unmarshal(raw, &row) != nil || row.ScopeKey == "" {
			continue
		}
		key := agentPrefsKey(row.OrganizationID, row.ProjectID, row.Level, row.ScopeKey)
		agentPrefsMu.Lock()
		if _, ok := agentPrefsLive[key]; !ok {
			agentPrefsLive[key] = &row
			n++
		}
		agentPrefsMu.Unlock()
	}
	if queryClient == nil {
		return n
	}
	rows, err := queryClient.Query(`
		SELECT organization_id, project_id, level, scope_key, prefs_json, updated_at, updated_by, deleted
		FROM opa.agent_prefs ORDER BY updated_at DESC LIMIT 2000`)
	if err != nil {
		return n
	}
	seen := map[string]struct{}{}
	for _, row := range rows {
		org := strFromAny(row["organization_id"])
		proj := strFromAny(row["project_id"])
		level := strFromAny(row["level"])
		scope := strFromAny(row["scope_key"])
		key := agentPrefsKey(org, proj, level, scope)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		agentPrefsMu.Lock()
		if _, ok := agentPrefsLive[key]; !ok {
			agentPrefsLive[key] = &agentPrefsRow{
				OrganizationID: org, ProjectID: proj, Level: level, ScopeKey: scope,
				PrefsJSON: strFromAny(row["prefs_json"]), UpdatedAt: strFromAny(row["updated_at"]),
				UpdatedBy: strFromAny(row["updated_by"]), Deleted: intFromAny(row["deleted"]) != 0,
			}
			n++
		}
		agentPrefsMu.Unlock()
	}
	return n
}

func registerAgentsPrefsMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	_ = authAdmin
	authView("/api/agents/prefs", handleAgentPrefs)
}

func handleAgentPrefs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		handleAgentPrefsGet(w, r)
	case http.MethodPut, http.MethodPost:
		if authEnforced {
			role := strings.TrimSpace(r.Header.Get("X-User-Role"))
			if !hasPermission(role, "admin") {
				http.Error(w, "forbidden", 403)
				return
			}
		}
		handleAgentPrefsPut(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleAgentPrefsGet(w http.ResponseWriter, r *http.Request) {
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	level := strings.ToLower(strings.TrimSpace(nz(r.URL.Query().Get("level"), "org")))
	scope := strings.TrimSpace(r.URL.Query().Get("scope_key"))
	connectorID := strings.TrimSpace(r.URL.Query().Get("connector_id"))
	repo := strings.TrimSpace(r.URL.Query().Get("repo"))
	if scope == "" {
		switch level {
		case "org":
			scope = org + "/" + proj
		case "installation":
			scope = connectorID
		case "repo":
			scope = repo
		default:
			level = "org"
			scope = org + "/" + proj
		}
	}
	effective, sources := resolveAgentPrefs(org, proj, connectorID, repo)
	stored := loadAgentPrefsJSON(org, proj, level, scope)
	var storedObj interface{} = map[string]interface{}{}
	_ = json.Unmarshal([]byte(nz(stored, "{}")), &storedObj)
	writeJSON(w, map[string]interface{}{
		"organization_id": org, "project_id": proj,
		"level": level, "scope_key": scope,
		"prefs": storedObj, "effective": effective, "sources": sources,
	})
}

func handleAgentPrefsPut(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		Level       string                     `json:"level"`
		ScopeKey    string                     `json:"scope_key"`
		ConnectorID string                     `json:"connector_id"`
		Repo        string                     `json:"repo"`
		Prefs       map[string]json.RawMessage `json:"prefs"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Prefs == nil {
		http.Error(w, "bad json — prefs object required (use null to clear fields)", 400)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	level := strings.ToLower(strings.TrimSpace(body.Level))
	if level == "" {
		http.Error(w, "level required — use org, installation, or repo (omit only on GET, which defaults to org)", 400)
		return
	}
	switch level {
	case "org", "installation", "repo":
	default:
		http.Error(w, "level must be org, installation, or repo", 400)
		return
	}
	scope := strings.TrimSpace(body.ScopeKey)
	if scope == "" {
		switch level {
		case "org":
			scope = org + "/" + proj
		case "installation":
			scope = strings.TrimSpace(body.ConnectorID)
		default:
			scope = strings.TrimSpace(body.Repo)
		}
	}
	if scope == "" {
		switch level {
		case "org":
			http.Error(w, "organization scope unavailable — tenant context missing", 400)
		case "installation":
			http.Error(w, "connector_id/scope_key required for installation level", 400)
		default:
			http.Error(w, "repo/scope_key required for repository level — use level=org for global prefs", 400)
		}
		return
	}
	// Merge onto existing blob so unspecified fields keep prior explicit values.
	existing := map[string]json.RawMessage{}
	_ = json.Unmarshal([]byte(nz(loadAgentPrefsJSON(org, proj, level, scope), "{}")), &existing)
	for k, v := range body.Prefs {
		if string(v) == "null" {
			delete(existing, k)
			continue
		}
		existing[k] = v
	}
	blob, _ := json.Marshal(existing)
	row := &agentPrefsRow{
		OrganizationID: org, ProjectID: proj, Level: level, ScopeKey: scope,
		PrefsJSON: string(blob), UpdatedBy: strings.TrimSpace(r.Header.Get("X-User-Username")),
	}
	if err := persistAgentPrefsRow(row); err != nil {
		http.Error(w, "persist failed", 500)
		return
	}
	effective, sources := resolveAgentPrefs(org, proj, body.ConnectorID, body.Repo)
	writeJSON(w, map[string]interface{}{
		"ok": true, "level": level, "scope_key": scope,
		"organization_id": org, "project_id": proj,
		"prefs": existing, "effective": effective, "sources": sources,
	})
}
