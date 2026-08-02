package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Rule kind / status extend opaReviewContext for Repository Rules.
const (
	ruleKindMust   = "must"
	ruleKindShould = "should"
	ruleKindNote   = "note"

	ruleStatusActive    = "active"
	ruleStatusCandidate = "candidate"
	ruleStatusRejected  = "rejected"
)

func normalizeRuleKind(k string) string {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case ruleKindMust, "required":
		return ruleKindMust
	case ruleKindShould, "recommended":
		return ruleKindShould
	case ruleKindNote, "info", "":
		return ruleKindNote
	default:
		return ruleKindNote
	}
}

func normalizeRuleStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ruleStatusCandidate:
		return ruleStatusCandidate
	case ruleStatusRejected:
		return ruleStatusRejected
	case ruleStatusActive, "":
		return ruleStatusActive
	default:
		return ruleStatusActive
	}
}

// resolveReviewContextsForPrefs respects repository_rules and only injects active rules.
func resolveReviewContextsForPrefs(org, proj, repo string, prefs agentPrefs) appliedReviewContexts {
	if !prefs.RepositoryRules {
		return appliedReviewContexts{
			Primary: []opaReviewContext{}, Linked: []opaReviewContext{}, Org: []opaReviewContext{},
		}
	}
	applied := resolveReviewContextsForRepo(org, proj, repo)
	filter := func(in []opaReviewContext) []opaReviewContext {
		out := make([]opaReviewContext, 0, len(in))
		for _, rc := range in {
			if normalizeRuleStatus(rc.Status) == ruleStatusActive {
				out = append(out, rc)
			}
		}
		return out
	}
	applied.Primary = filter(applied.Primary)
	applied.Linked = filter(applied.Linked)
	applied.Org = filter(applied.Org)
	return applied
}

// mineLearnedRuleCandidates writes candidate contexts from recurring high findings.
// Never auto-activates — human promotion required.
func mineLearnedRuleCandidates(job *scmJob, res aiReviewResult, prefs agentPrefs) int {
	if job == nil || !prefs.LearnedRules {
		return 0
	}
	n := 0
	seen := map[string]struct{}{}
	for _, f := range res.Findings {
		sev := strings.ToLower(strings.TrimSpace(fmt.Sprint(f["severity"])))
		if sev != "high" && sev != "critical" && sev != "blocker" {
			continue
		}
		rule := strings.TrimSpace(fmt.Sprint(f["rule"]))
		msg := strings.TrimSpace(fmt.Sprint(f["message"]))
		if msg == "" {
			msg = strings.TrimSpace(fmt.Sprint(f["problem"]))
		}
		if rule == "" && msg == "" {
			continue
		}
		title := rule
		if title == "" {
			title = truncateStr(msg, 80)
		}
		title = "Learned: " + title
		key := strings.ToLower(job.RepoFullName + "|" + title)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if existingRuleTitle(job.RepoFullName, title) {
			continue
		}
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		id := loadID("rctx", job.OrganizationID, job.ProjectID, job.RepoFullName, title, "learned")
		body := fmt.Sprintf("Candidate rule mined from OPA Review job `%s`.\n\n**Finding:** %s\n\n_Promote to activate; never auto-applied._",
			job.ID, msg)
		rc := &opaReviewContext{
			ID: id, OrganizationID: job.OrganizationID, ProjectID: job.ProjectID,
			ConnectorID: job.ConnectorID, RepoFullName: job.RepoFullName,
			Title: title, BodyMarkdown: body, TagsJSON: `["learned","candidate"]`,
			Source: "learned", Kind: ruleKindShould, Status: ruleStatusCandidate,
			CreatedAt: now, UpdatedAt: now,
		}
		if rc.LinkGroupID == "" {
			rc.LinkGroupID = linkGroupForRepo(job.RepoFullName)
		}
		reviewContextLive.Store(id, rc)
		persistReviewContext(rc)
		n++
		if n >= 5 {
			break
		}
	}
	return n
}

func existingRuleTitle(repo, title string) bool {
	found := false
	reviewContextLive.Range(func(_, v interface{}) bool {
		rc, ok := v.(*opaReviewContext)
		if !ok || rc == nil || rc.Deleted {
			return true
		}
		if rc.RepoFullName != repo {
			return true
		}
		if !strings.EqualFold(rc.Title, title) {
			return true
		}
		st := normalizeRuleStatus(rc.Status)
		if st == ruleStatusActive || st == ruleStatusCandidate {
			found = true
			return false
		}
		return true
	})
	return found
}

func handleReviewContextPromoteReject(w http.ResponseWriter, r *http.Request, rc *opaReviewContext, action string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	switch strings.ToLower(action) {
	case "promote":
		rc.Status = ruleStatusActive
		if rc.Kind == "" || rc.Kind == ruleKindNote {
			rc.Kind = ruleKindShould
		}
	case "reject":
		rc.Status = ruleStatusRejected
	default:
		http.Error(w, "unknown action", 400)
		return
	}
	rc.UpdatedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	persistReviewContext(rc)
	writeJSON(w, map[string]interface{}{"ok": true, "context": rc})
}

// maybeHandleRuleAction returns true if the subpath was promote/reject.
func maybeHandleRuleAction(w http.ResponseWriter, r *http.Request, id, rest string) bool {
	action := strings.Trim(rest, "/")
	if action != "promote" && action != "reject" {
		return false
	}
	rc := getReviewContext(id)
	if rc == nil || rc.Deleted {
		http.Error(w, "not found", 404)
		return true
	}
	handleReviewContextPromoteReject(w, r, rc, action)
	return true
}

func applyRuleFieldsFromCreate(rc *opaReviewContext, kind, status string) {
	if rc == nil {
		return
	}
	if kind != "" {
		rc.Kind = normalizeRuleKind(kind)
	} else if rc.Kind == "" {
		rc.Kind = ruleKindNote
	}
	if status != "" {
		rc.Status = normalizeRuleStatus(status)
	} else if rc.Status == "" {
		rc.Status = ruleStatusActive
	}
}

func decodeRulePatchExtras(raw []byte, rc *opaReviewContext) {
	var body struct {
		Kind   *string `json:"kind"`
		Status *string `json:"status"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return
	}
	if body.Kind != nil {
		rc.Kind = normalizeRuleKind(*body.Kind)
	}
	if body.Status != nil {
		rc.Status = normalizeRuleStatus(*body.Status)
	}
}
