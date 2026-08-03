package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// approvalPolicy is the clamp-only schema for .opa/approval-policy.json (base ref).
// No approve_if / widening clauses by design.
type approvalPolicy struct {
	Version int `json:"version"`
	Require []string `json:"require"` // agent kinds that must be terminal-success
	BlockIf struct {
		SecurityMinSeverity string `json:"security_min_severity"`
		MaxRiskScore        int    `json:"max_risk_score"`
	} `json:"block_if"`
	Route struct {
		Reviewers     []string `json:"reviewers"`
		TeamReviewers []string `json:"team_reviewers"`
	} `json:"route"`
	OnFail string `json:"on_fail"` // COMMENT (default) | REQUEST_CHANGES
}

type approvalEvidence struct {
	Prefs            agentPrefs
	Bugbot           aiReviewResult
	SecurityRunID    string
	SecurityFail     bool // gate fail
	SecurityFindings []agentFinding
	BugbotOK         bool
	SecurityOK       bool
	Degraded         []string
	CloudChildExists bool
	Policy           *approvalPolicy
	PolicyHonesty    string
	BaseRef          string
	MinScore         int // legacy watched AutoApproveMinScore; confidence veto threshold
	RiskScore        int // deterministic; 0 = unset
}

type approvalDecision struct {
	Event   string   // APPROVE | REQUEST_CHANGES | COMMENT
	Reasons []string
	Honesty string
	// Bugbot is the (possibly confidence-calibrated) review used for the decision body.
	Bugbot aiReviewResult
}

func parseApprovalPolicy(raw string) (*approvalPolicy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty policy")
	}
	if len(raw) > 64*1024 {
		return nil, fmt.Errorf("policy exceeds 64KiB")
	}
	var p approvalPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	if p.Version != 0 && p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d", p.Version)
	}
	if p.Version == 0 {
		p.Version = 1
	}
	// Reject unknown widening keys by re-decode into map.
	var probe map[string]json.RawMessage
	_ = json.Unmarshal([]byte(raw), &probe)
	for k := range probe {
		switch k {
		case "version", "require", "block_if", "route", "on_fail":
			// known clamp-only keys
		case "approve_if", "allow_if", "widen":
			return nil, fmt.Errorf("policy contains forbidden widening key %q", k)
		default:
			return nil, fmt.Errorf("policy contains unknown key %q (fail closed)", k)
		}
	}
	if p.OnFail == "" {
		p.OnFail = "COMMENT"
	}
	return &p, nil
}

// evaluateApproval is the sole place APPROVE can be granted. Confidence is
// veto-only: low confidence blocks; high confidence never grants.
//
// Low confidence without an actionable why (findings, merge-blocker priorities,
// request_changes verdict, or fallback) is raised to MinScore so clean PRs are
// not stuck forever below the veto threshold.
func evaluateApproval(ev approvalEvidence) approvalDecision {
	d := approvalDecision{Event: "COMMENT"}
	var reasons []string

	add := func(s string) { reasons = append(reasons, s) }

	if len(ev.Degraded) > 0 {
		add("degraded: " + strings.Join(ev.Degraded, ", "))
		d.Event = "COMMENT"
		d.Reasons = reasons
		d.Honesty = "Degraded input — never APPROVE"
		d.Bugbot = ev.Bugbot
		return d
	}
	if ev.CloudChildExists {
		add("cloud child pending — APPROVE downgraded")
		d.Event = "COMMENT"
		d.Reasons = reasons
		d.Honesty = "pending_autofix"
		d.Bugbot = ev.Bugbot
		return d
	}

	// AutoApprove is the sole grant switch. MinScore is veto-only and must
	// never promote auto-approve on its own.
	if !ev.Prefs.AutoApprove {
		add("auto_approve off")
		d.Event = "COMMENT"
		d.Reasons = reasons
		d.Honesty = "auto-approve disabled"
		d.Bugbot = ev.Bugbot
		return d
	}

	status := strings.ToLower(strings.TrimSpace(ev.Bugbot.Status))
	if status == "skipped" || status == "error" {
		add("bugbot status=" + status)
		d.Event = "COMMENT"
		d.Reasons = reasons
		d.Bugbot = ev.Bugbot
		return d
	}

	bugbot := ev.Bugbot
	if raised, note := calibrateConfidenceForVeto(&bugbot, ev.MinScore); raised {
		add(note)
		d.Honesty = note
	}
	d.Bugbot = bugbot

	// Confidence veto-only (after we know bugbot produced a real review).
	if ev.MinScore > 0 && bugbot.AutoMergeConfidence < ev.MinScore {
		why := concreteConfidenceWhy(bugbot)
		add(fmt.Sprintf("confidence %d below veto threshold %d", bugbot.AutoMergeConfidence, ev.MinScore))
		if why != "" {
			add("why: " + why)
		} else {
			add("why: low confidence without a concrete merge-blocker explanation")
		}
		d.Event = "REQUEST_CHANGES"
		d.Reasons = reasons
		d.Honesty = "confidence veto"
		return d
	}

	if hasBlockerOrHighFinding(bugbot) || strings.ToLower(bugbot.Verdict) == "request_changes" {
		add("bugbot blocker/high or request_changes verdict")
		d.Event = "REQUEST_CHANGES"
		d.Reasons = reasons
		return d
	}
	status = strings.ToLower(strings.TrimSpace(bugbot.Status))
	if status == "findings" {
		add("bugbot reported findings")
		d.Event = "REQUEST_CHANGES"
		d.Reasons = reasons
		return d
	}

	if ev.SecurityFail {
		add("security gate failed")
		d.Event = "REQUEST_CHANGES"
		d.Reasons = reasons
		return d
	}
	minSev := "high"
	if ev.Policy != nil && ev.Policy.BlockIf.SecurityMinSeverity != "" {
		minSev = ev.Policy.BlockIf.SecurityMinSeverity
	}
	if sec := highestSecuritySeverity(ev.SecurityFindings); severityAtLeast(sec, minSev) {
		add("security finding severity " + sec + " ≥ " + minSev)
		d.Event = "REQUEST_CHANGES"
		d.Reasons = reasons
		return d
	}
	if ev.Policy != nil && ev.Policy.BlockIf.MaxRiskScore > 0 && ev.RiskScore > ev.Policy.BlockIf.MaxRiskScore {
		add(fmt.Sprintf("risk score %d > policy max %d", ev.RiskScore, ev.Policy.BlockIf.MaxRiskScore))
		d.Event = failEvent(ev.Policy)
		d.Reasons = reasons
		d.Honesty = "risk score veto"
		return d
	}

	// Policy require cross-check.
	if ev.Policy != nil {
		for _, req := range ev.Policy.Require {
			req = strings.ToLower(strings.TrimSpace(req))
			switch req {
			case "security":
				if !ev.SecurityOK {
					add("policy require security not satisfied")
					d.Event = failEvent(ev.Policy)
					d.Reasons = reasons
					d.Honesty = "require cross-check abstain/fail"
					return d
				}
			case "bugbot", "review", "ai":
				if !ev.BugbotOK {
					add("policy require bugbot not satisfied")
					d.Event = failEvent(ev.Policy)
					d.Reasons = reasons
					d.Honesty = "require cross-check abstain/fail"
					return d
				}
			}
		}
	} else if ev.PolicyHonesty != "" {
		// Unparseable policy → never approve.
		add(ev.PolicyHonesty)
		d.Event = "COMMENT"
		d.Reasons = reasons
		d.Honesty = ev.PolicyHonesty
		return d
	}

	// All conjunctions held — APPROVE. Confidence did not grant this; evidence did.
	d.Event = "APPROVE"
	d.Reasons = append(reasons, "all approval conjunctions satisfied")
	if d.Honesty == "" {
		d.Honesty = "approved by evidence conjunction (confidence veto-only)"
	}
	return d
}

// concreteConfidenceWhy returns the human-facing reason low confidence should block.
func concreteConfidenceWhy(res aiReviewResult) string {
	var parts []string
	if r := strings.TrimSpace(res.ConfidenceRationale); r != "" {
		parts = append(parts, truncateStr(r, 240))
	}
	for _, p := range res.HumanReviewPriorities {
		c := strings.TrimSpace(p.Concern)
		if c == "" {
			continue
		}
		if f := strings.TrimSpace(p.File); f != "" {
			if p.Line > 0 {
				parts = append(parts, fmt.Sprintf("%s:%d — %s", f, p.Line, truncateStr(c, 160)))
			} else {
				parts = append(parts, fmt.Sprintf("%s — %s", f, truncateStr(c, 160)))
			}
		} else {
			parts = append(parts, truncateStr(c, 160))
		}
		if len(parts) >= 4 {
			break
		}
	}
	if res.Fallback {
		parts = append(parts, "rule-based fallback (structured AI synthesis unavailable)")
	}
	return strings.TrimSpace(strings.Join(parts, "; "))
}

// confidenceWhyIsActionable is true when low confidence points at something a
// human (or a follow-up commit) can address — not a vague empty rationale.
// A non-empty ConfidenceRationale counts: models often put real uncertainty
// only there (without findings/priorities), and raising the score would hide it.
func confidenceWhyIsActionable(res aiReviewResult) bool {
	if res.Fallback {
		return true
	}
	if hasBlockerOrHighFinding(res) || len(res.Findings) > 0 {
		return true
	}
	if len(res.HumanReviewPriorities) > 0 {
		return true
	}
	if strings.TrimSpace(res.ConfidenceRationale) != "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(res.Verdict), "request_changes") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(res.Verdict), "needs_context") {
		return true
	}
	st := strings.ToLower(strings.TrimSpace(res.Status))
	if st == "findings" || st == "error" {
		return true
	}
	return false
}

// calibrateConfidenceForVeto raises confidence to minScore when the review is
// clean but the model under-scored without any why (empty rationale, no
// findings/priorities). Never rewrites needs_context → approve.
func calibrateConfidenceForVeto(res *aiReviewResult, minScore int) (bool, string) {
	if res == nil || minScore <= 0 || res.AutoMergeConfidence >= minScore {
		return false, ""
	}
	if confidenceWhyIsActionable(*res) {
		return false, ""
	}
	prev := res.AutoMergeConfidence
	res.AutoMergeConfidence = minScore
	res.ConfidenceLabel = confidenceLabelFromScore(res.AutoMergeConfidence)
	if strings.TrimSpace(res.ConfidenceRationale) == "" {
		res.ConfidenceRationale = "No findings or merge-blocker priorities; confidence raised to the auto-approve veto threshold."
	}
	return true, fmt.Sprintf("confidence calibrated %d→%d (no actionable why for hard veto)", prev, minScore)
}

func failEvent(p *approvalPolicy) string {
	if p != nil && strings.EqualFold(p.OnFail, "REQUEST_CHANGES") {
		return "REQUEST_CHANGES"
	}
	return "COMMENT"
}

func highestSecuritySeverity(findings []agentFinding) string {
	order := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4, "blocker": 5}
	best := ""
	bestN := 0
	for _, f := range findings {
		s := strings.ToLower(strings.TrimSpace(f.Severity))
		if n := order[s]; n > bestN {
			bestN = n
			best = s
		}
	}
	return best
}

func severityAtLeast(have, want string) bool {
	order := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4, "blocker": 5}
	return order[strings.ToLower(have)] >= order[strings.ToLower(want)] && order[strings.ToLower(want)] > 0
}

// decideOPAReviewEvent keeps the legacy signature. Confidence/MinScore is
// veto-only and never grants APPROVE (AutoApprove stays off here). Prefer
// evaluateApproval with explicit prefs for real APPROVE decisions.
func decideOPAReviewEvent(res aiReviewResult, minScore int) string {
	ev := approvalEvidence{
		Bugbot:   res,
		MinScore: minScore,
		BugbotOK: strings.ToLower(res.Status) != "skipped" && strings.ToLower(res.Status) != "error" && strings.ToLower(res.Status) != "failed",
		Prefs:    agentPrefs{AutoApprove: false},
	}
	d := evaluateApproval(ev)
	return d.Event
}
