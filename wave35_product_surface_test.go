package main

import (
	"strings"
	"testing"
)

func TestSplitPRBodyFenceHumanEdit(t *testing.T) {
	outside := "Human description here"
	hash := hashOutsideBody(outside)
	body := outside + "\n\n" + opaSummaryStart + "\n" +
		opaSummaryOutsideHashPrefix + hash + " -->\n" +
		"### OPA Review\nold\n" + opaSummaryEnd
	gotOut, gotHash, had := splitPRBodyFence(body)
	if !had || gotHash != hash {
		t.Fatalf("parse fence: had=%v hash=%s want %s", had, gotHash, hash)
	}
	if strings.TrimSpace(gotOut) != outside {
		t.Fatalf("outside=%q", gotOut)
	}
	// Human edits outside → hash mismatch path.
	edited := "Human CHANGED description\n\n" + opaSummaryStart + "\n" +
		opaSummaryOutsideHashPrefix + hash + " -->\nOPA\n" + opaSummaryEnd
	out2, prior, _ := splitPRBodyFence(edited)
	if hashOutsideBody(out2) == prior {
		t.Fatal("edited outside should not match prior hash")
	}
}

func TestComputeRiskScore(t *testing.T) {
	r := computeRiskScore(riskEvidence{
		SecurityFail: true,
		SecurityFindings: []agentFinding{
			{Severity: "critical"}, {Severity: "high"},
		},
		Bugbot: aiReviewResult{Status: "findings", Verdict: "request_changes"},
		TouchedFiles: []string{".github/workflows/ci.yml", "db/migration/001.sql"},
	})
	if r.Score < 50 {
		t.Fatalf("expected elevated score, got %d factors=%+v", r.Score, r.Factors)
	}
	if r.Score > 100 {
		t.Fatalf("score capped at 100, got %d", r.Score)
	}
	clean := computeRiskScore(riskEvidence{Bugbot: aiReviewResult{Status: "ok"}})
	if clean.Score != 0 {
		t.Fatalf("clean want 0 got %d", clean.Score)
	}
}

func TestNormalizeRuleKindStatus(t *testing.T) {
	if normalizeRuleKind("MUST") != ruleKindMust {
		t.Fatal("must")
	}
	if normalizeRuleStatus("candidate") != ruleStatusCandidate {
		t.Fatal("candidate")
	}
	prefsOff := agentPrefs{RepositoryRules: false}
	a := resolveReviewContextsForPrefs("o", "p", "org/repo", prefsOff)
	if len(a.Primary)+len(a.Linked)+len(a.Org) != 0 {
		t.Fatal("repository_rules off must return empty")
	}
}

func TestEvaluateApprovalRiskVeto(t *testing.T) {
	clean := aiReviewResult{Status: "ok", AutoMergeConfidence: 90, Verdict: "approve"}
	d := evaluateApproval(approvalEvidence{
		Bugbot: clean, BugbotOK: true, SecurityOK: true,
		Prefs: agentPrefs{AutoApprove: true}, MinScore: 70, RiskScore: 80,
		Policy: &approvalPolicy{Version: 1, BlockIf: struct {
			SecurityMinSeverity string `json:"security_min_severity"`
			MaxRiskScore        int    `json:"max_risk_score"`
		}{MaxRiskScore: 50}, OnFail: "COMMENT"},
	})
	if d.Event != "COMMENT" {
		t.Fatalf("risk veto want COMMENT got %s", d.Event)
	}
}
