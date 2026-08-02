package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

type riskFactor struct {
	Name    string `json:"name"`
	Detail  string `json:"detail"`
	Points  int    `json:"points"`
}

type riskEvidence struct {
	Bugbot           aiReviewResult
	SecurityFail     bool
	SecurityFindings []agentFinding
	Diff             string
	TouchedFiles     []string
	Degraded         []string
}

type riskScoreResult struct {
	Score   int          `json:"score"`
	Factors []riskFactor `json:"factors"`
}

// computeRiskScore is deterministic Go — never a model output. Higher = riskier.
// Caps at 100. Used for Dashboard / PR summary; approval may veto on high scores
// when policy declares block_if.max_risk_score.
func computeRiskScore(ev riskEvidence) riskScoreResult {
	factors := []riskFactor{}
	add := func(name, detail string, pts int) {
		if pts == 0 {
			return
		}
		factors = append(factors, riskFactor{Name: name, Detail: detail, Points: pts})
	}

	if ev.SecurityFail {
		add("security_gate", "AppSec gate failed", 35)
	}
	crit, high, med := 0, 0, 0
	for _, f := range ev.SecurityFindings {
		switch strings.ToLower(f.Severity) {
		case "critical", "blocker":
			crit++
		case "high":
			high++
		case "medium":
			med++
		}
	}
	if crit > 0 {
		add("security_critical", fmt.Sprintf("%d critical finding(s)", crit), minInt(40, crit*20))
	}
	if high > 0 {
		add("security_high", fmt.Sprintf("%d high finding(s)", high), minInt(25, high*10))
	}
	if med > 0 {
		add("security_medium", fmt.Sprintf("%d medium finding(s)", med), minInt(10, med*3))
	}

	if hasBlockerOrHighFinding(ev.Bugbot) {
		add("bugbot_blocker", "bugbot reported blocker/high", 20)
	} else if strings.EqualFold(ev.Bugbot.Status, "findings") {
		add("bugbot_findings", "bugbot reported findings", 12)
	}
	if strings.EqualFold(ev.Bugbot.Verdict, "request_changes") {
		add("bugbot_verdict", "verdict=request_changes", 10)
	}

	files := ev.TouchedFiles
	if len(files) == 0 {
		files = mapKeys(diffPathsFromUnified(ev.Diff))
	}
	sensitive := 0
	for _, f := range files {
		lf := strings.ToLower(f)
		base := filepath.Base(lf)
		switch {
		case strings.Contains(lf, ".github/workflows"), strings.HasSuffix(lf, "dockerfile"),
			strings.Contains(lf, "docker-compose"), strings.HasPrefix(base, "."):
			sensitive++
		case strings.Contains(lf, "migration"), strings.Contains(lf, "/auth"),
			strings.Contains(lf, "secret"), strings.Contains(lf, "credential"),
			strings.Contains(lf, "permission"), strings.Contains(lf, "rbac"):
			sensitive++
		case strings.HasSuffix(lf, ".env"), strings.HasSuffix(lf, ".pem"), strings.HasSuffix(lf, ".key"):
			sensitive += 2
		}
	}
	if sensitive > 0 {
		add("sensitive_paths", fmt.Sprintf("%d sensitive path hit(s)", sensitive), minInt(25, sensitive*8))
	}
	if n := len(files); n > 40 {
		add("large_diff", fmt.Sprintf("%d files touched", n), 15)
	} else if n > 20 {
		add("medium_diff", fmt.Sprintf("%d files touched", n), 8)
	}
	if len(ev.Degraded) > 0 {
		add("degraded", strings.Join(ev.Degraded, ", "), 10)
	}

	score := 0
	for _, f := range factors {
		score += f.Points
	}
	if score > 100 {
		score = 100
	}
	return riskScoreResult{Score: score, Factors: factors}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
