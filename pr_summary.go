package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	opaSummaryStart = "<!-- opa-summary:start -->"
	opaSummaryEnd   = "<!-- opa-summary:end -->"
	// Hidden hash of the human-authored body outside the fence. If this drifts,
	// a human edited the PR description and we refuse to overwrite.
	opaSummaryOutsideHashPrefix = "<!-- opa-summary:outside-hash:"
)

// upsertPRSummary splices an OPA-owned fenced block into the PR body. Skips
// when a human has edited content outside the fence since the last write.
func upsertPRSummary(conn *opaConnector, owner, repo string, job *scmJob, narrative string) (skipped string, err error) {
	if job == nil || job.PRNumber <= 0 || conn == nil {
		return "", nil
	}
	pull, err := githubGetPull(conn, owner, repo, job.PRNumber)
	if err != nil {
		return "", err
	}
	current := ""
	if pull != nil {
		current = pull.Body
	}
	outside, priorHash, hadFence := splitPRBodyFence(current)
	if hadFence && priorHash != "" {
		nowHash := hashOutsideBody(outside)
		if nowHash != priorHash {
			return "human_edit", nil
		}
	}
	inner := strings.TrimSpace(narrative)
	if inner == "" {
		inner = "_OPA Review summary unavailable._"
	}
	newOutsideHash := hashOutsideBody(outside)
	fenced := opaSummaryStart + "\n" +
		opaSummaryOutsideHashPrefix + newOutsideHash + " -->\n" +
		inner + "\n" +
		opaSummaryEnd
	newBody := splicePRBodyFence(outside, fenced)
	if err := githubUpdatePullBody(conn, owner, repo, job.PRNumber, newBody); err != nil {
		return "", err
	}
	return "", nil
}

func splitPRBodyFence(body string) (outside, priorHash string, hadFence bool) {
	start := strings.Index(body, opaSummaryStart)
	end := strings.Index(body, opaSummaryEnd)
	if start < 0 || end < 0 || end < start {
		return body, "", false
	}
	hadFence = true
	block := body[start : end+len(opaSummaryEnd)]
	outside = strings.TrimSpace(body[:start] + body[end+len(opaSummaryEnd):])
	if i := strings.Index(block, opaSummaryOutsideHashPrefix); i >= 0 {
		rest := block[i+len(opaSummaryOutsideHashPrefix):]
		if j := strings.Index(rest, " -->"); j > 0 {
			priorHash = strings.TrimSpace(rest[:j])
		}
	}
	return outside, priorHash, hadFence
}

func splicePRBodyFence(outside, fenced string) string {
	outside = strings.TrimSpace(outside)
	if outside == "" {
		return fenced
	}
	return outside + "\n\n" + fenced
}

func hashOutsideBody(s string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s)))
	return hex.EncodeToString(sum[:8])
}

// formatPRSummaryNarrative builds the fenced inner markdown from AI + optional risk.
func formatPRSummaryNarrative(res aiReviewResult, risk *riskScoreResult) string {
	var b strings.Builder
	b.WriteString("### OPA Review\n\n")
	status := nz(res.Status, "—")
	fmt.Fprintf(&b, "**Status:** `%s`", status)
	if res.Verdict != "" {
		fmt.Fprintf(&b, " · **Verdict:** `%s`", res.Verdict)
	}
	if res.AutoMergeConfidence > 0 {
		fmt.Fprintf(&b, " · **Confidence:** %d/100", res.AutoMergeConfidence)
	}
	b.WriteString("\n\n")
	if s := strings.TrimSpace(res.Summary); s != "" {
		b.WriteString(s)
		b.WriteString("\n\n")
	}
	if len(res.Findings) > 0 {
		fmt.Fprintf(&b, "_%d finding(s) — see inline comments / OPA Review résumé._\n", len(res.Findings))
	}
	if risk != nil && risk.Score > 0 {
		fmt.Fprintf(&b, "\n**Risk score:** %d/100", risk.Score)
		if len(risk.Factors) > 0 {
			b.WriteString(" (")
			parts := make([]string, 0, len(risk.Factors))
			for _, f := range risk.Factors {
				if f.Points > 0 {
					parts = append(parts, f.Name)
				}
			}
			b.WriteString(strings.Join(parts, ", "))
			b.WriteString(")")
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}
