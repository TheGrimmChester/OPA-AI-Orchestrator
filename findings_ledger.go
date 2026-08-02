package main

import (
	"fmt"
	"strings"
)

// agentFinding is the only inter-agent vocabulary for approval.
type agentFinding struct {
	Key       string `json:"key"`
	Source    string `json:"source"` // bugbot|security
	Severity  string `json:"severity"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Message   string `json:"message"`
	Rule      string `json:"rule,omitempty"`
	Namespace string `json:"namespace,omitempty"` // e.g. security for masked inlines
}

func findingFromBugbotMap(f map[string]interface{}) agentFinding {
	path, line, _ := findingFileLine(f)
	sev := strings.ToLower(strings.TrimSpace(fmt.Sprint(f["severity"])))
	if sev == "" {
		sev = strings.ToLower(strings.TrimSpace(fmt.Sprint(f["Severity"])))
	}
	msg := strings.TrimSpace(fmt.Sprint(f["message"]))
	if msg == "" {
		msg = strings.TrimSpace(fmt.Sprint(f["problem"]))
	}
	return agentFinding{
		Key: opaReviewFindingKey(f), Source: "bugbot", Severity: sev,
		File: path, Line: line, Message: msg,
		Rule: strings.TrimSpace(fmt.Sprint(f["rule"])),
	}
}

func buildLedger(bugbot aiReviewResult, security []agentFinding) []agentFinding {
	seen := map[string]struct{}{}
	out := []agentFinding{}
	add := func(f agentFinding) {
		if f.Key == "" {
			f.Key = fmt.Sprintf("%s:%s:%d:%s", f.Source, f.File, f.Line, f.Severity)
		}
		if _, ok := seen[f.Key]; ok {
			return
		}
		seen[f.Key] = struct{}{}
		out = append(out, f)
	}
	for _, f := range bugbot.Findings {
		add(findingFromBugbotMap(f))
	}
	for _, f := range security {
		add(f)
	}
	return out
}

func securityFindingsFromRun(org, runID string) []agentFinding {
	if runID == "" || queryClient == nil {
		return nil
	}
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT rule, file, line, severity, snippet FROM opa.secret_findings
		WHERE security_run_id = '%s' ORDER BY scraped_at DESC LIMIT 200`, escapeSQL(runID)))
	if err != nil {
		return nil
	}
	out := []agentFinding{}
	for _, row := range rows {
		file := strFromAny(row["file"])
		line := intFromAny(row["line"])
		sev := strFromAny(row["severity"])
		rule := strFromAny(row["rule"])
		msg := strFromAny(row["snippet"])
		key := fmt.Sprintf("security:%s:%s:%d:%s", runID, file, line, rule)
		out = append(out, agentFinding{
			Key: key, Source: "security", Severity: sev, File: file, Line: line,
			Message: msg, Rule: rule, Namespace: "security",
		})
	}
	_ = org
	return out
}

// maskFindingBody redacts secret-looking material from bodies destined for PR comments.
func maskFindingBody(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	s = strings.ReplaceAll(s, "AKIA", "AKIA***")
	// Mask long token-like runs (28+ alnum/_/-).
	var out strings.Builder
	var buf strings.Builder
	flush := func() {
		if buf.Len() >= 28 {
			out.WriteString("***")
		} else {
			out.WriteString(buf.String())
		}
		buf.Reset()
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			buf.WriteRune(r)
			continue
		}
		flush()
		out.WriteRune(r)
	}
	flush()
	return out.String()
}

func formatMaskedSecurityInline(f agentFinding) string {
	sev := nz(f.Severity, "medium")
	msg := maskFindingBody(f.Message)
	if msg == "" {
		msg = "secret-scan finding"
	}
	return fmt.Sprintf("<!-- opa-review:finding:%s -->\n**[security:%s]** %s\n\n`%s` — details masked.", f.Key, sev, msg, f.Rule)
}
