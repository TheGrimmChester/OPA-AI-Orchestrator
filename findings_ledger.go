package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	openlogger "github.com/TheGrimmChester/open-logger-go"
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

// securityFindingsFromRun loads AppSec findings for the approval ledger via the OSA peer.
// Fail closed: empty run id, unset PEER_OSA_URL, peer error, or empty payload → no findings.
// Never reads opa.secret_findings / opa.sast_findings / opa.iac_findings from ClickHouse.
func securityFindingsFromRun(org, runID string) []agentFinding {
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return nil
	}
	if strings.TrimSpace(os.Getenv("PEER_OSA_URL")) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	payload, err := peerOSAGetSecurityRunFindings(ctx, org, runID)
	if err != nil {
		openlogger.LogWarn("peer OSA findings failed", map[string]interface{}{
			"error": err.Error(), "security_run_id": runID, "organization_id": org,
		})
		return nil
	}
	return agentFindingsFromOSAPeer(runID, payload)
}

// osaFindingMaps extracts a typed finding list from the OSA findings payload.
func osaFindingMaps(findings map[string]interface{}, key string) []map[string]interface{} {
	if findings == nil {
		return nil
	}
	raw, ok := findings[key]
	if !ok || raw == nil {
		return nil
	}
	switch t := raw.(type) {
	case []map[string]interface{}:
		return t
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(t))
		for _, item := range t {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func agentFindingFromOSARow(runID, kind string, row map[string]interface{}) agentFinding {
	file := strFromAny(row["file"])
	line := intFromAny(row["line"])
	sev := strFromAny(row["severity"])
	rule := strFromAny(row["rule"])
	msg := strFromAny(row["snippet"])
	if msg == "" {
		msg = strFromAny(row["message"])
	}
	key := fmt.Sprintf("security:%s:%s:%s:%d:%s", kind, runID, file, line, rule)
	return agentFinding{
		Key: key, Source: "security", Severity: sev, File: file, Line: line,
		Message: msg, Rule: rule, Namespace: "security",
	}
}

// agentFindingsFromOSAPeer maps OSA GET …/findings JSON into ledger agentFinding rows.
// Prefer secrets, then sast, then iac (cve deferred — not used by the review ledger).
func agentFindingsFromOSAPeer(runID string, payload map[string]interface{}) []agentFinding {
	if payload == nil {
		return nil
	}
	findings, _ := payload["findings"].(map[string]interface{})
	if findings == nil {
		return nil
	}
	out := []agentFinding{}
	appendKind := func(kind string, limit int) {
		rows := osaFindingMaps(findings, kind)
		if limit > 0 && len(rows) > limit {
			rows = rows[:limit]
		}
		for _, row := range rows {
			out = append(out, agentFindingFromOSARow(runID, kind, row))
		}
	}
	appendKind("secrets", 200)
	appendKind("sast", 200)
	appendKind("iac", 200)
	return out
}

// writeThisRunSecurityFindingsBrief appends this-run secret/SAST sections from the OSA peer.
// Fail closed when peer unset/error/empty — never SELECT opa.secret_findings / opa.sast_findings.
// IAST/vuln service-scoped CH sections stay separate (deferred migration).
func writeThisRunSecurityFindingsBrief(b *strings.Builder, org, securityRunID string) {
	securityRunID = strings.TrimSpace(securityRunID)
	if b == nil || securityRunID == "" {
		return
	}
	if strings.TrimSpace(os.Getenv("PEER_OSA_URL")) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	payload, err := peerOSAGetSecurityRunFindings(ctx, org, securityRunID)
	if err != nil || payload == nil {
		if err != nil {
			openlogger.LogWarn("peer OSA findings brief failed", map[string]interface{}{
				"error": err.Error(), "security_run_id": securityRunID, "organization_id": org,
			})
		}
		return
	}
	findings, _ := payload["findings"].(map[string]interface{})
	if findings == nil {
		return
	}
	writeBriefFindingSection := func(title, kind string, fields []string) {
		rows := osaFindingMaps(findings, kind)
		if len(rows) == 0 {
			return
		}
		if len(rows) > 20 {
			rows = rows[:20]
		}
		projected := make([]map[string]interface{}, 0, len(rows))
		for _, row := range rows {
			m := map[string]interface{}{}
			for _, f := range fields {
				if v, ok := row[f]; ok {
					m[f] = v
				}
			}
			projected = append(projected, m)
		}
		b.WriteString(title)
		jb, _ := json.MarshalIndent(projected, "", "  ")
		b.Write(jb)
		b.WriteString("\n\n")
	}
	writeBriefFindingSection("## This-run secret findings\n", "secrets", []string{"rule", "file", "line", "severity"})
	writeBriefFindingSection("## This-run SAST findings\n", "sast", []string{"rule", "file", "line", "severity", "message"})
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
