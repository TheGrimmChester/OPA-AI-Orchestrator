package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const (
	opaReviewResumeMarker   = "<!-- opa-review:resume -->"
	opaReviewFindingIDOpen  = "<!-- opa-review:id="
	opaReviewFindingIDClose = " -->"
)

var (
	opaReviewFindingIDRe = regexp.MustCompile(`<!--\s*opa-review:id=([a-f0-9]+)\s*-->`)
	opaReviewResumeRe    = regexp.MustCompile(`<!--\s*opa-review:resume\s*-->`)
)

// opaReviewFindingKey returns a stable key for matching findings across re-runs.
// Prefer path + rule_id when present; otherwise path + normalized message/problem.
func opaReviewFindingKey(f map[string]interface{}) string {
	path, _ := f["file"].(string)
	path = normalizeFindingPath(path)
	rule := findingRuleID(f)
	text := normalizeFindingText(f)
	raw := path + "\x00" + rule + "\x00" + text
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])[:16]
}

func findingRuleID(f map[string]interface{}) string {
	for _, k := range []string{"rule_id", "rule", "check_id", "id"} {
		if s, _ := f[k].(string); strings.TrimSpace(s) != "" {
			return strings.ToLower(strings.TrimSpace(s))
		}
	}
	return ""
}

func normalizeFindingPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimPrefix(path, "./")
	return strings.ToLower(path)
}

func normalizeFindingText(f map[string]interface{}) string {
	candidates := []string{}
	if s, _ := f["problem"].(string); strings.TrimSpace(s) != "" {
		candidates = append(candidates, s)
	}
	if s, _ := f["message"].(string); strings.TrimSpace(s) != "" {
		candidates = append(candidates, s)
	}
	if s, _ := f["why"].(string); strings.TrimSpace(s) != "" {
		candidates = append(candidates, s)
	}
	joined := strings.Join(candidates, " ")
	joined = strings.ToLower(joined)
	joined = regexp.MustCompile(`\s+`).ReplaceAllString(joined, " ")
	joined = strings.TrimSpace(joined)
	if len(joined) > 240 {
		joined = joined[:240]
	}
	return joined
}

func embedOPAReviewFindingMarker(body, key string) string {
	body = strings.TrimSpace(body)
	key = strings.TrimSpace(key)
	if key == "" {
		return body
	}
	marker := opaReviewFindingIDOpen + key + opaReviewFindingIDClose
	if strings.Contains(body, marker) || opaReviewFindingIDRe.MatchString(body) {
		// Replace existing id marker if present so re-embeds stay single.
		if opaReviewFindingIDRe.MatchString(body) {
			return strings.TrimSpace(opaReviewFindingIDRe.ReplaceAllString(body, marker))
		}
		return body
	}
	return marker + "\n" + body
}

func embedOPAReviewResumeMarker(body string) string {
	body = strings.TrimSpace(body)
	if opaReviewResumeRe.MatchString(body) {
		return body + "\n"
	}
	return opaReviewResumeMarker + "\n" + body + "\n"
}

func extractOPAReviewFindingID(body string) string {
	m := opaReviewFindingIDRe.FindStringSubmatch(body)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func isOPAReviewResumeBody(body string) bool {
	if opaReviewResumeRe.MatchString(body) {
		return true
	}
	// Legacy résumés from before markers.
	trimmed := strings.TrimSpace(body)
	return strings.HasPrefix(trimmed, "## OPA Review")
}

func isOPAReviewInlineBody(body string) bool {
	if extractOPAReviewFindingID(body) != "" {
		return true
	}
	return strings.Contains(body, "**OPA Review**") || strings.Contains(body, "OPA Review ·")
}

func stripOPAReviewMarkers(body string) string {
	body = opaReviewFindingIDRe.ReplaceAllString(body, "")
	body = opaReviewResumeRe.ReplaceAllString(body, "")
	return strings.TrimSpace(body)
}

func bodiesMeaningfullyEqual(a, b string) bool {
	return stripOPAReviewMarkers(a) == stripOPAReviewMarkers(b)
}

func formatSupersededFindingBody(oldBody, sha string) string {
	core := stripOPAReviewMarkers(oldBody)
	sha = strings.TrimSpace(sha)
	if sha == "" {
		sha = "later commits"
	}
	var b strings.Builder
	if key := extractOPAReviewFindingID(oldBody); key != "" {
		b.WriteString(opaReviewFindingIDOpen + key + opaReviewFindingIDClose + "\n")
	}
	fmt.Fprintf(&b, "♻️ ~~Superseded — appears fixed as of `%s`.~~\n\n", sha)
	b.WriteString("<details><summary>Previous finding</summary>\n\n")
	b.WriteString(core)
	b.WriteString("\n\n</details>\n")
	return strings.TrimSpace(b.String())
}

func formatFixedReplyBody(sha string) string {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		sha = "later commits"
	}
	return fmt.Sprintf("✅ Fixed in later commits (as of `%s`) — OPA Review no longer reports this finding.", sha)
}

func severityEmoji(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "blocker", "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium", "moderate":
		return "🟡"
	case "low", "info", "note":
		return "🔵"
	case "fixed", "resolved", "pass", "clean":
		return "✅"
	default:
		return "⚠️"
	}
}

func confidenceEmoji(score int) string {
	// Numeric score is authoritative. Models sometimes emit confidence_label
	// "high" with a low auto_merge_confidence (e.g. 8/100); never trust the
	// label alone for the traffic-light emoji.
	switch confidenceLabelFromScore(score) {
	case "high":
		return "🟢"
	case "medium":
		return "🟡"
	default:
		return "🔴"
	}
}

// planOPAReviewCommentActions computes create/update/resolve sets for unit tests
// and the live syncer. Prior is keyed by finding id; line/body come from GitHub.
type opaReviewPriorComment struct {
	ID   int64
	Key  string
	Path string
	Line int
	Body string
}

type opaReviewCommentPlan struct {
	Create []opaReviewPlannedFinding
	Update []opaReviewPlannedUpdate
	Close  []opaReviewPriorComment
}

type opaReviewPlannedFinding struct {
	Key  string
	Path string
	Line int
	Body string
}

type opaReviewPlannedUpdate struct {
	Prior opaReviewPriorComment
	Path  string
	Line  int
	Body  string
	// Retarget means the line moved — create new + close old rather than PATCH line.
	Retarget bool
}

func planOPAReviewCommentActions(findings []map[string]interface{}, prior []opaReviewPriorComment, carried map[string]struct{}) opaReviewCommentPlan {
	if carried == nil {
		carried = map[string]struct{}{}
	}
	priorByKey := map[string]opaReviewPriorComment{}
	for _, p := range prior {
		if p.Key == "" {
			continue
		}
		// Keep the newest/first; callers should pass unique keys.
		if _, ok := priorByKey[p.Key]; !ok {
			priorByKey[p.Key] = p
		}
	}
	seen := map[string]struct{}{}
	plan := opaReviewCommentPlan{}
	for _, f := range findings {
		path, line, ok := findingFileLine(f)
		if !ok {
			continue
		}
		key := opaReviewFindingKey(f)
		body := embedOPAReviewFindingMarker(formatInlineFindingBody(f), key)
		seen[key] = struct{}{}
		if old, ok := priorByKey[key]; ok {
			if old.Path == path && old.Line == line {
				if !bodiesMeaningfullyEqual(old.Body, body) {
					plan.Update = append(plan.Update, opaReviewPlannedUpdate{
						Prior: old, Path: path, Line: line, Body: body,
					})
				}
				continue
			}
			// Line/path moved — retarget via new comment + close old.
			plan.Create = append(plan.Create, opaReviewPlannedFinding{Key: key, Path: path, Line: line, Body: body})
			plan.Update = append(plan.Update, opaReviewPlannedUpdate{
				Prior: old, Path: path, Line: line, Body: body, Retarget: true,
			})
			continue
		}
		plan.Create = append(plan.Create, opaReviewPlannedFinding{Key: key, Path: path, Line: line, Body: body})
	}
	for key, old := range priorByKey {
		if _, ok := seen[key]; ok {
			continue
		}
		// Carried-forward keys from incremental review must not mass-close.
		if _, ok := carried[key]; ok {
			continue
		}
		// Already superseded? skip re-closing.
		if strings.Contains(old.Body, "Superseded — appears fixed") || strings.Contains(old.Body, "Fixed in later commits") {
			continue
		}
		plan.Close = append(plan.Close, old)
	}
	return plan
}
