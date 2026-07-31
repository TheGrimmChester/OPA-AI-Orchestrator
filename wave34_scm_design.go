package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Design / UI enforcement for AI PR review when the diff touches frontend files.

var uiPathHints = []string{
	".jsx", ".tsx", ".css", ".scss", ".sass", ".less", ".vue", ".svelte",
	"/components/", "/src/pages/", "/src/theme/", "/theme/", "/design/",
	"/styles/", "tokens.css", "ui.css",
}

var designTagNames = map[string]bool{
	"design": true, "ui": true, "design-system": true, "design_system": true, "frontend": true,
}

func diffTouchesUI(diff string) bool {
	if diff == "" {
		return false
	}
	low := strings.ToLower(diff)
	for _, line := range strings.Split(low, "\n") {
		if !strings.HasPrefix(line, "+++ ") && !strings.HasPrefix(line, "--- ") && !strings.HasPrefix(line, "diff --git") {
			continue
		}
		for _, h := range uiPathHints {
			if strings.Contains(line, h) {
				return true
			}
		}
	}
	for _, h := range uiPathHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

func reviewContextTags(rc opaReviewContext) []string {
	tags := []string{}
	if rc.TagsJSON == "" || rc.TagsJSON == "[]" {
		return tags
	}
	_ = json.Unmarshal([]byte(rc.TagsJSON), &tags)
	return tags
}

func isDesignContext(rc opaReviewContext) bool {
	for _, t := range reviewContextTags(rc) {
		if designTagNames[strings.ToLower(strings.TrimSpace(t))] {
			return true
		}
	}
	title := strings.ToLower(rc.Title)
	return strings.Contains(title, "design enforcement") ||
		strings.Contains(title, "design system") ||
		(strings.Contains(title, "design") && strings.Contains(title, "ui"))
}

func filterContextsForUI(applied appliedReviewContexts, uiTouched bool) appliedReviewContexts {
	if !uiTouched {
		return applied
	}
	out := applied
	out.Primary = prioritizeDesignContexts(applied.Primary)
	out.Linked = prioritizeDesignContexts(applied.Linked)
	out.Org = prioritizeDesignContexts(applied.Org)
	return out
}

func prioritizeDesignContexts(in []opaReviewContext) []opaReviewContext {
	design, other := []opaReviewContext{}, []opaReviewContext{}
	for _, rc := range in {
		if isDesignContext(rc) {
			design = append(design, rc)
		} else {
			other = append(other, rc)
		}
	}
	return append(design, other...)
}

func worktreeLooksFrontend(root string) bool {
	if root == "" {
		return false
	}
	checks := []string{
		"package.json",
		filepath.Join("src", "theme"),
		filepath.Join("src", "components", "ui"),
		filepath.Join("src", "pages"),
		"vite.config.js", "vite.config.ts", "next.config.js",
	}
	for _, rel := range checks {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			return true
		}
	}
	return false
}

// packDesignEnforcementFromWorktree extracts findable design-system signals only.
// Honesty: if nothing is found, returns a short note — never invents a brand system.
func packDesignEnforcementFromWorktree(root string) string {
	if root == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Design enforcement (from worktree)\n\n")
	b.WriteString("Enforce consistency with the **existing** design system in this repository. ")
	b.WriteString("Do **not** invent a new look, brand, or token set. ")
	b.WriteString("Flag violations with rule `design-enforcement` and file:line when possible.\n\n")

	found := false
	type hit struct {
		path string
		note string
	}
	candidates := []hit{
		{filepath.Join("src", "theme", "tokens.css"), "CSS design tokens / variables"},
		{filepath.Join("src", "theme", "ui.css"), "UI theme stylesheet"},
		{filepath.Join("src", "theme", "light.css"), "Light theme"},
		{filepath.Join("src", "theme", "format.js"), "Formatting helpers"},
		{filepath.Join("src", "components", "ui", "index.js"), "Shared UI component barrel"},
		{filepath.Join("src", "components", "ui", "Panel.jsx"), "Panel primitive"},
		{filepath.Join("src", "components", "ui", "DataTable.jsx"), "DataTable primitive"},
		{filepath.Join("src", "components", "ui", "Badges.jsx"), "Badge / StatusPill primitives"},
		{filepath.Join("src", "components", "ui", "Controls.jsx"), "Form controls"},
		{"theme/tokens.css", "CSS design tokens"},
		{"components/ui", "UI kit directory"},
	}
	b.WriteString("### Findable conventions (cite these files)\n")
	for _, c := range candidates {
		p := filepath.Join(root, c.path)
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		found = true
		fmt.Fprintf(&b, "- `%s` — %s\n", c.path, c.note)
		if !st.IsDir() && st.Size() < 12000 {
			if raw, rerr := os.ReadFile(p); rerr == nil {
				excerpt := truncateStr(string(raw), 1800)
				if strings.Contains(c.path, ".css") {
					vars := extractCSSVarNames(excerpt)
					if len(vars) > 0 {
						fmt.Fprintf(&b, "  - tokens sample: %s\n", strings.Join(vars, ", "))
					}
				}
				if strings.HasSuffix(c.path, "index.js") || strings.HasSuffix(c.path, "index.ts") {
					exports := extractExportNames(excerpt)
					if len(exports) > 0 {
						fmt.Fprintf(&b, "  - exports: %s\n", strings.Join(exports, ", "))
					}
				}
			}
		}
	}
	if !found {
		b.WriteString("_No theme/ or components/ui conventions found in this worktree. ")
		b.WriteString("Do not claim a brand system exists; only flag clear inconsistencies with patterns already in the diff/repo._\n\n")
		return b.String()
	}

	b.WriteString("\n### Reviewer rules (when UI files change)\n")
	b.WriteString("- Reuse existing components from `components/ui` (or the repo’s UI kit) instead of one-off card/hero layouts.\n")
	b.WriteString("- Prefer existing CSS variables / tokens over hardcoded colors, new gradient themes, or default Inter/Roboto stacks unless already used here.\n")
	b.WriteString("- Match typography, spacing, and density already used on sibling pages.\n")
	b.WriteString("- Avoid generic AI-slop UI (purple-on-white gradients, glow pills, floating badge clutter) unless those patterns already exist in this repo.\n")
	b.WriteString("- Findings: `{\"rule\":\"design-enforcement\",\"severity\":\"medium\",\"file\":\"…\",\"line\":N,\"message\":\"…\"}`\n\n")
	return b.String()
}

func extractCSSVarNames(css string) []string {
	re := regexp.MustCompile(`--[a-zA-Z0-9_-]+`)
	seen := map[string]bool{}
	out := []string{}
	for _, m := range re.FindAllString(css, -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
		if len(out) >= 24 {
			break
		}
	}
	return out
}

func extractExportNames(js string) []string {
	out := []string{}
	seen := map[string]bool{}
	brace := regexp.MustCompile(`export\s*\{([^}]+)\}`)
	if m := brace.FindStringSubmatch(js); len(m) > 1 {
		for _, part := range strings.Split(m[1], ",") {
			name := strings.TrimSpace(strings.Split(part, " as ")[0])
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	re := regexp.MustCompile(`(?m)^export\s+(?:async\s+)?(?:function|const|class)\s+([A-Za-z0-9_]+)`)
	for _, m := range re.FindAllStringSubmatch(js, -1) {
		name := m[1]
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func designEnforcementPromptExtra(uiTouched bool) string {
	if !uiTouched {
		return ""
	}
	return `
## Design enforcement mode (UI files changed)
This PR touches UI/component/theme files. In addition to security review:
1. Load and cite the worktree design system files listed above (theme tokens, components/ui).
2. Enforce consistency with **existing** patterns only — typography, spacing, colors, shared components.
3. Do not propose a new visual brand. If no design system files exist, say so and only flag clear contradictions with nearby code.
4. Report design violations as findings with rule "design-enforcement" and file/line when possible.
`
}

func heuristicDesignFindings(diff string) []map[string]interface{} {
	if !diffTouchesUI(diff) {
		return nil
	}
	out := []map[string]interface{}{}
	low := strings.ToLower(diff)
	checks := []struct {
		needle string
		msg    string
	}{
		{"font-family: inter", "Introducing Inter font — prefer existing theme typography unless already used in-repo"},
		{"font-family: roboto", "Introducing Roboto — prefer existing theme typography unless already used in-repo"},
		{"purple", "Purple accent/gradient often signals generic AI UI — verify against existing tokens"},
		{"linear-gradient", "New gradient theme — verify it uses existing CSS variables, not a one-off palette"},
		{"box-shadow: 0 0", "Glow/multi-layer shadow — check against existing elevation patterns"},
	}
	for _, c := range checks {
		if strings.Contains(low, c.needle) {
			out = append(out, map[string]interface{}{
				"severity": "medium", "file": "diff", "line": 1,
				"message": c.msg, "rule": "design-enforcement",
			})
		}
	}
	return out
}

func generateDesignEnforcementSection(root, seed string) string {
	pack := packDesignEnforcementFromWorktree(root)
	if pack == "" && !worktreeLooksFrontend(root) && !strings.Contains(strings.ToLower(seed), "react") && !strings.Contains(strings.ToLower(seed), "vite") {
		return ""
	}
	if pack == "" {
		return "## Design enforcement\n\nRepository appears frontend-related but no theme/ui kit files were found in the worktree. Document only conventions discoverable from the codebase; do not invent tokens or brand rules.\n"
	}
	return pack
}
