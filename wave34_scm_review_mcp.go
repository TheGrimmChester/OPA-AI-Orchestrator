package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// reviewMCPPlan describes MCP servers wired into an OPA Review worktree session.
type reviewMCPPlan struct {
	ConfigPath     string   `json:"config_path,omitempty"`
	Servers        []string `json:"servers,omitempty"`
	BrowserEnabled bool     `json:"browser_enabled"`
	PreviewURL     string   `json:"preview_url,omitempty"`
	VisualStatus   string   `json:"visual_status"` // done | skipped | not_applicable
	VisualWhy      string   `json:"visual_why"`
}

// prepareOPAReviewMCP writes .cursor/mcp.json into the worktree (or copies
// OPA_REVIEW_MCP_CONFIG) and reports whether browser visual validation can run.
// Product copy never names the underlying agent vendor.
func prepareOPAReviewMCP(checkoutRoot string, uiTouched bool, previewURL string) reviewMCPPlan {
	plan := reviewMCPPlan{
		VisualStatus: "not_applicable",
		VisualWhy:    "no UI files in diff",
		PreviewURL:   strings.TrimSpace(previewURL),
	}
	if plan.PreviewURL == "" {
		plan.PreviewURL = strings.TrimSpace(os.Getenv("OPA_REVIEW_PREVIEW_URL"))
	}
	if checkoutRoot == "" {
		plan.VisualStatus = "skipped"
		plan.VisualWhy = "no worktree"
		return plan
	}

	servers := map[string]interface{}{}
	if cfgPath := strings.TrimSpace(os.Getenv("OPA_REVIEW_MCP_CONFIG")); cfgPath != "" {
		if raw, err := os.ReadFile(cfgPath); err == nil {
			var base struct {
				MCPServers map[string]interface{} `json:"mcpServers"`
			}
			if json.Unmarshal(raw, &base) == nil && len(base.MCPServers) > 0 {
				for k, v := range base.MCPServers {
					servers[k] = v
				}
			}
		}
	}

	browserWanted := uiTouched && envOr("OPA_REVIEW_BROWSER_MCP", "1") != "0"
	browserReady, browserWhy := probeBrowserMCPReady()
	if browserWanted {
		if browserReady {
			if _, exists := servers["browser"]; !exists {
				servers["browser"] = map[string]interface{}{
					"command": "npx",
					"args":    []string{"-y", "@playwright/mcp@latest", "--headless"},
				}
			}
			plan.BrowserEnabled = true
			if plan.PreviewURL != "" {
				plan.VisualStatus = "done"
				plan.VisualWhy = "browser MCP enabled; preview URL provided — agent instructed to validate visually"
			} else {
				plan.VisualStatus = "done"
				plan.VisualWhy = "browser MCP enabled; no preview URL — agent may open static HTML/storybook paths in worktree when present"
			}
		} else {
			plan.VisualStatus = "skipped"
			plan.VisualWhy = "visual MCP unavailable — " + browserWhy
		}
	} else if uiTouched {
		plan.VisualStatus = "skipped"
		plan.VisualWhy = "browser MCP disabled (OPA_REVIEW_BROWSER_MCP=0)"
	}

	if len(servers) == 0 {
		// Still create an empty mcp.json so the CLI has a predictable project config.
		servers = map[string]interface{}{}
	}
	for name := range servers {
		plan.Servers = append(plan.Servers, name)
	}

	cursorDir := filepath.Join(checkoutRoot, ".cursor")
	_ = os.MkdirAll(cursorDir, 0o755)
	outPath := filepath.Join(cursorDir, "mcp.json")
	payload, _ := json.MarshalIndent(map[string]interface{}{"mcpServers": servers}, "", "  ")
	if err := os.WriteFile(outPath, payload, 0o644); err != nil {
		if plan.BrowserEnabled {
			plan.BrowserEnabled = false
			plan.VisualStatus = "skipped"
			plan.VisualWhy = "visual MCP unavailable — could not write .cursor/mcp.json: " + err.Error()
		}
		return plan
	}
	plan.ConfigPath = outPath
	return plan
}

func probeBrowserMCPReady() (bool, string) {
	if envOr("OPA_REVIEW_BROWSER_MCP", "1") == "0" {
		return false, "OPA_REVIEW_BROWSER_MCP=0"
	}
	if _, err := exec.LookPath("npx"); err != nil {
		return false, "npx not on PATH (install Node.js in the Agent image, or mount OPA_REVIEW_MCP_CONFIG)"
	}
	if _, err := exec.LookPath("node"); err != nil {
		return false, "node not on PATH"
	}
	// Playwright browsers are optional at probe time; @playwright/mcp downloads on first use
	// when network is allowed. Headless Chromium deps may still be missing in slim images.
	if envOr("OPA_REVIEW_BROWSER_DEPS_OK", "") == "0" {
		return false, "OPA_REVIEW_BROWSER_DEPS_OK=0 (Chromium/system libs not provisioned)"
	}
	return true, "npx+node present"
}

func formatVisualValidationLine(plan reviewMCPPlan) string {
	status := nz(plan.VisualStatus, "skipped")
	why := strings.TrimSpace(plan.VisualWhy)
	if why == "" {
		return fmt.Sprintf("**Visual validation:** %s", status)
	}
	return fmt.Sprintf("**Visual validation:** %s — %s", status, why)
}

func opaReviewPreviewURL(job *scmJob) string {
	if job == nil {
		return strings.TrimSpace(os.Getenv("OPA_REVIEW_PREVIEW_URL"))
	}
	if job.Summary != nil {
		if u, _ := job.Summary["preview_url"].(string); strings.TrimSpace(u) != "" {
			return strings.TrimSpace(u)
		}
	}
	return strings.TrimSpace(os.Getenv("OPA_REVIEW_PREVIEW_URL"))
}
