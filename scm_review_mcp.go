package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	openlogger "github.com/TheGrimmChester/open-logger-go"
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

// mcpServerAllowlist is the only set of server names mergeable from
// OPA_REVIEW_MCP_CONFIG. Anything else is dropped.
var mcpServerAllowlist = map[string]bool{
	"browser": true,
}

// prepareOPAReviewMCP writes mcp.json to a host-owned overlay (never into the
// attacker-writable checkout) and reports whether browser visual validation can run.
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
					if !mcpServerAllowlist[k] {
						openlogger.LogWarn("prepareOPAReviewMCP: dropped non-allowlisted MCP server", map[string]interface{}{"name": k})
						continue
					}
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
				// Pin the package version — never @latest at runtime.
				servers["browser"] = map[string]interface{}{
					"command": "npx",
					"args":    []string{"-y", "@playwright/mcp@0.0.39", "--headless"},
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
		servers = map[string]interface{}{}
	}
	for name := range servers {
		plan.Servers = append(plan.Servers, name)
	}

	outPath, err := writeReviewMCPOverlay(checkoutRoot, servers)
	if err != nil {
		if plan.BrowserEnabled {
			plan.BrowserEnabled = false
			plan.VisualStatus = "skipped"
			plan.VisualWhy = "visual MCP unavailable — could not write mcp overlay: " + err.Error()
		}
		return plan
	}
	plan.ConfigPath = outPath
	return plan
}

// writeReviewMCPOverlay writes mcp.json under scm-state, never into the PR tree.
// A checkout whose .cursor is a symlink to scm-state must not be able to capture
// ai-settings.json via TOCTOU on MkdirAll/WriteFile inside the worktree.
func writeReviewMCPOverlay(checkoutRoot string, servers map[string]interface{}) (string, error) {
	// Refuse to write through a symlinked .cursor in the checkout (defense in depth
	// even though we no longer write there).
	if checkoutRoot != "" {
		cursorDir := filepath.Join(checkoutRoot, ".cursor")
		if fi, err := os.Lstat(cursorDir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			openlogger.LogWarn("prepareOPAReviewMCP: refusing checkout .cursor symlink", map[string]interface{}{
				"path": cursorDir,
			})
		}
	}

	key := strings.ReplaceAll(strings.TrimSpace(checkoutRoot), string(os.PathSeparator), "_")
	if key == "" {
		key = "default"
	}
	if len(key) > 80 {
		key = key[len(key)-80:]
	}
	overlayDir := filepath.Join(scmStateDir(), "mcp-overlay", key, ".cursor")
	if err := os.MkdirAll(overlayDir, 0o700); err != nil {
		return "", err
	}
	outPath := filepath.Join(overlayDir, "mcp.json")
	payload, err := json.MarshalIndent(map[string]interface{}{"mcpServers": servers}, "", "  ")
	if err != nil {
		return "", err
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return outPath, nil
}

func probeBrowserMCPReady() (bool, string) {
	if envOr("OPA_REVIEW_BROWSER_MCP", "1") == "0" {
		return false, "OPA_REVIEW_BROWSER_MCP=0"
	}
	if _, err := exec.LookPath("npx"); err != nil {
		return false, "required missing: npx not on PATH (orchestrator image must include Node.js)"
	}
	if _, err := exec.LookPath("node"); err != nil {
		return false, "required missing: node not on PATH"
	}
	// Image must ship Chromium + system libs and set this to 1 (see Dockerfile).
	if envOr("OPA_REVIEW_BROWSER_DEPS_OK", "0") != "1" {
		return false, "required missing: OPA_REVIEW_BROWSER_DEPS_OK=1 (Playwright Chromium/system libs not provisioned)"
	}
	return true, "node+npx+browser deps ready"
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
