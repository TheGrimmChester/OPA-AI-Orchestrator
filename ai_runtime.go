package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Shared AI completion runtime used by /api/ai/tasks and (optionally) OPA Review HTTP fallback.

type aiCompleteRequest struct {
	System    string
	Prompt    string
	Messages  []aiMessage
	MaxTokens int
	JSONMode  bool
	Timeout   time.Duration
	WorkDir   string // CLI only
}

type aiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiCompleteResult struct {
	Text     string
	Provider string
	Model    string
}

var (
	errAINoProvider = errors.New("no AI provider configured — set OpenAI-compatible, Anthropic-compatible, or CLI agent in AI settings")
	errAITimeout    = errors.New("AI completion timed out")
)

func aiDefaultTimeout() time.Duration {
	sec := atoiDefault(envOr("OPA_AI_TIMEOUT_SEC", "60"), 60)
	if sec < 5 {
		sec = 5
	}
	if sec > 300 {
		sec = 300
	}
	return time.Duration(sec) * time.Second
}

func aiDefaultMaxTokens() int {
	return clampInt(atoiDefault(envOr("OPA_AI_MAX_TOKENS", "2048"), 2048), 16, 8192)
}

// ResolveProvider picks a provider for a task kind.
// opa_review / auto_fix → CLI Cursor first, then HTTP fallback.
// dashboard kinds → OpenAI then Anthropic (honoring default_provider when set).
func ResolveProvider(taskKind string, doc aiSettingsDoc) []string {
	kind := strings.ToLower(strings.TrimSpace(taskKind))
	switch kind {
	case "opa_review", "auto_fix", "cli":
		out := []string{}
		if doc.CLICursor.Enabled && (doc.CLICursor.APIKey != "" || strings.TrimSpace(os.Getenv("CURSOR_API_KEY")) != "") {
			out = append(out, aiProviderCLICursor)
		}
		out = append(out, httpProvidersPrefer(doc)...)
		return uniqueStrings(out)
	default:
		// generic, metrics_explain, trace_analyze, …
		prefs := httpProvidersPrefer(doc)
		if def := strings.TrimSpace(doc.DefaultProvider); def != "" && def != "auto" {
			prefs = prependProvider(prefs, def)
		}
		return prefs
	}
}

func httpProvidersPrefer(doc aiSettingsDoc) []string {
	out := []string{}
	openOK := doc.OpenAI.Enabled && doc.OpenAI.APIKey != ""
	anthOK := doc.Anthropic.Enabled && doc.Anthropic.APIKey != ""
	// Env-only keys still count via applyAIEnvOverrides (Enabled flipped on)
	if !openOK && doc.OpenAI.APIKey != "" {
		openOK = true
	}
	if !anthOK && doc.Anthropic.APIKey != "" {
		anthOK = true
	}
	if openOK {
		out = append(out, aiProviderOpenAI)
	}
	if anthOK {
		out = append(out, aiProviderAnthropic)
	}
	return out
}

func prependProvider(list []string, first string) []string {
	out := []string{first}
	for _, p := range list {
		if p != first {
			out = append(out, p)
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// Complete runs the first available provider from ResolveProvider(taskKind).
func Complete(ctx context.Context, taskKind string, req aiCompleteRequest) (*aiCompleteResult, error) {
	doc := getAISettings("", "")
	providers := ResolveProvider(taskKind, doc)
	if len(providers) == 0 {
		return nil, errAINoProvider
	}
	if req.MaxTokens <= 0 {
		req.MaxTokens = aiDefaultMaxTokens()
	}
	if req.Timeout <= 0 {
		req.Timeout = aiDefaultTimeout()
	}
	var lastErr error
	for _, p := range providers {
		res, err := completeWithProvider(ctx, p, doc, req)
		if err == nil {
			return res, nil
		}
		lastErr = err
		// CLI unavailable → try HTTP fallback
		if p == aiProviderCLICursor {
			continue
		}
	}
	if lastErr == nil {
		lastErr = errAINoProvider
	}
	return nil, lastErr
}

func completeWithProvider(ctx context.Context, provider string, doc aiSettingsDoc, req aiCompleteRequest) (*aiCompleteResult, error) {
	switch provider {
	case aiProviderOpenAI:
		return completeOpenAI(ctx, doc, req)
	case aiProviderAnthropic:
		return completeAnthropic(ctx, doc, req)
	case aiProviderCLICursor:
		return completeCLI(ctx, doc, req)
	default:
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
}

func completeOpenAI(ctx context.Context, doc aiSettingsDoc, req aiCompleteRequest) (*aiCompleteResult, error) {
	key := doc.OpenAI.APIKey
	if key == "" {
		return nil, errors.New("openai-compatible: api key not set")
	}
	base := strings.TrimRight(nz(doc.OpenAI.BaseURL, "https://api.openai.com/v1"), "/")
	model := nz(doc.OpenAI.Model, "gpt-4o-mini")
	msgs := buildChatMessages(req)
	body := map[string]interface{}{
		"model":       model,
		"messages":    msgs,
		"max_tokens":  req.MaxTokens,
		"temperature": 0.2,
	}
	if req.JSONMode {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	raw, _ := json.Marshal(body)
	url := base + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+key)
	client := &http.Client{Timeout: req.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, errAITimeout
		}
		return nil, fmt.Errorf("openai-compatible: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openai-compatible: HTTP %d: %s", resp.StatusCode, truncateStr(string(respBody), 300))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("openai-compatible: bad response: %w", err)
	}
	text := ""
	if len(parsed.Choices) > 0 {
		text = parsed.Choices[0].Message.Content
	}
	return &aiCompleteResult{Text: text, Provider: aiProviderOpenAI, Model: nz(parsed.Model, model)}, nil
}

func completeAnthropic(ctx context.Context, doc aiSettingsDoc, req aiCompleteRequest) (*aiCompleteResult, error) {
	key := doc.Anthropic.APIKey
	if key == "" {
		return nil, errors.New("anthropic-compatible: api key not set")
	}
	base := strings.TrimRight(nz(doc.Anthropic.BaseURL, "https://api.anthropic.com"), "/")
	model := nz(doc.Anthropic.Model, "claude-sonnet-4-20250514")
	msgs := []map[string]string{}
	if len(req.Messages) > 0 {
		for _, m := range req.Messages {
			role := m.Role
			if role == "system" {
				continue
			}
			if role != "assistant" {
				role = "user"
			}
			msgs = append(msgs, map[string]string{"role": role, "content": m.Content})
		}
	} else {
		msgs = append(msgs, map[string]string{"role": "user", "content": req.Prompt})
	}
	body := map[string]interface{}{
		"model":      model,
		"max_tokens": req.MaxTokens,
		"messages":   msgs,
	}
	system := req.System
	if system == "" {
		for _, m := range req.Messages {
			if m.Role == "system" {
				system = m.Content
				break
			}
		}
	}
	if system != "" {
		body["system"] = system
	}
	raw, _ := json.Marshal(body)
	url := base + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", key)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	client := &http.Client{Timeout: req.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, errAITimeout
		}
		return nil, fmt.Errorf("anthropic-compatible: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("anthropic-compatible: HTTP %d: %s", resp.StatusCode, truncateStr(string(respBody), 300))
	}
	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("anthropic-compatible: bad response: %w", err)
	}
	var b strings.Builder
	for _, c := range parsed.Content {
		if c.Type == "text" || c.Text != "" {
			b.WriteString(c.Text)
		}
	}
	return &aiCompleteResult{Text: b.String(), Provider: aiProviderAnthropic, Model: nz(parsed.Model, model)}, nil
}

func completeCLI(ctx context.Context, doc aiSettingsDoc, req aiCompleteRequest) (*aiCompleteResult, error) {
	key := doc.CLICursor.APIKey
	if key == "" {
		return nil, errors.New("cli agent: api key not set")
	}
	bin := nz(doc.CLICursor.Bin, envOr("OPA_CURSOR_AGENT_BIN", "agent"))
	model := nz(doc.CLICursor.Model, "auto")
	prompt := req.Prompt
	if prompt == "" && len(req.Messages) > 0 {
		var parts []string
		for _, m := range req.Messages {
			parts = append(parts, m.Role+": "+m.Content)
		}
		prompt = strings.Join(parts, "\n")
	}
	if req.System != "" {
		prompt = req.System + "\n\n" + prompt
	}
	args := []string{"-p", "--trust", "--output-format", "text", "--model", model}
	if doc.CLICursor.Force || envOr("OPA_CURSOR_AGENT_FORCE", "0") == "1" {
		args = append(args, "--force")
	}
	args = append(args, prompt)
	cmd := exec.CommandContext(ctx, bin, args...)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	cmd.Env = append(os.Environ(), "CURSOR_API_KEY="+key, "NO_OPEN_BROWSER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, errAITimeout
		}
		return nil, fmt.Errorf("cli agent: %w (%s)", err, truncateStr(string(out), 200))
	}
	return &aiCompleteResult{Text: strings.TrimSpace(string(out)), Provider: aiProviderCLICursor, Model: model}, nil
}

func buildChatMessages(req aiCompleteRequest) []map[string]string {
	out := []map[string]string{}
	if req.System != "" {
		out = append(out, map[string]string{"role": "system", "content": req.System})
	}
	if len(req.Messages) > 0 {
		for _, m := range req.Messages {
			out = append(out, map[string]string{"role": m.Role, "content": m.Content})
		}
		return out
	}
	out = append(out, map[string]string{"role": "user", "content": req.Prompt})
	return out
}

// resolveCLICursorConfig returns key/bin/model/force from unified AI settings.
func resolveCLICursorConfig(org, proj string) (key, bin, model string, force bool) {
	doc := getAISettings(org, proj)
	key = doc.CLICursor.APIKey
	bin = nz(doc.CLICursor.Bin, envOr("OPA_CURSOR_AGENT_BIN", "agent"))
	model = nz(doc.CLICursor.Model, envOr("OPA_CURSOR_MODEL", "auto"))
	force = doc.CLICursor.Force || envOr("OPA_CURSOR_AGENT_FORCE", "0") == "1"
	return
}
