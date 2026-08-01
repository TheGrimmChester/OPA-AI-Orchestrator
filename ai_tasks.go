package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// POST /api/ai/tasks — dashboard-wide AI task kinds (stubs pack input; Complete() via HTTP providers).

func handleAITasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	var body struct {
		Kind         string                 `json:"kind"`
		Input        interface{}            `json:"input"`
		ContextRefs  map[string]interface{} `json:"context_refs"`
		System       string                 `json:"system"`
		MaxTokens    int                    `json:"max_tokens"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(body.Kind))
	if kind == "" {
		kind = "generic"
	}
	prompt, system, err := packAITaskPrompt(kind, body.Input, body.ContextRefs, body.System)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	res, err := Complete(r.Context(), kind, aiCompleteRequest{
		System:    system,
		Prompt:    prompt,
		MaxTokens: body.MaxTokens,
	})
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"ok": false, "kind": kind, "error": err.Error(),
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "kind": kind, "text": res.Text, "provider": res.Provider, "model": res.Model,
	})
}

func packAITaskPrompt(kind string, input interface{}, refs map[string]interface{}, systemOverride string) (prompt, system string, err error) {
	inputJSON, _ := json.MarshalIndent(input, "", "  ")
	refsJSON := ""
	if len(refs) > 0 {
		b, _ := json.MarshalIndent(refs, "", "  ")
		refsJSON = string(b)
	}
	switch kind {
	case "generic":
		system = nz(systemOverride, "You are a helpful assistant for an observability platform. Be concise and accurate.")
		prompt = string(inputJSON)
		if prompt == "" || prompt == "null" {
			prompt = fmt.Sprint(input)
		}
		if refsJSON != "" {
			prompt += "\n\nContext refs:\n" + refsJSON
		}
	case "metrics_explain":
		system = nz(systemOverride, "You explain observability metrics for engineers. Focus on anomalies, likely causes, and next checks. Do not invent data.")
		prompt = "Explain these metrics / stats. Highlight what looks unusual and what to inspect next.\n\n" + string(inputJSON)
		if refsJSON != "" {
			prompt += "\n\nContext refs (service/trace ids may be resolved later via Agent):\n" + refsJSON
		}
	case "trace_analyze":
		system = nz(systemOverride, "You analyze distributed traces for latency and errors. Be specific about spans and likely bottlenecks. Do not invent spans.")
		prompt = "Analyze this trace summary. Identify slow or failing spans and suggest concrete next steps.\n\n" + string(inputJSON)
		if refsJSON != "" {
			prompt += "\n\nContext refs:\n" + refsJSON
		}
	default:
		return "", "", fmt.Errorf("unknown kind %q (supported: generic, metrics_explain, trace_analyze)", kind)
	}
	if strings.TrimSpace(prompt) == "" || prompt == "null" {
		return "", "", fmt.Errorf("input required")
	}
	return prompt, system, nil
}
