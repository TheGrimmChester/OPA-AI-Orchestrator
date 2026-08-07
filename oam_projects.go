package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// registerOAMProjectsMux exposes GET /api/oam/projects for the dashboard switcher.
func registerOAMProjectsMux(mux *http.ServeMux, authView func(string, http.HandlerFunc)) {
	authView("/api/oam/projects", handleOAMProjects)
}

func peerOAMBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("PEER_OAM_URL")), "/")
}

// handleOAMProjects proxies GET OAM /api/projects for the family project switcher.
//
// Fail-closed hook (review jobs): before enqueueing work for a concrete OAM
// directory id, call the same upstream with ?product=ora and reject when the
// id is absent from projects[]. Skip when PEER_OAM_URL is unset or the project
// header is empty/"all". Enablement writes stay on OAM only.
func handleOAMProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	base := peerOAMBaseURL()
	if base == "" {
		writeJSON(w, map[string]interface{}{
			"projects":         []interface{}{},
			"peer_unavailable": true,
			"peer":             "oam-api",
			"note":             "Set PEER_OAM_URL to discover OAM directory projects.",
		})
		return
	}
	target := oamProjectsTarget(base, r.URL.Query())
	raw, status, err := proxyOAMProjectsGET(r.Context(), target, r)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"projects": []interface{}{},
			"error":    err.Error(),
			"peer":     "oam-api",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(aliasDirectoryIDs(raw, "projects", "project_id"))
}

func oamProjectsTarget(base string, q url.Values) string {
	target := strings.TrimRight(base, "/") + "/api/projects"
	vals := url.Values{}
	if org := strings.TrimSpace(q.Get("organization_id")); org != "" && !strings.EqualFold(org, "all") {
		vals.Set("organization_id", org)
	}
	if product := strings.TrimSpace(q.Get("product")); product != "" {
		vals.Set("product", product)
	}
	if enc := vals.Encode(); enc != "" {
		target += "?" + enc
	}
	return target
}

func aliasDirectoryIDs(raw []byte, listKey, aliasKey string) []byte {
	var payload map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return raw
	}
	list, ok := payload[listKey].([]interface{})
	if !ok {
		return raw
	}
	for _, item := range list {
		row, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if _, exists := row[aliasKey]; exists {
			continue
		}
		if id, ok := row["id"].(string); ok && id != "" {
			row[aliasKey] = id
		}
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return raw
	}
	return out
}

func proxyOAMProjectsGET(ctx context.Context, target string, r *http.Request) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	} else if c, err := r.Cookie(openauth.CookieName); err == nil && c.Value != "" {
		req.Header.Set("Authorization", "Bearer "+c.Value)
	}
	for _, h := range []string{"X-Organization-ID", "X-Project-ID", "X-Tenant-User-ID"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

// requireEnabledOAMProject rejects when PEER_OAM_URL is set and the concrete
// X-Project-ID is absent from GET OAM /api/projects?product=<code>.
func requireEnabledOAMProject(r *http.Request, product string) (status int, msg string) {
	base := peerOAMBaseURL()
	if base == "" {
		return 0, ""
	}
	proj := strings.TrimSpace(r.Header.Get("X-Project-ID"))
	if proj == "" || strings.EqualFold(proj, "all") {
		return 0, ""
	}
	ok, err := oamDirectoryHasProject(r.Context(), r, base, product, proj)
	if err != nil {
		return 503, "could not verify project enablement with OAM: " + err.Error()
	}
	if !ok {
		return 403, fmt.Sprintf("project %q is disabled for product %q (OAM disabled_products)", proj, product)
	}
	return 0, ""
}

func oamDirectoryHasProject(ctx context.Context, r *http.Request, base, product, projectID string) (bool, error) {
	q := url.Values{}
	q.Set("product", product)
	if org := strings.TrimSpace(r.Header.Get("X-Organization-ID")); org != "" && !strings.EqualFold(org, "all") {
		q.Set("organization_id", org)
	}
	target := oamProjectsTarget(base, q)
	raw, status, err := proxyOAMProjectsGET(ctx, target, r)
	if err != nil {
		return false, err
	}
	if status < 200 || status >= 300 {
		return false, fmt.Errorf("oam returned %d", status)
	}
	var payload struct {
		Projects []struct {
			ID        string `json:"id"`
			ProjectID string `json:"project_id"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return false, err
	}
	for _, row := range payload.Projects {
		id := strings.TrimSpace(row.ID)
		if id == "" {
			id = strings.TrimSpace(row.ProjectID)
		}
		if id == projectID {
			return true, nil
		}
	}
	return false, nil
}
