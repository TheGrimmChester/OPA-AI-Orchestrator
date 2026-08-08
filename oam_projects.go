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
	openclient "github.com/TheGrimmChester/open-client-go"
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

type oamDirectoryProject struct {
	ID             string   `json:"id"`
	ProjectID      string   `json:"project_id"`
	OrganizationID string   `json:"organization_id"`
	ExternalKey    string   `json:"external_key"`
	ConnectorIDs   []string `json:"connector_ids"`
}

func (p oamDirectoryProject) directoryID() string {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		id = strings.TrimSpace(p.ProjectID)
	}
	return id
}

func normalizeRepoFullName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// listOAMDirectoryProjects fetches GET OAM /api/projects?product=… (optional org).
// Uses a service JWT when OPEN_SERVICE_JWT_SECRET is set (open-client PeerJSON).
func listOAMDirectoryProjects(ctx context.Context, org, product string) ([]oamDirectoryProject, error) {
	base := peerOAMBaseURL()
	if base == "" {
		return nil, fmt.Errorf("PEER_OAM_URL unset")
	}
	product = strings.TrimSpace(product)
	if product == "" {
		return nil, fmt.Errorf("product required")
	}
	q := url.Values{}
	q.Set("product", product)
	org = strings.TrimSpace(org)
	if org != "" && !strings.EqualFold(org, "all") {
		q.Set("organization_id", org)
	}
	path := "/api/projects"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	cfg := openclient.PeerFromEnv("PEER_OAM_URL", "ora-api", "oam-api", "orgs:read")
	cfg.OrgID = org
	var payload struct {
		Projects []oamDirectoryProject `json:"projects"`
	}
	if err := openclient.PeerJSON(ctx, cfg, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}
	return payload.Projects, nil
}

// lookupOAMProjectByExternalKey finds an ora-enabled OAM project whose
// external_key matches owner/repo (case-insensitive). Returns (nil, nil) on miss.
func lookupOAMProjectByExternalKey(ctx context.Context, org, repoFullName string) (*oamDirectoryProject, error) {
	want := normalizeRepoFullName(repoFullName)
	if want == "" || !strings.Contains(want, "/") {
		return nil, nil
	}
	rows, err := listOAMDirectoryProjects(ctx, org, "ora")
	if err != nil {
		return nil, err
	}
	for i := range rows {
		row := &rows[i]
		if normalizeRepoFullName(row.ExternalKey) == want {
			return row, nil
		}
	}
	return nil, nil
}

func resolveConnectorOnOAMProject(proj *oamDirectoryProject, connectorID string) (string, string) {
	if proj == nil {
		return "", "no OAM project with ora enabled for repo"
	}
	connectorID = strings.TrimSpace(connectorID)
	bound := make([]string, 0, len(proj.ConnectorIDs))
	for _, id := range proj.ConnectorIDs {
		if t := strings.TrimSpace(id); t != "" {
			bound = append(bound, t)
		}
	}
	if connectorID != "" {
		for _, id := range bound {
			if id == connectorID {
				return connectorID, ""
			}
		}
		return "", "connector not bound on OAM project"
	}
	switch len(bound) {
	case 0:
		return "", "project has no connector_ids"
	case 1:
		return bound[0], ""
	default:
		return "", "connector not bound on OAM project"
	}
}

// ensureWatchedFromOAM upserts a runtime watched row when an OAM project has
// product ora enabled and external_key matches the repo. Returns a skip reason
// (no invent) when there is no match. No-op path when PEER_OAM_URL is unset
// should be handled by the caller (solo lab keeps auto-watch).
func ensureWatchedFromOAM(org, repo, connectorID string) (*opaWatchedRepo, *opaConnector, string) {
	if peerOAMBaseURL() == "" {
		return nil, nil, "PEER_OAM_URL unset"
	}
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return nil, nil, "repo required"
	}
	org = strings.TrimSpace(org)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	proj, err := lookupOAMProjectByExternalKey(ctx, org, repo)
	if err != nil {
		return nil, nil, "could not verify OAM project enablement: " + err.Error()
	}
	if proj == nil {
		return nil, nil, "no OAM project with ora enabled for repo"
	}
	resolvedConn, skip := resolveConnectorOnOAMProject(proj, connectorID)
	if skip != "" {
		return nil, nil, skip
	}
	conn := getOrHydrateConnector(resolvedConn)
	if conn == nil {
		return nil, nil, "connector not found locally"
	}
	projID := proj.directoryID()
	orgID := org
	if orgID == "" {
		orgID = strings.TrimSpace(proj.OrganizationID)
	}
	if orgID == "" {
		orgID = strings.TrimSpace(conn.OrganizationID)
	}
	if projID == "" {
		projID = strings.TrimSpace(conn.ProjectID)
	}
	// Idempotent: leave an already-enabled watch as-is (do not clobber checks).
	key := conn.ID + "|" + repo
	if v, ok := watchedLive.Load(key); ok {
		if wr, ok := v.(*opaWatchedRepo); ok && wr.Enabled {
			return wr, conn, ""
		}
	}
	wr := upsertWatched(orgID, projID, conn.ID, repo, "", true, defaultWatchedChecks(), "auto", "high", false, false, 0)
	return wr, conn, ""
}

func oamDirectoryHasProject(ctx context.Context, r *http.Request, base, product, projectID string) (bool, error) {
	row, err := lookupOAMDirectoryProject(ctx, r, base, product, projectID)
	if err != nil {
		return false, err
	}
	return row != nil, nil
}

// lookupOAMDirectoryProject returns the product-filtered OAM directory row, or
// (nil, nil) when the id is absent / disabled for the product.
func lookupOAMDirectoryProject(ctx context.Context, r *http.Request, base, product, projectID string) (*oamDirectoryProject, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("project id required")
	}
	q := url.Values{}
	q.Set("product", product)
	if org := strings.TrimSpace(r.Header.Get("X-Organization-ID")); org != "" && !strings.EqualFold(org, "all") {
		q.Set("organization_id", org)
	}
	target := oamProjectsTarget(base, q)
	raw, status, err := proxyOAMProjectsGET(ctx, target, r)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("oam returned %d", status)
	}
	var payload struct {
		Projects []oamDirectoryProject `json:"projects"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	for i := range payload.Projects {
		row := &payload.Projects[i]
		if row.directoryID() == projectID {
			return row, nil
		}
	}
	return nil, nil
}

// resolveConnectorFromOAMProject fills connector_id from the OAM directory when
// the client omitted it. Fail closed when a concrete project has no connector_ids.
// Skips (returns input unchanged) when PEER_OAM_URL is unset or project is empty/"all".
func resolveConnectorFromOAMProject(r *http.Request, connectorID string) (string, string, int) {
	connectorID = strings.TrimSpace(connectorID)
	if connectorID != "" {
		return connectorID, "", 0
	}
	base := peerOAMBaseURL()
	if base == "" {
		return "", "", 0
	}
	proj := strings.TrimSpace(r.Header.Get("X-Project-ID"))
	if proj == "" || strings.EqualFold(proj, "all") {
		return "", "", 0
	}
	row, err := lookupOAMDirectoryProject(r.Context(), r, base, "ora", proj)
	if err != nil {
		return "", "could not resolve project connectors from OAM: " + err.Error(), 503
	}
	if row == nil {
		return "", fmt.Sprintf("project %q is disabled for product ora (OAM disabled_products)", proj), 403
	}
	if len(row.ConnectorIDs) == 0 || strings.TrimSpace(row.ConnectorIDs[0]) == "" {
		return "", "project has no connector_ids; attach a connector in Account Manager", 400
	}
	return strings.TrimSpace(row.ConnectorIDs[0]), "", 0
}
