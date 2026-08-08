package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	openclient "github.com/TheGrimmChester/open-client-go"
)

// Peer client for OAM job-credential lease/redeem and agent catalog publish.
// Pattern mirrors OPM-API/oam_client.go — product is "ora".

const oamResolveScope = "creds:resolve health:read"

func oamConfigured() bool { return peerOAMBaseURL() != "" }

// resolvedAgentBinding is the model configuration and credential for one job,
// resolved together by OAM (lease → redeem or /api/agents/resolve).
type resolvedAgentBinding struct {
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	BaseURL       string `json:"base_url"`
	MaxTokens     uint32 `json:"max_tokens"`
	Effort        string `json:"effort"`
	Timeout       uint32 `json:"timeout_seconds"`
	APIKey        string `json:"api_key"`
	KeyScope      string `json:"key_scope"`
	ModelSource   string `json:"model_source"`
	LogicalKey    string `json:"logical_key"`
	AgentKeyKnown bool   `json:"agent_key_known"`
}

type oamResolveRequest struct {
	OrganizationID string `json:"organization_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	Product        string `json:"product"`
	AgentKey       string `json:"agent_key"`
}

// errOAMNotConfigured is returned when PEER_OAM_URL is unset.
var errOAMNotConfigured = fmt.Errorf("PEER_OAM_URL not configured")

// resolveAgentFromOAM asks OAM for the model + key this job should run with.
//
// Prefer lease → one-shot redeem. Fall back to direct resolve when lease
// endpoints are unavailable (older OAM). Once PEER_OAM_URL is set, failures are
// fatal for the caller — never fall back to scm_secrets.
func resolveAgentFromOAM(ctx context.Context, org, proj, actor, agentKey string) (resolvedAgentBinding, error) {
	var out resolvedAgentBinding
	if !oamConfigured() {
		return out, errOAMNotConfigured
	}
	agentKey = strings.TrimSpace(agentKey)
	if agentKey == "" {
		return out, fmt.Errorf("agent_key required")
	}
	cfg := openclient.PeerFromEnv("PEER_OAM_URL", "ora-api", "oam-api", oamResolveScope)
	cfg.OrgID = strings.TrimSpace(org)

	req := oamResolveRequest{
		OrganizationID: strings.TrimSpace(org),
		ProjectID:      strings.TrimSpace(proj),
		UserID:         strings.TrimSpace(actor),
		Product:        "ora",
		AgentKey:       agentKey,
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if leased, err := leaseAndRedeemAgentFromOAM(ctx, cfg, req); err == nil {
		out = leased
	} else if err := openclient.PeerJSON(ctx, cfg, http.MethodPost, "/api/agents/resolve", req, &out); err != nil {
		return resolvedAgentBinding{}, err
	}
	if strings.TrimSpace(out.APIKey) == "" {
		return resolvedAgentBinding{}, fmt.Errorf("oam returned an empty api key for agent %q", agentKey)
	}
	if !out.AgentKeyKnown {
		log.Printf("oam: agent key %q is not in ORA's published catalog — "+
			"it resolved against a default binding. Publish it via /api/agents/catalog/publish.", agentKey)
	}
	return out, nil
}

func leaseAndRedeemAgentFromOAM(ctx context.Context, cfg openclient.PeerConfig, req oamResolveRequest) (resolvedAgentBinding, error) {
	var lease struct {
		LeaseID string `json:"lease_id"`
	}
	if err := openclient.PeerJSON(ctx, cfg, http.MethodPost, "/api/internal/job-credentials/lease", req, &lease); err != nil {
		return resolvedAgentBinding{}, err
	}
	if strings.TrimSpace(lease.LeaseID) == "" {
		return resolvedAgentBinding{}, fmt.Errorf("oam lease returned empty lease_id")
	}
	var out resolvedAgentBinding
	if err := openclient.PeerJSON(ctx, cfg, http.MethodPost, "/api/internal/job-credentials/redeem", map[string]string{
		"lease_id": lease.LeaseID,
	}, &out); err != nil {
		return resolvedAgentBinding{}, err
	}
	return out, nil
}

// publishAgentCatalog registers ORA's agents with OAM on boot (best-effort).
func publishAgentCatalog(ctx context.Context) {
	if !oamConfigured() {
		return
	}
	cfg := openclient.PeerFromEnv("PEER_OAM_URL", "ora-api", "oam-api", "catalog:write")
	body := map[string]interface{}{"product": "ora", "agents": agentCatalog()}
	var out struct {
		Agents []string `json:"agents"`
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := openclient.PeerJSON(ctx, cfg, http.MethodPost, "/api/agents/catalog/publish", body, &out); err != nil {
		log.Printf("oam: agent catalog publish failed (continuing): %v", err)
		return
	}
	log.Printf("oam: published %d agent keys: %s", len(out.Agents), strings.Join(out.Agents, ","))
}
