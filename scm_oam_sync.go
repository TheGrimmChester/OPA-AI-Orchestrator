package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	openclient "github.com/TheGrimmChester/open-client-go"
	openlogger "github.com/TheGrimmChester/open-logger-go"
)

const serviceScopeConnectorsWrite = "connectors:write"

func connectorWebhookMode(c *opaConnector) string {
	if c == nil {
		return "app"
	}
	if c.Kind == "github_pat" {
		return "repo"
	}
	return "app"
}

func syncConnectorToOAM(c *opaConnector) {
	if c == nil || !peerProductConfigured("PEER_OAM_URL") {
		return
	}
	deleted := c.Status == "deleted"
	org := strings.TrimSpace(c.OrganizationID)
	proj := strings.TrimSpace(c.ProjectID)
	scope := inferLegacyScope(c.OrganizationID, c.Scope)
	userID := strings.TrimSpace(c.UserID)
	personal := scope == credScopeUser && userID != "" && org == ""
	if !deleted {
		if proj == "" {
			return
		}
		if org == "" && !personal {
			return
		}
	}
	display := ""
	if meta := parseConnectorMeta(c.MetaJSON); meta != nil {
		if s, ok := meta["display_name"].(string); ok {
			display = strings.TrimSpace(s)
		}
	}
	name := display
	if name == "" {
		name = strings.TrimSpace(c.AccountLogin)
	}
	if name == "" {
		name = c.Kind
	}
	body := map[string]interface{}{
		"id":              c.ID,
		"organization_id": org,
		"project_id":      proj,
		"scope":           scope,
		"user_id":         userID,
		"kind":            c.Kind,
		"name":            name,
		"webhook_mode":    connectorWebhookMode(c),
		"deleted":         deleted,
		"config": map[string]interface{}{
			"account_login":   c.AccountLogin,
			"display_name":    display,
			"installation_id": c.InstallationID,
			"status":          c.Status,
		},
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cfg := openclient.PeerFromEnv("PEER_OAM_URL", "ora-api", "oam-api", serviceScopeConnectorsWrite)
		cfg.OrgID = org
		var out map[string]interface{}
		if err := openclient.PeerJSON(ctx, cfg, http.MethodPost, "/api/internal/connectors/sync", body, &out); err != nil {
			openlogger.LogWarn("oam connector sync failed", map[string]interface{}{
				"connector_id": c.ID, "error": err.Error(),
			})
		}
	}()
}
