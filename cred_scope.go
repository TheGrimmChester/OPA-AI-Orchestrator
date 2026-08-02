package main

import (
	"fmt"
	"net/http"
	"strings"
)

// Credential scopes for connectors and AI secrets (OPA Review / OpenAI / Anthropic / Cursor).
//
// Inheritance for tenant jobs (most specific wins; never inherit admin):
//  1. user  — caller's personal override for an org
//  2. org   — org default for members without a user override
//  3. fail closed — no key (do NOT fall back to admin, env globals, or "any" row)
//
// Admin scope is isolated: platform admin's own keys for admin-only use.
// Never grant admin keys to org/user jobs.
const (
	credScopeAdmin = "admin"
	credScopeOrg   = "org"
	credScopeUser  = "user"
)

// credActor is the authenticated principal + tenant for credential operations.
type credActor struct {
	Username       string
	Role           string // viewer | editor | admin
	OrganizationID string
	ProjectID      string
}

func actorFromRequest(r *http.Request) credActor {
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := "", ""
	if ctx != nil {
		org, proj = ctx.OrganizationID, ctx.ProjectID
		if strings.EqualFold(org, tenantAll) {
			org = ""
		}
		if strings.EqualFold(proj, tenantAll) {
			proj = ""
		}
	}
	username := strings.TrimSpace(r.Header.Get("X-User-Username"))
	role := strings.TrimSpace(r.Header.Get("X-User-Role"))
	// Soft-hydrate identity from Bearer/cookie JWT when headers are absent.
	// Needed when OPA_AUTH_REQUIRED is off (middleware skipped) but the Dashboard
	// still sends a login token — user-scoped AI secrets key off username.
	if username == "" {
		if claims := claimsFromRequestToken(r); claims != nil {
			username = strings.TrimSpace(claims.Username)
			if role == "" {
				role = strings.TrimSpace(claims.Role)
			}
		}
	}
	return credActor{
		Username:       username,
		Role:           role,
		OrganizationID: org,
		ProjectID:      proj,
	}
}

// claimsFromRequestToken parses Authorization Bearer or opa_token cookie without
// enforcing auth. Returns nil when missing/invalid (never errors to caller).
func claimsFromRequestToken(r *http.Request) *Claims {
	token := ""
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token = parts[1]
		}
	} else if c, err := r.Cookie(authCookieName); err == nil {
		token = c.Value
	}
	if token == "" {
		return nil
	}
	ah := &AuthHandler{queryClient: queryClient}
	claims, err := ah.VerifyToken(token)
	if err != nil {
		return nil
	}
	return claims
}

func (a credActor) isAdmin() bool {
	return hasPermission(a.Role, "admin") || (!authEnforced && a.Role == "")
}

// normalizeCredScope validates and defaults a requested write scope.
func normalizeCredScope(raw string, a credActor) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "":
		// Default: admin with no org selected → admin; otherwise org.
		if a.isAdmin() && a.OrganizationID == "" {
			return credScopeAdmin, nil
		}
		if a.OrganizationID != "" {
			return credScopeOrg, nil
		}
		if a.Username != "" {
			return credScopeUser, nil
		}
		return credScopeOrg, nil
	case credScopeAdmin, credScopeOrg, credScopeUser:
		return s, nil
	default:
		return "", fmt.Errorf("invalid scope %q (want admin|org|user)", raw)
	}
}

// canWriteCredScope enforces who may create/update credentials at a scope.
func canWriteCredScope(a credActor, scope string) error {
	switch scope {
	case credScopeAdmin:
		if !a.isAdmin() {
			return fmt.Errorf("admin scope requires admin role")
		}
		return nil
	case credScopeOrg:
		if !a.isAdmin() {
			return fmt.Errorf("org scope requires admin role")
		}
		if a.OrganizationID == "" {
			return fmt.Errorf("org scope requires X-Organization-ID")
		}
		return nil
	case credScopeUser:
		if a.Username == "" && authEnforced {
			return fmt.Errorf("user scope requires authenticated username")
		}
		return nil
	default:
		return fmt.Errorf("invalid scope %q", scope)
	}
}

// canSeeCredScope controls list/get visibility (secret values never returned either way).
//
// Rules:
//   - admin: platform admin only
//   - org: callers whose selected org matches the credential's org (members + admins
//     acting in that org). Empty-org legacy "org" rows are admin-only (no cross-tenant leak).
//   - user: owner-only (prefer owner-only for secrets; no admin-for-support peek)
func canSeeCredScope(a credActor, scope, ownerUser, ownerOrg string) bool {
	scope = inferLegacyScope(ownerOrg, scope)
	switch scope {
	case credScopeAdmin:
		return a.isAdmin()
	case credScopeOrg:
		if strings.TrimSpace(ownerOrg) == "" {
			// Pre-scope empty-org rows: do not expose to every org member.
			return a.isAdmin()
		}
		if sel := strings.TrimSpace(a.OrganizationID); sel != "" {
			return ownerOrg == sel
		}
		// Tenant picker "All" (empty org): admins may list/get across orgs
		// (same rule as canSeeSCMJob). Non-admins must pick a concrete org.
		return a.isAdmin()
	case credScopeUser:
		return userCredOwnerMatch(a.Username, ownerUser)
	default:
		return false
	}
}

// userCredOwnerMatch compares credential owner to the signed-in username.
// Legacy PAT bootstrap rows used user_id "admin" before the nas login was
// renamed to opa-admin — treat that pair as the same owner.
func userCredOwnerMatch(actorUser, ownerUser string) bool {
	actorUser = strings.TrimSpace(actorUser)
	ownerUser = strings.TrimSpace(ownerUser)
	if actorUser == "" || ownerUser == "" {
		return false
	}
	if actorUser == ownerUser {
		return true
	}
	if ownerUser == "admin" && (actorUser == "opa-admin" || actorUser == "root") {
		return true
	}
	return false
}

// canMutateCred enforces write/delete on an existing credential row.
// Combines write-scope role gates with ownership / org match (fail closed).
func canMutateCred(a credActor, scope, ownerUser, ownerOrg string) error {
	scope = inferLegacyScope(ownerOrg, scope)
	if err := canWriteCredScope(a, scope); err != nil {
		return err
	}
	switch scope {
	case credScopeAdmin:
		return nil
	case credScopeOrg:
		if a.OrganizationID == "" {
			return fmt.Errorf("org scope requires X-Organization-ID")
		}
		if ownerOrg != "" && ownerOrg != a.OrganizationID {
			return fmt.Errorf("forbidden: credential belongs to another organization")
		}
		return nil
	case credScopeUser:
		if !userCredOwnerMatch(a.Username, ownerUser) {
			return fmt.Errorf("forbidden: not credential owner")
		}
		if a.Username == "" && authEnforced {
			return fmt.Errorf("user scope requires authenticated username")
		}
		return nil
	default:
		return fmt.Errorf("forbidden")
	}
}

// inferLegacyScope maps pre-v39 rows (empty scope column) to a sensible default.
// Prefer org when organization_id is present; admin only for empty-org bootstrap installs.
func inferLegacyScope(organizationID, scopeCol string) string {
	s := strings.ToLower(strings.TrimSpace(scopeCol))
	if s == credScopeAdmin || s == credScopeOrg || s == credScopeUser {
		return s
	}
	if strings.TrimSpace(organizationID) != "" {
		return credScopeOrg
	}
	return credScopeAdmin
}

// scmSecretStorageKey encodes scope into the ClickHouse `key` column so
// ReplacingMergeTree ORDER BY (organization_id, project_id, key) stays unique
// across admin/org/user rows without a table rebuild.
//
//	org / legacy: "<logical>"
//	user:         "<logical>#user:<userID>"
//	admin:        "<logical>#admin"
func scmSecretStorageKey(logicalKey, scope, userID string) string {
	logicalKey = strings.TrimSpace(logicalKey)
	switch inferLegacyScope("", scope) {
	case credScopeUser:
		uid := strings.TrimSpace(userID)
		if uid == "" {
			uid = "_"
		}
		return logicalKey + "#user:" + uid
	case credScopeAdmin:
		return logicalKey + "#admin"
	default:
		return logicalKey
	}
}

func parseSCMSecretStorageKey(stored string) (logical, scope, userID string) {
	stored = strings.TrimSpace(stored)
	if i := strings.Index(stored, "#user:"); i >= 0 {
		return stored[:i], credScopeUser, stored[i+len("#user:"):]
	}
	if strings.HasSuffix(stored, "#admin") {
		return strings.TrimSuffix(stored, "#admin"), credScopeAdmin, ""
	}
	return stored, "", ""
}

// resolveCredTarget picks org/project/user_id fields for a write at the given scope.
func resolveCredTarget(a credActor, scope string) (org, proj, userID string) {
	switch scope {
	case credScopeAdmin:
		// Admin keys are not tied to a tenant org.
		return "", "", ""
	case credScopeUser:
		org, proj = a.OrganizationID, a.ProjectID
		if org == "" {
			org, proj = defaultOrgID, defaultProjectID
		}
		if proj == "" || proj == tenantAll {
			proj = defaultProjectID
		}
		userID = a.Username
		return org, proj, userID
	default: // org
		org, proj = a.OrganizationID, a.ProjectID
		if org == "" {
			org = defaultOrgID
		}
		if proj == "" || proj == tenantAll {
			proj = defaultProjectID
		}
		return org, proj, ""
	}
}

// credResolveQuery is the input for fail-closed secret resolution used by jobs.
type credResolveQuery struct {
	OrganizationID string
	ProjectID      string
	UserID         string // optional acting user; empty → skip user layer
	// WantAdminOnly: when true, resolve only admin-scoped secrets (admin's own use).
	WantAdminOnly bool
}
