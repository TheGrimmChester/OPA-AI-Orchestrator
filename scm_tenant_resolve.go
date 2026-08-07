package main

import (
	"strings"
)

// scmTenantResolution is the org/project stamp applied to jobs and SCM envelopes.
type scmTenantResolution struct {
	OrganizationID string
	ProjectID      string
	PendingTenant  bool
	PendingClaim   bool
	Reason         string
}

func resolveSCMTenant(wr *opaWatchedRepo, conn *opaConnector) scmTenantResolution {
	org, proj := "", ""
	if wr != nil {
		org, proj = strings.TrimSpace(wr.OrganizationID), strings.TrimSpace(wr.ProjectID)
	}
	if org == "" && conn != nil {
		org, proj = strings.TrimSpace(conn.OrganizationID), strings.TrimSpace(conn.ProjectID)
	}
	if conn != nil && strings.EqualFold(strings.TrimSpace(conn.Status), "pending_claim") {
		return scmTenantResolution{
			OrganizationID: org,
			ProjectID:      proj,
			PendingClaim:   true,
			Reason:         "GitHub App install pending Open account claim",
		}
	}
	// Personal user-scoped connectors: empty org is intentional — jobs run under
	// the owner user_id, not an Open organization tenant.
	if org == "" && conn != nil {
		scope := inferLegacyScope(conn.OrganizationID, conn.Scope)
		if scope == credScopeUser && strings.TrimSpace(conn.UserID) != "" {
			if proj == "" {
				proj = defaultProjectID
			}
			return scmTenantResolution{OrganizationID: "", ProjectID: proj}
		}
	}
	if org == "" {
		return scmTenantResolution{
			PendingTenant: true,
			Reason:        "organization_id required — assign connector/repo watch to an OAM org before SCM jobs run",
		}
	}
	if proj == "" {
		proj = defaultProjectID
	}
	return scmTenantResolution{OrganizationID: org, ProjectID: proj}
}

func stampSCMJobTenant(job *scmJob, tenant scmTenantResolution) {
	if job == nil || tenant.PendingTenant || tenant.PendingClaim {
		return
	}
	if strings.TrimSpace(job.OrganizationID) == "" {
		job.OrganizationID = tenant.OrganizationID
	}
	if strings.TrimSpace(job.ProjectID) == "" {
		job.ProjectID = tenant.ProjectID
	}
}

func scmTenantBlocksJob(tenant scmTenantResolution) bool {
	return tenant.PendingTenant || tenant.PendingClaim
}
