package main

import (
	"net/http"
	"testing"
)

func TestCanSeeConnectorHidesPending(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	admin := credActor{Username: "root", Role: "admin", OrganizationID: "org-a"}
	svc := credActor{Username: "service:opm-api", Role: "admin", OrganizationID: "org-a"}
	pending := &opaConnector{ID: "p", Status: "pending_claim", OrganizationID: "", Scope: credScopeOrg}
	orphan := &opaConnector{ID: "o", Status: "active", OrganizationID: "", Scope: credScopeOrg}
	active := &opaConnector{ID: "a", Status: "active", OrganizationID: "org-a", Scope: credScopeOrg}
	foreign := &opaConnector{ID: "f", Status: "active", OrganizationID: "org-b", Scope: credScopeOrg}
	adminConn := &opaConnector{ID: "adm", Status: "active", OrganizationID: "", Scope: credScopeAdmin}

	if canSeeConnector(admin, pending) || canSeeConnector(svc, pending) {
		t.Fatal("pending_claim must be invisible to admin and service")
	}
	if canSeeConnector(admin, orphan) {
		t.Fatal("empty-org org-scoped must be invisible")
	}
	if !canSeeConnector(admin, active) {
		t.Fatal("active same-org should be visible to admin")
	}
	if canSeeConnector(admin, foreign) {
		t.Fatal("foreign org must be hidden")
	}
	if !canSeeConnector(svc, active) {
		t.Fatal("service should see active connectors for its org")
	}
	if canSeeConnector(svc, foreign) {
		t.Fatal("service must not see foreign org")
	}
	svcNoOrg := credActor{Username: "service:opm-api", Role: "admin", OrganizationID: ""}
	if canSeeConnector(svcNoOrg, active) {
		t.Fatal("service with empty org must see nothing")
	}
	if !canSeeConnector(admin, adminConn) {
		t.Fatal("admin-scoped empty-org connector stays visible to platform admin")
	}
	userConn := &opaConnector{
		ID: "u", Status: "active", OrganizationID: "", Scope: credScopeUser, UserID: "solo",
	}
	if canSeeConnector(svc, userConn) {
		t.Fatal("service JWT must not see personal/user-scoped connectors")
	}
	owner := credActor{Username: "solo", Role: "editor", OrganizationID: ""}
	if !canSeeConnector(owner, userConn) {
		t.Fatal("owner must see own user-scoped connector")
	}
}

func TestCanSeeCredScope(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	member := credActor{Username: "alice", Role: "viewer", OrganizationID: "org-a"}
	memberNoOrg := credActor{Username: "alice", Role: "viewer", OrganizationID: ""}
	otherOrg := credActor{Username: "bob", Role: "editor", OrganizationID: "org-b"}
	adminInA := credActor{Username: "root", Role: "admin", OrganizationID: "org-a"}
	adminNoOrg := credActor{Username: "root", Role: "admin", OrganizationID: ""}
	owner := credActor{Username: "alice", Role: "viewer", OrganizationID: "org-a"}
	ownerDefault := credActor{Username: "admin", Role: "admin", OrganizationID: defaultOrgID}

	cases := []struct {
		name      string
		actor     credActor
		scope     string
		ownerUser string
		ownerOrg  string
		want      bool
	}{
		{"admin_only_admin", adminNoOrg, credScopeAdmin, "", "", true},
		{"admin_denied_member", member, credScopeAdmin, "", "", false},
		{"org_member_same", member, credScopeOrg, "", "org-a", true},
		{"org_other_denied", otherOrg, credScopeOrg, "", "org-a", false},
		{"org_empty_owner_denied_member", member, credScopeOrg, "", "", false},
		{"org_empty_owner_admin_ok", adminInA, credScopeOrg, "", "", true},
		{"org_all_admin_denied_under_auth", adminNoOrg, credScopeOrg, "", "org-a", false},
		{"org_all_member_denied", memberNoOrg, credScopeOrg, "", "org-a", false},
		{"user_owner_ok", owner, credScopeUser, "alice", "org-a", true},
		{"user_other_denied", otherOrg, credScopeUser, "alice", "org-a", false},
		{"user_admin_no_peek", adminInA, credScopeUser, "alice", "org-a", false},
		{"user_legacy_admin_opa_admin", credActor{Username: "opa-admin", Role: "admin", OrganizationID: "nas"}, credScopeUser, "admin", "nas", true},
		{"user_cross_org_denied", ownerDefault, credScopeUser, "admin", "nas", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canSeeCredScope(tc.actor, tc.scope, tc.ownerUser, tc.ownerOrg)
			if got != tc.want {
				t.Fatalf("canSeeCredScope=%v want %v", got, tc.want)
			}
		})
	}
}

func TestCanMutateCred(t *testing.T) {
	member := credActor{Username: "alice", Role: "viewer", OrganizationID: "org-a"}
	admin := credActor{Username: "root", Role: "admin", OrganizationID: "org-a"}
	adminOther := credActor{Username: "root", Role: "admin", OrganizationID: "org-b"}

	if err := canMutateCred(member, credScopeOrg, "", "org-a"); err == nil {
		t.Fatal("viewer must not mutate org credentials")
	}
	if err := canMutateCred(admin, credScopeOrg, "", "org-a"); err != nil {
		t.Fatalf("admin in org should mutate org: %v", err)
	}
	if err := canMutateCred(adminOther, credScopeOrg, "", "org-a"); err == nil {
		t.Fatal("admin in other org must not mutate")
	}
	if err := canMutateCred(member, credScopeUser, "alice", "org-a"); err != nil {
		t.Fatalf("owner should mutate user cred: %v", err)
	}
	if err := canMutateCred(member, credScopeUser, "bob", "org-a"); err == nil {
		t.Fatal("non-owner must not mutate user cred")
	}
	if err := canMutateCred(admin, credScopeAdmin, "", ""); err != nil {
		t.Fatalf("admin should mutate admin scope: %v", err)
	}
	if err := canMutateCred(member, credScopeAdmin, "", ""); err == nil {
		t.Fatal("viewer must not mutate admin scope")
	}
}

func TestCanWriteCredScope(t *testing.T) {
	viewer := credActor{Username: "u", Role: "viewer", OrganizationID: "org-a"}
	admin := credActor{Username: "a", Role: "admin", OrganizationID: "org-a"}
	if err := canWriteCredScope(viewer, credScopeOrg); err == nil {
		t.Fatal("expected org write denied for viewer")
	}
	if err := canWriteCredScope(admin, credScopeOrg); err != nil {
		t.Fatalf("admin org write: %v", err)
	}
	if err := canWriteCredScope(viewer, credScopeUser); err != nil {
		t.Fatalf("viewer user write: %v", err)
	}
}

func TestInferLegacyScope(t *testing.T) {
	if got := inferLegacyScope("org-a", ""); got != credScopeOrg {
		t.Fatalf("got %q", got)
	}
	if got := inferLegacyScope("", ""); got != credScopeAdmin {
		t.Fatalf("got %q", got)
	}
	if got := inferLegacyScope("", "user"); got != credScopeUser {
		t.Fatalf("got %q", got)
	}
}

func TestCanSeeSCMJob(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	adminAll := credActor{Username: "root", Role: "admin", OrganizationID: ""}
	adminNas := credActor{Username: "root", Role: "admin", OrganizationID: "nas"}
	memberAll := credActor{Username: "alice", Role: "viewer", OrganizationID: ""}
	memberNas := credActor{Username: "alice", Role: "viewer", OrganizationID: "nas"}

	nasJob := &scmJob{ID: "1", OrganizationID: "nas", ActorUserID: "alice"}
	defJob := &scmJob{ID: "2", OrganizationID: "default-org", ActorUserID: "bob"}
	ownDef := &scmJob{ID: "3", OrganizationID: "default-org", ActorUserID: "alice"}
	legacy := &scmJob{ID: "4", OrganizationID: "", ActorUserID: ""}

	// Empty org under auth fails closed (actorFromRequest pins WriteTenant in HTTP).
	if canSeeSCMJob(adminAll, nasJob, "") || canSeeSCMJob(adminAll, defJob, "") {
		t.Fatal("admin with empty org must not dump all tenants under auth")
	}
	if canSeeSCMJob(adminNas, defJob, "") {
		t.Fatal("admin scoped to nas must not see default-org")
	}
	if !canSeeSCMJob(adminNas, nasJob, "") {
		t.Fatal("admin scoped to nas should see nas")
	}
	if canSeeSCMJob(memberAll, defJob, "") || canSeeSCMJob(memberAll, ownDef, "") {
		t.Fatal("member with empty org must not see jobs under auth")
	}
	if !canSeeSCMJob(memberNas, nasJob, "") {
		t.Fatal("member in nas should see nas jobs")
	}
	if canSeeSCMJob(memberNas, ownDef, "") {
		t.Fatal("member in nas must not see default-org even if own actor")
	}
	// Legacy empty org counts as default-org when default-org selected.
	if !canSeeSCMJob(credActor{Username: "x", Role: "viewer", OrganizationID: defaultOrgID}, legacy, "") {
		t.Fatal("legacy empty org should match default-org filter")
	}
	authEnforced = false
	if !canSeeSCMJob(credActor{OrganizationID: ""}, nasJob, "") {
		t.Fatal("auth off + All should see all")
	}
	// Connector filter bypasses tenant org for admins (App install often on default-org).
	authEnforced = true
	defJob.ConnectorID = "conn-app"
	if !canSeeSCMJob(adminNas, defJob, "conn-app") {
		t.Fatal("admin nas + connector filter should see default-org job on that connector")
	}
	if canSeeSCMJob(adminNas, defJob, "conn-other") {
		t.Fatal("connector filter must not match wrong connector")
	}
}

func TestActorFromRequestWriteTenant(t *testing.T) {
	prev := authEnforced
	authEnforced = true
	defer func() { authEnforced = prev }()

	r, _ := http.NewRequest(http.MethodGet, "/api/connectors", nil)
	a := actorFromRequest(r)
	if a.OrganizationID != defaultOrgID || a.ProjectID != defaultProjectID {
		t.Fatalf("missing headers under auth → WriteTenant, got %q/%q", a.OrganizationID, a.ProjectID)
	}
	r.Header.Set("X-Organization-ID", "all")
	r.Header.Set("X-Project-ID", "all")
	a = actorFromRequest(r)
	if a.OrganizationID != defaultOrgID || a.ProjectID != defaultProjectID {
		t.Fatalf("all/all under auth → WriteTenant, got %q/%q", a.OrganizationID, a.ProjectID)
	}
	r.Header.Set("X-Organization-ID", "nas")
	r.Header.Set("X-Project-ID", "infra")
	a = actorFromRequest(r)
	if a.OrganizationID != "nas" || a.ProjectID != "infra" {
		t.Fatalf("concrete tenant kept, got %q/%q", a.OrganizationID, a.ProjectID)
	}
}

func TestSCMSecretStorageKey(t *testing.T) {
	if got := scmSecretStorageKey("cursor_api_key", credScopeAdmin, ""); got != "cursor_api_key#admin" {
		t.Fatalf("admin: %q", got)
	}
	if got := scmSecretStorageKey("cursor_api_key", credScopeUser, "alice"); got != "cursor_api_key#user:alice" {
		t.Fatalf("user: %q", got)
	}
	if got := scmSecretStorageKey("cursor_api_key", credScopeOrg, "alice"); got != "cursor_api_key" {
		t.Fatalf("org: %q", got)
	}
	logical, scope, user := parseSCMSecretStorageKey("cursor_api_key#admin")
	if logical != "cursor_api_key" || scope != credScopeAdmin || user != "" {
		t.Fatalf("parse admin: %q %q %q", logical, scope, user)
	}
	logical, scope, user = parseSCMSecretStorageKey("cursor_api_key#user:alice")
	if logical != "cursor_api_key" || scope != credScopeUser || user != "alice" {
		t.Fatalf("parse user: %q %q %q", logical, scope, user)
	}
	logical, scope, user = parseSCMSecretStorageKey("cursor_api_key")
	if logical != "cursor_api_key" || scope != "" || user != "" {
		t.Fatalf("parse org/legacy: %q %q %q", logical, scope, user)
	}
}
