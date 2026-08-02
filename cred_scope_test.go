package main

import "testing"

func TestCanSeeCredScope(t *testing.T) {
	member := credActor{Username: "alice", Role: "viewer", OrganizationID: "org-a"}
	otherOrg := credActor{Username: "bob", Role: "editor", OrganizationID: "org-b"}
	adminInA := credActor{Username: "root", Role: "admin", OrganizationID: "org-a"}
	adminNoOrg := credActor{Username: "root", Role: "admin", OrganizationID: ""}
	owner := credActor{Username: "alice", Role: "viewer", OrganizationID: "org-a"}

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
		{"org_no_selected_org", adminNoOrg, credScopeOrg, "", "org-a", false},
		{"user_owner_ok", owner, credScopeUser, "alice", "org-a", true},
		{"user_other_denied", otherOrg, credScopeUser, "alice", "org-a", false},
		{"user_admin_no_peek", adminInA, credScopeUser, "alice", "org-a", false},
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

	if !canSeeSCMJob(adminAll, nasJob) || !canSeeSCMJob(adminAll, defJob) {
		t.Fatal("admin with All should see every org")
	}
	if canSeeSCMJob(adminNas, defJob) {
		t.Fatal("admin scoped to nas must not see default-org")
	}
	if !canSeeSCMJob(adminNas, nasJob) {
		t.Fatal("admin scoped to nas should see nas")
	}
	if canSeeSCMJob(memberAll, defJob) {
		t.Fatal("member with All must not see others' jobs")
	}
	if !canSeeSCMJob(memberAll, ownDef) {
		t.Fatal("member with All should see own queued jobs")
	}
	if !canSeeSCMJob(memberNas, nasJob) {
		t.Fatal("member in nas should see nas jobs")
	}
	if canSeeSCMJob(memberNas, ownDef) {
		t.Fatal("member in nas must not see default-org even if own actor")
	}
	// Legacy empty org counts as default-org when default-org selected.
	if !canSeeSCMJob(credActor{Username: "x", Role: "viewer", OrganizationID: defaultOrgID}, legacy) {
		t.Fatal("legacy empty org should match default-org filter")
	}
	authEnforced = false
	if !canSeeSCMJob(credActor{OrganizationID: ""}, nasJob) {
		t.Fatal("auth off + All should see all")
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
