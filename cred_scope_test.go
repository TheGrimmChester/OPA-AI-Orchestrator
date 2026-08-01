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

func TestSCMSecretStorageKey(t *testing.T) {
	if got := scmSecretStorageKey("cursor_api_key", credScopeAdmin, ""); got != "cursor_api_key#admin" {
		t.Fatalf("admin key: %q", got)
	}
	if got := scmSecretStorageKey("cursor_api_key", credScopeUser, "alice"); got != "cursor_api_key#user:alice" {
		t.Fatalf("user key: %q", got)
	}
	logical, scope, uid := parseSCMSecretStorageKey("cursor_api_key#user:alice")
	if logical != "cursor_api_key" || scope != credScopeUser || uid != "alice" {
		t.Fatalf("parse user: %q %q %q", logical, scope, uid)
	}
}
