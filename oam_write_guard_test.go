package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalOAMWritesBlocked(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "")
	if localOAMWritesBlocked() {
		t.Fatal("expected open when OAM unset")
	}
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	if !localOAMWritesBlocked() {
		t.Fatal("expected blocked when OAM configured")
	}
}

func TestRefuseOAMLocalWrite(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	rr := httptest.NewRecorder()
	if !refuseOAMLocalWrite(rr) {
		t.Fatal("expected refuse")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestPersistSCMSecretBlockedWhenOAM(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam:8090")
	if err := persistSCMSecretScoped("org", "proj", credScopeOrg, "", "key", "val", false); err == nil {
		t.Fatal("expected error when OAM is credential home")
	}
}
