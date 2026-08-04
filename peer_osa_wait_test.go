package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The gate must wait for the security run to finish. Evaluating straight after
// creating the run reads an empty findings set and reports a verdict about a
// scan that never happened.
func TestAwaitOSASecurityRunWaitsForTerminalStatus(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/security/runs/") {
			http.NotFound(w, r)
			return
		}
		n := atomic.AddInt32(&calls, 1)
		status := "running"
		if n >= 3 {
			status = "completed"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "srun-x", "status": status})
	}))
	defer srv.Close()

	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("OPA_GATE_WAIT_TIMEOUT_SEC", "30")

	status, terminal := awaitOSASecurityRun("default-org", "srun-x")
	if !terminal {
		t.Fatalf("expected a terminal state, got status=%q", status)
	}
	if status != "completed" {
		t.Errorf("status = %q, want completed", status)
	}
	if got := atomic.LoadInt32(&calls); got < 3 {
		t.Errorf("polled %d times, expected to keep polling until terminal", got)
	}
}

// A run that never appears must give up on the shorter appearance budget rather
// than holding the check open for the full scan timeout.
func TestAwaitOSASecurityRunGivesUpWhenRunNeverAppears(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("OPA_GATE_WAIT_TIMEOUT_SEC", "300")
	t.Setenv("OPA_GATE_RUN_APPEAR_TIMEOUT_SEC", "1")

	status, terminal := awaitOSASecurityRun("default-org", "srun-missing")
	if terminal {
		t.Fatal("a missing run must not report a terminal state")
	}
	if status != "" {
		t.Errorf("status = %q, want empty", status)
	}
}

// A peer that rejects the service token yields an unavailable verdict, never a
// findings failure — the family-wide 401 regression.
func TestGateAfterScanUnauthorizedPeerIsNeutral(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
	}))
	defer srv.Close()

	t.Setenv("PEER_OSA_URL", srv.URL)
	t.Setenv("OPA_GATE_WAIT_TIMEOUT_SEC", "5")
	t.Setenv("OPA_GATE_RUN_APPEAR_TIMEOUT_SEC", "1")

	gate := gateAfterScan("default-org", "srun-401", "high", nil)
	if gate["fail"] == true {
		t.Fatal("a 401 from the peer must not fail the gate")
	}
	conclusion, title := gateCheckOutcome(gate)
	if conclusion != "neutral" {
		t.Errorf("conclusion = %q, want neutral", conclusion)
	}
	if !strings.Contains(title, "could not evaluate") {
		t.Errorf("title = %q", title)
	}
}
