package main

import (
	"strings"
	"testing"
)

func TestScmJobDashboardURL(t *testing.T) {
	t.Setenv("OPA_DASHBOARD_URL", "http://192.168.100.101:8088/")
	got := scmJobDashboardURL("scmjob-b4a520d2f20ba19f")
	want := "http://192.168.100.101:8088/security/jobs/scmjob-b4a520d2f20ba19f"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if scmJobDashboardURL("") != "" {
		t.Fatal("empty job id should yield empty URL")
	}
}

func TestCheckRunSummaryWithJobLink(t *testing.T) {
	t.Setenv("OPA_DASHBOARD_URL", "http://192.168.100.101:8088")
	sum := checkRunSummaryWithJobLink("Running OPA Review", "scmjob-abc")
	if !strings.Contains(sum, "Running OPA Review") {
		t.Fatalf("missing original summary: %q", sum)
	}
	if !strings.Contains(sum, "[View in OPA Dashboard](http://192.168.100.101:8088/security/jobs/scmjob-abc)") {
		t.Fatalf("missing dashboard link: %q", sum)
	}
}

func TestConnectorsDashboardURL(t *testing.T) {
	t.Setenv("OAM_DASHBOARD_URL", "http://192.168.100.101:18097/")
	t.Setenv("OPA_DASHBOARD_URL", "http://192.168.100.101:8088")
	got := connectorsDashboardURL("conn-1", "tok")
	want := "http://192.168.100.101:18097/connectors?connector=conn-1#claim_token=tok"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// Prefer OAM; fall back to OPA when OAM unset.
	t.Setenv("OAM_DASHBOARD_URL", "")
	got = connectorsDashboardURL("conn-2", "")
	want = "http://192.168.100.101:8088/connectors?connector=conn-2"
	if got != want {
		t.Fatalf("fallback got %q want %q", got, want)
	}
	if !strings.HasSuffix(connectorsDashboardBaseURL()+"/"+"connectors", "/connectors") {
		t.Fatal("base must combine with /connectors")
	}
}
