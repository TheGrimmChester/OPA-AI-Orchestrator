package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseEgressAllowlist(t *testing.T) {
	got := parseEgressAllowlist("api.cursor.sh, api2.cursor.sh;registry.npmjs.org")
	want := []string{"api.cursor.sh", "api2.cursor.sh", "registry.npmjs.org"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	got = parseEgressAllowlist("https://api.cursor.sh:443/path")
	if len(got) != 1 || got[0] != "api.cursor.sh" {
		t.Fatalf("normalize: %v", got)
	}
	if len(parseEgressAllowlist("  ,  ")) != 0 {
		t.Fatal("empty tokens")
	}
}

func TestAIEgressAllowlistDefaults(t *testing.T) {
	t.Setenv("OPA_JOB_EGRESS_ALLOWLIST", "")
	t.Setenv("OPA_JOB_EGRESS_NPM", "")
	t.Setenv("OPA_JOB_EGRESS_CHECKUP", "0")
	t.Setenv("OPA_JOB_SANDBOX", "")
	got := aiEgressAllowlist()
	if len(got) < 2 || got[0] != "api.cursor.sh" || got[1] != "api2.cursor.sh" {
		t.Fatalf("defaults: %v", got)
	}
	for _, h := range got {
		if strings.Contains(h, "npm") || h == "proxy.golang.org" {
			t.Fatalf("package registries must be off without checkup/npm flags: %v", got)
		}
	}
	t.Setenv("OPA_JOB_EGRESS_NPM", "1")
	got = aiEgressAllowlist()
	found := false
	for _, h := range got {
		if h == "registry.npmjs.org" {
			found = true
		}
	}
	if !found {
		t.Fatalf("npm gated on: %v", got)
	}
	t.Setenv("OPA_JOB_EGRESS_NPM", "")
	t.Setenv("OPA_JOB_EGRESS_CHECKUP", "")
	t.Setenv("OPA_JOB_SANDBOX", "docker")
	got = aiEgressAllowlist()
	foundNPM, foundGo := false, false
	for _, h := range got {
		if h == "registry.npmjs.org" {
			foundNPM = true
		}
		if h == "proxy.golang.org" {
			foundGo = true
		}
	}
	if !foundNPM || !foundGo {
		t.Fatalf("checkup docker defaults should allow npm+go: %v", got)
	}
	t.Setenv("OPA_JOB_EGRESS_ALLOWLIST", "only.example")
	got = aiEgressAllowlist()
	if len(got) != 1 || got[0] != "only.example" {
		t.Fatalf("explicit override: %v", got)
	}
}

func TestHostOnEgressAllowlist(t *testing.T) {
	allow := []string{"api.cursor.sh", "api2.cursor.sh"}
	if !hostOnEgressAllowlist("api.cursor.sh:443", allow) {
		t.Fatal("exact+port")
	}
	if !hostOnEgressAllowlist("API.CURSOR.SH", allow) {
		t.Fatal("case")
	}
	if hostOnEgressAllowlist("evil.com:443", allow) {
		t.Fatal("deny evil")
	}
	if hostOnEgressAllowlist("notapi.cursor.sh", allow) {
		t.Fatal("deny lookalike prefix")
	}
	if !hostOnEgressAllowlist("west.api.cursor.sh", allow) {
		t.Fatal("allow subdomain suffix")
	}
}

func TestNetworkForPhaseModes(t *testing.T) {
	t.Setenv("OPA_JOB_SANDBOX", "")
	if networkForPhase(jobPhaseScan) != "none" {
		t.Fatal("scan always none")
	}
	if networkForPhase(jobPhaseReview) != "none" {
		t.Fatal("host mode AI → none")
	}

	t.Setenv("OPA_JOB_SANDBOX", "docker")
	t.Setenv("OPA_JOB_EGRESS_PROXY", "")
	if networkForPhase(jobPhaseScan) != "none" {
		t.Fatal("scan stays none in docker")
	}
	if networkForPhase(jobPhaseReview) != networkModeInternalProxy {
		t.Fatalf("review want internal+proxy got %s", networkForPhase(jobPhaseReview))
	}
	if networkForPhase(jobPhaseAutofix) != networkModeInternalProxy {
		t.Fatal("autofix proxy")
	}
	if networkForPhase(jobPhaseCheckup) != "none" {
		t.Fatal("checkup sentinel none (overridden at run)")
	}

	t.Setenv("OPA_JOB_EGRESS_PROXY", "0")
	if networkForPhase(jobPhaseReview) != "bridge" {
		t.Fatalf("proxy off → bridge, got %s", networkForPhase(jobPhaseReview))
	}
}

func TestEgressProxyEnabledDefault(t *testing.T) {
	t.Setenv("OPA_JOB_SANDBOX", "off")
	if egressProxyEnabled() {
		t.Fatal("off sandbox")
	}
	t.Setenv("OPA_JOB_SANDBOX", "docker")
	t.Setenv("OPA_JOB_EGRESS_PROXY", "")
	if !egressProxyEnabled() {
		t.Fatal("default on in docker")
	}
	t.Setenv("OPA_JOB_EGRESS_PROXY", "false")
	if egressProxyEnabled() {
		t.Fatal("explicit off")
	}
}

func TestAllowlistProxyDeniesUnknownHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv := &http.Server{Handler: newAllowlistProxyHandler([]string{"api.cursor.sh"}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}
	resp, err := client.Get("http://evil.example/")
	if err != nil {
		t.Fatalf("proxy GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 403 got %d %s", resp.StatusCode, body)
	}

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "403") {
		t.Fatalf("CONNECT want 403 got %q", string(buf[:n]))
	}
}
