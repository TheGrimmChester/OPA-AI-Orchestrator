package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Shared allowlist egress proxy for sandboxed AI phases.
//
// Honesty: HTTP(S)_PROXY is only a hint — a process inside the box can unset it.
// The real boundary is the per-job --internal network (no default route) with the
// proxy as the only container that also joins an egress network.

const (
	egressProxyRoleLabel     = "egress-proxy"
	egressProxyPort          = 3128
	egressProxyAlias         = "opa-egress-proxy"
	networkModeInternalProxy = "internal+proxy" // sentinel for networkForPhase / runner
)

var (
	egressProxyMu       sync.Mutex
	defaultAIAllowHosts = []string{"api.cursor.sh", "api2.cursor.sh"}
	// npm registry hosts — off by default; enable with OPA_JOB_EGRESS_NPM=1 when
	// browser MCP must fetch packages at runtime (prefer pinning in the image).
	npmEgressAllowHosts = []string{
		"registry.npmjs.org",
		"registry.yarnpkg.com",
	}
)

// egressProxyEnabled is on by default whenever OPA_JOB_SANDBOX=docker.
// Set OPA_JOB_EGRESS_PROXY=0 to fall back to unrestricted bridge for AI phases.
func egressProxyEnabled() bool {
	if sandboxMode() != "docker" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OPA_JOB_EGRESS_PROXY"))) {
	case "0", "off", "false", "no":
		return false
	default:
		return true
	}
}

// parseEgressAllowlist splits a comma/space-separated host list. Empty tokens dropped.
// Hosts are lowercased; optional trailing :port is stripped for the allow entry.
func parseEgressAllowlist(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == ';'
	})
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		h := normalizeAllowHost(f)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

func normalizeAllowHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(h, ".")
	return h
}

// aiEgressAllowlist returns hosts the shared proxy may dial for AI phases.
func aiEgressAllowlist() []string {
	if v := strings.TrimSpace(os.Getenv("OPA_JOB_EGRESS_ALLOWLIST")); v != "" {
		parsed := parseEgressAllowlist(v)
		if len(parsed) > 0 {
			return parsed
		}
	}
	out := append([]string{}, defaultAIAllowHosts...)
	if strings.TrimSpace(os.Getenv("OPA_JOB_EGRESS_NPM")) == "1" {
		out = append(out, npmEgressAllowHosts...)
	}
	return out
}

func hostOnEgressAllowlist(hostport string, allow []string) bool {
	host := normalizeAllowHost(hostport)
	if host == "" {
		return false
	}
	for _, a := range allow {
		a = normalizeAllowHost(a)
		if a == "" {
			continue
		}
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

func egressProxyImage() string {
	if v := strings.TrimSpace(os.Getenv("OPA_JOB_EGRESS_PROXY_IMAGE")); v != "" {
		return v
	}
	tag := nz(strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_TAG")), "smoke")
	return "opa-egress-proxy:" + tag
}

func egressProxyContainerName() string {
	return "opa-egress-proxy-" + opaInstanceID()
}

func egressNetworkName() string {
	return "opa-egress-" + opaInstanceID()
}

func jobNetworkName(jobID string) string {
	return "opa-job-" + sanitizeDockerName(jobID)
}

// egressProxyEnvVars are injected into AI job boxes when using internal+proxy.
func egressProxyEnvVars() map[string]string {
	url := fmt.Sprintf("http://%s:%d", egressProxyAlias, egressProxyPort)
	return map[string]string{
		"HTTP_PROXY":  url,
		"HTTPS_PROXY": url,
		"http_proxy":  url,
		"https_proxy": url,
		"NO_PROXY":    "localhost,127.0.0.1," + egressProxyAlias,
		"no_proxy":    "localhost,127.0.0.1," + egressProxyAlias,
	}
}

// ensureSharedEgressProxy starts (or reuses) the long-lived allowlist proxy for
// this orchestrator instance. Labels: opa.owner, opa.role=egress-proxy, opa.instance.
func ensureSharedEgressProxy(ctx context.Context) (string, error) {
	if sandboxMode() != "docker" {
		return "", nil
	}
	if err := requireDockerCLI(); err != nil {
		return "", err
	}
	egressProxyMu.Lock()
	defer egressProxyMu.Unlock()

	name := egressProxyContainerName()
	if id, err := dockerContainerIDByName(ctx, name); err == nil && id != "" {
		if running, _ := dockerContainerRunning(ctx, name); running {
			return name, nil
		}
		_ = dockerRmForce(ctx, name)
	}

	egNet := egressNetworkName()
	if out, err := dockerCmd(ctx, "network", "create", egNet); err != nil {
		low := strings.ToLower(string(out) + err.Error())
		if !strings.Contains(low, "already") {
			return "", fmt.Errorf("egress network: %w (%s)", err, truncateStr(string(out), 160))
		}
	}

	allow := strings.Join(aiEgressAllowlist(), ",")
	image := egressProxyImage()
	argv := []string{
		"run", "-d",
		"--name", name,
		"--label", "opa.owner=opa-orchestrator",
		"--label", "opa.role=" + egressProxyRoleLabel,
		"--label", "opa.instance=" + opaInstanceID(),
		"--network", egNet,
		"--restart", "unless-stopped",
		"-e", "OPA_EGRESS_ALLOWLIST=" + allow,
		"-e", "OPA_EGRESS_PROXY_LISTEN=:" + strconv.Itoa(egressProxyPort),
		image,
	}
	out, err := dockerCmd(ctx, argv...)
	if err != nil {
		return "", fmt.Errorf("egress proxy start: %w (%s)", err, truncateStr(string(out), 240))
	}
	// Brief ready wait — CONNECT listener.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if running, _ := dockerContainerRunning(ctx, name); running {
			return name, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return name, nil
}

func dockerContainerIDByName(ctx context.Context, name string) (string, error) {
	out, err := dockerCmd(ctx, "ps", "-aq", "--filter", "name=^/"+name+"$")
	if err != nil {
		return "", err
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		// Docker name filter is substring; fall back to inspect.
		out2, err2 := dockerCmd(ctx, "inspect", "-f", "{{.Id}}", name)
		if err2 != nil {
			return "", err2
		}
		return strings.TrimSpace(string(out2)), nil
	}
	return ids[0], nil
}

func dockerContainerRunning(ctx context.Context, name string) (bool, error) {
	out, err := dockerCmd(ctx, "inspect", "-f", "{{.State.Running}}", name)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

// attachEgressProxyToJobNetwork connects the shared proxy to a per-job --internal
// network with a stable DNS alias jobs use in HTTP(S)_PROXY.
func attachEgressProxyToJobNetwork(ctx context.Context, jobNet string) error {
	jobNet = strings.TrimSpace(jobNet)
	if jobNet == "" {
		return fmt.Errorf("empty job network")
	}
	proxy, err := ensureSharedEgressProxy(ctx)
	if err != nil {
		return err
	}
	out, err := dockerCmd(ctx, "network", "connect", "--alias", egressProxyAlias, jobNet, proxy)
	if err != nil {
		low := strings.ToLower(string(out) + err.Error())
		if strings.Contains(low, "already") {
			return nil
		}
		return fmt.Errorf("proxy network connect: %w (%s)", err, truncateStr(string(out), 160))
	}
	return nil
}

func detachEgressProxyFromNetwork(ctx context.Context, jobNet string) {
	jobNet = strings.TrimSpace(jobNet)
	if jobNet == "" || sandboxMode() != "docker" {
		return
	}
	name := egressProxyContainerName()
	_, _ = dockerCmd(ctx, "network", "disconnect", "-f", jobNet, name)
}

// prepareAIJobNetwork creates --internal job net, attaches the shared proxy, and
// returns the docker network name for --network. Caller must not remove the net
// mid-job; removeJobInternalNetwork detaches the proxy first.
func prepareAIJobNetwork(ctx context.Context, jobID string) (netName string, err error) {
	netName, err = createJobInternalNetwork(ctx, jobID)
	if err != nil {
		return "", err
	}
	if err := attachEgressProxyToJobNetwork(ctx, netName); err != nil {
		return "", err
	}
	return netName, nil
}

// --- CONNECT allowlist proxy (runs inside opa-egress-proxy container) ---

func runEgressProxyCLI(_ []string) error {
	allow := aiEgressAllowlist()
	if v := strings.TrimSpace(os.Getenv("OPA_EGRESS_ALLOWLIST")); v != "" {
		if parsed := parseEgressAllowlist(v); len(parsed) > 0 {
			allow = parsed
		}
	}
	listen := nz(strings.TrimSpace(os.Getenv("OPA_EGRESS_PROXY_LISTEN")), ":"+strconv.Itoa(egressProxyPort))
	return serveAllowlistEgressProxy(listen, allow)
}

func serveAllowlistEgressProxy(listen string, allow []string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	LogInfo("egress proxy listening", map[string]interface{}{
		"listen": listen, "allow": allow,
		"honesty": "allowlist is the dial gate; clients on --internal have no other route",
	})
	srv := &http.Server{
		Handler:           newAllowlistProxyHandler(allow),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.Serve(ln)
}

func newAllowlistProxyHandler(allow []string) http.Handler {
	allow = append([]string{}, allow...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleEgressCONNECT(w, r, allow)
			return
		}
		// Absolute-form HTTP proxy (rare for HTTPS APIs; still gated).
		handleEgressHTTP(w, r, allow)
	})
}

func handleEgressCONNECT(w http.ResponseWriter, r *http.Request, allow []string) {
	target := r.Host
	if target == "" {
		http.Error(w, "missing CONNECT host", http.StatusBadRequest)
		return
	}
	if !hostOnEgressAllowlist(target, allow) {
		http.Error(w, "egress deny: host not on allowlist", http.StatusForbidden)
		return
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = normalizeAllowHost(target)
		port = "443"
		target = net.JoinHostPort(host, port)
	}
	dest, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		_ = dest.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, bufrw, err := hij.Hijack()
	if err != nil {
		_ = dest.Close()
		return
	}
	_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufrw.Flush()
	go func() { _, _ = io.Copy(dest, client); _ = dest.Close(); _ = client.Close() }()
	_, _ = io.Copy(client, dest)
	_ = dest.Close()
	_ = client.Close()
}

func handleEgressHTTP(w http.ResponseWriter, r *http.Request, allow []string) {
	if r.URL == nil || r.URL.Host == "" {
		http.Error(w, "absolute URL required", http.StatusBadRequest)
		return
	}
	if !hostOnEgressAllowlist(r.URL.Host, allow) {
		http.Error(w, "egress deny: host not on allowlist", http.StatusForbidden)
		return
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	outReq.Header = r.Header.Clone()
	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
