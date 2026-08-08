package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	openegress "github.com/TheGrimmChester/open-egress-proxy/orchestrate"
	openlogger "github.com/TheGrimmChester/open-logger-go"
)

// Shared allowlist egress proxy for sandboxed AI phases.
//
// Honesty: HTTP(S)_PROXY is only a hint — a process inside the box can unset it.
// The real boundary is the per-job --internal network (no default route) with the
// proxy as the only container that also joins an egress network.

const (
	egressProxyRoleLabel     = "egress-proxy"
	egressProxyPort          = 3128
	egressProxyAlias         = "open-egress-proxy"
	networkModeInternalProxy = "internal+proxy" // sentinel for networkForPhase / runner
)

var (
	// Cursor agent endpoints rotate (api, api2, api5 / agentn.global.api5…).
	// Suffix match covers regional hosts like agentn.global.api5.cursor.sh.
	defaultAIAllowHosts = []string{
		"api.cursor.sh",
		"api2.cursor.sh",
		"api3.cursor.sh",
		"api4.cursor.sh",
		"api5.cursor.sh",
	}
	// npm registry hosts — off by default for AI; enable with OPA_JOB_EGRESS_NPM=1
	// or OPA_JOB_EGRESS_CHECKUP=1 (checkup defaults ON so npm ci / go test work).
	npmEgressAllowHosts = []string{
		"registry.npmjs.org",
		"registry.yarnpkg.com",
	}
	// Go module / checksum / VCS hosts for checkup `go test` / `go mod download`.
	goEgressAllowHosts = []string{
		"proxy.golang.org",
		"sum.golang.org",
		"storage.googleapis.com",
		"github.com",
		"objects.githubusercontent.com",
		"codeload.github.com",
		"proxy.golang.com",
	}
	// Composer / Packagist for PHP checkup install steps.
	composerEgressAllowHosts = []string{
		"repo.packagist.org",
		"packagist.org",
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

// checkupEgressEnabled adds package-registry hosts to the shared proxy allowlist.
// Default ON in docker sandbox so heuristic checkup (npm ci / go test / composer)
// can reach registries; set OPA_JOB_EGRESS_CHECKUP=0 for sealed offline checkup.
func checkupEgressEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OPA_JOB_EGRESS_CHECKUP"))) {
	case "0", "off", "false", "no":
		return false
	default:
		return sandboxMode() == "docker"
	}
}

// aiEgressAllowlist returns hosts the shared proxy may dial for AI / checkup phases.
func aiEgressAllowlist() []string {
	if v := strings.TrimSpace(os.Getenv("OPA_JOB_EGRESS_ALLOWLIST")); v != "" {
		parsed := parseEgressAllowlist(v)
		if len(parsed) > 0 {
			return parsed
		}
	}
	out := append([]string{}, defaultAIAllowHosts...)
	if strings.TrimSpace(os.Getenv("OPA_JOB_EGRESS_NPM")) == "1" || checkupEgressEnabled() {
		out = append(out, npmEgressAllowHosts...)
	}
	if checkupEgressEnabled() {
		out = append(out, goEgressAllowHosts...)
		out = append(out, composerEgressAllowHosts...)
	}
	return out
}

// parseEgressAllowlist delegates to open-egress-proxy/orchestrate.
func parseEgressAllowlist(raw string) []string {
	return openegress.ParseAllowlist(raw)
}

func normalizeAllowHost(h string) string {
	return openegress.NormalizeHost(h)
}

func hostOnEgressAllowlist(hostport string, allow []string) bool {
	return openegress.HostAllowed(hostport, allow)
}

func egressProxyImage() string {
	if v := strings.TrimSpace(os.Getenv("OPA_JOB_EGRESS_PROXY_IMAGE")); v != "" {
		return v
	}
	tag := nz(strings.TrimSpace(os.Getenv("OPA_JOB_IMAGE_TAG")), "smoke")
	return "open-egress-proxy:" + tag
}

func egressProxyContainerName() string {
	return "open-egress-proxy-" + opaInstanceID()
}

func egressNetworkName() string {
	return "opa-egress-" + opaInstanceID()
}

// egressStackNetworks are extra docker networks the shared proxy must join so
// outbound routing/DNS matches the compose stack (NAS: opa-stack_opa_internal).
// Override with OPA_JOB_EGRESS_STACK_NETWORKS=net1,net2 (empty disables).
func egressStackNetworks() []string {
	if v, ok := os.LookupEnv("OPA_JOB_EGRESS_STACK_NETWORKS"); ok {
		return parseEgressAllowlist(v)
	}
	return []string{"opa-stack_opa_internal", "opa_network"}
}

func jobNetworkName(jobID string) string {
	return "opa-job-" + sanitizeDockerName(jobID)
}

type oraEgressDocker struct{}

func (oraEgressDocker) Cmd(ctx context.Context, args ...string) ([]byte, error) {
	return dockerCmd(ctx, args...)
}

func (oraEgressDocker) RmForce(ctx context.Context, name string) error {
	return dockerRmForce(ctx, name)
}

func egressOrchestrateConfig() openegress.Config {
	return openegress.Config{
		ContainerName: egressProxyContainerName(),
		NetworkName:   egressNetworkName(),
		Image:         egressProxyImage(),
		Allowlist:     aiEgressAllowlist(),
		OwnerLabel:    "opa.owner=opa-orchestrator",
		InstanceLabel: "opa.instance=" + opaInstanceID(),
		RoleLabelKey:  "opa.role",
		StackNetworks: egressStackNetworks(),
		Alias:         egressProxyAlias,
		Port:          egressProxyPort,
	}
}

// egressProxyEnvVars are injected into AI job boxes when using internal+proxy.
func egressProxyEnvVars() map[string]string {
	return openegress.ProxyEnvVars(egressProxyAlias, egressProxyPort)
}

// ensureSharedEgressProxy starts (or reuses) the long-lived allowlist proxy for
// this orchestrator instance via open-egress-proxy/orchestrate.
func ensureSharedEgressProxy(ctx context.Context) (string, error) {
	if sandboxMode() != "docker" {
		return "", nil
	}
	if err := requireDockerCLI(); err != nil {
		return "", err
	}
	return openegress.EnsureShared(ctx, oraEgressDocker{}, egressOrchestrateConfig())
}

// attachEgressProxyToJobNetwork connects the shared proxy to a per-job --internal
// network with a stable DNS alias jobs use in HTTP(S)_PROXY.
func attachEgressProxyToJobNetwork(ctx context.Context, jobNet string) error {
	if sandboxMode() != "docker" {
		return nil
	}
	if err := requireDockerCLI(); err != nil {
		return err
	}
	return openegress.AttachToNetwork(ctx, oraEgressDocker{}, egressOrchestrateConfig(), jobNet)
}

func detachEgressProxyFromNetwork(ctx context.Context, jobNet string) {
	if sandboxMode() != "docker" {
		return
	}
	openegress.DetachFromNetwork(ctx, oraEgressDocker{}, egressOrchestrateConfig(), jobNet)
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
	openlogger.LogInfo("egress proxy listening", map[string]interface{}{
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
