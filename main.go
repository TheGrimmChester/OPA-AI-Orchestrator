package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	queryClient  *ClickHouseQuery
	writer       *ClickHouseWriter
	buildVersion = "orchestrator-dev"
)

func main() {
	// Shared allowlist egress proxy (OPA_JOB_SANDBOX=docker). Runs as a separate
	// container from the opa-egress-proxy image / this binary's egress-proxy mode.
	if len(os.Args) >= 2 && os.Args[1] == "egress-proxy" {
		if err := runEgressProxyCLI(os.Args[2:]); err != nil {
			log.Fatalf("egress-proxy: %v", err)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "orchestrator" {
		runORAOrchestrator()
		return
	}

	addr := envOr("HTTP_ADDR", ":8091")
	chURL := envOr("CLICKHOUSE_URL", "http://127.0.0.1:8123")

	writer = NewClickHouseWriter(chURL, 100)
	queryClient = NewClickHouseQuery(chURL)
	ensureClickHouseDatabase(queryClient)
	ensureOraSchema(queryClient)
	initAuthMode()

	authRequired := authRequiredEnv()
	setAuthEnforced(authRequired)
	if authRequired {
		log.Printf("auth: ENABLED (OPA_AUTH_REQUIRED)")
	} else {
		log.Printf("auth: disabled — endpoints open")
	}

	mux := http.NewServeMux()
	authView := func(pattern string, h http.HandlerFunc) {
		if authRequired {
			mux.HandleFunc(pattern, AuthMiddleware(h, "viewer"))
		} else {
			mux.HandleFunc(pattern, h)
		}
	}
	authAdmin := func(pattern string, h http.HandlerFunc) {
		if authRequired {
			mux.HandleFunc(pattern, AuthMiddleware(h, "admin"))
		} else {
			mux.HandleFunc(pattern, h)
		}
	}

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"status":   "ok",
			"service":  "ora-api",
			"version":  buildVersion,
			"database": clickHouseDatabase(),
			"auth_mode": string(authMode),
		})
	})
	registerLocalAuthMux(mux)

	registerOAMProjectsMux(mux, authView)
	registerRepoWatchMux(mux, authView, authAdmin)
	registerAIMux(mux, authView, authAdmin)
	registerAgentsPrefsMux(mux, authView, authAdmin)
	if oamConfigured() {
		go publishAgentCatalog(context.Background())
	} else {
		log.Printf("oam: PEER_OAM_URL unset — AI job keys stay on local settings until OAM is configured")
		loadAISettingsFromFileOnBoot()
	}

	go func() {
		// Give CH a moment, then hydrate SCM state (PATs, jobs, stacks).
		time.Sleep(2 * time.Second)
		hydrateSCMOnBoot()
		bootSandboxMaintenance()
		if !oamConfigured() {
			loadAISettingsFromFileOnBoot()
		}
	}()

	srv := &http.Server{
		Addr:              addr,
		Handler:           corsMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("ora-api listening on %s (CH=%s db=%s)", addr, chURL, clickHouseDatabase())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}
