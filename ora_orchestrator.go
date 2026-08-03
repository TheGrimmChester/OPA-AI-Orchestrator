package main

import (
	"log"
	"net/http"

	openjob "github.com/TheGrimmChester/open-job-go"
)

// runORAOrchestrator is the ora-orchestrator entrypoint (same image, second command).
// Schedules review/git/coding jobs as one ephemeral ora-runner-* container per phase.
func runORAOrchestrator() {
	addr := envOr("ORCHESTRATOR_LISTEN_ADDR", ":8096")
	tag := envOr("ORA_RUNNER_TAG", "smoke")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"service": "ora-orchestrator",
			"version": buildVersion,
			"runners": []string{
				openjob.RunnerImage("ora", "git", tag),
				openjob.RunnerImage("ora", "ai", tag),
				openjob.RunnerImage("ora", "php", tag),
			},
		})
	})
	log.Printf("ora-orchestrator listening on %s (one container per review job phase)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
