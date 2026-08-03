package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTeardownJobContainersByRunUsesOpaRunLabel(t *testing.T) {
	got := dockerLabelFilter("opa.run", "Run_1/../x")
	want := "label=opa.run=" + sanitizeDockerName("Run_1/../x")
	if got != want {
		t.Fatalf("filter=%q want %q", got, want)
	}
	if !strings.HasPrefix(got, "label=opa.run=") {
		t.Fatalf("ByRun must filter on opa.run label, got %q", got)
	}
	if strings.Contains(got, "/") || strings.Contains(got, "..") {
		t.Fatalf("value must be sanitized: %q", got)
	}

	jobFilter := dockerLabelFilter("opa.job", "child-1")
	if !strings.HasPrefix(jobFilter, "label=opa.job=") {
		t.Fatalf("job teardown filter: %q", jobFilter)
	}

	// sandbox off / empty runID must no-op without talking to docker.
	t.Setenv("OPA_JOB_SANDBOX", "off")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := teardownJobContainersByRun(ctx, "run1"); err != nil {
		t.Fatalf("sandbox off: %v", err)
	}
	t.Setenv("OPA_JOB_SANDBOX", "docker")
	if err := teardownJobContainersByRun(ctx, ""); err != nil {
		t.Fatalf("empty runID: %v", err)
	}
	if err := teardownJobContainersByRun(ctx, "   "); err != nil {
		t.Fatalf("blank runID: %v", err)
	}
}
