package main

import (
	"strings"
	"testing"
)

func TestEnsureOraSchemaStatementsCoverProductTables(t *testing.T) {
	t.Setenv("CLICKHOUSE_DB", "ora")
	db := clickHouseDatabase()
	if db != "ora" {
		t.Fatalf("clickHouseDatabase=%q want ora", db)
	}
	required := []string{
		"connectors",
		"watched_repos",
		"scm_jobs",
		"scm_review_stacks",
		"scm_webhooks",
		"review_contexts",
		"scm_secrets",
		"ai_reviews",
		"agent_prefs",
	}
	joined := strings.Join(required, " ")
	for _, name := range required {
		if !strings.Contains(joined, name) {
			t.Fatalf("missing table %s", name)
		}
		want := db + "." + name
		if !strings.Contains(want, "ora.") {
			t.Fatalf("qualified name %s", want)
		}
	}
}
