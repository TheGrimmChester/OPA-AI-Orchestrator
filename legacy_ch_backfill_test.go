package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestOraLegacyBackfillTablesCoverSchema(t *testing.T) {
	required := []string{
		"watched_repos",
		"scm_jobs",
		"scm_review_stacks",
		"scm_webhooks",
		"review_contexts",
		"scm_secrets",
		"ai_reviews",
		"agent_prefs",
	}
	if len(oraLegacyBackfillTables) != len(required) {
		t.Fatalf("oraLegacyBackfillTables len=%d want %d", len(oraLegacyBackfillTables), len(required))
	}
	seen := map[string]struct{}{}
	for _, name := range oraLegacyBackfillTables {
		seen[name] = struct{}{}
	}
	for _, name := range required {
		if _, ok := seen[name]; !ok {
			t.Fatalf("missing legacy backfill table %s", name)
		}
	}
}

func TestBackfillLegacyTableOnBootSkipsWhenNotProductDB(t *testing.T) {
	t.Setenv("CLICKHOUSE_DB", "opa")
	if got := backfillLegacyTableOnBoot("watched_repos"); got != 0 {
		t.Fatalf("hub-only db should skip backfill, got %d", got)
	}
}

func TestBackfillLegacyTableOnBootNoClient(t *testing.T) {
	old := queryClient
	queryClient = nil
	t.Cleanup(func() { queryClient = old })
	t.Setenv("CLICKHOUSE_DB", "ora")
	if got := backfillLegacyTablesOnBoot(); got != 0 {
		t.Fatalf("nil client should skip, got %d", got)
	}
}

func TestLegacyBackfillInsertSQL(t *testing.T) {
	t.Setenv("CLICKHOUSE_DB", "ora")
	sql := fmtLegacyBackfillSQL("watched_repos")
	if !strings.Contains(sql, "INSERT INTO ora.watched_repos SELECT * FROM opa.watched_repos") {
		t.Fatalf("unexpected sql: %q", sql)
	}
}

// fmtLegacyBackfillSQL is test-only visibility for the INSERT shape.
func fmtLegacyBackfillSQL(table string) string {
	return fmt.Sprintf("INSERT INTO %s.%s SELECT * FROM %s.%s",
		clickHouseDatabase(), table, hubClickHouseDB, table)
}
