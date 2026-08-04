package main

import (
	"log"
	"os"
	"strings"
)

// clickHouseDatabase resolves the product ClickHouse database name.
// Precedence: CLICKHOUSE_DB > CLICKHOUSE_DATABASE > product default.
func clickHouseDatabase() string {
	if v := strings.TrimSpace(os.Getenv("CLICKHOUSE_DB")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("CLICKHOUSE_DATABASE")); v != "" {
		return v
	}
	return defaultClickHouseDB
}

// ensureClickHouseDatabase creates the product DB when a query client is available.
func ensureClickHouseDatabase(q *ClickHouseQuery) {
	if q == nil {
		return
	}
	db := q.database
	if db == "" || db == "default" {
		return
	}
	_ = q.Execute("CREATE DATABASE IF NOT EXISTS " + db)
}

// ensureOraSchema creates ORA product tables in CLICKHOUSE_DB.
// Without this, legacy SQL rewrite (opa.* → ora.*) and writer INSERTs target an
// empty database and list/hydrate endpoints fail or return stale in-memory state only.
func ensureOraSchema(q *ClickHouseQuery) {
	if q == nil {
		return
	}
	db := clickHouseDatabase()
	if db == "" || db == "default" {
		return
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ` + db + `.connectors (
			id String,
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			kind LowCardinality(String) DEFAULT 'github_app',
			installation_id String DEFAULT '',
			account_login String DEFAULT '',
			status LowCardinality(String) DEFAULT 'active',
			token_ref String DEFAULT '',
			meta_json String DEFAULT '{}',
			created_at DateTime64(3) DEFAULT now64(3),
			updated_at DateTime64(3) DEFAULT now64(3),
			scope LowCardinality(String) DEFAULT '',
			user_id String DEFAULT ''
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY (organization_id, project_id, id)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.watched_repos (
			id String,
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			connector_id String DEFAULT '',
			repo_full_name String DEFAULT '',
			repo_id String DEFAULT '',
			enabled UInt8 DEFAULT 1,
			service_name String DEFAULT '',
			profile LowCardinality(String) DEFAULT 'auto',
			checks_json String DEFAULT '["secrets","sast","iac","ai_review"]',
			min_severity LowCardinality(String) DEFAULT 'high',
			ai_blocking UInt8 DEFAULT 0,
			auto_request_reviewer UInt8 DEFAULT 0,
			auto_approve_min_score UInt8 DEFAULT 0,
			updated_at DateTime64(3) DEFAULT now64(3),
			link_group_id String DEFAULT ''
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY (organization_id, project_id, connector_id, repo_full_name)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.scm_jobs (
			id String,
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			connector_id String DEFAULT '',
			repo_full_name String DEFAULT '',
			pr_number Int32 DEFAULT 0,
			commit_sha String DEFAULT '',
			event LowCardinality(String) DEFAULT '',
			status LowCardinality(String) DEFAULT 'queued',
			security_run_id String DEFAULT '',
			ai_job_id String DEFAULT '',
			check_run_ids String DEFAULT '{}',
			error String DEFAULT '',
			summary_json String DEFAULT '{}',
			started_at DateTime64(3) DEFAULT now64(3),
			finished_at DateTime64(3) DEFAULT now64(3),
			kind LowCardinality(String) DEFAULT '',
			run_id String DEFAULT '',
			attempt UInt8 DEFAULT 0
		) ENGINE = ReplacingMergeTree(finished_at)
		ORDER BY (organization_id, project_id, id)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.scm_review_stacks (
			id String,
			status LowCardinality(String) DEFAULT 'queued',
			job_ids_json String DEFAULT '[]',
			items_json String DEFAULT '[]',
			force UInt8 DEFAULT 1,
			ai_only UInt8 DEFAULT 0,
			note String DEFAULT '',
			honesty String DEFAULT '',
			created_at DateTime64(3) DEFAULT now64(3),
			updated_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY id`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.scm_webhooks (
			id String,
			received_at DateTime64(3) DEFAULT now64(3),
			delivery_id String DEFAULT '',
			event LowCardinality(String) DEFAULT '',
			action LowCardinality(String) DEFAULT '',
			repo_full_name String DEFAULT '',
			pr_number Int32 DEFAULT 0,
			commit_sha String DEFAULT '',
			installation_id String DEFAULT '',
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			connector_id String DEFAULT '',
			signature_valid UInt8 DEFAULT 0,
			outcome LowCardinality(String) DEFAULT '',
			job_id String DEFAULT '',
			stack_id String DEFAULT '',
			error String DEFAULT '',
			honesty String DEFAULT '',
			http_status Int32 DEFAULT 0,
			source LowCardinality(String) DEFAULT 'live'
		) ENGINE = ReplacingMergeTree(received_at)
		ORDER BY (organization_id, id)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.review_contexts (
			id String,
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			connector_id String DEFAULT '',
			repo_full_name String DEFAULT '',
			title String DEFAULT '',
			body_markdown String DEFAULT '',
			tags_json String DEFAULT '[]',
			link_group_id String DEFAULT '',
			source LowCardinality(String) DEFAULT 'manual',
			updated_at DateTime64(3) DEFAULT now64(3),
			created_at DateTime64(3) DEFAULT now64(3),
			deleted UInt8 DEFAULT 0,
			kind LowCardinality(String) DEFAULT 'note',
			status LowCardinality(String) DEFAULT 'active'
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY (organization_id, project_id, id)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.scm_secrets (
			key String,
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			ciphertext String DEFAULT '',
			updated_at DateTime64(3) DEFAULT now64(3),
			deleted UInt8 DEFAULT 0,
			scope LowCardinality(String) DEFAULT '',
			user_id String DEFAULT ''
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY (organization_id, project_id, key)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.ai_reviews (
			id String,
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			job_id String DEFAULT '',
			model String DEFAULT '',
			summary String DEFAULT '',
			findings_json String DEFAULT '[]',
			cursor_usage String DEFAULT '',
			status LowCardinality(String) DEFAULT 'pending',
			created_at DateTime64(3) DEFAULT now64(3),
			finished_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(finished_at)
		ORDER BY (organization_id, project_id, id)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.agent_prefs (
			organization_id String,
			project_id String,
			level LowCardinality(String),
			scope_key String,
			prefs_json String DEFAULT '{}',
			updated_at DateTime64(3) DEFAULT now64(3),
			updated_by String DEFAULT '',
			deleted UInt8 DEFAULT 0
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY (organization_id, project_id, level, scope_key)`,
	}
	for _, s := range stmts {
		if err := q.Execute(s); err != nil {
			log.Printf("ora schema: %v", err)
		}
	}
}
