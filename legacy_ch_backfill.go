package main

import (
	"fmt"
	"log"
)

const hubClickHouseDB = "opa"

// oraLegacyBackfillTables are ORA product tables that may still hold rows only in
// hub opa.* while Query() rewrites opa → ora. Connectors use row-level boot backfill
// in scm_connectors.go (#17); these tables use bulk INSERT SELECT on boot.
var oraLegacyBackfillTables = []string{
	"watched_repos",
	"scm_jobs",
	"scm_review_stacks",
	"scm_webhooks",
	"review_contexts",
	"scm_secrets",
	"ai_reviews",
	"agent_prefs",
}

func backfillLegacyTablesOnBoot() int {
	if queryClient == nil || !needsLegacyConnectorFallback() {
		return 0
	}
	total := 0
	for _, table := range oraLegacyBackfillTables {
		total += backfillLegacyTableOnBoot(table)
	}
	return total
}

func backfillLegacyTableOnBoot(table string) int {
	if queryClient == nil || table == "" || !needsLegacyConnectorFallback() {
		return 0
	}
	productDB := clickHouseDatabase()
	hubN, err := chTableRowCount(hubClickHouseDB, table)
	if err != nil || hubN == 0 {
		return 0
	}
	prodN, err := chTableRowCount(productDB, table)
	if err != nil {
		log.Printf("[WARN] legacy backfill %s: product count: %v", table, err)
		return 0
	}
	if prodN >= hubN {
		return 0
	}
	sql := fmt.Sprintf("INSERT INTO %s.%s SELECT * FROM %s.%s",
		productDB, table, hubClickHouseDB, table)
	if err := queryClient.ExecuteExact(sql); err != nil {
		log.Printf("[WARN] legacy backfill %s: %v", table, err)
		return 0
	}
	after, _ := chTableRowCount(productDB, table)
	if after > prodN {
		return int(after - prodN)
	}
	return 0
}

func chTableRowCount(db, table string) (uint64, error) {
	rows, err := queryClient.QueryExact(fmt.Sprintf(
		"SELECT count() AS c FROM %s.%s", db, table))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	switch v := rows[0]["c"].(type) {
	case float64:
		return uint64(v), nil
	case uint64:
		return v, nil
	case int64:
		if v < 0 {
			return 0, nil
		}
		return uint64(v), nil
	default:
		return 0, nil
	}
}
