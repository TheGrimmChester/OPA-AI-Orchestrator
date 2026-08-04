package main

import (
	"testing"
)

func TestNeedsLegacyConnectorFallback(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"ora", true},
		{"osa", true},
		{"opa", false},
		{"default", false},
		{"", true}, // defaultClickHouseDB = ora
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("CLICKHOUSE_DB", tc.env)
			t.Setenv("CLICKHOUSE_DATABASE", "")
			if got := needsLegacyConnectorFallback(); got != tc.want {
				t.Fatalf("needsLegacyConnectorFallback()=%v want %v (CLICKHOUSE_DB=%q)", got, tc.want, tc.env)
			}
		})
	}
}

func TestStoreHydratedConnectorSkipsDeleted(t *testing.T) {
	connectorLive.Delete("conn-test-deleted")
	c := &opaConnector{ID: "conn-test-deleted", Status: "deleted"}
	if got := storeHydratedConnector(c, false); got != nil {
		t.Fatalf("deleted connector should not be stored")
	}
	if _, ok := connectorLive.Load("conn-test-deleted"); ok {
		t.Fatal("deleted connector leaked into connectorLive")
	}
}
