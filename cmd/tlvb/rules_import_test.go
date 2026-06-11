package main

import (
	"reflect"
	"testing"

	"github.com/tlvb/tlvb/internal/rulesdb"
)

func TestStaleSchemaRows(t *testing.T) {
	rows := []rulesdb.CacheRow{
		{RuleID: "a", SchemaVersion: "v3"},
		{RuleID: "b", SchemaVersion: "v2"},
		{RuleID: "c", SchemaVersion: "v3"},
		{RuleID: "d", SchemaVersion: "v1"},
	}
	n, vers := staleSchemaRows(rows, "v3")
	if n != 2 {
		t.Errorf("stale count = %d, want 2", n)
	}
	if !reflect.DeepEqual(vers, []string{"v1", "v2"}) {
		t.Errorf("stale versions = %v, want [v1 v2]", vers)
	}

	n, vers = staleSchemaRows(rows, "v9")
	if n != 4 || len(vers) != 3 {
		t.Errorf("all-stale case: n=%d vers=%v", n, vers)
	}

	if n, _ := staleSchemaRows(nil, "v3"); n != 0 {
		t.Errorf("empty input: n=%d, want 0", n)
	}
}
