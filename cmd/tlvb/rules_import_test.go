package main

import (
	"reflect"
	"testing"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/rulesdb"
)

func TestStaleSchemaRows(t *testing.T) {
	// The expected key is now per-rule: a row is current when its stored
	// schema_version equals casedb.SchemaVersionFor(its prefilter). An evtx row
	// must NOT be flagged stale just because a non-evtx section changed.
	evtxCur := casedb.SchemaVersionFor([]string{"evtx"})
	amcacheCur := casedb.SchemaVersionFor([]string{"amcache"})
	allCur := casedb.SchemaVersionFor(nil) // empty prefilter => whole-doc fallback

	rows := []rulesdb.CacheRow{
		{RuleID: "a", PrefilterArtifacts: "evtx", SchemaVersion: evtxCur},       // current
		{RuleID: "b", PrefilterArtifacts: "evtx", SchemaVersion: "uev-old1"},    // stale
		{RuleID: "c", PrefilterArtifacts: "amcache", SchemaVersion: amcacheCur}, // current
		{RuleID: "d", PrefilterArtifacts: "amcache", SchemaVersion: "uev-old2"}, // stale
		{RuleID: "e", PrefilterArtifacts: "", SchemaVersion: allCur},            // current (fallback)
	}
	n, vers := staleSchemaRows(rows)
	if n != 2 {
		t.Errorf("stale count = %d, want 2", n)
	}
	if !reflect.DeepEqual(vers, []string{"uev-old1", "uev-old2"}) {
		t.Errorf("stale versions = %v, want [uev-old1 uev-old2]", vers)
	}

	// All-stale: every stored version is wrong.
	allStale := []rulesdb.CacheRow{
		{RuleID: "x", PrefilterArtifacts: "evtx", SchemaVersion: "uev-z"},
		{RuleID: "y", PrefilterArtifacts: "prefetch", SchemaVersion: "uev-z"},
	}
	if n, vers := staleSchemaRows(allStale); n != 2 || len(vers) != 1 {
		t.Errorf("all-stale case: n=%d vers=%v", n, vers)
	}

	if n, _ := staleSchemaRows(nil); n != 0 {
		t.Errorf("empty input: n=%d, want 0", n)
	}
}
