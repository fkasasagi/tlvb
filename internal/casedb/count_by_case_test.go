package casedb

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func i64(v int64) *int64 { return &v }

// TestCountByCase covers the scan-free per-case enrichment used by the
// Dashboard listing: event counts come from parse_results.row_count (not a
// unified_events scan), evidence counts from the evidence table. A case with
// no rows must be absent from the map (callers default to 0).
func TestCountByCase(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "cases.duckdb"), ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	// Case A: 2 evidence, parse_results summing to 30 events.
	// Case B: 1 evidence, parse_results summing to 5 events.
	// Case C: registered but no evidence and no parse rows (the zero case).
	for _, id := range []string{"A", "B", "C"} {
		if err := m.RegisterCase(ctx, CaseRow{CaseID: id, Name: id, Examiner: "t"}); err != nil {
			t.Fatalf("register case %s: %v", id, err)
		}
	}
	if err := m.BulkInsertEvidence(ctx, []EvidenceRow{
		{EvidenceID: "e1", CaseID: "A", Path: "/a1", SHA256: "x", SizeBytes: 1, RegisteredAt: now},
		{EvidenceID: "e2", CaseID: "A", Path: "/a2", SHA256: "y", SizeBytes: 1, RegisteredAt: now},
		{EvidenceID: "e1", CaseID: "B", Path: "/b1", SHA256: "z", SizeBytes: 1, RegisteredAt: now},
	}); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	if err := m.BulkInsertParseResults(ctx, []ParseResultRow{
		{CaseID: "A", ArtifactID: "evtx", StartedAt: now, Command: "c", RowCount: i64(20)},
		{CaseID: "A", ArtifactID: "amcache", StartedAt: now, Command: "c", RowCount: i64(10)},
		{CaseID: "B", ArtifactID: "evtx", StartedAt: now, Command: "c", RowCount: i64(5)},
	}); err != nil {
		t.Fatalf("insert parse_results: %v", err)
	}

	ec, err := m.EventCountsByCase(ctx)
	if err != nil {
		t.Fatalf("EventCountsByCase: %v", err)
	}
	if ec["A"] != 30 || ec["B"] != 5 {
		t.Fatalf("event counts = %v, want A:30 B:5", ec)
	}
	if _, ok := ec["C"]; ok {
		t.Fatalf("case C has no parse rows but appeared in the map: %v", ec)
	}

	vc, err := m.CountEvidenceByCase(ctx)
	if err != nil {
		t.Fatalf("CountEvidenceByCase: %v", err)
	}
	if vc["A"] != 2 || vc["B"] != 1 {
		t.Fatalf("evidence counts = %v, want A:2 B:1", vc)
	}
	if _, ok := vc["C"]; ok {
		t.Fatalf("case C has no evidence but appeared in the map: %v", vc)
	}
}
