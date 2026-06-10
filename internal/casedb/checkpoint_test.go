package casedb

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestCheckpoint covers the post-delete WAL flush wired into the Web delete
// handler: CHECKPOINT must run cleanly through go-duckdb's connection pool
// right after a large delete, and must be rejected on a read-only manager.
func TestCheckpoint(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cases.duckdb")
	m, err := Open(p, ReadWrite)
	if err != nil {
		t.Fatalf("open rw: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()

	if err := m.RegisterCase(ctx, CaseRow{CaseID: "A", Name: "A", Examiner: "t"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	rows := make([]UnifiedEventRow, 0, 5000)
	for i := 0; i < 5000; i++ {
		rows = append(rows, UnifiedEventRow{
			CaseID: "A", ArtifactID: "evtx", AuditID: "a", EventType: "e",
			PayloadJSON: `{"k":"vvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"}`, TsUTC: now,
		})
	}
	if err := m.BulkInsertUnifiedEvents(ctx, rows); err != nil {
		t.Fatalf("bulk insert: %v", err)
	}
	if err := m.DeleteCase(ctx, "A"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// The real concern: CHECKPOINT must not error through the pooled connection.
	if err := m.Checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint after delete: %v", err)
	}
	m.Close()

	// A read-only manager must refuse to checkpoint.
	ro, err := Open(p, ReadOnly)
	if err != nil {
		t.Fatalf("open ro: %v", err)
	}
	defer ro.Close()
	if err := ro.Checkpoint(ctx); err == nil {
		t.Fatal("checkpoint on a read-only manager should error")
	}
}
