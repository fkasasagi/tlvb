package casedb

import (
	"context"
	"path/filepath"
	"testing"
)

// TestCaseBackgroundRoundTrip covers the full background lifecycle: create with
// background, read it back via every accessor (GetCaseStatus / GetCaseBackground
// / raw ReadBackground), edit it mid-case, and reject an edit of an unknown case.
func TestCaseBackgroundRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cases.duckdb")
	ctx := context.Background()

	mgr, err := Open(dbPath, ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer mgr.Close()

	const bg = "WS01 is the internet-facing web server."
	if err := mgr.RegisterCase(ctx, CaseRow{
		CaseID: "c1", Name: "n", Examiner: "e", Timezone: "UTC", Background: bg,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	st, err := mgr.GetCaseStatus(ctx, "c1")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Case.Background != bg {
		t.Errorf("GetCaseStatus background = %q, want %q", st.Case.Background, bg)
	}

	if got := ReadBackground(ctx, mgr.DB(), "c1"); got != bg {
		t.Errorf("ReadBackground = %q, want %q", got, bg)
	}
	if got, _ := mgr.GetCaseBackground(ctx, "c1"); got != bg {
		t.Errorf("GetCaseBackground = %q, want %q", got, bg)
	}

	// Mid-case edit.
	const bg2 = "Updated: password brute-force confirmed against WS01."
	if err := mgr.UpdateCaseBackground(ctx, "c1", bg2); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got, _ := mgr.GetCaseBackground(ctx, "c1"); got != bg2 {
		t.Errorf("after update GetCaseBackground = %q, want %q", got, bg2)
	}

	// Editing a case that doesn't exist must error (no silent no-op).
	if err := mgr.UpdateCaseBackground(ctx, "missing", "x"); err == nil {
		t.Error("UpdateCaseBackground of unknown case must error")
	}

	// A case created without a background reads back as "".
	if err := mgr.RegisterCase(ctx, CaseRow{
		CaseID: "c2", Name: "n2", Examiner: "e", Timezone: "UTC",
	}); err != nil {
		t.Fatalf("register c2: %v", err)
	}
	if got := ReadBackground(ctx, mgr.DB(), "c2"); got != "" {
		t.Errorf("no-background case ReadBackground = %q, want empty", got)
	}
}

// TestReadBackgroundUnknownCase ensures the raw read degrades to "" rather than
// erroring when the case row is absent (background is advisory, never required).
func TestReadBackgroundUnknownCase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cases.duckdb")
	mgr, err := Open(dbPath, ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer mgr.Close()
	if got := ReadBackground(context.Background(), mgr.DB(), "nope"); got != "" {
		t.Errorf("ReadBackground of unknown case = %q, want empty", got)
	}
}
