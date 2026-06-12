package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// These tests pin the fix for the "deleted case carries over" bug: a create
// against an existing case_id must NOT silently inherit the old case's data
// (RegisterCase is an UPSERT). Default → 409 reject (data preserved); with
// overwrite=true → old DB rows + workspace wiped, fresh case created.

func createCaseServer(t *testing.T) (*Server, http.Handler, string) {
	t.Helper()
	root := t.TempDir()
	s := &Server{
		cfg:    Config{DBPath: filepath.Join(root, "cases.duckdb"), OutputsRoot: filepath.Join(root, "cases")},
		jobs:   newJobsManager(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/cases", s.handleCreateCase)
	return s, mux, s.cfg.OutputsRoot
}

func postCreate(t *testing.T, mux http.Handler, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/cases", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func seedCaseData(t *testing.T, s *Server, caseID string) {
	t.Helper()
	if err := s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		if err := m.RegisterEvidence(context.Background(), casedb.EvidenceRow{
			EvidenceID: "ev1", CaseID: caseID, Path: "/img", SHA256: "s", RegisteredAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		if err := m.BulkInsertUnifiedEvents(context.Background(), []casedb.UnifiedEventRow{
			{CaseID: caseID, ArtifactID: "evtx", AuditID: "a", EventType: "e", PayloadJSON: "{}", TsUTC: time.Now().UTC()},
		}); err != nil {
			return err
		}
		// The real ingest path records a parse_results row alongside the events;
		// the case-detail event count (GetCaseStatus.UnifiedRowCount) is derived
		// scan-free from SUM(parse_results.row_count), so seed it too or the
		// snapshot would report 0 events for this 1-event case.
		rc := int64(1)
		return m.BulkInsertParseResults(context.Background(), []casedb.ParseResultRow{
			{CaseID: caseID, ArtifactID: "evtx", StartedAt: time.Now().UTC(), Command: "c", RowCount: &rc},
		})
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func caseSnapshot(t *testing.T, s *Server, caseID string) (ev int, events int64, name string, exists bool) {
	t.Helper()
	_ = s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		st, err := m.GetCaseStatus(context.Background(), caseID)
		if err != nil {
			return nil
		}
		ev, events, name, exists = st.EvidenceCount, st.UnifiedRowCount, st.Case.Name, true
		return nil
	})
	return
}

func TestCreateCase_RejectsDuplicateAndPreservesData(t *testing.T) {
	s, mux, _ := createCaseServer(t)

	if rec := postCreate(t, mux, map[string]any{"case_id": "C1", "name": "first"}); rec.Code != http.StatusCreated {
		t.Fatalf("first create: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	seedCaseData(t, s, "C1")

	// Duplicate create without overwrite → 409, and the old case is untouched.
	rec := postCreate(t, mux, map[string]any{"case_id": "C1", "name": "second"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create: want 409, got %d (%s)", rec.Code, rec.Body.String())
	}
	ev, events, name, _ := caseSnapshot(t, s, "C1")
	if ev != 1 || events != 1 {
		t.Errorf("reject must preserve data: evidence=%d events=%d", ev, events)
	}
	if name != "first" {
		t.Errorf("rejected create must not mutate the case: name=%q", name)
	}
}

func TestCreateCase_OverwriteWipesDataAndWorkspace(t *testing.T) {
	s, mux, outputs := createCaseServer(t)

	if rec := postCreate(t, mux, map[string]any{"case_id": "C1", "name": "first"}); rec.Code != http.StatusCreated {
		t.Fatalf("first create: %d", rec.Code)
	}
	seedCaseData(t, s, "C1")

	// A stale workspace file that overwrite must also remove.
	ws := filepath.Join(outputs, "C1")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(ws, "synthesis.json")
	if err := os.WriteFile(stale, []byte(`{"old":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := postCreate(t, mux, map[string]any{"case_id": "C1", "name": "fresh", "overwrite": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("overwrite create: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	ev, events, name, _ := caseSnapshot(t, s, "C1")
	if ev != 0 || events != 0 {
		t.Errorf("overwrite must wipe DB data: evidence=%d events=%d", ev, events)
	}
	if name != "fresh" {
		t.Errorf("overwrite should apply the new name: got %q", name)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("overwrite must remove stale workspace file (stat err=%v)", err)
	}
}

func TestCreateCase_NewCaseStillWorks(t *testing.T) {
	_, mux, _ := createCaseServer(t)
	rec := postCreate(t, mux, map[string]any{"case_id": "brand-new", "name": "n"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("new case: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
}
