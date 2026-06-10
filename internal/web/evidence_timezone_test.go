package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// tzServer builds a Server over a fresh DB seeded with one case + one evidence,
// plus a mux carrying just the set-timezone route under test.
func tzServer(t *testing.T) (*Server, http.Handler, string, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "cases.duckdb")
	m, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	ctx := context.Background()
	caseID, evID := "case-tz", "EV-1"
	if err := m.RegisterCase(ctx, casedb.CaseRow{
		CaseID: caseID, Name: "tz", Examiner: "test", Timezone: "UTC",
		CreatedAt: time.Now().UTC(), Status: "active",
	}); err != nil {
		t.Fatalf("register case: %v", err)
	}
	if err := m.RegisterEvidence(ctx, casedb.EvidenceRow{
		EvidenceID: evID, CaseID: caseID, Path: "/tmp/x", SHA256: "s",
		RegisteredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("register evidence: %v", err)
	}
	m.Close()

	s := &Server{cfg: Config{DBPath: dbPath}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/cases/{id}/evidence/{evid}/timezone", s.handleSetEvidenceTimezone)
	return s, mux, caseID, evID
}

func tzOfEvidence(t *testing.T, s *Server, caseID, evID string) string {
	t.Helper()
	var got string
	if err := s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		evs, err := m.ListEvidence(context.Background(), caseID)
		if err != nil {
			return err
		}
		for _, e := range evs {
			if e.EvidenceID == evID {
				got = e.Timezone
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	return got
}

func TestSetEvidenceTimezone(t *testing.T) {
	s, mux, caseID, evID := tzServer(t)
	path := "/api/cases/" + caseID + "/evidence/" + evID + "/timezone"

	// Valid IANA zone → 200 and persisted.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", path,
		bytes.NewBufferString(`{"timezone":"Asia/Tokyo"}`)))
	if rec.Code != 200 {
		t.Fatalf("set valid tz: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := tzOfEvidence(t, s, caseID, evID); got != "Asia/Tokyo" {
		t.Fatalf("after set: want Asia/Tokyo, got %q", got)
	}

	// Empty string clears the override (inherit case).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", path,
		bytes.NewBufferString(`{"timezone":""}`)))
	if rec.Code != 200 {
		t.Fatalf("clear tz: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := tzOfEvidence(t, s, caseID, evID); got != "" {
		t.Fatalf("after clear: want empty, got %q", got)
	}

	// Garbage zone → 400, and nothing persisted.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", path,
		bytes.NewBufferString(`{"timezone":"Not/AZone"}`)))
	if rec.Code != 400 {
		t.Fatalf("invalid tz: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
	if got := tzOfEvidence(t, s, caseID, evID); got != "" {
		t.Fatalf("invalid tz must not persist, got %q", got)
	}

	// Unknown evidence → 500 (UpdateEvidenceTimezone reports no rows affected).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST",
		"/api/cases/"+caseID+"/evidence/EV-nope/timezone",
		bytes.NewBufferString(`{"timezone":"UTC"}`)))
	if rec.Code != 500 {
		t.Fatalf("unknown evidence: want 500, got %d (%s)", rec.Code, rec.Body.String())
	}
}
