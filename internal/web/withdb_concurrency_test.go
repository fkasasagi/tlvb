package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// newDBServer creates a Server backed by a fresh on-disk cases.duckdb (schema
// materialised by the ReadWrite open).
func newDBServer(t *testing.T) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "cases.duckdb")
	m, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	m.Close()
	return &Server{cfg: Config{DBPath: dbPath}}
}

// Two read-only withDB calls must be able to sit inside their callbacks at the
// same time — that is the whole point of the RWMutex switch, and it also
// confirms DuckDB permits concurrent access_mode=read_only opens of one file.
func TestWithDBReadOnlyAllowsConcurrentReaders(t *testing.T) {
	s := newDBServer(t)
	inside := make(chan struct{}, 2)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.withDB(casedb.ReadOnly, func(*casedb.Manager) error {
				inside <- struct{}{}
				<-release
				return nil
			}); err != nil {
				t.Errorf("withDB ReadOnly: %v", err)
			}
		}()
	}
	deadline := time.After(3 * time.Second)
	for got := 0; got < 2; {
		select {
		case <-inside:
			got++
		case <-deadline:
			t.Fatalf("only %d/2 readers were inside concurrently — reads are still serialised", got)
		}
	}
	close(release)
	wg.Wait()
}

// A writer must wait until in-flight readers drain, then proceed.
func TestWithDBWriterWaitsForReaders(t *testing.T) {
	s := newDBServer(t)
	readerIn := make(chan struct{})
	releaseReader := make(chan struct{})
	go func() {
		_ = s.withDB(casedb.ReadOnly, func(*casedb.Manager) error {
			close(readerIn)
			<-releaseReader
			return nil
		})
	}()
	<-readerIn

	writerDone := make(chan struct{})
	go func() {
		_ = s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
			return m.Ping(context.Background())
		})
		close(writerDone)
	}()

	select {
	case <-writerDone:
		t.Fatal("writer acquired the lock while a reader still held the RLock")
	case <-time.After(200 * time.Millisecond):
		// expected: blocked behind the reader
	}
	close(releaseReader)
	select {
	case <-writerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("writer never completed after the reader released")
	}
}

// A read must fail fast with ErrDBBusy (not block) while a writer holds the
// lock — that is what lets the HTTP layer answer "processing" instead of hanging.
func TestWithDBReadOnlyReturnsBusyUnderWriter(t *testing.T) {
	s := newDBServer(t)
	writerIn := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = s.withDB(casedb.ReadWrite, func(*casedb.Manager) error {
			close(writerIn)
			<-release
			return nil
		})
	}()
	<-writerIn
	err := s.withDB(casedb.ReadOnly, func(*casedb.Manager) error { return nil })
	if err == nil || err.Error() != ErrDBBusy.Error() {
		t.Fatalf("want ErrDBBusy while writer holds lock, got %v", err)
	}
	close(release)
}

// End-to-end of the busy contract: while a job holds the write lock, the Events
// handler answers 503 + busy:true (the UI cue) rather than hanging or 500.
func TestEventsHandlerReturns503BusyUnderWriter(t *testing.T) {
	s := newDBServer(t)
	s.dbMu.Lock() // stand in for a Parse/mutation job holding the case DB
	defer s.dbMu.Unlock()

	req := httptest.NewRequest("GET", "/api/cases/C1/events", nil)
	req.SetPathValue("id", "C1")
	w := httptest.NewRecorder()
	s.handleQueryEvents(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d (%s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["busy"] != true {
		t.Fatalf("want busy:true, got %v", body)
	}
}
