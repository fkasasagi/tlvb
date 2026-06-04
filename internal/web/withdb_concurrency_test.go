package web

import (
	"context"
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
