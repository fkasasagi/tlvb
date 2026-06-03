package rulebuild

import (
	"database/sql"
	"fmt"

	_ "github.com/marcboeker/go-duckdb"
)

// SQLCompiler validates that generated SQL actually RUNS against the
// unified_events schema, by executing it (bound to a dummy case_id) over an
// empty in-memory DuckDB table. This catches build-time-valid-but-runtime-
// broken SQL the string validator can't see — unknown functions
// (regexp_like), unsupported operators (ILIKE ANY), malformed regex literals
// — before such SQL is cached as "built" and then silently skipped at Tier 1A
// runtime (known issue #6). Executing over an empty table is enough: these
// failure modes are data-independent (parser / catalog / regex-compile fire
// on zero rows too).
type SQLCompiler struct {
	db *sql.DB
}

// NewSQLCompiler opens an in-memory DuckDB and creates unified_events from the
// given DDL (casedb.UnifiedEventsDDL). An empty ddl yields a nil compiler so
// Check becomes a no-op — callers stay decoupled from casedb and a missing
// DDL simply disables the gate rather than erroring.
func NewSQLCompiler(ddl string) (*SQLCompiler, error) {
	if ddl == "" {
		return nil, nil
	}
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return nil, fmt.Errorf("open in-memory duckdb: %w", err)
	}
	if _, err := db.Exec(ddl); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create unified_events: %w", err)
	}
	db.SetMaxOpenConns(1)
	return &SQLCompiler{db: db}, nil
}

// Check executes sqlText (one bound case_id) against the empty table. A nil
// compiler or empty SQL is a no-op. A non-nil error means the SQL would fail
// at Tier 1A runtime.
func (c *SQLCompiler) Check(sqlText string) error {
	if c == nil || c.db == nil || sqlText == "" {
		return nil
	}
	rows, err := c.db.Query(sqlText, "__compilecheck__")
	if err != nil {
		return err
	}
	return rows.Close()
}

// Close releases the in-memory DB. Safe on a nil compiler.
func (c *SQLCompiler) Close() error {
	if c != nil && c.db != nil {
		return c.db.Close()
	}
	return nil
}
