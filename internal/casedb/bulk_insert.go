package casedb

import (
	"context"
	"errors"
	"fmt"
)

// Bulk-insert helpers used by the importer (REQ-2 Issue #16). Kept in a
// separate file so the import path's surface area is obvious to reviewers.
//
// None of these are exposed through MCP — they are read-write operations
// and the architectural constraint (DESIGN §1 原則3) says MCP is
// read-only by construction. They're plain Go methods on *Manager,
// reachable only from the CLI / Web import handler.

// BulkInsertEvidence inserts a batch of evidence rows. Existing rows
// with the same (case_id, evidence_id) are silently kept (ON CONFLICT
// DO NOTHING), because evidence_id is the chain-of-custody anchor —
// we never re-attribute one evidence to a different case. Wave 16
// changed the PK from (evidence_id) alone to (case_id, evidence_id)
// composite; Wave 47 fixes the conflict-target to match (the old form
// caused `case import` to crash with "specified columns as conflict
// target are not referenced by a UNIQUE/PRIMARY KEY CONSTRAINT").
func (m *Manager) BulkInsertEvidence(ctx context.Context, rows []EvidenceRow) error {
	if m.mode == ReadOnly {
		return errors.New("casedb opened read-only")
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO evidence (evidence_id, case_id, path, sha256, size_bytes,
		                     registered_at, source_host, evidence_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (case_id, evidence_id) DO NOTHING`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx,
			r.EvidenceID, r.CaseID, r.Path, r.SHA256, r.SizeBytes,
			r.RegisteredAt, nullableString(r.SourceHost),
			nullableString(r.EvidenceType),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("evidence %s: %w", r.EvidenceID, err)
		}
	}
	return tx.Commit()
}

// BulkInsertParseResults overwrites parse_results for each (case_id,
// evidence_id, artifact_id) tuple. Re-imports are idempotent. Rows from
// a pre-per-evidence .fcz carry no evidence_id and land under "" (the
// legacy un-attributed bucket).
func (m *Manager) BulkInsertParseResults(ctx context.Context, rows []ParseResultRow) error {
	if m.mode == ReadOnly {
		return errors.New("casedb opened read-only")
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO parse_results (case_id, evidence_id, artifact_id, started_at,
		                           finished_at, command, exit_code, stdout_tail,
		                           stderr_tail, output_csv, row_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (case_id, evidence_id, artifact_id) DO UPDATE SET
		  started_at=excluded.started_at,
		  finished_at=excluded.finished_at,
		  command=excluded.command,
		  exit_code=excluded.exit_code,
		  stdout_tail=excluded.stdout_tail,
		  stderr_tail=excluded.stderr_tail,
		  output_csv=excluded.output_csv,
		  row_count=excluded.row_count`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		var finishedAt any
		if r.FinishedAt != nil {
			finishedAt = *r.FinishedAt
		}
		var exitCode any
		if r.ExitCode != nil {
			exitCode = *r.ExitCode
		}
		var rowCount any
		if r.RowCount != nil {
			rowCount = *r.RowCount
		}
		if _, err := stmt.ExecContext(ctx,
			r.CaseID, r.EvidenceID, r.ArtifactID, r.StartedAt, finishedAt,
			r.Command, exitCode,
			nullableString(r.StdoutTail), nullableString(r.StderrTail),
			nullableString(r.OutputCSV), rowCount,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("parse_result %s/%s: %w", r.CaseID, r.ArtifactID, err)
		}
	}
	return tx.Commit()
}

// BulkInsertUnifiedEvents bulk-inserts unified events. unified_events
// has no primary key, so we never deduplicate at the SQL layer —
// callers are expected to DELETE existing case rows first when doing
// a clean overwrite.
func (m *Manager) BulkInsertUnifiedEvents(ctx context.Context, rows []UnifiedEventRow) error {
	if m.mode == ReadOnly {
		return errors.New("casedb opened read-only")
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO unified_events (case_id, evidence_id, artifact_id, audit_id,
		                            ts_utc, event_type, computer, payload_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		// Wave 47: when the row's ts_utc was originally NULL (e.g.
		// shimcache events which have no per-event timestamp), our
		// query helper stores it as a zero time.Time. Re-emit as
		// SQL NULL on insert so a round-trip preserves the semantic.
		var ts any
		if !r.TsUTC.IsZero() {
			ts = r.TsUTC
		}
		if _, err := stmt.ExecContext(ctx,
			r.CaseID, nullableString(r.EvidenceID), r.ArtifactID, r.AuditID,
			ts, r.EventType, nullableString(r.Computer), r.PayloadJSON,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("unified_event %s: %w", r.AuditID, err)
		}
	}
	return tx.Commit()
}

// DeleteCaseRows is the rows-only counterpart of DeleteCase. It is used
// by the importer when --overwrite is given so the new payload replaces
// the existing rows transactionally.
func (m *Manager) DeleteCaseRows(ctx context.Context, caseID string) error {
	return m.DeleteCase(ctx, caseID)
}
