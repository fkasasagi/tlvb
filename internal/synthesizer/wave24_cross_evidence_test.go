package synthesizer

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/tlvb/tlvb/internal/agents"
)

// Wave 24: DetectCrossEvidence is a SQL-backed helper. We test it against
// an in-memory DuckDB seeded with a minimal unified_events table so the
// detection logic can be exercised without a real case.

func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE unified_events (
			case_id     VARCHAR,
			evidence_id VARCHAR,
			audit_id    VARCHAR,
			ts_utc      TIMESTAMP,
			artifact_id VARCHAR,
			computer    VARCHAR,
			payload_json VARCHAR
		)
	`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func seed(t *testing.T, db *sql.DB, caseID, evID, auditID string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO unified_events (case_id, evidence_id, audit_id, ts_utc, artifact_id)
		 VALUES (?, ?, ?, NOW(), 'test')`,
		caseID, evID, auditID,
	)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func TestDetectCrossEvidence_SingleEvidenceReturnsNil(t *testing.T) {
	db := setupDB(t)
	defer db.Close()
	seed(t, db, "CASE-A", "ev-1", "audit-1")
	seed(t, db, "CASE-A", "ev-1", "audit-2")

	agg := &AggregateResult{
		AllFindings: []FindingWithSource{
			{
				TacticID: "TA0001",
				Finding: agents.Finding{
					FindingID: "f1", TechniqueID: "T1078",
					Evidence: []agents.Evidence{{AuditID: "audit-1"}},
				},
			},
		},
	}
	out, err := DetectCrossEvidence(context.Background(), db, "CASE-A", agg)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("single-evidence case must return nil, got %d correlations", len(out))
	}
}

func TestDetectCrossEvidence_MultiEvidenceSameTechniqueHits(t *testing.T) {
	db := setupDB(t)
	defer db.Close()
	// Two evidences observing the same technique via different audit_ids.
	seed(t, db, "CASE-B", "ev-A", "audit-1")
	seed(t, db, "CASE-B", "ev-B", "audit-2")

	agg := &AggregateResult{
		AllFindings: []FindingWithSource{
			{
				TacticID: "TA0008", // Lateral Movement
				Finding: agents.Finding{
					FindingID: "f1", TechniqueID: "T1021",
					Evidence: []agents.Evidence{
						{AuditID: "audit-1"},
						{AuditID: "audit-2"},
					},
				},
			},
		},
	}
	out, err := DetectCrossEvidence(context.Background(), db, "CASE-B", agg)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 cross-evidence correlation, got %d: %+v", len(out), out)
	}
	c := out[0]
	if c.TechniqueID != "T1021" {
		t.Errorf("TechniqueID: got %s, want T1021", c.TechniqueID)
	}
	if len(c.EvidenceIDs) != 2 {
		t.Errorf("EvidenceIDs: got %v, want 2 entries", c.EvidenceIDs)
	}
	if c.Severity != "warning" {
		t.Errorf("Lateral Movement (TA0008) should be warning, got %s", c.Severity)
	}
}

func TestDetectCrossEvidence_LowImpactTacticIsInfo(t *testing.T) {
	db := setupDB(t)
	defer db.Close()
	seed(t, db, "CASE-C", "ev-1", "audit-1")
	seed(t, db, "CASE-C", "ev-2", "audit-2")

	agg := &AggregateResult{
		AllFindings: []FindingWithSource{
			{
				TacticID: "TA0007", // Discovery — low impact
				Finding: agents.Finding{
					FindingID: "f1", TechniqueID: "T1083",
					Evidence: []agents.Evidence{
						{AuditID: "audit-1"},
						{AuditID: "audit-2"},
					},
				},
			},
		},
	}
	out, err := DetectCrossEvidence(context.Background(), db, "CASE-C", agg)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(out))
	}
	if out[0].Severity != "info" {
		t.Errorf("Discovery (TA0007) should be info, got %s", out[0].Severity)
	}
}

func TestDetectCrossEvidence_DifferentEvidencesDifferentTechniquesNoHit(t *testing.T) {
	// Two evidences, but each technique only observed on ONE evidence →
	// no cross-evidence correlation.
	db := setupDB(t)
	defer db.Close()
	seed(t, db, "CASE-D", "ev-A", "audit-1")
	seed(t, db, "CASE-D", "ev-B", "audit-2")

	agg := &AggregateResult{
		AllFindings: []FindingWithSource{
			{TacticID: "TA0001", Finding: agents.Finding{
				FindingID: "f1", TechniqueID: "T1078",
				Evidence: []agents.Evidence{{AuditID: "audit-1"}}}},
			{TacticID: "TA0003", Finding: agents.Finding{
				FindingID: "f2", TechniqueID: "T1547",
				Evidence: []agents.Evidence{{AuditID: "audit-2"}}}},
		},
	}
	out, err := DetectCrossEvidence(context.Background(), db, "CASE-D", agg)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("no shared technique → no correlation, got %d: %+v", len(out), out)
	}
}

func TestDetectCrossEvidence_StableOrderingByseverity(t *testing.T) {
	db := setupDB(t)
	defer db.Close()
	// 4 evidences, 2 techniques across all.
	for _, ev := range []string{"ev-1", "ev-2", "ev-3", "ev-4"} {
		seed(t, db, "CASE-E", ev, ev+"-audit-A")
		seed(t, db, "CASE-E", ev, ev+"-audit-B")
	}

	agg := &AggregateResult{
		AllFindings: []FindingWithSource{
			// Low-impact (info)
			{TacticID: "TA0007", Finding: agents.Finding{
				FindingID: "f1", TechniqueID: "T1083",
				Evidence: []agents.Evidence{
					{AuditID: "ev-1-audit-A"}, {AuditID: "ev-2-audit-A"},
				}}},
			// High-impact (warning) — should sort FIRST
			{TacticID: "TA0008", Finding: agents.Finding{
				FindingID: "f2", TechniqueID: "T1021",
				Evidence: []agents.Evidence{
					{AuditID: "ev-3-audit-B"}, {AuditID: "ev-4-audit-B"},
				}}},
		},
	}
	out, err := DetectCrossEvidence(context.Background(), db, "CASE-E", agg)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 correlations, got %d", len(out))
	}
	if out[0].Severity != "warning" || out[1].Severity != "info" {
		t.Errorf("severity order broken: %s then %s (want warning first)",
			out[0].Severity, out[1].Severity)
	}
}

func TestDetectCrossEvidence_NilAggIsNoop(t *testing.T) {
	db := setupDB(t)
	defer db.Close()
	out, err := DetectCrossEvidence(context.Background(), db, "X", nil)
	if err != nil {
		t.Errorf("nil agg should not error: %v", err)
	}
	if out != nil {
		t.Errorf("nil agg should return nil correlations, got %+v", out)
	}
}

func TestCaseSynthesis_HasCrossEvidenceField(t *testing.T) {
	// Pin the struct field so future renames break the test, not the report.
	c := CaseSynthesis{}
	c.CrossEvidenceCorrelations = []CrossEvidenceCorrelation{
		{TechniqueID: "T1021", Tactic: "TA0008", Severity: "warning"},
	}
	if c.CrossEvidenceCorrelations[0].TechniqueID != "T1021" {
		t.Errorf("CrossEvidenceCorrelations field round-trip broken")
	}
}
