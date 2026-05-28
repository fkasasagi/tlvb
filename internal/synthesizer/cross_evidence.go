// Package synthesizer — cross-evidence correlation (Wave 24, DESIGN v0.3 #7).
//
// Detects when a single MITRE technique was observed across MULTIPLE
// evidences in the same case. Useful for examiners reading multi-host
// engagements: "T1110 (Brute Force) hit hosts A and B with overlapping
// timing → likely coordinated rather than two independent intrusions".
//
// The detection is intentionally simple: count distinct evidence_ids per
// technique by looking up the unified_events.evidence_id for every
// Finding.Evidence[].AuditID the LLM cited. A correlation is "open" if
// the same technique was observed on >= 2 evidence_ids.
//
// Severity scheme:
//   info     — same technique on 2 evidences, low-noise tactic
//                (Discovery / Collection)
//   warning  — same technique on 2+ evidences, high-impact tactic
//                (Initial Access / Lateral Movement / Credential Access /
//                 Defense Evasion)
//
// The result is plumbed into CaseSynthesis.CrossEvidenceCorrelations
// (omitempty for single-evidence cases) so the report (Tier 3) and the
// review UI (Gate 1) can surface it.
package synthesizer

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// CrossEvidenceCorrelation records one technique observed across multiple
// evidences. JSON-stable for serialisation into CaseSynthesis.
type CrossEvidenceCorrelation struct {
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name,omitempty"`
	Tactic        string   `json:"tactic"` // tactic_id e.g. TA0008
	EvidenceIDs   []string `json:"evidence_ids"`
	FindingIDs    []string `json:"finding_ids"`
	AuditIDs      []string `json:"audit_ids"`
	Description   string   `json:"description"` // examiner-facing summary
	Severity      string   `json:"severity"`    // info | warning
}

// High-impact tactics that trigger "warning" severity when observed on
// multiple evidences. Other tactics (Discovery, Collection, …) default
// to "info" because they don't on their own indicate active spread.
var highImpactTactics = map[string]bool{
	"TA0001": true, // Initial Access
	"TA0006": true, // Credential Access
	"TA0008": true, // Lateral Movement
	"TA0005": true, // Defense Evasion
	"TA0010": true, // Command and Control
	"TA0040": true, // Impact
}

// DetectCrossEvidence (Wave 24) walks every finding in the aggregate result,
// resolves the evidence_id of each cited audit_id via unified_events, and
// emits one CrossEvidenceCorrelation per technique observed on ≥ 2 evidences.
//
// Returns an empty slice (no error) when:
//   - the case has fewer than 2 evidences total (single-host)
//   - no finding has cited audit_ids that resolve to multiple evidence_ids
//
// Per-technique audit_ids are deduped and lex-sorted so the output is
// stable across runs (relevant for diff-based regression tests).
func DetectCrossEvidence(
	ctx context.Context,
	db *sql.DB,
	caseID string,
	agg *AggregateResult,
) ([]CrossEvidenceCorrelation, error) {
	if agg == nil || len(agg.AllFindings) == 0 {
		return nil, nil
	}
	// Short-circuit: if the case has <2 evidences, nothing to correlate.
	row := db.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT evidence_id) FROM unified_events WHERE case_id = ?",
		caseID)
	var nev int
	if err := row.Scan(&nev); err != nil {
		return nil, fmt.Errorf("count evidences: %w", err)
	}
	if nev < 2 {
		return nil, nil
	}

	// Resolve every cited audit_id → evidence_id in one batch query.
	// audit_id → evidence_id map (audit_id is unique within a case).
	type techAccum struct {
		techniqueName string
		tactic        string
		evidenceSet   map[string]bool
		findingSet    map[string]bool
		auditSet      map[string]bool
	}
	techs := map[string]*techAccum{}

	// Build the cited audit_id set + remember which technique each came from.
	auditToTechs := map[string][]string{}
	for _, fws := range agg.AllFindings {
		tid := strings.TrimSpace(fws.Finding.TechniqueID)
		if tid == "" {
			continue
		}
		if _, ok := techs[tid]; !ok {
			techs[tid] = &techAccum{
				techniqueName: fws.Finding.TechniqueName,
				tactic:        fws.TacticID,
				evidenceSet:   map[string]bool{},
				findingSet:    map[string]bool{},
				auditSet:      map[string]bool{},
			}
		}
		t := techs[tid]
		t.findingSet[fws.Finding.FindingID] = true
		for _, e := range fws.Finding.Evidence {
			aid := strings.TrimSpace(e.AuditID)
			if aid == "" {
				continue
			}
			t.auditSet[aid] = true
			auditToTechs[aid] = append(auditToTechs[aid], tid)
		}
	}
	if len(auditToTechs) == 0 {
		return nil, nil
	}

	// Batch SQL lookup. Build placeholders and args.
	ids := make([]string, 0, len(auditToTechs))
	for aid := range auditToTechs {
		ids = append(ids, aid)
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, caseID)
	for i, aid := range ids {
		placeholders[i] = "?"
		args = append(args, aid)
	}
	q := "SELECT audit_id, evidence_id FROM unified_events WHERE case_id = ? AND audit_id IN (" +
		strings.Join(placeholders, ",") + ")"
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("lookup audit_ids: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var aid, eid string
		if err := rows.Scan(&aid, &eid); err != nil {
			return nil, err
		}
		for _, tid := range auditToTechs[aid] {
			techs[tid].evidenceSet[eid] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Emit one correlation per technique observed on ≥ 2 evidences.
	var out []CrossEvidenceCorrelation
	for tid, t := range techs {
		if len(t.evidenceSet) < 2 {
			continue
		}
		evs := setSorted(t.evidenceSet)
		fids := setSorted(t.findingSet)
		aids := setSorted(t.auditSet)
		sev := "info"
		if highImpactTactics[t.tactic] {
			sev = "warning"
		}
		out = append(out, CrossEvidenceCorrelation{
			TechniqueID:   tid,
			TechniqueName: t.techniqueName,
			Tactic:        t.tactic,
			EvidenceIDs:   evs,
			FindingIDs:    fids,
			AuditIDs:      aids,
			Description: fmt.Sprintf(
				"Technique %s observed across %d evidences: %s "+
					"(%d findings citing %d audit rows)",
				tid, len(evs), strings.Join(evs, ", "),
				len(fids), len(aids)),
			Severity: sev,
		})
	}
	// Stable order: by severity (warning first), then by technique_id.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity == "warning"
		}
		return out[i].TechniqueID < out[j].TechniqueID
	})
	return out, nil
}

func setSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
