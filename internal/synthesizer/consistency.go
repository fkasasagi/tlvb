package synthesizer

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
)

// Inconsistency is one rule hit. Severity is "warning" for true conflicts
// and "info" for advisory observations (e.g. "no Lateral Movement findings
// — single-host case").
type Inconsistency struct {
	Rule        string   `json:"rule"`
	Severity    string   `json:"severity"`    // warning | info
	Description string   `json:"description"` // Japanese, examiner-facing
	Affected    []string `json:"affected"`    // tactic_ids
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Resolved    bool     `json:"resolved"`
	Resolution  string   `json:"resolution,omitempty"`
}

// CheckConsistency runs all deterministic rules against the aggregator
// output and (where useful) the unified_events table.
//
// Rules from DESIGN.md §6.3:
//   R1 — Defense Evasion で 1102 (log clear) ありなのに、Lateral Movement /
//        Credential Access の finding が極端に少ない → 消されて見えてない可能性
//   R2 — Persistence finding ありなのに、Execution の痕跡 (Prefetch/Amcache)
//        が無い → 不整合
//   R3 — Lateral Movement で 4624 type 3 の流入ありなのに、流入元ホスト側に
//        Lateral Movement finding 無し (multi-host) → 不整合
//   R4 — Initial Access の特定時刻より前に Execution finding がある →
//        時系列矛盾
//
// Rules return [] when the precondition doesn't apply (e.g. no Persistence
// finding → R2 silent). Caller surfaces all hits to the examiner.
func CheckConsistency(
	ctx context.Context,
	db *sql.DB,
	caseID string,
	agg *AggregateResult,
) ([]Inconsistency, error) {
	var out []Inconsistency

	if hit := ruleR1(agg); hit != nil {
		out = append(out, *hit)
	}
	if hit, err := ruleR2(ctx, db, caseID, agg); err != nil {
		return out, err
	} else if hit != nil {
		out = append(out, *hit)
	}
	if hit := ruleR3(ctx, db, caseID, agg); hit != nil {
		out = append(out, *hit)
	}
	if hit, err := ruleR4(ctx, db, caseID, agg); err != nil {
		return out, err
	} else if hit != nil {
		out = append(out, *hit)
	}

	return out, nil
}

// ----------------------------------------------------------------------------
// R1 — log-clear with suspiciously few lateral / cred findings
// ----------------------------------------------------------------------------

const r1FewThreshold = 2 // < this many findings = "極端に少ない"

func ruleR1(agg *AggregateResult) *Inconsistency {
	// Did defense_evasion cite EventID 1102?
	deRep, ok := agg.ReportsByTac["defense_evasion"]
	if !ok {
		return nil
	}
	cleared := false
	var clearAuditIDs []string
	for _, f := range deRep.Findings {
		if !strings.HasPrefix(f.TechniqueID, "T1070.001") {
			continue
		}
		cleared = true
		for _, ev := range f.Evidence {
			clearAuditIDs = append(clearAuditIDs, ev.AuditID)
		}
	}
	if !cleared {
		return nil
	}

	lmCount := agg.Stats.FindingsByTactic["TA0008"]
	caCount := agg.Stats.FindingsByTactic["TA0006"]
	if lmCount >= r1FewThreshold && caCount >= r1FewThreshold {
		// Logs cleared but findings still abundant — no inconsistency.
		return nil
	}

	return &Inconsistency{
		Rule:     "R1",
		Severity: "warning",
		Description: fmt.Sprintf(
			"Defense Evasion で Event Log Clear (T1070.001) を検出したが、"+
				"Lateral Movement の finding 数=%d、Credential Access の finding 数=%d と"+
				"極端に少ない。クリアされたログにこれらの痕跡が含まれていた可能性があり、"+
				"検出漏れを否定できない。",
			lmCount, caCount),
		Affected:    []string{"TA0005", "TA0008", "TA0006"},
		EvidenceIDs: clearAuditIDs,
		Resolved:    false,
	}
}

// ----------------------------------------------------------------------------
// R2 — persistence findings present but no prefetch/amcache evidence cited
// ----------------------------------------------------------------------------

func ruleR2(
	ctx context.Context, db *sql.DB, caseID string, agg *AggregateResult,
) (*Inconsistency, error) {
	persRep, ok := agg.ReportsByTac["persistence"]
	if !ok || len(persRep.Findings) == 0 {
		return nil, nil
	}

	// Walk the cluster member list — we want to know if ANY agent surfaced
	// prefetch/amcache rows tied to the persistence findings' evidence.
	// Easiest: query the DB for prefetch/amcache rows referenced by any
	// persistence audit_id. If zero, R2 fires.
	persEvidenceIDs := map[string]struct{}{}
	for _, f := range persRep.Findings {
		for _, ev := range f.Evidence {
			if ev.AuditID != "" {
				persEvidenceIDs[ev.AuditID] = struct{}{}
			}
		}
	}

	// Are any prefetch/amcache rows present for the *case* at all?
	var totalPrefAm int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unified_events
		   WHERE case_id = ? AND artifact_id IN ('prefetch','amcache')`,
		caseID).Scan(&totalPrefAm); err != nil {
		return nil, err
	}
	if totalPrefAm == 0 {
		// Evidence not collected — this is a *gap*, not an *inconsistency*.
		return &Inconsistency{
			Rule:     "R2",
			Severity: "info",
			Description: fmt.Sprintf(
				"Persistence finding が %d 件あるが、本ケースには Prefetch / Amcache "+
					"アーティファクトが収集されていない。実行痕跡で裏付けるには別途 "+
					"%%SystemRoot%%\\Prefetch と Amcache.hve を投入する必要がある。",
				len(persRep.Findings)),
			Affected: []string{"TA0003"},
			Resolved: false,
		}, nil
	}

	// Evidence exists at the case level — check whether the persistence
	// findings cite any of it. If none of them reference prefetch/amcache,
	// the agent missed the corroboration opportunity → R2.
	hasCorroboration := false
	for _, f := range persRep.Findings {
		for _, ev := range f.Evidence {
			if ev.SourceArtifact == "prefetch" || ev.SourceArtifact == "amcache" {
				hasCorroboration = true
				break
			}
		}
		if hasCorroboration {
			break
		}
	}
	if hasCorroboration {
		return nil, nil
	}

	return &Inconsistency{
		Rule:     "R2",
		Severity: "warning",
		Description: fmt.Sprintf(
			"Persistence finding が %d 件あるが、いずれの finding も Prefetch / "+
				"Amcache を corroboration として引いていない。本ケースには Prefetch / "+
				"Amcache 行が %d 件存在するため、Persistence Agent は再調査の余地が "+
				"ある。",
			len(persRep.Findings), totalPrefAm),
		Affected: []string{"TA0003"},
		Resolved: false,
	}, nil
}

// ----------------------------------------------------------------------------
// R3 — Lateral Movement inflow without source-host LM finding (multi-host)
// ----------------------------------------------------------------------------

func ruleR3(
	ctx context.Context, db *sql.DB, caseID string, agg *AggregateResult,
) *Inconsistency {
	// Inferred from evidence Computer field. If our case spans >1 distinct
	// Computer, R3 may apply. Otherwise note as N/A info.
	hosts := map[string]struct{}{}
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT COALESCE(computer, '') FROM unified_events
		   WHERE case_id = ? AND computer IS NOT NULL AND computer != ''`,
		caseID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			continue
		}
		hosts[c] = struct{}{}
	}
	if len(hosts) <= 1 {
		// Single-host evidence set — R3 doesn't apply structurally.
		// Surface as info so the examiner sees the rule was considered.
		return &Inconsistency{
			Rule:     "R3",
			Severity: "info",
			Description: fmt.Sprintf(
				"R3 (流入元ホスト側 Lateral Movement の整合性) は本ケースが "+
					"単一ホスト (host count = %d) のため適用外。",
				len(hosts)),
			Affected: []string{"TA0008"},
			Resolved: true,
			Resolution: "single-host scope; cross-host correlation requires " +
				"additional evidence collection",
		}
	}

	// Multi-host case. Look for inbound network logons (4624 type 3) and
	// compare the source identification against the LM tactic findings.
	lmRep, ok := agg.ReportsByTac["lateral_movement"]
	if !ok || len(lmRep.Findings) == 0 {
		return &Inconsistency{
			Rule:     "R3",
			Severity: "warning",
			Description: fmt.Sprintf(
				"本ケースは複数ホスト (host count = %d) を含むが、Lateral "+
					"Movement の finding が 0。流入経路の整合性が検証できない。",
				len(hosts)),
			Affected: []string{"TA0008"},
			Resolved: false,
		}
	}
	// We don't have parsed source-host attribution for findings — keep this
	// at info severity until that lands.
	return &Inconsistency{
		Rule:     "R3",
		Severity: "info",
		Description: fmt.Sprintf(
			"複数ホストケース (host count = %d) において、Lateral Movement "+
				"finding %d 件と流入元ホストの突き合わせは未実装。Examiner による "+
				"目視確認を推奨。",
			len(hosts), len(lmRep.Findings)),
		Affected: []string{"TA0008"},
		Resolved: false,
	}
}

// ----------------------------------------------------------------------------
// R4 — Execution finding earlier than Initial Access timestamp
// ----------------------------------------------------------------------------

func ruleR4(
	ctx context.Context, db *sql.DB, caseID string, agg *AggregateResult,
) (*Inconsistency, error) {
	iaRep, okIA := agg.ReportsByTac["initial_access"]
	exRep, okEX := agg.ReportsByTac["execution"]
	if !okIA || !okEX || len(iaRep.Findings) == 0 || len(exRep.Findings) == 0 {
		return nil, nil
	}

	iaFirst, iaIDs, err := earliestEvidenceTS(ctx, db, caseID, iaRep.Findings)
	if err != nil {
		return nil, err
	}
	if iaFirst.IsZero() {
		return nil, nil
	}
	exFirst, exIDs, err := earliestEvidenceTS(ctx, db, caseID, exRep.Findings)
	if err != nil {
		return nil, err
	}
	if exFirst.IsZero() {
		return nil, nil
	}

	if !exFirst.Before(iaFirst) {
		return nil, nil
	}

	return &Inconsistency{
		Rule:     "R4",
		Severity: "warning",
		Description: fmt.Sprintf(
			"Execution の最古 finding 時刻 %s が Initial Access の最古 "+
				"finding 時刻 %s より前。時系列が成立していない。実際の侵入起点が "+
				"別にあるか、Initial Access Agent が最古ではない finding を返した "+
				"可能性。",
			exFirst.UTC().Format(time.RFC3339),
			iaFirst.UTC().Format(time.RFC3339)),
		Affected:    []string{"TA0001", "TA0002"},
		EvidenceIDs: append(iaIDs, exIDs...),
		Resolved:    false,
	}, nil
}

// earliestEvidenceTS returns the minimum ts_utc across all evidence audit_ids
// referenced by `findings`, plus the audit_ids that match.
func earliestEvidenceTS(
	ctx context.Context, db *sql.DB, caseID string, findings []agents.Finding,
) (time.Time, []string, error) {
	auditIDs := map[string]struct{}{}
	for _, f := range findings {
		for _, ev := range f.Evidence {
			if ev.AuditID != "" {
				auditIDs[ev.AuditID] = struct{}{}
			}
		}
	}
	if len(auditIDs) == 0 {
		return time.Time{}, nil, nil
	}
	ids := sortedKeys(auditIDs)
	args := []any{caseID}
	placeholders := make([]string, 0, len(ids))
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	q := `SELECT MIN(ts_utc) FROM unified_events
	      WHERE case_id = ? AND audit_id IN (` + strings.Join(placeholders, ",") + `)`
	var ts sql.NullTime
	if err := db.QueryRowContext(ctx, q, args...).Scan(&ts); err != nil {
		return time.Time{}, nil, err
	}
	if !ts.Valid {
		return time.Time{}, ids, nil
	}
	return ts.Time, ids, nil
}

// SortInconsistencies orders by severity (warning before info) then rule.
func SortInconsistencies(in []Inconsistency) {
	sevWeight := func(s string) int {
		if s == "warning" {
			return 0
		}
		return 1
	}
	sort.SliceStable(in, func(i, j int) bool {
		wi, wj := sevWeight(in[i].Severity), sevWeight(in[j].Severity)
		if wi != wj {
			return wi < wj
		}
		return in[i].Rule < in[j].Rule
	})
}
