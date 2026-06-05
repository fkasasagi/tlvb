package tier2

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// EnrichTimestamps fills in missing evidence.TsUTC values by looking up
// audit_ids in unified_events. Tier 1B findings come in with audit_ids
// only — this step makes them clusterable.
//
// Also fills artifact_id when missing (Tier 1B doesn't propagate it).
func EnrichTimestamps(ctx context.Context, db *sql.DB, caseID string, findings []Finding) ([]Finding, error) {
	// Collect every audit_id that needs a lookup.
	want := map[string]bool{}
	for _, f := range findings {
		for _, e := range f.Evidence {
			if e.AuditID != "" && (!e.HasTS || e.ArtifactID == "") {
				want[e.AuditID] = true
			}
		}
	}
	if len(want) == 0 {
		return findings, nil
	}

	// Bulk lookup in batches of 200 to avoid blowing the placeholder limit.
	resolved := map[string]struct {
		ts    time.Time
		hasTS bool
		art   string
		et    string
	}{}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	const batch = 200
	for i := 0; i < len(ids); i += batch {
		end := i + batch
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[i:end]
		placeholders := strings.Repeat("?,", len(chunk))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]any, 0, len(chunk)+1)
		args = append(args, caseID)
		for _, id := range chunk {
			args = append(args, id)
		}
		q := fmt.Sprintf(`SELECT audit_id, ts_utc, artifact_id, event_type
		                    FROM unified_events
		                   WHERE case_id = ? AND audit_id IN (%s)`,
			placeholders)
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("lookup audits: %w", err)
		}
		for rows.Next() {
			var aid, art, et string
			var ts sql.NullTime
			if err := rows.Scan(&aid, &ts, &art, &et); err != nil {
				rows.Close()
				return nil, err
			}
			r := struct {
				ts    time.Time
				hasTS bool
				art   string
				et    string
			}{art: art, et: et}
			if ts.Valid {
				r.ts = ts.Time.UTC()
				r.hasTS = true
			}
			resolved[aid] = r
		}
		rows.Close()
	}

	// Apply lookups back.
	for i := range findings {
		for j := range findings[i].Evidence {
			e := &findings[i].Evidence[j]
			if r, ok := resolved[e.AuditID]; ok {
				if !e.HasTS && r.hasTS {
					e.TsUTC = r.ts
					e.HasTS = true
				}
				if e.ArtifactID == "" {
					e.ArtifactID = r.art
				}
				if e.EventType == "" {
					e.EventType = r.et
				}
			}
		}
	}
	return findings, nil
}

// ClusterFindings groups findings whose representative time falls within
// `gap` of each other (default 30 min). Findings without any
// timestamps are bundled into a separate "no-timestamp" cluster at
// position 0 so the LLM can still discuss them.
//
// Strategy: sort by FirstTimestamp, walk and merge when the gap to the
// previous cluster's EndTS is ≤ gap. Each finding contributes exactly
// one point in time — its FirstTimestamp — to both the membership test
// and the cluster hull. We deliberately do NOT expand EndTS to a
// finding's *latest* evidence ts: a single rule whose evidence happens
// to span months (e.g. an amcache/registry rule matching both a 2024
// provisioning entry and the 2026 intrusion) would otherwise drag EndTS
// across that whole gap and chain two unrelated episodes into one giant
// cluster. The per-cluster timeline sampler (FetchClusterTimeline) still
// anchors on every evidence ts, so wide-span evidence is not lost — it
// just no longer bridges clusters.
func ClusterFindings(findings []Finding, gap time.Duration) []Cluster {
	if gap <= 0 {
		gap = 30 * time.Minute
	}

	var dated, undated []Finding
	for _, f := range findings {
		if !f.FirstTimestamp().IsZero() {
			dated = append(dated, f)
		} else {
			undated = append(undated, f)
		}
	}

	sort.SliceStable(dated, func(i, j int) bool {
		return dated[i].FirstTimestamp().Before(dated[j].FirstTimestamp())
	})

	var clusters []Cluster
	var cur *Cluster
	for _, f := range dated {
		ft := f.FirstTimestamp()
		if cur == nil || ft.Sub(cur.EndTS) > gap {
			if cur != nil {
				clusters = append(clusters, *cur)
			}
			cur = &Cluster{
				ID:       len(clusters) + 1,
				StartTS:  ft,
				EndTS:    ft,
				Findings: []Finding{f},
			}
			continue
		}
		cur.Findings = append(cur.Findings, f)
		if ft.After(cur.EndTS) {
			cur.EndTS = ft
		}
	}
	if cur != nil {
		clusters = append(clusters, *cur)
	}

	if len(undated) > 0 {
		clusters = append(clusters, Cluster{
			ID:       len(clusters) + 1,
			Findings: undated,
		})
	}
	return clusters
}
