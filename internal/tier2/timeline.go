package tier2

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// timelineNoiseEVTXEventIDs mirrors tier1b's noise filter — handle access
// and WFP packet events that have no analytic value for attack chain
// reconstruction. Excluded at SQL level when fetching the raw timeline
// excerpt around a cluster.
const timelineNoiseEVTXEventIDsSQL = `'4656','4658','4663','4670','4674','4690','4703','5152','5154','5156','5157','5158'`

// FetchClusterTimeline pulls a per-cluster raw timeline window using
// stratified per-artifact sampling so signal-dense small artifacts (LNK,
// browser_history, registry, prefetch) aren't crowded out by EVTX / MFT
// volume.
//
// Within each artifact the per-artifact budget is filled by the rows
// CLOSEST to a detection — i.e. ordered by proximity to the nearest
// finding-evidence timestamp (the "anchors"), not by earliest-ts. This
// matters whenever the cluster hull is wider than a couple of minutes: an
// earliest-N sample over a wide window only ever returns the very start of
// the window, so a file written 9 s after a credential dump (loot.txt-style
// staging) at the *end* of the window would be silently dropped — exactly
// the failure that hid such events before. Proximity sampling keeps the
// rows around where detections actually fired, regardless of hull width or
// artifact volume.
//
// Skipped for clusters with no timestamps (Tier 1B can still discuss
// those findings purely from their descriptions).
func FetchClusterTimeline(ctx context.Context, db *sql.DB, caseID string,
	c *Cluster, window time.Duration, maxRowsPerCluster int) error {

	if c.StartTS.IsZero() {
		return nil // undated cluster
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	if maxRowsPerCluster <= 0 {
		maxRowsPerCluster = 300
	}

	winStart := c.StartTS.Add(-window)
	winEnd := c.EndTS.Add(window)

	artifacts, err := listArtifacts(ctx, db, caseID)
	if err != nil {
		return err
	}
	if len(artifacts) == 0 {
		return nil
	}
	perArtifact := maxRowsPerCluster / len(artifacts)
	if perArtifact < 30 {
		perArtifact = 30
	}

	// Order each artifact's rows by distance (seconds) to the nearest anchor.
	// Falls back to chronological order when a cluster has no usable anchors.
	orderExpr := "ts_utc"
	if anchors := clusterAnchorEpochs(c, window); len(anchors) > 0 {
		terms := make([]string, len(anchors))
		for i, a := range anchors {
			terms[i] = fmt.Sprintf("abs(epoch(ts_utc)-%d)", a)
		}
		if len(terms) == 1 {
			orderExpr = terms[0]
		} else {
			orderExpr = "LEAST(" + strings.Join(terms, ",") + ")"
		}
	}

	var sb strings.Builder
	args := []any{}
	for i, art := range artifacts {
		if i > 0 {
			sb.WriteString(" UNION ALL ")
		}
		if art == "evtx" {
			sb.WriteString(`(SELECT audit_id, ts_utc, artifact_id, event_type, payload_json
			                   FROM unified_events
			                  WHERE case_id = ? AND artifact_id = 'evtx'
			                    AND ts_utc >= ? AND ts_utc <= ?
			                    AND COALESCE(json_extract_string(payload_json, '$.EventId'),'') NOT IN (` + timelineNoiseEVTXEventIDsSQL + `)
			                  ORDER BY ` + orderExpr + ` LIMIT ?)`)
			args = append(args, caseID, winStart, winEnd, perArtifact)
		} else {
			sb.WriteString(`(SELECT audit_id, ts_utc, artifact_id, event_type, payload_json
			                   FROM unified_events
			                  WHERE case_id = ? AND artifact_id = ?
			                    AND ts_utc >= ? AND ts_utc <= ?
			                  ORDER BY ` + orderExpr + ` LIMIT ?)`)
			args = append(args, caseID, art, winStart, winEnd, perArtifact)
		}
	}

	rows, err := db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return fmt.Errorf("fetch cluster timeline: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var aid, art, et, payload string
		var ts sql.NullTime
		if err := rows.Scan(&aid, &ts, &art, &et, &payload); err != nil {
			return err
		}
		ev := TimelineEvent{
			AuditID:    aid,
			ArtifactID: art,
			EventType:  et,
			Excerpt:    shrinkPayload(art, payload),
		}
		if ts.Valid {
			ev.TsUTC = ts.Time.UTC()
		}
		c.RawTimelineExcerpt = append(c.RawTimelineExcerpt, ev)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Proximity ordering scrambles the per-artifact subqueries; present the
	// merged excerpt chronologically so the LLM reads a real timeline.
	sort.SliceStable(c.RawTimelineExcerpt, func(i, j int) bool {
		return c.RawTimelineExcerpt[i].TsUTC.Before(c.RawTimelineExcerpt[j].TsUTC)
	})
	return nil
}

// clusterAnchorEpochs returns the distinct whole-second Unix timestamps of
// the cluster's finding evidence that fall inside the sampling window
// [StartTS-window, EndTS+window]. These are the points where a Tier 1
// detection actually fired; the timeline sampler orders raw events by
// proximity to the nearest one. Bounded to a sane count so the generated
// ORDER BY expression can't explode on a pathologically dense cluster.
func clusterAnchorEpochs(c *Cluster, window time.Duration) []int64 {
	lo := c.StartTS.Add(-window)
	hi := c.EndTS.Add(window)
	seen := map[int64]bool{}
	var out []int64
	for _, f := range c.Findings {
		for _, e := range f.Evidence {
			if !e.HasTS || e.TsUTC.Before(lo) || e.TsUTC.After(hi) {
				continue
			}
			s := e.TsUTC.Unix()
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	const maxAnchors = 96
	if len(out) > maxAnchors {
		thinned := make([]int64, 0, maxAnchors)
		step := float64(len(out)-1) / float64(maxAnchors-1)
		for i := 0; i < maxAnchors; i++ {
			thinned = append(thinned, out[int(float64(i)*step+0.5)])
		}
		out = thinned
	}
	return out
}

func listArtifacts(ctx context.Context, db *sql.DB, caseID string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT artifact_id FROM unified_events
		   WHERE case_id = ? ORDER BY 1`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// shrinkPayload reuses the same per-artifact key map Tier 1B settled on
// (see internal/tier1b/prefilter.go::shrinkPayload). Duplicated here to
// keep tier1b/tier2 packages decoupled.
func shrinkPayload(artifactID, payload string) map[string]any {
	wantedKeys := map[string][]string{
		"evtx":              {"EventId", "Channel", "MapDescription", "PayloadData1", "ExecutableInfo"},
		"hayabusa":          {"RuleTitle", "Level", "Channel", "EventID", "Details"},
		"registry":          {"HiveType", "Category", "KeyPath", "ValueName", "ValueData"},
		"lnk":               {"SourceFile", "RelativePath", "WorkingDirectory", "TargetCreated", "FileSize"},
		"prefetch":          {"executable", "run_count", "hash", "size_bytes"},
		"mft":               {"ParentPath", "FileName", "Extension", "FileSize", "InUse"},
		"amcache":           {"ApplicationName", "FullPath", "SHA1", "ProductName", "FileExtension"},
		"shellbags":         {"BagPath", "AbsolutePath", "ShellType", "CreatedOn", "ModifiedOn"},
		"browser_history":   {"browser_kind", "url", "title", "visit_count", "typed_count"},
		"jumplists":         {"SourceFile", "AppId", "Path", "TargetCreated"},
		"recyclebin":        {"SourceName", "FileSize", "DeletedOn"},
		"win10timeline":     {"AppId", "AppName", "Payload", "StartTime"},
		"srum":              {"AppId", "UserName", "BytesSent", "BytesRecvd"},
		"usn_journal":       {"FileName", "Reason", "FullPath"},
		"washizukami_audit": {"path", "status", "category"},
	}
	out := map[string]any{}
	keys := wantedKeys[artifactID]
	if len(keys) == 0 {
		// fallback
		if len(payload) > 200 {
			out["_excerpt"] = payload[:200] + "..."
		} else {
			out["_excerpt"] = payload
		}
		return out
	}
	for _, k := range keys {
		if v, ok := extractFieldValue(payload, k); ok {
			if len(v) > 200 {
				v = v[:200] + "..."
			}
			out[k] = v
		}
	}
	return out
}

// extractFieldValue does a tolerant string-level extraction of `"key"` →
// the JSON value as a string. Handles both compact ("key":"v") and
// space-padded ("key": "v") JSON formatting that Python's default
// json.dumps emits. Numeric values are returned without quotes.
//
// Returns (value, true) on hit, ("", false) on miss. Not a full JSON
// parser — designed for fast pass over thousands of payloads.
func extractFieldValue(payload, key string) (string, bool) {
	needle := `"` + key + `"`
	i := strings.Index(payload, needle)
	if i < 0 {
		return "", false
	}
	i += len(needle)
	// skip whitespace until ':'
	for i < len(payload) && (payload[i] == ' ' || payload[i] == '\t') {
		i++
	}
	if i >= len(payload) || payload[i] != ':' {
		return "", false
	}
	i++
	// skip whitespace after ':'
	for i < len(payload) && (payload[i] == ' ' || payload[i] == '\t') {
		i++
	}
	if i >= len(payload) {
		return "", false
	}
	if payload[i] == '"' {
		// string value — read to next unescaped quote.
		i++
		start := i
		for i < len(payload) {
			if payload[i] == '\\' && i+1 < len(payload) {
				i += 2
				continue
			}
			if payload[i] == '"' {
				return payload[start:i], true
			}
			i++
		}
		return "", false
	}
	// numeric / bool / null — read until delimiter.
	start := i
	for i < len(payload) && payload[i] != ',' && payload[i] != '}' && payload[i] != ']' && payload[i] != '\n' {
		i++
	}
	return strings.TrimSpace(payload[start:i]), true
}
