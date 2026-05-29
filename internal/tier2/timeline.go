package tier2

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// timelineNoiseEVTXEventIDs mirrors tier1b's noise filter — handle access
// and WFP packet events that have no analytic value for attack chain
// reconstruction. Excluded at SQL level when fetching the raw timeline
// excerpt around a cluster.
const timelineNoiseEVTXEventIDsSQL = `'4656','4658','4663','4670','4674','4690','4703','5152','5154','5156','5157','5158'`

// FetchClusterTimeline pulls a per-cluster raw timeline window
// (±window minutes around StartTS / EndTS) using stratified per-artifact
// sampling so signal-dense small artifacts (LNK, browser_history,
// registry, prefetch) aren't crowded out by EVTX / MFT volume.
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
			                  ORDER BY ts_utc LIMIT ?)`)
			args = append(args, caseID, winStart, winEnd, perArtifact)
		} else {
			sb.WriteString(`(SELECT audit_id, ts_utc, artifact_id, event_type, payload_json
			                   FROM unified_events
			                  WHERE case_id = ? AND artifact_id = ?
			                    AND ts_utc >= ? AND ts_utc <= ?
			                  ORDER BY ts_utc LIMIT ?)`)
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
	return rows.Err()
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
