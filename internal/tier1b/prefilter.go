package tier1b

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"
)

// candidate is one prefilter-passing event with the lenses that fired.
type candidate struct {
	AuditID    string
	TsUTC      time.Time
	HasTS      bool
	ArtifactID string
	Computer   string
	Payload    string // raw JSON, will be shrunk before LLM prompt
	Lenses     []string
	Score      int
}

type candidateBundle struct {
	Events []candidate
	MinTS  time.Time
	MaxTS  time.Time
	Total  int // total candidates before truncation
}

// buildCandidates queries unified_events and scores rows against the
// anomaly lenses. Returns at most maxRows candidates sorted by score desc.
//
// Lenses applied:
//   A1 — off-hours (h < 6 or h >= 22 UTC)
//   A2 — suspicious path in payload (Temp / AppData / ProgramData / Public)
//   A4 — rare process (image name appears < 3 times in scanned sample)
//   A5 — adjacency to any prior finding's timestamp (±30 min)
//
// (A3 / A6 / A7 from the skill prompt are LLM-side judgments — the
// harness doesn't pre-score them.)
func buildCandidates(ctx context.Context, db *sql.DB, caseID string,
	prior *priorContext, maxRows int) (*candidateBundle, error) {

	excluded := map[string]bool{}
	for _, a := range prior.UniqueAudits {
		excluded[a] = true
	}

	// Parse priorTimestamps once for adjacency check.
	var priorTimes []time.Time
	for _, s := range prior.KeyTimestamps {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			priorTimes = append(priorTimes, t)
		}
	}
	sort.Slice(priorTimes, func(i, j int) bool {
		return priorTimes[i].Before(priorTimes[j])
	})

	// Pull a wide sample we score in-memory. 5x cap is a balance between
	// memory and coverage; for a 470k-event case, this means 1000+ rows
	// processed which is fast.
	sampleCap := maxRows * 5
	if sampleCap < 1000 {
		sampleCap = 1000
	}
	q := `SELECT audit_id, ts_utc, artifact_id, COALESCE(computer,''), payload_json
	        FROM unified_events
	       WHERE case_id = ?
	       ORDER BY ts_utc
	       LIMIT ?`
	rows, err := db.QueryContext(ctx, q, caseID, sampleCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type rawRow struct {
		auditID    string
		ts         time.Time
		hasTS      bool
		artifactID string
		computer   string
		payload    string
	}
	var sample []rawRow
	imageCount := map[string]int{}
	for rows.Next() {
		var r rawRow
		var ts sql.NullTime
		if err := rows.Scan(&r.auditID, &ts, &r.artifactID, &r.computer, &r.payload); err != nil {
			return nil, err
		}
		if ts.Valid {
			r.ts = ts.Time.UTC()
			r.hasTS = true
		}
		sample = append(sample, r)
		if img := extractImage(r.payload); img != "" {
			imageCount[strings.ToLower(img)]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]candidate, 0, len(sample))
	for _, r := range sample {
		if excluded[r.auditID] {
			continue
		}
		var lenses []string
		score := 0

		if r.hasTS {
			h := r.ts.Hour()
			if h < 6 || h >= 22 {
				lenses = append(lenses, "A1")
				score += 2
			}
		}
		if hasSuspiciousPath(r.payload) {
			lenses = append(lenses, "A2")
			score += 3
		}
		if img := extractImage(r.payload); img != "" {
			if imageCount[strings.ToLower(img)] < 3 {
				lenses = append(lenses, "A4")
				score += 2
			}
		}
		if r.hasTS && nearAnyTime(r.ts, priorTimes, 30*time.Minute) {
			lenses = append(lenses, "A5")
			score += 1
		}

		if score == 0 {
			continue
		}
		out = append(out, candidate{
			AuditID:    r.auditID,
			TsUTC:      r.ts,
			HasTS:      r.hasTS,
			ArtifactID: r.artifactID,
			Computer:   r.computer,
			Payload:    r.payload,
			Lenses:     lenses,
			Score:      score,
		})
	}

	// Sort by score desc; ties broken by ts asc.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].TsUTC.Before(out[j].TsUTC)
	})

	bundle := &candidateBundle{Total: len(out)}
	if len(out) > maxRows {
		out = out[:maxRows]
	}
	bundle.Events = out
	for _, c := range out {
		if !c.HasTS {
			continue
		}
		if bundle.MinTS.IsZero() || c.TsUTC.Before(bundle.MinTS) {
			bundle.MinTS = c.TsUTC
		}
		if c.TsUTC.After(bundle.MaxTS) {
			bundle.MaxTS = c.TsUTC
		}
	}
	return bundle, nil
}

// extractImage attempts to pull the process image path from a payload.
// EvtxECmd uses ExecutableInfo; some artifacts use Image (Sysmon) or
// FullPath (amcache/MFT).
func extractImage(payload string) string {
	// Cheap string scan — avoid json.Unmarshal for performance over 1000s of rows.
	for _, key := range []string{`"ExecutableInfo":"`, `"Image":"`, `"NewProcessName":"`, `"FullPath":"`, `"ExecutableName":"`} {
		i := strings.Index(payload, key)
		if i < 0 {
			continue
		}
		i += len(key)
		j := strings.Index(payload[i:], `"`)
		if j < 0 {
			continue
		}
		val := payload[i : i+j]
		// ExecutableInfo holds the whole command line — return only the
		// first whitespace-separated token (the binary path).
		if key == `"ExecutableInfo":"` {
			val = strings.TrimSpace(val)
			// strip the leading executable from "C:\path\bin.exe args..."
			if idx := strings.Index(val, ".exe"); idx > 0 {
				val = val[:idx+len(".exe")]
			}
		}
		return val
	}
	return ""
}

// hasSuspiciousPath returns true when the payload mentions paths attackers
// commonly stage from.
func hasSuspiciousPath(payload string) bool {
	lower := strings.ToLower(payload)
	for _, m := range []string{
		`\\appdata\\local\\temp\\`,
		`\\users\\public\\`,
		`\\programdata\\`,
		`\\windows\\temp\\`,
		`\\perflogs\\`,
	} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// nearAnyTime returns true when ts is within ±window of any t in times.
func nearAnyTime(ts time.Time, times []time.Time, window time.Duration) bool {
	for _, t := range times {
		d := ts.Sub(t)
		if d < 0 {
			d = -d
		}
		if d <= window {
			return true
		}
	}
	return false
}

// shrinkPayload reduces a payload JSON to the most useful fields for the
// LLM. We don't want to send raw 2KB payloads — pull a few canonical
// fields per artifact and truncate the rest.
func shrinkPayload(artifactID, payload string) map[string]any {
	out := map[string]any{}
	// Universal: peek at the first few key fields if present.
	wantedKeys := map[string][]string{
		"evtx":            {"EventId", "Channel", "MapDescription", "PayloadData1", "ExecutableInfo"},
		"hayabusa":        {"RuleTitle", "Level", "Channel", "EventID", "Details"},
		"registry":        {"KeyPath", "ValueName", "ValueData"},
		"lnk":             {"SourceFile", "TargetPath", "Arguments"},
		"prefetch":        {"ExecutableName", "LastRun"},
		"mft":             {"FullPath", "FileSize"},
		"amcache":         {"FullPath", "SHA1"},
		"browser_history": {"URL", "Title", "LastVisited"},
	}
	keys := wantedKeys[artifactID]
	if len(keys) == 0 {
		// fallback: include first 200 chars of payload
		if len(payload) > 200 {
			out["_excerpt"] = payload[:200] + "..."
		} else {
			out["_excerpt"] = payload
		}
		return out
	}
	for _, k := range keys {
		needle := `"` + k + `":"`
		i := strings.Index(payload, needle)
		if i < 0 {
			continue
		}
		i += len(needle)
		j := strings.Index(payload[i:], `"`)
		if j < 0 {
			continue
		}
		val := payload[i : i+j]
		if len(val) > 200 {
			val = val[:200] + "..."
		}
		out[k] = val
	}
	return out
}
