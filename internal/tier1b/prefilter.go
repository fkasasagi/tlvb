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

// evtxNoiseEventIDs are Security / WFP / handle-access events that fire
// at extreme volume on stock Windows and rarely carry attack signal. We
// exclude them at SQL level so the candidate window can spend its
// budget on signal-rich events.
//
//   4656 — handle requested        4658 — handle closed
//   4663 — object access attempt   4670 — permissions changed
//   4674 — privileged operation    4690 — handle duplicated
//   4703 — user right adjusted
//   5152/5154 — WFP packet blocked/allowed
//   5156/5157 — WFP connection allowed/blocked
//   5158 — WFP local port bind
const evtxNoiseEventIDsSQL = `'4656','4658','4663','4670','4674','4690','4703','5152','5154','5156','5157','5158'`

// artifactDiversityBoost rewards artifacts where Tier 1A signature SQL
// rules are sparse (Sigma is overwhelmingly EVTX-focused). Tier 1B's
// strongest value is surfacing anomalies in artifacts the signature
// layer can't reach: file-system metadata, registry, shell artifacts.
//
// Score added on top of the lens-based score.
var artifactDiversityBoost = map[string]int{
	"lnk":             3, // LNK metadata (target, args, working dir) often pivotal
	"registry":        2, // Run keys, MRU lists, COM hijack
	"prefetch":        2, // execution history outside of EVTX
	"mft":             1, // file timeline; many rows but each is cheap to surface
	"amcache":         2, // installed binary inventory
	"browser_history": 2, // URL/typed/visit trail
	"shellbags":       2, // folder navigation history
	"jumplists":       2, // recently opened files per app
	"recyclebin":      1,
	"win10timeline":   1,
	"srum":            1, // network bytes per app
	"usn_journal":     1,
	// evtx / hayabusa: no boost — Tier 1A already covers these well
}

// buildCandidates queries unified_events and scores rows against the
// anomaly lenses. Returns at most maxRows candidates sorted by score desc.
//
// Lenses applied:
//   A0 — artifact-diversity boost (non-EVTX artifacts under-covered by Tier 1A)
//   A1 — off-hours (h < 6 or h >= 22 UTC)
//   A2 — suspicious path in payload (Temp / AppData / ProgramData / Public)
//   A4 — rare process (image name appears < 3 times in scanned sample)
//   A5 — adjacency to any prior finding's timestamp (±30 min)
//
// (A3 / A6 / A7 from the skill prompt are LLM-side judgments — the
// harness doesn't pre-score them.)
//
// Sampling strategy: per-artifact LIMIT so high-volume sources (MFT, EVTX)
// don't crowd out signal-dense small artifacts (LNK, browser_history,
// registry). Each artifact contributes up to maxRows×5 / num_artifacts
// rows to the in-memory scoring pool.
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

	rows, err := queryStratified(ctx, db, caseID, maxRows)
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

		// A0 — artifact diversity (boost for non-EVTX artifacts Tier 1A
		// rarely covers). Applied unconditionally — we don't gate other
		// lenses, but artifacts with no signal will have score=A0_only.
		if boost := artifactDiversityBoost[r.artifactID]; boost > 0 {
			lenses = append(lenses, "A0")
			score += boost
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

// queryStratified pulls a per-artifact sample so high-volume sources
// (MFT, evtx Security-noise) don't crowd out signal-dense small
// artifacts (LNK, browser_history). For each artifact present in the
// case, allocate a quota proportional to `maxRows × 5 / num_artifacts`,
// with a minimum of 100 rows per artifact so tiny artifacts still get
// sampled. EVTX rows further filter out the noise EventID set.
func queryStratified(ctx context.Context, db *sql.DB, caseID string, maxRows int) (*sql.Rows, error) {
	// First discover which artifacts the case has.
	artifacts, err := listArtifacts(ctx, db, caseID)
	if err != nil {
		return nil, err
	}
	if len(artifacts) == 0 {
		// fall back to the legacy global LIMIT for an empty/unknown case
		return db.QueryContext(ctx,
			`SELECT audit_id, ts_utc, artifact_id, COALESCE(computer,''), payload_json
			   FROM unified_events WHERE case_id = ? ORDER BY ts_utc LIMIT ?`,
			caseID, maxRows*5)
	}

	total := maxRows * 5
	if total < 2000 {
		total = 2000
	}
	perArtifact := total / len(artifacts)
	if perArtifact < 100 {
		perArtifact = 100
	}

	// Build a UNION ALL of per-artifact LIMITed queries. EVTX gets the
	// noise EID filter applied.
	var sb strings.Builder
	args := []any{}
	for i, art := range artifacts {
		if i > 0 {
			sb.WriteString(" UNION ALL ")
		}
		if art == "evtx" {
			sb.WriteString(`(SELECT audit_id, ts_utc, artifact_id, COALESCE(computer,'') AS computer, payload_json
			                 FROM unified_events
			                WHERE case_id = ? AND artifact_id = 'evtx'
			                  AND COALESCE(json_extract_string(payload_json, '$.EventId'), '') NOT IN (` + evtxNoiseEventIDsSQL + `)
			                ORDER BY ts_utc LIMIT ?)`)
		} else {
			sb.WriteString(`(SELECT audit_id, ts_utc, artifact_id, COALESCE(computer,'') AS computer, payload_json
			                 FROM unified_events
			                WHERE case_id = ? AND artifact_id = ?
			                ORDER BY ts_utc LIMIT ?)`)
			args = append(args, caseID, art, perArtifact)
			continue
		}
		args = append(args, caseID, perArtifact)
	}
	return db.QueryContext(ctx, sb.String(), args...)
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
// fields per artifact and truncate the rest. Field names are verified
// against actual Tier 0 parser output (see tests/parsers/ samples).
func shrinkPayload(artifactID, payload string) map[string]any {
	out := map[string]any{}
	wantedKeys := map[string][]string{
		"evtx":            {"EventId", "Channel", "MapDescription", "PayloadData1", "ExecutableInfo"},
		"hayabusa":        {"RuleTitle", "Level", "Channel", "EventID", "Details"},
		"registry":        {"HiveType", "Category", "KeyPath", "ValueName", "ValueData"},
		"lnk":             {"SourceFile", "RelativePath", "WorkingDirectory", "TargetCreated", "FileSize"},
		"prefetch":        {"executable", "run_count", "hash", "size_bytes"},
		"mft":             {"ParentPath", "FileName", "Extension", "FileSize", "InUse"},
		"amcache":         {"ApplicationName", "FullPath", "SHA1", "ProductName", "FileExtension"},
		"shellbags":       {"BagPath", "AbsolutePath", "ShellType", "CreatedOn", "ModifiedOn"},
		"browser_history": {"browser_kind", "url", "title", "visit_count", "typed_count"},
		"jumplists":       {"SourceFile", "AppId", "Path", "TargetCreated"},
		"recyclebin":      {"SourceName", "FileSize", "DeletedOn"},
		"win10timeline":   {"AppId", "AppName", "Payload", "StartTime"},
		"srum":            {"AppId", "UserName", "BytesSent", "BytesRecvd"},
		"usn_journal":     {"FileName", "Reason", "FullPath"},
		"washizukami_audit": {"path", "status", "category"},
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
