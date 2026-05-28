package agents

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// TacticSpec is the per-tactic configuration: which skill prompt to load,
// which UnifiedEvent rows are candidates, and how to identify the tactic
// in TacticReport output.
//
// Each tactic registers a list of SQL OR-clauses that the runner joins
// into one WHERE clause. Clauses are hand-written SQL fragments — we
// control all inputs, so no injection surface, but **never** interpolate
// untrusted values here.
type TacticSpec struct {
	ID        string // ATT&CK ID, e.g. "TA0003"
	Name      string // Human name, e.g. "Persistence"
	Slug      string // file basename, e.g. "persistence" (skills/<slug>.md)
	SkillFile string // resolved path; runner sets this
	OrClauses []string
}

// TacticRegistry holds every implemented tactic agent. Keys are slugs.
//
// Mapping rationale per tactic — see skills/<slug>.md for prose. SQL
// fragments stay synced with the technique tables in those skill files.
var TacticRegistry = map[string]TacticSpec{

	// ---- TA0001 Initial Access -------------------------------------------
	"initial_access": {
		ID: "TA0001", Name: "Initial Access", Slug: "initial_access",
		OrClauses: []string{
			// Logon evidence — RDP, network, failed
			evtxEventID("4624"),  // logon
			evtxEventID("4625"),  // failed logon
			evtxEventID("4648"),  // logon with explicit credentials
			// Sysmon process create with Office spawning shell
			sysmonOnly("1"),
			// Office macro / phishing leftovers in registry
			payloadLike("registry", "%Office%TrustRecords%"),
			payloadLike("registry", "%Office%Security%VBAWarnings%"),
			// Browser-spawned executables (basic heuristic via parent in payload)
			payloadLike("evtx", "%ParentImage%chrome%"),
			payloadLike("evtx", "%ParentImage%msedge%"),
			payloadLike("evtx", "%ParentImage%outlook%"),
			payloadLike("evtx", "%ParentImage%winword%"),
			payloadLike("evtx", "%ParentImage%excel%"),
		},
	},

	// ---- TA0002 Execution ------------------------------------------------
	"execution": {
		ID: "TA0002", Name: "Execution", Slug: "execution",
		OrClauses: []string{
			evtxEventID("4688"), // process create (Security)
			sysmonOnly("1"),     // process create (Sysmon)
			evtxEventID("4697"), // service installed (also TA0003)
			evtxEventID("7045"), // service installed (System)
			// scheduled_tasks: every task is execution+persistence
			`artifact_id = 'scheduled_tasks'`,
			// prefetch confirms execution
			`artifact_id = 'prefetch'`,
			// amcache for binary presence corroboration
			`artifact_id = 'amcache'`,
			// PowerShell Operational logs
			payloadLike("evtx", "%Microsoft-Windows-PowerShell/Operational%"),
		},
	},

	// ---- TA0003 Persistence ----------------------------------------------
	// (defined separately in init() below — uses persistenceWhereClause())

	// ---- TA0004 Privilege Escalation -------------------------------------
	"privilege_escalation": {
		ID: "TA0004", Name: "Privilege Escalation", Slug: "privilege_escalation",
		OrClauses: []string{
			evtxEventID("4672"), // special privileges assigned
			evtxEventID("4673"), // privileged service called
			evtxEventID("4674"), // operation on privileged object
			// UAC bypass: Sysmon 10 ProcessAccess (already covered);
			// IFEO Debugger and AppInit_DLLs surface here too
			registryHint("TA0004"),
			sysmonOnly("10"), // ProcessAccess (UAC bypass via injection)
			// Token-manipulation evidence in 4624 type 9 (NewCredentials)
			payloadLike("evtx", "%LogonType%9%"),
		},
	},

	// ---- TA0005 Defense Evasion ------------------------------------------
	"defense_evasion": {
		ID: "TA0005", Name: "Defense Evasion", Slug: "defense_evasion",
		OrClauses: []string{
			// Audit log clearing
			evtxEventID("1102"), // Audit log cleared (Security)
			evtxEventID("104"),  // Event log cleared (System)
			// Defender / SmartScreen disabled
			payloadLike("evtx", "%Microsoft-Windows-Windows Defender%"),
			payloadLike("evtx", "%5001%"), // RTP disabled placeholder
			// Defender exclusions in registry tagged TA0005 by registry_parser
			registryHint("TA0005"),
			// Suspicious command-line patterns in process creation
			payloadLike("evtx", "%-EncodedCommand%"),
			payloadLike("evtx", "%-WindowStyle Hidden%"),
			payloadLike("evtx", "%mshta%"),
			payloadLike("evtx", "%rundll32%"),
			payloadLike("evtx", "%regsvr32%"),
			// Sysmon 12/13: tampering with security registry hives
			sysmonOnly("12"),
			sysmonOnly("13"),
		},
	},

	// ---- TA0006 Credential Access ----------------------------------------
	"credential_access": {
		ID: "TA0006", Name: "Credential Access", Slug: "credential_access",
		OrClauses: []string{
			// Kerberos
			evtxEventID("4768"), // TGT requested
			evtxEventID("4769"), // service ticket requested
			evtxEventID("4776"), // NTLM auth
			evtxEventID("4648"), // logon with explicit creds (pass-the-hash)
			// Account lockouts (brute force)
			evtxEventID("4740"),
			// Sysmon 10 ProcessAccess targeting LSASS — primary credential dumping signal
			sysmonOnly("10"),
			// Registry SAM / SECURITY hive activity
			registryHint("TA0006"),
			payloadLike("registry", "%\\\\SAM\\\\Domains\\\\Account%"),
			payloadLike("registry", "%\\\\SECURITY\\\\Policy\\\\Secrets%"),
		},
	},

	// ---- TA0007 Discovery -------------------------------------------------
	"discovery": {
		ID: "TA0007", Name: "Discovery", Slug: "discovery",
		OrClauses: []string{
			evtxEventID("4688"), // process create
			sysmonOnly("1"),     // process create
			// LOLBins typically used for discovery — match on Image / CommandLine
			payloadLike("evtx", "%whoami%"),
			payloadLike("evtx", "%net.exe%user%"),
			payloadLike("evtx", "%net.exe%group%"),
			payloadLike("evtx", "%net.exe%localgroup%"),
			payloadLike("evtx", "%ipconfig%"),
			payloadLike("evtx", "%nltest%"),
			payloadLike("evtx", "%tasklist%"),
			payloadLike("evtx", "%systeminfo%"),
			payloadLike("evtx", "%netstat%"),
			payloadLike("evtx", "%arp -a%"),
			payloadLike("evtx", "%route print%"),
			// Discovery-tagged registry keys (Uninstall, NetworkList)
			registryHint("TA0007"),
		},
	},

	// ---- TA0008 Lateral Movement -----------------------------------------
	"lateral_movement": {
		ID: "TA0008", Name: "Lateral Movement", Slug: "lateral_movement",
		OrClauses: []string{
			// Network logons
			payloadLike("evtx", `%"LogonType"%"3"%`),  // network
			payloadLike("evtx", `%"LogonType"%"10"%`), // RDP
			evtxEventID("4624"),
			evtxEventID("4625"),
			// RDP-specific
			payloadLike("evtx", "%TerminalServices-RemoteConnectionManager%"),
			payloadLike("evtx", "%TerminalServices-LocalSessionManager%"),
			payloadLike("evtx", "%RdpCoreTS%"),
			// SMB / Named pipe
			evtxEventID("5140"), // network share accessed
			evtxEventID("5145"), // detailed file share
			// WinRM / WMI
			payloadLike("evtx", "%Windows Remote Management%"),
			payloadLike("evtx", "%WMI-Activity%"),
			// At.exe + remote scheduled tasks
			`artifact_id = 'scheduled_tasks'`,
			registryHint("TA0008"),
		},
	},

	// ---- TA0009 Collection ------------------------------------------------
	"collection": {
		ID: "TA0009", Name: "Collection", Slug: "collection",
		OrClauses: []string{
			// File creation in staging dirs
			sysmonOnly("11"), // file create
			evtxEventID("4663"), // attempt to access object
			evtxEventID("4656"), // handle to object
			payloadLike("evtx", "%TargetFilename%\\\\Temp\\\\%"),
			payloadLike("evtx", "%TargetFilename%\\\\AppData\\\\%"),
			// Compression / archiving tools
			payloadLike("evtx", "%7z.exe%"),
			payloadLike("evtx", "%winrar%"),
			payloadLike("evtx", "%makecab%"),
			payloadLike("evtx", "%Compress-Archive%"),
			// Clipboard capture (Sysmon 24, requires schema 4.50+)
			sysmonOnly("24"),
		},
	},

	// ---- TA0040 Impact ----------------------------------------------------
	"impact": {
		ID: "TA0040", Name: "Impact", Slug: "impact",
		OrClauses: []string{
			// Volume Shadow Copy deletion
			payloadLike("evtx", "%vssadmin%delete%"),
			payloadLike("evtx", "%wbadmin%delete%"),
			payloadLike("evtx", "%wmic%shadowcopy%delete%"),
			// BCDEdit recovery tampering
			payloadLike("evtx", "%bcdedit%recoveryenabled%no%"),
			payloadLike("evtx", "%bcdedit%bootstatuspolicy%ignoreallfailures%"),
			// Mass file ops / encryption indicators
			sysmonOnly("11"), // file create — volume of these matters
			evtxEventID("4660"), // object deleted
			// Service stop targeting backup / AV
			evtxEventID("7036"), // service state changed (System)
			payloadLike("evtx", "%stop-service%"),
			// Boot config / shadow copy registry tampering
			payloadLike("registry", "%\\\\BCD0%"),
			payloadLike("registry", "%VolumeSnapshots%"),
		},
	},
}

// init wires the Persistence spec — uses the existing persistenceWhereClause
// from persistence_query.go to avoid duplication.
func init() {
	TacticRegistry["persistence"] = TacticSpec{
		ID: "TA0003", Name: "Persistence", Slug: "persistence",
		OrClauses: []string{persistenceWhereClause()},
	}
}

// KnownTactics returns the registered slugs in stable order for help text.
func KnownTactics() []string {
	out := make([]string, 0, len(TacticRegistry))
	for k := range TacticRegistry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ----------------------------------------------------------------------------
// Clause builders — keep formatting consistent and self-documenting
// ----------------------------------------------------------------------------

func evtxEventID(id string) string {
	return fmt.Sprintf(`(artifact_id = 'evtx' AND payload_json LIKE '%%"EventId": "%s"%%')`, id)
}

func sysmonOnly(id string) string {
	return fmt.Sprintf(
		`(artifact_id = 'evtx' AND payload_json LIKE '%%Microsoft-Windows-Sysmon%%' `+
			`AND payload_json LIKE '%%"EventId": "%s"%%')`, id)
}

func registryHint(tacticID string) string {
	return fmt.Sprintf(
		`(artifact_id = 'registry' AND payload_json LIKE '%%%s%%')`, tacticID)
}

func payloadLike(artifactID, like string) string {
	if artifactID == "" {
		return fmt.Sprintf(`(payload_json LIKE '%s')`, like)
	}
	return fmt.Sprintf(
		`(artifact_id = '%s' AND payload_json LIKE '%s')`, artifactID, like)
}

// ----------------------------------------------------------------------------
// Generic query
// ----------------------------------------------------------------------------

// queryEventsForTactic runs the OR-joined filter for a tactic and returns
// up to maxRows rows plus the total match count (so we can flag truncation
// honestly to the LLM). Wave 20h: when artifactScope is non-empty, the
// filter is additionally AND'd with `artifact_id = ?` so the LLM only sees
// events from one parser's output. Wave 22: thin wrapper around
// queryEventsForTacticOffset with offset=0 for back-compat.
func queryEventsForTactic(
	ctx context.Context,
	db *sql.DB,
	caseID string,
	spec TacticSpec,
	maxRows int,
	artifactScope string,
) (window EventWindow, totalMatching int, err error) {
	return queryEventsForTacticOffset(ctx, db, caseID, spec, maxRows, 0, artifactScope)
}

// queryEventsForTacticOffset (Wave 22) is the slidable variant. offset is
// the number of rows to skip after the same ORDER BY ts_utc — used by the
// sliding window loop to walk past previously-shown events. Pass offset=0
// to reproduce the original 1-shot behaviour.
func queryEventsForTacticOffset(
	ctx context.Context,
	db *sql.DB,
	caseID string,
	spec TacticSpec,
	maxRows, offset int,
	artifactScope string,
) (window EventWindow, totalMatching int, err error) {
	if len(spec.OrClauses) == 0 {
		return EventWindow{}, 0,
			fmt.Errorf("tactic %q has empty OrClauses", spec.Slug)
	}
	where := strings.Join(spec.OrClauses, " OR ")

	totalMatching, err = countTacticEvents(ctx, db, caseID, where, artifactScope)
	if err != nil {
		return EventWindow{}, 0, err
	}

	// Wave 20h: scope guard. Without the artifact_id AND clause, a per-
	// artifact run would still pull events from every other artifact that
	// the tactic happens to match — defeating the point of "Analyze just
	// this artifact". With the AND clause, the LLM sees rows from one
	// parser exclusively.
	artifactAnd := ""
	args := []interface{}{caseID}
	if artifactScope != "" {
		artifactAnd = " AND artifact_id = ?"
		args = append(args, artifactScope)
	}
	args = append(args, maxRows, offset)

	q := `
		SELECT audit_id, COALESCE(ts_utc, NULL), artifact_id,
		       COALESCE(computer, ''), payload_json
		  FROM unified_events
		 WHERE case_id = ?` + artifactAnd + `
		   AND (` + where + `)
		 ORDER BY ts_utc
		 LIMIT ? OFFSET ?`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return EventWindow{}, 0, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	window = EventWindow{
		CaseID: caseID,
		Tactic: spec.ID,
		Events: make([]EventForLLM, 0, maxRows),
		Counts: map[string]int{},
	}

	var minTS, maxTS time.Time
	for rows.Next() {
		var auditID, artifactID, computer, payloadJSON string
		var ts sql.NullTime
		if err := rows.Scan(&auditID, &ts, &artifactID, &computer, &payloadJSON); err != nil {
			return EventWindow{}, 0, err
		}
		ev := EventForLLM{
			AuditID:  auditID,
			Artifact: artifactID,
			Computer: computer,
			Excerpt:  shrinkPayload(artifactID, payloadJSON),
		}
		if ts.Valid {
			ev.TS = ts.Time.UTC().Format(time.RFC3339Nano)
			if minTS.IsZero() || ts.Time.Before(minTS) {
				minTS = ts.Time
			}
			if ts.Time.After(maxTS) {
				maxTS = ts.Time
			}
		}
		window.Events = append(window.Events, ev)
		window.Counts[artifactID]++
	}
	if err := rows.Err(); err != nil {
		return EventWindow{}, 0, err
	}
	window.Total = len(window.Events)
	window.Truncated = totalMatching > maxRows
	if !minTS.IsZero() {
		window.WindowMin = minTS.UTC()
	}
	if !maxTS.IsZero() {
		window.WindowMax = maxTS.UTC()
	}
	return window, totalMatching, nil
}

func countTacticEvents(
	ctx context.Context, db *sql.DB, caseID, where, artifactScope string,
) (int, error) {
	args := []interface{}{caseID}
	artifactAnd := ""
	if artifactScope != "" {
		artifactAnd = " AND artifact_id = ?"
		args = append(args, artifactScope)
	}
	q := `SELECT COUNT(*) FROM unified_events
	      WHERE case_id = ?` + artifactAnd + ` AND (` + where + `)`
	var n int
	if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// TacticsForArtifact (Wave 20h) returns the tactic IDs whose OR-clauses
// reference the given artifact_id, either directly via `artifact_id =
// 'X'` or via a more complex expression containing the literal string.
// Used by the "Analyze this artifact" endpoint to skip tactics that
// would receive zero rows after the artifact scope is applied.
//
// The match is intentionally lexical (substring of the OR clauses) so
// it stays correct as new OR-clauses get added — no separate mapping
// table to drift out of sync. timeline_review is excluded because it
// runs after the tactic round, not in parallel with it.
func TacticsForArtifact(artifactID string) []string {
	if artifactID == "" {
		return nil
	}
	needle := fmt.Sprintf("artifact_id = '%s'", artifactID)
	out := make([]string, 0, len(TacticRegistry))
	for id, spec := range TacticRegistry {
		if id == "timeline_review" {
			continue
		}
		for _, clause := range spec.OrClauses {
			if strings.Contains(clause, needle) {
				out = append(out, id)
				break
			}
		}
	}
	// Stable order so the UI shows tactics in a predictable sequence
	// (caller can re-sort if it wants something else).
	sort.Strings(out)
	return out
}
