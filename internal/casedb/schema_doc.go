// Package casedb — schema_doc.go
//
// SchemaDoc / SchemaVersion(For) は Tier 1A build パイプラインが LLM に
// 「どのスキーマに対する SQL を書かせるか」を伝える単一情報源であり、同時に
// rule_sql_cache の無効化キーを供給する。
//
// ★ セクション化 (2026-06-19)
//
// 旧実装は doc 全体を 1 本のハッシュ (SchemaVersion) にしていたため、prefetch
// や amcache のドキュメントを足すだけで EVTX しか参照しない 1,700+ 本の sigma
// ルールまで一斉に再 build 対象になった。これを構造的に解消するため、doc を
//
//	schemaCommonHeader  — 全ルール共通 (列定義 + JSON 抽出構文)
//	schemaSections[art] — artifact_id ごとの payload 仕様 + 推奨 SQL
//	schemaMiscSection   — 専用セクションを持たない artifact 群の共通記述
//	schemaConstraints   — 全ルール共通 (SQL 生成規約)
//
// に分割し、ルールごとの無効化キーを SchemaVersionFor(prefilter) で
// 「そのルールが触る artifact のセクションだけ」から算出する。prefetch
// セクションを書き換えても evtx ルールのキーは動かない = 再 build されない。
//
// SchemaVersion() (doc 全体ハッシュ) は Tier 1B の skill_sql_cache 無効化キーと
// して引き続き使う (skill は任意 artifact を横断探索しうるので doc 全体に依存)。
package casedb

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// UnifiedEventsDDL is the canonical CREATE TABLE statement for unified_events.
// ensureSchema() embeds this verbatim so the schema_version key always
// reflects what's actually in the running DB.
const UnifiedEventsDDL = `CREATE TABLE IF NOT EXISTS unified_events (
    case_id       VARCHAR NOT NULL,
    evidence_id   VARCHAR,
    artifact_id   VARCHAR NOT NULL,
    audit_id      VARCHAR NOT NULL,
    ts_utc        TIMESTAMP,
    event_type    VARCHAR NOT NULL,
    computer      VARCHAR,
    payload_json  VARCHAR NOT NULL
)`

// schemaCommonHeader documents the unified_events columns and the DuckDB JSON
// extraction syntax. EVERY generated rule depends on this regardless of which
// artifact it targets, so it is folded into every schema_version key.
const schemaCommonHeader = `Table: unified_events  (DuckDB)
  case_id       VARCHAR  — required filter key (always filter by this)
  evidence_id   VARCHAR  — optional, identifies the evidence within a case
  artifact_id   VARCHAR  — source kind: "evtx" | "amcache" | "registry" |
                            "prefetch" | "shimcache" | "mft" | "shellbags" |
                            "jumplists" | "lnk" | "recyclebin" |
                            "win10timeline" | "usn_journal" | "hayabusa" |
                            "srum" | "browser_history" | "washizukami_audit" |
                            "w3c_iis" | "web_error" | "scheduled_tasks"
  audit_id      VARCHAR  — SHA-256 prefix of canonical payload, unique per case
  ts_utc        TIMESTAMP — event time in UTC; NULL for artifacts without
                            per-event timestamps (e.g. shimcache)
  event_type    VARCHAR  — coarse category, currently always equal to artifact_id
                            for EVTX rows (refine per-rule via payload fields)
  computer      VARCHAR  — hostname (optional)
  payload_json  VARCHAR  — JSON-encoded artifact-specific payload

DuckDB JSON extraction:
  json_extract_string(payload_json, '$.Channel')             → string
  json_extract(payload_json, '$.EventId')                    → JSON value
  CAST(json_extract_string(payload_json, '$.EventId') AS INTEGER)  → integer
  Use ILIKE for case-insensitive substring, LIKE for case-sensitive.`

// schemaConstraints is the rule-authoring contract appended after every
// schema doc. Shared by every rule, so it too is part of every version key.
const schemaConstraints = `Constraints for generated SQL:
  - MUST include WHERE case_id = ? as the first predicate (parameterised)
  - SHOULD include AND artifact_id = '<id>' when the rule targets a single source
  - Output column list MUST start with: audit_id, ts_utc, artifact_id, event_type
    (plus rule-specific extracted columns the runtime stores in Extra)
  - Use json_extract_string for VARCHAR comparisons; CAST to INTEGER for EventId
  - For Sigma "process_creation" rules that use Sysmon field names like
    Image/CommandLine/ParentImage: in our schema this data lives in
      $.ExecutableInfo  (full cmdline of the new process)
      $.PayloadData1    (parent process path on 4688)
    Use ILIKE on those, NOT a literal "$.Image".
  - Windows EVTX process-creation (4688) and Sysmon are NOT always present:
    audit policy may be off and no Sysmon installed. When a rule's intent is
    "a binary executed", prefer the forensic execution artifacts (amcache /
    prefetch / registry-UserAssist) which record execution independently of
    event-log auditing. Set the rule's prefilter artifacts accordingly.`

// schemaSections maps artifact_id -> the doc block describing that artifact's
// payload_json shape and recommended SQL. A Tier 1A rule's schema_version (see
// SchemaVersionFor) is computed from ONLY the sections for the artifacts it
// targets, plus schemaCommonHeader + schemaConstraints. Adding or expanding the
// section for one artifact therefore does NOT invalidate cached SQL for rules
// that target a different artifact.
//
// Field names below are the ACTUAL payload_json keys produced by the Tier 0
// parsers (verified against parsed cases) — earlier docs listed several wrong
// keys for the forensic artifacts (e.g. prefetch "$.ExecutableName"/"$.LastRun",
// browser "$.URL"/"$.LastVisited") which is partly why forensic SQL never
// worked. Use the keys documented here.
var schemaSections = map[string]string{
	"evtx": `===== artifact_id='evtx' (Windows Event Log via EvtxECmd) =====

Payload structure (top-level fields):
  TimeCreated      VARCHAR — "YYYY-MM-DD HH:MM:SS.fffffff" (also reflected in ts_utc)
  EventId          VARCHAR — Event ID as STRING (e.g. "4688", "4624", "4625", "4104", "3008"). CAST to INTEGER when comparing.
  Channel          VARCHAR — "Security" | "System" | "Application" |
                            "Microsoft-Windows-PowerShell/Operational" |
                            "Microsoft-Windows-DNS-Client/Operational" |
                            "Microsoft-Windows-Sysmon/Operational" | etc.
  Provider         VARCHAR — e.g. "Microsoft-Windows-Security-Auditing"
  Level            VARCHAR — "LogAlways" | "Info" | "Warning" | "Error" | etc.
  Computer         VARCHAR — hostname
  UserId           VARCHAR — SID
  MapDescription   VARCHAR — human description, e.g. "A new process has been created"
  PayloadData1..6  VARCHAR — pre-extracted important fields. For 4688:
                              PayloadData1 = "Parent process: <path>" (parent image)
                              PayloadData2 = "PID: 0x<hex>"
                              PayloadData3 = "Parent PID: 0x<hex>"
                            For 4624/4625 these hold logon-related fields.
  ExecutableInfo   VARCHAR — FULL command line of the new process (for 4688).
                            This is the canonical place to look for process
                            commandlines + arguments.
  raw              JSON object — original full event:
    raw.UserName   — DOMAIN\user
    raw.Payload    — original Windows EventData (stringified JSON). Contains
                     fields named NewProcessName, NewProcessId, CommandLine,
                     ParentProcessName, TargetUserName, IpAddress, etc.
                     Extract via:
                       json_extract_string(payload_json,
                         '$.raw.Payload') ILIKE '%CommandLine%'
                     or for direct nested access (less reliable, depends on
                     how DuckDB sees nested JSON):
                       json_extract_string(payload_json, '$.raw.UserName')

Recommended Windows EVTX SQL patterns:
  - 4688 with command line containing "X":
      WHERE artifact_id='evtx'
        AND CAST(json_extract_string(payload_json, '$.EventId') AS INTEGER) = 4688
        AND json_extract_string(payload_json, '$.ExecutableInfo') ILIKE '%X%'
  - 4625 failed logon:
      WHERE artifact_id='evtx'
        AND CAST(json_extract_string(payload_json, '$.EventId') AS INTEGER) = 4625
  - PowerShell 4104 script block:
      WHERE artifact_id='evtx'
        AND json_extract_string(payload_json, '$.Channel')
              = 'Microsoft-Windows-PowerShell/Operational'
        AND CAST(json_extract_string(payload_json, '$.EventId') AS INTEGER) = 4104
        AND json_extract_string(payload_json, '$.PayloadData1') ILIKE '%-enc%'
  - DNS-Client 3008 NXDOMAIN:
      WHERE artifact_id='evtx'
        AND json_extract_string(payload_json, '$.Channel')
              = 'Microsoft-Windows-DNS-Client/Operational'
        AND CAST(json_extract_string(payload_json, '$.EventId') AS INTEGER) = 3008`,

	"hayabusa": `===== artifact_id='hayabusa' (precomputed Sigma matches) =====

Hayabusa runs at parse-time and writes one row per matched EVTX event.
Payload fields:
  RuleTitle       VARCHAR — Sigma rule title that matched (e.g. "Proc Exec")
  Level           VARCHAR — "info" | "low" | "med" | "high"
  RuleAuthor      VARCHAR
  EventTitle      VARCHAR — normalised event description
  Channel         VARCHAR — same as evtx
  EventID         VARCHAR — original Windows EventId
  Details         VARCHAR — combined detail line (often contains command line)`,

	"w3c_iis": `===== artifact_id='w3c_iis' (IIS / web-server access log) =====

Web-facing HTTP request logs. IIS W3C Extended, IIS native, and NCSA
Common/Combined are ALL normalised to the canonical W3C field names below, so
one rule matches regardless of the on-disk format. One row per request.

IMPORTANT: these payload keys contain hyphens, so the JSON path MUST be
double-quoted, e.g. json_extract_string(payload_json, '$."cs-uri-stem"').
A bare '$.cs-uri-stem' will NOT work.

  "c-ip"           VARCHAR — client (source) IP
  "cs-method"      VARCHAR — HTTP method: GET | POST | HEAD | PUT | ...
  "cs-uri-stem"    VARCHAR — requested path WITHOUT the query string (e.g. /admin/x.aspx)
  "cs-uri-query"   VARCHAR — query string only ('-' when none)
  "sc-status"      VARCHAR — HTTP status as STRING ("200","404","500"); CAST to INTEGER to compare
  "cs-User-Agent"  VARCHAR — client User-Agent ('-' when absent)
  "cs(Referer)"    VARCHAR — referer (NCSA Combined only)
  "cs-username"    VARCHAR — authenticated user ('-' when anonymous)
  "s-ip"           VARCHAR — server IP
  "s-computername" VARCHAR — server hostname (IIS native only; mirrored in the computer column)
  "time-taken"     VARCHAR — request duration in ms (W3C / IIS native)
  "log_format"     VARCHAR — "w3c" | "iis" | "ncsa"

Recommended webserver SQL patterns (Sigma category:webserver rules target these):
  - Path traversal in the URI:
      WHERE artifact_id='w3c_iis'
        AND json_extract_string(payload_json, '$."cs-uri-stem"') ILIKE '%../%'
  - SQL injection / suspicious query string:
      WHERE artifact_id='w3c_iis'
        AND json_extract_string(payload_json, '$."cs-uri-query"') ILIKE '%union%select%'
  - Suspicious User-Agent (scanners / exploit tools):
      WHERE artifact_id='w3c_iis'
        AND json_extract_string(payload_json, '$."cs-User-Agent"') ILIKE '%sqlmap%'
  - Webshell access (uploaded script returning 200):
      WHERE artifact_id='w3c_iis'
        AND json_extract_string(payload_json, '$."cs-uri-stem"') ILIKE '%.aspx'
        AND CAST(json_extract_string(payload_json, '$."sc-status"') AS INTEGER) = 200`,

	"web_error": `===== artifact_id='web_error' (Apache / nginx / Tomcat error & diagnostic logs) =====

Non-NCSA diagnostic logs (Apache error_log, nginx error.log, Tomcat
catalina.out). Access logs are 'w3c_iis'; THIS artifact is the error/diagnostic
side. One row per log line. Payload fields (plain keys — no hyphens):
  "server_type"  VARCHAR — "apache" | "nginx" | "tomcat"
  "severity"     VARCHAR — normalised lowercase: "error" | "warn" | "notice" | "severe" | "info" | ...
  "client_ip"    VARCHAR — source IP when the line carries one ('-' otherwise)
  "message"      VARCHAR — the log message body
  "log_format"   VARCHAR — same as server_type

Recommended SQL patterns (Sigma service:apache / service:nginx rules target these):
  - Apache segfault / child crash (exploitation attempts):
      WHERE artifact_id='web_error'
        AND json_extract_string(payload_json, '$.server_type') = 'apache'
        AND json_extract_string(payload_json, '$.message') ILIKE '%segmentation fault%'
  - nginx worker crash / core dump:
      WHERE artifact_id='web_error'
        AND json_extract_string(payload_json, '$.server_type') = 'nginx'
        AND json_extract_string(payload_json, '$.message') ILIKE '%(core dumped)%'
  - All errors from a specific source IP:
      WHERE artifact_id='web_error'
        AND json_extract_string(payload_json, '$.client_ip') = '203.0.113.9'`,

	"prefetch": `===== artifact_id='prefetch' (Windows Prefetch, execution evidence) =====

One row per .pf file = one executable that RAN on this host. Records execution
WITHOUT depending on Security 4688 / Sysmon, so it survives when process-creation
auditing is off. ts_utc holds the run time for the row (run_kind says which run).
Payload fields (verified keys):
  executable     VARCHAR — image file NAME only, e.g. "NICEEDITOR.EXE" (NO path)
  run_count      INTEGER — total times executed
  run_kind       VARCHAR — "last_run" | "previous_run" (which run ts_utc refers to)
  files_loaded   VARCHAR — comma-joined FULL paths of files/DLLs the run touched.
                           THIS is where the executable's full path appears, e.g.
                           "...\USERS\TANAKA\DOWNLOADS\NICEEDITOR.EXE" — use it to
                           tell WHERE the binary lived (Downloads / Temp / AppData).
  directories    VARCHAR — comma-joined directories referenced by the run
  size_bytes     INTEGER
  hash           VARCHAR — prefetch hash (from the .pf filename)
  volume0_name / volume0_serial / volume0_created — backing volume info
  source_filename VARCHAR — the .pf filename

NOTE: prefetch paths are UPPERCASE and use \VOLUME{...} prefixes; match with
ILIKE on substrings like '%\DOWNLOADS\%' / '%\APPDATA\LOCAL\TEMP\%'.

Recommended SQL patterns:
  - Executable that ran from a user Downloads or Temp folder:
      WHERE artifact_id='prefetch'
        AND (json_extract_string(payload_json, '$.files_loaded') ILIKE '%\DOWNLOADS\%.EXE'
          OR json_extract_string(payload_json, '$.files_loaded') ILIKE '%\APPDATA\LOCAL\TEMP\%.EXE')
  - A specific binary name that executed:
      WHERE artifact_id='prefetch'
        AND json_extract_string(payload_json, '$.executable') = 'POWERSHELL.EXE'`,

	"amcache": `===== artifact_id='amcache' (Amcache.hve, program presence + hash) =====

One row per program/binary the OS recorded in Amcache. Independent of EVTX —
records that a PE was PRESENT (and usually ran) with its SHA1, so it is a prime
signal for "an executable existed here" even with no process-creation logs.
Payload fields (verified keys):
  FullPath                  VARCHAR — full on-disk path, e.g. "C:\Users\Tanaka\Downloads\niceeditor.exe"
  Name                      VARCHAR — file name
  SHA1                      VARCHAR — SHA-1 of the file (lowercase hex; may be empty)
  IsOsComponent             VARCHAR — "true"/"false" — OS-shipped component flag
  IsPeFile                  VARCHAR — "true"/"false"
  BinaryType                VARCHAR — "pe32" | "pe64" | ...
  ProductName / ProductVersion / Version / Description / OriginalFileName VARCHAR — PE metadata (often empty for malware)
  FileKeyLastWriteTimestamp VARCHAR — when Amcache recorded it (also in ts_utc)
  LinkDate                  VARCHAR — PE compile timestamp
  Size                      INTEGER

Recommended SQL patterns:
  - Non-OS PE under a user profile (suspicious binary that was present/ran):
      WHERE artifact_id='amcache'
        AND json_extract_string(payload_json, '$.IsOsComponent') = 'false'
        AND json_extract_string(payload_json, '$.FullPath') ILIKE '%\Users\%'
        AND (json_extract_string(payload_json, '$.FullPath') ILIKE '%\Downloads\%'
          OR json_extract_string(payload_json, '$.FullPath') ILIKE '%\AppData\Local\Temp\%')
  - Match a known-bad SHA1:
      WHERE artifact_id='amcache'
        AND lower(json_extract_string(payload_json, '$.SHA1')) = lower('<hash>')`,

	"registry": `===== artifact_id='registry' (RegRipper/RECmd plugin output) =====

One row per decoded registry value. RECmd/plugins decode high-value keys
(UserAssist, AppCompatFlags, Run keys, Services, etc.) into readable fields.
Payload fields (verified keys):
  KeyPath           VARCHAR — full registry key path
  ValueName         VARCHAR — value name (for UserAssist this is the ROT13 name)
  ValueData         VARCHAR — decoded value. For execution plugins this is the
                              DECODED program path, e.g. "C:\Users\Tanaka\Downloads\niceeditor.exe"
  ValueData2        VARCHAR — secondary decoded field, e.g. "Last executed: 2026-02-14 13:17:22"
  ValueData3        VARCHAR — tertiary decoded field, e.g. "Run count: 1"
  ValueType         VARCHAR
  Description       VARCHAR — plugin/key class. KEY VALUES: "UserAssist",
                              "AppCompatFlags", "Run", "Services", "ShimCache", ...
  Category          VARCHAR — high-level grouping. "Program Execution" tags
                              execution-evidence plugins (UserAssist / AppCompatFlags / etc.)
  HiveType          VARCHAR — "NTUSER" | "SOFTWARE" | "SYSTEM" | "SAM" | ...
  LastWriteTimestamp VARCHAR — key last-write (also in ts_utc where applicable)

Execution evidence lives here independently of EVTX. UserAssist records that a
user RAN a program (decoded path in ValueData, run count in ValueData3).

Recommended SQL patterns:
  - Program executed by a user from Downloads/Temp, via UserAssist or AppCompatFlags:
      WHERE artifact_id='registry'
        AND json_extract_string(payload_json, '$.Category') = 'Program Execution'
        AND (json_extract_string(payload_json, '$.ValueData') ILIKE '%\Downloads\%.exe'
          OR json_extract_string(payload_json, '$.ValueData') ILIKE '%\AppData\Local\Temp\%.exe')
  - Any UserAssist run entry:
      WHERE artifact_id='registry'
        AND json_extract_string(payload_json, '$.Description') = 'UserAssist'`,

	"browser_history": `===== artifact_id='browser_history' (Chrome/Firefox/Edge history) =====

One row per browser visit (and download landing). Captures the WEB PROVENANCE of
a file — e.g. that a user browsed to a sketchy host right before a binary ran.
Payload fields (verified keys — all lowercase):
  url            VARCHAR — visited URL, e.g. "http://niceeditor.com:443/"
  title          VARCHAR — page title, e.g. "Directory listing for /" (open dir = common drop site)
  browser_kind   VARCHAR — "chromium" | "firefox" | ...
  visit_count    INTEGER — total visits to this URL
  typed_count    INTEGER — times the URL was typed (>0 = user typed it directly)
  transition     VARCHAR — visit transition: "typed" | "link" | "download" | ...
  referrer_url   VARCHAR — referrer (may be null)
  visit_id       INTEGER
The visit time is in ts_utc (there is no separate last-visited payload field).

Recommended SQL patterns:
  - Visit to a raw directory-listing page (typical malware drop server):
      WHERE artifact_id='browser_history'
        AND json_extract_string(payload_json, '$.title') ILIKE 'Directory listing for%'
  - Directly-typed navigation to an executable / archive:
      WHERE artifact_id='browser_history'
        AND (json_extract_string(payload_json, '$.url') ILIKE '%.exe'
          OR json_extract_string(payload_json, '$.url') ILIKE '%.zip')
        AND CAST(json_extract_string(payload_json, '$.typed_count') AS INTEGER) > 0`,

	"mft": `===== artifact_id='mft' ($MFT file-system metadata) =====

One row per file-system record. Shows files that EXIST(ed) with timestamps —
useful to confirm a downloaded payload landed on disk.
Payload fields (verified keys):
  FullPath    VARCHAR — full path, e.g. "C:\Users\Tanaka\Downloads\niceeditor.exe"
  IsDirectory VARCHAR/BOOL — directory flag
  FileSize    INTEGER — size in bytes
  (standard/$FN timestamps reflected in ts_utc where available)

Recommended SQL pattern:
  - An executable dropped into a user Downloads folder:
      WHERE artifact_id='mft'
        AND json_extract_string(payload_json, '$.FullPath') ILIKE '%\Users\%\Downloads\%.exe'`,

	"shimcache": `===== artifact_id='shimcache' (AppCompatCache, execution/presence) =====

Ordered list of executables the OS saw. NO reliable per-entry run time (ts_utc is
often NULL); ordering and presence are the signal.
Payload fields (verified keys):
  Path          VARCHAR — full executable path
  LastModified  VARCHAR — $StandardInfo last-modified of the binary (may be empty)
  Executed      VARCHAR — "true"/"false"/"" depending on OS version

Recommended SQL pattern:
  - Executable seen running from a user/temp path:
      WHERE artifact_id='shimcache'
        AND (json_extract_string(payload_json, '$.Path') ILIKE '%\Downloads\%.exe'
          OR json_extract_string(payload_json, '$.Path') ILIKE '%\AppData\Local\Temp\%.exe')`,
}

// schemaMiscSection documents the artifacts without a dedicated section. It is
// included in the full doc AND used as the version input for any artifact not
// present in schemaSections, so every artifact yields a stable schema_version.
const schemaMiscSection = `===== other artifacts =====

Artifacts without a dedicated section above. payload_json carries the parser's
native field names; common high-value fields when present:
  - lnk rows:        $.SourceFile, $.TargetPath, $.WorkingDirectory, $.Arguments
  - jumplists:       $.Path, $.Arguments, $.AppId
  - recyclebin:      $.FileName, $.OriginalPath, $.FileSize, $.DeletedTimestamp
  - win10timeline:   $.AppId, $.Payload, $.StartTime
  - usn_journal:     $.FileName, $.Reason, $.ParentPath
  - shellbags:       $.AbsolutePath, $.LastWriteTime
  - scheduled_tasks: $.TaskName, $.Command, $.Arguments, $.Author
  - srum:            $.AppName / $.ExeInfo, network/energy usage counters
  - washizukami_audit: collector-specific audit rows`

// schemaVerHash hashes its parts (NUL-separated) into the "uev-"-prefixed
// short key used throughout rule_sql_cache.
func schemaVerHash(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	return "uev-" + hex.EncodeToString(sum[:8])
}

// SchemaDoc returns the full human/LLM-readable schema description used in
// Tier 1A build prompts: common header + every artifact section (sorted for
// determinism) + misc section + constraints. The LLM always sees the whole
// doc; the sectioning only affects cache-key computation.
func SchemaDoc() string {
	var b strings.Builder
	b.WriteString(schemaCommonHeader)
	keys := make([]string, 0, len(schemaSections))
	for k := range schemaSections {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("\n\n")
		b.WriteString(schemaSections[k])
	}
	b.WriteString("\n\n")
	b.WriteString(schemaMiscSection)
	b.WriteString("\n\n")
	b.WriteString(schemaConstraints)
	return b.String()
}

// SchemaVersion returns a short stable hash of UnifiedEventsDDL + the FULL
// SchemaDoc(). Used as the skill_sql_cache invalidation key for Tier 1B (whose
// learned SQL may touch any artifact, so it depends on the whole doc).
//
// Tier 1A rules use SchemaVersionFor instead — see that function.
func SchemaVersion() string {
	return schemaVerHash(UnifiedEventsDDL, SchemaDoc())
}

// SchemaVersionFor returns the cache-invalidation key for a Tier 1A rule that
// targets the given artifact_ids (its prefilter_artifacts). The key folds in
// ONLY the common header, the constraints, and the doc sections for the listed
// artifacts — so editing the section for artifact A never changes the key of a
// rule that targets only artifact B, and that rule is not rebuilt.
//
// An empty / all-artifacts prefilter ("" = the rule may read anything) falls
// back to SchemaVersion() (depends on the whole doc) — the conservative choice.
//
// Assumption: a rule's declared prefilter_artifacts faithfully lists the
// artifacts its SQL reads. Tier 1A rules are single-source by construction, so
// this holds; cross-artifact correlation is Tier 2's job, not Tier 1A's.
func SchemaVersionFor(artifacts []string) string {
	secs := sectionTextsFor(artifacts)
	if secs == nil {
		return SchemaVersion()
	}
	parts := make([]string, 0, len(secs)+3)
	parts = append(parts, UnifiedEventsDDL, schemaCommonHeader)
	parts = append(parts, secs...)
	parts = append(parts, schemaConstraints)
	return schemaVerHash(parts...)
}

// sectionTextsFor returns the deduplicated, sorted section texts for the given
// artifacts. Returns nil when the prefilter is empty/whitespace (signalling the
// whole-doc fallback). Artifacts without a dedicated section map to
// schemaMiscSection.
func sectionTextsFor(artifacts []string) []string {
	seen := map[string]bool{}
	var out []string
	any := false
	for _, a := range artifacts {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		any = true
		txt, ok := schemaSections[a]
		if !ok {
			txt = schemaMiscSection
		}
		if !seen[txt] {
			seen[txt] = true
			out = append(out, txt)
		}
	}
	if !any {
		return nil
	}
	sort.Strings(out)
	return out
}
