// Package casedb — schema_doc.go
//
// SchemaVersion / SchemaDoc は Tier 1A build パイプラインが LLM に
// 「どのスキーマに対する SQL を書かせるか」を伝えるための単一情報源。
//
// SchemaVersion は rule_sql_cache の無効化キー (rule_sha256 / model_id と
// 並ぶ 3 本柱) なので、unified_events の DDL を変更すると自動的に全 cache
// が再 build 対象になる。
package casedb

import (
	"crypto/sha256"
	"encoding/hex"
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

// SchemaVersion returns a short stable hash of both UnifiedEventsDDL and
// SchemaDoc. Used as one of the three cache invalidation keys in
// rule_sql_cache — touching either input invalidates all cached SQL so
// the next build regenerates it against the new schema description.
func SchemaVersion() string {
	h := sha256.New()
	h.Write([]byte(UnifiedEventsDDL))
	h.Write([]byte{0})
	h.Write([]byte(SchemaDoc()))
	sum := h.Sum(nil)
	return "uev-" + hex.EncodeToString(sum[:8])
}

// SchemaDoc returns a human/LLM-readable description of the unified_events
// schema, used in Tier 1A build prompts.
//
// The doc documents BOTH the query interface (unified_events columns +
// DuckDB JSON syntax) AND the per-artifact payload_json shape (so the LLM
// knows what fields each artifact actually exposes). We document the EVTX
// payload most thoroughly because it's the densest and most-targeted
// artifact for Sigma rules.
func SchemaDoc() string {
	return `Table: unified_events  (DuckDB)
  case_id       VARCHAR  — required filter key (always filter by this)
  evidence_id   VARCHAR  — optional, identifies the evidence within a case
  artifact_id   VARCHAR  — source kind: "evtx" | "amcache" | "registry" |
                            "prefetch" | "shimcache" | "mft" | "shellbags" |
                            "jumplists" | "lnk" | "recyclebin" |
                            "win10timeline" | "usn_journal" | "hayabusa" |
                            "srum" | "browser_history" | "washizukami_audit" |
                            "w3c_iis" | "web_error"
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
  Use ILIKE for case-insensitive substring, LIKE for case-sensitive.

===== artifact_id='evtx' (Windows Event Log via EvtxECmd) =====

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
        AND CAST(json_extract_string(payload_json, '$.EventId') AS INTEGER) = 3008

===== artifact_id='hayabusa' (precomputed Sigma matches) =====

Hayabusa runs at parse-time and writes one row per matched EVTX event.
Payload fields:
  RuleTitle       VARCHAR — Sigma rule title that matched (e.g. "Proc Exec")
  Level           VARCHAR — "info" | "low" | "med" | "high"
  RuleAuthor      VARCHAR
  EventTitle      VARCHAR — normalised event description
  Channel         VARCHAR — same as evtx
  EventID         VARCHAR — original Windows EventId
  Details         VARCHAR — combined detail line (often contains command line)

===== artifact_id='w3c_iis' (IIS / web-server access log) =====

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
        AND CAST(json_extract_string(payload_json, '$."sc-status"') AS INTEGER) = 200

===== artifact_id='web_error' (Apache / nginx / Tomcat error & diagnostic logs) =====

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
        AND json_extract_string(payload_json, '$.client_ip') = '203.0.113.9'

===== other artifacts =====

Each artifact has its own payload_json schema. Common fields when present:
  - registry rows: $.KeyPath, $.ValueName, $.ValueData, $.LastWriteTimestamp
  - lnk rows:      $.SourceFile, $.TargetPath, $.WorkingDirectory, $.Arguments
  - prefetch:      $.ExecutableName, $.LastRun, $.PreviousRunN
  - mft:           $.FullPath, $.IsDirectory, $.FileSize
  - amcache:       $.FullPath, $.SHA1, $.LastModifiedTime
  - browser_history: $.URL, $.Title, $.LastVisited

Constraints for generated SQL:
  - MUST include WHERE case_id = ? as the first predicate (parameterised)
  - SHOULD include AND artifact_id = '<id>' when the rule targets a single source
  - Output column list MUST start with: audit_id, ts_utc, artifact_id, event_type
    (plus rule-specific extracted columns the runtime stores in Extra)
  - Use json_extract_string for VARCHAR comparisons; CAST to INTEGER for EventId
  - For Sigma "process_creation" rules that use Sysmon field names like
    Image/CommandLine/ParentImage: in our schema this data lives in
      $.ExecutableInfo  (full cmdline of the new process)
      $.PayloadData1    (parent process path on 4688)
    Use ILIKE on those, NOT a literal "$.Image".`
}
