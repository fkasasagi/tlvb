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

// SchemaVersion returns a short stable hash of UnifiedEventsDDL.
// Used as one of the three cache invalidation keys in rule_sql_cache.
func SchemaVersion() string {
	h := sha256.Sum256([]byte(UnifiedEventsDDL))
	return "uev-" + hex.EncodeToString(h[:8])
}

// SchemaDoc returns a human/LLM-readable description of the unified_events
// schema, used in Tier 1A build prompts.
//
// The doc intentionally documents the *query interface* (column meaning +
// DuckDB JSON extraction syntax) rather than the per-artifact payload
// shape — payloads differ per artifact_id and are documented separately
// per-artifact (TODO: config/payload_schemas/<artifact_id>.json).
func SchemaDoc() string {
	return `Table: unified_events  (DuckDB)
  case_id       VARCHAR  — required filter key (always filter by this)
  evidence_id   VARCHAR  — optional, identifies the evidence within a case
  artifact_id   VARCHAR  — source kind: "evtx" | "amcache" | "registry" |
                            "prefetch" | "shimcache" | "mft" | "shellbags" |
                            "jumplists" | "lnk" | "recyclebin" |
                            "win10timeline" | "usn_journal" | "hayabusa" |
                            "srum" | "browser_history" | "washizukami_audit"
  audit_id      VARCHAR  — SHA-256 prefix of canonical payload, unique per case
  ts_utc        TIMESTAMP — event time in UTC; NULL for artifacts without
                            per-event timestamps (e.g. shimcache)
  event_type    VARCHAR  — coarse category, e.g. "process_creation",
                            "logon", "file_modify", "registry_write"
  computer      VARCHAR  — hostname (optional)
  payload_json  VARCHAR  — JSON-encoded artifact-specific payload

DuckDB JSON extraction:
  json_extract(payload_json, '$.EventID')                    → JSON value
  json_extract_string(payload_json, '$.User')                → string
  json_extract(payload_json, '$.Process.CommandLine')        → JSON value
  CAST(json_extract(payload_json, '$.EventID') AS INTEGER)   → integer

Constraints for generated SQL:
  - MUST include WHERE case_id = ? as the first predicate (parameterised)
  - SHOULD include AND artifact_id = '<id>' when the rule targets a single source
  - Output column list MUST start with: audit_id, ts_utc, artifact_id, event_type
    (plus any rule-specific extracted fields). The runtime maps these to
    finding evidence references.
  - Use LIKE / regexp_matches for substring patterns
  - Use ILIKE for case-insensitive substring match (DuckDB-specific)`
}
