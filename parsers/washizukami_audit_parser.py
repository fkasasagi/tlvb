"""Washizukami-Collector audit log parser.

Washizukami (https://github.com/tadmaddad/Washizukami-Collector) is a Rust
forensic collector that drops a structured audit log named
``collection.log`` next to its output. Each line records one collection
attempt with its timestamp, status (OK / SKIP / FAIL / TOOL / INFO),
collection method (NTFS / File / tool name), the original source path,
the destination inside the collection bundle, the file size, and a
SHA-256 hash.

This parser ingests that log into the unified_events table so:
  - Tactic Agents can cross-reference every event back to its original
    NTFS source path on the live host (Washizukami flattens artefacts
    under category subfolders, which loses this info otherwise).
  - The SHA-256 hashes Washizukami already computed are exposed as
    evidence-integrity records — the examiner can verify them later
    without re-hashing.
  - Failed / skipped collection attempts surface as visible
    ``negative_findings``-style records, not silent gaps.

Important: this parser does NOT read the collected artefacts themselves
(those are picked up by the existing parsers — evtx_parser, registry_parser,
etc. — because Washizukami preserves the source path structure beneath each
category folder so our recursive ``**/`` globs find them).

The Washizukami project's structure is documented at:
https://github.com/tadmaddad/Washizukami-Collector#output-structure
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Iterator
from typing import Any

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    now_iso,
    write_unified_events,
)

ARTIFACT_ID = "washizukami_audit"
PARSER_VERSION = "washizukami_audit_parser/1.0.0"

DEFAULT_JSONL_NAME = "washizukami_audit.jsonl"


# Format: [TS] [STATUS] [METHOD] BODY
#   TS:     ISO8601 with timezone offset, e.g. 2026-03-21T10:30:00+0900
#   STATUS: OK / SKIP / FAIL / TOOL / INFO / SCAN / MATCH (8 chars padded)
#   METHOD: NTFS / File / winpmem_x64 / yr / yara / -  (12 chars padded)
#   BODY:   varies by status (see _parse_body)
_LINE_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<status>[^\]]+)\]\s+\[(?P<method>[^\]]+)\]\s+(?P<body>.*)$"
)

# OK body: "<src> -> <dest> (<size> bytes, SHA256: <hash>)"
_OK_RE = re.compile(
    r"^(?P<src>.+?)\s+->\s+(?P<dest>.+?)\s+\((?P<size>\d+)\s+bytes,\s+SHA256:\s+(?P<sha256>[0-9a-fA-F]+)\.*\s*\)\s*$"
)
# SKIP / FAIL body: "<src> — <reason>" (em-dash) — Washizukami uses em-dash but be lenient
_SKIPFAIL_RE = re.compile(
    r"^(?P<src>.+?)\s+(?:—|--|-)\s+(?P<reason>.+)$"
)
# TOOL body: "Starting: <cmd> -> <dest>"
_TOOL_RE = re.compile(r"^Starting:\s+(?P<cmd>.+?)\s+->\s+(?P<dest>.+)$")
# MATCH body: "<src> — <rule_name>"
_MATCH_RE = re.compile(r"^(?P<src>.+?)\s+—\s+(?P<rule>.+)$")


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / DEFAULT_JSONL_NAME

    cmd_str = (f"python3 -c 'parsers.washizukami_audit_parser.parse({req.input_path})' "
               f"--output {jsonl_path}")

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )
    if req.input_path.is_dir():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error="washizukami_audit parser expects a file (collection.log), got a directory",
            parser_version=PARSER_VERSION,
        )

    started_mono = datetime.datetime.now(datetime.UTC)
    try:
        row_count = write_unified_events(jsonl_path, _iter_events(req))
    except Exception as exc:  # noqa: BLE001
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"parse failed: {exc!r}",
            parser_version=PARSER_VERSION,
        )
    finished_mono = datetime.datetime.now(datetime.UTC)

    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=cmd_str, exit_code=0,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(
            (finished_mono - started_mono).total_seconds(), 3),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            "Records Washizukami-Collector's per-file collection metadata "
            "(source path, dest path, method, size, SHA-256).",
            "Status values: OK = collected, SKIP = source missing, "
            "FAIL = collection error, TOOL = external tool launched "
            "(e.g. winpmem), MATCH = YARA scan hit, INFO = summary line.",
            "SHA-256 hashes are computed by Washizukami at collection time. "
            "Examiner can later re-hash the destination file in the bundle "
            "and confirm bit-identical handover.",
            f"source: {req.input_path}",
        ],
    )


def _iter_events(req: ParseRequest) -> Iterator[dict]:
    """Yield one UnifiedEvent per parseable line in collection.log."""
    idx = 0
    with req.input_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            m = _LINE_RE.match(line)
            if not m:
                continue
            ts_raw = m.group("ts").strip()
            status = m.group("status").strip()
            method = m.group("method").strip()
            body = m.group("body").strip()

            ts_iso = _normalise_ts(ts_raw)
            payload: dict[str, Any] = {
                "status": status,
                "method": method,
                "raw_line": line,
                "line_no": line_no,
            }
            payload.update(_parse_body(status, body))

            event_type = _event_type_for_status(status)
            audit = audit_id(
                req.case_id, ARTIFACT_ID, idx,
                f"{ts_iso}|{status}|{payload.get('source_path') or body}",
            )
            idx += 1
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit,
                ts_utc=ts_iso,
                event_type=event_type,
                computer=None,
                payload=payload,
                parser_version=PARSER_VERSION,
            )


def _parse_body(status: str, body: str) -> dict[str, Any]:
    """Decode the body section into structured fields."""
    s = status.upper()
    if s == "OK":
        m = _OK_RE.match(body)
        if m:
            return {
                "source_path": m.group("src"),
                "dest_path": m.group("dest"),
                "size_bytes": int(m.group("size")),
                "sha256": m.group("sha256").lower(),
            }
    elif s in ("SKIP", "FAIL"):
        m = _SKIPFAIL_RE.match(body)
        if m:
            return {"source_path": m.group("src"), "reason": m.group("reason")}
    elif s == "TOOL":
        m = _TOOL_RE.match(body)
        if m:
            return {"command": m.group("cmd"), "dest_path": m.group("dest")}
    elif s == "MATCH":
        m = _MATCH_RE.match(body)
        if m:
            return {"source_path": m.group("src"), "yara_rule": m.group("rule")}
    elif s == "INFO":
        return {"summary": body}
    return {"unparsed_body": body}


def _event_type_for_status(status: str) -> str:
    """Map Washizukami status to a UnifiedEvent event_type."""
    s = status.upper()
    return {
        "OK":    "evidence_collected",
        "SKIP":  "evidence_skipped",
        "FAIL":  "evidence_failed",
        "TOOL":  "tool_invoked",
        "MATCH": "yara_match",
        "INFO":  "collection_summary",
        "SCAN":  "scan_summary",
    }.get(s, f"washizukami_{s.lower()}")


def _normalise_ts(ts_raw: str) -> str:
    """Convert Washizukami's timestamp (e.g. 2026-03-21T10:30:00+0900) to
    canonical ISO8601 UTC. Falls back to the raw string if parsing fails."""
    # Python's fromisoformat in 3.11+ accepts +0900 (no colon); 3.10 doesn't.
    # Be defensive: insert the colon if missing.
    s = ts_raw.strip()
    if len(s) >= 5 and (s[-5] in "+-") and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.UTC)
        return dt.astimezone(datetime.UTC).isoformat()
    except (ValueError, TypeError):
        return ts_raw
