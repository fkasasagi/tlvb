"""W3C / IIS log parser (Wave 37) — web server access logs.

Status: skeleton — parses W3C Extended Log File Format (the IIS / Apache
common log format ancestor) directly in Python, no external tool needed.
The format is text with #Fields directive defining columns.

Useful for web-facing attack reconstruction: identify suspicious User-Agent
strings, paths probing for admin pages, source IPs hitting login endpoints,
etc. Tier 1 initial_access agent can correlate these with credential-access
events.

Input: a single .log file (W3C format) or a directory of them.

Reference format:
    #Software: Microsoft Internet Information Services 10.0
    #Version: 1.0
    #Date: 2026-05-21 00:00:00
    #Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem cs-uri-query sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken
    2026-05-21 12:34:56 192.0.2.4 - 10.0.0.5 443 GET /login - 200 0 0 1234 567 89
"""

from __future__ import annotations

import pathlib

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    now_iso,
    write_unified_events,
)

ARTIFACT_ID = "w3c_iis"
PARSER_VERSION = "w3c_iis_parser/0.1.0-skeleton"


def _iter_w3c_logs(root: pathlib.Path):
    """Yield (path, fields, row_values) per data line across all .log files."""
    if root.is_file():
        targets = [root]
    else:
        targets = sorted(root.rglob("*.log"))
    for path in targets:
        fields: list[str] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    if line.startswith("#Fields:"):
                        fields = line[len("#Fields:"):].strip().split()
                        continue
                    if line.startswith("#"):
                        continue
                    if not fields:
                        continue
                    parts = line.split(" ")
                    # Pad shorter lines, truncate longer.
                    if len(parts) < len(fields):
                        parts += [""] * (len(fields) - len(parts))
                    elif len(parts) > len(fields):
                        # Last field absorbs the overflow (often UserAgent
                        # with spaces).
                        parts = parts[:len(fields) - 1] + [" ".join(parts[len(fields) - 1:])]
                    yield path, fields, parts
        except OSError:
            continue


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command="(no command issued)",
            started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    def _iter() -> "Iterator[dict]":
        idx = 0
        for path, fields, parts in _iter_w3c_logs(req.input_path):
            row = dict(zip(fields, parts))
            # W3C date + time → ISO-8601 (UTC, IIS default).
            ts_utc = ""
            d = row.get("date") or row.get("Date")
            t = row.get("time") or row.get("Time")
            if d and t:
                ts_utc = f"{d}T{t}Z"
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit_id(req.case_id, ARTIFACT_ID, idx,
                               f"{path.name}|{idx}|{ts_utc}"),
                ts_utc=ts_utc,
                event_type="w3c_iis_request",
                payload={**row, "log_path": str(path)},
                parser_version=PARSER_VERSION,
            )
            idx += 1

    jsonl_path = req.output_dir / "w3c_iis.jsonl"
    try:
        from typing import Iterator  # noqa: F401
        row_count = write_unified_events(jsonl_path, _iter())
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error=f"convert W3C logs→JSONL: {exc}",
            parser_version=PARSER_VERSION,
        )
    if row_count == 0:
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error="no W3C log records parsed — files missing #Fields header?",
            parser_version=PARSER_VERSION,
        )
    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command="(in-process W3C parser)", exit_code=0,
        started_at=started, finished_at=now_iso(),
        duration_seconds=0.0,
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            "W3C Extended Log Format parsed in-process (no external tool).",
            "If input contains IIS-specific extensions (cs-uri-stem, etc.) "
            "they're preserved verbatim in payload.",
        ],
    )
