"""Windows 10/11 Timeline (Activities Cache) parser — direct SQLite read.

Reads ``ActivitiesCache.db`` (the ConnectedDevicesPlatform user-activity store)
directly with Python's stdlib ``sqlite3`` — no external tool.

We previously shelled out to EZ Tools' WxTCmd, but WxTCmd 2026.5.0 bundles a
``Stub.System.Data.SQLite`` build whose native ``SQLite.Interop.dll`` (exports
renamed to per-build hashed names) is not shippable on SIFT/Linux, so WxTCmd
could not open the DB at all and Review Gate 0 always showed win10timeline as
FAIL. ``ActivitiesCache.db`` is a plain SQLite file, so reading it directly is
both more robust and fully reproducible (no vendored binary, no version skew).

Input is a single ``ActivitiesCache.db``, typically at::

    %LOCALAPPDATA%\\ConnectedDevicesPlatform\\L.<profile>\\ActivitiesCache.db

Forensic value: per-user record of "what application showed what content" in
the Win10/11 Timeline feature (file paths, URLs, durations).

NOTE: Microsoft removed Timeline from Windows 11 22H2 — newer hosts may have an
empty / missing DB. Pre-22H2 still records.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
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

ARTIFACT_ID = "win10timeline"
PARSER_VERSION = "win10timeline_parser/2.0.0+sqlite-direct"

# ActivityType code → human label (subset; unknown codes pass through as int).
_ACTIVITY_TYPE = {
    2: "Notification",
    3: "Mobile/Backup",
    5: "Open",
    6: "InFocus",
    10: "ClipboardCopy",
    11: "ContextResume",
    12: "ContextResume",
    15: "CopyPaste",
    16: "SystemDefined",
}


def _guid(b: Any) -> str | None:
    """16-byte Windows GUID blob → canonical GUID string (little-endian)."""
    if not isinstance(b, (bytes, bytearray)) or len(b) != 16:
        return None
    if bytes(b) == b"\x00" * 16:
        return None
    return str(uuid.UUID(bytes_le=bytes(b)))


def _ts(v: Any) -> str | None:
    """Unix epoch seconds → ISO-8601 UTC; 0 / negative / non-int → None.

    ActivitiesCache stores 'never' / unset timestamps as 0 or large negative
    sentinels (.NET epoch leftovers), which are not real events.
    """
    if not isinstance(v, int) or v <= 0:
        return None
    try:
        return datetime.fromtimestamp(v, tz=UTC).replace(microsecond=0).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _executable(app_id: Any) -> str | None:
    """AppId is a JSON array of ``{application, platform}``; return the first
    non-empty ``application`` (usually the exe path or AUMID)."""
    if not app_id:
        return None
    try:
        arr = json.loads(app_id)
    except (json.JSONDecodeError, TypeError):
        return app_id if isinstance(app_id, str) else None
    if isinstance(arr, list):
        for item in arr:
            if isinstance(item, dict) and item.get("application"):
                return item["application"]
    return None


def _payload(blob: Any) -> Any:
    """Best-effort decode of a Payload/ClipboardPayload blob: JSON if it parses,
    else base64 of the raw bytes so the row is never silently dropped."""
    if blob is None:
        return None
    if isinstance(blob, (bytes, bytearray)):
        raw = bytes(blob)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"_b64": base64.b64encode(raw).decode("ascii")}
    if isinstance(blob, str):
        try:
            return json.loads(blob)
        except json.JSONDecodeError:
            return blob
    return blob


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    t0 = time.monotonic()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / "win10timeline.jsonl"
    cmd_str = f"(python sqlite3 direct read) {req.input_path}"

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )
    if req.input_path.is_dir():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"expected ActivitiesCache.db file, got dir: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    try:
        con = sqlite3.connect(f"file:{req.input_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"cannot open SQLite DB: {exc}", parser_version=PARSER_VERSION,
        )
    con.row_factory = sqlite3.Row

    try:
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "Activity" not in tables:
            # A valid-but-empty / non-timeline DB is empty, not a failure.
            return ParseResult(
                artifact_id=ARTIFACT_ID, success=True, command=cmd_str, exit_code=0,
                started_at=started, finished_at=now_iso(),
                duration_seconds=round(time.monotonic() - t0, 3),
                row_count=0, parser_version=PARSER_VERSION,
                notes=["no Activity table — empty/non-timeline DB, not a failure"],
            )

        def _events() -> Iterator[dict]:
            idx = 0
            for row in con.execute("SELECT * FROM Activity"):
                start = _ts(row["StartTime"])
                ts = start or _ts(row["LastModifiedTime"]) or ""
                atype = row["ActivityType"]
                payload = {
                    "Id": _guid(row["Id"]),
                    "Executable": _executable(row["AppId"]),
                    "ActivityTypeCode": atype,
                    "ActivityType": _ACTIVITY_TYPE.get(atype, atype),
                    "StartTime": start,
                    "EndTime": _ts(row["EndTime"]),
                    "LastModifiedTime": _ts(row["LastModifiedTime"]),
                    "ExpirationTime": _ts(row["ExpirationTime"]),
                    "Tag": row["Tag"],
                    "Group": row["Group"],
                    "Payload": _payload(row["Payload"]),
                    "ClipboardPayload": _payload(row["ClipboardPayload"]),
                }
                audit = audit_id(
                    req.case_id, ARTIFACT_ID, idx, f"{payload['Id']}|{ts}|{idx}")
                idx += 1
                yield make_unified_event(
                    case_id=req.case_id, evidence_id=req.evidence_id,
                    artifact_id=ARTIFACT_ID, audit=audit, ts_utc=ts,
                    event_type="win10timeline", payload=payload,
                    parser_version=PARSER_VERSION,
                )

        row_count = write_unified_events(jsonl_path, _events())
    except sqlite3.Error as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"SQLite read failed: {exc}", parser_version=PARSER_VERSION,
        )
    finally:
        con.close()

    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True, command=cmd_str, exit_code=0,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(time.monotonic() - t0, 3),
        output_jsonl=str(jsonl_path), row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            "Direct stdlib sqlite3 read (no WxTCmd / native lib).",
            "Microsoft removed Timeline from Windows 11 22H2; absent / empty DB "
            "on newer hosts is expected, not anomalous.",
            "Per-user artifact: each user profile has its own ActivitiesCache.db.",
        ],
    )
