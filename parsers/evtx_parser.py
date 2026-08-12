"""EvtxECmd parser.

Calls EvtxECmd v1.5.2.0 over a directory of ``*.evtx`` files, then converts
the wide CSV output into UnifiedEvent JSON Lines.

Forensic caveats (delivered with every ParseResult — see valhuntir_analysis.md
§5.3 L1 — and mirrored in config/artifacts.yaml):
  - TimeCreated is UTC at the source, but skewed evtx (wrong host clock)
    needs cross-check against TimeZoneInformation registry value.
  - EventId alone is meaningless; significance is (Provider, EventId, Channel).
  - Maps directory misses → PayloadDataN holds raw values.
"""

from __future__ import annotations

import csv
import pathlib
from collections.abc import Iterator

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    now_iso,
    run_command,
    tail,
    write_unified_events,
)

ARTIFACT_ID = "evtx"
PARSER_VERSION = "evtx_parser/1.0.0+evtxecmd-1.5.2.0"

EVTXECMD_DLL = "/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"
EVTXECMD_MAPS = "/opt/zimmermantools/EvtxeCmd/Maps/"
DEFAULT_CSV_NAME = "evtx.csv"
DEFAULT_JSONL_NAME = "evtx.jsonl"


def parse(req: ParseRequest) -> ParseResult:
    """Parse all *.evtx under req.input_path → CSV + UnifiedEvent JSONL.

    EvtxECmd's ``-d`` walks the directory recursively. We pass ``--csv DIR
    --csvf NAME`` so output ends up at ``output_dir/evtx.csv``.
    """
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = req.output_dir / DEFAULT_CSV_NAME
    jsonl_path = req.output_dir / DEFAULT_JSONL_NAME

    cmd = [
        "dotnet", EVTXECMD_DLL,
        "-d", str(req.input_path),
        "--csv", str(req.output_dir),
        "--csvf", DEFAULT_CSV_NAME,
        "--maps", EVTXECMD_MAPS,
    ]
    cmd_str = " ".join(cmd)

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)

    if rc != 0:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"EvtxECmd exit={rc}",
            exit_code=rc,
            stdout_tail=tail(stdout),
            stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    if not csv_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"EvtxECmd succeeded but CSV not found at {csv_path}",
            exit_code=rc,
            stdout_tail=tail(stdout),
            stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    try:
        row_count = write_unified_events(jsonl_path, _convert(csv_path, req))
    except Exception as exc:  # noqa: BLE001 — surface conversion errors uniformly
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"CSV→JSONL conversion failed: {exc}",
            exit_code=rc,
            stdout_tail=tail(stdout),
            stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    return ParseResult(
        artifact_id=ARTIFACT_ID,
        success=True,
        command=cmd_str,
        exit_code=rc,
        started_at=started,
        finished_at=now_iso(),
        duration_seconds=round(elapsed, 3),
        stdout_tail=tail(stdout),
        stderr_tail=tail(stderr),
        output_csv=str(csv_path),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            "Amcache/Shimcache-style 'presence != execution' caveats do NOT apply to EVTX.",
            "Timestamp is UTC; verify host TZ via Computer + TimeZoneInformation registry value.",
            "Significance requires (Provider, EventId, Channel) — EventId alone is ambiguous.",
        ],
    )


# ---------------------------------------------------------------------------
# CSV → UnifiedEvent
# ---------------------------------------------------------------------------

# EvtxECmd emits these columns (1.5.x). We only project a stable subset; the
# full row is preserved under payload.raw for downstream Tactic Agents.
_PROJECTED_COLUMNS = (
    "TimeCreated", "EventId", "Level", "Provider", "Channel", "Computer",
    "UserId", "MapDescription", "ChunkNumber", "RecordNumber", "EventRecordId",
    "ProcessId", "ThreadId", "PayloadData1", "PayloadData2", "PayloadData3",
    "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo",
    "HiddenRecord", "SourceFile",
)


def _convert(csv_path: pathlib.Path, req: ParseRequest) -> Iterator[dict]:
    """Stream-read CSV and yield UnifiedEvent dicts.

    EvtxECmd CSVs have a header row. We use ``csv.DictReader`` so column
    additions in newer EvtxECmd versions don't break us (extra columns land
    in payload.raw).
    """
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for idx, row in enumerate(reader):
            ts = (row.get("TimeCreated") or "").strip()
            payload = {k: row.get(k, "") for k in _PROJECTED_COLUMNS if k in row}
            payload["raw"] = row  # preserve full row for grounding

            audit = audit_id(
                req.case_id, ARTIFACT_ID, idx,
                f"{ts}|{row.get('EventRecordId','')}|{row.get('SourceFile','')}",
            )
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit,
                ts_utc=_normalise_ts(ts),
                event_type="evtx",
                computer=row.get("Computer") or None,
                payload=payload,
                parser_version=PARSER_VERSION,
            )


def _normalise_ts(ts: str) -> str:
    """EvtxECmd writes UTC timestamps in ``YYYY-MM-DD HH:MM:SS.fffffff``.

    We pass them through verbatim — DuckDB's TIMESTAMP type parses both space
    and 'T' separators. The case_db layer is the canonical normaliser; here
    we just ensure the field is non-empty for sortability.
    """
    return ts or ""
