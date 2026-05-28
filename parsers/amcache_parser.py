"""AmcacheParser parser.

Wraps EZ Tools' ``AmcacheParser`` (1.5.2.0). The tool emits multiple CSVs from
one Amcache.hve hive — typically one each for AssociatedFileEntries,
UnassociatedFileEntries, ProgramEntries, DeviceContainers, DevicePnps, ShortCuts,
and DriveBinaries. We union them all into a single UnifiedEvent JSONL stream,
tagging ``payload.amcache_table`` so Tactic Agents can filter by entry type.

Forensic caveat (delivered with every ParseResult):
  Amcache proves PRESENCE, not EXECUTION. Cross-check Prefetch / EVTX for run.
"""

from __future__ import annotations

import csv
import pathlib
from typing import Iterator

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


ARTIFACT_ID = "amcache"
PARSER_VERSION = "amcache_parser/1.0.0+amcacheparser-1.5.2.0"

DLL = "/opt/zimmermantools/AmcacheParser.dll"
DEFAULT_CSV_PREFIX = "amcache.csv"   # AmcacheParser appends table suffixes
DEFAULT_JSONL_NAME = "amcache.jsonl"

# Per AmcacheParser docs, the timestamp column varies by table:
_TS_COL_BY_TABLE = {
    "AssociatedFileEntries":   "FileKeyLastWriteTimestamp",
    "UnassociatedFileEntries": "FileKeyLastWriteTimestamp",
    "ProgramEntries":          "KeyLastWriteTimestamp",
    "DeviceContainers":        "KeyLastWriteTimestamp",
    "DevicePnps":              "KeyLastWriteTimestamp",
    "DriverBinaries":          "KeyLastWriteTimestamp",
    "DriverPackages":          "KeyLastWriteTimestamp",
    "ShortCuts":               "KeyLastWriteTimestamp",
}


def parse(req: ParseRequest) -> ParseResult:
    """Parse Amcache.hve → CSVs (multi) + UnifiedEvent JSONL.

    ``req.input_path`` must point to an Amcache.hve **file** (not a directory).
    """
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / DEFAULT_JSONL_NAME

    cmd = [
        "dotnet", DLL,
        "-f", str(req.input_path),
        "--csv", str(req.output_dir),
        "--csvf", DEFAULT_CSV_PREFIX,
        "-i",  # include linked Associated entries
    ]
    cmd_str = " ".join(cmd)

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )
    if req.input_path.is_dir():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error="amcache parser expects a file (Amcache.hve), got a directory",
            parser_version=PARSER_VERSION,
        )

    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)
    if rc != 0:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"AmcacheParser exit={rc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    # AmcacheParser writes <timestamp>_amcache.csv_<TableName>.csv into output_dir
    csv_files = sorted(req.output_dir.glob("*_amcache.csv_*.csv"))
    # Fall back to a less-specific glob if naming changes between versions
    if not csv_files:
        csv_files = sorted(req.output_dir.glob("*amcache*.csv"))

    if not csv_files:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error="AmcacheParser produced no CSV outputs",
            exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    try:
        row_count = write_unified_events(jsonl_path, _convert_all(csv_files, req))
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"CSV→JSONL conversion failed: {exc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=cmd_str, exit_code=rc,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(elapsed, 3),
        stdout_tail=tail(stdout), stderr_tail=tail(stderr),
        output_csv=str(csv_files[0]),         # representative; full list in notes
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            "Amcache proves file PRESENCE only; never EXECUTION. Corroborate via Prefetch / EVTX 4688 / Sysmon 1.",
            f"Amcache tables emitted: {', '.join(p.name for p in csv_files)}",
            "FileKeyLastWriteTimestamp is the Amcache key write time, NOT file creation/modification time.",
            "SHA1 column is empty on Win10 builds < 1709.",
        ],
    )


# ---------------------------------------------------------------------------
# CSV → UnifiedEvent (multi-table union)
# ---------------------------------------------------------------------------


def _table_name_from_filename(p: pathlib.Path) -> str:
    """Extract the Amcache table name from AmcacheParser's filename suffix."""
    # e.g. "20260502123456_amcache.csv_AssociatedFileEntries.csv"
    stem = p.stem  # drop .csv
    if "_" in stem:
        return stem.rsplit("_", 1)[-1]
    return stem


def _convert_all(csv_files: list[pathlib.Path], req: ParseRequest) -> Iterator[dict]:
    global_idx = 0
    for csv_path in csv_files:
        table = _table_name_from_filename(csv_path)
        ts_col = _TS_COL_BY_TABLE.get(table, "KeyLastWriteTimestamp")
        with csv_path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                ts = (row.get(ts_col) or "").strip()
                payload = dict(row)
                payload["amcache_table"] = table
                key_for_id = f"{table}|{row.get('FullPath','')}|{row.get('SHA1','')}|{ts}"
                audit = audit_id(req.case_id, ARTIFACT_ID, global_idx, key_for_id)
                global_idx += 1
                yield make_unified_event(
                    case_id=req.case_id,
                    evidence_id=req.evidence_id,
                    artifact_id=ARTIFACT_ID,
                    audit=audit,
                    ts_utc=ts,
                    event_type="amcache",
                    computer=None,  # Amcache hive has no Computer column
                    payload=payload,
                    parser_version=PARSER_VERSION,
                )
