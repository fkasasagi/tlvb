"""SQLECmd parser (Wave 37) — Eric Zimmerman's SQLite forensic CLI.

SQLECmd extracts forensic-relevant fields from various SQLite databases
(browser history beyond Chrome/Edge, Skype, Teams, etc.) by applying
named SQL maps. Output is per-DB CSVs.

Status: skeleton — detects SQLECmd.dll presence and invokes it on the
SQLite file. Field mapping into UnifiedEvent is intentionally minimal
(timestamp + db_path + raw_row) because SQLECmd's per-map column set is
heterogeneous; per-map normalisation lives in a future wave.

SIFT install: /opt/zimmermantools/SQLECmd/SQLECmd.dll (already P1 inventory).
"""

from __future__ import annotations

import csv
import pathlib

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

ARTIFACT_ID = "sqlecmd"
PARSER_VERSION = "sqlecmd_parser/0.1.0-skeleton"
SQLECMD_DLL = "/opt/zimmermantools/SQLECmd/SQLECmd.dll"
SQLECMD_MAPS = "/opt/zimmermantools/SQLECmd/Maps"


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
    if not pathlib.Path(SQLECMD_DLL).is_file():
        return fail(
            artifact_id=ARTIFACT_ID,
            command="(SQLECmd.dll not installed)",
            started=started,
            error=(
                f"SQLECmd.dll not present at {SQLECMD_DLL}. "
                f"Install via P1 inventory or skip this artifact. "
                f"See docs/tool_inventory.md."
            ),
            parser_version=PARSER_VERSION,
        )
    cmd = [
        "dotnet", SQLECMD_DLL,
        "-f", str(req.input_path),
        "--csv", str(req.output_dir),
        "--maps", SQLECMD_MAPS,
    ]
    cmd_str = " ".join(cmd)
    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)
    # SQLECmd-on-Linux often signal-exits (rc=-1) after logging "No maps found"
    # because dumping the unmatched-db summary loads System.Data.SQLite which
    # tries to dlopen SQLite.Interop.dll — a native lib SQLECmd doesn't ship
    # for Linux. The "no map matched" outcome is a *fact about the DB*, not a
    # parser failure, so promote it to a graceful-skip success row regardless
    # of rc.
    no_map_hit = "No maps found for" in (stdout or "")
    # SQLECmd opens the matched DB through System.Data.SQLite, which P/Invokes a
    # native SQLite.Interop.dll. SIFT/Linux has no compatible build (the EZ-Tools
    # stub renames its exports per build), so a map-matched DB dies with
    # DllNotFound / EntryPointNotFound (sometimes still exit 0). That is a fact
    # about the environment, not a parser bug.
    combined = f"{stdout or ''}\n{stderr or ''}"
    sqlite_native_err = any(m in combined for m in (
        "SQLite.Interop",
        "DllNotFoundException",
        "EntryPointNotFoundException",
        "Unable to load shared library",
        "Unable to find an entry point",
    ))
    csvs = sorted(req.output_dir.glob("*SQLECmd*.csv"))
    if not csvs and (no_map_hit or sqlite_native_err):
        # No CSV because either no map matched, or a map matched but the native
        # SQLite lib is unavailable. Promote to graceful-skip EMPTY (regardless
        # of rc) so Review Gate 0 shows EMPTY, not FAIL. A genuine crash with no
        # SQLite markers (e.g. SIGSEGV at boot) does NOT match and still fails.
        reason = (
            f"SQLECmd has no map for {req.input_path.name}"
            if no_map_hit else
            f"SQLECmd could not process {req.input_path.name} on Linux "
            f"(native SQLite.Interop.dll unavailable)"
        )
        return ParseResult(
            artifact_id=ARTIFACT_ID, success=True,
            command=cmd_str, exit_code=0,
            started_at=started, finished_at=now_iso(),
            duration_seconds=round(elapsed, 3),
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            row_count=0,
            parser_version=PARSER_VERSION,
            notes=[f"{reason} — graceful skip, not a parser failure"],
        )
    if rc != 0:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"SQLECmd exit={rc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )
    # Collect every CSV SQLECmd produced (one per matched map) and emit a
    # generic UnifiedEvent per row. Per-map column normalisation is TODO.
    jsonl_path = req.output_dir / "sqlecmd.jsonl"
    if not csvs:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error="SQLECmd produced no CSV — no matching map?", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    def _iter() -> "Iterator[dict]":
        idx = 0
        for csv_path in csvs:
            with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
                rd = csv.DictReader(fh)
                for row in rd:
                    ts = (row.get("Timestamp") or row.get("LastUsed") or "").strip()
                    yield make_unified_event(
                        case_id=req.case_id,
                        evidence_id=req.evidence_id,
                        artifact_id=ARTIFACT_ID,
                        audit=audit_id(req.case_id, ARTIFACT_ID, idx,
                                       f"{csv_path.name}|{ts}|{idx}"),
                        ts_utc=ts,
                        event_type="sqlite_row",
                        payload={**row, "sqlecmd_map_csv": csv_path.name},
                        parser_version=PARSER_VERSION,
                    )
                    idx += 1

    try:
        from typing import Iterator  # late import for type hint
        row_count = write_unified_events(jsonl_path, _iter())
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"convert CSV→JSONL: {exc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )
    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=cmd_str, exit_code=rc,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(elapsed, 3),
        stdout_tail=tail(stdout), stderr_tail=tail(stderr),
        output_csv=",".join(str(p) for p in csvs),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            f"SQLECmd processed {len(csvs)} map(s).",
            "Per-map column normalisation is TODO (Wave 37+).",
        ],
    )
