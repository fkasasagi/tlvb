"""USN Journal ($J) parser via MFTECmd.

Wraps EZ Tools' MFTECmd against the NTFS USN journal ``$J`` file. Where
present in the input, the sibling ``$MFT`` is passed via ``-m`` so MFTECmd
can resolve FileReference numbers → full paths; without it the parser
still runs but ParentPath / FullName columns will only carry FRN values.

Forensic value: per-file change journal with sub-second precision. Catches
rename/delete cycles that ``$MFT`` alone cannot reconstruct (because the
MFT only sees the *final* state).

Issue #24: priority P2 artifact picked first because $J is on disk in
every standard triage collection and MFTECmd is already on SIFT.
"""

from __future__ import annotations

import csv
import pathlib
from collections.abc import Iterator

from parsers._collector_prefix import MFT_RE
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

ARTIFACT_ID = "usn_journal"
PARSER_VERSION = "usn_journal_parser/1.0.0+mftecmd-1.3.0.0"
MFTECMD_DLL = "/opt/zimmermantools/MFTECmd.dll"
DEFAULT_CSV_NAME = "usn_journal.csv"
DEFAULT_JSONL_NAME = "usn_journal.jsonl"

# MFTECmd emits per-update rows. The Update Timestamp column carries the
# authoritative event time for the change record.
_TIMESTAMP_COLUMNS = ["UpdateTimestamp", "Timestamp", "UpdateTime"]


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / DEFAULT_JSONL_NAME

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command="(no command issued)",
            started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )
    if req.input_path.is_dir():
        return fail(
            artifact_id=ARTIFACT_ID, command="(no command issued)",
            started=started,
            error=f"expected $J file, got directory: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    cmd = [
        "dotnet", MFTECMD_DLL,
        "-f", str(req.input_path),
        "--csv", str(req.output_dir),
        "--csvf", DEFAULT_CSV_NAME,
    ]
    # MFTECmd resolves FileReference → path when -m points at the matching
    # $MFT. Look for it next to $J first (the standard Velociraptor /
    # KAPE / Washizukami collectors place them in the same dir).
    mft_companion = _sibling_mft(req.input_path)
    if mft_companion is not None:
        cmd += ["-m", str(mft_companion)]
    cmd_str = " ".join(cmd)

    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)
    if rc != 0:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"MFTECmd exit={rc}",
            exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    csv_files = _find_csvs(req.output_dir)
    if not csv_files:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error="MFTECmd produced no CSV outputs",
            exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    try:
        row_count = write_unified_events(jsonl_path, _convert(csv_files, req))
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
        output_csv=str(csv_files[0]),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            "USN journal captures per-file change events with sub-second precision.",
            ("Resolved FileReference → path via sibling $MFT." if mft_companion
             else "No sibling $MFT detected — ParentPath/FullName carry FRN only."),
            "$J wraps around — older entries may be overwritten by Windows.",
        ],
    )


def _sibling_mft(j_path: pathlib.Path) -> pathlib.Path | None:
    # Wave 15: match prefix-tolerant `[<drive>_]$MFT` so TANAKA / KAPE-NTFS
    # flatten layouts (`C_$MFT` next to `C_$UsnJrnl-$J`) still resolve.
    for p in j_path.parent.iterdir():
        if p.is_file() and MFT_RE.fullmatch(p.name):
            return p
    return None


def _find_csvs(output_dir: pathlib.Path) -> list[pathlib.Path]:
    """MFTECmd prepends a timestamp to the output name; pick the most recent."""
    base = DEFAULT_CSV_NAME
    stem = pathlib.Path(base).stem
    candidates: list[pathlib.Path] = []
    for pat in (base, f"*_{base}", f"*{stem}*.csv"):
        for p in sorted(output_dir.glob(pat)):
            if p.is_file() and p not in candidates:
                candidates.append(p)
    return candidates


def _convert(csv_files: list[pathlib.Path], req: ParseRequest) -> Iterator[dict]:
    global_idx = 0
    for csv_path in csv_files:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                ts = ""
                for col in _TIMESTAMP_COLUMNS:
                    v = (row.get(col) or "").strip()
                    if v:
                        ts = v
                        break
                key = "|".join([
                    row.get("FullName", "")
                    or row.get("Name", "")
                    or row.get("ParentPath", ""),
                    row.get("UpdateReasons", ""),
                    ts,
                ])
                audit = audit_id(req.case_id, ARTIFACT_ID, global_idx, key)
                global_idx += 1
                yield make_unified_event(
                    case_id=req.case_id,
                    evidence_id=req.evidence_id,
                    artifact_id=ARTIFACT_ID,
                    audit=audit,
                    ts_utc=ts,
                    event_type="usn_journal",
                    computer=None,
                    payload=dict(row),
                    parser_version=PARSER_VERSION,
                )
