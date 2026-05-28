"""Hayabusa parser (Sigma-based EVTX threat-hunting CLI).

Hayabusa converts Sigma rules into a fast Rust matcher and emits a CSV /
JSONL of timeline events keyed by rule + MITRE technique. Useful as a
second opinion alongside our Tactic Agents — strong signal for known
TTPs that don't need LLM interpretation.

Issue #24: scoped P2. The tool itself is NOT installed on the standard
SIFT image (see docs/tool_inventory.md), so this parser uses the same
"opt-in fallback" pattern as PECmd in prefetch_parser.py: present →
delegate; absent → fail with a clear install hint instead of crashing
the whole pipeline.

Install procedure on SIFT::

    # As root:
    cd /opt && \\
    curl -L https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-2.x.x-lin-x64-musl-gnu.zip -o /tmp/hayabusa.zip && \\
    unzip /tmp/hayabusa.zip -d /opt/hayabusa && \\
    ln -s /opt/hayabusa/hayabusa-*-lin-x64-musl-gnu /usr/local/bin/hayabusa

The parser picks the first executable in ``HAYABUSA_BIN_CANDIDATES``.
"""

from __future__ import annotations

import csv
import pathlib
import re
import shutil
from typing import Iterator


# Wave 20d-2: Hayabusa CSV emits timestamps as "YYYY-MM-DD HH:MM:SS.ms +00:00"
# with a space before the timezone offset (the format chrono::DateTime uses
# with its default Display impl). DuckDB's timestamp parser only accepts
# "YYYY-MM-DD HH:MM:SS[.US][±HH:MM]" — no space between time and offset —
# and otherwise raises `ConversionException: invalid timestamp field format`
# during _bulk_insert_unified_events, which aborts the WHOLE orchestrator
# run (every other parser's rows in the same batch are lost). Strip the
# space before the offset to produce a DuckDB-compatible value.
_TZ_SPACE = re.compile(r"\s+([+-]\d{2}:?\d{2})$")


def _normalise_hayabusa_ts(ts: str) -> str:
    """Collapse 'YYYY-MM-DD HH:MM:SS.ms +00:00' → 'YYYY-MM-DD HH:MM:SS.ms+00:00'.

    No-ops on already-compact timestamps and on empty/garbage input (the
    caller still passes whatever string Hayabusa produced into payload so
    debugging visibility is preserved).
    """
    return _TZ_SPACE.sub(r"\1", ts) if ts else ts

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


ARTIFACT_ID = "hayabusa"
PARSER_VERSION = "hayabusa_parser/1.0.0+optional"
DEFAULT_CSV_NAME = "hayabusa_timeline.csv"
DEFAULT_JSONL_NAME = "hayabusa.jsonl"

HAYABUSA_BIN_CANDIDATES = (
    "/usr/local/bin/hayabusa",
    "/opt/hayabusa/hayabusa",
)

_INSTALL_HINT = (
    "Hayabusa is not installed on this SIFT instance. Install via the "
    "release zip from github.com/Yamato-Security/hayabusa (see "
    "docs/tool_inventory.md). Symlink to /usr/local/bin/hayabusa once "
    "extracted. Parser skipped — no fallback."
)


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / DEFAULT_JSONL_NAME
    csv_path = req.output_dir / DEFAULT_CSV_NAME

    binary = _locate_binary()
    if binary is None:
        return fail(
            artifact_id=ARTIFACT_ID, command="(tool not installed)",
            started=started,
            error=_INSTALL_HINT,
            parser_version=PARSER_VERSION,
        )

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command="(no command issued)",
            started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    # csv-timeline subcommand: deterministic CSV output, no interactive prompts.
    # Wave 20d: `--no-wizard` is required when running non-interactively. Without
    # it, Hayabusa v2+ launches a "Scan wizard" dialog that reads from stdin, and
    # panics on non-TTY with `IO(NotConnected) "not a terminal"` (subprocess
    # pipe). `--no-color`/`--quiet` suppress decoration only, they do not skip
    # the wizard.
    cmd = [
        binary, "csv-timeline",
        "-d" if req.input_path.is_dir() else "-f", str(req.input_path),
        "-o", str(csv_path),
        "--no-wizard",
        "--no-color", "--quiet", "--quiet-errors", "--UTC",
    ]
    cmd_str = " ".join(cmd)

    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)
    if rc != 0 or not csv_path.is_file():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"Hayabusa exit={rc} (csv_exists={csv_path.is_file()})",
            exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    try:
        row_count = write_unified_events(jsonl_path, _convert(csv_path, req))
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
        output_csv=str(csv_path),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            f"Engine: Hayabusa via {binary}.",
            "Rules: built-in Sigma set (Yamato Security distribution).",
            "Per-rule MITRE ATT&CK tags surfaced in payload.MitreTactics / payload.MitreTags.",
        ],
    )


def _locate_binary() -> str | None:
    for path in HAYABUSA_BIN_CANDIDATES:
        if pathlib.Path(path).is_file():
            return path
    found = shutil.which("hayabusa")
    return found


def _convert(csv_path: pathlib.Path, req: ParseRequest) -> Iterator[dict]:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for idx, row in enumerate(reader):
            ts = _normalise_hayabusa_ts(
                (row.get("Timestamp") or row.get("Datetime") or "").strip()
            )
            computer = (row.get("Computer") or row.get("ComputerName") or "").strip() or None
            key = "|".join([
                row.get("RuleTitle", ""),
                row.get("Channel", ""),
                row.get("EventID", ""),
                ts,
            ])
            audit = audit_id(req.case_id, ARTIFACT_ID, idx, key)
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit,
                ts_utc=ts,
                event_type="hayabusa_detection",
                computer=computer,
                payload=dict(row),
                parser_version=PARSER_VERSION,
            )
