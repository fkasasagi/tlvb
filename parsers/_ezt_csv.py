"""Shared helper for EZ Tool parsers that produce a single CSV.

Most P1 EZ Tools (AppCompatCacheParser, MFTECmd, SBECmd, JLECmd, LECmd,
RBCmd, WxTCmd) follow the same shape:

    dotnet <DLL> [-f|-d] <input> --csv <output_dir> --csvf <name>

then a single CSV (or a small set under output_dir) is produced. This
helper centralises:
  - command construction with input mode validation
  - CSV discovery (the tool may prepend its own timestamp prefix)
  - UnifiedEvent JSONL conversion using a per-parser config object

Each P1 parser module reduces to ~50 lines: spec + ``parse(req)`` that
calls :func:`run_simple_ezt`.
"""

from __future__ import annotations

import csv
import dataclasses
import pathlib
from typing import Callable, Iterator

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


@dataclasses.dataclass
class EztSpec:
    """Per-parser configuration for :func:`run_simple_ezt`."""

    artifact_id: str
    parser_version: str
    dll: str
    input_mode: str            # "file" or "dir"
    csv_filename: str          # base name passed to --csvf
    jsonl_filename: str
    # Column from the CSV row used as the UnifiedEvent timestamp. May fall
    # back to alternates if the primary is empty (some tools emit nullable
    # timestamps in different columns depending on input).
    timestamp_columns: list[str]
    event_type: str            # UnifiedEvent.event_type / source_artifact value
    # Optional: extra args to insert before the standard --csv / --csvf flags.
    extra_args: list[str] = dataclasses.field(default_factory=list)
    # Optional: which CSV column carries the host name. Most EZ Tools don't
    # carry one (they parse a single host's hive); leave None.
    computer_column: str | None = None
    # Optional: CSV glob fallback when --csvf doesn't pin the exact name
    # (some tools emit multiple files or prepend timestamps).
    csv_glob_fallbacks: list[str] = dataclasses.field(default_factory=list)
    # Optional: caveat strings appended to ParseResult.notes.
    caveats: list[str] = dataclasses.field(default_factory=list)


def run_simple_ezt(
    spec: EztSpec,
    req: ParseRequest,
    *,
    extra_input_check: Callable[[pathlib.Path], str | None] | None = None,
) -> ParseResult:
    """Generic runner for single-CSV EZ Tools."""
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / spec.jsonl_filename

    if spec.input_mode == "file":
        input_flag = ["-f", str(req.input_path)]
        bad = "input_path does not exist" if not req.input_path.exists() \
              else ("expected file got dir" if req.input_path.is_dir() else None)
    elif spec.input_mode == "dir":
        input_flag = ["-d", str(req.input_path)]
        bad = "input_path does not exist" if not req.input_path.exists() \
              else ("expected dir got file" if not req.input_path.is_dir() else None)
    else:
        raise ValueError(f"unknown input_mode {spec.input_mode!r}")

    cmd = [
        "dotnet", spec.dll,
        *input_flag,
        *spec.extra_args,
        "--csv", str(req.output_dir),
        "--csvf", spec.csv_filename,
    ]
    cmd_str = " ".join(cmd)

    if bad is not None:
        return fail(
            artifact_id=spec.artifact_id, command=cmd_str, started=started,
            error=f"{bad}: {req.input_path}", parser_version=spec.parser_version,
        )
    if extra_input_check is not None:
        msg = extra_input_check(req.input_path)
        if msg:
            return fail(
                artifact_id=spec.artifact_id, command=cmd_str, started=started,
                error=msg, parser_version=spec.parser_version,
            )

    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)
    if rc != 0:
        return fail(
            artifact_id=spec.artifact_id, command=cmd_str, started=started,
            error=f"{spec.artifact_id} exit={rc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=spec.parser_version,
        )

    csv_files = _find_csvs(req.output_dir, spec)
    if not csv_files:
        return fail(
            artifact_id=spec.artifact_id, command=cmd_str, started=started,
            error=f"{spec.artifact_id} produced no CSV outputs",
            exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=spec.parser_version,
        )

    try:
        row_count = write_unified_events(jsonl_path, _convert(csv_files, req, spec))
    except Exception as exc:
        return fail(
            artifact_id=spec.artifact_id, command=cmd_str, started=started,
            error=f"CSV→JSONL conversion failed: {exc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=spec.parser_version,
        )

    return ParseResult(
        artifact_id=spec.artifact_id, success=True,
        command=cmd_str, exit_code=rc,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(elapsed, 3),
        stdout_tail=tail(stdout), stderr_tail=tail(stderr),
        output_csv=str(csv_files[0]),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=spec.parser_version,
        notes=spec.caveats[:],
    )


def _find_csvs(output_dir: pathlib.Path, spec: EztSpec) -> list[pathlib.Path]:
    """Return CSV outputs in deterministic order.

    EZ Tools usually write ``<TIMESTAMP>_<csvf>`` so the exact ``--csvf`` name
    isn't enough; we glob a few candidate patterns. If the spec provides
    explicit fallbacks, those win.
    """
    candidates: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()

    base = pathlib.Path(spec.csv_filename).name
    stem = pathlib.Path(spec.csv_filename).stem  # without .csv

    patterns = [
        spec.csv_filename,                # exact name (rare for EZ Tools)
        f"*_{base}",                       # <TS>_<base>
        f"*_{stem}*.csv",                  # <TS>_<stem>...csv
        f"*{stem}*.csv",                   # any csv containing the stem
    ] + spec.csv_glob_fallbacks

    for pat in patterns:
        for p in sorted(output_dir.glob(pat)):
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            candidates.append(p)

    return candidates


def _convert(
    csv_files: list[pathlib.Path],
    req: ParseRequest,
    spec: EztSpec,
) -> Iterator[dict]:
    global_idx = 0
    for csv_path in csv_files:
        # EZ Tools sometimes write UTF-8 with BOM (utf-8-sig handles both).
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                ts = ""
                for col in spec.timestamp_columns:
                    v = (row.get(col) or "").strip()
                    if v:
                        ts = v
                        break
                computer = None
                if spec.computer_column:
                    computer = (row.get(spec.computer_column) or "").strip() or None
                # audit_id: stable hash of (case, artifact, row_index, key fields)
                key_fields = [
                    spec.artifact_id, ts,
                    row.get("FileName", "") or row.get("Name", "") or row.get("Path", "") or "",
                ]
                audit = audit_id(req.case_id, spec.artifact_id, global_idx, "|".join(key_fields))
                global_idx += 1
                yield make_unified_event(
                    case_id=req.case_id,
                    evidence_id=req.evidence_id,
                    artifact_id=spec.artifact_id,
                    audit=audit,
                    ts_utc=ts,
                    event_type=spec.event_type,
                    computer=computer,
                    payload=dict(row),
                    parser_version=spec.parser_version,
                )
