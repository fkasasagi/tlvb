"""SRUM (System Resource Usage Monitor) parser — Plaso primary, SrumECmd fallback.

Windows aggregates 60-second resource snapshots into
``%SystemRoot%\\System32\\sru\\SRUDB.dat``. Per-process CPU / network / push
notification counters survive a reboot for ~60 days. Forensic value:
proves program execution + bandwidth attribution even when prefetch is
disabled or has rolled.

Engine selection (Wave 13 / 2026-05-16):

  Primary: Plaso ``psteal.py --parsers esedb/srum``
    SRUDB.dat is an ESE (Extensible Storage Engine) database. Plaso
    parses it via libesedb's pure-C bindings, which work on Linux.
    On SIFT this is the only engine that actually runs.

  Fallback: SrumECmd
    Eric Zimmerman's .NET parser. **Windows-only** because it loads
    ``Managed.Esent`` which is a thin wrapper around Windows-native ESE
    APIs (``Non-Windows platforms not supported`` error on Linux). We
    keep it in the chain so Windows dev boxes still benefit from the
    richer per-table CSV decomposition (NetworkUsages,
    ApplicationResourceUsage, EnergyUsage, …) and SOFTWARE hive
    app-name resolution.

Same policy as prefetch_parser: any NG in the primary path (binary
absent / non-zero exit / no CSV / 0 rows / Python conversion exception)
falls through to the next engine. `parse_results.notes` records which
engine ran and why a fallback was chosen.
"""

from __future__ import annotations

import csv
import datetime
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

ARTIFACT_ID = "srum"
PARSER_VERSION = "srum_parser/2.0.0+plaso-primary"

SRUMECMD_DLL = "/opt/zimmermantools/SrumECmd.dll"
DEFAULT_JSONL_NAME = "srum.jsonl"
PLASO_CSV_NAME     = "srum_plaso.csv"
PLASO_STORAGE_NAME = "srum.plaso"

# SrumECmd emits one CSV per known SRUM table.
_CSV_TABLES = ("NetworkUsages", "ApplicationResourceUsage", "NetworkConnections",
               "EnergyUsage", "PushNotifications", "SrumECmd")


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

    # =========================================================================
    # Primary: Plaso psteal with esedb/srum plugin (Linux-capable)
    # =========================================================================
    plaso_csv = req.output_dir / PLASO_CSV_NAME
    plaso_storage = req.output_dir / PLASO_STORAGE_NAME
    # psteal (Plaso 20240308+) refuses to overwrite an existing -w target
    # with `ERROR: Output file ... already exists` (rc=1). Re-parsing the
    # same case would always trip this. Pre-clean the destination so we
    # always start from a clean slate; the workspace dir is owned by the
    # case so we're not stomping on anything we don't manage.
    if plaso_csv.exists():
        plaso_csv.unlink()
    # psteal writes an intermediate .plaso storage file in addition to the
    # `-w` CSV. Without --storage_file it lands in the CWD as
    # <timestamp>-<source>.plaso and accumulates forever (51 of these piled
    # up at the repo root by 2026-06-14). Pin it inside the case workspace
    # and delete it after the run — we only ever consume the CSV.
    plaso_storage.unlink(missing_ok=True)
    # psteal drops its own gzipped run log in the CWD as
    # psteal-<TIMESTAMP>.log.gz. Unlike the storage file there is no flag to
    # redirect it — only log2timeline registers --logfile, psteal rejects it
    # as an unrecognized argument. So run psteal *inside* the case workspace
    # and let the log land there instead of wherever tlvb was invoked from
    # (7 of these piled up at the repo root on 2026-08-12, one per pytest
    # run). Every path below is absolute so the changed CWD can't
    # reinterpret them.
    psteal_cmd = [
        "psteal.py",
        "--source", str(req.input_path.resolve()),
        "--parsers", "esedb/srum",
        "--storage_file", str(plaso_storage.resolve()),
        "-o", "dynamic",
        "-w", str(plaso_csv.resolve()),
        "-q",
    ]
    # Plaso 20240308+ requires the long form `--output_time_zone`; psort/psteal
    # both dropped the `-z` shorthand.
    case_tz = (req.timezone or "").strip()
    if case_tz and case_tz.upper() != "UTC":
        psteal_cmd += ["--output_time_zone", case_tz]
    cmd_str = " ".join(psteal_cmd)

    rc, stdout, stderr, elapsed = run_command(
        psteal_cmd, timeout=req.timeout_seconds, cwd=req.output_dir)
    plaso_storage.unlink(missing_ok=True)
    plaso_ok = (
        rc == 0 and plaso_csv.is_file()
        and _csv_row_count(plaso_csv) > 0
    )

    plaso_conv_error: str | None = None
    if plaso_ok:
        try:
            row_count = write_unified_events(
                jsonl_path, _convert_plaso(plaso_csv, req),
            )
        except Exception as exc:
            plaso_conv_error = f"{type(exc).__name__}: {exc}"
            if jsonl_path.exists():
                jsonl_path.unlink()
        else:
            return ParseResult(
                artifact_id=ARTIFACT_ID, success=True,
                command=cmd_str, exit_code=rc,
                started_at=started, finished_at=now_iso(),
                duration_seconds=round(elapsed, 3),
                stdout_tail=tail(stdout), stderr_tail=tail(stderr),
                output_csv=str(plaso_csv),
                output_jsonl=str(jsonl_path),
                row_count=row_count,
                parser_version=PARSER_VERSION,
                notes=[
                    "SRUM proves EXECUTION + bandwidth/energy attribution.",
                    "Engine: Plaso psteal (esedb/srum plugin, libesedb via pyesedb).",
                    f"Case TZ propagated to psteal --output_time_zone: {case_tz or 'UTC (default)'}.",
                    "SRUM retains ~60 days of 60-second snapshots; older buckets aggregate up.",
                    "App IDs in payload may be GUID-like — provider name resolution "
                    "requires SOFTWARE hive (Plaso doesn't auto-join; SrumECmd fallback does).",
                ],
            )

    # Primary NG — capture audit string for fallback notes.
    if plaso_conv_error is not None:
        plaso_audit = (
            f"Plaso ran (exit={rc}) and wrote {plaso_csv} with "
            f"{_csv_row_count(plaso_csv)} rows, but Python conversion failed: "
            f"{plaso_conv_error}"
        )
    else:
        plaso_audit = (
            f"Plaso esedb/srum failed: exit={rc}, csv_exists={plaso_csv.is_file()}, "
            f"rows={_csv_row_count(plaso_csv) if plaso_csv.is_file() else 0}"
        )

    # =========================================================================
    # Fallback: SrumECmd (Windows dev boxes only)
    # =========================================================================
    if not pathlib.Path(SRUMECMD_DLL).is_file():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=(
                f"Primary (Plaso esedb/srum) failed and SrumECmd is not installed "
                f"at {SRUMECMD_DLL}. Primary outcome: {plaso_audit}"
            ),
            exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    # SrumECmd: -f SRUDB.dat, optional -r SOFTWARE hive, --csv output_dir
    srum_cmd = [
        "dotnet", SRUMECMD_DLL,
        "-f", str(req.input_path),
        "--csv", str(req.output_dir),
    ]
    software = _sibling_software(req.input_path)
    if software is not None:
        srum_cmd += ["-r", str(software)]
    srum_cmd_str = " ".join(srum_cmd)

    srum_rc, srum_stdout, srum_stderr, srum_elapsed = run_command(
        srum_cmd, timeout=req.timeout_seconds,
    )
    if srum_rc != 0:
        return fail(
            artifact_id=ARTIFACT_ID,
            command=cmd_str + "  // fallback: " + srum_cmd_str,
            started=started,
            error=(
                f"Both engines failed. Primary: {plaso_audit}. "
                f"SrumECmd exit={srum_rc} (Linux not supported is normal)."
            ),
            exit_code=srum_rc,
            stdout_tail=tail(srum_stdout), stderr_tail=tail(srum_stderr),
            parser_version=PARSER_VERSION,
        )

    csv_files = _find_srumecmd_csvs(req.output_dir)
    if not csv_files:
        return fail(
            artifact_id=ARTIFACT_ID,
            command=cmd_str + "  // fallback: " + srum_cmd_str,
            started=started,
            error=(
                f"Both engines failed. Primary: {plaso_audit}. "
                f"SrumECmd ran (exit={srum_rc}) but produced no CSV outputs."
            ),
            exit_code=srum_rc,
            stdout_tail=tail(srum_stdout), stderr_tail=tail(srum_stderr),
            parser_version=PARSER_VERSION,
        )

    try:
        row_count = write_unified_events(
            jsonl_path, _convert_srumecmd(csv_files, req),
        )
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID,
            command=cmd_str + "  // fallback: " + srum_cmd_str,
            started=started,
            error=(
                f"Both engines failed. Primary: {plaso_audit}. "
                f"SrumECmd CSV→JSONL conversion failed: {type(exc).__name__}: {exc}"
            ),
            exit_code=srum_rc,
            stdout_tail=tail(srum_stdout), stderr_tail=tail(srum_stderr),
            parser_version=PARSER_VERSION,
        )

    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=cmd_str + "  // fallback: " + srum_cmd_str,
        exit_code=srum_rc,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(elapsed + srum_elapsed, 3),
        stdout_tail=tail(srum_stdout), stderr_tail=tail(srum_stderr),
        output_csv=str(csv_files[0]),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            "SRUM proves EXECUTION + bandwidth/energy attribution.",
            f"Engine: SrumECmd fallback (primary path: {plaso_audit}).",
            "Tables: " + ", ".join(_CSV_TABLES),
            "Resolved app/provider names via sibling SOFTWARE hive."
            if software else "No sibling SOFTWARE hive — provider names show as GUIDs.",
            "SRUM retains ~60 days of 60-second snapshots; older buckets aggregate up.",
        ],
    )


# ---------------------------------------------------------------------------
# CSV reading helpers
# ---------------------------------------------------------------------------


def _csv_row_count(csv_path: pathlib.Path | None) -> int:
    if csv_path is None or not csv_path.is_file():
        return 0
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            next(reader, None)
            return sum(1 for _ in reader)
    except OSError:
        return 0


def _sibling_software(srudb: pathlib.Path) -> pathlib.Path | None:
    for name in ("SOFTWARE", "Software"):
        candidate = srudb.parent / name
        if candidate.is_file():
            return candidate
    return None


def _find_srumecmd_csvs(output_dir: pathlib.Path) -> list[pathlib.Path]:
    """SrumECmd writes one CSV per table, typically with timestamp prefix."""
    candidates: list[pathlib.Path] = []
    for table in _CSV_TABLES:
        for pat in (f"*_{table}*.csv", f"{table}*.csv"):
            for p in sorted(output_dir.glob(pat)):
                if p.is_file() and p not in candidates:
                    candidates.append(p)
    return candidates


# ---------------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------------


def _convert_plaso(csv_path: pathlib.Path, req: ParseRequest) -> Iterator[dict]:
    """psort '-o dynamic' rows → UnifiedEvent.

    Plaso doesn't decompose SRUM into per-table CSVs the way SrumECmd
    does; every row carries `parser=esedb/srum` and a free-form
    `message` field that contains the metric ("Application: 1", "Bytes
    sent: 12345", etc.) The Tier 1 SQL prefilter / Tier 2 timeline
    treats SRUM events as a single artifact_id; granular per-table
    discrimination requires the SrumECmd fallback path.
    """
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for idx, row in enumerate(reader):
            ts = _plaso_dt_to_iso_utc(row.get("datetime", ""))
            payload = dict(row)
            payload["engine"] = "plaso"
            key = "|".join([
                row.get("timestamp_desc", ""),
                row.get("message", ""),
                ts,
            ])
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit_id(req.case_id, ARTIFACT_ID, idx, key),
                ts_utc=ts,
                event_type="srum",
                computer=None,
                payload=payload,
                parser_version=PARSER_VERSION,
            )


def _plaso_dt_to_iso_utc(dt_str: str) -> str:
    """Plaso dynamic format datetime → ISO-8601 UTC (space-separated, no offset)."""
    dt_str = (dt_str or "").strip()
    if not dt_str:
        return ""
    s = dt_str.replace(" ", "T")
    try:
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        return ""
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.UTC)
    d_utc = d.astimezone(datetime.UTC).replace(tzinfo=None)
    return d_utc.isoformat(sep=" ", timespec="seconds")


def _convert_srumecmd(csv_files: list[pathlib.Path],
                     req: ParseRequest) -> Iterator[dict]:
    """SrumECmd per-table CSVs → UnifiedEvent."""
    global_idx = 0
    for csv_path in csv_files:
        table_name = csv_path.stem.split("_", 1)[-1]
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                ts = (
                    row.get("Timestamp")
                    or row.get("TimeStamp")
                    or row.get("ConnectStartTime")
                    or row.get("EventTimestamp")
                    or ""
                ).strip()
                payload = dict(row)
                payload["engine"] = "srumecmd"
                payload["srum_table"] = table_name
                key = "|".join([
                    table_name,
                    row.get("AppId", "") or row.get("ExeInfo", "")
                    or row.get("BinaryName", ""),
                    ts,
                ])
                yield make_unified_event(
                    case_id=req.case_id,
                    evidence_id=req.evidence_id,
                    artifact_id=ARTIFACT_ID,
                    audit=audit_id(req.case_id, ARTIFACT_ID, global_idx, key),
                    ts_utc=ts,
                    event_type=f"srum_{table_name.lower()}",
                    computer=None,
                    payload=payload,
                    parser_version=PARSER_VERSION,
                )
                global_idx += 1
