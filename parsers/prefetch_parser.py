"""Prefetch parser — altpf primary, Plaso fallback (Issue #17 / #27).

Primary: altpf 0.5.1+ (https://github.com/fkasasagi/altpf)
  Linux-native pure-Go parser, PECmd-compatible output schema (LastRun
  + PreviousRun0..6 columns), v17-v31 auto-detect, MAM/LZXPRESS Huffman
  decompression in-process. Single binary, no toolchain. Verified
  100% accuracy on Win10/Win11 corpora vs PECmd.

Fallback: Plaso `psteal.py` (single-step pipeline)
  Only attempted when altpf is missing OR altpf reports a run with
  zero successful files. psteal combines log2timeline + psort in one
  process — no intermediate .plaso storage file to chain through,
  fewer flag-version pitfalls than the two-stage approach (Wave 12
  predecessor stumbled on `psort.py -z` shorthand removal in
  Plaso 20240308+). Plaso's dynamic format gives a LastRun-only view
  (no PreviousRun N), but covers cases where altpf trips on a corner
  case (e.g. truncated MAM payload that Velocidex's pure-Go
  decompressor can't fully unwind).

The fallback path is auditable: parse_results.notes records which
engine actually produced the row + the SHA-256 of the altpf binary
used at primary time.

Forensic note: Prefetch DOES prove execution (unlike Amcache). Server
SKUs disable Prefetch by default — absence on a server is expected,
not suspicious. altpf and PECmd treat MAM-truncated files as partial
records (ParseError field set); Plaso silently drops them.

PECmd (Windows-only .NET) was dropped from the chain in Wave 12 because
it cannot run on Linux (the standard TLVB deploy target). The
binary still ships on dev boxes; it's just no longer in the fallback
ladder for forensic correctness — the orchestrator's behaviour must
not depend on whether a developer happens to have built PECmd.
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import pathlib
import sys
from collections.abc import Iterator

# Wave 20d: altpf occasionally emits very wide columns when a process has
# accumulated a long FilesAccessed list (e.g. svchost.exe service hosting
# scenarios). Python's csv module defaults to 131072 chars per field and
# raises `_csv.Error: field larger than field limit` while we count rows,
# which trips the entire prefetch parse via the orchestrator exception
# path. Raise the cap once at module load.
csv.field_size_limit(sys.maxsize)

from parsers.base import (  # noqa: E402  (import follows the deliberate csv.field_size_limit call)
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

ARTIFACT_ID = "prefetch"
PARSER_VERSION = "prefetch_parser/3.0.0+altpf-primary"

# altpf binary location — installed by docs/QUICKSTART or scripts/setup.sh.
# We deliberately don't fall back to $PATH lookup: the binary path needs to
# be auditable per-case, and /opt/altpf is the SIFT-convention placement.
ALTPF_BIN = "/opt/altpf/altpf"

# Plaso fallback output. psteal writes an intermediate `.plaso` storage file
# in addition to the `-w` CSV; without --storage_file it lands in the CWD as
# <timestamp>-<source>.plaso and never gets cleaned up. We pin it into the
# case workspace and delete it after the run — only the CSV is consumed.
PLASO_CSV_NAME     = "prefetch_plaso.csv"
PLASO_STORAGE_NAME = "prefetch.plaso"

# UnifiedEvent output (case-DB-bound).
DEFAULT_JSONL_NAME = "prefetch.jsonl"


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
    if not req.input_path.is_dir():
        return fail(
            artifact_id=ARTIFACT_ID, command="(no command issued)",
            started=started,
            error=f"expected directory, got file: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    # =========================================================================
    # Primary: altpf
    # =========================================================================
    altpf_present = pathlib.Path(ALTPF_BIN).is_file()
    altpf_sha = _altpf_sha256() if altpf_present else None
    if altpf_present:
        altpf_cmd = [
            ALTPF_BIN,
            "-d", str(req.input_path),
            "-q",                                # suppress stdout text dump
            "--csv", str(req.output_dir),
        ]
        cmd_str = " ".join(altpf_cmd)
        rc, stdout, stderr, elapsed = run_command(altpf_cmd, timeout=req.timeout_seconds)

        # altpf writes CSV with timestamp-prefixed names — locate them.
        altpf_csv      = _find_altpf_csv(req.output_dir, suffix="_altpf_Output.csv")
        altpf_timeline = _find_altpf_csv(req.output_dir, suffix="_altpf_Timeline_Output.csv")
        altpf_runlog   = _find_altpf_csv(req.output_dir, suffix="_altpf_Run.log")

        # altpf success criteria: exit 0 AND main CSV present AND at least
        # one row (header + >=1 data line). An empty result is suspicious
        # given the parser claims 100% on Win10/Win11 corpora — fall
        # through to Plaso for a second opinion.
        altpf_ok = (
            rc == 0 and altpf_csv is not None
            and _csv_row_count(altpf_csv) > 0
        )

        # Conversion error counts as altpf "NG" per the project policy
        # ("altpf でパースをして NG の場合は plaso を使用する"): if any
        # stage of the altpf pipeline (run / CSV emit / row count / CSV→
        # JSONL conversion) fails, we must fall through to psteal — not
        # return fail() immediately. Capture the failure reason in
        # altpf_audit so parse_results.notes records what happened.
        altpf_conv_error: str | None = None
        if altpf_ok:
            try:
                row_count = write_unified_events(
                    jsonl_path, _convert_altpf(altpf_csv, req),
                )
            except Exception as exc:
                altpf_conv_error = f"{type(exc).__name__}: {exc}"
                # Wipe any partial JSONL that may have been written before
                # the exception fired so the Plaso fallback starts clean.
                if jsonl_path.exists():
                    jsonl_path.unlink()
            else:
                return ParseResult(
                    artifact_id=ARTIFACT_ID, success=True,
                    command=cmd_str, exit_code=rc,
                    started_at=started, finished_at=now_iso(),
                    duration_seconds=round(elapsed, 3),
                    stdout_tail=tail(stdout), stderr_tail=tail(stderr),
                    output_csv=str(altpf_csv),
                    output_jsonl=str(jsonl_path),
                    row_count=row_count,
                    parser_version=PARSER_VERSION,
                    notes=[
                        "Prefetch proves EXECUTION (unlike Amcache).",
                        f"Engine: altpf {ALTPF_BIN} (SHA-256={altpf_sha or '?'}).",
                        "PECmd-compatible CSV columns (LastRun + PreviousRun0..6).",
                        f"Timeline CSV: {altpf_timeline or '(none)'}.",
                        f"Run log: {altpf_runlog or '(none)'}.",
                        "Server SKUs disable Prefetch by default — absence on a server is expected.",
                    ],
                )
        # altpf NG (any stage). Record the precise reason for the audit
        # trail and drop through to the Plaso fallback below.
        if altpf_conv_error is not None:
            altpf_audit = (
                f"altpf ran (exit={rc}) and wrote {altpf_csv} with "
                f"{_csv_row_count(altpf_csv)} rows, but Python conversion "
                f"failed: {altpf_conv_error}"
            )
        else:
            altpf_audit = (
                f"altpf failed: exit={rc}, csv={altpf_csv}, "
                f"rows={_csv_row_count(altpf_csv) if altpf_csv else 0}"
            )
    else:
        altpf_audit = (
            f"altpf binary not installed at {ALTPF_BIN} — "
            f"see https://github.com/fkasasagi/altpf/releases"
        )

    # =========================================================================
    # Fallback: Plaso psteal.py (single-step extract + format)
    # =========================================================================
    plaso_csv = req.output_dir / PLASO_CSV_NAME
    plaso_storage = req.output_dir / PLASO_STORAGE_NAME
    # psteal refuses to overwrite an existing -w target (rc=1). Pre-clean
    # the destination so re-parsing the same case doesn't trip this on the
    # fallback path. Same fix as srum_parser.py.
    if plaso_csv.exists():
        plaso_csv.unlink()
    # Pin the intermediate storage into the case workspace (see comment on
    # PLASO_STORAGE_NAME) and pre-clean it so log2timeline doesn't refuse a
    # stale file from a previous run.
    plaso_storage.unlink(missing_ok=True)
    # psteal also drops a gzipped run log (psteal-<TIMESTAMP>.log.gz) in the
    # CWD and offers no flag to redirect it — --logfile exists on
    # log2timeline only. Run it inside the case workspace so the log stays
    # with the case. Same fix as srum_parser.py; paths are absolute so the
    # changed CWD can't reinterpret them.
    psteal_cmd = [
        "psteal.py",
        "--source", str(req.input_path.resolve()),
        "--parsers", "prefetch",
        "--storage_file", str(plaso_storage.resolve()),
        "-o", "dynamic",
        "-w", str(plaso_csv.resolve()),
        "-q",
    ]
    # Plaso 20240308+ requires the long form `--output_time_zone`; the
    # short `-z` alias was removed from psort and psteal carries forward
    # the same long-form contract.
    case_tz = (req.timezone or "").strip()
    if case_tz and case_tz.upper() != "UTC":
        psteal_cmd += ["--output_time_zone", case_tz]
    cmd_str = " ".join(psteal_cmd)

    rc, stdout, stderr, elapsed = run_command(
        psteal_cmd, timeout=req.timeout_seconds, cwd=req.output_dir)
    plaso_storage.unlink(missing_ok=True)
    plaso_ok = rc == 0 and plaso_csv.exists()

    if plaso_ok:
        try:
            row_count = write_unified_events(jsonl_path, _convert_plaso(plaso_csv, req))
        except Exception as exc:
            return fail(
                artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
                error=f"Plaso CSV→JSONL conversion failed: {exc}", exit_code=rc,
                stdout_tail=tail(stdout), stderr_tail=tail(stderr),
                parser_version=PARSER_VERSION,
            )
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
                "Prefetch proves EXECUTION (unlike Amcache).",
                f"Engine: Plaso psteal fallback (altpf path: {altpf_audit}).",
                "LastRun only (Plaso dynamic format doesn't carry PreviousRun N).",
                f"Case TZ propagated to psteal --output_time_zone: {case_tz or 'UTC (default)'}.",
                "Server SKUs disable Prefetch by default — absence on a server is expected.",
            ],
        )

    # =========================================================================
    # Both engines failed — surface the combined diagnosis.
    # =========================================================================
    return fail(
        artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
        error=(
            f"prefetch parse failed in both engines. "
            f"altpf: {altpf_audit}. "
            f"Plaso psteal: exit={rc}, csv_exists={plaso_csv.exists()}"
        ),
        exit_code=rc,
        stdout_tail=tail(stdout),
        stderr_tail=tail(stderr),
        parser_version=PARSER_VERSION,
    )


# ---------------------------------------------------------------------------
# altpf CSV reading helpers
# ---------------------------------------------------------------------------


def _find_altpf_csv(output_dir: pathlib.Path, suffix: str) -> pathlib.Path | None:
    """altpf prefixes outputs with ``YYYYMMDDHHMMSS_`` — locate by suffix."""
    matches = sorted(output_dir.glob(f"*{suffix}"))
    return matches[-1] if matches else None


def _csv_row_count(csv_path: pathlib.Path | None) -> int:
    """Count data rows (excluding header). Returns 0 on missing / unreadable."""
    if csv_path is None or not csv_path.is_file():
        return 0
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            next(reader, None)  # header
            return sum(1 for _ in reader)
    except OSError:
        return 0


def _altpf_sha256() -> str | None:
    """Cached SHA-256 of the deployed altpf binary, for audit notes."""
    p = pathlib.Path(ALTPF_BIN)
    if not p.is_file():
        return None
    try:
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Converters: vendor CSV → UnifiedEvent JSONL
# ---------------------------------------------------------------------------


# altpf CSV columns (v0.5.1+, PECmd-compatible):
#   SourceFile, SourceFilename, SourceCreated, SourceModified, SourceAccessed,
#   ExecutableName, Hash, Size, Version, RunCount,
#   LastRun, PreviousRun0..PreviousRun6,
#   Volume0Name, Volume0Serial, Volume0Created,
#   Volume1Name, Volume1Serial, Volume1Created,
#   Directories, FilesLoaded, ParseError
_ALTPF_PREV_RUN_COLS = [f"PreviousRun{i}" for i in range(7)]


def _convert_altpf(csv_path: pathlib.Path, req: ParseRequest) -> Iterator[dict]:
    """One UnifiedEvent per execution timestamp (LastRun + each PreviousRun).

    altpf gives us 8 distinct timestamps per binary (LastRun + 7 history
    slots), which is forensically richer than Plaso's dynamic output.
    We emit each one as its own row so Tier 1 SQL prefilters can
    reason about per-run TTPs (e.g. "this binary ran 7 times in the
    last 48 hours — burst detection").
    """
    idx = 0
    with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            base_payload = {
                "engine": "altpf",
                "executable": row.get("ExecutableName", ""),
                "hash": row.get("Hash", ""),
                "size_bytes": row.get("Size", ""),
                "prefetch_version": row.get("Version", ""),
                "run_count": row.get("RunCount", ""),
                "volume0_name":  row.get("Volume0Name", ""),
                "volume0_serial": row.get("Volume0Serial", ""),
                "volume0_created": row.get("Volume0Created", ""),
                "volume1_name":  row.get("Volume1Name", ""),
                "volume1_serial": row.get("Volume1Serial", ""),
                "volume1_created": row.get("Volume1Created", ""),
                "directories":  row.get("Directories", ""),
                "files_loaded": row.get("FilesLoaded", ""),
                "source_file":  row.get("SourceFile", ""),
                "source_filename": row.get("SourceFilename", ""),
                "parse_error":  row.get("ParseError", ""),
            }
            exe = row.get("ExecutableName", "") or row.get("SourceFilename", "")

            # LastRun (always emitted, even when blank, so the row count
            # matches the source CSV's row count for cross-checks).
            ts = _altpf_ts(row.get("LastRun", ""))
            payload = dict(base_payload)
            payload["run_kind"] = "last_run"
            key = f"{exe}|last_run|{ts}"
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit_id(req.case_id, ARTIFACT_ID, idx, key),
                ts_utc=ts, event_type="prefetch", computer=None,
                payload=payload,
                parser_version=PARSER_VERSION,
            )
            idx += 1

            # PreviousRun0..6 — emit only when the slot has a value (skip
            # the zero / blank entries Windows leaves for un-used slots).
            for slot, col in enumerate(_ALTPF_PREV_RUN_COLS):
                raw = (row.get(col) or "").strip()
                if not raw:
                    continue
                ts = _altpf_ts(raw)
                if not ts:
                    continue
                payload = dict(base_payload)
                payload["run_kind"] = f"previous_run_{slot}"
                key = f"{exe}|prev_{slot}|{ts}"
                yield make_unified_event(
                    case_id=req.case_id,
                    evidence_id=req.evidence_id,
                    artifact_id=ARTIFACT_ID,
                    audit=audit_id(req.case_id, ARTIFACT_ID, idx, key),
                    ts_utc=ts, event_type="prefetch", computer=None,
                    payload=payload,
                    parser_version=PARSER_VERSION,
                )
                idx += 1


def _altpf_ts(s: str) -> str:
    """altpf default layout is ``2006-01-02 15:04:05`` (UTC, no offset)."""
    s = (s or "").strip()
    if not s:
        return ""
    try:
        d = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ""
    return d.isoformat(sep=" ", timespec="seconds")


# ---------------------------------------------------------------------------
# Plaso fallback converter (kept from previous parser version, unchanged)
# ---------------------------------------------------------------------------


def _convert_plaso(csv_path: pathlib.Path, req: ParseRequest) -> Iterator[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for idx, row in enumerate(reader):
            # psort -o dynamic columns:
            #   datetime,timestamp_desc,source,source_long,message,
            #   parser,display_name,tag
            ts = _dynamic_dt_to_iso_utc(row.get("datetime", ""))
            payload = dict(row)
            payload["engine"] = "plaso"
            key = f"{row.get('source','')}|{row.get('message','')}|{ts}"
            audit = audit_id(req.case_id, ARTIFACT_ID, idx, key)
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit,
                ts_utc=ts,
                event_type="prefetch",
                computer=None,
                payload=payload,
                parser_version=PARSER_VERSION,
            )


def _dynamic_dt_to_iso_utc(dt_str: str) -> str:
    """psort '-o dynamic' datetime cell → ISO-8601 UTC.

    Accepts ISO-8601 with optional offset, falls back to assuming UTC for
    offset-naive inputs (e.g. when psort was run without -o dynamic timezone).
    Returns '' on parse failure so the row persists with ts_utc=NULL
    rather than aborting the entire batch insert.
    """
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
