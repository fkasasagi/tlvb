"""Tier 0 parser orchestrator.

Responsibilities:
  1. Accept evidence input — a .zip collector bundle or a bare directory.
  2. Stage evidence into ``outputs/cases/{case_id}/extractions/`` (read-only
     evidence is never modified — we only ever copy or extract).
  3. Detect which artifact types are present (by filename pattern).
  4. Dispatch to the matching parser module under ``parsers.<id>_parser``.
  5. Persist ``parse_results`` and ``unified_events`` into the case DuckDB.
  6. Append every action to ``outputs/cases/{case_id}/actions.jsonl`` for the
     Examiner Portal Review Gate 0 to render later.

Run from CLI as::

    python3 -m parsers.orchestrator \
        --case-id INC-2026-0001 \
        --evidence-id EV-001 \
        --input /path/to/triage.zip \
        --db outputs/cases.duckdb \
        --workspace outputs/cases/INC-2026-0001

The orchestrator is invoked from Go via subprocess (``findevil parse``).
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import functools
import importlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from typing import Callable

from parsers import _archive
from parsers._collector_prefix import (
    CHROMIUM_HIST_RE,
    MFT_RE,
    NTUSER_RE,
    PLACES_SQLITE_RE,
    USN_J_RE,
    USRCLASS_RE,
)
from parsers.base import ParseRequest, ParseResult


# ---------------------------------------------------------------------------
# Artifact detection
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Detection:
    """A single artifact detection: which parser to call and on what input."""

    artifact_id: str
    parser_module: str          # importable as ``parsers.<id>_parser``
    input_path: pathlib.Path
    input_mode: str             # "file" or "dir"


# Detection rules in priority order. First match wins per (artifact_id, path).
# We deliberately keep this conservative — a Tactic Agent will catch what we
# miss, but a false-positive parse is expensive (timeouts, garbage rows).
_DETECTORS: list[tuple[str, str, str]] = [
    # (artifact_id, glob pattern, expected_mode)
    # The tuple's third field constrains glob hits to the parser's input_mode
    # so a directory accidentally named "SYSTEM" doesn't get fed to the
    # shimcache parser (which expects a hive file).
    # ---- P0 ----
    ("evtx",            "**/*.evtx",                                              "file"),
    ("amcache",         "**/Amcache.hve",                                         "file"),
    # NOTE: prefetch is detected as dir-mode below (in detect()) — altpf takes
    # `-d DIR` and processes every .pf inside in one shot. Issuing one
    # Detection per .pf would invoke altpf 215 times instead of once.
    ("scheduled_tasks", "**/System32/Tasks/**",                                   "any"),
    ("scheduled_tasks", "**/Tasks/**/*.xml",                                      "file"),
    # ---- P1 (file-mode) ----
    # Shimcache lives inside the SYSTEM hive; AppCompatCacheParser takes the hive file directly.
    ("shimcache",       "**/SYSTEM",                                              "file"),
    # NOTE (Wave 15): mft / usn_journal / browser_history detection moved
    # below to a basename-regex pass so we can absorb the `C_$MFT` /
    # `Tanaka_NTUSER.dat` / `Tanaka_Default_History` flatten conventions
    # used by TANAKA / KAPE-NTFS bundled collectors. Glob character classes
    # can only handle single-letter prefixes, and they cannot express
    # variable user-token middles like `<user>_$UsnJrnl-`.
    # SRUM — SRUDB.dat under System32\sru. Parser is graceful-skip when
    # SrumECmd isn't installed (Issue #24).
    ("srum",            "**/sru/SRUDB.dat",                                       "file"),
    ("srum",            "**/SRUDB.dat",                                           "file"),
    # Win10 Timeline — ActivitiesCache.db under each user's CDP profile.
    ("win10timeline",   "**/ConnectedDevicesPlatform/**/ActivitiesCache.db",     "file"),
    # Washizukami-Collector audit log — emitted next to its output. We parse it
    # to surface the SHA-256 hashes Washizukami already computed plus the
    # original (live-host) source paths that get flattened away by the bundle
    # layout. The collected artefacts themselves are picked up by the existing
    # parsers above because Washizukami preserves the source path structure
    # underneath each category subfolder (so **/*.evtx, **/$MFT, etc still hit).
    ("washizukami_audit", "**/collection.log",                                    "file"),
    # ---- P1 (dir-mode pinned to specific subtrees) ----
    ("jumplists",       "**/Microsoft/Windows/Recent",                            "dir"),
    ("recyclebin",      "**/$Recycle.Bin",                                        "dir"),
    # ---- P2-skeleton (Wave 37) — graceful-skip parsers ----
    # Patterns are intentionally specific to avoid Tier 0 false-positive
    # spam (one detection per non-matching artifact would otherwise
    # explode for big triage trees).
    # sqlecmd is no longer a glob-pattern detector — Wave 40B switched to
    # a basename-allowlist matched against SQLECmd's installed map set
    # (see _SQLECMD_MAP_BASENAMES below + the basename loop in detect()).
    # `**/*.sqlite` was matching Firefox places/cookies that SQLECmd has
    # no map for, generating spurious FAIL rows on every TANAKA case.
    ("yara",            "**/triage-yara",                                         "dir"),   # operator-explicit
    ("volatility3",     "**/*.dmp",                                               "file"),
    ("w3c_iis",         "**/W3SVC*/u_ex*.log",                                    "file"),  # IIS default layout
    # bulk_extractor accepts the raw image directly; no detect pattern (operator-triggered).
]

# Registry "system" hive filenames (collectors we have seen always emit these
# plain — no drive-letter or user prefix observed). NTUSER.DAT / UsrClass.DAT
# are matched by the prefix-aware NTUSER_RE / USRCLASS_RE in the basename pass
# below so the TANAKA `Tanaka_NTUSER.dat` flatten style is also picked up.
_REGISTRY_HIVE_NAMES = {
    "SOFTWARE", "SYSTEM", "SECURITY", "SAM", "DEFAULT",
}

# SQLECmd targets DBs by FileName: extracted from the Windows_*.smap maps
# shipped with EZ Tools (as of SQLECmd 1.1.0.0 / 72 Windows maps). Wave 40B
# replaces the old `**/*.sqlite` detector with this allowlist so we only
# invoke SQLECmd on files it actually has a map for — Firefox places.sqlite
# IS in the list, but TANAKA-style collectors flatten path → basename with
# a `Tanaka_<profile>_` prefix, which SQLECmd's exact-FileName match can't
# resolve. Conservative behaviour: detect only when basename matches one of
# these strings *exactly*. A prefix-tolerant pass (with the parser symlinking
# to canonical names before exec) is a documented follow-up.
_SQLECMD_MAP_BASENAMES = frozenset({
    "ActivitiesCache.db", "Antiphishing.db", "Connections.db",
    "EventTranscript.db", "FSIV.db", "Favicons", "History", "IvAppMon.db",
    "Media History", "MediaDb.v1.sqlite", "Network Action Predictor",
    "Notes.db", "Notifications.db", "Phone.db", "RansomwareRecover.db",
    "Shortcuts", "Store.db", "Top Sites", "Web Data", "WebAssistDatabase",
    "Windows-gather.db", "Windows.db", "aggregation.dbx", "cache.db",
    "chp.db", "cloud_graph.db", "collectionsSQLite", "config.db",
    "contacts.db", "Cookies", "cookies.sqlite", "data.db",
    "downloads.sqlite", "es.db", "favicons.sqlite", "filecache.db",
    "formhistory.sqlite", "home.db", "icon.db", "instance.dbx",
    "main.db", "metadata_sqlite_db", "msty.db", "nessusd.db", "notion.db",
    "photos.db", "places.sqlite", "plum.sqlite", "queue.sqlite3",
    "random.db", "random.sqlite", "settings.db", "snapshot.db",
    "sync_config.db", "sync_history.db", "tray-thumbnails.db",
    "wpndatabase.db",
})


def detect(root: pathlib.Path) -> list[Detection]:
    """Return all artifact detections under ``root``.

    Detections are deduplicated. ``evtx`` is detected as a directory (one
    parse run over the whole tree) rather than per-file, to keep the parse
    count bounded — EvtxECmd's ``-d`` already walks recursively.
    """
    out: list[Detection] = []
    seen: set[tuple[str, str]] = set()

    # ---- pattern-mode artifacts (each detector pins its expected mode) ----
    for artifact_id, pattern, expected_mode in _DETECTORS:
        if artifact_id == "evtx":
            continue  # handled below as dir-mode
        for hit in root.glob(pattern):
            if not hit.exists():
                continue
            actual_mode = "dir" if hit.is_dir() else "file"
            if expected_mode != "any" and expected_mode != actual_mode:
                # e.g. a stray directory accidentally named "SYSTEM" should
                # NOT trigger shimcache. Skip silently.
                continue
            key = (artifact_id, str(hit))
            if key in seen:
                continue
            seen.add(key)
            out.append(Detection(
                artifact_id=artifact_id,
                parser_module=f"parsers.{artifact_id}_parser",
                input_path=hit,
                input_mode=actual_mode,
            ))

    # ---- evtx is dir-mode: collect parent dirs that contain *.evtx ----
    evtx_dirs: set[pathlib.Path] = set()
    for evtx in root.rglob("*.evtx"):
        evtx_dirs.add(evtx.parent)
    # Pick highest-level common ancestors so we don't re-walk subdirs.
    minimised = _minimise_dirs(evtx_dirs)
    for d in sorted(minimised):
        out.append(Detection(
            artifact_id="evtx",
            parser_module="parsers.evtx_parser",
            input_path=d,
            input_mode="dir",
        ))
        # Issue #24: Hayabusa runs on the same evtx tree. We only schedule
        # it when the binary is actually installed — otherwise every case
        # on a stock SIFT image would record a "failed_artifact: hayabusa"
        # row. Once installed (see parsers/hayabusa_parser.py) the
        # detection becomes automatic.
        if _hayabusa_present():
            out.append(Detection(
                artifact_id="hayabusa",
                parser_module="parsers.hayabusa_parser",
                input_path=d,
                input_mode="dir",
            ))

    # ---- single rglob pass for everything that needs basename matching ----
    # We walk the tree once and route each file by (a) plain registry hive
    # names (SOFTWARE / SYSTEM / SECURITY / SAM / DEFAULT) and (b) the
    # prefix-tolerant regex set in `_collector_prefix` for NTFS meta files,
    # per-user registry hives, and browser history DBs. Wave 15 changed this
    # from per-artifact glob loops because the TANAKA / KAPE-NTFS bundled
    # collector flattens trees and prepends `<drive>_` / `<user>_` tokens.
    reg_dirs: set[pathlib.Path] = set()
    shellbag_dirs: set[pathlib.Path] = set()
    mft_files: list[pathlib.Path] = []
    usn_files: list[pathlib.Path] = []
    browser_files: list[pathlib.Path] = []
    sqlecmd_files: list[pathlib.Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        name = p.name
        if name in _REGISTRY_HIVE_NAMES:
            reg_dirs.add(p.parent)
        elif NTUSER_RE.fullmatch(name) or USRCLASS_RE.fullmatch(name):
            # per-user hive feeds both registry (RECmd walks the parent dir)
            # and shellbags (SBECmd consumes NTUSER.DAT / UsrClass.DAT in dir).
            reg_dirs.add(p.parent)
            shellbag_dirs.add(p.parent)
        elif MFT_RE.fullmatch(name):
            mft_files.append(p)
        elif USN_J_RE.fullmatch(name):
            usn_files.append(p)
        elif CHROMIUM_HIST_RE.fullmatch(name) or PLACES_SQLITE_RE.fullmatch(name):
            browser_files.append(p)
        if name in _SQLECMD_MAP_BASENAMES:
            sqlecmd_files.append(p)

    for d in sorted(_minimise_dirs(reg_dirs)):
        key = ("registry", str(d))
        if key in seen:
            continue
        seen.add(key)
        out.append(Detection(
            artifact_id="registry",
            parser_module="parsers.registry_parser",
            input_path=d,
            input_mode="dir",
        ))

    for d in sorted(_minimise_dirs(shellbag_dirs)):
        key = ("shellbags", str(d))
        if key in seen:
            continue
        seen.add(key)
        out.append(Detection(
            artifact_id="shellbags",
            parser_module="parsers.shellbags_parser",
            input_path=d,
            input_mode="dir",
        ))

    for p in sorted(mft_files):
        key = ("mft", str(p))
        if key in seen:
            continue
        seen.add(key)
        out.append(Detection(
            artifact_id="mft",
            parser_module="parsers.mft_parser",
            input_path=p,
            input_mode="file",
        ))

    for p in sorted(usn_files):
        key = ("usn_journal", str(p))
        if key in seen:
            continue
        seen.add(key)
        out.append(Detection(
            artifact_id="usn_journal",
            parser_module="parsers.usn_journal_parser",
            input_path=p,
            input_mode="file",
        ))

    for p in sorted(browser_files):
        key = ("browser_history", str(p))
        if key in seen:
            continue
        seen.add(key)
        out.append(Detection(
            artifact_id="browser_history",
            parser_module="parsers.browser_history_parser",
            input_path=p,
            input_mode="file",
        ))

    for p in sorted(sqlecmd_files):
        key = ("sqlecmd", str(p))
        if key in seen:
            continue
        seen.add(key)
        out.append(Detection(
            artifact_id="sqlecmd",
            parser_module="parsers.sqlecmd_parser",
            input_path=p,
            input_mode="file",
        ))

    # ---- lnk: dirs that contain *.lnk files. Most forensic interest sits in
    # %APPDATA%\Microsoft\Windows\Recent, but LNKs from desktop / startup also
    # matter — collect every directory that has at least one .lnk.
    lnk_dirs: set[pathlib.Path] = set()
    for lnk in root.rglob("*.lnk"):
        lnk_dirs.add(lnk.parent)
    for d in sorted(_minimise_dirs(lnk_dirs)):
        key = ("lnk", str(d))
        if key in seen:
            continue
        seen.add(key)
        out.append(Detection(
            artifact_id="lnk",
            parser_module="parsers.lnk_parser",
            input_path=d,
            input_mode="dir",
        ))

    # ---- prefetch: dirs containing *.pf. altpf takes -d DIR and walks the
    # tree in one process call (Issue #27 / Wave 12). Issuing one Detection
    # per .pf would invoke altpf N times. Mirror the lnk/evtx pattern:
    # gather parent dirs, minimise, emit one dir-mode Detection per group.
    pf_dirs: set[pathlib.Path] = set()
    for pf in root.rglob("*.pf"):
        pf_dirs.add(pf.parent)
    for d in sorted(_minimise_dirs(pf_dirs)):
        key = ("prefetch", str(d))
        if key in seen:
            continue
        seen.add(key)
        out.append(Detection(
            artifact_id="prefetch",
            parser_module="parsers.prefetch_parser",
            input_path=d,
            input_mode="dir",
        ))

    return out


@functools.lru_cache(maxsize=1)
def _hayabusa_present() -> bool:
    """Return True iff Hayabusa is reachable on this host (cached per run)."""
    for path in ("/usr/local/bin/hayabusa", "/opt/hayabusa/hayabusa"):
        if pathlib.Path(path).is_file():
            return True
    return bool(shutil.which("hayabusa"))


# ---------------------------------------------------------------------------
# NOT_PRESENT bookkeeping (Wave 15)
# ---------------------------------------------------------------------------

_ARTIFACTS_YAML = (
    pathlib.Path(__file__).resolve().parent.parent / "config" / "artifacts.yaml"
)

# Sentinel that downstream layers (DB writer + UI badge logic) use to
# distinguish "we tried and failed" from "the artefact wasn't in the input".
# Keep the prefix stable — the Web UI matches `command.startsWith(...)`.
NOT_PRESENT_COMMAND_SENTINEL = "(not present in input)"


@functools.lru_cache(maxsize=1)
def implemented_artifact_ids() -> frozenset[str]:
    """Return artifact ids declared in ``config/artifacts.yaml``.

    This is the implementation-side source of truth for "what artefacts
    should we try to parse on every case?". STATUS.md §3 is the human-
    facing tracker; the two must stay in sync (verified by
    ``scripts/verify.sh``).
    """
    import yaml  # local import: keep startup cost off the cold path
    with _ARTIFACTS_YAML.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return frozenset(a["id"] for a in (data.get("artifacts") or []) if "id" in a)


def not_present_results(
    *, detected_ids: set[str], only: list[str] | None = None,
) -> list[ParseResult]:
    """Emit a ParseResult per implemented artefact that the detector didn't find.

    Schema-compatible with regular ParseResults so the existing DB writer
    and audit log can ingest them unchanged. The UI distinguishes the
    NOT_PRESENT state by checking ``command.startswith(...)``.
    """
    if only:
        target = frozenset(only)
    else:
        target = implemented_artifact_ids()
    missing = sorted(target - detected_ids)
    now = now_iso_utc()
    out: list[ParseResult] = []
    for aid in missing:
        out.append(ParseResult(
            artifact_id=aid,
            success=True,  # not_present is not a failure; it's a fact report
            command=NOT_PRESENT_COMMAND_SENTINEL,
            exit_code=None,
            started_at=now,
            finished_at=now,
            duration_seconds=0.0,
            row_count=0,
            parser_version="orchestrator/not-present-sentinel",
            notes=["artifact not present in input — skipped without invoking parser"],
        ))
    return out


def now_iso_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _minimise_dirs(dirs: set[pathlib.Path]) -> set[pathlib.Path]:
    """If A is an ancestor of B, drop B (A's parser will see B during walk)."""
    keep: set[pathlib.Path] = set()
    sorted_dirs = sorted(dirs, key=lambda p: len(p.parts))
    for d in sorted_dirs:
        if any(d.is_relative_to(k) for k in keep):
            continue
        keep.add(d)
    return keep


# ---------------------------------------------------------------------------
# Staging
# ---------------------------------------------------------------------------


def stage_input(
    input_path: pathlib.Path, workspace: pathlib.Path,
) -> pathlib.Path:
    """Place evidence into a stable working dir.

    For zip input: extract under ``workspace/extracted/``.
    For directory input: return the directory unchanged (no copy — the parsers
    only read).

    Falls back to the system ``unzip`` binary when Python's stdlib
    ``zipfile`` rejects a compression method (most commonly Deflate64,
    which PowerShell's ``Compress-Archive`` emits by default and stdlib
    has never implemented). The fallback is read-only on the original
    zip so chain-of-custody is preserved.

    Returns the root that ``detect()`` should walk.
    """
    if input_path.is_dir():
        return input_path
    if input_path.suffix.lower() == ".zip":
        extracted = workspace / "extracted"
        extracted.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(input_path, "r") as zf:
                zf.extractall(extracted)
        except NotImplementedError as e:
            # Python's zipfile only implements stored / deflate / bzip2 /
            # lzma. PowerShell's `Compress-Archive` defaults to Deflate64
            # (method 9) which is widely supported by other tools but not
            # by stdlib — fall back to the system `unzip` binary.
            if not shutil.which("unzip"):
                raise RuntimeError(
                    f"zip uses an unsupported compression method "
                    f"({e}) and the system `unzip` binary isn't available "
                    f"as a fallback. Install unzip: sudo apt install unzip"
                ) from e
            # Wipe the partial extract (extractall may have written some files
            # before hitting the unsupported member).
            for p in extracted.iterdir():
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
            cmd = ["unzip", "-q", "-o", str(input_path), "-d", str(extracted)]
            rc = subprocess.run(cmd, check=False, capture_output=True)
            if rc.returncode != 0:
                raise RuntimeError(
                    f"system unzip failed (rc={rc.returncode}): "
                    f"{rc.stderr.decode('utf-8', 'replace')[:300]}"
                ) from e
        return extracted
    raise ValueError(
        f"unsupported input: {input_path} (must be a directory or a .zip)",
    )


# ---------------------------------------------------------------------------
# Parser dispatch
# ---------------------------------------------------------------------------


def run_parser(det: Detection, req_template: ParseRequest) -> ParseResult:
    """Import the parser module and call its ``parse``."""
    mod = importlib.import_module(det.parser_module)
    fn = getattr(mod, "parse")
    req = dataclasses.replace(req_template, input_path=det.input_path)
    return fn(req)


# ---------------------------------------------------------------------------
# DuckDB persistence
#
# We import duckdb lazily so the orchestrator can also be used in dry-run /
# unit-test contexts without the dependency.
# ---------------------------------------------------------------------------


def persist(
    db_path: pathlib.Path,
    case_id: str,
    evidence_id: str,
    results: list[ParseResult],
) -> dict[str, int]:
    import duckdb  # local import

    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_path))
    try:
        _ensure_schema(con)
        # parse_results has PRIMARY KEY (case_id, artifact_id), so multiple
        # detections of the same artifact_id (e.g., evtx from the staged
        # tree AND evtx unpacked from a nested archive) must be combined
        # into one row. Insert ALL per-detection JSONLs into
        # unified_events though — that's where the data lives.
        events_inserted = 0
        by_artifact: dict[str, list[ParseResult]] = {}
        for r in results:
            by_artifact.setdefault(r.artifact_id, []).append(r)
            if r.success and r.output_jsonl:
                events_inserted += _bulk_insert_unified_events(
                    con, case_id, evidence_id, pathlib.Path(r.output_jsonl),
                )
        for aid, group in by_artifact.items():
            merged = _merge_parse_results(group) if len(group) > 1 else group[0]
            _upsert_parse_result(con, case_id, merged)
        return {"parse_results": len(by_artifact), "unified_events": events_inserted}
    finally:
        con.close()


_USER_FROM_PATH = __import__("re").compile(r"/users/([^/]+)/", __import__("re").IGNORECASE)


def _hint_from_command(cmd: str) -> str:
    """Pull the most informative slice out of a parser command so notes
    can surface "which user / which input failed" without dumping 200 B
    of dotnet flag soup. Falls back to a leading basename if no /users/
    segment is present (e.g. system-level NTFS meta detections).
    """
    if not cmd:
        return "<no command>"
    m = _USER_FROM_PATH.search(cmd)
    if m:
        return f"user={m.group(1)}"
    # System artefacts (registry SYSTEM hive, $MFT, ...) — show the
    # input path's last 2 segments so it's still recognisable.
    parts = cmd.split()
    for i, p in enumerate(parts):
        if p in ("-f", "-d", "--source", "--input") and i + 1 < len(parts):
            tail = parts[i + 1].rstrip("/").rsplit("/", 2)
            return "/".join(tail[-2:])
    return cmd[:60]


def _merge_parse_results(group: list[ParseResult]) -> ParseResult:
    """Combine N ParseResults for the same artifact_id into one row.

    Wave 18c (partial-success): per-user artefacts (jumplists, shellbags,
    registry, lnk, browser_history) routinely have some users with empty
    Recent dirs / no NTUSER.DAT / no browser profile. The earlier `ok =
    all-succeeded` policy marked the whole merged row FAIL even when 3/6
    users had hundreds of real rows — masking real evidence and confusing
    examiners ("why does jumplists say FAIL when row_count=377?").

    New policy: ``success = any-succeeded`` (partial OK). When the merged
    row would otherwise be flagged FAIL because **a subset** of users had
    no data, we instead mark it OK and keep a per-detection breakdown in
    ``notes`` so the examiner can still see which users contributed and
    which were empty. exit_code is normalised to 0 in the any-success
    case so the UI badge logic (`exit_code===0 && row_count>0`) lands on
    🟢 OK rather than 🔴 FAIL.

    Aggregation: row_count = sum, duration = sum, command = " && ".join,
    started_at = earliest, finished_at = latest, stdout/stderr tails =
    concatenated with separator.
    """
    head = group[0]
    cmds = []
    rc_max = 0
    rows_total = 0
    dur_total = 0.0
    any_ok = False
    all_ok = True
    started = head.started_at
    finished = head.finished_at
    stdout_parts = []
    stderr_parts = []
    notes: list[str] = []
    per_detection: list[str] = []  # human-readable user-by-user summary
    failed_hints: list[str] = []   # short hints for the failed subset
    for r in group:
        cmds.append(r.command)
        if r.exit_code is not None and abs(r.exit_code) > abs(rc_max):
            rc_max = r.exit_code
        if r.row_count is not None:
            rows_total += r.row_count
        dur_total += r.duration_seconds or 0.0
        any_ok = any_ok or r.success
        all_ok = all_ok and r.success
        if r.started_at and (not started or r.started_at < started):
            started = r.started_at
        if r.finished_at and (not finished or r.finished_at > finished):
            finished = r.finished_at
        if r.stdout_tail:
            stdout_parts.append(r.stdout_tail)
        if r.stderr_tail:
            stderr_parts.append(r.stderr_tail)
        if r.notes:
            notes.extend(r.notes)
        # Per-detection breakdown: which user / which input
        hint = _hint_from_command(r.command)
        if r.success:
            per_detection.append(f"  ok    {hint}: rows={r.row_count or 0}")
        else:
            err = (r.error or "no output").splitlines()[0][:120]
            per_detection.append(f"  fail  {hint}: {err}")
            failed_hints.append(hint)

    n_ok = sum(1 for r in group if r.success)
    n_fail = len(group) - n_ok
    notes.append(
        f"merged {len(group)} detections: {n_ok} ok / {n_fail} fail "
        f"(total rows={rows_total})"
    )
    if failed_hints:
        notes.append(
            "failed detections (no parseable output — typically empty "
            "Recent / no per-user hive / artifact absent): "
            + ", ".join(failed_hints)
        )
    notes.append("--- per-detection breakdown ---")
    notes.extend(per_detection)

    # Partial-success policy: any-OK → success/rc=0 so the UI shows 🟢 OK.
    # All-failed → preserve the worst exit_code so the UI shows 🔴 FAIL.
    if any_ok:
        final_success = True
        final_rc = 0
    else:
        final_success = False
        final_rc = rc_max

    return dataclasses.replace(
        head,
        success=final_success,
        command=" && ".join(cmds),
        exit_code=final_rc,
        started_at=started,
        finished_at=finished,
        duration_seconds=round(dur_total, 3),
        stdout_tail="\n---\n".join(stdout_parts) if stdout_parts else "",
        stderr_tail="\n---\n".join(stderr_parts) if stderr_parts else "",
        row_count=rows_total,
        notes=notes,
    )


def _ensure_schema(con) -> None:
    """Mirror internal/casedb/manager.go DDL. DuckDB's IF NOT EXISTS makes
    this safe to run from either side; the Go writer has the same statements.
    """
    con.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id      VARCHAR PRIMARY KEY,
            name         VARCHAR NOT NULL,
            examiner     VARCHAR NOT NULL,
            timezone     VARCHAR NOT NULL DEFAULT 'UTC',
            created_at   TIMESTAMP NOT NULL,
            status       VARCHAR NOT NULL DEFAULT 'active'
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id     VARCHAR PRIMARY KEY,
            case_id         VARCHAR NOT NULL,
            path            VARCHAR NOT NULL,
            sha256          VARCHAR NOT NULL,
            size_bytes      BIGINT  NOT NULL,
            registered_at   TIMESTAMP NOT NULL,
            source_host     VARCHAR,
            evidence_type   VARCHAR
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS parse_results (
            case_id      VARCHAR NOT NULL,
            artifact_id  VARCHAR NOT NULL,
            started_at   TIMESTAMP NOT NULL,
            finished_at  TIMESTAMP,
            command      VARCHAR NOT NULL,
            exit_code    INTEGER,
            stdout_tail  VARCHAR,
            stderr_tail  VARCHAR,
            output_csv   VARCHAR,
            row_count    BIGINT,
            PRIMARY KEY (case_id, artifact_id)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS unified_events (
            case_id       VARCHAR NOT NULL,
            evidence_id   VARCHAR,
            artifact_id   VARCHAR NOT NULL,
            audit_id      VARCHAR NOT NULL,
            ts_utc        TIMESTAMP,
            event_type    VARCHAR NOT NULL,
            computer      VARCHAR,
            payload_json  VARCHAR NOT NULL
        )
    """)


def _upsert_parse_result(con, case_id: str, r: ParseResult) -> None:
    # Wave 18 defence-in-depth: never let an empty-string timestamp reach
    # DuckDB. The dispatch-failure branch above stamps real ISO strings,
    # but a third-party parser could still emit "" by accident. parse_results
    # uses TIMESTAMP NOT NULL for started_at, so an empty value would abort
    # the whole bulk insert (and the actions.jsonl append). Normalise empty
    # strings to a synthetic "now" instead of crashing.
    now = now_iso_utc()
    started = r.started_at if r.started_at else now
    finished = r.finished_at if r.finished_at else None  # finished_at is NULLable
    con.execute(
        "DELETE FROM parse_results WHERE case_id = ? AND artifact_id = ?",
        [case_id, r.artifact_id],
    )
    con.execute(
        """
        INSERT INTO parse_results (
            case_id, artifact_id, started_at, finished_at, command,
            exit_code, stdout_tail, stderr_tail, output_csv, row_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            case_id, r.artifact_id, started, finished, r.command,
            r.exit_code, r.stdout_tail, r.stderr_tail,
            r.output_csv, r.row_count,
        ],
    )


def _bulk_insert_unified_events(
    con, case_id: str, evidence_id: str, jsonl_path: pathlib.Path,
) -> int:
    if not jsonl_path.exists() or jsonl_path.stat().st_size == 0:
        return 0
    # Single vectorised INSERT...SELECT via DuckDB's native newline-delimited
    # JSON reader, rather than per-row executemany — ~150x faster on large
    # artefacts (a 732 MB $MFT dump drops from ~80 min to ~30 s). Only the
    # unified-event envelope fields are typed; `payload` is read as a generic
    # JSON value and re-serialised to text so each artefact's heterogeneous
    # payload schema is preserved verbatim. `timestamp` is TRY_CAST so an
    # unparseable value becomes NULL instead of aborting the whole file, and
    # ignore_errors skips a malformed line rather than failing the parse.
    res = con.execute(
        """
        INSERT INTO unified_events
            (case_id, evidence_id, artifact_id, audit_id, ts_utc,
             event_type, computer, payload_json)
        SELECT ?, ?,
               COALESCE(artifact_id, ''),
               COALESCE(audit_id, ''),
               TRY_CAST(timestamp AS TIMESTAMP),
               COALESCE(event_type, ''),
               computer,
               COALESCE(CAST(payload AS VARCHAR), '{}')
        FROM read_json(?,
                       format='newline_delimited',
                       ignore_errors=true,
                       columns={
                           'artifact_id': 'VARCHAR',
                           'audit_id': 'VARCHAR',
                           'timestamp': 'VARCHAR',
                           'event_type': 'VARCHAR',
                           'computer': 'VARCHAR',
                           'payload': 'JSON',
                       })
        """,
        [case_id, evidence_id, str(jsonl_path)],
    )
    row = res.fetchone()
    return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# Audit log (Examiner Portal Review Gate 0 input)
# ---------------------------------------------------------------------------


def append_actions(
    actions_path: pathlib.Path, case_id: str, results: list[ParseResult],
) -> None:
    actions_path.parent.mkdir(parents=True, exist_ok=True)
    with actions_path.open("a", encoding="utf-8") as fh:
        for r in results:
            if r.command == NOT_PRESENT_COMMAND_SENTINEL:
                # Wave 15: NOT_PRESENT artefacts get a distinct audit kind so
                # downstream consumers (forensic timeline, Examiner reports)
                # can filter or surface them separately from real parse runs.
                entry = {
                    "ts": now_iso_utc(),
                    "case_id": case_id,
                    "actor": "tier0-orchestrator",
                    "kind": "skip",
                    "artifact_id": r.artifact_id,
                    "reason": "not_present_in_input",
                    "parser_version": r.parser_version,
                }
            else:
                entry = {
                    "ts": now_iso_utc(),
                    "case_id": case_id,
                    "actor": "tier0-orchestrator",
                    "kind": "parse",
                    "artifact_id": r.artifact_id,
                    "success": r.success,
                    "exit_code": r.exit_code,
                    "command": r.command,
                    "row_count": r.row_count,
                    "duration_seconds": r.duration_seconds,
                    "error": r.error,
                    "parser_version": r.parser_version,
                }
            fh.write(json.dumps(entry, ensure_ascii=False, default=str))
            fh.write("\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class OrchestratorReport:
    case_id: str
    evidence_id: str
    detections: int
    succeeded: int             # detection-level (UI summary)
    failed: int                # detection-level (UI summary)
    parse_results: list[dict]  # ParseResult dataclasses → dicts for JSON

    # Wave 20d-3: artifact-level counts. After Wave 18c's any-success
    # _merge_parse_results, per-user/per-hive detection failures (e.g. 3 of
    # 6 user dirs have no NTUSER.DAT) collapse into ONE artifact-level row
    # that's OK overall. The detection counts above DON'T reflect that
    # merge, so an examiner sees "9 failed" in stdout while parse_results
    # shows 0 FAIL. Worse, the orchestrator returns exit 2 in that case,
    # which CI treats as a parse failure. These fields capture the
    # post-merge view that _main() should base the exit code on.
    artifact_succeeded: int = 0
    artifact_failed: int = 0


def run(
    *,
    case_id: str,
    evidence_id: str,
    input_path: pathlib.Path,
    db_path: pathlib.Path,
    workspace: pathlib.Path,
    timeout_seconds: int = 600,
    timezone: str = "UTC",
    only: list[str] | None = None,
    progress_emit: "Callable[[dict], None] | None" = None,
    input_mode: str = "auto",
    image_format: str = "auto",
) -> OrchestratorReport:
    """Run the parser orchestrator.

    progress_emit is an optional callable that receives structured progress
    events (dicts) and is responsible for delivering them to whatever
    consumer is interested. The Web UI passes a function that prints
    PROGRESS|<json> lines to stderr; the CLI runs without it.
    """
    def _emit(event: dict) -> None:
        if progress_emit is not None:
            try:
                progress_emit(event)
            except Exception:  # noqa: BLE001
                pass  # progress reporting must never fail the parse

    workspace.mkdir(parents=True, exist_ok=True)

    # Issue #23: input-shape gating.
    # - "image": always run the disk-image extractor (with the operator's
    #   explicit format if provided; else magic-byte detection).
    # - "auto":  run the extractor only when is_image() says yes.
    # - "cdir" / "washizukami": skip the extractor entirely — those layouts
    #   are dir-shaped and will be staged like any directory input.
    from parsers import image_extractor
    should_extract_image = False
    if input_mode == "image":
        if not input_path.is_file():
            raise ValueError(
                f"--input-mode=image requires a file, got: {input_path}")
        should_extract_image = True
    elif input_mode == "auto":
        should_extract_image = (
            input_path.is_file() and image_extractor.is_image(input_path))

    if should_extract_image:
        fmt = image_extractor.detect_image(input_path) or image_format
        if (image_format != "auto" and fmt != image_format
                and not (image_format == "ewf" and fmt == "ewf")):
            # Operator explicitly asked for X, we detected Y — fail loudly
            # rather than silently mounting under the wrong driver.
            raise ValueError(
                f"image format mismatch: --image-format={image_format} "
                f"but magic bytes look like {fmt}")
        _emit({"type": "stage", "phase": "image_extracting", "image_format": fmt})
        try:
            res = image_extractor.extract(
                input_path, workspace, timeout_seconds=timeout_seconds * 3,
            )
            _emit({"type": "stage", "phase": "image_extracted",
                   "summary": res.summary,
                   "extract_log": str(res.extract_log)})
            input_path = res.staging_dir
        except Exception as exc:
            _emit({"type": "stage", "phase": "image_extract_failed",
                   "error": str(exc)})
            raise
    elif input_mode in ("cdir", "washizukami"):
        _emit({"type": "stage", "phase": "input_mode_hint",
               "input_mode": input_mode,
               "note": "skipping image_extractor; existing **/glob detectors "
                       "handle this layout"})

    _emit({"type": "stage", "phase": "extracting"})
    extractions_root = stage_input(input_path, workspace)

    # v0.4 REQ-1: recursively unpack nested archives (.zip / .7z /
    # .tar / .tar.gz / .tar.bz2 / .tar.xz / .gz) so the detector below
    # can see artifacts that collectors bundled inside per-host or
    # per-category sub-archives.
    actions_path = workspace / "actions.jsonl"
    config_path = pathlib.Path(__file__).resolve().parent.parent / "config" / "staging.yaml"

    def _append_action(event: dict) -> None:
        actions_path.parent.mkdir(parents=True, exist_ok=True)
        with actions_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"case_id": case_id, **event},
                                ensure_ascii=False, default=str))
            fh.write("\n")

    _emit({"type": "stage", "phase": "extracting_nested_start"})
    nested_records = _archive.extract_nested_recursively(
        extractions_root,
        workspace=workspace,
        config_path=config_path if config_path.exists() else None,
        progress_emit=progress_emit,
        audit_emit=_append_action,
    )
    _emit({"type": "stage", "phase": "extracting_nested_done",
           "extracted": sum(1 for r in nested_records if r.result == "ok"),
           "skipped":   sum(1 for r in nested_records if r.result != "ok")})

    _emit({"type": "stage", "phase": "detecting"})
    detections = detect(extractions_root)
    # When the input is a read-only directory, extracted archive contents
    # land under workspace/extracted/__nested__/ — which is OUTSIDE
    # extractions_root, so the line above misses them. Sweep the nested
    # tree as a second root and merge the deduplicated detection set.
    nested_root = workspace / "extracted" / "__nested__"
    try:
        nested_under_root = nested_root.is_relative_to(extractions_root)
    except (ValueError, AttributeError):
        nested_under_root = False
    if nested_root.exists() and not nested_under_root:
        seen = {(d.artifact_id, str(d.input_path)) for d in detections}
        for d in detect(nested_root):
            key = (d.artifact_id, str(d.input_path))
            if key not in seen:
                detections.append(d)
                seen.add(key)
    if only:
        detections = [d for d in detections if d.artifact_id in only]

    total = len(detections)
    _emit({"type": "detect_done", "total": total,
           "artifact_ids": [d.artifact_id for d in detections]})

    template = ParseRequest(
        input_path=pathlib.Path("/placeholder"),  # overwritten per-detection
        output_dir=workspace / "extractions",
        case_id=case_id,
        evidence_id=evidence_id,
        timezone=timezone,
        timeout_seconds=timeout_seconds,
    )

    # Count detections per artifact_id up-front so we only suffix the
    # output dir when there's an actual collision risk. This keeps the
    # one-detection-per-artifact case backwards compatible with prior
    # workspace layouts.
    counts: dict[str, int] = {}
    for d in detections:
        counts[d.artifact_id] = counts.get(d.artifact_id, 0) + 1

    results: list[ParseResult] = []
    seen_idx: dict[str, int] = {}
    for i, det in enumerate(detections, start=1):
        _emit({"type": "parse_start", "artifact_id": det.artifact_id,
               "i": i, "of": total})
        # Each artifact gets its own subdir so different detections don't
        # collide on default csv names (e.g. evtx in the staged tree AND
        # evtx unpacked from a nested archive — both legitimate, both
        # produced by the same parser module so they'd overwrite each
        # other's output without the per-detection suffix).
        if counts[det.artifact_id] > 1:
            seen_idx[det.artifact_id] = seen_idx.get(det.artifact_id, 0) + 1
            sub = f"{det.artifact_id}_{seen_idx[det.artifact_id]}"
        else:
            sub = det.artifact_id
        per_artifact_dir = workspace / "extractions" / sub
        per_artifact_dir.mkdir(parents=True, exist_ok=True)
        req_for_det = dataclasses.replace(template, output_dir=per_artifact_dir)
        try:
            r = run_parser(det, req_for_det)
        except Exception as exc:  # noqa: BLE001
            # Wave 18 fix: started_at / finished_at must be valid ISO-8601
            # strings, NOT empty strings. parse_results.started_at is
            # TIMESTAMP NOT NULL in DuckDB, so an empty string raises
            # `invalid timestamp field format: ""` during persist() and
            # *aborts the whole bulk insert*, which in turn skips the
            # actions.jsonl append. The case is then left with a partial
            # parse_results table and no audit trail. Stamp both with the
            # current time so the failure row lands cleanly.
            now = now_iso_utc()
            r = ParseResult(
                artifact_id=det.artifact_id,
                success=False,
                command=f"(import {det.parser_module})",
                exit_code=None,
                started_at=now,
                finished_at=now,
                duration_seconds=0.0,
                error=f"orchestrator dispatch failed: {exc!r}",
                parser_version="",
            )
        results.append(r)
        _emit({"type": "parse_done", "artifact_id": det.artifact_id,
               "i": i, "of": total, "ok": r.success,
               "row_count": r.row_count, "duration_s": r.duration_seconds})

    # Wave 15: emit a NOT_PRESENT row for every implemented artefact that
    # detect() didn't find. This lets Review Gate 0 (Parse Results) show a
    # complete 17-row picture — OK / EMPTY / NOT_PRESENT / FAIL — instead
    # of silently omitting missing artefacts. The `--only` flag scopes the
    # implemented set so a targeted re-run doesn't suddenly flag everything
    # else as missing.
    detected_ids = {d.artifact_id for d in detections}
    np_results = not_present_results(detected_ids=detected_ids, only=only)
    results.extend(np_results)

    # Wave 43: persist (DuckDB bulk_insert_unified_events) can take several
    # minutes for big cases (USN journal ≈ 2 M rows, MFT ≈ 1.5 M rows). Emit
    # explicit phase markers so the Web Status tab doesn't look frozen at
    # "done <last-parser> (N/N)" during ingest. Row counts are estimated
    # from the per-parser ParseResult.row_count so the UI can show an ETA.
    pending_rows = sum(r.row_count or 0 for r in results if r.success)
    _emit({"type": "stage", "phase": "persisting", "rows": pending_rows})
    counts = persist(db_path, case_id, evidence_id, results)
    _emit({"type": "stage", "phase": "persisted",
           "parse_results": counts.get("parse_results", 0),
           "unified_events": counts.get("unified_events", 0)})
    append_actions(workspace / "actions.jsonl", case_id, results)

    succeeded = sum(1 for r in results if r.success)
    failed = len(results) - succeeded

    # Wave 20d-3: re-apply Wave 18c partial-success merge in-memory to get
    # the artifact-level pass/fail view that parse_results actually shows.
    # _main() uses artifact_failed (not detection-level failed) for the
    # exit code so CI doesn't trip on benign per-user "no NTUSER.DAT"
    # cases that the merge has already collapsed into an OK row.
    by_artifact: dict[str, list[ParseResult]] = {}
    for r in results:
        by_artifact.setdefault(r.artifact_id, []).append(r)
    artifact_failed = 0
    for aid, group in by_artifact.items():
        merged = _merge_parse_results(group) if len(group) > 1 else group[0]
        if not merged.success:
            artifact_failed += 1
    artifact_succeeded = len(by_artifact) - artifact_failed

    return OrchestratorReport(
        case_id=case_id,
        evidence_id=evidence_id,
        detections=len(detections),
        succeeded=succeeded,
        failed=failed,
        parse_results=[dataclasses.asdict(r) for r in results],
        artifact_succeeded=artifact_succeeded,
        artifact_failed=artifact_failed,
    )


def _main() -> int:
    p = argparse.ArgumentParser(prog="parsers.orchestrator")
    p.add_argument("--case-id", required=True)
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--input", required=True, help="zip or directory")
    p.add_argument("--db", required=True, help="DuckDB path")
    p.add_argument("--workspace", required=True, help="case workspace dir")
    p.add_argument("--timeout-seconds", type=int, default=600)
    p.add_argument("--timezone", default="UTC")
    p.add_argument("--only", nargs="*", default=None,
                   help="restrict to listed artifact_ids")
    p.add_argument("--report-json", default="-",
                   help="write JSON report here (- = stdout)")
    p.add_argument("--progress", action="store_true",
                   help="emit PROGRESS|<json> lines to stderr around each "
                        "detection / parse step (consumed by the Web UI to "
                        "drive the progress bar)")
    # Issue #23: optional input-shape hints from the Parse modal. When
    # omitted (or "auto") the orchestrator auto-detects.
    p.add_argument("--input-mode", default="auto",
                   choices=("auto", "image", "cdir", "washizukami"),
                   help="explicit input shape (overrides auto-detection)")
    p.add_argument("--image-format", default="auto",
                   choices=("auto", "ewf", "raw", "vmdk", "vhd", "vhdx"),
                   help="force a disk-image format (only valid with --input-mode=image)")
    args = p.parse_args()

    progress_emit: Callable[[dict], None] | None = None
    if args.progress:
        def progress_emit(event: dict) -> None:
            sys.stderr.write("PROGRESS|" + json.dumps(event, ensure_ascii=False) + "\n")
            sys.stderr.flush()

    report = run(
        case_id=args.case_id,
        evidence_id=args.evidence_id,
        input_path=pathlib.Path(args.input),
        db_path=pathlib.Path(args.db),
        workspace=pathlib.Path(args.workspace),
        timeout_seconds=args.timeout_seconds,
        timezone=args.timezone,
        only=args.only,
        progress_emit=progress_emit,
        input_mode=args.input_mode,
        image_format=args.image_format,
    )
    body = json.dumps(dataclasses.asdict(report), ensure_ascii=False, default=str)
    if args.report_json == "-":
        sys.stdout.write(body + "\n")
    else:
        pathlib.Path(args.report_json).write_text(body, encoding="utf-8")
    # Wave 20d-3: exit code is based on the **artifact-level** failure
    # count (post-Wave 18c partial-success merge), NOT the raw
    # per-detection count. Otherwise per-user merges (e.g. 3 of 6 user
    # dirs have no NTUSER.DAT, which the merge collapses into a single
    # OK row) would still drive exit 2 → CI false positive. The stdout
    # summary keeps showing detection counts so the operator can see
    # individual outcomes.
    return 0 if report.artifact_failed == 0 else 2


if __name__ == "__main__":
    sys.exit(_main())
