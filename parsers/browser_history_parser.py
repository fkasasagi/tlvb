"""Browser History parser — Chrome / Edge (Chromium) and Firefox.

Reads SQLite history databases directly via the stdlib ``sqlite3`` module
in *immutable* mode (URI ``?immutable=1``) — the original file is opened
read-only and never has its journal touched, so it stays bit-identical
on disk.

Why no EZ Tool / SQLECmd: the schemas for Chrome and Firefox are stable
enough that direct SQL is simpler and gives us full control over the
output shape. SQLECmd works too, but its CSVs vary by detected map and
the field naming changes per version.

Forensic value: when the initial-access vector was a malicious URL
(driveby, phishing redirect, watering hole), the browser's history /
visits table is often the only artefact tying the user's click to the
downloaded payload. Pair with Downloads metadata for full chain.

Schemas covered:
  - Chromium ``History`` (Chrome, Edge, Brave, Opera, ...)
      tables: urls, visits, downloads
      ts column: WebKit epoch (microseconds since 1601-01-01 UTC)
  - Firefox ``places.sqlite``
      tables: moz_places, moz_historyvisits, moz_annos
      ts column: PRTime (microseconds since 1970-01-01 UTC)

Caveats (delivered with every ParseResult):
  - The browser typically holds an exclusive lock on the live DB; this
    parser will fail on a *running* host. For forensic copies (offline
    image / collected file) it works fine.
  - Visit counts may not match real-world usage — Chrome has a SQLite
    expiration policy that prunes old entries.
  - Title is set when the page finished loading; pages opened then
    closed before load may have an empty title but a recorded visit.
"""

from __future__ import annotations

import dataclasses
import datetime
import pathlib
import sqlite3
from collections.abc import Iterable
from typing import Any, Iterator

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    now_iso,
    tail,
    write_unified_events,
)


ARTIFACT_ID = "browser_history"
PARSER_VERSION = "browser_history_parser/1.0.0+stdlib-sqlite3"

# WebKit epoch starts 1601-01-01 UTC; seconds offset to unix epoch:
_WEBKIT_TO_UNIX_OFFSET = 11_644_473_600


# ---------------------------------------------------------------------------
# Public entry — file-mode parser (one DB per call).
# ---------------------------------------------------------------------------

def parse(req: ParseRequest) -> ParseResult:
    """Parse a single browser-history SQLite file → UnifiedEvent JSONL.

    ``req.input_path`` must be one of:
      - Chromium ``History``  (no extension, lives under
        ``Users/<u>/AppData/Local/<vendor>/User Data/<profile>/History``)
      - Firefox ``places.sqlite``  (under ``Profiles/<id>/places.sqlite``)

    The browser_kind is auto-detected by filename + a quick schema sniff.
    """
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / f"{ARTIFACT_ID}_{_safe_name(req.input_path)}.jsonl"

    cmd_str = (f"python3 -c 'parsers.browser_history_parser.parse({req.input_path})' "
               f"--output {jsonl_path}")

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )
    if req.input_path.is_dir():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error="browser_history parser expects a file (History or places.sqlite), got a directory",
            parser_version=PARSER_VERSION,
        )

    kind = _detect_browser_kind(req.input_path)
    if kind == "unknown":
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"could not identify browser DB at {req.input_path} "
                  f"(name={req.input_path.name}; expected History or places.sqlite)",
            parser_version=PARSER_VERSION,
        )

    started_at_mono = datetime.datetime.now(datetime.timezone.utc)
    try:
        if kind == "chromium":
            row_count = write_unified_events(
                jsonl_path, _chromium_visits_iter(req, req.input_path))
        elif kind == "firefox":
            row_count = write_unified_events(
                jsonl_path, _firefox_visits_iter(req, req.input_path))
        else:
            raise RuntimeError(f"unhandled browser kind {kind!r}")
    except sqlite3.DatabaseError as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"sqlite read failed: {exc} (DB locked? try forensic copy)",
            parser_version=PARSER_VERSION,
        )
    except Exception as exc:  # noqa: BLE001 — surface anything else as failed
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"parse failed: {exc!r}",
            parser_version=PARSER_VERSION,
        )

    finished_mono = datetime.datetime.now(datetime.timezone.utc)
    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=cmd_str, exit_code=0,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(
            (finished_mono - started_at_mono).total_seconds(), 3),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            f"browser kind = {kind} (auto-detected)",
            "Live DB is exclusively locked by the browser process — this "
            "parser is intended for forensic copies (offline collection).",
            "Chromium prunes history entries on its own schedule; visit "
            "counts may understate real usage.",
            "Title is set only after page load completes; opened-then-closed "
            "URLs may show empty title with a real visit_time.",
        ],
    )


# ---------------------------------------------------------------------------
# Browser detection
# ---------------------------------------------------------------------------

def _detect_browser_kind(p: pathlib.Path) -> str:
    """Return "chromium" / "firefox" / "unknown".

    Decision: filename first (cheap), then a 1-table sniff on the SQLite
    schema as a tie-breaker. We don't trust filename alone because Edge
    sometimes ships a backup as ``History.bak``.
    """
    name = p.name.lower()
    if name == "history" or name.startswith("history."):
        return _sniff(p, expect_table="urls", fallback="chromium")
    if name == "places.sqlite":
        return _sniff(p, expect_table="moz_places", fallback="firefox")
    # Last resort sniff for unusual names (forensic exports get renamed):
    return _sniff(p, expect_table=None, fallback="unknown")


def _sniff(p: pathlib.Path, expect_table: str | None, fallback: str) -> str:
    try:
        conn = _open_ro(p)
    except sqlite3.DatabaseError:
        return "unknown"
    try:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
    finally:
        conn.close()
    if "urls" in tables and "visits" in tables:
        return "chromium"
    if "moz_places" in tables and "moz_historyvisits" in tables:
        return "firefox"
    if expect_table and expect_table in tables:
        return fallback
    return "unknown"


def _open_ro(path: pathlib.Path) -> sqlite3.Connection:
    """Open a SQLite DB strictly read-only and refuse to journal.

    The ``immutable=1`` URI parameter tells SQLite "the file will not be
    modified by anyone while we have it open"; combined with ``mode=ro``
    we get a guarantee that we never write back, which matters for chain
    of custody (the original History file's bytes stay intact).
    """
    uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True, timeout=5.0)


# ---------------------------------------------------------------------------
# Chromium (Chrome / Edge / Brave / Opera): one row per visit.
# ---------------------------------------------------------------------------

# Chromium visit `transition` field encodes how the user got to the URL.
# The low byte is the core type; high bits are qualifiers. See:
#   chromium/src/components/history/core/browser/page_transition_types.h
_CHROMIUM_TRANSITION_CORE = {
    0: "link",            # clicked a link
    1: "typed",           # typed in address bar
    2: "auto_bookmark",   # bookmark / suggestion picked from UI
    3: "auto_subframe",   # iframe loaded automatically
    4: "manual_subframe", # user clicked into an iframe
    5: "generated",       # autocompleted URL from address bar
    6: "auto_toplevel",   # browser-internal e.g. session restore
    7: "form_submit",     # form POST
    8: "reload",          # F5 / reload
    9: "keyword",         # keyword search
    10: "keyword_generated",
}


def _chromium_visits_iter(req: ParseRequest, dbpath: pathlib.Path) -> Iterator[dict]:
    conn = _open_ro(dbpath)
    try:
        # JOIN visits → urls. LEFT JOIN to from_visit so referrer is optional.
        sql = """
            SELECT v.id           AS visit_id,
                   v.visit_time   AS ts_webkit,
                   v.transition   AS transition_raw,
                   v.visit_duration AS visit_duration_us,
                   u.url          AS url,
                   u.title        AS title,
                   u.visit_count  AS visit_count,
                   u.typed_count  AS typed_count,
                   u.hidden       AS hidden,
                   ref.url        AS referrer_url
              FROM visits v
              JOIN urls   u   ON v.url        = u.id
              LEFT JOIN visits vf ON v.from_visit = vf.id
              LEFT JOIN urls   ref ON vf.url     = ref.id
             ORDER BY v.visit_time
        """
        cur = conn.execute(sql)
        cols = [d[0] for d in cur.description]
        for idx, row in enumerate(cur):
            rec = dict(zip(cols, row))
            ts = _webkit_to_iso(rec.get("ts_webkit"))
            transition_raw = int(rec.get("transition_raw") or 0)
            transition_core = _CHROMIUM_TRANSITION_CORE.get(
                transition_raw & 0xFF, f"unknown({transition_raw & 0xFF})")
            payload: dict[str, Any] = {
                "browser_kind": "chromium",
                "url": rec.get("url"),
                "title": rec.get("title"),
                "visit_id": rec.get("visit_id"),
                "visit_count": rec.get("visit_count"),
                "typed_count": rec.get("typed_count"),
                "transition": transition_core,
                "transition_raw": transition_raw,
                "visit_duration_seconds": _us_to_s(rec.get("visit_duration_us")),
                "referrer_url": rec.get("referrer_url"),
                "hidden": bool(rec.get("hidden") or 0),
                "source_db": str(dbpath),
            }
            audit = audit_id(
                req.case_id, ARTIFACT_ID, idx,
                f"chromium|{rec.get('url')}|{rec.get('visit_id')}|{ts}",
            )
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit,
                ts_utc=ts,
                event_type="browser_visit",
                computer=None,
                payload=payload,
                parser_version=PARSER_VERSION,
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Firefox: places.sqlite — one row per visit.
# ---------------------------------------------------------------------------

# moz_historyvisits.visit_type values (from nsINavHistoryService.idl)
_FIREFOX_VISIT_TYPE = {
    1: "link",            # TRANSITION_LINK
    2: "typed",           # TRANSITION_TYPED
    3: "bookmark",        # TRANSITION_BOOKMARK
    4: "embed",           # TRANSITION_EMBED (image / iframe)
    5: "redirect_permanent",
    6: "redirect_temporary",
    7: "download",
    8: "framed_link",
    9: "reload",
}


def _firefox_visits_iter(req: ParseRequest, dbpath: pathlib.Path) -> Iterator[dict]:
    conn = _open_ro(dbpath)
    try:
        sql = """
            SELECT h.id            AS visit_id,
                   h.visit_date    AS ts_prtime,
                   h.visit_type    AS visit_type,
                   p.url           AS url,
                   p.title         AS title,
                   p.visit_count   AS visit_count,
                   p.frecency      AS frecency,
                   ref.url         AS referrer_url
              FROM moz_historyvisits h
              JOIN moz_places       p   ON h.place_id = p.id
              LEFT JOIN moz_historyvisits hf ON h.from_visit = hf.id
              LEFT JOIN moz_places         ref ON hf.place_id = ref.id
             ORDER BY h.visit_date
        """
        cur = conn.execute(sql)
        cols = [d[0] for d in cur.description]
        for idx, row in enumerate(cur):
            rec = dict(zip(cols, row))
            ts = _prtime_to_iso(rec.get("ts_prtime"))
            visit_type = int(rec.get("visit_type") or 0)
            payload: dict[str, Any] = {
                "browser_kind": "firefox",
                "url": rec.get("url"),
                "title": rec.get("title"),
                "visit_id": rec.get("visit_id"),
                "visit_count": rec.get("visit_count"),
                "frecency": rec.get("frecency"),
                "transition": _FIREFOX_VISIT_TYPE.get(
                    visit_type, f"unknown({visit_type})"),
                "transition_raw": visit_type,
                "referrer_url": rec.get("referrer_url"),
                "source_db": str(dbpath),
            }
            audit = audit_id(
                req.case_id, ARTIFACT_ID, idx,
                f"firefox|{rec.get('url')}|{rec.get('visit_id')}|{ts}",
            )
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit,
                ts_utc=ts,
                event_type="browser_visit",
                computer=None,
                payload=payload,
                parser_version=PARSER_VERSION,
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _webkit_to_iso(us: int | None) -> str:
    """Chromium WebKit epoch (μs since 1601-01-01) → ISO8601 UTC."""
    if not us:
        return ""
    unix_seconds = (us / 1_000_000.0) - _WEBKIT_TO_UNIX_OFFSET
    if unix_seconds <= 0:
        return ""
    try:
        return datetime.datetime.fromtimestamp(
            unix_seconds, tz=datetime.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _prtime_to_iso(us: int | None) -> str:
    """Firefox PRTime (μs since 1970-01-01) → ISO8601 UTC."""
    if not us:
        return ""
    unix_seconds = us / 1_000_000.0
    try:
        return datetime.datetime.fromtimestamp(
            unix_seconds, tz=datetime.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _us_to_s(us: int | None) -> float | None:
    if us is None:
        return None
    try:
        return round(float(us) / 1_000_000.0, 3)
    except (TypeError, ValueError):
        return None


def _safe_name(p: pathlib.Path) -> str:
    """Build a JSONL filename suffix from the input path so multi-profile
    runs don't overwrite each other's output."""
    parts = list(p.parts[-3:])
    s = "_".join(parts).replace("/", "_").replace(" ", "_")
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)
