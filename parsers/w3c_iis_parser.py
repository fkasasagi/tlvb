"""W3C / IIS / NCSA web-server access-log parser — web-facing attack recon.

Status: implemented (pure Python, no external tool). Supersedes the 0.1.0
skeleton which only read the W3C #Fields layout and dumped raw columns.

IIS can emit access logs in three on-disk shapes; this parser detects and
normalises all three:

  * **W3C Extended Log File Format** — ``#Fields:``-driven, space-delimited,
    UTC. The IIS default.
  * **IIS native (Microsoft IIS Log File Format)** — fixed comma-delimited
    column order, no header, local time (canonicalised to UTC at parse time
    using the evidence timezone as the source zone).
  * **NCSA Common / Combined** — Apache-style, ``"METHOD URI PROTO"`` quoted
    request, offset-stamped time.

All three are normalised to the SAME payload keys — the canonical **W3C field
names** (``cs-uri-stem``, ``cs-uri-query``, ``c-ip``, ``cs-method``,
``sc-status``, ``cs-User-Agent`` …). This matters because the Sigma
``category: webserver`` rule corpus is written against W3C names, so emitting
W3C names regardless of source format lets one rule match every layout.

Useful for web-facing attack reconstruction: suspicious User-Agent strings,
path-traversal / SQLi / webshell URIs, source IPs probing admin endpoints.
Tier 1A signature rules hit these directly; Tier 1B initial_access correlates
them with credential-access events (w3wp.exe → cmd.exe child processes).

Input: a single ``.log`` file or a directory of them (recursively).
"""

from __future__ import annotations

import datetime
import pathlib
import re
from collections.abc import Iterator

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    naive_local_to_utc_iso,
    now_iso,
    write_unified_events,
)

ARTIFACT_ID = "w3c_iis"
PARSER_VERSION = "w3c_iis_parser/0.2.0"

# IIS native (Microsoft IIS Log File Format) has no header; columns are fixed.
# Order per Microsoft docs (IIS native uses ", " as the field separator).
_IIS_NATIVE_FIELDS = [
    "c-ip", "cs-username", "date", "time", "s-sitename", "s-computername",
    "s-ip", "time-taken", "cs-bytes", "sc-bytes", "sc-status",
    "sc-win32-status", "cs-method", "cs-uri-stem", "cs-uri-query",
]

# NCSA Common: host ident authuser [date] "request" status bytes
# NCSA Combined: ... status bytes "referer" "user-agent"
_NCSA_RE = re.compile(
    r'^(?P<cip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<dt>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def _detect_format(path: pathlib.Path) -> str | None:
    """Sniff the first non-empty lines to pick a layout. Returns one of
    'w3c' | 'iis' | 'ncsa', or None when nothing parseable is seen."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for _ in range(50):
                line = fh.readline()
                if line == "":
                    break
                line = line.rstrip("\r\n")
                if not line:
                    continue
                if line.startswith("#Fields:") or line.startswith("#Software:"):
                    return "w3c"
                if line.startswith("#"):
                    continue
                if _NCSA_RE.match(line):
                    return "ncsa"
                # IIS native: fixed 15 comma-separated columns, ", " delimited.
                if line.count(", ") >= 10 and "," in line:
                    return "iis"
                # A non-comment data line matching NEITHER the NCSA shape NOR the
                # IIS-native column shape, with no W3C #Fields/#Software header
                # seen yet, is not a web log we recognise. Keep scanning (a header
                # may follow after a roll); fall through to None if nothing else
                # matches. This strictness matters because the orchestrator uses
                # this same sniffer to classify EVERY *.log by content — a default
                # "w3c" here would misroute arbitrary logs (setup.log, …) to this
                # parser. The IIS-default `#Software:`/`#Fields:` header keeps real
                # W3C logs reliably detected.
                continue
    except OSError:
        return None
    return None


def _split_uri(stem: str) -> tuple[str, str]:
    """Split a raw request target into (cs-uri-stem, cs-uri-query)."""
    if "?" in stem:
        s, q = stem.split("?", 1)
        return s, q
    return stem, "-"


def _ts_w3c(date: str, t: str) -> str:
    """W3C date+time (UTC) → ISO-8601 with trailing Z. Sub-second preserved."""
    if not date or not t:
        return ""
    return f"{date}T{t}Z"


def _ts_iis_native(date: str, t: str, tz: str) -> str:
    """IIS native MM/DD/YY HH:MM:SS (LOCAL time) → UTC ISO-8601.

    IIS native logs are written in the server's local time with no offset, so
    we canonicalise to UTC by interpreting the wall-clock in the evidence
    timezone (`tz`), keeping the store UTC like every other artifact.
    """
    if not date or not t:
        return ""
    for fmt in ("%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(f"{date} {t}", fmt)
            return naive_local_to_utc_iso(dt, tz)
        except ValueError:
            continue
    return ""


def _ts_ncsa(raw: str) -> str:
    """NCSA '10/Oct/2026:13:55:36 +0000' → UTC ISO-8601 with Z."""
    try:
        dt = datetime.datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ""


def _iter_w3c(path: pathlib.Path, tz: str) -> Iterator[dict]:
    """Yield normalised row dicts from a W3C Extended log. ``#Fields:`` may
    appear multiple times (config change / log roll); re-bind on each.
    W3C time is UTC by spec, so ``tz`` is unused here."""
    fields: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#Fields:"):
                fields = line[len("#Fields:"):].strip().split()
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            parts = line.split(" ")
            if len(parts) < len(fields):
                parts += ["-"] * (len(fields) - len(parts))
            elif len(parts) > len(fields):
                # Overflow (rare; UA with spaces is normally %20-encoded in W3C)
                # folds into the last column.
                parts = parts[:len(fields) - 1] + [" ".join(parts[len(fields) - 1:])]
            row = dict(zip(fields, parts, strict=False))
            row["__ts__"] = _ts_w3c(row.get("date", ""), row.get("time", ""))
            yield row


def _iter_iis_native(path: pathlib.Path, tz: str) -> Iterator[dict]:
    """Yield normalised row dicts from an IIS native log (fixed columns).
    IIS-native time is server-LOCAL; ``tz`` is the source zone used to
    canonicalise to UTC."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n").rstrip(",")
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(", ")]
            if len(parts) < len(_IIS_NATIVE_FIELDS):
                parts += ["-"] * (len(_IIS_NATIVE_FIELDS) - len(parts))
            row = dict(zip(_IIS_NATIVE_FIELDS, parts, strict=False))
            row["__ts__"] = _ts_iis_native(row.get("date", ""), row.get("time", ""), tz)
            yield row


def _iter_ncsa(path: pathlib.Path, tz: str) -> Iterator[dict]:
    """Yield normalised row dicts from an NCSA Common/Combined log.
    NCSA carries an explicit offset, so ``tz`` is unused here."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            m = _NCSA_RE.match(line)
            if not m:
                continue
            g = m.groupdict()
            method, stem, version = "-", "-", "-"
            req = (g.get("req") or "").split()
            if len(req) >= 1:
                method = req[0]
            if len(req) >= 2:
                stem = req[1]
            if len(req) >= 3:
                version = req[2]
            uri_stem, uri_query = _split_uri(stem)
            row = {
                "c-ip": g["cip"],
                "cs-username": g["user"],
                "cs-method": method,
                "cs-uri-stem": uri_stem,
                "cs-uri-query": uri_query,
                "cs-version": version,
                "sc-status": g["status"],
                "sc-bytes": g["bytes"],
                "cs(Referer)": g.get("referer") or "-",
                "cs-User-Agent": g.get("ua") or "-",
                "__ts__": _ts_ncsa(g["dt"]),
            }
            yield row


def _iter_logs(root: pathlib.Path, tz: str) -> Iterator[tuple[pathlib.Path, str, dict]]:
    """Yield (path, log_format, normalised_row) across all .log files."""
    targets = [root] if root.is_file() else sorted(root.rglob("*.log"))
    iterators = {"w3c": _iter_w3c, "iis": _iter_iis_native, "ncsa": _iter_ncsa}
    for path in targets:
        fmt = _detect_format(path)
        if fmt is None:
            continue
        try:
            for row in iterators[fmt](path, tz):
                yield path, fmt, row
        except OSError:
            continue


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

    saw_native = [False]

    def _iter() -> Iterator[dict]:
        idx = 0
        for path, fmt, row in _iter_logs(req.input_path, req.timezone):
            if fmt == "iis":
                saw_native[0] = True
            ts_utc = row.pop("__ts__", "")
            computer = row.get("s-computername") or row.get("s-ip") or ""
            payload = {k: v for k, v in row.items()}
            payload["log_path"] = str(path)
            payload["log_format"] = fmt
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit_id(req.case_id, ARTIFACT_ID, idx,
                               f"{path.name}|{idx}|{ts_utc}"),
                ts_utc=ts_utc,
                event_type="w3c_iis_request",
                computer=computer,
                payload=payload,
                parser_version=PARSER_VERSION,
            )
            idx += 1

    jsonl_path = req.output_dir / "w3c_iis.jsonl"
    try:
        row_count = write_unified_events(jsonl_path, _iter())
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error=f"convert web logs→JSONL: {exc}",
            parser_version=PARSER_VERSION,
        )
    if row_count == 0:
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error="no web-server log records parsed — unrecognised format or "
                  "missing #Fields header?",
            parser_version=PARSER_VERSION,
        )

    notes = [
        "Parsed in-process (no external tool): W3C Extended / IIS native / "
        "NCSA all normalised to canonical W3C field names.",
        "Sigma category:webserver rules match payload keys cs-uri-stem, "
        "cs-uri-query, cs-method, sc-status, cs-User-Agent verbatim.",
    ]
    if saw_native[0]:
        notes.append(
            "IIS native records carry LOCAL time (no offset); converted to UTC "
            f"assuming source timezone='{req.timezone}' (the evidence timezone).")
    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command="(in-process web-log parser)", exit_code=0,
        started_at=started, finished_at=now_iso(),
        duration_seconds=0.0,
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=notes,
    )
