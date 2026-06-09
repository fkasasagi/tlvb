"""Apache / nginx / Tomcat error & diagnostic log parser (non-NCSA).

Access logs for all three servers are NCSA Common/Combined and are handled by
``w3c_iis_parser`` (content-sniffed → ``artifact_id='w3c_iis'``). THIS parser
handles the DIAGNOSTIC logs, which are each a distinct, non-NCSA text format:

  - Apache  error_log    ``[Sun Jun 08 13:18:17.123456 2026] [core:error] [pid 1:tid 2] [client 192.168.50.1:1234] AH..: msg``
  - nginx   error.log    ``2026/06/08 13:18:17 [error] 12345#0: *1 msg, client: 192.168.50.1, server: ...``
  - Tomcat  catalina.out ``08-Jun-2026 13:18:17.123 SEVERE [main] org.apache... msg``

All normalise to ``artifact_id='web_error'`` with payload fields:
``server_type`` ("apache"|"nginx"|"tomcat"), ``severity``, ``client_ip``,
``message``.

Diagnostic logs capture FAILED attempts (permission denied, file not found,
stack traces) — useful for spotting traversal/SQLi probes that 404'd, segfault
exploitation, and Tomcat exceptions. Timestamps are server-local (no offset),
emitted naive.

Input: a single log file (error_log / error.log / catalina.out) or a directory.
"""

from __future__ import annotations

import datetime
import pathlib
import re
from typing import Iterator

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    now_iso,
    write_unified_events,
)

ARTIFACT_ID = "web_error"
PARSER_VERSION = "web_error_parser/0.1.0"

# Apache: [time] [module:severity] [pid ...] [client IP:port] message
# Apache 2.4 adds the module prefix + pid/tid; 2.2 is [time] [severity] [client IP] msg.
_APACHE_RE = re.compile(
    r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d [\d:.]+ \d{4})\]\s+"
    r"\[(?P<modsev>[^\]]+)\]\s+"
    r"(?:\[pid[^\]]*\]\s+)?"
    r"(?:\[client (?P<client>[^\]]+)\]\s+)?"
    r"(?P<msg>.*)$"
)
# nginx: 2026/06/08 13:18:17 [error] 12345#0: *1 message
_NGINX_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<sev>\w+)\]\s+\d+#\d+:\s+(?P<msg>.*)$"
)
# Tomcat catalina: 08-Jun-2026 13:18:17.123 SEVERE [thread] logger message
_TOMCAT_RE = re.compile(
    r"^(?P<ts>\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<sev>SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST|ERROR|WARN|DEBUG|TRACE)\s+"
    r"(?:\[(?P<thread>[^\]]*)\]\s+)?(?P<msg>.*)$"
)
# nginx embeds the client IP in the message: "..., client: 1.2.3.4, ..."
_NGINX_CLIENT_RE = re.compile(r"client:\s*(?P<ip>[^,]+)")


def _detect_error_format(path: pathlib.Path) -> str | None:
    """Sniff the first non-empty line. Returns 'apache'|'nginx'|'tomcat' or None
    (strict — an unrecognised first line is not an error log we handle)."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for _ in range(50):
                line = fh.readline()
                if line == "":
                    break
                line = line.rstrip("\r\n")
                if not line:
                    continue
                if _APACHE_RE.match(line):
                    return "apache"
                if _NGINX_RE.match(line):
                    return "nginx"
                if _TOMCAT_RE.match(line):
                    return "tomcat"
                return None
    except OSError:
        return None
    return None


def _ts_apache(raw: str) -> str:
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.datetime.strptime(raw, fmt).isoformat()
        except ValueError:
            continue
    return ""


def _ts_nginx(raw: str) -> str:
    try:
        return datetime.datetime.strptime(raw, "%Y/%m/%d %H:%M:%S").isoformat()
    except ValueError:
        return ""


def _ts_tomcat(raw: str) -> str:
    try:
        return datetime.datetime.strptime(raw, "%d-%b-%Y %H:%M:%S.%f").isoformat()
    except ValueError:
        return ""


def _sev_norm(modsev: str) -> str:
    """'core:error' → 'error'; bare 'error' → 'error'."""
    return modsev.split(":")[-1].strip().lower()


def _iter_apache(path: pathlib.Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _APACHE_RE.match(line.rstrip("\r\n"))
            if not m:
                continue
            g = m.groupdict()
            client = g.get("client")
            client = client.rsplit(":", 1)[0] if client else "-"   # drop :port
            yield {
                "server_type": "apache",
                "severity": _sev_norm(g["modsev"]),
                "client_ip": client,
                "message": g["msg"],
                "__ts__": _ts_apache(g["ts"]),
            }


def _iter_nginx(path: pathlib.Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _NGINX_RE.match(line.rstrip("\r\n"))
            if not m:
                continue
            g = m.groupdict()
            cm = _NGINX_CLIENT_RE.search(g["msg"])
            yield {
                "server_type": "nginx",
                "severity": g["sev"].lower(),
                "client_ip": cm.group("ip").strip() if cm else "-",
                "message": g["msg"],
                "__ts__": _ts_nginx(g["ts"]),
            }


def _iter_tomcat(path: pathlib.Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _TOMCAT_RE.match(line.rstrip("\r\n"))
            if not m:
                continue
            g = m.groupdict()
            yield {
                "server_type": "tomcat",
                "severity": g["sev"].lower(),
                "client_ip": "-",
                "message": g["msg"],
                "__ts__": _ts_tomcat(g["ts"]),
            }


def _iter_logs(root: pathlib.Path) -> Iterator[tuple[pathlib.Path, str, dict]]:
    targets = [root] if root.is_file() else sorted(root.rglob("*"))
    iters = {"apache": _iter_apache, "nginx": _iter_nginx, "tomcat": _iter_tomcat}
    for path in targets:
        if not path.is_file():
            continue
        fmt = _detect_error_format(path)
        if fmt is None:
            continue
        try:
            for row in iters[fmt](path):
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

    saw_naive = [False]

    def _iter() -> Iterator[dict]:
        idx = 0
        for path, fmt, row in _iter_logs(req.input_path):
            ts_utc = row.pop("__ts__", "")
            if ts_utc:
                saw_naive[0] = True
            payload = dict(row)
            payload["log_path"] = str(path)
            payload["log_format"] = fmt
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit_id(req.case_id, ARTIFACT_ID, idx,
                               f"{path.name}|{idx}|{ts_utc}"),
                ts_utc=ts_utc,
                event_type="web_error_log",
                computer="",
                payload=payload,
                parser_version=PARSER_VERSION,
            )
            idx += 1

    jsonl_path = req.output_dir / "web_error.jsonl"
    try:
        row_count = write_unified_events(jsonl_path, _iter())
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error=f"convert web error logs→JSONL: {exc}",
            parser_version=PARSER_VERSION,
        )
    if row_count == 0:
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error="no Apache/nginx/Tomcat error-log records parsed — unrecognised format?",
            parser_version=PARSER_VERSION,
        )

    notes = [
        "Apache/nginx/Tomcat diagnostic logs normalised to artifact_id='web_error' "
        "(server_type/severity/client_ip/message).",
    ]
    if saw_naive[0]:
        notes.append("Timestamps are server-LOCAL (no offset) — emitted naive (no Z).")
    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command="(in-process web-error parser)", exit_code=0,
        started_at=started, finished_at=now_iso(),
        duration_seconds=0.0,
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=notes,
    )
