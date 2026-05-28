"""Scheduled Tasks (Win Task Scheduler XML) parser.

Parses XML files under ``%SystemRoot%\\System32\\Tasks`` directly with
``xml.etree.ElementTree`` — no external tool needed (Plaso is available as a
fallback in artifacts.yaml but the structure is simple enough that a direct
parser gives us better control over field extraction).

Extracts:
  - Task name (relative path under Tasks/)
  - Author, Description, RunAs (Principal/UserId)
  - Triggers (Time/Boot/Logon/Daily/Weekly/Calendar/Event/Registration)
  - Actions (Exec command + arguments, ComHandler, SendEmail)
  - Dates (Date/RegistrationInfo/Date)

A task with an Action that runs from %TEMP%, %APPDATA%, or contains
``powershell -enc`` is flagged with tactic_hints for TA0002 (Execution) and
TA0003 (Persistence).
"""

from __future__ import annotations

import pathlib
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterator

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    now_iso,
    write_unified_events,
)


ARTIFACT_ID = "scheduled_tasks"
PARSER_VERSION = "scheduled_tasks_parser/1.0.0"

DEFAULT_JSONL_NAME = "scheduled_tasks.jsonl"

# Microsoft schtasks XML namespace
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

# Suspicious-action heuristics (for tactic_hints)
_SUSPICIOUS_PATH_RX = re.compile(
    r"(\\Users\\[^\\]+\\AppData\\|\\Temp\\|\\Public\\|\\ProgramData\\)", re.I,
)
_SUSPICIOUS_CMD_RX = re.compile(
    r"(powershell.*\-(?:e|ec|enc|encodedcommand)\b|"
    r"-w\s+hidden|"
    r"\bIEX\b|"
    r"\bDownloadString\b|"
    r"mshta\b|"
    r"rundll32\b.*,\s*\w+|"
    r"regsvr32\b)", re.I,
)


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / DEFAULT_JSONL_NAME

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command="(direct xml parse)", started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    # Two acceptable input shapes:
    #   1. a file (single task XML)
    #   2. a directory tree (recursive scan)
    if req.input_path.is_file():
        files = [req.input_path]
    else:
        # Real Windows tasks are not always *.xml suffixed — some have no
        # extension. Try both.
        files = sorted(
            list(req.input_path.rglob("*.xml")) +
            [p for p in req.input_path.rglob("*") if p.is_file() and not p.suffix]
        )

    if not files:
        return fail(
            artifact_id=ARTIFACT_ID,
            command=f"(scan {req.input_path})", started=started,
            error="no Scheduled Task XML files found under input_path",
            parser_version=PARSER_VERSION,
        )

    cmd_str = f"(direct xml parse: {len(files)} files under {req.input_path})"
    parse_errors: list[str] = []

    def _events() -> Iterator[dict]:
        for idx, path in enumerate(files):
            try:
                ev = _parse_one(path, req.input_path, idx, req)
            except ET.ParseError as exc:
                parse_errors.append(f"{path}: {exc}")
                continue
            except Exception as exc:  # noqa: BLE001
                parse_errors.append(f"{path}: {exc!r}")
                continue
            if ev is not None:
                yield ev

    try:
        row_count = write_unified_events(jsonl_path, _events())
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"XML→JSONL write failed: {exc}",
            parser_version=PARSER_VERSION,
        )

    elapsed = 0.0
    notes = [
        f"Parsed {row_count} of {len(files)} task XML files.",
        "Task creation time is taken from RegistrationInfo/Date when present.",
        "tactic_hints are advisory — verify before classifying.",
    ]
    if parse_errors:
        notes.append(f"{len(parse_errors)} files failed XML parse (see stderr_tail).")

    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=cmd_str, exit_code=0,
        started_at=started, finished_at=now_iso(),
        duration_seconds=elapsed,
        stdout_tail="",
        stderr_tail="\n".join(parse_errors[:50]),
        output_csv=None,                        # XML parser writes JSONL only
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=notes,
    )


def _parse_one(
    path: pathlib.Path,
    root_dir: pathlib.Path,
    idx: int,
    req: ParseRequest,
) -> dict[str, Any] | None:
    root = _robust_parse(path)

    # Task XML may or may not declare the namespace. Try with NS first.
    def _find(node: ET.Element, xpath: str) -> ET.Element | None:
        n = node.find(xpath, NS)
        if n is None:
            # Strip ns prefix and try without
            stripped = re.sub(r"t:", "", xpath)
            n = node.find(stripped)
        return n

    def _findall(node: ET.Element, xpath: str) -> list[ET.Element]:
        nodes = node.findall(xpath, NS)
        if not nodes:
            stripped = re.sub(r"t:", "", xpath)
            nodes = node.findall(stripped)
        return nodes

    reg_info = _find(root, "t:RegistrationInfo")
    date_node = _find(reg_info, "t:Date") if reg_info is not None else None
    author = _text(_find(reg_info, "t:Author")) if reg_info is not None else ""
    description = _text(_find(reg_info, "t:Description")) if reg_info is not None else ""
    registration_date = _text(date_node)

    principals = _find(root, "t:Principals")
    run_as = ""
    if principals is not None:
        for p in _findall(principals, "t:Principal"):
            user_id = _text(_find(p, "t:UserId"))
            if user_id:
                run_as = user_id
                break

    triggers_node = _find(root, "t:Triggers")
    triggers: list[dict[str, Any]] = []
    if triggers_node is not None:
        for trig in list(triggers_node):
            trig_type = _strip_ns(trig.tag)
            triggers.append({
                "type": trig_type,
                "start_boundary": _text(_find(trig, "t:StartBoundary")),
                "enabled": _text(_find(trig, "t:Enabled")),
                "execution_time_limit": _text(_find(trig, "t:ExecutionTimeLimit")),
            })

    actions_node = _find(root, "t:Actions")
    actions: list[dict[str, Any]] = []
    if actions_node is not None:
        for act in list(actions_node):
            act_type = _strip_ns(act.tag)
            entry: dict[str, Any] = {"type": act_type}
            if act_type == "Exec":
                entry["command"] = _text(_find(act, "t:Command"))
                entry["arguments"] = _text(_find(act, "t:Arguments"))
                entry["working_directory"] = _text(_find(act, "t:WorkingDirectory"))
            elif act_type == "ComHandler":
                entry["class_id"] = _text(_find(act, "t:ClassId"))
                entry["data"] = _text(_find(act, "t:Data"))
            elif act_type == "SendEmail":
                entry["to"] = _text(_find(act, "t:To"))
                entry["subject"] = _text(_find(act, "t:Subject"))
            actions.append(entry)

    task_name = str(path.relative_to(root_dir)) if path != root_dir else path.name
    hints = _hints(actions, run_as)

    payload = {
        "task_name": task_name,
        "source_file": str(path),
        "author": author,
        "description": description,
        "run_as": run_as,
        "registration_date": registration_date,
        "triggers": triggers,
        "actions": actions,
        "tactic_hints": hints,
    }
    audit_key = f"{task_name}|{registration_date}|{[a.get('command') for a in actions]}"
    audit = audit_id(req.case_id, ARTIFACT_ID, idx, audit_key)
    return make_unified_event(
        case_id=req.case_id,
        evidence_id=req.evidence_id,
        artifact_id=ARTIFACT_ID,
        audit=audit,
        ts_utc=registration_date or "",
        event_type="scheduled_task",
        computer=None,
        payload=payload,
        parser_version=PARSER_VERSION,
    )


def _hints(actions: list[dict[str, Any]], run_as: str) -> list[str]:
    """Conservative tactic mapping. Always cite TA0002 + TA0003 as base
    (every scheduled task is by definition execution + persistence)."""
    hits = ["TA0002", "TA0003"]
    suspicious = False
    for a in actions:
        cmd = (a.get("command") or "") + " " + (a.get("arguments") or "")
        if _SUSPICIOUS_PATH_RX.search(cmd):
            suspicious = True
        if _SUSPICIOUS_CMD_RX.search(cmd):
            suspicious = True
    if suspicious:
        hits.append("TA0005")  # Defense Evasion (encoded / unusual loaders)
    if run_as.upper() in {"S-1-5-18", "SYSTEM", "LOCAL SYSTEM", "NT AUTHORITY\\SYSTEM"}:
        if "TA0004" not in hits:
            hits.append("TA0004")  # Privilege Escalation
    return hits


def _robust_parse(path: pathlib.Path) -> ET.Element:
    """Parse a Windows task XML, tolerating common encoding-declaration drift.

    Real Windows tasks are UTF-16 LE with BOM. ElementTree handles those
    natively. But synthetic / re-saved XML sometimes has ``encoding="UTF-16"``
    declared while the bytes are actually UTF-8 — that mismatch makes ET
    raise ``encoding specified in XML declaration is incorrect``.

    Strategy: read raw bytes, strip a leading BOM, drop the encoding pseudo-
    attribute from the XML declaration if present, and parse the cleaned
    string. Real UTF-16 files are detected by BOM and decoded explicitly.
    """
    raw = path.read_bytes()
    # UTF-16 BOM detection (Windows native format)
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            text = raw.decode("utf-16-le", errors="replace")
    else:
        # UTF-8 (with optional BOM)
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        text = raw.decode("utf-8", errors="replace")

    # Strip ``encoding="..."`` from the XML decl so ET doesn't reject mismatch.
    text = re.sub(
        r"^(<\?xml[^?>]*?)\s+encoding=[\"'][^\"']+[\"']", r"\1",
        text, count=1,
    )
    return ET.fromstring(text)


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _text(node: ET.Element | None) -> str:
    if node is None:
        return ""
    return (node.text or "").strip()
