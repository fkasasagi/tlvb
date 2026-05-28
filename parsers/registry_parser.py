"""RECmd (Kroll batch) parser with MITRE ATT&CK tactic_hints.

Wraps RECmd over a directory containing one or more Windows registry hives
(SOFTWARE, SYSTEM, NTUSER.DAT, etc.) using the bundled ``Kroll_Batch.reb``
batch file. Output is a long-format CSV: one row per (key, value) hit. We
union it into UnifiedEvent JSONL and tag each row with ``tactic_hints`` —
candidate MITRE ATT&CK tactics inferred from the registry path.

Hint mapping is intentionally conservative — we attach hints, not classifications.
A Tactic Agent is still responsible for confirming or rejecting the hint with
corroborating evidence (Valhuntir Grounding Score §3.4).
"""

from __future__ import annotations

import csv
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
    run_command,
    tail,
    write_unified_events,
)


ARTIFACT_ID = "registry"
PARSER_VERSION = "registry_parser/1.0.0+recmd"

DLL = "/opt/zimmermantools/RECmd/RECmd.dll"
KROLL_BATCH = "/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb"
DEFAULT_CSV_NAME = "registry.csv"
DEFAULT_JSONL_NAME = "registry.jsonl"


# ---------------------------------------------------------------------------
# Tactic hint table — case-insensitive substrings against KeyPath/Category
#
# Sources: MITRE ATT&CK Enterprise (TA0003 Persistence, TA0004 Privilege
# Escalation, TA0005 Defense Evasion, TA0007 Discovery, TA0008 Lateral
# Movement, TA0010 Exfiltration). We mirror the LOLBAS / atomic-red-team
# style of citing ATT&CK at the technique level rather than tactic level only,
# but emit the *tactic* here because we don't yet have full technique fidelity.
# ---------------------------------------------------------------------------

_TACTIC_RULES: list[tuple[re.Pattern[str], list[str]]] = [
    # Persistence — autorun-style keys
    (re.compile(r"\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?(Ex)?", re.I),
     ["TA0003"]),
    (re.compile(r"\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", re.I),
     ["TA0003"]),
    (re.compile(r"\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", re.I),
     ["TA0003", "TA0005"]),  # IFEO Debugger hijack: persistence + DE
    (re.compile(r"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", re.I),
     ["TA0003"]),
    (re.compile(r"\\Services\\.+\\(ImagePath|ServiceDll)", re.I),
     ["TA0003", "TA0004"]),
    (re.compile(r"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", re.I),
     ["TA0003"]),
    (re.compile(r"AppInit_DLLs|AppCertDlls", re.I),
     ["TA0003", "TA0004"]),

    # Privilege Escalation / Defense Evasion overlap
    (re.compile(r"\\Microsoft\\Windows Defender\\Exclusions", re.I),
     ["TA0005"]),
    (re.compile(r"\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\(EnableLUA|ConsentPromptBehavior)", re.I),
     ["TA0005", "TA0004"]),

    # Discovery
    (re.compile(r"\\Microsoft\\Windows\\CurrentVersion\\Uninstall", re.I),
     ["TA0007"]),
    (re.compile(r"\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", re.I),
     ["TA0007"]),

    # Lateral Movement / Remote access
    (re.compile(r"\\Terminal Server\\WinStations|\\Microsoft\\Terminal Server Client", re.I),
     ["TA0008"]),
    (re.compile(r"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", re.I),
     ["TA0008", "TA0007"]),

    # Credential Access
    (re.compile(r"\\SAM\\Domains\\Account|\\SECURITY\\Policy\\Secrets", re.I),
     ["TA0006"]),
    (re.compile(r"\\Microsoft\\Cryptography\\MachineGuid", re.I),
     ["TA0007"]),

    # Execution (User Shell Folders, Scheduled Tasks pointers)
    (re.compile(r"\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache", re.I),
     ["TA0002", "TA0003"]),
]


def _tactic_hints(category: str, key_path: str, value_name: str) -> list[str]:
    haystack = "|".join((category or "", key_path or "", value_name or ""))
    hits: list[str] = []
    seen: set[str] = set()
    for rx, tactics in _TACTIC_RULES:
        if rx.search(haystack):
            for t in tactics:
                if t not in seen:
                    seen.add(t)
                    hits.append(t)
    return hits


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = req.output_dir / DEFAULT_JSONL_NAME

    cmd = [
        "dotnet", DLL,
        "-d", str(req.input_path),
        "--bn", KROLL_BATCH,
        "--csv", str(req.output_dir),
        "--csvf", DEFAULT_CSV_NAME,
        "--nl", "false",
    ]
    cmd_str = " ".join(cmd)

    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)
    if rc != 0:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"RECmd exit={rc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    # RECmd writes <timestamp>_<DEFAULT_CSV_NAME>.
    csv_files = sorted(req.output_dir.glob(f"*_{DEFAULT_CSV_NAME}"))
    if not csv_files:
        # Some RECmd versions write the file verbatim.
        if (req.output_dir / DEFAULT_CSV_NAME).exists():
            csv_files = [req.output_dir / DEFAULT_CSV_NAME]
    if not csv_files:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error="RECmd succeeded but no CSV found",
            exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    csv_path = csv_files[-1]  # most recent if multiple
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
            "LastWriteTimestamp is the KEY's last write — it does NOT pin a specific Value's mod time.",
            "Transaction logs (.LOG1/.LOG2) must be applied separately to surface uncommitted changes.",
            "tactic_hints are advisory — confirm with corroborating evidence before classifying.",
            f"Used batch file: {KROLL_BATCH}",
        ],
    )


# ---------------------------------------------------------------------------
# CSV → UnifiedEvent
# ---------------------------------------------------------------------------

# Kroll batch CSV columns (RECmd 1.x): HivePath, HiveType, Description, Category,
# KeyPath, ValueName, ValueType, ValueData, ValueData2, ValueData3,
# Comment, Recursive, Deleted, LastWriteTimestamp, PluginDetailFile
_TS_COLUMN = "LastWriteTimestamp"


def _convert(csv_path: pathlib.Path, req: ParseRequest) -> Iterator[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for idx, row in enumerate(reader):
            ts = (row.get(_TS_COLUMN) or "").strip()
            category = row.get("Category") or ""
            key_path = row.get("KeyPath") or ""
            value_name = row.get("ValueName") or ""

            payload = dict(row)
            payload["tactic_hints"] = _tactic_hints(category, key_path, value_name)

            audit_key = f"{row.get('HivePath','')}|{key_path}|{value_name}|{ts}"
            audit = audit_id(req.case_id, ARTIFACT_ID, idx, audit_key)
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit,
                ts_utc=ts,
                event_type="registry",
                computer=None,
                payload=payload,
                parser_version=PARSER_VERSION,
            )
