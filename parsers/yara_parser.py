"""YARA parser (Wave 37) — rule-based file scanning.

Walks a directory and runs YARA rules against every file, emitting one
UnifiedEvent per match (rule_id + path). Useful for known-malware
detection without going through a malware sandbox.

Status: skeleton — graceful skip when `yara` binary is absent or no
rules directory is configured.

SIFT install:
    # apt install yara              # adds /usr/bin/yara
    # or compile from source for newer version

Rules path defaults to /opt/yara-rules/ (operator-provisioned). Users
typically populate this with the Yara-Rules/rules repo or custom set.
"""

from __future__ import annotations

import pathlib
import shutil

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

ARTIFACT_ID = "yara"
PARSER_VERSION = "yara_parser/0.1.0-skeleton"
YARA_BIN = "yara"
DEFAULT_RULES_DIR = "/opt/yara-rules"


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
    if shutil.which(YARA_BIN) is None:
        return fail(
            artifact_id=ARTIFACT_ID,
            command="(yara binary not installed)",
            started=started,
            error=(
                "YARA CLI not present. Install via: apt install yara. "
                "Note: libyara10 only on default SIFT — full CLI requires "
                "the 'yara' package."
            ),
            parser_version=PARSER_VERSION,
        )
    rules_dir = pathlib.Path(req.extra.get("yara_rules_dir") or DEFAULT_RULES_DIR)
    rules_files = sorted(rules_dir.glob("*.yar")) + sorted(rules_dir.glob("*.yara"))
    if not rules_files:
        return fail(
            artifact_id=ARTIFACT_ID,
            command=f"(no rules in {rules_dir})",
            started=started,
            error=(
                f"No .yar/.yara files in {rules_dir}. "
                f"Provision Yara-Rules/rules (https://github.com/Yara-Rules/rules) "
                f"or pass --extra yara_rules_dir=<path>."
            ),
            parser_version=PARSER_VERSION,
        )
    # YARA can scan a directory recursively with -r. Output is plain:
    #   <rule_id> <file_path>
    # Run one master include file so it scans with all rules at once.
    include_path = req.output_dir / "_yara_all_rules.yar"
    with include_path.open("w") as fh:
        for r in rules_files:
            fh.write(f'include "{r}"\n')
    cmd = [YARA_BIN, "-r", "-s", str(include_path), str(req.input_path)]
    cmd_str = " ".join(cmd)
    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)
    if rc != 0 and rc != 1:
        # rc=0 → no matches, rc=1 → matches found. >1 = real failure.
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"yara exit={rc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    def _iter() -> Iterator[dict]:
        idx = 0
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # YARA -s format: "<rule> <file>\n<offset>:<identifier>: <bytes>"
            # We only consume rule+file pairs (the first line of each block);
            # detail lines are concatenated for context.
            parts = line.split(" ", 1)
            if len(parts) < 2 or ":" in parts[0]:
                continue  # skip detail lines
            rule, path = parts[0], parts[1]
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit_id(req.case_id, ARTIFACT_ID, idx,
                               f"{rule}|{path}"),
                ts_utc="",
                event_type="yara_match",
                payload={"rule": rule, "matched_path": path},
                parser_version=PARSER_VERSION,
            )
            idx += 1

    jsonl_path = req.output_dir / "yara.jsonl"
    try:
        from collections.abc import Iterator  # noqa: F401
        row_count = write_unified_events(jsonl_path, _iter())
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"convert YARA stdout→JSONL: {exc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )
    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=cmd_str, exit_code=rc,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(elapsed, 3),
        stdout_tail=tail(stdout), stderr_tail=tail(stderr),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            f"YARA scanned {req.input_path} with {len(rules_files)} rule file(s).",
            "YARA matches do NOT prove malice — examiner must triage each rule "
            "in context (rule quality varies).",
        ],
    )
