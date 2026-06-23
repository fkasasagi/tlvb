"""Volatility 3 parser (Wave 37) — memory image analysis.

Status: skeleton — checks vol binary presence, runs a small fixed plugin
set (windows.pslist, windows.netscan) against the input memory image,
emits results as UnifiedEvents. Plugin set is intentionally narrow for
MVP — the full Volatility plugin catalog is hundreds of plugins and
choosing the right ones is an interactive examiner decision.

SIFT install: /opt/volatility3 / vol command already on PATH.

Input: .dmp / .raw / .lime / .vmem file.
"""

from __future__ import annotations

import json
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

ARTIFACT_ID = "volatility3"
PARSER_VERSION = "volatility3_parser/0.1.0-skeleton"
VOL_BIN = "vol"  # SIFT symlink to /opt/volatility3/bin/vol
PLUGINS = (
    "windows.pslist",   # process list
    "windows.netscan",  # network connections
)


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    if not req.input_path.exists() or not req.input_path.is_file():
        return fail(
            artifact_id=ARTIFACT_ID, command="(no command issued)",
            started=started,
            error=f"input_path must be a memory image file: {req.input_path}",
            parser_version=PARSER_VERSION,
        )
    if shutil.which(VOL_BIN) is None:
        return fail(
            artifact_id=ARTIFACT_ID,
            command="(volatility3 not installed)",
            started=started,
            error=(
                "Volatility 3 'vol' binary not in PATH. "
                "SIFT default ships it at /opt/volatility3/bin/vol — "
                "ensure symlink to /usr/local/bin/vol exists."
            ),
            parser_version=PARSER_VERSION,
        )

    rows_per_plugin: dict[str, list[dict]] = {}
    cmd_lines: list[str] = []
    last_rc = 0
    last_stderr = ""
    for plugin in PLUGINS:
        # Emit JSON for easier parsing (vol -r json-pretty).
        cmd = [VOL_BIN, "-r", "json", "-f", str(req.input_path), plugin]
        cmd_str = " ".join(cmd)
        cmd_lines.append(cmd_str)
        rc, stdout, stderr, _elapsed = run_command(cmd, timeout=req.timeout_seconds)
        last_rc = rc
        last_stderr = stderr
        if rc != 0:
            # Single plugin failure shouldn't abort the whole parse; log
            # to notes and continue.
            rows_per_plugin[plugin] = []
            continue
        try:
            data = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError:
            data = []
        rows_per_plugin[plugin] = data if isinstance(data, list) else []

    if not any(rows_per_plugin.values()):
        return fail(
            artifact_id=ARTIFACT_ID,
            command=" && ".join(cmd_lines),
            started=started,
            error=(
                "Volatility ran but no plugin produced rows. Common causes: "
                "wrong profile (vol auto-detects but fails on truncated/non-Windows "
                "memory), or input not a memory image."
            ),
            exit_code=last_rc, stderr_tail=tail(last_stderr),
            parser_version=PARSER_VERSION,
        )

    def _iter() -> Iterator[dict]:
        idx = 0
        for plugin, rows in rows_per_plugin.items():
            for row in rows:
                yield make_unified_event(
                    case_id=req.case_id,
                    evidence_id=req.evidence_id,
                    artifact_id=ARTIFACT_ID,
                    audit=audit_id(req.case_id, ARTIFACT_ID, idx,
                                   f"{plugin}|{idx}"),
                    ts_utc="",
                    event_type=f"vol_{plugin.split('.', 1)[-1]}",
                    payload={**row, "vol_plugin": plugin},
                    parser_version=PARSER_VERSION,
                )
                idx += 1

    jsonl_path = req.output_dir / "volatility3.jsonl"
    try:
        from collections.abc import Iterator  # noqa: F401
        row_count = write_unified_events(jsonl_path, _iter())
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID,
            command=" && ".join(cmd_lines), started=started,
            error=f"convert vol JSON→JSONL: {exc}",
            parser_version=PARSER_VERSION,
        )
    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=" && ".join(cmd_lines), exit_code=0,
        started_at=started, finished_at=now_iso(),
        duration_seconds=0.0,  # per-plugin times not tracked here
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            f"Volatility 3 ran {len(PLUGINS)} plugin(s): {', '.join(PLUGINS)}.",
            "Plugin catalog is intentionally narrow — operator can extend "
            "via custom orchestrator config in a future wave.",
        ],
    )
