"""Common parser interface.

Every artifact parser under ``parsers/`` exports a callable ``parse`` matching
:class:`ParserFn` and a module-level ``ARTIFACT_ID``. The orchestrator
discovers parsers by ``ARTIFACT_ID`` (matching ``config/artifacts.yaml``) and
calls ``parse`` with a populated :class:`ParseRequest`.

Forensic discipline (see docs/valhuntir_analysis.md §5.3 L1):
  - tools NEVER mutate evidence; we read input_path, write output to output_dir
  - all timestamps emitted as ISO8601 UTC
  - ParseResult always carries the full executed command + stderr tail so the
    Examiner Portal Review Gate 0 can audit what ran
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import pathlib
import subprocess
import time
from collections.abc import Iterable
from typing import Any, Protocol

# Schema versions are pinned so downstream consumers (UI, Tactic Agents) can
# detect breaking changes.
PARSER_API_VERSION = "tlvb/parser/v1"
UNIFIED_EVENT_SCHEMA = "tlvb/unified-event/v1"


@dataclasses.dataclass(frozen=True)
class ParseRequest:
    """Inputs to a parser run."""

    input_path: pathlib.Path        # file or directory (per artifact's input.mode)
    output_dir: pathlib.Path        # parser writes CSV / JSONL here
    case_id: str
    evidence_id: str
    timezone: str = "UTC"           # case timezone (parser may need for normalisation)
    timeout_seconds: int = 600
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ParseResult:
    """Outputs of a parser run, persisted by the orchestrator into DuckDB."""

    artifact_id: str
    success: bool
    command: str                    # exact shell command line executed
    exit_code: int | None
    started_at: str                 # ISO8601 UTC
    finished_at: str                # ISO8601 UTC
    duration_seconds: float
    stdout_tail: str = ""           # last ~4 KB
    stderr_tail: str = ""           # last ~4 KB
    output_csv: str | None = None   # absolute path or None
    output_jsonl: str | None = None # UnifiedEvent JSONL path
    row_count: int | None = None
    parser_version: str = ""
    error: str | None = None        # populated on failure
    notes: list[str] = dataclasses.field(default_factory=list)


class ParserFn(Protocol):
    def __call__(self, req: ParseRequest) -> ParseResult: ...


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    """ISO8601 UTC timestamp, second precision (parsers can override for ns)."""
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat()


def naive_local_to_utc_iso(dt: datetime.datetime, tz_name: str) -> str:
    """Interpret a *naive* datetime as wall-clock time in ``tz_name`` (an IANA
    zone such as ``"Asia/Tokyo"``) and return the equivalent UTC ISO-8601
    string with an explicit ``+00:00`` offset.

    The canonical store is UTC (see module docstring), but some artifacts —
    IIS native access logs, Apache/nginx/Tomcat diagnostic logs — record the
    server's LOCAL time with no offset. Those parsers cannot self-determine the
    source zone, so the examiner-supplied evidence timezone
    (``ParseRequest.timezone``) is used as the source zone to canonicalise to
    UTC at parse time. DST for the given date is handled by ``zoneinfo``.

    An empty/garbage ``dt`` is the caller's responsibility; an unknown
    ``tz_name`` falls back to UTC (no shift).
    """
    try:
        from zoneinfo import ZoneInfo

        src: datetime.tzinfo = (
            ZoneInfo(tz_name) if tz_name and tz_name != "UTC" else datetime.UTC
        )
    except Exception:
        src = datetime.UTC
    return dt.replace(tzinfo=src).astimezone(datetime.UTC).isoformat()


def tail(s: str | bytes, max_bytes: int = 4096) -> str:
    """Last ``max_bytes`` of stdout/stderr — keeps DuckDB rows bounded."""
    if isinstance(s, bytes):
        s = s.decode("utf-8", errors="replace")
    if len(s) <= max_bytes:
        return s
    return "...[truncated]...\n" + s[-max_bytes:]


def audit_id(case_id: str, artifact_id: str, source_row_index: int, raw: str) -> str:
    """Deterministic audit_id for a UnifiedEvent.

    Matches Valhuntir's "決定的ドキュメント ID（再投入で重複ゼロ）" pattern
    (architecture.md §opensearch-mcp). Re-parsing the same input produces the
    same audit_ids, so the orchestrator can upsert idempotently.
    """
    h = hashlib.sha256()
    h.update(case_id.encode())
    h.update(b"\x1f")
    h.update(artifact_id.encode())
    h.update(b"\x1f")
    h.update(str(source_row_index).encode())
    h.update(b"\x1f")
    h.update(raw.encode("utf-8", errors="replace"))
    return h.hexdigest()[:32]


def run_command(
    cmd: list[str],
    *,
    timeout: int,
    cwd: pathlib.Path | None = None,
) -> tuple[int, str, str, float]:
    """Run a subprocess with a strict timeout. Returns (rc, stdout, stderr, secs).

    No shell interpolation — caller passes argv list. Evidence paths are not
    expanded by the shell, eliminating quoting bugs and command injection.
    """
    started = time.monotonic()
    try:
        cp = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
        elapsed = time.monotonic() - started
        return cp.returncode, cp.stdout.decode("utf-8", errors="replace"), \
            cp.stderr.decode("utf-8", errors="replace"), elapsed
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        out = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        err = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
        return -1, out, err + f"\n[timeout after {timeout}s]", elapsed


def write_unified_events(
    output_jsonl: pathlib.Path,
    events: Iterable[dict[str, Any]],
) -> int:
    """Write an iterable of UnifiedEvent dicts as JSON Lines. Returns row count."""
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with output_jsonl.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False, default=str))
            fh.write("\n")
            n += 1
    return n


def make_unified_event(
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    audit: str,
    ts_utc: str,
    event_type: str,
    computer: str | None = None,
    payload: dict[str, Any] | None = None,
    parser_version: str = "",
) -> dict[str, Any]:
    """Build a UnifiedEvent dict matching the schema in
    ``config/artifacts.yaml#unified_event_required_fields``."""
    return {
        "schema": UNIFIED_EVENT_SCHEMA,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_id": artifact_id,
        "audit_id": audit,
        "timestamp": ts_utc,
        "event_type": event_type,
        "source_artifact": event_type,  # alias, see artifacts.yaml
        "computer": computer or "",
        "parser_version": parser_version,
        "payload": payload or {},
    }


# Sentinel exit_code returned by `fail()` when the underlying tool exited
# cleanly (rc=0) but produced no usable output. Without this, parse_results
# rows looked indistinguishable from genuine successes (exit_code=0,
# row_count=0) and the synthesizer's `collectFailedArtifacts` quietly
# missed them. Negative numbers don't clash with any real exit code POSIX
# can return.
FAIL_SILENT_SENTINEL = -1


def fail(
    *,
    artifact_id: str,
    command: str,
    started: str,
    error: str,
    exit_code: int | None = None,
    stdout_tail: str = "",
    stderr_tail: str = "",
    parser_version: str = "",
) -> ParseResult:
    """Convenience constructor for the unhappy path.

    Forensic-correctness fix (2026-05-16): when a parser fails *despite*
    the underlying tool reporting exit=0 (e.g. PECmd on Linux exiting
    cleanly without writing any CSV, or psort succeeding but producing
    an empty timeline), we stamp ``exit_code=FAIL_SILENT_SENTINEL`` so
    the row is visibly non-zero in ``parse_results`` and gets picked up
    by ``collectFailedArtifacts``. Genuine exit-code failures keep their
    original rc.
    """
    finished = now_iso()
    effective_rc = exit_code
    if effective_rc == 0:
        effective_rc = FAIL_SILENT_SENTINEL
    return ParseResult(
        artifact_id=artifact_id,
        success=False,
        command=command,
        exit_code=effective_rc,
        started_at=started,
        finished_at=finished,
        duration_seconds=0.0,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
        parser_version=parser_version,
        error=error,
    )


# ---------------------------------------------------------------------------
# Concrete parsers must export both:
#
#   ARTIFACT_ID: str          # matches config/artifacts.yaml id
#   PARSER_VERSION: str       # bump when output schema changes
#   parse: ParserFn
# ---------------------------------------------------------------------------


__all__ = [
    "PARSER_API_VERSION",
    "UNIFIED_EVENT_SCHEMA",
    "ParseRequest",
    "ParseResult",
    "ParserFn",
    "audit_id",
    "fail",
    "make_unified_event",
    "naive_local_to_utc_iso",
    "now_iso",
    "run_command",
    "tail",
    "write_unified_events",
]
