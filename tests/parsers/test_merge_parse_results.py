"""Tests for orchestrator._merge_parse_results (Wave 18c).

Per-user artefacts (jumplists / shellbags / registry / lnk / browser_history)
get one Detection per discovered user. Real-world data routinely has 3/6
users with empty Recent dirs / no NTUSER hive / no browser profile —
parsers correctly return fail() for those, then the orchestrator merges
the N ParseResults into one parse_results row.

Earlier `ok = all-succeeded` policy meant 3 successful users with hundreds
of real rows showed up as 🔴 FAIL because of the 3 empty users. Wave 18c
changes the merge to any-success (partial OK) AND keeps a per-detection
breakdown in `notes` so an examiner can see exactly which users had data
and which were empty.
"""

from __future__ import annotations

from parsers.base import ParseResult
from parsers.orchestrator import _merge_parse_results, _hint_from_command


def _pr(*, user: str, success: bool, rows: int | None = None,
        rc: int = 0, error: str | None = None) -> ParseResult:
    """Construct a per-user ParseResult that mirrors what the per-user
    triage loop produces: command embeds /users/<user>/AppData/..."""
    return ParseResult(
        artifact_id="jumplists",
        success=success,
        command=f"dotnet JLECmd.dll -d /x/users/{user}/AppData/Roaming/Microsoft/Windows/Recent --all",
        exit_code=rc,
        started_at="2026-05-18T10:00:00+00:00",
        finished_at="2026-05-18T10:00:05+00:00",
        duration_seconds=2.0,
        row_count=rows,
        error=error,
    )


def test_hint_from_command_extracts_user():
    cmd = "dotnet JLECmd.dll -d /tmp/users/mhill/AppData/Roaming/Microsoft/Windows/Recent --all"
    assert _hint_from_command(cmd) == "user=mhill"


def test_hint_from_command_falls_back_to_input_path():
    # System artefact: no /users/ segment, fall back to the input arg.
    cmd = "dotnet MFTECmd.dll -f /tmp/extracted/part00/Windows/System32/config/SYSTEM --csv /out"
    hint = _hint_from_command(cmd)
    assert "SYSTEM" in hint or "config" in hint, f"unexpected hint: {hint}"


def test_hint_from_command_handles_empty():
    assert _hint_from_command("") == "<no command>"
    assert _hint_from_command(None) == "<no command>"


# ----- Wave 18c partial-success policy --------------------------------------


def test_any_success_marks_merged_row_as_ok():
    """3 successful users + 3 failed users → merged row should be 🟢 OK."""
    group = [
        _pr(user="mhill",                       success=True,  rows=361),
        _pr(user="rsydow-a",                    success=False, rc=-1,
            error="jumplists produced no CSV outputs"),
        _pr(user="administrator.shieldbase",    success=True,  rows=8),
        _pr(user="Default",                     success=False, rc=-1,
            error="jumplists produced no CSV outputs"),
        _pr(user="cbarton-a",                   success=False, rc=-1,
            error="jumplists produced no CSV outputs"),
        _pr(user="Administrator.BASE-WKSTN-01", success=True,  rows=8),
    ]
    merged = _merge_parse_results(group)

    # Any-success policy: partial OK with rc=0 so the UI badge shows 🟢 OK.
    assert merged.success is True
    assert merged.exit_code == 0
    assert merged.row_count == 377  # 361 + 8 + 8


def test_failed_users_listed_in_notes():
    """Examiner must be able to see WHICH users had no data, by name."""
    group = [
        _pr(user="mhill",    success=True,  rows=361),
        _pr(user="rsydow-a", success=False, rc=-1,
            error="jumplists produced no CSV outputs"),
        _pr(user="Default",  success=False, rc=-1,
            error="jumplists produced no CSV outputs"),
    ]
    merged = _merge_parse_results(group)

    notes_blob = "\n".join(merged.notes)
    # Header line with counts.
    assert "merged 3 detections: 1 ok / 2 fail" in notes_blob
    # Failed-user roll-up: examiner can see at a glance which users were empty.
    assert "user=rsydow-a" in notes_blob
    assert "user=Default" in notes_blob
    # Successful user also listed in the per-detection breakdown.
    assert "user=mhill" in notes_blob
    assert "rows=361" in notes_blob


def test_all_failed_keeps_failure_status():
    """If every user failed, the merged row stays 🔴 FAIL (no false OK)."""
    group = [
        _pr(user="a", success=False, rc=-1, error="empty"),
        _pr(user="b", success=False, rc=-1, error="empty"),
    ]
    merged = _merge_parse_results(group)

    assert merged.success is False
    assert merged.exit_code == -1
    assert merged.row_count == 0


def test_all_success_unchanged():
    """All-success case still works the same — rc=0, success=True."""
    group = [
        _pr(user="a", success=True, rows=10),
        _pr(user="b", success=True, rows=20),
    ]
    merged = _merge_parse_results(group)

    assert merged.success is True
    assert merged.exit_code == 0
    assert merged.row_count == 30


def test_single_detection_passes_through():
    """A group of size 1 is the no-op base case."""
    only = _pr(user="solo", success=True, rows=5)
    merged = _merge_parse_results([only])
    assert merged.success is True
    assert merged.row_count == 5
    # Single-detection still gets the breakdown so the format stays uniform.
    assert any("user=solo: rows=5" in n for n in merged.notes)
