"""Wave 40A: SQLECmd "no map matched" → graceful skip regression.

Background (also recorded in docs/STATUS.md §0 Wave 40 entry):
TANAKA-PC's Firefox places.sqlite has no SQLECmd map. Prior to this
fix the parser returned fail() with "produced no CSV — no matching
map?" and parse_results showed sqlecmd as FAIL on every TANAKA case.
The DB-without-a-map outcome is a *fact about the DB*, not a parser
bug — we now promote it to success=True row_count=0 with a note.

This test stubs run_command so SQLECmd never has to actually execute.
"""

from __future__ import annotations

import pathlib

from parsers import sqlecmd_parser
from parsers.base import ParseRequest


def _fake_run_command_no_map(_cmd, timeout):
    """Mimic SQLECmd stdout for a DB without a matching map.

    The "No maps found for" substring is what the parser keys off; exit
    code -1 mirrors the real signal-exit we observed on SIFT when the
    unmatched-db summary path tries to dlopen the missing
    SQLite.Interop.dll.
    """
    stdout = (
        "SQLECmd version 1.1.0.0\n"
        "Maps loaded: 92\n"
        "Processing /tmp/x.sqlite...\n"
        "\tNo maps found for /tmp/x.sqlite. Adding to unmatched database list\n"
    )
    stderr = "DllNotFoundException: SQLite.Interop.dll\n"
    return -1, stdout, stderr, 0.5


def test_sqlecmd_no_map_promoted_to_graceful_skip(monkeypatch, tmp_path):
    sqlite = tmp_path / "places.sqlite"
    sqlite.write_bytes(b"SQLite format 3\x00")  # presence + magic only
    out_dir = tmp_path / "out"

    # Make the SQLECmd.dll presence check pass even on machines that don't
    # have the EZ Tools install (CI). The parser short-circuits before
    # exec when the dll is missing, which would mask the no-map branch.
    monkeypatch.setattr(pathlib.Path, "is_file", lambda self: True)
    monkeypatch.setattr(sqlecmd_parser, "run_command", _fake_run_command_no_map)

    req = ParseRequest(
        input_path=sqlite, output_dir=out_dir,
        case_id="C", evidence_id="E", timezone="UTC", timeout_seconds=60,
    )
    r = sqlecmd_parser.parse(req)

    assert r.success is True, (
        f"no-map outcome must be graceful skip, got fail: {r.error!r}"
    )
    assert r.row_count == 0
    assert r.notes and "no map" in r.notes[0].lower()
    assert r.error is None


def test_sqlecmd_real_failure_still_fails(monkeypatch, tmp_path):
    """rc != 0 with no `No maps found` marker → still a fail (e.g. dll
    crashes BEFORE writing any "no map" line). Guard so the new branch
    doesn't swallow genuine parser failures."""
    sqlite = tmp_path / "places.sqlite"
    sqlite.write_bytes(b"SQLite format 3\x00")
    out_dir = tmp_path / "out"
    monkeypatch.setattr(pathlib.Path, "is_file", lambda self: True)
    monkeypatch.setattr(
        sqlecmd_parser, "run_command",
        lambda _cmd, timeout: (1, "boot error\n", "fatal: SIGSEGV\n", 0.1),
    )
    req = ParseRequest(
        input_path=sqlite, output_dir=out_dir,
        case_id="C", evidence_id="E", timezone="UTC", timeout_seconds=60,
    )
    r = sqlecmd_parser.parse(req)
    assert r.success is False
    assert r.exit_code == 1
