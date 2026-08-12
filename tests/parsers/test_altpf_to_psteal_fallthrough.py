"""Regression: altpf NG → psteal fallback の包括カバレッジ。

ユーザー指定の方針「altpf でパースをして NG の場合は plaso を使用」を
全 NG シナリオで保証する。

NG が起きうるパイプライン段:
  ① altpf binary が無い               (existing — test_psteal_fallback で確認)
  ② altpf run が rc != 0               (← 本ファイル A)
  ③ altpf rc=0 だが CSV ファイル無し   (← 本ファイル B)
  ④ altpf CSV はあるが 0 rows         (← 本ファイル C)
  ⑤ altpf CSV → JSONL 変換で例外      (← 本ファイル D — bug fix 2026-05-16)

旧コード (Wave 12 初版) は ⑤ で fail() 即 return していたが、それは
方針違反。修正後はすべて Plaso psteal にフォールスルーすることを確認。
"""

from __future__ import annotations

import pathlib
from unittest.mock import patch

import pytest

from parsers.base import ParseRequest
from parsers import prefetch_parser as pp

# These tests mock altpf *runs* (rc!=0, empty CSV, conversion errors) to prove
# the parser falls through to Plaso psteal. They require the real altpf binary:
# parse() short-circuits to a different "binary not installed" path when
# ALTPF_BIN is absent (e.g. on a clean CI runner), bypassing the mocked runs.
pytestmark = pytest.mark.skipif(
    not pathlib.Path(pp.ALTPF_BIN).is_file(),
    reason="altpf binary not installed at ALTPF_BIN (clean CI); "
    "altpf-failure → psteal fallthrough paths need the real binary",
)


@pytest.fixture
def fake_pf_dir(tmp_path):
    """Minimal input directory with one dummy `.pf` so parse() passes its
    `input_path.is_dir()` precondition."""
    d = tmp_path / "Prefetch"
    d.mkdir()
    (d / "DUMMY.EXE-12345678.pf").write_bytes(b"\x00" * 16)
    return d


def _req(input_path: pathlib.Path, out: pathlib.Path) -> ParseRequest:
    return ParseRequest(
        input_path=input_path, output_dir=out,
        case_id="T", evidence_id="EV",
        timezone="UTC", timeout_seconds=60,
    )


def _make_psteal_emit_minimal_csv(out_dir: pathlib.Path):
    """Helper: build a run_command stub that emits a minimal valid
    Plaso dynamic CSV when psteal is invoked. Returns the stub +
    a captured-cmds list."""
    captured: list[list[str]] = []

    def fake_run(cmd, timeout=None):
        captured.append(list(cmd))
        if cmd and isinstance(cmd[0], str) and cmd[0].endswith("psteal.py"):
            # Write the destination CSV with a single header line so
            # `_convert_plaso` finds it and returns 0 events.
            csv_path = cmd[cmd.index("-w") + 1]
            pathlib.Path(csv_path).write_text(
                "datetime,timestamp_desc,source,source_long,message,"
                "parser,display_name,tag\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.05)
        # Anything else (altpf etc.) — caller will configure via outer.
        return (0, "", "", 0.01)

    return fake_run, captured


# ===========================================================================
# Scenario A: altpf rc != 0 → psteal fallback
# ===========================================================================


def test_altpf_nonzero_exit_falls_through_to_psteal(tmp_path, fake_pf_dir):
    fake_run, captured = _make_psteal_emit_minimal_csv(tmp_path)

    def run_dispatch(cmd, timeout=None):
        if cmd[0] == pp.ALTPF_BIN:
            return (2, "", "boom", 0.01)            # altpf rc=2
        return fake_run(cmd, timeout=timeout)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(pp, "run_command", side_effect=run_dispatch):
        def is_file_impl(self):
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = pp.parse(_req(fake_pf_dir, tmp_path))

    assert res.success, f"should succeed via psteal, got: {res.error}"
    # The 2nd captured command (the first is altpf) must be psteal.
    assert any(c[0].endswith("psteal.py") for c in captured)
    notes = "\n".join(res.notes or [])
    assert "psteal" in notes.lower()
    assert "altpf failed: exit=2" in notes


# ===========================================================================
# Scenario B: altpf rc=0 but no CSV file → psteal fallback
# ===========================================================================


def test_altpf_no_csv_produced_falls_through_to_psteal(tmp_path, fake_pf_dir):
    fake_run, captured = _make_psteal_emit_minimal_csv(tmp_path)

    def run_dispatch(cmd, timeout=None):
        if cmd[0] == pp.ALTPF_BIN:
            # altpf claims success but writes nothing.
            return (0, "altpf processed 0 file(s)", "", 0.01)
        return fake_run(cmd, timeout=timeout)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(pp, "run_command", side_effect=run_dispatch):
        def is_file_impl(self):
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = pp.parse(_req(fake_pf_dir, tmp_path))

    assert res.success, f"should succeed via psteal, got: {res.error}"
    assert any(c[0].endswith("psteal.py") for c in captured)
    notes = "\n".join(res.notes or [])
    assert "psteal" in notes.lower()


# ===========================================================================
# Scenario C: altpf produces CSV but it has 0 data rows → psteal fallback
# ===========================================================================


def test_altpf_empty_csv_falls_through_to_psteal(tmp_path, fake_pf_dir):
    fake_run, captured = _make_psteal_emit_minimal_csv(tmp_path)

    def run_dispatch(cmd, timeout=None):
        if cmd[0] == pp.ALTPF_BIN:
            # altpf writes a CSV with only a header (0 data rows).
            (tmp_path / "20260516120000_altpf_Output.csv").write_text(
                "SourceFile,SourceFilename,SourceCreated,SourceModified,"
                "SourceAccessed,ExecutableName,Hash,Size,Version,RunCount,"
                "LastRun,PreviousRun0,PreviousRun1,PreviousRun2,"
                "PreviousRun3,PreviousRun4,PreviousRun5,PreviousRun6,"
                "Volume0Name,Volume0Serial,Volume0Created,"
                "Volume1Name,Volume1Serial,Volume1Created,"
                "Directories,FilesLoaded,ParseError\n",
                encoding="utf-8",
            )
            return (0, "altpf processed 0 file(s)", "", 0.01)
        return fake_run(cmd, timeout=timeout)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(pp, "run_command", side_effect=run_dispatch):
        def is_file_impl(self):
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = pp.parse(_req(fake_pf_dir, tmp_path))

    assert res.success, f"should succeed via psteal, got: {res.error}"
    assert any(c[0].endswith("psteal.py") for c in captured)
    notes = "\n".join(res.notes or [])
    assert "psteal" in notes.lower()
    assert "rows=0" in notes


# ===========================================================================
# Scenario D: altpf CSV → JSONL conversion blows up → psteal fallback
# (本日 fix した穴。旧コードは ここで fail() 即 return していた。)
# ===========================================================================


def test_altpf_conversion_exception_falls_through_to_psteal(tmp_path, fake_pf_dir):
    """altpf が CSV を生成して row が 1 件以上あっても、Python の
    `_convert_altpf` が例外を投げる場面では Plaso にフォールスルー。

    例: altpf が将来 v0.6 で新カラムを追加し、現行コードがそれを期待しない
    場面など。テストでは monkey-patch で例外を強制する。"""
    fake_run, captured = _make_psteal_emit_minimal_csv(tmp_path)

    def run_dispatch(cmd, timeout=None):
        if cmd[0] == pp.ALTPF_BIN:
            # altpf "succeeds" with a 1-row CSV.
            (tmp_path / "20260516120000_altpf_Output.csv").write_text(
                "SourceFile,SourceFilename,SourceCreated,SourceModified,"
                "SourceAccessed,ExecutableName,Hash,Size,Version,RunCount,"
                "LastRun,PreviousRun0,PreviousRun1,PreviousRun2,"
                "PreviousRun3,PreviousRun4,PreviousRun5,PreviousRun6,"
                "Volume0Name,Volume0Serial,Volume0Created,"
                "Volume1Name,Volume1Serial,Volume1Created,"
                "Directories,FilesLoaded,ParseError\n"
                "/p/A.pf,A.pf,2026-02-14 00:00:00,2026-02-14 00:00:00,"
                "2026-02-14 00:00:00,A.EXE,0x1,100,Windows 10,1,"
                "2026-02-14 00:00:00,,,,,,,,"
                ",,,,,,,,(no error)\n",
                encoding="utf-8",
            )
            return (0, "altpf processed 1 file(s)", "", 0.01)
        return fake_run(cmd, timeout=timeout)

    def boom(*args, **kwargs):
        raise ValueError("simulated conversion failure (e.g. unknown column)")

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(pp, "run_command", side_effect=run_dispatch), \
         patch.object(pp, "_convert_altpf", side_effect=boom):
        def is_file_impl(self):
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = pp.parse(_req(fake_pf_dir, tmp_path))

    # The whole point: parse must NOT bail with fail() — it must fall
    # through to psteal which succeeds.
    assert res.success, (
        f"altpf conversion failure should fall through to psteal, "
        f"got fail() instead: {res.error}"
    )
    assert any(c[0].endswith("psteal.py") for c in captured), \
        "psteal fallback was not invoked after altpf conversion error"
    notes = "\n".join(res.notes or [])
    assert "psteal" in notes.lower()
    assert "conversion failed" in notes.lower() or \
           "ValueError" in notes, \
           f"audit note must capture the conversion failure: {notes}"


# ===========================================================================
# Forensic invariant: altpf NG note is always preserved
# ===========================================================================


def test_altpf_audit_note_always_in_psteal_path(tmp_path, fake_pf_dir):
    """Whichever NG branch fired, parse_results.notes must record what
    altpf did (or didn't do) so the Examiner can audit the choice."""
    fake_run, captured = _make_psteal_emit_minimal_csv(tmp_path)

    def run_dispatch(cmd, timeout=None):
        if cmd[0] == pp.ALTPF_BIN:
            return (137, "", "killed", 0.01)        # rc=137 (OOM-style)
        return fake_run(cmd, timeout=timeout)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(pp, "run_command", side_effect=run_dispatch):
        def is_file_impl(self):
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = pp.parse(_req(fake_pf_dir, tmp_path))

    assert res.success
    notes = "\n".join(res.notes or [])
    assert "altpf" in notes.lower()
    assert "exit=137" in notes
