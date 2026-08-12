"""Tests for parsers.srum_parser (Wave 13).

Wave 13 で srum_parser を Plaso primary + SrumECmd fallback に refactor
した。altpf/prefetch_parser と対称な二段設計。SrumECmd は Windows API
依存 (ESE / Managed.Esent) で Linux で動かないため fallback に。

ここでは subprocess を mock してコマンド構築 + フォールスルー挙動を保証:

  - Plaso `psteal.py --parsers esedb/srum` を primary で呼ぶ
  - 旧 `psort.py` / `log2timeline.py` の二段は使わない
  - case TZ が非 UTC のとき `--output_time_zone` を渡す (UTC は省く)
  - Plaso NG の各シナリオで SrumECmd fallback にフォールスルー
  - 両エンジン NG のとき fail() の error メッセージに両エンジンの結果を残す

実 SRUDB.dat E2E は CLI smoke (F1-03-UI ケース、1404 events / 3.2s) で
確認済。
"""

from __future__ import annotations

import pathlib
from unittest.mock import patch

import pytest

from parsers.base import ParseRequest
from parsers import srum_parser as sp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_srudb(tmp_path):
    """Minimal SRUDB.dat — content irrelevant when subprocess is mocked."""
    p = tmp_path / "SRUDB.dat"
    p.write_bytes(b"\x00" * 16)
    return p


def _req(input_path: pathlib.Path, out: pathlib.Path,
         tz: str = "UTC") -> ParseRequest:
    return ParseRequest(
        input_path=input_path, output_dir=out,
        case_id="T", evidence_id="EV",
        timezone=tz, timeout_seconds=60,
    )


def _make_plaso_emit_csv(out_dir: pathlib.Path, rows: int = 1):
    """Build a run_command stub that emits a minimal valid Plaso dynamic
    CSV when psteal is invoked. Returns (stub, captured_cmds_list)."""
    captured: list[list[str]] = []

    def fake_run(cmd, timeout=None, cwd=None):
        captured.append(list(cmd))
        if cmd and isinstance(cmd[0], str) and cmd[0].endswith("psteal.py"):
            csv_path = pathlib.Path(cmd[cmd.index("-w") + 1])
            header = ("datetime,timestamp_desc,source,source_long,message,"
                      "parser,display_name,tag\n")
            data = "".join(
                f"2026-02-14T13:07:13+00:00,Recorded Time,LOG,"
                f"System Resource Usage Monitor,Application: {i},"
                f"esedb/srum,SRUDB.dat,-\n"
                for i in range(rows)
            )
            csv_path.write_text(header + data, encoding="utf-8")
            return (0, "", "", 0.05)
        return (0, "", "", 0.01)

    return fake_run, captured


# ===========================================================================
# Plaso primary — command construction
# ===========================================================================


def _capture_plaso_cmd(fake_srudb: pathlib.Path, out: pathlib.Path,
                      tz: str = "UTC") -> list[str]:
    fake_run, captured = _make_plaso_emit_csv(out)
    with patch.object(sp, "run_command", side_effect=fake_run):
        res = sp.parse(_req(fake_srudb, out, tz=tz))
    assert res.success
    return captured[0]


def test_plaso_command_uses_psteal_not_log2timeline(fake_srudb, tmp_path):
    """psteal.py 1 段呼出。log2timeline+psort の二段は使わない (regression)."""
    cmd = _capture_plaso_cmd(fake_srudb, tmp_path)
    assert cmd[0] == "psteal.py"
    assert "log2timeline.py" not in cmd
    assert "psort.py" not in cmd


def test_plaso_command_targets_esedb_srum_plugin(fake_srudb, tmp_path):
    """--parsers esedb/srum で SRUM ESE プラグインを指定。"""
    cmd = _capture_plaso_cmd(fake_srudb, tmp_path)
    idx = cmd.index("--parsers")
    assert cmd[idx + 1] == "esedb/srum"


def test_plaso_command_required_flags(fake_srudb, tmp_path):
    cmd = _capture_plaso_cmd(fake_srudb, tmp_path)
    assert "--source" in cmd
    assert "-o" in cmd and "dynamic" in cmd
    assert "-w" in cmd
    assert "-q" in cmd
    # source is the input SRUDB.dat
    idx = cmd.index("--source")
    assert cmd[idx + 1] == str(fake_srudb)


def test_plaso_omits_output_time_zone_for_utc(fake_srudb, tmp_path):
    cmd = _capture_plaso_cmd(fake_srudb, tmp_path, tz="UTC")
    assert "--output_time_zone" not in cmd


def test_plaso_propagates_non_utc_timezone(fake_srudb, tmp_path):
    for tz in ("Asia/Tokyo", "America/Los_Angeles"):
        cmd = _capture_plaso_cmd(fake_srudb, tmp_path, tz=tz)
        assert "--output_time_zone" in cmd
        idx = cmd.index("--output_time_zone")
        assert cmd[idx + 1] == tz


# ===========================================================================
# Plaso NG → SrumECmd fallback
# ===========================================================================


def test_plaso_nonzero_exit_falls_through_to_srumecmd(fake_srudb, tmp_path):
    """Plaso rc != 0 → SrumECmd fallback (Linux なら SrumECmd も coke るが
    ここは ECmd を mock して "success" にして見せる)"""
    plaso_csv_done: list[pathlib.Path] = []

    def fake_run(cmd, timeout=None, cwd=None):
        if cmd and isinstance(cmd[0], str) and cmd[0].endswith("psteal.py"):
            return (2, "", "boom", 0.01)
        if cmd and cmd[0] == "dotnet":
            # SrumECmd: emit one synthetic table CSV
            out_dir = pathlib.Path(cmd[cmd.index("--csv") + 1])
            (out_dir / "20260516120000_NetworkUsages.csv").write_text(
                "Timestamp,AppId,BytesSent,BytesReceived\n"
                "2026-02-14T13:07:13,APP-1,100,200\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.5)
        return (0, "", "", 0.01)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(sp, "run_command", side_effect=fake_run):
        def is_file_impl(self):
            # SrumECmd DLL: pretend installed; everything else delegate.
            if str(self) == sp.SRUMECMD_DLL:
                return True
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = sp.parse(_req(fake_srudb, tmp_path))

    assert res.success
    assert "fallback" in res.command.lower() or "srumecmd" in res.command.lower() \
        or "dotnet" in res.command.lower()
    notes = "\n".join(res.notes or [])
    assert "SrumECmd fallback" in notes
    assert "Plaso esedb/srum failed: exit=2" in notes


def test_plaso_empty_csv_falls_through_to_srumecmd(fake_srudb, tmp_path):
    """Plaso rc=0 だが 0 rows → SrumECmd fallback."""
    def fake_run(cmd, timeout=None, cwd=None):
        if cmd[0].endswith("psteal.py"):
            csv_path = pathlib.Path(cmd[cmd.index("-w") + 1])
            csv_path.write_text(
                "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.05)
        if cmd[0] == "dotnet":
            out_dir = pathlib.Path(cmd[cmd.index("--csv") + 1])
            (out_dir / "20260516120000_NetworkUsages.csv").write_text(
                "Timestamp,AppId\n2026-02-14T13:07:13,APP-1\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.5)
        return (0, "", "", 0.01)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(sp, "run_command", side_effect=fake_run):
        def is_file_impl(self):
            if str(self) == sp.SRUMECMD_DLL:
                return True
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = sp.parse(_req(fake_srudb, tmp_path))

    assert res.success
    notes = "\n".join(res.notes or [])
    assert "SrumECmd fallback" in notes
    assert "rows=0" in notes


# ===========================================================================
# Both engines fail
# ===========================================================================


def test_both_engines_fail_returns_fail_with_combined_audit(fake_srudb, tmp_path):
    """Plaso rc=2 + SrumECmd Linux 拒否 (rc!=0) → fail() で両方の audit string."""
    def fake_run(cmd, timeout=None, cwd=None):
        if cmd[0].endswith("psteal.py"):
            return (2, "", "esedb plugin not loadable", 0.01)
        if cmd[0] == "dotnet":
            # SrumECmd on Linux: "Non-Windows platforms not supported"
            return (1, "Non-Windows platforms not supported", "", 0.1)
        return (0, "", "", 0.01)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(sp, "run_command", side_effect=fake_run):
        def is_file_impl(self):
            if str(self) == sp.SRUMECMD_DLL:
                return True
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = sp.parse(_req(fake_srudb, tmp_path))

    assert res.success is False
    assert "Both engines failed" in (res.error or "")
    assert "Plaso esedb/srum failed: exit=2" in (res.error or "")
    # SrumECmd exit recorded too.
    assert "SrumECmd exit=1" in (res.error or "")


def test_plaso_fail_and_srumecmd_not_installed_returns_fail(fake_srudb, tmp_path):
    """Plaso fail + SrumECmd DLL absent → fail() with install hint."""
    def fake_run(cmd, timeout=None, cwd=None):
        if cmd[0].endswith("psteal.py"):
            return (2, "", "", 0.01)
        return (0, "", "", 0.01)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(sp, "run_command", side_effect=fake_run):
        def is_file_impl(self):
            if str(self) == sp.SRUMECMD_DLL:
                return False        # DLL absent
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = sp.parse(_req(fake_srudb, tmp_path))

    assert res.success is False
    assert "SrumECmd is not installed" in (res.error or "")


# ===========================================================================
# CSV→JSONL conversion exception (covered by altpf playbook)
# ===========================================================================


def test_plaso_conversion_exception_falls_through_to_srumecmd(fake_srudb, tmp_path):
    """psteal が CSV を作っても _convert_plaso が例外 → SrumECmd 試す。"""
    def fake_run(cmd, timeout=None, cwd=None):
        if cmd[0].endswith("psteal.py"):
            csv_path = pathlib.Path(cmd[cmd.index("-w") + 1])
            csv_path.write_text(
                "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
                "2026-02-14T13:07:13+00:00,Recorded,LOG,SRUM,App: 1,esedb/srum,SRUDB.dat,-\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.05)
        if cmd[0] == "dotnet":
            out_dir = pathlib.Path(cmd[cmd.index("--csv") + 1])
            (out_dir / "20260516120000_NetworkUsages.csv").write_text(
                "Timestamp,AppId\n2026-02-14T13:07:13,APP-1\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.5)
        return (0, "", "", 0.01)

    def boom(*args, **kwargs):
        raise ValueError("simulated Plaso conversion error")

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(sp, "run_command", side_effect=fake_run), \
         patch.object(sp, "_convert_plaso", side_effect=boom):
        def is_file_impl(self):
            if str(self) == sp.SRUMECMD_DLL:
                return True
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = sp.parse(_req(fake_srudb, tmp_path))

    assert res.success
    notes = "\n".join(res.notes or [])
    assert "SrumECmd fallback" in notes
    assert "conversion failed" in notes.lower() or "ValueError" in notes


# ===========================================================================
# Forensic audit invariant
# ===========================================================================


def test_audit_notes_include_engine_choice(fake_srudb, tmp_path):
    """Success path: notes は "Engine: Plaso psteal" を明記。"""
    fake_run, _ = _make_plaso_emit_csv(tmp_path)
    with patch.object(sp, "run_command", side_effect=fake_run):
        res = sp.parse(_req(fake_srudb, tmp_path, tz="Asia/Tokyo"))
    notes = "\n".join(res.notes or [])
    assert res.success
    assert "Engine: Plaso psteal" in notes
    assert "esedb/srum" in notes
    assert "Asia/Tokyo" in notes
