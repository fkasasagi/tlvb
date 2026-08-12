"""Tests for the Plaso psteal fallback path in prefetch_parser.

altpf primary は別ファイル (test_altpf_csv_convert.py) でカバー。
ここでは psteal.py 単段呼出のコマンド構築 + 動作を保証する:

  - altpf が無い / 失敗した時に psteal path に正しく落ちる
  - psteal コマンドの引数列が `--source` `--parsers prefetch` `-o dynamic`
    `-w <csv>` `-q` を必ず含む
  - case timezone が非 UTC のとき `--output_time_zone <tz>` を追加、
    UTC のとき追加しない
  - 旧 log2timeline.py / psort.py の二段呼出に戻ってしまっていないか
    (regression: Wave 12 で 1 段化したのを保証)

Real psteal execution は CLI E2E 検証 (F1-01-REAL-PSTEAL ケース、969 rows
/ 10.57s) で別途確認済。ここでは subprocess を mock して引数文字列を
読み取る方針。
"""

from __future__ import annotations

import pathlib
from unittest.mock import patch

import pytest

from parsers.base import ParseRequest
from parsers import prefetch_parser as pp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_pf_dir(tmp_path):
    """Minimal Prefetch dir — content doesn't matter for the fallback
    code path since we mock run_command, but `parse()` validates that
    the input is an existing directory upfront."""
    d = tmp_path / "Prefetch"
    d.mkdir()
    (d / "DUMMY.EXE-12345678.pf").write_bytes(b"\x00" * 16)
    return d


def _req(input_path: pathlib.Path, out: pathlib.Path,
         tz: str = "UTC") -> ParseRequest:
    return ParseRequest(
        input_path=input_path, output_dir=out,
        case_id="T", evidence_id="EV",
        timezone=tz, timeout_seconds=60,
    )


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


def _capture_psteal_cmd(fake_pf_dir: pathlib.Path, out: pathlib.Path,
                        tz: str = "UTC") -> list[str]:
    """Force fallback path (altpf binary absent), capture the psteal
    subprocess argv via run_command mock. Return the captured list."""
    captured: list[list[str]] = []

    def fake_run_command(cmd, timeout=None, cwd=None):
        captured.append(list(cmd))
        # psteal "succeeds" — write a minimal valid CSV so the parser's
        # success-path code is executed. We don't need rich content.
        for c in cmd:
            if isinstance(c, str) and c.endswith("prefetch_plaso.csv"):
                pathlib.Path(c).write_text(
                    "datetime,timestamp_desc,source,source_long,message,"
                    "parser,display_name,tag\n",
                    encoding="utf-8",
                )
        return (0, "", "", 0.1)

    with patch.object(pp, "_altpf_sha256", return_value=None), \
         patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(pp, "run_command", side_effect=fake_run_command):
        # is_file: altpf binary path → False; everything else (including the
        # CSV we wrote above) → real implementation.
        real_is_file = pathlib.Path.is_file.__wrapped__ if hasattr(
            pathlib.Path.is_file, "__wrapped__") else None

        def is_file_impl(self):
            if str(self) == pp.ALTPF_BIN:
                return False
            # Delegate to real os.path.isfile for everything else.
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl

        res = pp.parse(_req(fake_pf_dir, out, tz=tz))

    assert res.success, f"parse should succeed (mocked psteal), got: {res.error}"
    # The 1st captured invocation is the psteal call (no altpf, no log2timeline).
    return captured[0]


def test_psteal_command_uses_single_step_psteal(tmp_path, fake_pf_dir):
    """psteal.py を 1 回だけ呼ぶ (旧 log2timeline+psort 2 段 ではない)。"""
    cmd = _capture_psteal_cmd(fake_pf_dir, tmp_path)
    assert cmd[0] == "psteal.py", f"first arg must be psteal.py, got {cmd[0]}"
    # Regression: old impl invoked these — they must not appear.
    assert "log2timeline.py" not in cmd
    assert "psort.py" not in cmd


def test_psteal_command_includes_required_flags(tmp_path, fake_pf_dir):
    cmd = _capture_psteal_cmd(fake_pf_dir, tmp_path)
    cmd_str = " ".join(cmd)
    assert "--source" in cmd
    assert "--parsers" in cmd and "prefetch" in cmd
    assert "-o" in cmd and "dynamic" in cmd
    assert "-w" in cmd
    assert "-q" in cmd, "should run quietly to keep stdout/stderr small"


def test_psteal_command_targets_correct_input(tmp_path, fake_pf_dir):
    cmd = _capture_psteal_cmd(fake_pf_dir, tmp_path)
    # --source <path> must point at the input dir we passed.
    idx = cmd.index("--source")
    assert cmd[idx + 1] == str(fake_pf_dir)


def test_psteal_command_writes_to_expected_csv(tmp_path, fake_pf_dir):
    cmd = _capture_psteal_cmd(fake_pf_dir, tmp_path)
    idx = cmd.index("-w")
    out_path = pathlib.Path(cmd[idx + 1])
    assert out_path.parent == tmp_path
    assert out_path.name == "prefetch_plaso.csv"


# ---------------------------------------------------------------------------
# TZ propagation
# ---------------------------------------------------------------------------


def test_psteal_omits_output_time_zone_for_utc(tmp_path, fake_pf_dir):
    """UTC は psteal 既定なので明示的に渡さない (Wave 12 の決め)。"""
    cmd = _capture_psteal_cmd(fake_pf_dir, tmp_path, tz="UTC")
    assert "--output_time_zone" not in cmd


def test_psteal_propagates_non_utc_timezone(tmp_path, fake_pf_dir):
    """Asia/Tokyo / America/New_York 等は `--output_time_zone <tz>` で
    psteal に伝播する (Issue #19)。"""
    for tz in ("Asia/Tokyo", "America/New_York", "Europe/London"):
        cmd = _capture_psteal_cmd(fake_pf_dir, tmp_path, tz=tz)
        assert "--output_time_zone" in cmd, f"missing for tz={tz}"
        idx = cmd.index("--output_time_zone")
        assert cmd[idx + 1] == tz, f"got {cmd[idx + 1]!r} for tz={tz}"


def test_psteal_uses_long_form_flag_not_short_z(tmp_path, fake_pf_dir):
    """Regression: psort/psteal 20240308+ では `-z` 短形式が廃止。
    `--output_time_zone` 長形式のみ使う。"""
    cmd = _capture_psteal_cmd(fake_pf_dir, tmp_path, tz="Asia/Tokyo")
    assert "-z" not in cmd, "must use --output_time_zone (long form) not -z"


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_psteal_fallback_notes_record_engine_choice(tmp_path, fake_pf_dir):
    """parse_results.notes に "Plaso psteal fallback" が記録される
    (forensic 監査: どちらの engine で parse したか後追い可能)。"""
    captured: list[list[str]] = []

    def fake_run_command(cmd, timeout=None, cwd=None):
        captured.append(list(cmd))
        for c in cmd:
            if isinstance(c, str) and c.endswith("prefetch_plaso.csv"):
                pathlib.Path(c).write_text(
                    "datetime,timestamp_desc,source,source_long,message,"
                    "parser,display_name,tag\n",
                    encoding="utf-8",
                )
        return (0, "", "", 0.1)

    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(pp, "run_command", side_effect=fake_run_command):
        def is_file_impl(self):
            if str(self) == pp.ALTPF_BIN:
                return False
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = pp.parse(_req(fake_pf_dir, tmp_path, tz="Asia/Tokyo"))

    notes = "\n".join(res.notes or [])
    assert "psteal" in notes.lower()
    assert "altpf" in notes.lower()    # altpf was skipped/missing — recorded for audit
    assert "asia/tokyo" in notes.lower()
