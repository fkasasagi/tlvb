"""Regression: psteal が既存 -w ファイルで reject する問題。

Plaso 20240308+ の `psteal.py` は `-w OUTPUT_FILE` で既存ファイルが
あると以下のエラーで rc=1 終了する:

    ERROR: Output file: <path> already exists.

つまり同じケースで再 parse を流すと 2 回目以降 silent に失敗する
(以前 Plaso 経路で 1404 events 取れた SRUM が 2 回目では fail に化け、
TANAKA ケースの WebUI 再 parse で "FAIL exit status 2" が出た事例)。

修正は 2 箇所:
  - parsers/srum_parser.py: plaso_csv 起動前 unlink
  - parsers/prefetch_parser.py: plaso_csv 起動前 unlink (fallback path)

ここではその 2 箇所の前処理が確実に走ることを確認する。
"""

from __future__ import annotations

import pathlib
from unittest.mock import patch

import pytest

from parsers.base import ParseRequest
from parsers import prefetch_parser as pp
from parsers import srum_parser as sp


def _req(input_path: pathlib.Path, out: pathlib.Path) -> ParseRequest:
    return ParseRequest(
        input_path=input_path, output_dir=out,
        case_id="T", evidence_id="EV",
        timezone="UTC", timeout_seconds=60,
    )


# ---------------------------------------------------------------------------
# srum_parser: Plaso primary は既存ファイルを削除してから psteal を呼ぶ
# ---------------------------------------------------------------------------


def test_srum_plaso_unlinks_existing_csv_before_psteal(tmp_path):
    fake_srudb = tmp_path / "SRUDB.dat"
    fake_srudb.write_bytes(b"\x00" * 16)
    out_dir = tmp_path / "srum_out"
    out_dir.mkdir()

    # 既存 srum_plaso.csv を仕掛ける (前回試行の残骸を模す)
    existing_csv = out_dir / "srum_plaso.csv"
    existing_csv.write_text("stale,header\nstale,row\n", encoding="utf-8")
    pre_size = existing_csv.stat().st_size

    captured: list[list[str]] = []

    def fake_run(cmd, timeout=None):
        captured.append(list(cmd))
        if cmd[0].endswith("psteal.py"):
            # psteal は -w 既存で本来 rc=1 を返すが、ここではテスト用に
            # 「parser は事前 unlink した状態で psteal を呼ぶ」のを検証
            # するので、unlink 済みなら新たに書ける、を再現する。
            csv_path = pathlib.Path(cmd[cmd.index("-w") + 1])
            assert not csv_path.exists(), \
                "psteal を呼ぶ前に既存 csv が削除されていない (regression)"
            csv_path.write_text(
                "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
                "2026-02-14T13:07:13+00:00,Recorded,LOG,SRUM,App: 1,esedb/srum,SRUDB.dat,-\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.05)
        return (0, "", "", 0.01)

    with patch.object(sp, "run_command", side_effect=fake_run):
        res = sp.parse(_req(fake_srudb, out_dir))

    assert res.success, f"再 parse で失敗 (regression): {res.error}"
    # psteal が確かに呼ばれた
    assert any(c[0].endswith("psteal.py") for c in captured)


# ---------------------------------------------------------------------------
# prefetch_parser: altpf 不在で fallback の Plaso psteal が既存削除する
# ---------------------------------------------------------------------------


def test_prefetch_plaso_fallback_unlinks_existing_csv(tmp_path):
    fake_pf_dir = tmp_path / "Prefetch"
    fake_pf_dir.mkdir()
    (fake_pf_dir / "DUMMY.EXE-12345678.pf").write_bytes(b"\x00" * 16)
    out_dir = tmp_path / "pf_out"
    out_dir.mkdir()

    # 既存 prefetch_plaso.csv を仕掛ける
    existing_csv = out_dir / "prefetch_plaso.csv"
    existing_csv.write_text("stale\n", encoding="utf-8")

    captured: list[list[str]] = []

    def fake_run(cmd, timeout=None):
        captured.append(list(cmd))
        if cmd[0].endswith("psteal.py"):
            csv_path = pathlib.Path(cmd[cmd.index("-w") + 1])
            assert not csv_path.exists(), \
                "psteal 起動前に既存 csv が削除されていない (regression)"
            csv_path.write_text(
                "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
                "2026-02-14T13:07:13+00:00,Last Connection Time,LOG,Prefetch,A.exe,prefetch,/A.pf,-\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.05)
        return (0, "", "", 0.01)

    # altpf 不在 → Plaso fallback に直行
    with patch("pathlib.Path.is_file", autospec=True) as is_file, \
         patch.object(pp, "run_command", side_effect=fake_run):
        def is_file_impl(self):
            if str(self) == pp.ALTPF_BIN:
                return False
            import os
            return os.path.isfile(str(self))
        is_file.side_effect = is_file_impl
        res = pp.parse(_req(fake_pf_dir, out_dir))

    assert res.success, f"prefetch 再 parse 失敗 (regression): {res.error}"
    assert any(c[0].endswith("psteal.py") for c in captured)


# ---------------------------------------------------------------------------
# 単発: 既存ファイル無い場合は unlink を skip (StopIteration 等で死なない)
# ---------------------------------------------------------------------------


def test_srum_plaso_skips_unlink_when_csv_absent(tmp_path):
    fake_srudb = tmp_path / "SRUDB.dat"
    fake_srudb.write_bytes(b"\x00" * 16)
    out_dir = tmp_path / "srum_out"
    out_dir.mkdir()
    # 既存 csv 無し

    def fake_run(cmd, timeout=None):
        if cmd[0].endswith("psteal.py"):
            csv_path = pathlib.Path(cmd[cmd.index("-w") + 1])
            csv_path.write_text(
                "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
                "2026-02-14T13:07:13+00:00,Recorded,LOG,SRUM,App: 1,esedb/srum,SRUDB.dat,-\n",
                encoding="utf-8",
            )
            return (0, "", "", 0.05)
        return (0, "", "", 0.01)

    with patch.object(sp, "run_command", side_effect=fake_run):
        res = sp.parse(_req(fake_srudb, out_dir))

    assert res.success
