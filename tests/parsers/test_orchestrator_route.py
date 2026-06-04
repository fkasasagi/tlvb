"""Tests for parsers/orchestrator.py routing additions (Wave 8).

Covers:
  - The new $J / SRUDB.dat detectors registered in _DETECTORS.
  - _hayabusa_present() caching (called many times per run on a host
    where the binary doesn't exist — we don't want N filesystem stats).
  - input_mode / image_format error branches in `run()`.

Real subprocess execution of orchestrator.run() requires a populated
case DB + EZ Tools and is covered by docs/TEST_TIER0.md §14 (manual).
"""

from __future__ import annotations

import pathlib

import pytest

from parsers import orchestrator


# ---------------------------------------------------------------------------
# Detection table — Wave 8 additions
# ---------------------------------------------------------------------------


def test_usn_journal_detected_by_dollar_j(tmp_path):
    (tmp_path / "$J").write_bytes(b"")
    hits = orchestrator.detect(tmp_path)
    ids = {h.artifact_id for h in hits}
    assert "usn_journal" in ids


def test_usn_journal_alt_name_detected(tmp_path):
    (tmp_path / "USNJournal__J").write_bytes(b"")
    hits = orchestrator.detect(tmp_path)
    assert "usn_journal" in {h.artifact_id for h in hits}


def test_srum_detected_under_sru_dir(tmp_path):
    sru = tmp_path / "Windows" / "System32" / "sru"
    sru.mkdir(parents=True)
    (sru / "SRUDB.dat").write_bytes(b"")
    hits = orchestrator.detect(tmp_path)
    assert "srum" in {h.artifact_id for h in hits}


def test_hayabusa_skipped_when_binary_absent(tmp_path, monkeypatch):
    # Force the cached check to report "absent" regardless of the host.
    orchestrator._hayabusa_present.cache_clear()
    monkeypatch.setattr(orchestrator, "_hayabusa_present", lambda: False)
    (tmp_path / "Application.evtx").write_bytes(b"")
    hits = orchestrator.detect(tmp_path)
    ids = {h.artifact_id for h in hits}
    assert "evtx" in ids
    assert "hayabusa" not in ids


# ---------------------------------------------------------------------------
# input_mode routing
# ---------------------------------------------------------------------------


def test_run_rejects_image_mode_on_directory(tmp_path):
    dir_input = tmp_path / "evidence_tree"
    dir_input.mkdir()
    with pytest.raises(ValueError, match="requires a file"):
        orchestrator.run(
            case_id="TST", evidence_id="EV-001",
            input_path=dir_input, db_path=tmp_path / "x.duckdb",
            workspace=tmp_path / "ws",
            input_mode="image",
        )


def test_run_rejects_image_format_mismatch(tmp_path):
    # Build a tiny .raw file that won't have EWF magic.
    raw = tmp_path / "fake.raw"
    raw.write_bytes(b"\x00" * 32)
    with pytest.raises(ValueError, match="format mismatch"):
        orchestrator.run(
            case_id="TST", evidence_id="EV-001",
            input_path=raw, db_path=tmp_path / "x.duckdb",
            workspace=tmp_path / "ws",
            input_mode="image",
            image_format="ewf",
        )


def test_run_cdir_mode_skips_image_extractor(tmp_path):
    """input_mode=cdir on a directory must NOT call image_extractor.

    We can't run the full orchestrator (needs MFT etc.); instead we
    assert that the input-mode hint isn't dropped — done by checking
    that stage_input is what raises (no extractor branch taken).
    """
    import shutil
    # Empty dir → stage_input emits an empty extractions root; detector
    # returns no detections; orchestrator returns 0/0 succeeded.
    dir_input = tmp_path / "evidence_tree"
    dir_input.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    report = orchestrator.run(
        case_id="TST", evidence_id="EV-001",
        input_path=dir_input,
        db_path=tmp_path / "x.duckdb",
        workspace=workspace,
        input_mode="cdir",
    )
    # Reached past the image branch without raising; extract.log absent.
    assert not (workspace / "extract.log").exists()
    assert report.detections == 0


# ===========================================================================
# Wave 15 — prefix-tolerant detection
# ===========================================================================
#
# Collectors (TANAKA / KAPE-NTFS bundled, FastIR, ...) flatten trees and
# prepend `<drive>_` or `<user>_` tokens. The orchestrator now uses
# basename regex (parsers._collector_prefix) so the per-collector flavours
# all converge on the same Detection. These tests pin both the positive
# cases (plain + multiple prefix shapes) and the decoy rejects.
# ---------------------------------------------------------------------------


def _ids(hits):
    return {h.artifact_id for h in hits}


# --- mft ----

def test_mft_detected_plain_dollar_mft(tmp_path):
    (tmp_path / "$MFT").write_bytes(b"")
    assert "mft" in _ids(orchestrator.detect(tmp_path))


def test_mft_detected_with_drive_prefix_c(tmp_path):
    (tmp_path / "C_$MFT").write_bytes(b"")
    assert "mft" in _ids(orchestrator.detect(tmp_path))


def test_mft_detected_with_drive_prefix_d(tmp_path):
    (tmp_path / "D_$MFT").write_bytes(b"")
    assert "mft" in _ids(orchestrator.detect(tmp_path))


def test_mft_not_detected_for_decoy(tmp_path):
    (tmp_path / "My$MFT.txt").write_bytes(b"")
    (tmp_path / "$MFTmirr").write_bytes(b"")
    (tmp_path / "$MFT.bak").write_bytes(b"")
    assert "mft" not in _ids(orchestrator.detect(tmp_path))


def test_mft_plain_and_prefixed_dedup_per_path(tmp_path):
    # Both files should produce two Detections, not collapse into one.
    (tmp_path / "$MFT").write_bytes(b"")
    (tmp_path / "C_$MFT").write_bytes(b"")
    mft_hits = [h for h in orchestrator.detect(tmp_path) if h.artifact_id == "mft"]
    assert len(mft_hits) == 2


# --- usn_journal ----

def test_usn_detected_with_drive_prefix(tmp_path):
    (tmp_path / "C_$UsnJrnl-$J").write_bytes(b"")
    assert "usn_journal" in _ids(orchestrator.detect(tmp_path))


def test_usn_detected_dollarless_j_suffix(tmp_path):
    # WINDEV triage collector renders the `$UsnJrnl:$J` ADS as `$UsnJrnl_J`
    # (no `$` before the final J). Must still route to usn_journal.
    (tmp_path / "$UsnJrnl_J").write_bytes(b"")
    assert "usn_journal" in _ids(orchestrator.detect(tmp_path))


def test_usn_detected_legacy_alt_name(tmp_path):
    (tmp_path / "USNJournal__J").write_bytes(b"")
    assert "usn_journal" in _ids(orchestrator.detect(tmp_path))


def test_usn_not_detected_for_decoy(tmp_path):
    (tmp_path / "backup_$J.log").write_bytes(b"")
    (tmp_path / "$Journal").write_bytes(b"")
    assert "usn_journal" not in _ids(orchestrator.detect(tmp_path))


# --- shellbags ----

def test_shellbags_detected_plain_ntuser(tmp_path):
    reg = tmp_path / "Registry"
    reg.mkdir()
    (reg / "NTUSER.DAT").write_bytes(b"")
    assert "shellbags" in _ids(orchestrator.detect(tmp_path))


def test_shellbags_detected_with_user_prefix(tmp_path):
    reg = tmp_path / "Registry"
    reg.mkdir()
    (reg / "Tanaka_NTUSER.dat").write_bytes(b"")
    assert "shellbags" in _ids(orchestrator.detect(tmp_path))


def test_shellbags_detected_with_multiple_users(tmp_path):
    reg = tmp_path / "Registry"
    reg.mkdir()
    for u in ("Tanaka", "Saionji", "vagrant", "Default"):
        (reg / f"{u}_NTUSER.dat").write_bytes(b"")
    hits = [h for h in orchestrator.detect(tmp_path) if h.artifact_id == "shellbags"]
    # All four hives sit in the same parent dir → SBECmd processes them in
    # one shot, so we expect exactly one shellbags Detection.
    assert len(hits) == 1


def test_shellbags_detected_for_usrclass_prefix(tmp_path):
    reg = tmp_path / "Registry"
    reg.mkdir()
    (reg / "Tanaka_UsrClass.dat").write_bytes(b"")
    assert "shellbags" in _ids(orchestrator.detect(tmp_path))


def test_shellbags_decoy_log_not_matched(tmp_path):
    # NTUSER.DAT.LOG1/LOG2 must NOT trigger shellbags (they are transaction
    # logs, not the hive itself).
    reg = tmp_path / "Registry"
    reg.mkdir()
    (reg / "NTUSER.DAT.LOG1").write_bytes(b"")
    (reg / "Tanaka_NTUSER.dat.LOG2").write_bytes(b"")
    assert "shellbags" not in _ids(orchestrator.detect(tmp_path))


# --- browser_history ----

def test_browser_history_detected_plain_chromium(tmp_path):
    (tmp_path / "History").write_bytes(b"")
    assert "browser_history" in _ids(orchestrator.detect(tmp_path))


def test_browser_history_detected_with_user_prefix_chromium(tmp_path):
    (tmp_path / "Tanaka_Default_History").write_bytes(b"")
    assert "browser_history" in _ids(orchestrator.detect(tmp_path))


def test_browser_history_detected_plain_firefox(tmp_path):
    (tmp_path / "places.sqlite").write_bytes(b"")
    assert "browser_history" in _ids(orchestrator.detect(tmp_path))


def test_browser_history_detected_with_user_prefix_firefox(tmp_path):
    (tmp_path / "Tanaka_o7yzgq90.default-release_places.sqlite").write_bytes(b"")
    assert "browser_history" in _ids(orchestrator.detect(tmp_path))


def test_browser_history_decoy_not_matched(tmp_path):
    # `history.log` (lower-case + extension) is not a Chromium History DB
    # and must not be picked up.
    (tmp_path / "history.log").write_bytes(b"")
    (tmp_path / "My_places.sqlite.bak").write_bytes(b"")
    assert "browser_history" not in _ids(orchestrator.detect(tmp_path))


# --- combined TANAKA-like layout (sanity smoke for the full set) ----

def test_tanaka_flatten_layout_detects_all_four(tmp_path):
    ntfs = tmp_path / "NTFS"; ntfs.mkdir()
    reg = tmp_path / "Registry"; reg.mkdir()
    web = tmp_path / "Web" / "Chrome"; web.mkdir(parents=True)
    fx  = tmp_path / "Web" / "Firefox"; fx.mkdir(parents=True)
    (ntfs / "C_$MFT").write_bytes(b"")
    (ntfs / "C_$UsnJrnl-$J").write_bytes(b"")
    (reg / "Tanaka_NTUSER.dat").write_bytes(b"")
    (reg / "Tanaka_UsrClass.dat").write_bytes(b"")
    (web / "Tanaka_Default_History").write_bytes(b"")
    (fx  / "Tanaka_o7yz_places.sqlite").write_bytes(b"")
    ids = _ids(orchestrator.detect(tmp_path))
    assert {"mft", "usn_journal", "shellbags", "browser_history"} <= ids
