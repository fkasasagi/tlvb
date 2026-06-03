"""Tests for parsers/image_extractor.py (Issue #23).

No real disk image is required — these exercise the format-detection +
extract.log shape + helper functions that don't need ewfmount / fls /
icat. End-to-end tests with a real NTFS volume live in
docs/TEST_TIER0.md §13 (manual, ~15 min).
"""

from __future__ import annotations

import dataclasses
import json
import pathlib

from parsers import image_extractor


# ---------------------------------------------------------------------------
# detect_image — magic bytes + extension matrix
# ---------------------------------------------------------------------------


def _write_bytes(path: pathlib.Path, payload: bytes) -> pathlib.Path:
    path.write_bytes(payload + b"\x00" * (64 - len(payload)))
    return path


def test_detect_image_ewf_by_magic(tmp_path):
    # Magic wins over extension: a renamed E01 with .raw still detects as EWF.
    p = _write_bytes(tmp_path / "evidence.raw", image_extractor._MAGIC_EWF)
    assert image_extractor.detect_image(p) == "ewf"


def test_detect_image_ewf_v2(tmp_path):
    p = _write_bytes(tmp_path / "evidence.E01", image_extractor._MAGIC_EWF2)
    assert image_extractor.detect_image(p) == "ewf"


def test_detect_image_vmdk_by_magic(tmp_path):
    p = _write_bytes(tmp_path / "ambiguous.bin", image_extractor._MAGIC_VMDK)
    assert image_extractor.detect_image(p) == "vmdk"


def test_detect_image_vhdx_by_magic(tmp_path):
    p = _write_bytes(tmp_path / "ambiguous.bin", image_extractor._MAGIC_VHDX)
    assert image_extractor.detect_image(p) == "vhdx"


def test_detect_image_raw_by_extension(tmp_path):
    # No usable magic — extension alone classifies as raw.
    p = _write_bytes(tmp_path / "disk.dd", b"\x00" * 16)
    assert image_extractor.detect_image(p) == "raw"


def test_detect_image_vhd_by_extension(tmp_path):
    # VHD has a footer-based signature; header detection falls back to ext.
    p = _write_bytes(tmp_path / "disk.vhd", b"\x00" * 16)
    assert image_extractor.detect_image(p) == "vhd"


def test_detect_image_unknown_returns_none(tmp_path):
    p = _write_bytes(tmp_path / "notes.txt", b"hello")
    assert image_extractor.detect_image(p) is None


def test_detect_image_missing_path_returns_none(tmp_path):
    assert image_extractor.detect_image(tmp_path / "nope.E01") is None


def test_is_image_matches_detect_image(tmp_path):
    e01 = _write_bytes(tmp_path / "a.E01", image_extractor._MAGIC_EWF)
    txt = _write_bytes(tmp_path / "a.txt", b"hi")
    assert image_extractor.is_image(e01) is True
    assert image_extractor.is_image(txt) is False


# ---------------------------------------------------------------------------
# extract.log schema — JSONL header + records
# ---------------------------------------------------------------------------


def test_extract_record_dataclass_round_trips_to_json():
    rec = image_extractor.ExtractRecord(
        target="ntfs/$MFT",
        status="ok",
        partition=0,
        inum="0",
        sha256="deadbeef" * 8,
        bytes=27648,
        extracted_path="/tmp/work/extracted/part00/ntfs/$MFT",
    )
    body = json.dumps(dataclasses.asdict(rec))
    parsed = json.loads(body)
    assert parsed["target"] == "ntfs/$MFT"
    assert parsed["status"] == "ok"
    assert parsed["inum"] == "0"          # Regression: $MFT inum is "0" — Issue #23
    assert parsed["bytes"] == 27648


def test_triage_path_list_covers_key_artifacts():
    """Wave 18b: labels now mirror the NTFS source path so the staging
    tree preserves the original Windows directory structure (needed so
    the orchestrator's `**/System32/Tasks/**` and friends still match
    after extraction). Pin the new shape."""
    targets = {label for _path, label in image_extractor._TRIAGE_PATHS}
    expected = {
        "$MFT", "$J", "$LogFile",
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SOFTWARE",
        "Windows/System32/config/SAM",
        "Windows/System32/config/SECURITY",
        "Windows/System32/config/DEFAULT",
        "Windows/AppCompat/Programs/Amcache.hve",
        "Windows/Prefetch", "Windows/System32/winevt/Logs",
        "Windows/System32/Tasks",
        "Windows/System32/sru/SRUDB.dat",
    }
    missing = expected - targets
    assert not missing, f"triage paths regression: {missing}"


def test_per_user_triage_includes_browser_history():
    labels = {label for _path, label in image_extractor._PER_USER_TRIAGE}
    # Wave 18b: per-user labels also mirror source paths now.
    assert "NTUSER.DAT" in labels
    assert "AppData/Local/Microsoft/Edge/User Data/Default/History" in labels
    assert "AppData/Local/Google/Chrome/User Data/Default/History" in labels


# ===========================================================================
# Wave 18 — directory triage regression
# ===========================================================================
#
# Earlier versions of image_extractor had three coupled bugs that made
# directory triage paths (Prefetch / winevt/Logs / Tasks / Users) extract
# zero files:
#   X. _is_directory() only looked at line 0 of istat output, so every
#      NTFS dir came back as "not a directory" → _icat_to_file ran on the
#      dir inum and produced a ~200B index-record blob.
#   Y. _extract_directory() and _list_dir() passed the textual ntfs_path
#      to fls; fls treats that as a second image-file argument and errors
#      out with "raw_open: image ... No such file or directory".
#   Z. recyclebin / win10timeline triage paths were missing entirely.
# This block pins all three so a regression on any one surfaces fast.
# ---------------------------------------------------------------------------


def test_is_directory_recognises_allocated_directory(monkeypatch):
    """istat puts 'Allocated Directory' on line 3-4, not line 0."""
    istat_out = (
        "MFT Entry Header Values:\n"
        "Entry: 21866        Sequence: 10\n"
        "$LogFile Sequence Number: 42968407519\n"
        "Allocated Directory\n"
        "Links: 1\n"
    )
    monkeypatch.setattr(image_extractor, "run_command",
                        lambda cmd, timeout=None: (0, istat_out, "", 0.01))
    assert image_extractor._is_directory("/x", 0, "21866", 30) is True


def test_is_directory_recognises_deleted_directory(monkeypatch):
    out = (
        "MFT Entry Header Values:\n"
        "Entry: 999  Sequence: 1\n"
        "$LogFile Sequence Number: 0\n"
        "Deleted Directory\n"
    )
    monkeypatch.setattr(image_extractor, "run_command",
                        lambda cmd, timeout=None: (0, out, "", 0.01))
    assert image_extractor._is_directory("/x", 0, "999", 30) is True


def test_is_directory_returns_false_for_regular_file(monkeypatch):
    out = (
        "MFT Entry Header Values:\n"
        "Entry: 100\n"
        "$LogFile Sequence Number: 12345\n"
        "Allocated File\n"
    )
    monkeypatch.setattr(image_extractor, "run_command",
                        lambda cmd, timeout=None: (0, out, "", 0.01))
    assert image_extractor._is_directory("/x", 0, "100", 30) is False


def test_extract_directory_passes_inum_to_fls(monkeypatch):
    """fls must receive the directory INUM, not the textual ntfs_path."""
    captured: list[list[str]] = []

    def fake_run(cmd, timeout=None):
        captured.append(list(cmd))
        if cmd[0] == "fls":
            # Return a small recursive listing so the loop has something to walk.
            return (0,
                    "r/r 7739-128-4:\tAutomaticDestinations/sample.ms\n",
                    "", 0.01)
        # _icat_to_file: pretend it succeeded with a tiny payload.
        return (0, "", "", 0.01)

    monkeypatch.setattr(image_extractor, "run_command", fake_run)
    monkeypatch.setattr(image_extractor, "_icat_to_file",
                        lambda *a, **k: image_extractor.ExtractRecord(
                            target=a[5], status="ok", partition=a[6], inum=a[2],
                            bytes=64))
    import tempfile, pathlib as _pl
    with tempfile.TemporaryDirectory() as t:
        dest = _pl.Path(t) / "recent"
        rec = image_extractor._extract_directory(
            "/x", 0, "Users/mhill/AppData/Roaming/Microsoft/Windows/Recent",
            dest, "lnk_jumplists/Recent", 0, "7734", 30,
        )
    assert rec.status == "ok"
    # The first call should be fls; the last positional arg is the INUM
    # string, NOT the path. This is the Wave 18 regression check.
    fls_cmd = [c for c in captured if c[0] == "fls"][0]
    assert fls_cmd[-1] == "7734", \
        f"fls received {fls_cmd[-1]!r}; expected the inum '7734'"


def test_list_dir_ifinds_first_then_fls_by_inum(monkeypatch):
    """_list_dir must resolve path → inum before calling fls."""
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):
        calls.append(list(cmd))
        if cmd[0] == "ifind":
            return (0, "10240\n", "", 0.01)
        if cmd[0] == "fls":
            # Mix of dir + file rows; -D filter is best-effort, regex pins
            # to "d/" so files must be excluded.
            return (0,
                    "d/d 11525-128-1:\tmhill\n"
                    "d/d 11526-128-1:\tAdministrator\n"
                    "r/r 11528-128-1:\tdesktop.ini\n",
                    "", 0.01)
        return (0, "", "", 0.01)

    monkeypatch.setattr(image_extractor, "run_command", fake_run)
    names = image_extractor._list_dir("/x", 0, "Users", 30)
    assert names == ["Administrator", "mhill"]
    # ifind goes first to translate path → inum.
    assert calls[0][0] == "ifind"
    # fls is invoked with the inum, never the path.
    fls_calls = [c for c in calls if c[0] == "fls"]
    assert fls_calls and fls_calls[0][-1] == "10240"


def test_triage_path_includes_recyclebin():
    targets = {label for _path, label in image_extractor._TRIAGE_PATHS}
    assert "$Recycle.Bin" in targets, \
        "Wave 18: $Recycle.Bin must be in the system triage list"


def test_per_user_triage_includes_win10timeline():
    labels = {label for _path, label in image_extractor._PER_USER_TRIAGE}
    assert "AppData/Local/ConnectedDevicesPlatform" in labels, \
        "Wave 18: ConnectedDevicesPlatform must be in the per-user triage list"


# ---------------------------------------------------------------------------
# Wave 20d: registry hive transaction log siblings (amcache + shimcache fix)
# ---------------------------------------------------------------------------


def test_triage_paths_include_system_hive_logs():
    """AmcacheParser / AppCompatCacheParser refuse to parse a dirty hive
    when LOG1/LOG2 are missing ("Registry hive is dirty and no transaction
    logs were found in the same directory! ... Aborting!!"). They MUST be
    extracted as siblings of the hive."""
    targets = {label for _path, label in image_extractor._TRIAGE_PATHS}
    for hive in ("SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"):
        for ext in (".LOG1", ".LOG2"):
            label = f"Windows/System32/config/{hive}{ext}"
            assert label in targets, \
                f"Wave 20d: {label} must be in triage list (dirty-hive fix)"


def test_triage_paths_include_amcache_logs():
    targets = {label for _path, label in image_extractor._TRIAGE_PATHS}
    for ext in (".LOG1", ".LOG2"):
        label = f"Windows/AppCompat/Programs/Amcache.hve{ext}"
        assert label in targets, \
            f"Wave 20d: {label} must be in triage list (amcache dirty-hive fix)"


def test_per_user_triage_includes_ntuser_logs():
    labels = {label for _path, label in image_extractor._PER_USER_TRIAGE}
    for ext in (".LOG1", ".LOG2"):
        assert f"NTUSER.DAT{ext}" in labels
        assert f"AppData/Local/Microsoft/Windows/UsrClass.dat{ext}" in labels


# ---------------------------------------------------------------------------
# Wave 20d: $UsnJrnl:$J ADS resolution + sparse extraction
# ---------------------------------------------------------------------------


def test_triage_paths_include_usnjrnl_ads():
    paths = {ntfs_path for ntfs_path, _label in image_extractor._TRIAGE_PATHS}
    assert "$Extend/$UsnJrnl:$J" in paths, \
        "Wave 20d: $J ADS path syntax must remain in triage list (icat resolves it)"


def test_resolve_ads_finds_j_stream_in_istat_table(monkeypatch):
    """Wave 20d: `_resolve_ads` walks the istat attribute table and returns
    the icat-ready ``<inum>-128-<attr_id>`` spec. For $UsnJrnl, the J ADS is
    typically the second of two $DATA entries (after $Max), with attr_id
    matching whatever NTFS assigned when the journal was created.
    """
    sample_istat = """\
MFT Entry Header Values:
Entry: 55815        Sequence: 5
$LogFile Sequence Number: 12345
Allocated File

$STANDARD_INFORMATION Attribute Values:

$FILE_NAME Attribute Values:
    Name: $UsnJrnl

Attributes:
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
Type: $ATTRIBUTE_LIST (32-35)   Name: N/A   Resident   size: 168
Type: $FILE_NAME (48-1)   Name: N/A   Resident   size: 82
Type: $DATA (128-86)   Name: $Max   Resident   size: 32
Type: $DATA (128-87)   Name: $J   Non-Resident, Sparse   size: 9031712080
"""
    def fake_run(cmd, timeout=None):  # noqa: ARG001
        return 0, sample_istat, "", 0.1
    monkeypatch.setattr(image_extractor, "run_command", fake_run)
    spec = image_extractor._resolve_ads(
        raw_device="/dev/fake", offset_bytes=0, inum="55815",
        ads_name="$J", timeout=30,
    )
    assert spec == "55815-128-87"


def test_resolve_ads_returns_max_when_requested(monkeypatch):
    sample = (
        "Attributes:\n"
        "Type: $DATA (128-86)   Name: $Max   Resident   size: 32\n"
        "Type: $DATA (128-87)   Name: $J   Non-Resident, Sparse\n"
    )
    def fake_run(cmd, timeout=None):  # noqa: ARG001
        return 0, sample, "", 0.1
    monkeypatch.setattr(image_extractor, "run_command", fake_run)
    spec = image_extractor._resolve_ads(
        raw_device="/dev/fake", offset_bytes=0, inum="55815",
        ads_name="$Max", timeout=30,
    )
    assert spec == "55815-128-86"


def test_resolve_ads_returns_none_for_missing_stream(monkeypatch):
    sample = (
        "Attributes:\n"
        "Type: $DATA (128-1)   Name: N/A   Resident   size: 100\n"
    )
    def fake_run(cmd, timeout=None):  # noqa: ARG001
        return 0, sample, "", 0.1
    monkeypatch.setattr(image_extractor, "run_command", fake_run)
    spec = image_extractor._resolve_ads(
        raw_device="/dev/fake", offset_bytes=0, inum="42",
        ads_name="$NonExistent", timeout=30,
    )
    assert spec is None


def test_resolve_ads_returns_none_on_istat_failure(monkeypatch):
    def fake_run(cmd, timeout=None):  # noqa: ARG001
        return 1, "", "istat: error opening image", 0.1
    monkeypatch.setattr(image_extractor, "run_command", fake_run)
    spec = image_extractor._resolve_ads(
        raw_device="/dev/fake", offset_bytes=0, inum="55815",
        ads_name="$J", timeout=30,
    )
    assert spec is None


def test_icat_to_file_sparse_creates_sparse_file(tmp_path, monkeypatch):
    """Wave 20d: sparse-aware writer must (a) preserve apparent size,
    (b) leave zero blocks as filesystem holes (st_blocks < st_size/512),
    (c) compute SHA-256 over the full byte stream including holes.
    """
    import subprocess as _sp
    import hashlib as _h

    # Synthesise a 192 KiB payload: 64 KiB zero | 64 KiB data | 64 KiB zero
    BLOCK = 64 * 1024
    payload = b"\x00" * BLOCK + b"X" * BLOCK + b"\x00" * BLOCK
    expected_sha = _h.sha256(payload).hexdigest()

    class FakePopen:
        def __init__(self, *args, **kwargs):  # noqa: ARG002
            self.stdout = type("S", (), {
                "_buf": payload,
                "_pos": 0,
                "read": lambda self_, n: (
                    self_._buf[self_._pos:self_._pos + n]
                    if self_._pos < len(self_._buf) else b""
                ),
            })()
            # Trick: bump _pos as read is called via closure
            data = {"pos": 0}
            def reader(n):
                p = data["pos"]
                chunk = payload[p:p + n]
                data["pos"] = p + len(chunk)
                return chunk
            self.stdout.read = reader  # type: ignore[assignment]
            self.stderr = type("E", (), {"read": lambda self_: b""})()
            self.returncode = 0
        def wait(self, timeout=None):  # noqa: ARG002
            return 0
        def kill(self):
            pass

    monkeypatch.setattr(_sp, "Popen", FakePopen)
    monkeypatch.setattr(image_extractor.subprocess, "Popen", FakePopen)

    dest = tmp_path / "J_sparse.bin"
    rec = image_extractor._icat_to_file_sparse(
        raw_device="/dev/fake", offset_bytes=0,
        attr_spec="55815-128-87", dest=dest, label="$J",
        partition=0, timeout=10,
    )
    assert rec.status == "ok"
    assert rec.bytes == len(payload)
    assert rec.sha256 == expected_sha
    # Apparent size preserved.
    st = dest.stat()
    assert st.st_size == len(payload)
    # Sparse: actual block usage strictly less than apparent size (the two
    # 64 KiB zero blocks should be holes). On filesystems that pack small
    # writes into the same block this can be VERY low; we just need it
    # below the apparent-size floor to prove sparseness.
    assert st.st_blocks * 512 < st.st_size, (
        f"file is not sparse: blocks={st.st_blocks * 512}, size={st.st_size}"
    )


# ---------------------------------------------------------------------------
# GPT partition enumeration — modern Windows NTFS is "Basic data partition"
# ---------------------------------------------------------------------------
#
# Regression: _enumerate_partitions keyed off the literal "NTFS" in the mmls
# description, but GPT disks (every modern Windows image) label the OS volume
# "Basic data partition". The mismatch made it fall back to offset 0 and
# extract zero files. It also misread the START column as bytes when mmls
# emits 512-byte sectors. Pin both.

_GPT_MMLS = """\
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Size    Description
000:  Meta      0000000000   0000000000   0000000001   0000B   Safety Table
001:  -------   0000000000   0000002047   0000002048   0001M   Unallocated
002:  Meta      0000000001   0000000001   0000000001   0000B   GPT Header
003:  Meta      0000000002   0000000033   0000000032   0016K   Partition Table
004:  000       0000002048   0000206847   0000204800   0100M   EFI system partition
005:  001       0000206848   0000239615   0000032768   0016M   Microsoft reserved partition
006:  002       0000239616   0124751871   0124512256   0059G   Basic data partition
007:  003       0124751872   0125825023   0001073152   0524M
"""


def test_enumerate_partitions_gpt_basic_data(monkeypatch):
    monkeypatch.setattr(image_extractor, "run_command",
                        lambda cmd, timeout=None: (0, _GPT_MMLS, "", 0.01))
    parts = image_extractor._enumerate_partitions("/dev/fake")
    # Keep the Windows NTFS "Basic data partition" (slot 2) and the
    # unlabelled recovery volume (slot 3); drop EFI / MSR / metadata /
    # unallocated. Offsets are start_sector * 512 so the downstream `// 512`
    # recovers the correct `fls -o` sector (239616, not 239616/512).
    assert parts == [(0, 239616 * 512), (1, 124751872 * 512)]


_MBR_MMLS = """\
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0020971519   0020969472   NTFS / exFAT (0x07)
"""


def test_enumerate_partitions_mbr_ntfs(monkeypatch):
    monkeypatch.setattr(image_extractor, "run_command",
                        lambda cmd, timeout=None: (0, _MBR_MMLS, "", 0.01))
    parts = image_extractor._enumerate_partitions("/dev/fake")
    assert parts == [(0, 2048 * 512)]


def test_enumerate_partitions_falls_back_when_mmls_fails(monkeypatch):
    monkeypatch.setattr(image_extractor, "run_command",
                        lambda cmd, timeout=None: (1, "", "mmls: cannot open", 0.01))
    assert image_extractor._enumerate_partitions("/dev/fake") == [(0, 0)]
