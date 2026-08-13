"""Velociraptor offline-collector layout support.

Velociraptor stores collected files under ``uploads/<accessor>/`` and
percent-escapes the characters that cannot appear in a Windows filename:

    uploads/auto/C%3A/Windows/System32/config/SYSTEM
    uploads/ntfs/%5C%5C.%5CC%3A/$MFT
    uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J

Only the drive/device component is escaped for most artefacts, so basename
matching already works. The exception is the USN journal, whose real NTFS
name is the alternate data stream ``$UsnJrnl:$J`` — the colon is escaped
into ``%3A`` and the basename no longer matches.

Docs: https://docs.velociraptor.app/docs/deployment/offline_collections/collection_data/
"""

from __future__ import annotations

import pathlib

import pytest

from parsers import orchestrator, usn_journal_parser
from parsers._collector_prefix import USN_J_RE, is_usn_journal

VELO_DEVICE = "%5C%5C.%5CC%3A"
VELO_DRIVE = "C%3A"


def _velociraptor_tree(root: pathlib.Path) -> pathlib.Path:
    """Build a minimal but realistic extracted offline-collection tree."""
    auto = root / "uploads" / "auto" / VELO_DRIVE
    ntfs = root / "uploads" / "ntfs" / VELO_DEVICE

    for rel in (
        "Windows/System32/winevt/Logs/Security.evtx",
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SOFTWARE",
        "Users/tanaka/NTUSER.DAT",
        "Windows/Prefetch/CMD.EXE-12345678.pf",
        "Windows/AppCompat/Programs/Amcache.hve",
        "Windows/System32/sru/SRUDB.dat",
    ):
        p = auto / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"")

    (ntfs / "$Extend").mkdir(parents=True, exist_ok=True)
    (ntfs / "$MFT").write_bytes(b"")
    (ntfs / "$Extend" / "$UsnJrnl%3A$J").write_bytes(b"")

    # Container metadata that ships alongside the uploads.
    (root / "results").mkdir(parents=True, exist_ok=True)
    (root / "results" / "Windows.KapeFiles.Targets%2FUploads.json").write_bytes(b"")
    (root / "collection_context.json").write_bytes(b"")
    return root


# ---------------------------------------------------------------------------
# is_usn_journal — collector dialects, escaped and not
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "$J",
    "C_$J",
    "$UsnJrnl-$J",
    "$UsnJrnl_$J",
    "USNJournal__J",
    "$UsnJrnl:$J",       # canonical NTFS stream name
    "$UsnJrnl%3A$J",     # ...as Velociraptor's ntfs accessor escapes it
])
def test_is_usn_journal_accepts_known_forms(name):
    assert is_usn_journal(name), f"{name} should be recognised as the journal"


@pytest.mark.parametrize("name", [
    "UsnJrnl.txt",
    "$UsnJrnl",
    "$UsnJrnl%3A$Max",   # a different stream of the same file
    "$MFT",
    "notes$J.txt",
    "report%20draft.txt",
])
def test_is_usn_journal_rejects_other_names(name):
    assert not is_usn_journal(name)


@pytest.mark.parametrize("name", [
    "$J", "C_$J", "$UsnJrnl-$J", "$UsnJrnl:$J", "USNJournal__J",
    "$MFT", "NTUSER.DAT", "History", "places.sqlite", "Security.evtx",
    "$UsnJrnl", "notes$J.txt", "SOFTWARE", "SRUDB.dat",
])
def test_decode_never_changes_the_verdict_for_unescaped_names(name):
    """The no-regression invariant, stated as a property.

    Adding the decode is only safe because `USN_J_RE` contains no `%`: a name
    that carries no escape must get exactly the answer the bare regex gives.
    Asserting that directly is what stops a future edit from letting the
    decode reinterpret a name the old code already classified.
    """
    assert "%" not in name
    assert is_usn_journal(name) == bool(USN_J_RE.fullmatch(name))


def test_usn_pattern_itself_stays_free_of_percent():
    # The premise the property above rests on. If someone ever writes an
    # escape into the pattern, the guarantee is void and this fails loudly.
    assert "%" not in USN_J_RE.pattern


# ---------------------------------------------------------------------------
# detect() over a Velociraptor tree
# ---------------------------------------------------------------------------


def test_velociraptor_usn_journal_is_detected(tmp_path):
    """The regression this feature exists for: %3A-escaped USN journal."""
    root = _velociraptor_tree(tmp_path)
    ids = {d.artifact_id for d in orchestrator.detect(root)}
    assert "usn_journal" in ids


def test_velociraptor_usn_detection_points_at_the_escaped_file(tmp_path):
    root = _velociraptor_tree(tmp_path)
    usn = [d for d in orchestrator.detect(root) if d.artifact_id == "usn_journal"]
    assert len(usn) == 1
    # The staged file is never renamed — the detection carries the on-disk name.
    assert usn[0].input_path.name == "$UsnJrnl%3A$J"


def test_velociraptor_windows_artifacts_survive_the_escaped_drive_dir(tmp_path):
    """The %3A drive component must not break the path-glob detectors."""
    root = _velociraptor_tree(tmp_path)
    ids = {d.artifact_id for d in orchestrator.detect(root)}
    for expected in ("evtx", "registry", "shimcache", "amcache", "prefetch",
                     "srum", "mft", "shellbags"):
        assert expected in ids, f"{expected} not detected under uploads/auto/C%3A"


def test_plain_usn_layout_still_detected(tmp_path):
    """No regression for collectors that do not percent-escape."""
    (tmp_path / "$J").write_bytes(b"")
    ids = {d.artifact_id for d in orchestrator.detect(tmp_path)}
    assert "usn_journal" in ids


def test_percent_name_that_decodes_to_nothing_is_not_detected(tmp_path):
    """Decoding must not invent detections for ordinary files."""
    (tmp_path / "report%20draft.txt").write_bytes(b"")
    (tmp_path / "100%25.csv").write_bytes(b"")
    assert orchestrator.detect(tmp_path) == []


# ---------------------------------------------------------------------------
# _sibling_mft — MFTECmd needs $MFT to resolve FRNs into paths
# ---------------------------------------------------------------------------


def test_sibling_mft_same_directory_wins(tmp_path):
    """TANAKA / KAPE-NTFS flatten layout: $MFT sits next to $J."""
    (tmp_path / "C_$MFT").write_bytes(b"")
    j = tmp_path / "C_$UsnJrnl-$J"
    j.write_bytes(b"")
    assert usn_journal_parser._sibling_mft(j) == tmp_path / "C_$MFT"


def test_sibling_mft_found_one_level_up(tmp_path):
    """Velociraptor ntfs layout: $MFT is a sibling of $Extend/, not of $J."""
    device = tmp_path / "uploads" / "ntfs" / VELO_DEVICE
    (device / "$Extend").mkdir(parents=True)
    mft = device / "$MFT"
    mft.write_bytes(b"")
    j = device / "$Extend" / "$UsnJrnl%3A$J"
    j.write_bytes(b"")
    assert usn_journal_parser._sibling_mft(j) == mft


def test_sibling_mft_stops_after_one_level(tmp_path):
    """The bound in I4: a $MFT two levels up belongs to another volume."""
    deep = tmp_path / "vol_b" / "$Extend"
    deep.mkdir(parents=True)
    (tmp_path / "$MFT").write_bytes(b"")        # two levels up — must NOT win
    j = deep / "$UsnJrnl%3A$J"
    j.write_bytes(b"")
    assert usn_journal_parser._sibling_mft(j) is None


def test_sibling_mft_ascends_only_out_of_extend(tmp_path):
    """A directory that is not $Extend must not license an ascent."""
    other = tmp_path / "vol_b" / "NTFS"
    other.mkdir(parents=True)
    (tmp_path / "vol_b" / "$MFT").write_bytes(b"")
    j = other / "$J"
    j.write_bytes(b"")
    assert usn_journal_parser._sibling_mft(j) is None


@pytest.mark.parametrize("extend_dir", ["$Extend", "$EXTEND", "$extend", "$ExTeNd"])
def test_sibling_mft_extend_match_is_case_insensitive(tmp_path, extend_dir):
    """Collectors differ on hive/stream casing; the ascent must not care."""
    device = tmp_path / "device"
    (device / extend_dir).mkdir(parents=True)
    mft = device / "$MFT"
    mft.write_bytes(b"")
    j = device / extend_dir / "$UsnJrnl%3A$J"
    j.write_bytes(b"")
    assert usn_journal_parser._sibling_mft(j) == mft


def test_sibling_mft_absent_returns_none(tmp_path):
    """Unchanged contract: no $MFT means MFTECmd runs without -m."""
    lone = tmp_path / "a" / "b" / "c"
    lone.mkdir(parents=True)
    j = lone / "$J"
    j.write_bytes(b"")
    assert usn_journal_parser._sibling_mft(j) is None
