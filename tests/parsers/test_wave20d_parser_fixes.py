"""Wave 20d: regression tests for the 5-parser FAIL fix.

SRL-2018-V05 exposed five separate FAIL modes that were each a single
bug in a different layer. These tests pin the small contract pieces so
the bugs can't regress silently:

- prefetch_parser: ``csv.field_size_limit`` raised at module import
  (altpf occasionally emits very wide FilesAccessed columns).
- hayabusa_parser: ``--no-wizard`` is in the command vector (without it
  hayabusa panics on non-TTY stdin).
- image_extractor: triage list contains hive transaction logs
  (covered in test_image_extractor.py — referenced here for completeness).

The full end-to-end verification with a real EWF image is in
docs/TEST_REAL_EVIDENCE.md §2.
"""

from __future__ import annotations

import csv
import inspect
import sys


def test_prefetch_parser_raises_csv_field_size_limit():
    """altpf produces a single FilesAccessed column joined with backslashes
    that can exceed Python's default csv field_size_limit of 131072 chars
    for long-running service processes. prefetch_parser bumps the cap at
    module load — verify the side effect actually took."""
    # The parser may already be imported; force re-import to ensure the
    # module-level bump fires under the test session.
    sys.modules.pop("parsers.prefetch_parser", None)
    import parsers.prefetch_parser  # noqa: F401

    # The default is 131072. We raise to sys.maxsize. On 64-bit systems
    # this is 9223372036854775807; the contract is "well above 1 MB".
    assert csv.field_size_limit() > 1_000_000, (
        f"prefetch_parser must raise csv.field_size_limit on import; "
        f"got {csv.field_size_limit()}"
    )


def test_hayabusa_command_includes_no_wizard():
    """hayabusa v2+ ``csv-timeline`` launches an interactive Scan Wizard by
    default. When stdin is a pipe (subprocess in our orchestrator) the
    wizard panics with ``IO(NotConnected) "not a terminal"``. The fix is
    to pass ``--no-wizard`` (a.k.a. ``-w``) so it scans for all events
    and alerts non-interactively.
    """
    from parsers import hayabusa_parser
    src = inspect.getsource(hayabusa_parser.parse)
    # The flag may be written as either "--no-wizard" or "-w" — accept
    # either, but it must be passed to the csv-timeline subcommand.
    assert "--no-wizard" in src or '"-w"' in src, (
        "hayabusa_parser.parse must pass --no-wizard / -w to csv-timeline "
        "(without it the parser panics on non-TTY stdin)."
    )


def test_image_extractor_handles_ads_in_extract_one(monkeypatch, tmp_path):
    """Wave 20d: paths containing ``:`` (NTFS ADS notation) go through the
    dedicated ADS branch which calls ``_resolve_ads`` then
    ``_icat_to_file_sparse``. Verify the dispatch routes correctly
    without exercising real ``icat``.
    """
    from parsers import image_extractor

    calls = []

    def fake_ifind(raw_device, offset_bytes, ntfs_path, timeout):
        calls.append(("ifind", ntfs_path))
        # First call: the file path (parent of ADS). Return inum 55815.
        return "55815"

    def fake_resolve_ads(raw_device, offset_bytes, inum, ads_name, timeout):
        calls.append(("resolve_ads", inum, ads_name))
        return f"{inum}-128-87"

    def fake_sparse(raw_device, offset_bytes, attr_spec, dest, label, partition, timeout):
        calls.append(("sparse", attr_spec))
        dest.write_bytes(b"\x00" * 1024)
        return image_extractor.ExtractRecord(
            target=label, partition=partition, status="ok",
            inum=attr_spec, sha256="x" * 64, bytes=1024,
            extracted_path=str(dest),
        )

    monkeypatch.setattr(image_extractor, "_ifind", fake_ifind)
    monkeypatch.setattr(image_extractor, "_resolve_ads", fake_resolve_ads)
    monkeypatch.setattr(image_extractor, "_icat_to_file_sparse", fake_sparse)

    rec = image_extractor._extract_one(
        raw_device="/dev/fake", offset_bytes=0,
        ntfs_path="$Extend/$UsnJrnl:$J",
        dest=tmp_path / "$J", label="$J",
        partition=0, timeout=60,
    )
    assert rec.status == "ok"
    # ifind was called WITHOUT the ":$J" suffix — image_extractor must split
    # on the last colon before passing to ifind. This is critical because
    # TSK's ifind silently strips the ADS suffix and returns the file's
    # inum, which then causes icat to extract the wrong stream.
    assert ("ifind", "$Extend/$UsnJrnl") in calls
    assert ("resolve_ads", "55815", "$J") in calls
    assert ("sparse", "55815-128-87") in calls


def test_image_extractor_ads_branch_handles_missing_stream(monkeypatch, tmp_path):
    """If the ADS doesn't exist (e.g. requesting :$J on a file that only
    has :$Max), return not_found with a descriptive error rather than
    crashing or extracting the wrong stream."""
    from parsers import image_extractor

    monkeypatch.setattr(image_extractor, "_ifind", lambda *a, **k: "42")
    monkeypatch.setattr(image_extractor, "_resolve_ads", lambda *a, **k: None)

    rec = image_extractor._extract_one(
        raw_device="/dev/fake", offset_bytes=0,
        ntfs_path="$Extend/$UsnJrnl:$NonExistent",
        dest=tmp_path / "x", label="x",
        partition=0, timeout=60,
    )
    assert rec.status == "not_found"
    assert "ADS" in (rec.error or "")
