"""Wave 40B: SQLECmd detector basename allowlist.

Replaced the old "**/*.sqlite" glob with an exact-basename match against
SQLECmd's installed map FileNames. This test pins the contract:

  - Canonical basenames in the allowlist (places.sqlite, History,
    Cookies) → detected.
  - Prefix-flattened names (Tanaka_*_places.sqlite) → NOT detected.
    The parser cannot canonicalise the basename before exec yet, so
    detecting these would only re-create the FAIL noise Wave 40 aims
    to remove.
  - Random *.sqlite files SQLECmd has no map for → NOT detected.
"""

from __future__ import annotations

import pathlib

from parsers.orchestrator import _SQLECMD_MAP_BASENAMES, detect


def test_sqlecmd_detects_canonical_basenames_only(tmp_path):
    triage = tmp_path / "Web" / "Firefox"
    triage.mkdir(parents=True)
    (triage / "places.sqlite").write_bytes(b"\x00")
    (triage / "History").write_bytes(b"\x00")
    (triage / "Cookies").write_bytes(b"\x00")
    # The three lines below MUST NOT be picked up:
    (triage / "Tanaka_o7yzgq90.default-release_places.sqlite").write_bytes(b"\x00")
    (triage / "Tanaka_Default_History").write_bytes(b"\x00")
    (triage / "user_notes_app.sqlite").write_bytes(b"\x00")  # not in allowlist

    detected = sorted(
        d.input_path.name for d in detect(tmp_path) if d.artifact_id == "sqlecmd"
    )
    assert detected == sorted(["Cookies", "History", "places.sqlite"]), (
        f"detector matched unexpected set: {detected}"
    )


def test_sqlecmd_allowlist_has_expected_windows_basenames():
    # Spot-check: the basenames operators report most often (Chrome/Edge
    # browser DBs, Win10 ActivitiesCache, OneDrive caches) must be in the
    # allowlist. If a future EZ Tools upgrade renames any of these the
    # test fails loudly so we can resync.
    must_include = {
        "History", "Cookies", "Favicons", "Top Sites", "Web Data",
        "ActivitiesCache.db", "EventTranscript.db",
        "places.sqlite", "cookies.sqlite", "formhistory.sqlite",
    }
    missing = must_include - _SQLECMD_MAP_BASENAMES
    assert not missing, (
        f"expected basenames missing from _SQLECMD_MAP_BASENAMES: {missing}"
    )
