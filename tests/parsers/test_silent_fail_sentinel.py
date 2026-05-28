"""Regression tests for parsers.base.fail() silent-failure sentinel.

A forensic-critical bug surfaced 2026-05-16: when an underlying tool
exited cleanly (rc=0) but produced no usable output (PECmd on Linux
"Non-Windows platforms not supported. Exiting...", Plaso psort succeeding
but writing an empty timeline, etc.), the parser correctly built a
`fail()` ParseResult — but the stored `exit_code=0` was indistinguishable
from a genuine success. The synthesizer's `collectFailedArtifacts`
(which queries `WHERE exit_code IS NULL OR exit_code <> 0`) missed
these rows, so the Failed Artifacts section of the report didn't
surface them.

Fix: `fail()` rewrites exit_code=0 to FAIL_SILENT_SENTINEL (-1).
"""

from __future__ import annotations

from parsers.base import FAIL_SILENT_SENTINEL, fail


def _mkfail(**overrides):
    base = dict(artifact_id="X", command="c", started="2026-05-16T00:00Z",
                error="boom", parser_version="t/0")
    base.update(overrides)
    return fail(**base)


def test_rc_zero_is_promoted_to_sentinel():
    """rc=0 (silent failure) must NOT be persisted as 0."""
    r = _mkfail(exit_code=0)
    assert r.success is False
    assert r.exit_code == FAIL_SILENT_SENTINEL == -1


def test_rc_nonzero_is_preserved():
    """Genuine non-zero exits stay unchanged."""
    for rc in (1, 2, 127, 137):
        r = _mkfail(exit_code=rc)
        assert r.success is False
        assert r.exit_code == rc, f"rc={rc} got mangled to {r.exit_code}"


def test_rc_none_stays_none_for_graceful_skip():
    """rc=None is used for "no command issued" cases (e.g. Hayabusa /
    SrumECmd binary not installed). We don't want those promoted to -1
    because the synthesizer treats NULL and non-zero identically for
    Failed Artifacts purposes — but keeping the distinction lets future
    consumers tell "we tried and tool exited cleanly with no output"
    apart from "we never ran the tool"."""
    r = _mkfail(exit_code=None)
    assert r.success is False
    assert r.exit_code is None


def test_sentinel_is_caught_by_failed_artifacts_query():
    """Mirror the synthesizer's SQL: WHERE exit_code IS NULL OR
    exit_code <> 0. The sentinel must match this clause so silent
    failures appear in the report."""
    r = _mkfail(exit_code=0)
    # Simulate the SQL predicate.
    matches = r.exit_code is None or r.exit_code != 0
    assert matches, "silent fail must be picked up by collectFailedArtifacts"
