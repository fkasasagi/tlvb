"""Tests for parsers.prefetch_parser._dynamic_dt_to_iso_utc (Issue #17 残).

psort.py '-o dynamic' emits an ISO-8601 'datetime' column with an
optional offset. We normalise to UTC ISO-8601 for DuckDB's TIMESTAMP
column.
"""

from __future__ import annotations

import pytest

from parsers.prefetch_parser import _dynamic_dt_to_iso_utc as to_utc


@pytest.mark.parametrize("inp,expected", [
    # Asia/Tokyo offset → UTC
    ("2026-05-15T09:28:40.000000+09:00", "2026-05-15 00:28:40"),
    # America/Los_Angeles -07:00 → UTC
    ("2026-05-15T05:00:00-07:00",        "2026-05-15 12:00:00"),
    # Explicit UTC offset
    ("2026-05-15T00:28:40+00:00",        "2026-05-15 00:28:40"),
    # Offset-naive ISO with space separator (psort fallback shape) → assume UTC
    ("2026-05-15 09:28:40",              "2026-05-15 09:28:40"),
    # Empty input
    ("",                                 ""),
    # Garbage → empty rather than raising
    ("not a date",                       ""),
])
def test_dynamic_dt_to_iso_utc_table(inp, expected):
    assert to_utc(inp) == expected


def test_dynamic_dt_preserves_sub_second_truncation():
    # Sub-second component is dropped by `timespec="seconds"` — this is
    # the *documented* behaviour, captured here so a future widening of
    # precision needs an explicit decision.
    got = to_utc("2026-05-15T09:28:40.123456+00:00")
    assert got == "2026-05-15 09:28:40"


def test_dynamic_dt_strips_whitespace():
    assert to_utc("  2026-05-15T09:28:40+00:00  ") == "2026-05-15 09:28:40"
