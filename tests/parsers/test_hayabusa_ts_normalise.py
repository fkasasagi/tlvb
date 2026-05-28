"""Wave 20d-2: hayabusa timestamp DuckDB compatibility.

Hayabusa CSV emits "YYYY-MM-DD HH:MM:SS.ms +00:00" (space before offset),
DuckDB's TIMESTAMP parser rejects that format. Without normalisation, the
orchestrator's _bulk_insert_unified_events raises ConversionException and
the entire parse run aborts — losing every other parser's events in the
same batch. Test pins the regex contract.
"""

from __future__ import annotations

from parsers.hayabusa_parser import _normalise_hayabusa_ts


def test_strip_space_before_positive_offset():
    assert _normalise_hayabusa_ts("2019-11-15 21:47:55.652 +00:00") \
        == "2019-11-15 21:47:55.652+00:00"


def test_strip_space_before_negative_offset():
    assert _normalise_hayabusa_ts("2019-11-15 21:47:55 -05:00") \
        == "2019-11-15 21:47:55-05:00"


def test_already_compact_passes_through():
    assert _normalise_hayabusa_ts("2019-11-15 21:47:55.652+00:00") \
        == "2019-11-15 21:47:55.652+00:00"


def test_offset_without_colon_compacted():
    # Some chrono builds emit ±HHMM. Regex handles that too.
    assert _normalise_hayabusa_ts("2019-11-15 21:47:55 +0000") \
        == "2019-11-15 21:47:55+0000"


def test_empty_string_is_noop():
    assert _normalise_hayabusa_ts("") == ""


def test_garbage_is_passed_through():
    # No timezone tail → no rewrite. Caller still sees the original junk so
    # parse_results.notes can log it.
    assert _normalise_hayabusa_ts("not a timestamp") == "not a timestamp"


def test_multiple_spaces_between_time_and_offset():
    # Defensive: collapse any whitespace, not just a single space.
    assert _normalise_hayabusa_ts("2019-11-15 21:47:55.652   +00:00") \
        == "2019-11-15 21:47:55.652+00:00"


def test_no_offset_passes_through():
    # Naive timestamp (no tz). No change.
    assert _normalise_hayabusa_ts("2019-11-15 21:47:55.652") \
        == "2019-11-15 21:47:55.652"
