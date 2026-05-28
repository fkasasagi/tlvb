"""Shimcache parser via AppCompatCacheParser.

Wraps EZ Tools' AppCompatCacheParser (1.5.1.0). Input is the SYSTEM hive
file (one specific file, not a hive directory). Output is one CSV with
one row per ShimCache entry.

Forensic caveat: ShimCache (AppCompatCache) records EXISTENCE of an
executable in the file system at last update time, NOT execution.
"""

from __future__ import annotations

from parsers._ezt_csv import EztSpec, run_simple_ezt
from parsers.base import ParseRequest, ParseResult


ARTIFACT_ID = "shimcache"
PARSER_VERSION = "shimcache_parser/1.0.0+appcompatcacheparser-1.5.1.0"

_SPEC = EztSpec(
    artifact_id=ARTIFACT_ID,
    parser_version=PARSER_VERSION,
    dll="/opt/zimmermantools/AppCompatCacheParser.dll",
    input_mode="file",
    csv_filename="shimcache.csv",
    jsonl_filename="shimcache.jsonl",
    timestamp_columns=["LastModifiedTimeUTC"],
    event_type="shimcache",
    caveats=[
        "Shimcache proves existence on disk at observation time, NOT execution. "
        "Corroborate via Prefetch / Amcache / EVTX 4688 / Sysmon 1.",
        "Entries persist across reboots in memory and only flush to disk on shutdown — "
        "data may be stale if SYSTEM hive was captured from a running host.",
    ],
)


def parse(req: ParseRequest) -> ParseResult:
    return run_simple_ezt(_SPEC, req)
