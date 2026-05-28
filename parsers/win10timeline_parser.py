"""Windows 10 Timeline (Activities Cache) parser via WxTCmd.

Wraps EZ Tools' WxTCmd (1.1.0.0). Input is a single ``ActivitiesCache.db``
SQLite file, typically found at::

    %LOCALAPPDATA%\\ConnectedDevicesPlatform\\L.<profile>\\ActivitiesCache.db

Forensic value: per-user record of "what application showed what
content" in the Win10/11 Timeline feature. Includes file paths, URLs,
and durations.

NOTE: Microsoft removed Timeline from Windows 11 22H2 — newer hosts may
have an empty / missing DB. Pre-22H2 still records.
"""

from __future__ import annotations

from parsers._ezt_csv import EztSpec, run_simple_ezt
from parsers.base import ParseRequest, ParseResult


ARTIFACT_ID = "win10timeline"
PARSER_VERSION = "win10timeline_parser/1.0.0+wxtcmd-1.1.0.0"

# WxTCmd writes 3 distinct tables to separate CSVs (Activity,
# ActivityOperations, ActivityPackageId). The base name we pass via --csvf
# becomes a prefix; we glob all of them.
_SPEC = EztSpec(
    artifact_id=ARTIFACT_ID,
    parser_version=PARSER_VERSION,
    dll="/opt/zimmermantools/WxTCmd.dll",
    input_mode="file",
    csv_filename="win10timeline.csv",
    jsonl_filename="win10timeline.jsonl",
    timestamp_columns=["StartTime", "LastModifiedTime", "CreatedInCloud"],
    event_type="win10timeline",
    csv_glob_fallbacks=["*Activity*.csv", "*ActivityOperations*.csv",
                        "*ActivityPackageId*.csv"],
    caveats=[
        "Microsoft removed Timeline from Windows 11 22H2; absent / empty DB "
        "on newer hosts is expected, not anomalous.",
        "Per-user artifact: each user profile has its own ActivitiesCache.db.",
    ],
)


def parse(req: ParseRequest) -> ParseResult:
    return run_simple_ezt(_SPEC, req)
