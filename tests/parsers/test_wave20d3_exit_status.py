"""Wave 20d-3: orchestrator exit_status must reflect ARTIFACT-level status.

After Wave 18c's any-success _merge_parse_results, per-user/per-hive
detection failures (e.g. 3 of 6 user dirs have no NTUSER.DAT) collapse
into a single artifact-level OK row in parse_results. The previous
implementation computed exit code from the raw per-detection failed
count, so V06 returned exit 2 despite parse_results being OK 15 / FAIL 0.

These tests pin the new artifact-level counting in OrchestratorReport.
"""

from __future__ import annotations

import dataclasses

from parsers.base import FAIL_SILENT_SENTINEL, ParseResult
from parsers.orchestrator import OrchestratorReport, _merge_parse_results


def _ok(artifact_id: str, sub: int = 0, rows: int = 100) -> ParseResult:
    return ParseResult(
        artifact_id=artifact_id,
        success=True,
        command=f"cmd {artifact_id}{sub}",
        exit_code=0,
        started_at="2026-05-19T00:00:00Z",
        finished_at="2026-05-19T00:00:01Z",
        duration_seconds=1.0,
        row_count=rows,
        parser_version="test/1.0.0",
    )


def _fail(artifact_id: str, sub: int = 0, err: str = "no data") -> ParseResult:
    return ParseResult(
        artifact_id=artifact_id,
        success=False,
        command=f"cmd {artifact_id}{sub}",
        exit_code=FAIL_SILENT_SENTINEL,
        started_at="2026-05-19T00:00:00Z",
        finished_at="2026-05-19T00:00:01Z",
        duration_seconds=0.0,
        error=err,
        parser_version="test/1.0.0",
    )


def _compute_artifact_failed(results: list[ParseResult]) -> int:
    """Mirror the in-memory merge that orchestrator.run() now performs."""
    by_artifact: dict[str, list[ParseResult]] = {}
    for r in results:
        by_artifact.setdefault(r.artifact_id, []).append(r)
    n = 0
    for _aid, group in by_artifact.items():
        merged = _merge_parse_results(group) if len(group) > 1 else group[0]
        if not merged.success:
            n += 1
    return n


def test_orchestrator_report_has_artifact_level_fields():
    """The dataclass schema MUST carry artifact_succeeded / artifact_failed
    so _main() can compute exit code from the post-merge view."""
    r = OrchestratorReport(
        case_id="x", evidence_id="ev1",
        detections=10, succeeded=8, failed=2,
        parse_results=[],
        artifact_succeeded=5, artifact_failed=0,
    )
    assert r.artifact_succeeded == 5
    assert r.artifact_failed == 0
    # Backwards compatible default = 0.
    r2 = OrchestratorReport(
        case_id="x", evidence_id="ev1",
        detections=10, succeeded=8, failed=2,
        parse_results=[],
    )
    assert r2.artifact_succeeded == 0
    assert r2.artifact_failed == 0


def test_per_user_partial_success_drives_artifact_failed_to_zero():
    """V06 scenario: jumplists has 6 detections, 3 OK + 3 FAIL. After
    Wave 18c merge, the artifact is OK overall. Exit code should be 0
    even though detection-level failed=3."""
    results = [
        _ok("jumplists", 1, 8),
        _fail("jumplists", 2, "Recent empty"),
        _ok("jumplists", 3, 361),
        _fail("jumplists", 4, "no NTUSER"),
        _fail("jumplists", 5, "no NTUSER"),
        _ok("jumplists", 6, 8),
    ]
    # Detection-level: 3 succeeded, 3 failed.
    succeeded = sum(1 for r in results if r.success)
    assert succeeded == 3
    # Artifact-level: 1 artifact (jumplists), 0 failed (any-success merge).
    assert _compute_artifact_failed(results) == 0


def test_all_detections_failed_keeps_artifact_failed():
    """If EVERY detection of an artifact fails, the merged row is FAIL."""
    results = [
        _fail("registry", 1, "hive missing"),
        _fail("registry", 2, "hive missing"),
        _fail("registry", 3, "hive missing"),
    ]
    assert _compute_artifact_failed(results) == 1


def test_mixed_artifacts():
    """V06 macro view: many artifacts, one truly broken, the rest mix of
    OK + per-user FAIL. Only the all-failed artifact bumps the count."""
    results = [
        # jumplists: 3 OK + 3 FAIL → artifact OK
        _ok("jumplists", 1, 8),
        _fail("jumplists", 2),
        _ok("jumplists", 3, 361),
        _fail("jumplists", 4),
        _fail("jumplists", 5),
        _ok("jumplists", 6, 8),
        # registry: 1 hive FAIL out of 7 → artifact OK
        _fail("registry", 1, "RECmd no CSV"),
        _ok("registry", 2, 7039),
        _ok("registry", 3, 374),
        # mft: single detection, OK.
        _ok("mft", 0, 301363),
        # hypothetical_broken: every detection failed → artifact FAIL
        _fail("hypothetical_broken", 1),
        _fail("hypothetical_broken", 2),
    ]
    assert _compute_artifact_failed(results) == 1


def test_not_present_rows_count_as_success():
    """Wave 15 NOT_PRESENT sentinel rows are success=True (the marker is
    'we ran detection, this artifact wasn't in the input'). They MUST NOT
    contribute to artifact_failed."""
    from parsers.orchestrator import not_present_results

    np = not_present_results(detected_ids=set(), only=["win10timeline"])
    assert len(np) >= 1
    for r in np:
        assert r.success, "NOT_PRESENT rows are success=True (Wave 15 contract)"
    assert _compute_artifact_failed(list(np)) == 0


def test_orchestrator_report_dataclasses_asdict_serialisable():
    """dataclasses.asdict must include the new fields so the Go side can
    consume them via JSON. This guards against accidentally setting
    init=False or adding non-default-friendly types."""
    r = OrchestratorReport(
        case_id="c", evidence_id="e",
        detections=5, succeeded=3, failed=2,
        parse_results=[],
        artifact_succeeded=3, artifact_failed=0,
    )
    d = dataclasses.asdict(r)
    assert "artifact_succeeded" in d
    assert "artifact_failed" in d
    assert d["artifact_succeeded"] == 3
    assert d["artifact_failed"] == 0
