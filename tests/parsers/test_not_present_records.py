"""Tests for parsers/orchestrator NOT_PRESENT bookkeeping (Wave 15).

When detect() doesn't find an implemented artefact in the input, the
orchestrator emits a synthetic ParseResult with the
``(not present in input)`` command sentinel. This drives the UI's
"⚪ NOT_PRESENT" badge so Review Gate 0 can show a complete view of
all 17 implemented artefacts on every case.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from parsers import orchestrator
from parsers.base import ParseResult


def test_implemented_artifact_ids_returns_frozenset_of_17():
    ids = orchestrator.implemented_artifact_ids()
    # Set semantics: deduplicated, hashable.
    assert isinstance(ids, frozenset)
    # At least the artefacts called out in CLAUDE.md / artifacts.yaml.
    expected_subset = {
        "evtx", "amcache", "prefetch", "registry", "scheduled_tasks",
        "shimcache", "mft", "usn_journal", "shellbags", "jumplists",
        "lnk", "recyclebin", "win10timeline", "browser_history",
        "washizukami_audit", "srum", "hayabusa",
    }
    assert expected_subset <= ids


def test_not_present_results_all_missing_when_nothing_detected():
    target = orchestrator.implemented_artifact_ids()
    results = orchestrator.not_present_results(detected_ids=set())
    assert len(results) == len(target)
    aids = {r.artifact_id for r in results}
    assert aids == target


def test_not_present_results_skip_detected():
    detected = {"mft", "usn_journal"}
    results = orchestrator.not_present_results(detected_ids=detected)
    aids = {r.artifact_id for r in results}
    assert "mft" not in aids
    assert "usn_journal" not in aids
    # Everything else from the implemented set still gets a row.
    assert aids == orchestrator.implemented_artifact_ids() - detected


def test_not_present_sentinel_is_well_formed():
    results = orchestrator.not_present_results(detected_ids=set())
    for r in results:
        assert r.command == orchestrator.NOT_PRESENT_COMMAND_SENTINEL
        assert r.exit_code is None
        assert r.row_count == 0
        assert r.success is True            # not_present is a fact, not a fail
        assert r.parser_version.startswith("orchestrator/not-present")
        assert r.duration_seconds == 0.0


def test_not_present_obeys_only_filter():
    # When --only is passed, NOT_PRESENT is constrained to that subset.
    results = orchestrator.not_present_results(
        detected_ids={"mft"}, only=["mft", "usn_journal"],
    )
    aids = [r.artifact_id for r in results]
    assert aids == ["usn_journal"]


def test_append_actions_emits_skip_kind_for_not_present(tmp_path):
    # NOT_PRESENT rows must land in actions.jsonl with kind="skip" so the
    # forensic timeline can distinguish "we tried and failed" from
    # "we recognised the artefact wasn't here".
    np_results = orchestrator.not_present_results(detected_ids=set())
    actions_path = tmp_path / "actions.jsonl"
    orchestrator.append_actions(actions_path, "TST-CASE", np_results)
    lines = [json.loads(line) for line in actions_path.read_text().splitlines()]
    assert len(lines) == len(np_results)
    for entry in lines:
        assert entry["kind"] == "skip"
        assert entry["reason"] == "not_present_in_input"
        assert entry["artifact_id"] in orchestrator.implemented_artifact_ids()
        # No parse-specific fields leaked.
        assert "exit_code" not in entry
        assert "row_count" not in entry


def test_append_actions_keeps_parse_kind_for_real_results(tmp_path):
    # Regression: a normal ParseResult must still log as kind="parse",
    # not get swept into the skip path by accident.
    real = ParseResult(
        artifact_id="evtx", success=True, command="EvtxECmd ...",
        exit_code=0, started_at="2026-05-17T00:00:00+00:00",
        finished_at="2026-05-17T00:00:01+00:00",
        duration_seconds=1.0, row_count=42, parser_version="evtx/1.0",
    )
    actions_path = tmp_path / "actions.jsonl"
    orchestrator.append_actions(actions_path, "TST-CASE", [real])
    [entry] = [json.loads(l) for l in actions_path.read_text().splitlines()]
    assert entry["kind"] == "parse"
    assert entry["artifact_id"] == "evtx"
    assert entry["row_count"] == 42
