"""Web handler smoke tests — focus on the 400/422 validation paths.

We spin up a real `bin/tlvb serve` process on an ephemeral port and
poke it with urllib (no extra dependencies). Validation logic is in Go
and not directly importable from Python; these tests are the closest
we get to unit-testing it without adding *_test.go files.

The whole suite skips automatically when `bin/tlvb` isn't built —
intentional, so a fresh clone running `pytest` doesn't error before
`make build`.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BINARY    = REPO_ROOT / "bin" / "tlvb"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """Boot `tlvb serve` once per module — fast, no DB persistence."""
    if not BINARY.is_file():
        pytest.skip(f"{BINARY} not built — run `make build` first")
    workdir = tmp_path_factory.mktemp("server")
    db_path = workdir / "case.duckdb"
    port    = _free_port()
    env     = {**os.environ, "TLVB_PYTHON": "/projects/tlvb/.venv/bin/python3"}
    proc = subprocess.Popen(
        [str(BINARY), "serve",
         "--addr", f"127.0.0.1:{port}",
         "--db", str(db_path),
         "--outputs", str(workdir)],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            urllib.request.urlopen(base + "/api/cases", timeout=0.5)
            break
        except (urllib.error.URLError, urllib.error.HTTPError):
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("server did not start within 8s")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# Helper -------------------------------------------------------------------


def _post(base: str, path: str, body: dict) -> tuple[int, dict | str]:
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, ""


def _create_case(base: str, case_id: str = "TST-VAL") -> int:
    code, _ = _post(base, "/api/cases", {
        "case_id": case_id, "name": "validation test",
        "examiner": "tst", "timezone": "UTC", "language": "ja",
    })
    return code


# Tests --------------------------------------------------------------------


def test_create_case_accepts_valid_tz_and_language(server):
    assert _create_case(server, "TST-VAL-1") == 201


def test_parse_rejects_bogus_input_mode(server):
    _create_case(server, "TST-VAL-2")
    code, body = _post(server, "/api/cases/TST-VAL-2/parse",
        {"evidences": [{"evidence_path": "/tmp/nonexistent"}],
         "input_mode": "bogus"})
    assert code == 400
    assert "input_mode" in body.get("error", "")


def test_parse_rejects_bogus_image_format(server):
    _create_case(server, "TST-VAL-3")
    code, body = _post(server, "/api/cases/TST-VAL-3/parse",
        {"evidences": [{"evidence_path": "/tmp/nonexistent"}],
         "input_mode": "image", "image_format": "qcow2"})
    assert code == 400
    assert "image_format" in body.get("error", "")


def test_parse_rejects_missing_evidence(server):
    _create_case(server, "TST-VAL-4")
    code, body = _post(server, "/api/cases/TST-VAL-4/parse", {"evidences": []})
    assert code == 400
    assert "evidence" in body.get("error", "").lower()


def test_parse_accepts_image_mode_with_auto_format(server):
    """Even though the file doesn't exist, schema validation should pass
    and the failure happens later in the job. We accept either 202
    (queued) or 5xx (job rejected later); we ONLY assert it's not a 400."""
    _create_case(server, "TST-VAL-5")
    code, _ = _post(server, "/api/cases/TST-VAL-5/parse",
        {"evidences": [{"evidence_path": "/tmp/tlvb-no-such-file.E01"}],
         "input_mode": "image", "image_format": "auto"})
    assert code != 400


def test_bulk_reject_without_reason_is_accepted(server):
    """Issue #21 regression: an empty reason must NOT fail the *schema*
    layer (the old code returned 400 with `reason required for reject`).

    For a brand-new case the findings dir doesn't exist yet, so the
    request may legitimately fail with 500 — what matters is the cause
    isn't "reason required". This protects against #21 silently coming
    back."""
    _create_case(server, "TST-VAL-6")
    code, body = _post(server, "/api/cases/TST-VAL-6/findings/bulk",
        {"finding_ids": ["F-nonexistent"], "action": "reject", "reason": ""})
    err = (body or {}).get("error", "") if isinstance(body, dict) else ""
    assert "reason required" not in err.lower(), \
        f"#21 regression — got {code} with: {body}"


def test_bulk_invalid_action_is_400(server):
    _create_case(server, "TST-VAL-7")
    code, body = _post(server, "/api/cases/TST-VAL-7/findings/bulk",
        {"finding_ids": ["F-x"], "action": "explode", "reason": ""})
    assert code == 400
    assert "action" in body.get("error", "")


def test_events_audit_id_filter_round_trips(server):
    """The new audit_id query parameter (#20) must reach the SQL layer.

    With an empty case, the result is empty — we just verify the
    endpoint accepts the param and returns a well-formed body."""
    _create_case(server, "TST-VAL-8")
    req = urllib.request.Request(
        server + "/api/cases/TST-VAL-8/events?audit_id=deadbeef&limit=1")
    with urllib.request.urlopen(req, timeout=5) as r:
        body = json.loads(r.read())
    assert "events" in body
    # An empty case marshals as `"events": null`; a populated case as a list.
    # Either is fine — the contract is "the key exists and the filter
    # didn't trip a 400/500".
    assert body["events"] in (None,) or isinstance(body["events"], list)
