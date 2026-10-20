"""Execution-lane smoke test for the pooled worker transport (issue #21).

A parse check proves the generated loop is syntactically valid; only running it
proves the framing protocol works — that the host's base64 JSON request frame is
decoded, answered, and framed back so the caller can json.loads it. That is the
third failure shape this repo has been bitten by before (a script that parses
and has correct Python logic but a runtime-semantic bug invisible to both).

Runs only on Windows with a real powershell.exe; skipped everywhere else, exactly
like the repo's other Windows-only tests.
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from hyperv_mcp import psdsessions, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="the pooled worker is a Windows powershell.exe process"
)

CRED = CredentialSet("d05-exec-lane", "d05-exec-lane-pass")
GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


@pytest.fixture()
def worker():
    """A real pooled worker running the no-credential placeholder loop."""
    pswindows.init(Config(audit_log_path=None))
    key = psdsessions.SessionKey(GUID, "exec-lane", None, None)
    script, stdin_b64 = psdsessions.establishment_script(key, None)
    handle = pswindows.spawn_worker(script, stdin_b64)
    yield handle
    handle.close()


def test_open_handshake_arrives_before_any_request(worker):
    """spawn_worker reads exactly one line after starting the process and treats
    it as the open handshake. A loop that never emits it would make the host
    block to its deadline and hand the caller a worker it believes is dead."""
    assert worker.boot_epoch == "", worker.boot_epoch
    assert worker.session_ms == 0, worker.session_ms
    assert worker.is_alive()


def test_request_frame_round_trips_as_json(worker):
    """A base64 JSON request frame on stdin produces a base64 JSON response
    frame on stdout that decodes to the per-call wrapper shape."""
    result = worker.run("Write-Output round-trip", timeout_ms=30000)
    assert result.timed_out is False, result
    assert result.returncode == 0, result
    payload = json.loads(result.stdout)
    assert payload == {
        "exit_code": 0, "stdout": "", "stderr": "", "duration_ms": 0,
    }, payload


def test_worker_exit_terminates_the_process(worker):
    """close() writes the exit sentinel and the process actually goes away, so
    no host powershell.exe is stranded and no slot is leaked."""
    pid = worker._proc.pid
    worker.close()
    assert not worker.is_alive()
    assert worker._proc.poll() is not None, (
        f"worker pid {pid} survived close(); the slot it holds would leak"
    )


def test_an_arbitrary_frame_still_gets_a_well_formed_answer(worker):
    """Whatever the host writes, the worker answers with ONE decodable frame and
    keeps serving: a frame that is not base64 JSON must not desynchronise the
    stream or kill the worker for the next caller.

    Scope, stated honestly: the no-credential placeholder loop answers every
    frame with a canned success, so this pins the framing contract (one line in,
    one decodable line out, worker survives) rather than the real loop's
    `phase = 'frame'` validation branch, which is only reachable with a live
    guest session.
    """
    bad = base64.b64encode(b"not json at all").decode("ascii")
    worker._proc.stdin.write((bad + "\n").encode("ascii"))
    worker._proc.stdin.flush()
    line = worker._lines.get(timeout=30)
    payload = json.loads(base64.b64decode(line.strip()).decode("utf-8"))
    assert isinstance(payload, dict) and "ok" in payload, payload
    result = worker.run("Write-Output still-alive", timeout_ms=30000)
    assert result.returncode == 0, result
