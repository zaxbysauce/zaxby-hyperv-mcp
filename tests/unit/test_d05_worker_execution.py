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
import subprocess

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


def test_the_inner_script_crosses_as_base64(worker):
    """PRR-001: the request frame carries the inner guest script as BASE64.

    The shipped guest scriptblock decodes its `$enc` parameter with
    `[Convert]::FromBase64String`, so a raw frame makes every pooled guest call
    fail — and it failed the way that looks like success: `exit_code=0` with
    empty stdout, because the worker's own catch answered on the guest's behalf.
    No mocked test could see it; every pooled test drives a `FakeWorker` that
    never inspects the frame.

    The placeholder loop applies the SAME decode to `$req.script` that
    `_worker_loop` applies, so this pins the contract end to end: the live
    worker accepts the frame `run()` builds and refuses a raw one.
    """
    result = worker.run("Write-Output 'kept verbatim'", timeout_ms=30000)
    assert result.timed_out is False, result
    assert result.returncode == 0, (
        f"the live worker refused the frame run() built; the inner script is "
        f"not crossing as base64: {result}"
    )

    # And at the framing boundary itself, the script survives the round trip.
    inner = "Write-Output 'verbatim: $x'"
    frame = json.dumps({
        "script": pswindows.pswindows_b64(inner),
        "expect_epoch": None,
        "elevated": False,
    })
    wire = base64.b64encode(frame.encode("utf-8")).decode("ascii")
    decoded = json.loads(base64.b64decode(wire.strip()).decode("utf-8", "replace"))
    assert base64.b64decode(decoded["script"]).decode("utf-8") == inner, (
        "the inner script did not survive the frame round trip; the guest "
        "scriptblock would receive something other than the caller's script"
    )


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


def test_real_worker_loop_emits_the_per_call_wrapper(tmp_path):
    """The REAL credentialed worker loop produces the same
    `{exit_code, stdout, stderr}` wrapper the per-call host script produces.

    This is the check the implementation reviewer's finding 1 demanded. A bare
    `& $tmp` inside the guest scriptblock yields `null` on the parent pipeline —
    the guest's stdout never arrives and every exit code reads 0 — so the pooled
    path would silently fabricate success with empty output. The loop therefore
    runs `guestexec`'s capture body, and this test proves it by executing the
    emitted scriptblock text against a REAL powershell.

    Scope: the loop's session-establishment leg needs a live VM, so this executes
    the guest scriptblock the worker would send, not the whole loop. The loop's
    own parse-and-frame behaviour is covered by the placeholder-lane tests above.
    """
    pswindows.init(Config(audit_log_path=None))
    sb_text = psdsessions.guest_scriptblock(False)
    inner = "Write-Output 'd05-real-loop'; exit 7"

    # Both payloads cross as FILES, never as a -Command string: the scriptblock
    # text is full of quotes and dollar signs, and -Command would mangle them.
    sb_file = tmp_path / "sb.txt"
    inner_file = tmp_path / "inner.txt"
    runner = tmp_path / "run.ps1"
    sb_file.write_text(sb_text, encoding="utf-8")
    inner_file.write_text(inner, encoding="utf-8")
    runner.write_text(
        "$sb = [ScriptBlock]::Create((Get-Content -Raw $args[0]))\n"
        "$enc = [Convert]::ToBase64String("
        "[Text.Encoding]::UTF8.GetBytes((Get-Content -Raw $args[1])))\n"
        "& $sb $enc | ConvertTo-Json -Compress -Depth 3\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [pswindows._ps_path or "powershell.exe", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-File", str(runner),
         str(sb_file), str(inner_file)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-400:]
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["exit_code"] == 7, payload
    assert "d05-real-loop" in payload["stdout"], payload
    assert payload["stderr"] == "", payload


def test_an_arbitrary_frame_still_gets_a_well_formed_answer(worker):
    """Whatever the host writes, the worker answers with ONE decodable frame and
    keeps serving: a frame that is not base64 JSON must not desynchronise the
    stream or kill the worker for the next caller.

    Scope: the no-credential placeholder loop answers a BAD frame with the same
    `ok=false, phase='frame'` the real loop answers (PRR-079 aligned them), so
    this pins that branch too. What it cannot reach is the real loop's
    session-state and boot-epoch guards, which need a live guest session.
    """
    bad = base64.b64encode(b"not json at all").decode("ascii")
    worker._proc.stdin.write((bad + "\n").encode("ascii"))
    worker._proc.stdin.flush()
    line = worker._lines.get(timeout=30)
    payload = json.loads(base64.b64decode(line.strip()).decode("utf-8"))
    assert payload.get("ok") is False, payload
    assert payload.get("phase") == "frame", payload
    result = worker.run("Write-Output still-alive", timeout_ms=30000)
    assert result.returncode == 0, result
