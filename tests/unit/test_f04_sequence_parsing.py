"""Non-frozen companion to test_f04_sequences.py (implementation-review round
1, finding P3): the frozen stub protocol deliberately serves only VMID=/EPOCH=
on success, so the frozen suite cannot observe the STEP= decode path at all —
a parser regression there would silently convert a failed sequence into
{ok: true, steps: [{ok: true}, ...]}. These tests stub run_ps with REAL STEP=
stdout and pin console._parse_sequence_steps plus the run_sequence result
shapes built on it: per-step ok/error/skipped decoding, stop-on-failure skip
propagation, the wait-step stop_reason/frame_hash carry, and the UNKNOWN
executed-prefix parse. Transport: folded PowerShell (the conftest autouse
fixture pins wmiconsole.COM_AVAILABLE to False); nothing touches a real host.
GREEN at the implementation commit; every assertion here was mutant-verified
by the implementation reviewer's P3 probe (a dead STEP regex fails this file)."""

import base64

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config

SEQ_GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class StepStdoutPS:
    """Serves the resolution leg by shape and returns a canned stdout for the
    action script (the frozen FakePS idioms, one canned body)."""

    def __init__(self, action_stdout: str, timed_out: bool = False):
        self.scripts: list[str] = []
        self.action_stdout = action_stdout
        self.timed_out = timed_out

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout="seq-vm", returncode=0)
        if self.timed_out:
            return pswindows.PSResult(
                stdout=self.action_stdout, timed_out=True, returncode=None,
                duration_ms=7)
        return pswindows.PSResult(
            stdout="VMID=" + SEQ_GUID + "\nEPOCH=77\n" + self.action_stdout,
            returncode=0)


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


STEPS = [
    {"action": "press_key", "key": "enter"},
    {"action": "type_text", "text": "x"},
    {"action": "scroll", "delta": 1},
]


def test_failed_step_decodes_error_and_later_steps_skip(monkeypatch, unrestricted):
    """A STEP=<i> OK=0 ERR=<base64> record decodes to ok: False with the
    ORIGINAL error text, and the trailing SKIPPED=1 records decode as skipped
    — the stop-on-failure contract the README states."""
    stdout = "\n".join([
        "STEP=0 OK=1",
        "STEP=1 OK=0 ERR=" + _b64("TypeText failed with ReturnValue=5"),
        "STEP=2 SKIPPED=1",
    ])
    stub = StepStdoutPS(stdout)
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(unrestricted, "vm1", STEPS)
    assert out["ok"] is True, "the folded script exits 0; the STEP records carry the failure"
    steps = out["steps"]
    assert [s["index"] for s in steps] == [0, 1, 2]
    assert steps[0]["ok"] is True
    assert steps[1]["ok"] is False
    assert steps[1]["error"] == "TypeText failed with ReturnValue=5"
    assert steps[2].get("skipped") is True


def test_wait_step_carries_stop_reason_and_hash(monkeypatch, unrestricted):
    """A wait step's STEP line carries STOP=<reason> HASH=<hex>; both decode
    onto the step entry so the agent can tell stable from deadline."""
    wait_hash = "ab" * 32
    stdout = "\n".join([
        "STEP=0 OK=1 STOP=stable HASH=" + wait_hash,
    ])
    stub = StepStdoutPS(stdout)
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        unrestricted, "vm1",
        [{"action": "wait_frame_stable", "stable_ms": 100}])
    step = out["steps"][0]
    assert step["ok"] is True
    assert step["stop_reason"] == "stable"
    assert step["frame_hash"] == wait_hash


def test_unknown_record_carries_executed_prefix(monkeypatch, unrestricted):
    """An uncertain (timed-out) leg records UNKNOWN with whatever executed
    STEP= prefix the leg reported before the transport went dark — the
    AC-28.15 executed-prefix metadata."""
    stdout = "STEP=0 OK=1"
    stub = StepStdoutPS(stdout, timed_out=True)
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        unrestricted, "vm1", STEPS, request_key="parse-prefix-key")
    assert out["ok"] is False
    assert out["error_class"] == "unknown"
    assert [s["index"] for s in out["steps"]] == [0]
    assert out["steps"][0]["ok"] is True
    # the record replays for the same key without re-driving the guest
    again = console.run_sequence(
        unrestricted, "vm1", STEPS, request_key="parse-prefix-key")
    assert again["error_class"] == "unknown"
    assert len(stub.scripts) == 1, (
        "the by-name path folds resolution into ONE action leg; the retry must "
        "not spawn a second anything")


def test_parse_sequence_steps_ignores_non_step_lines(monkeypatch, unrestricted):
    """VMID=/EPOCH= metadata lines never decode as steps, and a success
    stdout with no STEP records synthesizes one ok result per plan step (the
    frozen stub protocol shape)."""
    stub = StepStdoutPS("")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(unrestricted, "vm1", STEPS)
    assert out["ok"] is True
    assert out["boot_epoch"] == 77
    assert [s for s in out["steps"]] == [
        {"index": 0, "ok": True}, {"index": 1, "ok": True}, {"index": 2, "ok": True}]
