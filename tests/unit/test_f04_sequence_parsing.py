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
        self.kwargs: list[dict] = []
        self.action_stdout = action_stdout
        self.timed_out = timed_out

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
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
    # the emitted wait block carries the unchanged/deadline distinction (the
    # supplied-baseline, never-differed case is distinguishable from an honest
    # deadline — PRR-004 parity with the folded script)
    assert "$waitStop = 'unchanged'" in stub.scripts[-1]
    assert "not $moveSeen" in stub.scripts[-1]


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


# ---------------------------------------------------------------------------
# Final-critic round 1 pins (F3 multi-text framing, F5 tolerance emission,
# F6 stale-hint self-heal retry) — each was mutant-verified: the critic's
# probes B (newline-join drop), A (tolerance widening), and D (self-heal
# removal) fail these tests.
# ---------------------------------------------------------------------------

def test_multi_text_steps_get_one_stdin_line_each(monkeypatch, unrestricted):
    """Two text steps produce exactly TWO newline-separated stdin payload
    lines in plan order, and each text step body consumes one ReadLine —
    a dropped join separator (the critic's probe B) concatenates the lines
    and fails this pin (final-critic finding F3)."""
    first, second = "first-text", "second-text"
    stub = StepStdoutPS("")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(unrestricted, "vm1", [
        {"action": "type_text", "text": first},
        {"action": "press_key", "key": "enter"},
        {"action": "type_text", "text": second},
    ])
    assert out["ok"] is True
    stdin_payload = stub.kwargs[-1]["stdin_b64"]
    assert stdin_payload == (
        pswindows.utf8_b64(first) + "\n" + pswindows.utf8_b64(second))
    action_script = stub.scripts[-1]
    assert action_script.count("[Console]::In.ReadLine()") == 2, (
        "each text step must consume exactly one stdin line, in plan order")


def test_boot_epoch_tolerance_emission_is_pinned(monkeypatch, unrestricted):
    """The folded script embeds the ±5-second boot-epoch comparison (the
    critic's probe A widened it to -gt 5000 and nothing noticed — the anchor
    substring with the closing paren cannot survive that widening;
    final-critic finding F5's PS half)."""
    stub = StepStdoutPS("")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    console.run_sequence(
        unrestricted, "vm1", STEPS, expect_boot_epoch=12345)
    script = stub.scripts[-1]
    assert ") -gt 5) {" in script, (
        "the folded script must compare the boot epoch with the documented "
        "±5 s tolerance")
    assert "12345" in script, "the expected epoch must ride the script"


def test_stale_hint_guard_self_heals_on_retry(monkeypatch, unrestricted):
    """After the identity guard fires, the host refreshes the hint from the
    guard's own report, so the RETRY locks and embeds the live GUID — the
    README/docstring self-heal promise (the critic's probe D removed the
    refresh and nothing noticed; final-critic finding F6)."""
    from hyperv_mcp import console as con
    stale = "e953c649-dcab-438d-9a54-3af74a82b624"
    live = "0f7d1c22-2222-4b3c-8d1e-6a5b4c3d2e1f"
    name = "t-f6-selfheal-vm"
    con.note_name_guid_hint(name, stale)

    class GuardFirePS:
        def __init__(self):
            self.scripts: list[str] = []
            self.kwargs: list[dict] = []
            self.calls = 0

        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            self.kwargs.append(kwargs)
            if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
                return pswindows.PSResult(stdout=live, returncode=0)
            self.calls += 1
            if stale in script:
                return pswindows.PSResult(returncode=1, stderr=(
                    "console press_key: console input precondition: VM identity "
                    "changed under name '" + name + "': locked " + stale
                    + " but resolved " + live))
            return pswindows.PSResult(stdout="RC=0 CHUNK=1/1", returncode=0)

    stub = GuardFirePS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(console.ConsoleError, match="identity changed"):
        console.press_key(unrestricted, name, "enter")
    # the refresh happened: the retry locks on the LIVE identity
    assert con._hint_for(name) == live
    console.press_key(unrestricted, name, "enter")
    retry_script = stub.scripts[-1]
    assert live in retry_script and stale not in retry_script, (
        "the retry must embed the refreshed (live) GUID — the mapping "
        "self-healed from the guard's own report")


# ---------------------------------------------------------------------------
# Feedback round pr107-20261027 (PRR-005/012/014/015/016): validation-arm,
# remote-mode, ordinary-failure, eviction and rejection pins.
# ---------------------------------------------------------------------------

def test_summed_wait_budgets_capped_by_call_timeout(monkeypatch, unrestricted):
    """PRR-005: summed wait budgets must fit the call timeout — a plan whose
    worst case exceeds it is rejected naming the offending step, before any
    spawn; the same plan under a raised timeout_s validates."""
    stub = StepStdoutPS("")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    waits = [{"action": "wait_frame_stable", "stable_ms": 100, "timeout_s": 60}
             for _ in range(3)]
    with pytest.raises(ValueError, match="step 1"):
        console.run_sequence(unrestricted, "vm1", waits, timeout_s=60)
    assert stub.scripts == [], "the sum rejection must fire before any spawn"
    out = console.run_sequence(unrestricted, "vm1", waits, timeout_s=180)
    assert out.get("ok") is True


@pytest.mark.parametrize(
    "steps,match",
    [
        ([{"action": "press_key", "modifiers": [1]}, {"action": "type_text", "text": "x"}],
         "step 0"),                                # non-string modifier
        ([{"action": "key_combo", "keys": ["win", 7]}], "step 0"),  # non-string key
        ([{"action": "type_text"}], "step 0"),    # missing text
        ([{"action": "type_scancodes", "scancodes": "28"}], "step 0"),  # not a list
        ([{"action": "click", "x": 1, "y": 2, "button": 5}], "step 0"),  # bad button
        ([{"action": "mouse_move", "x": 1, "y": 2, "frame_width": -1}], "step 0"),
        ([{"action": "wait_frame_stable", "stable_ms": 0}], "step 0"),
        ([{"action": "wait_frame_stable", "stable_ms": 100, "baseline_hash": "zz"}], "step 0"),
        ([{"action": "scroll"}], "step 0"),       # missing delta
        ([{"action": "press_key", "key": "enter"}, "not-a-dict"], "step 1"),
        ([], "steps"),                            # empty plan
        (None, "steps"),                          # None plan
    ])
def test_remaining_validation_arms_reject_with_step_or_steps(
        monkeypatch, unrestricted, steps, match):
    """PRR-012: the remaining validator rejection arms each raise the
    documented error naming the step (or steps for the plan-level caps), with
    zero PowerShell started."""
    stub = StepStdoutPS("")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(ValueError, match=match):
        console.run_sequence(unrestricted, "vm1", steps)
    assert stub.scripts == []


def test_run_sequence_argument_validation(monkeypatch, unrestricted):
    """PRR-012: the call-level argument gates (frame-hash format, boot-epoch
    type, timeout range, geometry range) reject before anything spawns."""
    stub = StepStdoutPS("")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    bad = [
        {"expect_frame_hash": "nothex"},
        {"expect_boot_epoch": "12345"},
        {"timeout_s": 0},
        {"width": 100},
    ]
    for kwargs in bad:
        with pytest.raises(ValueError):
            console.run_sequence(
                unrestricted, "vm1",
                [{"action": "press_key", "key": "enter"}], **kwargs)
    assert stub.scripts == []


def test_remote_mode_script_embeds_payload_params(monkeypatch, unrestricted):
    """PRR-014: with a remote Hyper-V host configured the sequence script
    carries the $__pN payload parameters instead of local stdin reads, and the
    run carries payload_lines for the composer."""
    secret = "remote-secret"
    stub = StepStdoutPS("")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    monkeypatch.setattr(pswindows, "hyperv_host", lambda cfg: "remote-host")
    out = console.run_sequence(unrestricted, "vm1", [
        {"action": "type_text", "text": secret},
        {"action": "type_text", "text": "second"},
    ])
    assert out["ok"] is True
    script = stub.scripts[-1]
    assert "$payloads = @($__p0, $__p1)" in script
    # remote mode: the step body reads $payloads[$ti]; the ReadLine lives in
    # the composer preamble's $__pN assignments, never inside the FromBase64
    # decode of a step body (the local-mode shape)
    assert "FromBase64String([Console]::In.ReadLine())" not in script
    assert "FromBase64String($payloads[$ti])" in script
    # remote mode forwards the payload lines through stdin for the composer
    stdin_payload = stub.kwargs[-1]["stdin_b64"]
    assert pswindows.utf8_b64(secret) in stdin_payload
    assert pswindows.utf8_b64("second") in stdin_payload


def test_ordinary_failure_surfaces_via_check_input_rc(monkeypatch, unrestricted):
    """PRR-015: an ordinary (non-precondition, non-timeout) nonzero exit
    surfaces as ConsoleError through the input check — and does NOT touch the
    hint map when the marker is absent."""
    from hyperv_mcp import console as con
    name = "t-ordinary-failure-vm"
    recording = StepStdoutPS("")

    def failer(script, **kwargs):
        recording.scripts.append(script)
        if "Get-VM -Id" in script:
            return pswindows.PSResult(stdout="resolved", returncode=0)
        return pswindows.PSResult(
            returncode=1, stderr="SetScrollPosition failed with ReturnValue=11")

    monkeypatch.setattr(pswindows, "run_ps", failer)
    with pytest.raises(console.ConsoleError, match="ReturnValue=11"):
        console.run_sequence(
            unrestricted, name, [{"action": "scroll", "delta": 1}])
    assert con._hint_for(name) is None, (
        "an ordinary failure carries no identity marker and must not seed a hint")


def test_hint_and_unknown_maps_bounded_and_rejecting(monkeypatch, unrestricted):
    """PRR-016: the hint map rejects malformed GUIDs and empty names; both
    maps evict their oldest entry at their caps."""
    from hyperv_mcp import console as con
    con.note_name_guid_hint("vm-a", "not-a-guid")
    assert con._hint_for("vm-a") is None
    con.note_name_guid_hint("   ", con.SEQ_GUID if hasattr(con, "SEQ_GUID")
                            else "e953c649-dcab-438d-9a54-3af74a82b624")
    # fill past the cap and confirm the map stays bounded (oldest evicted)
    for i in range(con._HINT_CAP + 8):
        con.note_name_guid_hint(f"churn-{i}", "e953c649-dcab-438d-9a54-3af74a82b624")
    assert len(con._NAME_GUID_HINTS) <= con._HINT_CAP
    # unknown-record eviction
    for i in range(con._UNKNOWN_CAP + 8):
        con._record_unknown(f"k-{i}", {"n": i})
    assert len(con._UNKNOWN_RESULTS) <= con._UNKNOWN_CAP
    assert con._lookup_unknown("k-0") is None, "oldest unknown record evicted"
    assert con._lookup_unknown(f"k-{con._UNKNOWN_CAP + 7}") == {
        "n": con._UNKNOWN_CAP + 7}
