"""Issue #28 acceptance checks (trace 77-28-console-actor-batched-sequences,
workstream F PR 4): batched console action sequences with frame and boot
preconditions.

Every check in this file is RED at base 4c7ac52 for its named reason and
GREEN after the fix. The transport is the folded PowerShell one (the conftest
autouse fixture pins wmiconsole.COM_AVAILABLE to False) and
pswindows.run_ps is stubbed per the FakePS idiom in test_console.py; nothing
here touches a real Hyper-V host.

Frozen run_sequence contract this file pins (the issue names the surface
console.run_sequence(cfg, vm_name, steps, ...); the remaining shapes are
underdetermined by the issue text, so this file IS the spec the fix
implements against):

  signature .... console.run_sequence(cfg, vm_name="", steps=None, vm_id="",
                  expect_frame_hash="", expect_boot_epoch=None,
                  timeout_s=60, request_key="") -> dict
                  (request_key is the issue's "request correlation key")
  steps ........ a list of at most 50 dicts, one per step; the action set and
                  fields mirror the single-step tools:
                    press_key: key, modifiers (optional)
                    key_combo: keys
                    type_text: text (ASCII; rides stdin base64, never script)
                    type_scancodes: scancodes
                    mouse_move: x, y, frame_width, frame_height
                    click: x, y (both or neither), frame_width,
                      frame_height, button
                    mouse_button: button, is_down
                    scroll: delta
                    wait_frame_stable: stable_ms, timeout_s, interval_ms,
                      baseline_hash
                  An invalid step raises ValueError naming "step <i>"; more
                  than 50 steps raises ValueError mentioning "steps". Sleep
                  and wait budgets are capped by the call timeout_s.
  success ...... {"ok": True, "vm_name": ..., "boot_epoch": <not None>,
                  "steps": [{"ok": True, ...} per step], ...}. The whole
                  sequence drives ONE folded action script after GUID
                  resolution; per-step ok is reported for every step.
  precondition . A mismatched expect_frame_hash / expect_boot_epoch RETURNS
                  (never raises) {"ok": False, "error_class": "precondition",
                  "steps": [], ...} and the actual observed value appears in
                  the result; no input executes.
  unknown ...... An uncertain post-dispatch transport failure (a timed-out
                  leg, PSResult timed_out=True exactly like the real run_ps)
                  is recorded once as an UNKNOWN outcome (the serialized
                  result mentions "unknown") with executed-prefix steps
                  metadata, is never automatically replayed, and a retry
                  carrying the same request_key returns the recorded result
                  without re-driving the guest.

Stub-side protocol this file serves (and the implementation must parse): the
folded sequence script exits 0 with stdout metadata lines VMID=<guid> and
EPOCH=<int>; a precondition mismatch exits nonzero with a stderr line
mentioning "precondition" plus the expected and actual values (all other
nonzero exits are ordinary ConsoleError failures).

AC map (01-issue-summary.md):
  AC-28.1 test_sequence_denied_by_default_before_any_powershell
  AC-28.2 test_invalid_step_raises_value_error_naming_index
  AC-28.3 test_step_count_capped_and_wait_budgets_bounded_by_timeout
  AC-28.4 test_one_folded_process_stdin_text_and_per_step_ok
  AC-28.5 test_precondition_mismatch_returns_envelope_without_input
  AC-28.6 test_console_write_lock_held_for_whole_sequence
  AC-28.7 test_sequence_tool_schema_and_boot_epoch_reporting
  AC-28.13 test_active_sequence_excludes_raw_input_and_second_sequence
  AC-28.14 test_two_vm_sequences_progress_concurrently
  AC-28.15 test_uncertain_outcome_recorded_unknown_and_replayed_by_request_key
"""

import asyncio
import importlib
import json
import re
import threading
import time

import pytest

from hyperv_mcp import console, pswindows, vmlocks
from hyperv_mcp.config import Config
from hyperv_mcp.policy import PolicyDenied

SEQ_GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
G286 = "11111111-2222-4333-8444-555555555556"
G2813 = "11111111-2222-4333-8444-555555555513"
G2814A = "11111111-2222-4333-8444-55555555514a"
G2814B = "11111111-2222-4333-8444-55555555514b"
G2815 = "11111111-2222-4333-8444-555555555515"

STEPS_BASIC = [{"action": "press_key", "key": "enter"}]


def _is_resolution_leg(script: str) -> bool:
    """A standalone resolution leg: the by-id Get-VM -Id lookup, or the bare
    by-name resolver emission (the shapes the shipped code produces today)."""
    if "Get-VM -Id" in script:
        return True
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


class SeqPS:
    """Recording run_ps stub serving the folded sequence legs per the frozen
    protocol in the module docstring. Resolution legs answer with the VM's
    display name; the sequence script answers VMID/EPOCH on success, a
    precondition-tagged nonzero exit when the script embeds an expectation
    the live VM does not satisfy, and records whether input executed."""

    def __init__(self, guid: str = SEQ_GUID, name: str = "seq-vm", epoch: int = 4242,
                 live_frame_hash: str = "", expect_frame_hash: str = "",
                 expect_boot_epoch: int | None = None):
        self.scripts: list[str] = []
        self.kwargs: list[dict] = []
        self.guid = guid
        self.name = name
        self.epoch = epoch
        self.live_frame_hash = live_frame_hash
        self.expect_frame_hash = expect_frame_hash
        self.expect_boot_epoch = expect_boot_epoch
        self.input_executed = False
        self.sequence_calls = 0

    def _success(self) -> pswindows.PSResult:
        self.input_executed = True
        return pswindows.PSResult(
            stdout="VMID=" + self.guid + "\nEPOCH=" + str(self.epoch) + "\n",
            returncode=0)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=self.name, returncode=0)
        self.sequence_calls += 1
        if self.expect_frame_hash and self.expect_frame_hash in script:
            return pswindows.PSResult(returncode=1, stderr=(
                "console sequence precondition mismatch: frame_hash expected "
                + self.expect_frame_hash + " actual " + self.live_frame_hash))
        if self.expect_boot_epoch is not None and str(self.expect_boot_epoch) in script:
            return pswindows.PSResult(returncode=1, stderr=(
                "console sequence precondition mismatch: boot_epoch expected "
                + str(self.expect_boot_epoch) + " actual " + str(self.epoch)))
        return self._success()


class DisplayInfoPS:
    """Serves the folded display-info leg with VMID= and EPOCH= metadata
    ahead of the snake_case JSON (the existing folded grammar plus the boot
    epoch line the fix adds)."""

    def __init__(self, guid: str = SEQ_GUID, epoch: int = 12345):
        self.scripts: list[str] = []
        self.guid = guid
        self.epoch = epoch

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        body = json.dumps({
            "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
            "keyboard_present": True, "keyboard_enabled": 2,
            "mouse_present": True, "mouse_enabled": 2,
        })
        return pswindows.PSResult(
            stdout="VMID=" + self.guid + "\nEPOCH=" + str(self.epoch) + "\n" + body,
            returncode=0)


# ---------------------------------------------------------------------------
# AC-28.1: console_input gate before any PowerShell
# ---------------------------------------------------------------------------

def test_sequence_denied_by_default_before_any_powershell(monkeypatch):
    """AC-28.1: console.run_sequence with the console_input category
    disabled raises PolicyDenied naming console_input BEFORE any PowerShell
    runs (the stub records zero scripts).
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    cfg = Config(allowed_vm_patterns=["t281-*"])  # name allowed, input disabled
    stub = SeqPS(name="t281-vm")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(PolicyDenied, match="console_input"):
        console.run_sequence(
            cfg, "t281-vm", [{"action": "press_key", "key": "enter"}])
    assert stub.scripts == [], (
        "the console_input denial must fire before any PowerShell leg — "
        "neither a resolution leg nor the sequence script may start")


# ---------------------------------------------------------------------------
# AC-28.2: invalid steps raise ValueError naming the step index
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "steps,match",
    [
        ([{"action": "teleport"}], "step 0"),                       # unknown action
        ([{"action": "press_key", "key": "meta"}], "step 0"),       # unknown key
        ([{"action": "type_text", "text": "café"}], "step 0"),      # non-ASCII text
        ([{"action": "type_scancodes", "scancodes": [256]}], "step 0"),  # out of range
        ([{"action": "click", "x": 10}], "step 0"),                 # bad coordinates
        ([{"action": "press_key", "key": "enter"},
          {"action": "key_combo", "keys": ["meta"]}], "step 1"),    # names THE index
    ],
)
def test_invalid_step_raises_value_error_naming_index(
        monkeypatch, unrestricted, steps, match):
    """AC-28.2: any invalid step raises ValueError naming the step index and
    no input script is sent. The last variant plants the bad step at index 1
    so a blanket message without the index cannot pass.
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(ValueError, match=match):
        console.run_sequence(unrestricted, "vm1", steps)
    assert stub.scripts == [], "step validation must reject the plan before any spawn"


# ---------------------------------------------------------------------------
# AC-28.3: step-count cap and wait budgets bounded by the call timeout
# ---------------------------------------------------------------------------

def test_step_count_capped_and_wait_budgets_bounded_by_timeout(
        monkeypatch, unrestricted):
    """AC-28.3: more than 50 steps raises ValueError mentioning "steps" with
    no script sent, and a wait step's own budget cannot exceed the call
    timeout_s (every in-script AddSeconds deadline is capped at the call
    bound).
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(ValueError, match="steps"):
        console.run_sequence(
            unrestricted, "vm1", [{"action": "press_key", "key": "enter"}] * 51)
    assert stub.scripts == []

    ok_stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", ok_stub)
    out = console.run_sequence(unrestricted, "vm1", [
        {"action": "wait_frame_stable", "stable_ms": 100, "timeout_s": 999,
         "interval_ms": 50},
        {"action": "press_key", "key": "enter"},
    ], timeout_s=30)
    assert out.get("ok") is True, f"the capped valid sequence must succeed: {out}"
    deadlines = [int(n) for n in re.findall(r"AddSeconds\((\d+)\)", ok_stub.scripts[-1])]
    assert all(n <= 30 for n in deadlines), (
        f"sleep/wait budgets must be capped by the call timeout_s=30, saw "
        f"in-script deadlines {deadlines}")


# ---------------------------------------------------------------------------
# AC-28.4: one folded process, stdin-carried text, per-step ok
# ---------------------------------------------------------------------------

def test_one_folded_process_stdin_text_and_per_step_ok(monkeypatch, unrestricted):
    """AC-28.4: a multi-step sequence drives exactly ONE action script (after
    GUID resolution, whether folded or a separate leg), text steps ride
    stdin base64 and never appear in the script, and per-step ok is reported
    for every step.
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    secret = "S3cr3t-Seq-P4ss!"
    steps = [
        {"action": "press_key", "key": "enter"},
        {"action": "type_text", "text": secret},
        {"action": "key_combo", "keys": ["win", "r"]},
        {"action": "click", "x": 8, "y": 9},
    ]
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(unrestricted, "vm1", steps)

    action_scripts = [s for s in stub.scripts if not _is_resolution_leg(s)]
    assert len(action_scripts) == 1, (
        f"the whole sequence must use ONE action script after GUID "
        f"resolution, saw {len(action_scripts)} (plus "
        f"{len(stub.scripts) - len(action_scripts)} resolution legs)")
    assert len(stub.scripts) <= 2, "at most one resolution leg may precede the script"
    script = action_scripts[0]
    # the stdin rule, asserted the way test_type_text_rides_stdin_never_script does
    assert secret not in script
    assert "[Console]::In.ReadLine()" in script
    stdin_payload = stub.kwargs[stub.scripts.index(script)].get("stdin_b64", "")
    assert pswindows.utf8_b64(secret) in stdin_payload, (
        "text steps must ride stdin as UTF-8 base64 lines")
    # per-step results
    assert out.get("ok") is True, f"the sequence must succeed: {out}"
    per_step = out["steps"]
    assert len(per_step) == len(steps), (
        f"one result per step: got {len(per_step)} for {len(steps)} steps")
    assert all(s.get("ok") is True for s in per_step), per_step
    assert out.get("boot_epoch") is not None, (
        "the sequence result must report the guest boot epoch")


# ---------------------------------------------------------------------------
# AC-28.5: precondition mismatch returns the envelope, no input
# ---------------------------------------------------------------------------

def test_precondition_mismatch_returns_envelope_without_input(
        monkeypatch, unrestricted):
    """AC-28.5: an expect_frame_hash mismatch RETURNS
    {"ok": False, "error_class": "precondition", "steps": []} with the actual
    hash carried in the result and no input executed; an expect_boot_epoch
    mismatch returns the same envelope. The expectation rides the script so
    the in-script exit-before-input guard is what trips.
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    expect_hash = "c" * 64
    live_hash = "b" * 64
    stub = SeqPS(live_frame_hash=live_hash, expect_frame_hash=expect_hash)
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        unrestricted, "vm1", [{"action": "press_key", "key": "enter"}],
        expect_frame_hash=expect_hash)
    assert isinstance(out, dict), "a precondition mismatch is returned, never raised"
    assert out["ok"] is False
    assert out["error_class"] == "precondition"
    assert out["steps"] == []
    assert live_hash in json.dumps(out), (
        "the precondition envelope must carry the ACTUAL observed hash")
    assert any(expect_hash in s for s in stub.scripts), (
        "the expected frame hash must ride the folded script so the guard "
        "compares it before any input")
    assert stub.input_executed is False, (
        "no console input may execute on a precondition mismatch")

    stub2 = SeqPS(epoch=4242, expect_boot_epoch=1000)
    monkeypatch.setattr(pswindows, "run_ps", stub2)
    out2 = console.run_sequence(
        unrestricted, "vm1", [{"action": "press_key", "key": "enter"}],
        expect_boot_epoch=1000)
    assert out2["ok"] is False and out2["error_class"] == "precondition"
    assert out2["steps"] == []
    assert stub2.input_executed is False


# ---------------------------------------------------------------------------
# AC-28.6: the console WRITE key is held for the whole sequence
# ---------------------------------------------------------------------------

def test_console_write_lock_held_for_whole_sequence(monkeypatch, unrestricted):
    """AC-28.6: from inside the stubbed transport (running on the sequence's
    own thread) a vm_lock attempt on the console key raises VMBusy — the
    same-thread re-entry guard only fires when THIS thread holds the key as
    writer, so a clean acquire would prove the sequence skipped the lock.
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    class LockProbePS(SeqPS):
        probe_held: bool | None = None

        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            self.kwargs.append(kwargs)
            if _is_resolution_leg(script):
                return pswindows.PSResult(stdout=self.name, returncode=0)
            self.sequence_calls += 1
            try:
                with vmlocks.vm_lock((G286, "console"), wait_s=0):
                    self.probe_held = False
            except vmlocks.VMBusy:
                self.probe_held = True
            return self._success()

    stub = LockProbePS(guid=G286, name="t286-vm")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        unrestricted, vm_name="t286-vm", vm_id=G286,
        steps=[{"action": "press_key", "key": "enter"}])
    assert out.get("ok") is True
    assert stub.probe_held is True, (
        "AC-28.6: the console WRITE key was NOT held while the sequence's "
        "transport script ran — a same-thread re-entry probe acquired it "
        "cleanly, so the per-VM lock does not span the whole sequence")


# ---------------------------------------------------------------------------
# AC-28.7: server registration and boot_epoch reporting
# ---------------------------------------------------------------------------

def test_sequence_tool_schema_and_boot_epoch_reporting(monkeypatch, unrestricted):
    """AC-28.7: hyperv_console_sequence is registered with steps,
    expect_frame_hash and expect_boot_epoch and WITHOUT a confirm parameter;
    get_display_info and the sequence result both report boot_epoch.
    RED at base for the named reason (the tool is not registered and
    boot_epoch does not exist in the console surface), GREEN after the fix.
    Schema half follows the fresh_server/_schemas idiom from
    tests/unit/test_server.py (that file itself stays untouched)."""
    import hyperv_mcp.server as server_module

    mod = importlib.reload(server_module)
    try:
        mod.bootstrap({})
        mcp = mod.get_mcp()
        tools = asyncio.run(mcp.list_tools())
        schemas = {
            t.name: (getattr(t, "input_schema", None) or t.inputSchema)
            for t in tools
        }
        assert "hyperv_console_sequence" in schemas, (
            "AC-28.7: hyperv_console_sequence is not registered in the "
            "server tool inventory")
        props = schemas["hyperv_console_sequence"].get("properties", {})
        for prop in ("vm_name", "vm_id", "steps", "expect_frame_hash",
                     "expect_boot_epoch"):
            assert prop in props, (
                f"hyperv_console_sequence is missing the {prop} parameter")
        assert "confirm" not in props, (
            "the batched sequence tool must not force a human confirm prompt")
        assert "steps" in schemas["hyperv_console_sequence"].get("required", []), (
            "steps is semantically required — a sequence without steps is invalid")
    finally:
        importlib.reload(server_module)

    info_stub = DisplayInfoPS(epoch=12345)
    monkeypatch.setattr(pswindows, "run_ps", info_stub)
    info = console.get_display_info(unrestricted, "t287-vm")
    assert info.get("boot_epoch") == 12345, (
        "get_display_info must report the guest boot epoch")

    seq_stub = SeqPS(epoch=4242)
    monkeypatch.setattr(pswindows, "run_ps", seq_stub)
    out = console.run_sequence(
        unrestricted, "t287-seq-vm", [{"action": "press_key", "key": "enter"}])
    assert out.get("ok") is True
    assert out.get("boot_epoch") == 4242, (
        "the sequence result must report the guest boot epoch")


# ---------------------------------------------------------------------------
# AC-28.13: an active sequence excludes raw input and a second sequence
# ---------------------------------------------------------------------------

def test_active_sequence_excludes_raw_input_and_second_sequence(
        monkeypatch, unrestricted):
    """AC-28.13: while a sequence is in flight on a VM, a concurrent raw
    console input on the same VM cannot interleave (it meets the held
    console WRITE key and fails VMBusy inside a short bounded wait) and a
    second sequence on the same VM starts its transport leg only after the
    first sequence's terminal result (recorded entry/exit order, never
    overlapping). Lease authorization retention per request is a live-host
    property pinned by the integration leg, not here.
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    cfg = unrestricted

    class GatedSeqPS(SeqPS):
        def __init__(self, guid, name):
            super().__init__(guid=guid, name=name)
            self.in_flight = threading.Event()
            self.release = threading.Event()
            self._mu = threading.Lock()
            self._current = 0
            self.peak = 0
            self.entries: list[float] = []
            self.exits: list[float] = []

        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            self.kwargs.append(kwargs)
            if _is_resolution_leg(script):
                return pswindows.PSResult(stdout=self.name, returncode=0)
            with self._mu:
                self._current += 1
                self.peak = max(self.peak, self._current)
                self.entries.append(time.monotonic())
            self.in_flight.set()
            self.release.wait(15)  # generous bound; the test always releases
            with self._mu:
                self._current -= 1
                self.exits.append(time.monotonic())
            return self._success()

    stub = GatedSeqPS(G2813, "t2813-vm")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    outcomes: dict[str, str] = {}

    def _run_seq(label, steps):
        try:
            out = console.run_sequence(
                cfg, vm_name="t2813-vm", vm_id=G2813, steps=steps)
            outcomes[label] = "ok" if out.get("ok") else "bad"
        except Exception as exc:  # the contention outcome IS the behavior
            outcomes[label] = type(exc).__name__

    w1 = threading.Thread(
        target=_run_seq, args=("seq1", [{"action": "press_key", "key": "enter"}]))
    w1.start()
    w2: threading.Thread | None = None
    try:
        assert stub.in_flight.wait(5), (
            f"the first sequence never reached its transport leg "
            f"(worker outcome so far: {outcomes})")
        # concurrent RAW input on the same VM: meets the held console key and
        # fails VMBusy inside the (temporarily shortened) bounded wait
        real_wait = vmlocks._DEFAULT_WAIT_S
        monkeypatch.setattr(vmlocks, "_DEFAULT_WAIT_S", 0.5)
        try:
            with pytest.raises(vmlocks.VMBusy):
                console.press_key(cfg, "t2813-vm", vm_id=G2813, key="enter")
        finally:
            monkeypatch.setattr(vmlocks, "_DEFAULT_WAIT_S", real_wait)
        # a second sequence may not interleave: it parks on the same key and
        # only runs its leg after the first sequence's terminal result
        w2 = threading.Thread(
            target=_run_seq, args=("seq2", [{"action": "type_text", "text": "second"}]))
        w2.start()
    finally:
        stub.release.set()
    w1.join(timeout=20)
    if w2 is not None:
        w2.join(timeout=20)
    assert outcomes == {"seq1": "ok", "seq2": "ok"}, outcomes
    assert stub.peak == 1, (
        "two same-VM sequence transport legs ran concurrently — a sequence "
        "must exclude every other same-VM plan until its terminal result")
    assert stub.exits[0] <= stub.entries[1], (
        "the second sequence's leg started before the first sequence's "
        "terminal result")


# ---------------------------------------------------------------------------
# AC-28.14: sequences on two different VM GUIDs progress concurrently
# ---------------------------------------------------------------------------

def test_two_vm_sequences_progress_concurrently(monkeypatch, unrestricted):
    """AC-28.14: two sequences addressing two different canonical VM GUIDs
    run their transport legs CONCURRENTLY (each leg observes the other
    already in flight, with a generous bounded cross-wait so a serializing
    implementation completes instead of deadlocking, then fails the
    concurrency assertion), both complete, and each transcript carries only
    its own VM's steps (its own stdin text, never the other plan's).
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    cfg = unrestricted
    secret_a = "SECRET-A-PLAN"
    secret_b = "SECRET-B-PLAN"

    class TwoVMPS:
        def __init__(self, vms: dict[str, str]):
            self.scripts: list[str] = []
            self.kwargs: list[dict] = []
            self.vms = vms  # guid -> display name
            self.started = {g: threading.Event() for g in vms}
            self.saw_other: dict[str, bool | None] = {g: None for g in vms}
            self.calls: dict[str, tuple[str, dict]] = {}

        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            self.kwargs.append(kwargs)
            owner = next(g for g in self.vms if g in script)
            if _is_resolution_leg(script):
                return pswindows.PSResult(stdout=self.vms[owner], returncode=0)
            self.started[owner].set()
            other = next(g for g in self.vms if g != owner)
            self.saw_other[owner] = self.started[other].wait(5)
            self.calls[owner] = (script, kwargs)
            return pswindows.PSResult(
                stdout="VMID=" + owner + "\nEPOCH=9\n", returncode=0)

    stub = TwoVMPS({
        G2814A: "t2814-a-vm",
        G2814B: "t2814-b-vm",
    })
    monkeypatch.setattr(pswindows, "run_ps", stub)
    results: dict[str, object] = {}

    def _run(label, guid, steps):
        try:
            results[label] = console.run_sequence(
                cfg, vm_name=stub.vms[guid], vm_id=guid, steps=steps)
        except Exception as exc:
            results[label] = type(exc).__name__

    steps_a = [
        {"action": "press_key", "key": "enter"},
        {"action": "type_text", "text": secret_a},
    ]
    steps_b = [
        {"action": "type_text", "text": secret_b},
        {"action": "click", "x": 4, "y": 5},
    ]
    ta = threading.Thread(target=_run, args=("a", G2814A, steps_a))
    tb = threading.Thread(target=_run, args=("b", G2814B, steps_b))
    ta.start()
    tb.start()
    ta.join(timeout=25)
    tb.join(timeout=25)

    out_a, out_b = results["a"], results["b"]
    assert isinstance(out_a, dict) and out_a.get("ok") is True, results
    assert isinstance(out_b, dict) and out_b.get("ok") is True, results
    assert stub.saw_other[G2814A] is True and stub.saw_other[G2814B] is True, (
        f"the two VM sequences did not progress concurrently "
        f"(saw_other={stub.saw_other})")
    # each transcript limited to its own VM's steps
    assert len(out_a["steps"]) == len(steps_a) and all(
        s.get("ok") is True for s in out_a["steps"])
    assert len(out_b["steps"]) == len(steps_b) and all(
        s.get("ok") is True for s in out_b["steps"])
    script_a, kw_a = stub.calls[G2814A]
    script_b, kw_b = stub.calls[G2814B]
    stdin_a = kw_a.get("stdin_b64", "")
    stdin_b = kw_b.get("stdin_b64", "")
    assert pswindows.utf8_b64(secret_a) in stdin_a
    assert pswindows.utf8_b64(secret_b) in stdin_b
    assert secret_a not in script_a and secret_a not in script_b
    assert secret_b not in script_a and secret_b not in script_b
    assert pswindows.utf8_b64(secret_a) not in stdin_b, (
        "VM A's plan text leaked into VM B's transcript")
    assert pswindows.utf8_b64(secret_b) not in stdin_a, (
        "VM B's plan text leaked into VM A's transcript")


# ---------------------------------------------------------------------------
# AC-28.15: uncertain outcome recorded UNKNOWN; same request_key replays it
# ---------------------------------------------------------------------------

def test_uncertain_outcome_recorded_unknown_and_replayed_by_request_key(
        monkeypatch, unrestricted):
    """AC-28.15: an uncertain post-dispatch transport failure (the leg times
    out exactly the way the real run_ps reports it — PSResult timed_out=True
    — so whether the guest received the input is unknowable) records an
    UNKNOWN outcome once, with executed-prefix steps metadata, without any
    automatic replay; retrying with the same request correlation key
    (request_key, the issue's own term) returns the recorded UNKNOWN result
    instead of re-driving the guest. The admission-vs-execution ordering of
    the precondition recheck is pinned by the AC-28.5 check (the mismatch is
    evaluated under the lock at execution and refuses before input).
    RED at base for the named reason (console.run_sequence is absent),
    GREEN after the fix."""
    class TimeoutSeqPS(SeqPS):
        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            self.kwargs.append(kwargs)
            if _is_resolution_leg(script):
                return pswindows.PSResult(stdout=self.name, returncode=0)
            self.sequence_calls += 1
            return pswindows.PSResult(timed_out=True, returncode=None, duration_ms=7)

    stub = TimeoutSeqPS(guid=G2815, name="t2815-vm")
    monkeypatch.setattr(pswindows, "run_ps", stub)
    steps = [
        {"action": "press_key", "key": "enter"},
        {"action": "type_text", "text": "maybe-sent"},
    ]
    request_key = "t2815-request-key-1"

    out = console.run_sequence(
        unrestricted, vm_name="t2815-vm", vm_id=G2815, steps=steps,
        request_key=request_key)
    assert isinstance(out, dict), "the uncertain outcome is recorded, never raised"
    assert out.get("ok") is False
    assert "unknown" in json.dumps(out).lower(), (
        "an uncertain post-dispatch outcome must be recorded as UNKNOWN "
        f"(result: {out})")
    assert "steps" in out, "the UNKNOWN record must carry executed-prefix metadata"
    assert stub.sequence_calls == 1, (
        "no automatic replay: the uncertain leg must be driven exactly once")
    assert stub.input_executed is False  # the timed-out leg never confirmed input

    retried = console.run_sequence(
        unrestricted, vm_name="t2815-vm", vm_id=G2815, steps=steps,
        request_key=request_key)
    assert stub.sequence_calls == 1, (
        "retrying with the same request_key must return the recorded UNKNOWN "
        "result instead of re-driving the guest")
    assert retried.get("ok") is False
    assert "unknown" in json.dumps(retried).lower(), (
        f"the retried call must return the recorded UNKNOWN result: {retried}")
