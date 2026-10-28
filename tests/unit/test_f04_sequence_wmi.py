"""WMI-transport companion to the frozen sequence checks (final-critic
round 1, finding F2): the frozen suite deliberately scopes to the folded
PowerShell transport (conftest pins COM_AVAILABLE False), which left the
in-process WMI sequence lane — including the round-1 review's single-lock
restructure — completely unpinned (the critic's probe C survived everything).
These tests drive console.run_sequence over a FAKE backend (never real COM)
and pin: the ONE `_input_lock` acquisition spanning boot epoch, frame
precondition, and every step; the WMI precondition envelopes; and the
per-step shapes. GREEN at the final-critic head; each assertion here was
mutant-verified by the critic's probe C (a lock-scope regression fails the
acquisition-count pin)."""

import pytest

from hyperv_mcp import console, pswindows, vmident, wmiconsole
from hyperv_mcp.config import Config

WMI_GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


def _pixels(w: int, h: int, fill: int) -> bytes:
    return bytes([0, 0, 0, 0]) + bytes([fill]) * (w * h * 2)


class FakeWMI:
    """Minimal backend surface for the sequence lane (only what
    console.run_sequence calls). Records the call order so the tests can pin
    precondition-before-input."""

    def __init__(self, epoch: int = 1000, frame_fill: int = 7):
        self.calls: list[str] = []
        self.epoch = epoch
        self.frame_fill = frame_fill
        self.texts: list[str] = []
        self.scancode_calls = 0

    def resolve_vm(self, cfg, vm_name="", vm_id=""):
        self.calls.append("resolve_vm")
        return vmident.VMRef(id=WMI_GUID, name=vm_name or "wmi-vm")

    def boot_epoch(self, guid):
        self.calls.append("boot_epoch")
        return self.epoch

    def capture(self, guid, width, height):
        self.calls.append("capture")
        return _pixels(width, height, self.frame_fill), {}

    def type_text(self, guid, text):
        self.calls.append("type_text")
        self.texts.append(text)
        return None, {}

    def type_scancodes(self, guid, codes):
        self.calls.append("type_scancodes")
        self.scancode_calls += 1
        return None, {}

    def head_resolution(self, guid):
        self.calls.append("head_resolution")
        return (1024, 768), {}

    def mouse_move(self, guid, hx, hy):
        self.calls.append("mouse_move")
        return None, {}

    def mouse_click(self, guid, button, hx=None, hy=None):
        self.calls.append("mouse_click")
        return None, {}

    def mouse_button(self, guid, button, is_down):
        self.calls.append("mouse_button")
        return None, {}

    def mouse_scroll(self, guid, delta):
        self.calls.append("mouse_scroll")
        return None, {}


@pytest.fixture()
def wmi_path(monkeypatch):
    """Force the WMI transport selection with a fake backend factory."""
    holder: dict = {"backend": None}

    def _install(backend: FakeWMI):
        holder["backend"] = backend
        monkeypatch.setattr(console, "_try_backend", lambda cfg: (backend, 0.0))
        return backend

    yield _install


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


def test_wmi_sequence_one_lock_across_everything(wmi_path, unrestricted, monkeypatch):
    """The round-1 review fix (critic probe C): the WMI path takes the console
    WRITE key exactly ONCE, and the boot-epoch read, the frame precondition
    capture, and every step all happen INSIDE that single acquisition. The
    spy records HOLD-STATE and the fake backend reports it per call, so the
    enclosure (not merely the entry count) is what is asserted: hoisting the
    boot read or the step loop outside the lock fails this pin (the delta
    reviewer's finding — the f1ff285 shape had exactly that hoisted boot
    read)."""
    be = wmi_path(FakeWMI())
    acquisitions: list[tuple] = []
    hold_state = {"held": False}
    real = console._input_lock

    import contextlib

    @contextlib.contextmanager
    def spy(ref):
        acquisitions.append(ref.id)
        with real(ref):
            hold_state["held"] = True
            try:
                yield
            finally:
                hold_state["held"] = False

    monkeypatch.setattr(console, "_input_lock", spy)
    # every backend call records whether the console key was held at that moment
    original_methods = {
        name: getattr(be, name)
        for name in ("boot_epoch", "capture", "type_scancodes", "type_text",
                     "mouse_scroll")
    }

    def recorded(name):
        method = original_methods[name]

        def wrapper(*args, **kwargs):
            be.calls.append((name, hold_state["held"]))
            return method(*args, **kwargs)

        return wrapper

    for name in original_methods:
        setattr(be, name, recorded(name))
    be.calls = []
    out = console.run_sequence(
        unrestricted, "wmi-vm",
        [{"action": "press_key", "key": "enter"},
         {"action": "type_text", "text": "hi"},
         {"action": "scroll", "delta": 2}],
        expect_frame_hash=console._frame_hash(_pixels(640, 480, 7)),
        width=640, height=480)
    assert out["ok"] is True, out
    assert acquisitions == [WMI_GUID], (
        "the WMI sequence must take the console key exactly once; saw "
        f"{len(acquisitions)} acquisitions")
    # ENCLOSURE, not just the count: every preconditions-and-steps call ran
    # while the single acquisition was held
    lock_bearing = [entry for entry in be.calls if entry[0] in original_methods]
    assert lock_bearing, "the fake backend calls must be recorded"
    unlocked = [entry for entry in lock_bearing if entry[1] is not True]
    assert unlocked == [], (
        "boot-epoch read, frame precondition capture, and every step must run "
        f"INSIDE the single console-key acquisition; ran unlocked: {unlocked}")
    kinds = [entry[0] for entry in lock_bearing]
    assert kinds.index("capture") < kinds.index("type_scancodes")
    assert kinds.index("boot_epoch") < kinds.index("type_scancodes")


def test_wmi_frame_precondition_envelope_without_input(wmi_path, unrestricted):
    """A frame-hash mismatch on the WMI transport returns the precondition
    envelope with the actual hash and executes NO input step."""
    be = wmi_path(FakeWMI(frame_fill=7))
    out = console.run_sequence(
        unrestricted, "wmi-vm",
        [{"action": "press_key", "key": "enter"}],
        expect_frame_hash="c" * 64, width=640, height=480)
    assert out["ok"] is False
    assert out["error_class"] == "precondition"
    assert out["steps"] == []
    assert out["precondition"] == "frame_hash", (
        "the WMI envelope must carry the same kind discriminator as the PS lane")
    assert out["frame_hash"] == console._frame_hash(_pixels(640, 480, 7))
    assert out["hash_domain"] == console.HASH_DOMAIN
    assert be.calls.count("type_scancodes") == 0, "no input may execute on a mismatch"


def test_wmi_boot_epoch_precondition_envelope(wmi_path, unrestricted):
    """A boot-epoch mismatch beyond the documented ±5 s tolerance returns the
    precondition envelope on the WMI transport (final-critic finding F5's WMI
    half: a tolerance widening mutant fails this — a 6 s drift must fire)."""
    be = wmi_path(FakeWMI(epoch=1000))
    out = console.run_sequence(
        unrestricted, "wmi-vm",
        [{"action": "press_key", "key": "enter"}],
        expect_boot_epoch=1006)  # 6 s drift: outside ±5, inside any widened bound
    assert out["ok"] is False
    assert out["error_class"] == "precondition"
    assert out["precondition"] == "boot_epoch", (
        "the WMI envelope must carry the same kind discriminator as the PS lane")
    assert out["boot_epoch"] == 1000
    assert be.calls.count("type_scancodes") == 0


def test_wmi_step_shapes_in_order(wmi_path, unrestricted):
    """Steps execute against the backend primitives in plan order with
    per-step ok results."""
    be = wmi_path(FakeWMI())
    out = console.run_sequence(
        unrestricted, "wmi-vm",
        [{"action": "type_text", "text": "abc"},
         {"action": "mouse_button", "button": 2, "is_down": True},
         {"action": "scroll", "delta": -3}])
    assert out["ok"] is True
    assert be.texts == ["abc"]
    input_calls = [c for c in be.calls if c != "resolve_vm"]
    assert input_calls == ["boot_epoch", "type_text", "mouse_button", "mouse_scroll"]
    assert [s["ok"] for s in out["steps"]] == [True, True, True]


# ---------------------------------------------------------------------------
# Feedback round pr107-20261027 (PRR-003/011/013): WMI failure arms, refusal
# arms, remaining step types, and the stop-on-failure contract on this
# transport. Each pin was mutant-verified by design: the pre-fix code raised
# past these shapes (per-step failure discarded the prefix) or never reached
# them (no wait/positional/click-here coverage).
# ---------------------------------------------------------------------------

def test_wmi_step_failure_reports_entry_and_skips_tail(wmi_path, unrestricted):
    """PRR-003: a failing backend step becomes a per-step ok:False entry with
    the error text, the rest of the plan is reported skipped, and the call
    still returns (not a whole-call ConsoleError that drops the prefix)."""
    class FailingScrollWMI(FakeWMI):
        def mouse_scroll(self, guid, delta):
            self.calls.append("mouse_scroll")
            raise wmiconsole.WMIError("SetScrollPosition failed with ReturnValue=5")

    be = wmi_path(FailingScrollWMI())
    out = console.run_sequence(unrestricted, "wmi-vm", [
        {"action": "press_key", "key": "enter"},
        {"action": "scroll", "delta": 3},
        {"action": "type_text", "text": "never"},
    ])
    assert out["ok"] is True, "the sequence returns; the STEP records carry the failure"
    steps = out["steps"]
    assert [s["index"] for s in steps] == [0, 1, 2]
    assert steps[1]["ok"] is False
    assert "ReturnValue=5" in steps[1]["error"]
    assert steps[2].get("skipped") is True
    assert be.texts == [], "steps after a failure must not execute"


def test_wmi_positional_and_head_refusal(wmi_path, unrestricted):
    """PRR-011: positional mouse steps scale through head_resolution, and a
    head with no resolution refuses before any input (console.py's structured
    error), instead of clicking blind."""
    be = wmi_path(FakeWMI())
    out = console.run_sequence(unrestricted, "wmi-vm", [
        {"action": "mouse_move", "x": 10, "y": 20},
        {"action": "click", "x": 0, "y": 0, "button": 2},
    ])
    assert out["ok"] is True
    assert out["steps"][0]["head_x"] is not None and out["steps"][0]["head_y"] is not None
    # two positional steps: each resolves the head and moves first; only the
    # click step adds the button press
    assert be.calls.count("head_resolution") == 2
    assert be.calls.count("mouse_move") == 2
    assert be.calls.count("mouse_click") == 1

    headless = wmi_path(FakeWMI())
    headless.head_resolution = lambda guid: ((None, None), {})  # type: ignore[assignment]
    out2 = console.run_sequence(unrestricted, "wmi-vm", [
        {"action": "mouse_move", "x": 10, "y": 20}])
    # stop-on-failure contract: the call returns; the step entry carries the
    # structured refusal
    assert out2["steps"][0]["ok"] is False
    assert "head" in out2["steps"][0]["error"].lower()


def test_wmi_click_here_step(wmi_path, unrestricted):
    """PRR-011: a click with no coordinates takes the click-here arm
    (ClickButton without SetAbsolutePosition)."""
    be = wmi_path(FakeWMI())
    out = console.run_sequence(
        unrestricted, "wmi-vm", [{"action": "click", "button": 2}])
    assert be.calls.count("mouse_click") == 1
    assert out["ok"] is True
    assert be.calls.count("mouse_click") == 1


def test_wmi_wait_step_reports_stop_reason(wmi_path, unrestricted):
    """PRR-011/TC-04: a wait step over the WMI transport runs the stable-poll
    loop and reports its stop reason (the static fake frame settles after the
    first poll seeds the reference)."""
    wmi_path(FakeWMI())
    out = console.run_sequence(unrestricted, "wmi-vm", [
        {"action": "wait_frame_stable", "stable_ms": 10, "timeout_s": 2,
         "interval_ms": 10}])
    step = out["steps"][0]
    assert step["ok"] is True
    assert step["stop_reason"] in ("stable", "deadline", "unchanged")
    assert step["frame_hash"]


def test_wmi_backend_error_mid_plan_is_step_failure(wmi_path, unrestricted):
    """PRR-013: a WMIError raised mid-plan (after a successful step) is
    converted to the failed-step entry + skipped tail — the executed prefix
    survives, mirroring the PS transport's contract."""
    class DieSecondWMI(FakeWMI):
        def type_text(self, guid, text):
            self.calls.append("type_text")
            raise wmiconsole.WMIError("COM method failure")

    be = wmi_path(DieSecondWMI())
    out = console.run_sequence(unrestricted, "wmi-vm", [
        {"action": "press_key", "key": "enter"},
        {"action": "type_text", "text": "dies"},
        {"action": "scroll", "delta": 1},
    ])
    assert out["ok"] is True
    assert be.calls.count("type_text") == 1
    assert out["steps"][0]["ok"] is True
    assert out["steps"][1]["ok"] is False
    assert out["steps"][2].get("skipped") is True


def test_wmi_unavailable_falls_back_to_powershell(wmi_path, unrestricted, monkeypatch):
    """PRR-013: a backend whose resolve_vm reports the VM missing selects the
    PowerShell transport (selection-time BackendUnavailable falls back;
    mid-operation it never switches)."""
    import contextlib

    class MissingVMWMI(FakeWMI):
        def resolve_vm(self, cfg, vm_name="", vm_id=""):
            raise wmiconsole.BackendUnavailable(f"VM '{vm_name}' not present")

    wmi_path(MissingVMWMI())
    scripts: list[str] = []

    def fake_run_ps(script, **kwargs):
        scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout="fallback-vm", returncode=0)
        return pswindows.PSResult(stdout="VMID=" + WMI_GUID + "\nEPOCH=1\n",
                                  returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)
    recorded = []
    real = console._input_lock

    @contextlib.contextmanager
    def spy(ref):
        recorded.append(ref.id)
        with real(ref):
            yield

    monkeypatch.setattr(console, "_input_lock", spy)
    # seed the hint so the by-name fallback locks on the canonical GUID (a
    # fresh process without a hint stays name-keyed — the disclosed residual)
    console.note_name_guid_hint("wmi-vm", WMI_GUID)
    out = console.run_sequence(
        unrestricted, "wmi-vm", [{"action": "press_key", "key": "enter"}])
    assert out["ok"] is True
    assert scripts, "the fallback must drive the folded PowerShell script"
    assert recorded == [WMI_GUID], "the fallback locks on the same canonical GUID"
