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

from hyperv_mcp import console, vmident
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
    capture, and every step all happen INSIDE that single acquisition."""
    be = wmi_path(FakeWMI())
    acquisitions: list[tuple] = []
    real = console._input_lock

    import contextlib

    @contextlib.contextmanager
    def spy(ref):
        acquisitions.append(ref.id)
        with real(ref):
            yield

    monkeypatch.setattr(console, "_input_lock", spy)
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
    # precondition-before-input ordering: capture happened before the first input
    assert be.calls.index("capture") < be.calls.index("type_scancodes")
    assert be.calls.index("boot_epoch") < be.calls.index("type_scancodes")


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
