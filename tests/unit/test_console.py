"""Console module tests: scancodes, gating, scaling, envelopes, wait bounds."""

import base64
import json

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import (
    ConsoleError,
    _scale_to_head,
    _scancodes_for_combo,
    _scancodes_for_key,
)
from hyperv_mcp.policy import PolicyDenied


class FakePS:
    """Adaptive stub: serves queued responses first, then sane defaults keyed
    by the script's purpose (guid lookup, capture, head res, success call)."""

    def __init__(self, responses=()):
        self.scripts = []
        self.kwargs = []
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if self.responses:
            item = self.responses.pop(0)
        elif ".Id.ToString()" in script:
            item = pswindows.PSResult(
                stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0)
        elif "GetVirtualSystemThumbnailImage" in script:
            w, h = 640, 480
            if "WidthPixels  = 320" in script or "WidthPixels = 320" in script:
                w, h = 320, 240
            payload = b"\x00\x00\x00\x00" + b"\x00\x00" * (w * h)
            item = pswindows.PSResult(
                stdout=json.dumps({
                    "returnValue": 0,
                    "imageDataB64": base64.b64encode(payload).decode(),
                }),
                returncode=0)
        elif "Msvm_VideoHead" in script:
            item = pswindows.PSResult(
                stdout='{"horizontal": 1024, "vertical": 768}', returncode=0)
        elif "RC=" in script or "CHUNK" in script or "SETPOS" in script or "DOWN" in script:
            item = pswindows.PSResult(stdout="RC=1 CHUNK=1/1", returncode=0)
        else:
            item = pswindows.PSResult(stdout="", returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


# ---------------------------------------------------------------------------
# scancode table
# ---------------------------------------------------------------------------

def test_space_make_break():
    assert _scancodes_for_key("space") == [0x39, 0xB9]


def test_enter_make_break():
    assert _scancodes_for_key("enter") == [0x1C, 0x9C]


def test_extended_keys_carry_e0_prefix():
    codes = _scancodes_for_key("up")
    assert codes == [0xE0, 0x48, 0xE0, 0xC8]
    codes = _scancodes_for_key("delete")
    assert codes == [0xE0, 0x53, 0xE0, 0xD3]


def test_letters_and_digits():
    assert _scancodes_for_key("a") == [0x1E, 0x9E]
    assert _scancodes_for_key("z") == [0x2C, 0xAC]
    assert _scancodes_for_key("1") == [0x02, 0x82]
    assert _scancodes_for_key("0") == [0x0B, 0x8B]


def test_function_keys():
    assert _scancodes_for_key("f1") == [0x3B, 0xBB]
    assert _scancodes_for_key("f12") == [0x58, 0xD8]


def test_unknown_key_rejected_with_supported_list():
    with pytest.raises(ValueError, match="unknown key"):
        _scancodes_for_key("meta")


def test_combo_orders_modifiers():
    codes = _scancodes_for_combo(["ctrl", "alt", "delete"])
    # ctrl make (0x1D), alt make (0x38), delete via _scancodes_for_key,
    # alt break, ctrl break
    assert codes[0] == 0x1D and codes[1] == 0x38
    assert codes[-2:] == [0xB8, 0x9D]
    assert 0xE0 in codes  # delete is extended


def test_combo_requires_non_modifier():
    with pytest.raises(ValueError, match="non-modifier"):
        _scancodes_for_combo(["ctrl", "alt"])


def test_right_modifiers_use_extended_prefix():
    # PS/2 set-1: right-ctrl = E0 1D, right-alt = E0 38 — the bare 0x1D/0x38
    # bytes are indistinguishable from left-ctrl/left-alt.
    assert _scancodes_for_key("rightctrl") == [0xE0, 0x1D, 0xE0, 0x9D]
    assert _scancodes_for_key("rightalt") == [0xE0, 0x38, 0xE0, 0xB8]
    assert _scancodes_for_key("leftctrl") == [0x1D, 0x9D]
    assert _scancodes_for_key("leftalt") == [0x38, 0xB8]


def test_combo_right_modifiers_carry_prefix():
    codes = _scancodes_for_combo(["rightctrl", "a"])
    assert codes[:2] == [0xE0, 0x1D]    # make carries the prefix
    assert codes[-2:] == [0xE0, 0x9D]   # break carries the prefix
    codes = _scancodes_for_combo(["ctrl", "a"])
    assert codes[0] == 0x1D and codes[-1] == 0x9D  # left side stays unprefixed


def test_case_insensitive_keys():
    assert _scancodes_for_key("ENTER") == _scancodes_for_key("enter")


# ---------------------------------------------------------------------------
# coordinate scaling
# ---------------------------------------------------------------------------

def test_scale_identity_when_frame_equals_head():
    assert _scale_to_head(100, 50, 1024, 768, (1024, 768)) == (100, 50)


def test_scale_scales_proportionally():
    # frame 640x480 -> head 1024x768
    hx, hy = _scale_to_head(320, 240, 640, 480, (1024, 768))
    assert (hx, hy) == (512, 384)


def test_scale_upscaling_frame_smaller_than_head():
    hx, hy = _scale_to_head(160, 120, 320, 240, (1024, 768))
    assert (hx, hy) == (512, 384)


def test_scale_without_head_and_without_frame_dims_errors():
    with pytest.raises(ConsoleError, match="head resolution unavailable"):
        _scale_to_head(10, 10, 0, 0, None)


def test_scale_bounds_clamp():
    hx, hy = _scale_to_head(9999, 9999, 640, 480, (1024, 768))
    assert hx == 1023 and hy == 767


def test_scale_rejects_bad_frame_dims():
    with pytest.raises(ValueError, match="positive"):
        _scale_to_head(10, 10, -1, 0, (1024, 768))


def test_scale_identity_when_dims_omitted_and_head_available():
    assert _scale_to_head(10, 10, 0, 0, (1024, 768)) == (10, 10)


# ---------------------------------------------------------------------------
# policy gating
# ---------------------------------------------------------------------------

def test_console_input_denied_by_default(monkeypatch):
    cfg = Config()
    called = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", called)
    with pytest.raises(PolicyDenied, match="console_input"):
        console.type_text(cfg, "vm1", "hello")
    with pytest.raises(PolicyDenied, match="console_input"):
        console.mouse_move(cfg, "vm1", 5, 5)
    assert called.scripts == []


def test_console_input_allowed_when_enabled(monkeypatch, unrestricted):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.press_key(unrestricted, "vm1", "enter")
    assert fake.scripts


def test_console_input_category_non_default_config():
    cfg = Config()
    cfg.destructive.console_input = True
    # require_category passes without confirm — key design property
    from hyperv_mcp.policy import require_category
    require_category(cfg, "console_input", "detail")


def test_screenshot_is_read_only_no_category(monkeypatch, unrestricted):
    """Screenshot needs no console_input category (read-only, VM allowlist)."""
    cfg = Config(allowed_vm_patterns=["*"])
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.get_display_info(cfg, "any-vm")
    assert fake.scripts  # reached PowerShell without a policy error


# ---------------------------------------------------------------------------
# type_text transport
# ---------------------------------------------------------------------------

def test_type_text_rides_stdin_never_script(monkeypatch, unrestricted):
    """Regression: typed text (possible credentials) must never appear in the
    PowerShell script body, where CLIXML error records would leak it."""
    secret_text = "S3cr3t-Typed-P4ss!"
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.type_text(unrestricted, "vm1", secret_text)
    script = fake.scripts[-1]
    assert secret_text not in script
    assert fake.kwargs[-1]["stdin_b64"] == pswindows.utf8_b64(secret_text)
    assert "[Console]::In.ReadLine()" in script


def test_type_text_rejects_non_ascii(unrestricted):
    with pytest.raises(ValueError, match="ASCII"):
        console.type_text(unrestricted, "vm1", "café")


def test_type_text_chunks_long_input(monkeypatch, unrestricted):
    text = "a" * 1200  # -> 3 chunks of <=512
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.type_text(unrestricted, "vm1", text)
    assert out["chunks"] == 3 and out["chars"] == 1200
    stdin_lens = [len(kw["stdin_b64"]) for kw in fake.kwargs if "stdin_b64" in kw]
    assert len(stdin_lens) == 3
    # base64 inflates 512 chars to ~684 chars; bound accordingly
    assert all(n <= 700 for n in stdin_lens)


def test_type_text_empty_rejected(unrestricted):
    with pytest.raises(ValueError, match="text is required"):
        console.type_text(unrestricted, "vm1", "")


# ---------------------------------------------------------------------------
# scancode validation + chunking
# ---------------------------------------------------------------------------

def test_type_scancodes_rejects_bools(unrestricted):
    with pytest.raises(ValueError, match="bools rejected"):
        console.type_scancodes(unrestricted, "vm1", [True])


def test_type_scancodes_rejects_out_of_range(unrestricted):
    with pytest.raises(ValueError, match="0..255"):
        console.type_scancodes(unrestricted, "vm1", [256])
    with pytest.raises(ValueError, match="0..255"):
        console.type_scancodes(unrestricted, "vm1", [-1])


def test_type_scancodes_chunks_at_64(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="RC=1 CHUNK=x", returncode=0)] * 3)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.type_scancodes(unrestricted, "vm1", [0x39, 0xB9] * 96)
    assert out["chunks"] == 3 and out["scancodes_sent"] == 192


def test_press_key_sends_make_break_via_keyboard_association(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="RC=1 CHUNK=1/1", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.press_key(unrestricted, "vm1", "enter")
    script = fake.scripts[-1]
    assert "Msvm_Keyboard" in script
    assert "TypeScancodes" in script
    assert "[byte[]](28,156)" in script


# ---------------------------------------------------------------------------
# WMI result mapping
# ---------------------------------------------------------------------------

def test_nonzero_wmi_returnvalue_maps_to_error(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(returncode=1, stderr="TypeScancodes failed with ReturnValue=5")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError, match="ReturnValue=5"):
        console.press_key(unrestricted, "vm1", "enter")


def test_missing_mouse_device_is_structured_error(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout='{"horizontal": 1024, "vertical": 768}', returncode=0),
        pswindows.PSResult(returncode=1, stderr="no synthetic mouse device associated with the VM")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError, match="no synthetic mouse"):
        console.mouse_move(unrestricted, "vm1", 5, 5)


def test_malformed_capture_json_is_structured(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="not json", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError, match="screenshot result parse failed"):
        console._capture_raw(unrestricted, "guid", 640, 480)


def test_capture_length_mismatch_rejected(monkeypatch, unrestricted):
    import base64
    bad = base64.b64encode(b"\x00" * 100).decode()
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"returnValue": 0, "imageDataB64": bad}), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError, match="length mismatch"):
        console._capture_raw(unrestricted, "guid", 640, 480)


# ---------------------------------------------------------------------------
# wait_frame_change bounds
# ---------------------------------------------------------------------------

def test_wait_frame_change_validates_bounds(unrestricted):
    with pytest.raises(ValueError, match="interval_s"):
        console.wait_frame_change(unrestricted, "vm1", interval_s=0)
    with pytest.raises(ValueError, match="timeout_s"):
        console.wait_frame_change(unrestricted, "vm1", timeout_s=0)


def test_wait_frame_change_max_polls_derived_from_timeout(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout="STOP=deadline POLLS=10 HASH=abc", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.wait_frame_change(unrestricted, "vm1", timeout_s=20, interval_s=2)
    # derived: 20/2 = 10 polls, run_ps timeout = deadline + 15
    assert fake.kwargs[-1]["timeout_s"] == 35
    assert out["stop_reason"] == "deadline" and out["polls"] == 10


def test_wait_frame_change_changed_returns_image(monkeypatch, unrestricted):
    import base64 as b64mod
    w, h = 320, 240
    pixels = b"\x00" * (w * h * 2)
    payload = b"\x00\x00\x00\x00" + pixels
    frame_b64 = b64mod.b64encode(payload).decode()
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0), pswindows.PSResult(
        stdout=f"STOP=changed POLLS=3 HASH=abc\nFRAME={frame_b64}", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.wait_frame_change(unrestricted, "vm1", baseline_hash="a" * 64, width=w, height=h)
    assert out["changed"] is True and out["stop_reason"] == "changed"
    assert out["image"].size == (w, h)
    assert out["frame_hash"] == console._frame_hash(payload)


def test_wait_frame_change_deadline_has_no_image(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout="STOP=deadline POLLS=10 HASH=abc", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.wait_frame_change(unrestricted, "vm1", timeout_s=20, interval_s=2)
    assert "image" not in out and out["changed"] is False


def test_capture_sequence_diff_metrics(monkeypatch, unrestricted):
    import base64 as b64mod
    w, h = 320, 240
    p1 = b"\x00\x00\x00\x00" + b"\x00\x00" * (w * h)
    p2 = b"\x00\x00\x00\x00" + b"\xFF\xFF" + b"\x00\x00" * (w * h - 1)
    payloads = [p1, p2, p2]
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0)] + [
        pswindows.PSResult(stdout=json.dumps(
            {"returnValue": 0, "imageDataB64": b64mod.b64encode(p).decode()}), returncode=0)
        for p in payloads
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.capture_sequence(unrestricted, "vm1", count=3, interval_s=1, width=w, height=h)
    assert [f["changed_bytes_vs_previous"] for f in out["frames"]] == [0, 2, 0]
    assert out["frames"][0]["frame_hash"] != out["frames"][1]["frame_hash"]
    assert out["frames"][1]["frame_hash"] == out["frames"][2]["frame_hash"]


# ---------------------------------------------------------------------------
# screenshot save_path policy (review PRR-016/PRR-021)
# ---------------------------------------------------------------------------

def test_screenshot_save_path_writes_and_creates_parent(monkeypatch, tmp_path):
    cfg = Config(unrestricted=True, host_write_roots=[str(tmp_path)])
    dest = tmp_path / "shots" / "sub" / "frame.png"
    fake = FakePS()  # adaptive: guid, head, capture (lands on 640x480 fallback)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    img, meta = console.screenshot(cfg, "vm1", save_path=str(dest))
    assert meta["saved_path"] == str(dest)
    assert dest.is_file() and dest.stat().st_size > 8
    assert img.size == (640, 480)


def test_screenshot_save_path_denied_outside_write_roots(monkeypatch, tmp_path):
    cfg = Config(allowed_vm_patterns=["*"], host_write_roots=[str(tmp_path / "allowed")])
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    outside = tmp_path / "elsewhere.png"
    with pytest.raises(PolicyDenied, match="host write"):
        console.screenshot(cfg, "vm1", save_path=str(outside))
    assert not outside.exists()  # the write itself never happens


def test_screenshot_fallback_chain_recovers(monkeypatch, unrestricted):
    """Requested size fails -> chain falls through to 640x480 (TI-4)."""
    w, h = 640, 480
    payload = b"\x00\x00\x00\x00" + b"\x00\x00" * (w * h)
    ok = pswindows.PSResult(stdout=json.dumps(
        {"returnValue": 0, "imageDataB64": base64.b64encode(payload).decode()}),
        returncode=0)
    fake = FakePS([
        pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout='{"horizontal": 1024, "vertical": 768}', returncode=0),
        pswindows.PSResult(returncode=1, stderr="capture boom"),  # 1024x768 fails
        ok,                                                       # 640x480 succeeds
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    img, meta = console.screenshot(unrestricted, "vm1")
    assert img.size == (640, 480)
    assert meta["fallback_used"] == "1024x768 failed; captured at 640x480"


def test_dimension_bounds_rejected_everywhere(unrestricted):
    for kwargs in ({"width": 159}, {"height": 4097}):
        with pytest.raises(ValueError, match="160..4096"):
            console.screenshot(unrestricted, "vm1", **kwargs)
        with pytest.raises(ValueError, match="160..4096"):
            console.wait_frame_change(unrestricted, "vm1", **kwargs)
        with pytest.raises(ValueError, match="160..4096"):
            console.capture_sequence(unrestricted, "vm1", **kwargs)


# ---------------------------------------------------------------------------
# wait_frame_change hash round-trip (review PRR-005)
# ---------------------------------------------------------------------------

def test_wait_frame_change_hash_roundtrips_as_baseline(monkeypatch, unrestricted):
    """The HASH= value must be full lowercase-hex sha256 — byte-identical to
    _frame_hash — so it passes baseline_hash validation and can be chained."""
    import hashlib

    w, h = 320, 240
    payload = b"\x00\x00\x00\x00" + b"\x5a\xa5" * (w * h)
    expected = hashlib.sha256(payload).hexdigest()
    fake = FakePS([
        pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout=f"STOP=deadline POLLS=4 HASH={expected}", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.wait_frame_change(unrestricted, "vm1", width=w, height=h)
    assert out["frame_hash"] == expected
    # the deadline-path hash must now be ACCEPTED as a baseline
    changed = pswindows.PSResult(
        stdout=f"STOP=changed POLLS=1 HASH={'f' * 64}\n"
               f"FRAME={base64.b64encode(payload).decode()}", returncode=0)
    fake2 = FakePS([
        pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        changed,
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake2)
    out2 = console.wait_frame_change(
        unrestricted, "vm1", baseline_hash=out["frame_hash"], width=w, height=h)
    assert out2["stop_reason"] == "changed"
    assert out2["frame_hash"] == expected  # host/PS hash formats agree


def test_display_info_emits_snake_case_enabled_state(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout=json.dumps({
            "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
            "keyboard_present": True, "keyboard_enabled": None,
            "mouse_present": False, "mouse_enabled": None}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.get_display_info(unrestricted, "vm1")
    assert out["enabled_state"] == 2
    assert "enabledState" not in fake.scripts[-1]


# ---------------------------------------------------------------------------
# click positioning branches (review TI-7)
# ---------------------------------------------------------------------------

def test_click_with_coordinates_positions_first(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout='{"horizontal": 1024, "vertical": 768}', returncode=0),
        pswindows.PSResult(stdout="RC=0 DOWN=1", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.click(unrestricted, "vm1", 160, 120, frame_width=320, frame_height=240)
    assert out["head_x"] == 512 and out["head_y"] == 384  # scaled to head space
    script = fake.scripts[-1]
    assert "SetAbsolutePosition" in script and "ClickButton" in script


def test_click_at_origin_skips_positioning(monkeypatch, unrestricted):
    """x=0,y=0 means 'click at current position' — no SetAbsolutePosition."""
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout='{"horizontal": 1024, "vertical": 768}', returncode=0),
        pswindows.PSResult(stdout="RC=0 DOWN=1", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.click(unrestricted, "vm1", 0, 0)
    assert "head_x" not in out and "head_y" not in out
    script = fake.scripts[-1]
    assert "SetAbsolutePosition" not in script
    assert "ClickButton" in script
