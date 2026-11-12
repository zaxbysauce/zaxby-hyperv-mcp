"""Guardrail tests for the letterbox-aware console mapping (issue #125) and
the wiring of the capture-citation/input ledger (issue #126) — regular
post-anchor tests; the frozen contract lives in
tests/unit/test_console_aspect_fit.py and tests/unit/test_console_commit_guard.py.

Pins:
  - the live-calibrated content-rect geometry at the measured 1-px boundary
    classes (1080-head sweep rows) plus the frozen 1010-head fixture;
  - shaped captures refuse pointer citations;
  - ledger wiring: inputs bump at DISPATCH (including a timed-out leg),
    captures auto-register (screenshots and wait tools), the guard's live
    capture runs on the already-held internal seam (no lock re-entry), and
    capture/input ordering shares ONE monotonic counter;
  - alias re-keying under note_name_guid_hint in BOTH registration orders;
  - reset_input_ledger isolation;
  - the PowerShell-transport wait holds the per-VM input lock for the whole
    wait (a concurrent click raises VMBusy);
  - the server tools forward the new citation/guard parameters verbatim, and
    the screenshot tool's height default is 0 at the MCP level;
  - the generated positional-mouse scaling block EXECUTES the rect-relative
    arithmetic and the band refusal in real PowerShell 5.1, for BOTH amended
    in-script mappers (the single-op template and the independent
    sequence-step mapper), after the harness pattern in
    tests/unit/test_console_folded_protocol.py:335-367.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import threading

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError, _content_rect, _scale_to_head

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
HEAD_WIDE = (1920, 1010)
HEAD_1080 = (1920, 1080)

_REAL_RUN_PS = pswindows.run_ps


def _rgb565_payload(w: int, h: int) -> bytes:
    return b"\x00\x00\x00\x00" + b"\x00\x00" * (w * h)


def _folded_size(script: str) -> tuple[int, int]:
    w = h = 0
    for line in script.splitlines():
        ls = line.strip()
        if ls.startswith("WidthPixels"):
            raw = ls.split("=", 1)[1].strip()
            if raw.isdigit():
                w = int(raw)
        elif ls.startswith("HeightPixels"):
            raw = ls.split("=", 1)[1].strip()
            if raw.isdigit():
                h = int(raw)
    if not (w and h):
        m = re.search(r"\$sizes = @\([,(@]*(\d+),(\d+)\)", script)
        if m:
            w, h = int(m.group(1)), int(m.group(2))
    return w, h


class FakePS:
    """The adaptive folded-transport stub after the frozen packs' FakePS,
    with a configurable head (every head-answering leg reports it)."""

    def __init__(self, responses=(), head=(1024, 768)):
        self.scripts = []
        self.kwargs = []
        self.responses = list(responses)
        self.head = head

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if self.responses:
            item = self.responses.pop(0)
        elif "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            item = pswindows.PSResult(stdout=GUID, returncode=0)
        elif "GetVirtualSystemThumbnailImage" in script:
            w, h = _folded_size(script)
            payload = _rgb565_payload(w, h)
            body = json.dumps({
                "returnValue": 0,
                "imageDataB64": base64.b64encode(payload).decode(),
            })
            item = pswindows.PSResult(
                stdout="VMID=" + GUID + "\nHEAD=" + str(self.head[0]) + "x"
                       + str(self.head[1]) + "\nSIZES=" + str(w) + "x"
                       + str(h) + "\nUSED=" + str(w) + "x" + str(h) + "\n"
                       + body,
                returncode=0)
        elif "EnabledState" in script:
            body = json.dumps({
                "enabled_state": 2,
                "head_horizontal": self.head[0], "head_vertical": self.head[1],
                "keyboard_present": True, "keyboard_enabled": 2,
                "mouse_present": True, "mouse_enabled": 2,
            })
            item = pswindows.PSResult(stdout="VMID=" + GUID + "\n" + body, returncode=0)
        elif "SetAbsolutePosition" in script:
            item = pswindows.PSResult(stdout="HEADX=1\nHEADY=1\nRC=0", returncode=0)
        elif "Msvm_VideoHead" in script:
            item = pswindows.PSResult(
                stdout=json.dumps(
                    {"horizontal": self.head[0], "vertical": self.head[1]}),
                returncode=0)
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


@pytest.fixture(autouse=True)
def _clean_ledger():
    console.reset_input_ledger()
    yield
    console.reset_input_ledger()


# ---------------------------------------------------------------------------
# calibrated geometry (F1): the measured boundary rows + the frozen fixture
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("frame,head,expected", [
    # the frozen C1 fixture: 1024x768 @ 1920x1010 -> [0,115,1024,653]
    ((1024, 768), HEAD_WIDE, [0, 115, 1024, 653]),
    # exact aspect -> the full frame
    ((1024, 576), HEAD_1080, [0, 0, 1024, 576]),
    ((320, 240), (1024, 768), [0, 0, 320, 240]),
    # the measured 1080-head 1-px boundary classes:
    # 1024x575 is height-limited: cw=(575*1920)//1080=1022 -> 1-px side bands
    ((1024, 575), HEAD_1080, [1, 0, 1023, 575]),
    # 1024x577 is width-limited: ch=576, remainder 1 -> top 0, bottom 1
    ((1024, 577), HEAD_1080, [0, 0, 1024, 576]),
    # 1023x576 is width-limited: ch=575, remainder 1 -> top 0, bottom 1
    ((1023, 576), HEAD_1080, [0, 0, 1023, 575]),
    # 1025x576 is height-limited: cw=1024, remainder 1 -> left 0, right 1
    ((1025, 576), HEAD_1080, [0, 0, 1024, 576]),
    # further calibration rows (floor model, symmetric splits)
    ((1024, 539), HEAD_1080, [33, 0, 991, 539]),
    ((1024, 540), HEAD_1080, [32, 0, 992, 540]),
    ((1024, 500), HEAD_1080, [68, 0, 956, 500]),
    ((1024, 768), HEAD_1080, [0, 96, 1024, 672]),
])
def test_content_rect_calibrated_boundaries(frame, head, expected):
    assert _content_rect(frame[0], frame[1], head) == expected


def test_content_rect_absent_when_head_unknown():
    """No head -> no rect: the metadata key is absent rather than fabricated
    (None is the sentinel the attachment sites test)."""
    assert _content_rect(1024, 768, None) is None
    assert _content_rect(1024, 768, (0, 0)) is None
    assert _content_rect(1024, 768, (1920, 0)) is None


def test_scale_to_head_full_frame_rect_clamps_like_base():
    """A full-frame rect and no rect are the SAME mapping, including
    out-of-frame clamping (the band refusal only fires for in-frame points
    outside the rect)."""
    head = (1024, 768)
    assert _scale_to_head(9999, 9999, 640, 480, head) == (1023, 767)
    assert _scale_to_head(
        9999, 9999, 640, 480, head, content_rect=[0, 0, 640, 480]) == (1023, 767)


def test_scale_to_head_band_refusal_is_in_frame_only():
    rect = [0, 115, 1024, 653]
    with pytest.raises(ConsoleError, match="letterbox band"):
        _scale_to_head(512, 10, 1024, 768, HEAD_WIDE, content_rect=rect)
    with pytest.raises(ConsoleError, match="letterbox band"):
        _scale_to_head(5, 400, 1024, 768, HEAD_WIDE, content_rect=[10, 0, 100, 768])


# ---------------------------------------------------------------------------
# shaped-citation refusal (F5)
# ---------------------------------------------------------------------------

def test_shaped_capture_refuses_pointer_citation(monkeypatch, unrestricted):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture(
        "b" * 64, head_resolution=(1024, 768), vm_name="vm1",
        frame_size=(320, 240), shaped=True)
    with pytest.raises(ConsoleError, match="shaped frame has no head-space mapping"):
        console.click(unrestricted, "vm1", 160, 120,
                      frame_width=320, frame_height=240, frame_hash="b" * 64)
    assert not any("SetAbsolutePosition" in s for s in fake.scripts)


def test_unknown_citation_refuses(monkeypatch, unrestricted):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError, match="unknown capture citation"):
        console.click(unrestricted, "vm1", 160, 120,
                      frame_width=320, frame_height=240, frame_hash="9" * 64)
    assert fake.scripts == []


# ---------------------------------------------------------------------------
# ledger wiring: dispatch-time bumps, auto-registration, single counter
# ---------------------------------------------------------------------------

def test_input_bumps_at_dispatch(monkeypatch, unrestricted):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.click(unrestricted, "vm1", 160, 120)
    assert console._last_input_seq_for("vm1") > 0, (
        "a dispatched click must bump the per-VM input ledger"
    )


def test_refused_input_never_bumps(monkeypatch, unrestricted):
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture(
        "b" * 64, head_resolution=HEAD_WIDE,
        content_rect=[0, 115, 1024, 653], vm_name="vm1")
    with pytest.raises(ConsoleError, match="letterbox band"):
        console.click(unrestricted, "vm1", 512, 10,
                      frame_width=1024, frame_height=768, frame_hash="b" * 64)
    assert console._last_input_seq_for("vm1") == 0, (
        "a refused, never-dispatched input must not bump the ledger"
    )


def test_timed_out_leg_still_bumps(monkeypatch, unrestricted):
    """A leg that times out after dispatch leaves delivery unknowable, so
    the conservative answer is that the input happened: the bump (placed at
    dispatch, inside the lock) survives the timeout failure."""
    fake = FakePS(responses=[pswindows.PSResult(
        stdout="", stderr="timed out", returncode=1, timed_out=True)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError):
        console.type_text(unrestricted, "vm1", "hello")
    assert console._last_input_seq_for("vm1") > 0


def test_screenshot_auto_registers_with_size_and_rect(
        monkeypatch, unrestricted):
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    _img, meta = console.screenshot(unrestricted, "vm1", width=1024, height=768)
    record = console._lookup_capture(meta["frame_hash"], meta["vm_id"])
    assert record is not None, "a returned capture must auto-register"
    assert record["frame_size"] == (1024, 768)
    assert record["head_resolution"] == HEAD_WIDE
    assert record["content_rect"] == [0, 115, 1024, 653]
    assert record["shaped"] is False


def test_shaped_screenshot_registers_shaped(monkeypatch, unrestricted):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    _img, meta = console.screenshot(
        unrestricted, "vm1", width=320, height=240, scale=0.5)
    record = console._lookup_capture(meta["frame_hash"], meta["vm_id"])
    assert record is not None and record["shaped"] is True


def test_wait_frame_change_auto_registers(monkeypatch, unrestricted):
    """The wait tools hold the input lock for the whole wait and register
    the producing poll's hash: the returned frame_hash is citable and its
    head provenance comes from the poll that produced it."""
    w, h = 320, 240
    payload = _rgb565_payload(w, h)
    import hashlib
    hsh = hashlib.sha256(payload[4:]).hexdigest()
    fake = FakePS(responses=[pswindows.PSResult(
        stdout="VMID=" + GUID + "\nHEAD=1024x768\nHEAD=1024x768\n"
               "STOP=changed POLLS=2 HASH=" + hsh + "\n"
               "FRAME=" + base64.b64encode(payload).decode(),
        returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.wait_frame_change(unrestricted, "vm1", width=w, height=h)
    assert out["frame_hash"] == hsh
    assert out["head_resolution"] == {"horizontal": 1024, "vertical": 768}
    assert out["content_rect"] == [0, 0, 320, 240]
    record = console._lookup_capture(hsh, GUID)
    assert record is not None, "the wait's hash must auto-register"
    assert record["frame_size"] == (w, h)
    assert record["head_resolution"] == (1024, 768)


def test_guard_live_capture_does_not_reenter_the_input_lock(
        monkeypatch, tmp_path):
    """A successful guarded click IS the no-reentry proof: the guard's live
    capture runs on the already-held internal seam, and vmlocks refuses
    same-thread re-entry with VMBusy — a re-entering implementation cannot
    pass this test."""
    cfg = Config(unrestricted=True)
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    verified = console._frame_hash(_rgb565_payload(320, 240))
    console.register_capture(
        verified, vm_name="vm1", frame_size=(320, 240),
        head_resolution=(1024, 768))
    out = console.click(
        cfg, "vm1", 160, 120, frame_width=320, frame_height=240,
        commit_guard=True, verified_frame_hash=verified)
    assert out["ok"] is True
    assert any("ClickButton" in s for s in fake.scripts)


def test_single_counter_orders_captures_and_inputs(unrestricted):
    """Captures and inputs draw from ONE monotonic counter: an input after a
    capture reads a HIGHER number, so freshness (capture.seq >
    last_input.seq) is a real ordering and not two clocks drifting."""
    console.register_capture("1" * 64, vm_name="vm1")
    capture_seq = console._lookup_capture("1" * 64, "vm1")["seq"]
    console.record_console_input(vm_name="vm1")
    assert console._last_input_seq_for("vm1") > capture_seq
    console.register_capture("2" * 64, vm_name="vm1")
    later = console._lookup_capture("2" * 64, "vm1")["seq"]
    assert later > console._last_input_seq_for("vm1")


# ---------------------------------------------------------------------------
# alias re-keying (R4-02) in both registration orders + reset isolation
# ---------------------------------------------------------------------------

def test_alias_rekey_name_registered_before_guid_learned():
    """Order 1: the capture is keyed by NAME, then note_name_guid_hint learns
    the pairing — the record re-keys to the GUID preserving its seq, and the
    name-keyed lookup stops resolving."""
    console.register_capture("3" * 64, vm_name="vm1", frame_size=(320, 240))
    seq = console._lookup_capture("3" * 64, "vm1")["seq"]
    console.note_name_guid_hint("vm1", GUID)
    assert console._lookup_capture("3" * 64, GUID)["seq"] == seq
    assert console._lookup_capture("3" * 64, "vm1") is None


def test_alias_rekey_takes_max_last_input():
    """Order 2: a GUID-keyed last-input high-water mark exists, then a
    NAME-keyed input arrives, then the hint is learned — the GUID key keeps
    the MAX of the two (a lower name-keyed stamp must not de-fresh the VM)."""
    console.record_console_input(vm_id=GUID)
    guid_stamp = console._last_input_seq_for(GUID)
    console.record_console_input(vm_name="vm1")
    name_stamp = console._last_input_seq_for("vm1")
    console.note_name_guid_hint("vm1", GUID)
    assert console._last_input_seq_for(GUID) == max(guid_stamp, name_stamp)
    assert console._last_input_seq_for("vm1") == 0


def test_reset_input_ledger_clears_both_maps():
    console.register_capture("4" * 64, vm_name="vm1")
    console.record_console_input(vm_name="vm1")
    console.reset_input_ledger()
    assert console._lookup_capture("4" * 64, "vm1") is None
    assert console._last_input_seq_for("vm1") == 0


# ---------------------------------------------------------------------------
# PS-transport whole-wait lock holding (R3-01)
# ---------------------------------------------------------------------------

def test_wait_holds_the_input_lock_for_the_whole_wait(monkeypatch, unrestricted):
    """A folded wait in flight holds the per-VM console input lock, so a
    concurrent click on the same VM raises VMBusy instead of interleaving
    (the PowerShell-transport proof of the whole-wait lock holding)."""
    from hyperv_mcp import vmlocks

    wait_spawned = threading.Event()
    release = threading.Event()
    real_wait_s = vmlocks._DEFAULT_WAIT_S

    class BlockablePS:
        def __init__(self) -> None:
            self.scripts: list[str] = []

        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            if "GetVirtualSystemThumbnailImage" in script and "STOP=" in script:
                wait_spawned.set()
                release.wait(timeout=30)
                return pswindows.PSResult(
                    stdout="STOP=deadline POLLS=1 HASH=" + "a" * 64,
                    returncode=0)
            return FakePS()(script, **kwargs)

    stub = BlockablePS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    vmlocks.set_default_wait_s(0.2)
    try:
        waiter = threading.Thread(
            target=lambda: console.wait_frame_change(
                unrestricted, "vm1", timeout_s=30, interval_s=1))
        waiter.start()
        assert wait_spawned.wait(timeout=30), "the wait never spawned"
        with pytest.raises(vmlocks.VMBusy):
            console.click(unrestricted, "vm1", 5, 5)
    finally:
        vmlocks.set_default_wait_s(real_wait_s)
        release.set()
        waiter.join(timeout=30)


# ---------------------------------------------------------------------------
# server wiring: parameter forwarding + the MCP-level height default
# ---------------------------------------------------------------------------

def _fresh_server(monkeypatch, tmp_path):
    import importlib

    import hyperv_mcp.server as server_module

    monkeypatch.setenv("HYPERV_MCP_UNRESTRICTED", "1")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
    return mod


def _call(mcp, tool, arguments):
    return asyncio.run(mcp.call_tool(tool, arguments))


def _meta(result) -> dict:
    from conftest import content_blocks

    texts = [c for c in content_blocks(result)
             if getattr(c, "type", "") == "text"]
    assert texts, "no metadata text block in the success result"
    return json.loads(texts[0].text)


def test_server_click_forwards_guard_parameters(monkeypatch, tmp_path):
    mod = _fresh_server(monkeypatch, tmp_path)
    mcp = mod.get_mcp()
    received: dict = {}

    def fake_click(cfg, vm_name="", x=None, y=None, frame_width=0,
                   frame_height=0, button=1, vm_id="", frame_hash="",
                   commit_guard=False, verified_frame_hash="",
                   verified_state_receipt=""):
        received.update(
            vm_name=vm_name, x=x, y=y, frame_width=frame_width,
            frame_height=frame_height, button=button, vm_id=vm_id,
            frame_hash=frame_hash, commit_guard=commit_guard,
            verified_frame_hash=verified_frame_hash,
            verified_state_receipt=verified_state_receipt)
        return {"ok": True, "operation": "click button 1", "vm_name": vm_name}

    monkeypatch.setattr(mod.console, "click", fake_click)
    _call(mcp, "hyperv_console_click", {
        "vm_name": "vm1", "x": 10, "y": 20, "frame_width": 320,
        "frame_height": 240, "frame_hash": "a" * 64,
        "commit_guard": True, "verified_frame_hash": "b" * 64,
    })
    assert received == {
        "vm_name": "vm1", "x": 10, "y": 20, "frame_width": 320,
        "frame_height": 240, "button": 1, "vm_id": "",
        "frame_hash": "a" * 64, "commit_guard": True,
        "verified_frame_hash": "b" * 64,
        # Issue #140: every citation/guard parameter forwards verbatim,
        # including the receipt channel (absent at the call => default "").
        "verified_state_receipt": "",
    }, "the server tool must forward every citation/guard parameter verbatim"


def test_server_mouse_move_forwards_frame_hash(monkeypatch, tmp_path):
    mod = _fresh_server(monkeypatch, tmp_path)
    mcp = mod.get_mcp()
    received: dict = {}

    def fake_move(cfg, vm_name="", x=None, y=None, frame_width=0,
                  frame_height=0, vm_id="", frame_hash=""):
        received.update(
            vm_name=vm_name, x=x, y=y, frame_width=frame_width,
            frame_height=frame_height, vm_id=vm_id, frame_hash=frame_hash)
        return {"ok": True, "operation": "move", "vm_name": vm_name,
                "head_x": 1, "head_y": 1}

    monkeypatch.setattr(mod.console, "mouse_move", fake_move)
    _call(mcp, "hyperv_console_mouse_move", {
        "vm_name": "vm1", "x": 1, "y": 2, "frame_hash": "c" * 64,
    })
    assert received["frame_hash"] == "c" * 64


def test_server_screenshot_height_defaults_to_head_aspect(
        monkeypatch, tmp_path):
    """MCP level: an omitted height is 0, which captures at the head's
    aspect — 1024 wide at the 1920x1080 head is 1024x576, band-free."""
    mod = _fresh_server(monkeypatch, tmp_path)
    mcp = mod.get_mcp()
    fake = FakePS(head=HEAD_1080)
    monkeypatch.setattr(mod.pswindows, "run_ps", fake)
    result = _call(mcp, "hyperv_console_screenshot", {"vm_name": "vm1", "width": 1024})
    meta = _meta(result)
    capture = next(
        s for s in fake.scripts if "GetVirtualSystemThumbnailImage" in s)
    assert _folded_size(capture) == (1024, 576)
    assert meta["height"] == 576
    assert meta["content_rect"] == [0, 0, 1024, 576]


# ---------------------------------------------------------------------------
# the amended in-script mappers, EXECUTED in real PowerShell 5.1
# (after the harness pattern in test_console_folded_protocol.py)
# ---------------------------------------------------------------------------

def _ps_available() -> bool:
    return os.path.isfile(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")


def _exec_block(block: str, head: tuple[int, int]) -> tuple[int, int] | None:
    """Run an extracted scaling block against a synthetic $vh and return the
    (hx, hy) it computes (None when the block reports no position)."""
    pswindows.init(Config(unrestricted=True))
    body = (
        "$vh = [PSCustomObject]@{ CurrentHorizontalResolution = "
        + str(head[0]) + "; CurrentVerticalResolution = " + str(head[1]) + " }\n"
        + block + "\n"
        + "Write-Output ('HX=' + $hx + ' HY=' + $hy)\n"
    )
    result = _REAL_RUN_PS(body, timeout_s=60)
    if result.returncode != 0:
        return None
    m = re.search(r"HX=(-?\d+) HY=(-?\d+)", result.stdout)
    assert m, f"the scaling block emitted no position: {result.stdout[:200]!r}"
    return int(m.group(1)), int(m.group(2))


def _exec_block_stderr(block: str, head: tuple[int, int]) -> str:
    pswindows.init(Config(unrestricted=True))
    body = (
        "$vh = [PSCustomObject]@{ CurrentHorizontalResolution = "
        + str(head[0]) + "; CurrentVerticalResolution = " + str(head[1]) + " }\n"
        + block + "\n"
        + "Write-Output ('HX=' + $hx + ' HY=' + $hy)\n"
    )
    result = _REAL_RUN_PS(body, timeout_s=60)
    assert result.returncode != 0, "the band point must make the block throw"
    return result.stderr or ""


_HY_CLAMP_PREFIX = "$hy = [math]::Max(0, [math]::Min($hy,"


def _extract_scale_block(script: str) -> str:
    """The emitted positional-scaling block: from the `$x = ` seed to the
    final $hy clamp line (verbatim lines; PS ignores the leading spaces)."""
    lines = script.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip().startswith("$x = "))
    end = next(
        i for i, ln in enumerate(lines)
        if ln.strip().startswith(_HY_CLAMP_PREFIX)
    )
    return "\n".join(line.strip() for line in lines[start:end + 1])


@pytest.mark.skipif(not _ps_available(), reason="no PowerShell on this host")
def test_single_op_mapper_executes_rect_relative_arithmetic(
        monkeypatch, unrestricted):
    """The single-op template's rect branch executes in real PS 5.1 and
    matches the Python reference (first content row -> head row 0)."""
    rect = [0, 115, 1024, 653]
    console.register_capture(
        "5" * 64, head_resolution=HEAD_WIDE, content_rect=list(rect),
        vm_name="vm1", frame_size=(1024, 768))
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.mouse_move(
        unrestricted, "vm1", 512, 115, frame_width=1024, frame_height=768,
        frame_hash="5" * 64)
    script = next(s for s in fake.scripts if "SetAbsolutePosition" in s)
    block = _extract_scale_block(script)
    assert "$bandl = 0" in block and "$bandt = 115" in block
    assert _exec_block(block, HEAD_WIDE) == _scale_to_head(
        512, 115, 1024, 768, HEAD_WIDE, content_rect=rect)


@pytest.mark.skipif(not _ps_available(), reason="no PowerShell on this host")
def test_single_op_mapper_executes_band_refusal(
        monkeypatch, unrestricted):
    rect = [0, 115, 1024, 653]
    console.register_capture(
        "6" * 64, head_resolution=HEAD_WIDE, content_rect=list(rect),
        vm_name="vm1", frame_size=(1024, 768))
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    # The band point is refused host-side, so build the script through a
    # CONTENT point and prove the same block refuses a band point when run.
    console.mouse_move(
        unrestricted, "vm1", 512, 200, frame_width=1024, frame_height=768,
        frame_hash="6" * 64)
    script = next(s for s in fake.scripts if "SetAbsolutePosition" in s)
    block = _extract_scale_block(script).replace("$x = 512", "$x = 512").replace(
        "$y = 200", "$y = 10")
    stderr = _exec_block_stderr(block, HEAD_WIDE)
    assert "letterbox band point refused" in stderr, (
        "the in-script band refusal must throw naming the letterbox band"
    )


@pytest.mark.skipif(not _ps_available(), reason="no PowerShell on this host")
def test_sequence_mapper_executes_rect_relative_arithmetic(
        monkeypatch, unrestricted):
    """The independent sequence-step mapper executes the same rect-relative
    arithmetic in real PS 5.1 and refuses band points (the two mappers
    cannot be allowed to drift)."""
    rect = [0, 115, 320, 353]
    head = (1024, 1010)
    vhash = "7" * 64
    console.register_capture(
        vhash, head_resolution=head, content_rect=list(rect),
        vm_name="vm1", frame_size=(320, 240))
    scripts: list[str] = []

    def _serve(script, **kwargs):
        scripts.append(script)
        return pswindows.PSResult(
            stdout="VMID=" + GUID + "\nEPOCH=42\nSTEP=0 OK=1\n", returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", _serve)
    steps = [{
        "action": "click", "x": 160, "y": 115 + 100,
        "frame_width": 320, "frame_height": 240, "button": 1,
        "commit_guard": True, "verified_frame_hash": vhash,
    }]
    out = console.run_sequence(
        unrestricted, "vm1", steps, expect_frame_hash=vhash,
        width=320, height=240)
    assert out["ok"] is True
    script = next(s for s in scripts if "ClickButton" in s)
    block = _extract_scale_block(script)
    assert "$bandl = 0" in block and "$bandt = 115" in block
    assert _exec_block(block, head) == _scale_to_head(
        160, 215, 320, 240, head, content_rect=rect)
    band_block = block.replace("$y = 215", "$y = 10")
    stderr = _exec_block_stderr(band_block, head)
    assert "letterbox band point refused" in stderr


def _wmi_pixels(w: int, h: int, fill: int = 7) -> bytes:
    """Synthetic RGB565 payload (4-byte opaque prefix + w*h 2-byte pixels),
    after tests/unit/test_f04_sequence_wmi.py's _pixels, for the WMI-backed
    tests below: _frame_hash(_wmi_pixels(w, h)) is what the fake serves."""
    return bytes([0, 0, 0, 0]) + bytes([fill]) * (w * h * 2)


# ---------------------------------------------------------------------------
# review round 1 (trace 125-126-console-accuracy-commit-guard)
# ---------------------------------------------------------------------------

def test_wait_frame_stable_holds_the_input_lock_for_the_whole_wait(
        monkeypatch, unrestricted):
    """Review Finding 3 (mutation M6b): the SETTLE wait holds the per-VM
    console input lock for the whole wait on the PowerShell transport too —
    a concurrent click while the folded wait_frame_stable leg is in flight
    raises VMBusy instead of interleaving (the mirror of the change-wait pin
    above, driven through console.wait_frame_stable)."""
    from hyperv_mcp import vmlocks

    wait_spawned = threading.Event()
    release = threading.Event()
    real_wait_s = vmlocks._DEFAULT_WAIT_S

    class BlockablePS:
        def __init__(self) -> None:
            self.scripts: list[str] = []

        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            if "GetVirtualSystemThumbnailImage" in script and "STOP=" in script:
                wait_spawned.set()
                release.wait(timeout=30)
                return pswindows.PSResult(
                    stdout="STOP=deadline POLLS=1 HASH=" + "a" * 64,
                    returncode=0)
            return FakePS()(script, **kwargs)

    stub = BlockablePS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    vmlocks.set_default_wait_s(0.2)
    try:
        waiter = threading.Thread(
            target=lambda: console.wait_frame_stable(
                unrestricted, "vm1", stable_ms=1500, timeout_s=30,
                interval_ms=250))
        waiter.start()
        assert wait_spawned.wait(timeout=30), "the wait never spawned"
        with pytest.raises(vmlocks.VMBusy):
            console.click(unrestricted, "vm1", 5, 5)
    finally:
        vmlocks.set_default_wait_s(real_wait_s)
        release.set()
        waiter.join(timeout=30)


def test_refused_sequence_step_does_not_bump_the_ledger(
        monkeypatch, unrestricted):
    """Review Finding 1 (the refused-step-bump mutation): on the WMI
    transport a sequence step refused by its OWN validation — a band point:
    _scale_to_head refuses inside _sequence_wmi_step, AFTER validation and
    BEFORE the device call — dispatches nothing and must NOT bump the input
    ledger, so a later guard citing a capture registered BEFORE the refused
    sequence stays fresh. The cited rect rides the plan step exactly the way
    run_sequence's guard injection threads it (guard_step["content_rect"]),
    reproduced here through the plan-validation seam so the refusal fires at
    DISPATCH, past the plan-build gate."""
    from hyperv_mcp import vmident

    class GuardRailWMI:
        """The f04 FakeWMI surface this test needs (positional click lane)."""

        def __init__(self) -> None:
            self.calls: list[str] = []

        def resolve_vm(self, cfg, vm_name="", vm_id=""):
            self.calls.append("resolve_vm")
            return vmident.VMRef(id=GUID, name=vm_name or "wmi-vm")

        def boot_epoch(self, guid):
            self.calls.append("boot_epoch")
            return 1000

        def capture(self, guid, width, height):
            self.calls.append("capture")
            return _wmi_pixels(width, height), {}

        def head_resolution(self, guid):
            self.calls.append("head_resolution")
            return (1024, 768), {}

        def mouse_move(self, guid, hx, hy):
            self.calls.append("mouse_move")
            return None, {}

        def mouse_click(self, guid, button, hx=None, hy=None):
            self.calls.append("mouse_click")
            return None, {}

    backend = GuardRailWMI()
    monkeypatch.setattr(console, "_try_backend", lambda cfg: (backend, 0.0))
    real_validate = console._validate_sequence_steps

    def _citing_rect(steps, call_timeout_s):
        plan = real_validate(steps, call_timeout_s)
        # the guard-injection seam: a cited content_rect on the step, as
        # run_sequence threads a verified record's rect onto a guarded step
        plan[0]["content_rect"] = [0, 115, 1024, 653]
        return plan

    monkeypatch.setattr(console, "_validate_sequence_steps", _citing_rect)
    # the later guard's citation, registered BEFORE the refused sequence: a
    # refused step that bumped the ledger would turn this capture stale
    verified = console._frame_hash(_wmi_pixels(320, 240))
    console.register_capture(
        verified, vm_name="wmi-vm", vm_id=GUID, frame_size=(320, 240))
    out = console.run_sequence(
        unrestricted, "wmi-vm",
        [{"action": "click", "x": 512, "y": 10,
          "frame_width": 1024, "frame_height": 768, "button": 1}],
        width=1024, height=768)
    assert out["steps"][0]["ok"] is False
    assert "letterbox band" in out["steps"][0]["error"]
    assert backend.calls.count("mouse_move") == 0
    assert backend.calls.count("mouse_click") == 0, (
        "a band-refused step must dispatch no device mouse call"
    )
    assert console._last_input_seq_for(GUID) == 0, (
        "a step refused before dispatch must not bump the input ledger"
    )
    # the follow-up guarded click on the same WMI path is NOT refused as
    # stale because of the refused step (it may only fail for other honest
    # reasons — never the stale-verification text)
    try:
        clicked = console.click(
            unrestricted, "wmi-vm", 160, 120,
            frame_width=320, frame_height=240,
            commit_guard=True, verified_frame_hash=verified)
    except ConsoleError as exc:
        assert "stale verification" not in str(exc), (
            "a refused, never-dispatched step must not stale a later guard: "
            f"refused with {exc}"
        )
        raise
    assert clicked["ok"] is True


# ---------------------------------------------------------------------------
# final-critic round 1 (trace 125-126): dispatch-time bumps on the MOUSE
# legs, both transports — a leg that fails AFTER dispatch leaves delivery
# unknowable, so the conservative answer is that the input happened (the
# mouse twins of test_timed_out_leg_still_bumps above)
# ---------------------------------------------------------------------------

def test_timed_out_ps_click_still_bumps(monkeypatch, unrestricted):
    """(a) A PowerShell positional click whose leg times out AFTER dispatch
    still bumps the ledger: the bump sits at dispatch, inside the input
    lock, BEFORE the spawn — never after the result check."""
    fake = FakePS(responses=[pswindows.PSResult(
        stdout="", stderr="timed out", returncode=1, timed_out=True)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError):
        console.click(unrestricted, "vm1", 160, 120)
    assert console._last_input_seq_for("vm1") > 0, (
        "a timed-out click leg must leave the dispatch-time bump behind"
    )


def test_timed_out_ps_mouse_move_still_bumps(monkeypatch, unrestricted):
    """(b) The mouse_move twin of (a) on the PowerShell transport."""
    fake = FakePS(responses=[pswindows.PSResult(
        stdout="", stderr="timed out", returncode=1, timed_out=True)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError):
        console.mouse_move(unrestricted, "vm1", 160, 120)
    assert console._last_input_seq_for("vm1") > 0, (
        "a timed-out move leg must leave the dispatch-time bump behind"
    )


def test_failed_wmi_click_after_dispatch_still_bumps(monkeypatch, unrestricted):
    """(c) A WMI click whose be.mouse_click raises AFTER dispatch (the bump
    precedes the device call on the WMI path) still bumps the ledger: the
    failure surfaces as ConsoleError, never erasing the bump."""
    from hyperv_mcp import vmident, wmiconsole

    class FailingClickWMI:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def resolve_vm(self, cfg, vm_name="", vm_id=""):
            self.calls.append("resolve_vm")
            return vmident.VMRef(id=GUID, name=vm_name or "wmi-vm")

        def head_resolution(self, guid):
            self.calls.append("head_resolution")
            return (1024, 768), {}

        def mouse_click(self, guid, button, hx=None, hy=None):
            self.calls.append("mouse_click")
            raise wmiconsole.WMIError(
                "ClickButton failed with ReturnValue=5")

    backend = FailingClickWMI()
    monkeypatch.setattr(console, "_try_backend", lambda cfg: (backend, 0.0))
    with pytest.raises(ConsoleError, match="ReturnValue=5"):
        console.click(unrestricted, "wmi-vm", 160, 120)
    assert backend.calls.count("mouse_click") == 1, (
        "the failure must come from the dispatched click leg itself"
    )
    assert console._last_input_seq_for(GUID) > 0, (
        "a click failing after dispatch must leave the bump behind"
    )


def test_failed_wmi_mouse_move_after_dispatch_still_bumps(
        monkeypatch, unrestricted):
    """(d) The mouse_move twin of (c) on the WMI transport: be.mouse_move
    raises after the dispatch-time bump."""
    from hyperv_mcp import vmident, wmiconsole

    class FailingMoveWMI:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def resolve_vm(self, cfg, vm_name="", vm_id=""):
            self.calls.append("resolve_vm")
            return vmident.VMRef(id=GUID, name=vm_name or "wmi-vm")

        def head_resolution(self, guid):
            self.calls.append("head_resolution")
            return (1024, 768), {}

        def mouse_move(self, guid, hx, hy):
            self.calls.append("mouse_move")
            raise wmiconsole.WMIError(
                "SetAbsolutePosition failed with ReturnValue=5")

    backend = FailingMoveWMI()
    monkeypatch.setattr(console, "_try_backend", lambda cfg: (backend, 0.0))
    with pytest.raises(ConsoleError, match="ReturnValue=5"):
        console.mouse_move(unrestricted, "wmi-vm", 160, 120)
    assert backend.calls.count("mouse_move") == 1, (
        "the failure must come from the dispatched move leg itself"
    )
    assert console._last_input_seq_for(GUID) > 0, (
        "a move failing after dispatch must leave the bump behind"
    )


# ---------------------------------------------------------------------------
# feedback round (trace 125-126-console-accuracy-commit-guard, PR #139):
# citation-domain fail-closed + record defaulting, guard-only rect threading,
# the hint-keyed read lock, the production HEAD= preflight parse, the
# in-script cited-head compare, and the hint-learn ledger-key invariant
# ---------------------------------------------------------------------------

# a letterboxed 320x240 capture at the 1920x1010 head (floor model):
# ch = (320*1010)//1920 = 168, top = (240-168)//2 = 36 -> [0, 36, 320, 204]
RECT_320 = [0, 36, 320, 204]


def test_cited_capture_requires_resolvable_domain(monkeypatch, unrestricted):
    """PRR-001 (fail-closed arm): a frame_hash citation whose record carries
    NO frame_size cannot default the pixel domain, so omitted dims refuse
    naming the requirement — head-space coordinates must never be silently
    reinterpreted through the record's rect-relative mapping. The refusal
    precedes every spawn."""
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture(
        "8" * 64, head_resolution=(1024, 768), vm_name="pr0001-vm")
    with pytest.raises(ConsoleError) as excinfo:
        console.click(
            unrestricted, "pr0001-vm", 160, 120, frame_hash="8" * 64)
    assert "frame_width/frame_height are required" in str(excinfo.value)
    assert "registered without a frame_size" in str(excinfo.value), (
        "the refusal must name what the caller has to supply"
    )
    assert fake.scripts == [], "the domain refusal must precede every spawn"


def test_cited_capture_dims_default_from_record(monkeypatch, unrestricted):
    """PRR-011: omitted frame dims default from the cited record's
    frame_size, and the record's content_rect threads into the mapping — the
    pre-dispatch host-side mapping call receives (320, 240) plus the record's
    rect (rect-relative result asserted against the Python reference), the
    emitted positional script carries the same defaulted literals, and a band
    point of that defaulted domain refuses with zero positional scripts."""
    calls: list = []
    real = console._scale_to_head

    def _spy(x, y, fw, fh, head, content_rect=None):
        out = real(x, y, fw, fh, head, content_rect=content_rect)
        calls.append(((x, y, fw, fh, head, content_rect), out))
        return out

    monkeypatch.setattr(console, "_scale_to_head", _spy)
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture(
        "2" * 64, head_resolution=HEAD_WIDE, content_rect=list(RECT_320),
        vm_name="pr0011-vm", frame_size=(320, 240))
    out = console.click(
        unrestricted, "pr0011-vm", 160, 136, frame_hash="2" * 64)
    assert out["ok"] is True
    assert len(calls) == 1
    (args, result) = calls[0]
    assert args[:4] == (160, 136, 320, 240), (
        "the omitted dims must default from the record's frame_size"
    )
    assert args[4] == HEAD_WIDE
    assert args[5] == RECT_320, "the record's content_rect must thread in"
    assert result == _scale_to_head(
        160, 136, 320, 240, HEAD_WIDE, content_rect=RECT_320), (
        "the rect-relative mapping must match the Python reference"
    )
    script = next(s for s in fake.scripts if "SetAbsolutePosition" in s)
    assert "$fw = 320" in script and "$fh = 240" in script, (
        "the emitted script must carry the DEFAULTED domain literals"
    )
    assert "$bandl = 0" in script and "$bandt = 36" in script
    # the band arm: the same defaulted domain + rect refuse host-side, and
    # only the head-only preflight spawns (no additional positional script)
    positional_before = sum(
        "SetAbsolutePosition" in s for s in fake.scripts)
    with pytest.raises(ConsoleError, match="letterbox band"):
        console.click(
            unrestricted, "pr0011-vm", 160, 10, frame_hash="2" * 64)
    assert sum("SetAbsolutePosition" in s for s in fake.scripts) == (
        positional_before), (
        "the band-refused click must record no additional positional script"
    )


def test_cited_capture_dims_default_from_record_mouse_move(
        monkeypatch, unrestricted):
    """PRR-011 (review round 2, N4): the mouse_move twin of
    test_cited_capture_dims_default_from_record — omitted frame dims default
    from the cited record's frame_size on the move path too, the record's
    content_rect threads into the mapping, and the emitted positional script
    carries the same defaulted domain and band literals."""
    calls: list = []
    real = console._scale_to_head

    def _spy(x, y, fw, fh, head, content_rect=None):
        out = real(x, y, fw, fh, head, content_rect=content_rect)
        calls.append(((x, y, fw, fh, head, content_rect), out))
        return out

    monkeypatch.setattr(console, "_scale_to_head", _spy)
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture(
        "7" * 64, head_resolution=HEAD_WIDE, content_rect=list(RECT_320),
        vm_name="pr0011m-vm", frame_size=(320, 240))
    out = console.mouse_move(
        unrestricted, "pr0011m-vm", 160, 136, frame_hash="7" * 64)
    assert out["ok"] is True
    assert len(calls) == 1, (
        "exactly one host-side mapping call: the pre-dispatch validation"
    )
    (args, result) = calls[0]
    assert args[:4] == (160, 136, 320, 240), (
        "the omitted dims must default from the record's frame_size"
    )
    assert args[4] == HEAD_WIDE
    assert args[5] == RECT_320, "the record's content_rect must thread in"
    assert result == _scale_to_head(
        160, 136, 320, 240, HEAD_WIDE, content_rect=RECT_320), (
        "the rect-relative mapping must match the Python reference"
    )
    script = next(s for s in fake.scripts if "SetAbsolutePosition" in s)
    assert "$fw = 320" in script and "$fh = 240" in script, (
        "the emitted move script must carry the DEFAULTED domain literals"
    )
    assert "$bandl = 0" in script and "$bandt = 36" in script, (
        "the record's band literals must thread into the move script"
    )


def test_guard_only_citation_threads_the_rect(monkeypatch, unrestricted):
    """PRR-007: a verified_frame_hash-ONLY guarded click (no frame_hash)
    resolves the verification's record BEFORE the guard check, so its
    frame_size and content_rect define the click's pixel domain exactly like
    a frame_hash citation: a band point of the verification's rect refuses
    with zero positional scripts, and a fresh matching content point proceeds
    with the record's defaulted dims and band literals in the script."""
    vhash = console._frame_hash(_rgb565_payload(320, 240))
    console.register_capture(
        vhash, head_resolution=HEAD_WIDE, content_rect=list(RECT_320),
        vm_name="pr0007-vm", frame_size=(320, 240))
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    # (a) band point of the verification's rect: refused before any spawn
    with pytest.raises(ConsoleError, match="letterbox band"):
        console.click(
            unrestricted, "pr0007-vm", 160, 10,
            commit_guard=True, verified_frame_hash=vhash)
    assert not any("SetAbsolutePosition" in s for s in fake.scripts), (
        "a band-refused guarded click must record zero positional scripts"
    )
    assert not any(
        "GetVirtualSystemThumbnailImage" in s for s in fake.scripts), (
        "the band refusal precedes the guard's live capture too"
    )
    # (b) fresh + matching: the click proceeds through the record's domain
    out = console.click(
        unrestricted, "pr0007-vm", 160, 136,
        commit_guard=True, verified_frame_hash=vhash)
    assert out["ok"] is True
    script = next(s for s in fake.scripts if "SetAbsolutePosition" in s)
    assert "$fw = 320" in script and "$fh = 240" in script, (
        "the omitted dims must default from the VERIFICATION record"
    )
    assert "$bandl = 0" in script and "$bandt = 36" in script, (
        "the verification record's content_rect must thread into the mapper"
    )


@pytest.mark.skipif(not _ps_available(), reason="no PowerShell on this host")
def test_guard_only_citation_mapper_executes_rect_relative(
        monkeypatch, unrestricted):
    """PRR-007 (executed arm, after the in-script band-refusal harness): the
    positional script a GUARD-ONLY citation produced maps through the
    verification record's rect in real PowerShell 5.1 identically to the
    Python reference — the coordinate-level proof that the guard-only record
    threads into the mapper exactly like a frame_hash citation."""
    vhash = console._frame_hash(_rgb565_payload(320, 240))
    console.register_capture(
        vhash, head_resolution=HEAD_WIDE, content_rect=list(RECT_320),
        vm_name="pr0007x-vm", frame_size=(320, 240))
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.click(
        unrestricted, "pr0007x-vm", 160, 136,
        commit_guard=True, verified_frame_hash=vhash)
    script = next(s for s in fake.scripts if "SetAbsolutePosition" in s)
    block = _extract_scale_block(script)
    assert "$bandl = 0" in block and "$bandt = 36" in block
    assert _exec_block(block, HEAD_WIDE) == _scale_to_head(
        160, 136, 320, 240, HEAD_WIDE, content_rect=RECT_320), (
        "the executed guard-only mapper must agree with the reference"
    )


def test_wait_lock_keyed_by_hinted_guid(monkeypatch, unrestricted):
    """PRR-002: once the hint map knows the name, a whole-wait READ locks on
    the GUID — the same identity every hinted input op locks on. The hint is
    learned FIRST, the parked wait's stub does emit VMID=, and a concurrent
    by-name click must still collide (VMBusy); a wait still keyed on the
    caller NAME would exclude nothing here (the hinted click locks the GUID)
    and this pin would fail."""
    from hyperv_mcp import vmlocks

    vm = "pr0002-vm"
    console.note_name_guid_hint(vm, GUID)
    wait_spawned = threading.Event()
    release = threading.Event()
    real_wait_s = vmlocks._DEFAULT_WAIT_S

    class VmidBlockablePS:
        def __init__(self) -> None:
            self.scripts: list[str] = []

        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            if "GetVirtualSystemThumbnailImage" in script and "STOP=" in script:
                wait_spawned.set()
                release.wait(timeout=30)
                return pswindows.PSResult(
                    stdout="VMID=" + GUID + "\nSTOP=deadline POLLS=1 HASH="
                    + "a" * 64,
                    returncode=0)
            return FakePS()(script, **kwargs)

    stub = VmidBlockablePS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    vmlocks.set_default_wait_s(0.2)
    try:
        waiter = threading.Thread(
            target=lambda: console.wait_frame_change(
                unrestricted, vm, timeout_s=30, interval_s=1))
        waiter.start()
        assert wait_spawned.wait(timeout=30), "the wait never spawned"
        with pytest.raises(vmlocks.VMBusy):
            console.click(unrestricted, vm, 5, 5)
    finally:
        vmlocks.set_default_wait_s(real_wait_s)
        release.set()
        waiter.join(timeout=30)


class MetaHeadPS(FakePS):
    """PRR-010: the head-only leg answers with the PRODUCTION ``HEAD=WxH``
    meta line and NO JSON payload, so the parse must ride _parse_head's
    meta-line branch (what real folded scripts emit) rather than the mock
    transport's JSON fallback the base FakePS serves."""

    def __init__(self, head=HEAD_1080):
        super().__init__(head=head)
        self.meta_head_served = False

    def __call__(self, script, **kwargs):
        if ("Msvm_VideoHead" in script
                and "GetVirtualSystemThumbnailImage" not in script):
            self.scripts.append(script)
            self.kwargs.append(kwargs)
            self.meta_head_served = True
            return pswindows.PSResult(
                stdout="VMID=" + GUID + "\nHEAD=" + str(self.head[0]) + "x"
                + str(self.head[1]) + "\n",
                returncode=0)
        return super().__call__(script, **kwargs)


def test_preflight_meta_line_parse_exercised(monkeypatch, unrestricted):
    """PRR-010: a height=0 screenshot's head preflight derives the aspect
    from the production ``HEAD=`` meta line ALONE (no JSON payload): 1024
    wide at a 1920x1080 head captures at 1024x576 — the production parse
    path runs, not the mock transport's JSON fallback."""
    fake = MetaHeadPS(head=HEAD_1080)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    _img, meta = console.screenshot(
        unrestricted, "pr0010-vm", width=1024, height=0)
    assert fake.meta_head_served, "the head-only preflight leg must have run"
    capture = next(
        s for s in fake.scripts if "GetVirtualSystemThumbnailImage" in s)
    assert _folded_size(capture) == (1024, 576), (
        "the derived height must be the head-aspect 576 on a 1920x1080 head"
    )
    assert meta["height"] == 576
    assert meta["content_rect"] == [0, 0, 1024, 576]


@pytest.mark.skipif(not _ps_available(), reason="no PowerShell on this host")
def test_in_script_cited_head_refuses(monkeypatch, unrestricted):
    """PRR-027 (executed, after the in-script band-refusal harness in
    test_single_op_mapper_executes_band_refusal): the %CITEDHEAD compare
    embedded in the positional script throws 'stale frame' when the live
    head differs from the cited record's head — BEFORE SetAbsolutePosition
    (the throw precedes the positioning call in the emitted script itself) —
    while the matching-head control maps normally through the same block."""
    rect = [0, 115, 1024, 653]
    console.register_capture(
        "3" * 64, head_resolution=HEAD_WIDE, content_rect=list(rect),
        vm_name="pr0027-vm", frame_size=(1024, 768))
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.mouse_move(
        unrestricted, "pr0027-vm", 512, 200,
        frame_width=1024, frame_height=768, frame_hash="3" * 64)
    script = next(s for s in fake.scripts if "SetAbsolutePosition" in s)
    # the compare precedes the positioning call in the emitted script
    assert script.index("stale frame") < script.index("SetAbsolutePosition")
    block = _extract_scale_block(script)
    stderr = _exec_block_stderr(block, HEAD_1080)   # a DIFFERENT live head
    assert "stale frame" in stderr, (
        "the in-script cited-head compare must throw naming the stale frame"
    )
    assert "the cited capture was taken at head 1920x1010" in stderr
    # control: the matching head maps normally through the same block
    assert _exec_block(block, HEAD_WIDE) == _scale_to_head(
        512, 200, 1024, 768, HEAD_WIDE, content_rect=rect)


def test_ledger_key_atomic_under_hint_learn():
    """PRR-005 (black-box invariant): the hint-learn re-key cannot orphan a
    name-keyed high-water mark. In the worst-case order — a NAME-keyed bump,
    a capture registered under the name key, the hint learn, then a
    GUID-keyed bump — the GUID key carries at least the name stamp (no lower
    high-water survives) and the mid-flight capture reads STALE against it:
    BOTH the pre-learn and post-learn bumps count."""
    vm = "pr0005-vm"
    console.record_console_input(vm_name=vm)          # name-keyed bump
    name_stamp = console._last_input_seq_for(vm)
    assert name_stamp > 0
    console.register_capture("6" * 64, vm_name=vm, frame_size=(320, 240))
    mid = console._lookup_capture("6" * 64, vm)
    assert mid is not None
    console.note_name_guid_hint(vm, GUID)             # the interleaving point
    migrated = console._lookup_capture("6" * 64, GUID)
    assert migrated is not None and migrated["seq"] == mid["seq"]
    assert console._last_input_seq_for(GUID) >= name_stamp, (
        "the name-keyed high-water must migrate to the GUID key, never orphan"
    )
    console.record_console_input(vm_id=GUID)          # guid-keyed bump
    assert console._last_input_seq_for(GUID) >= max(
        name_stamp, migrated["seq"])
    with pytest.raises(ConsoleError, match="stale verification"):
        console._commit_guard_freshness(migrated)


def test_ledger_key_casefold_merges_name_branch_into_guid():
    """PRR-037 (review round 2, N2): the cold by-name branch CASEFOLDS the
    ledger key exactly like note_name_guid_hint folds its hint-map key, so a
    non-ASCII name's cold stamp is found by the hint-learn merge — "vm-ß"
    (the name branch) and "VM-ß" (the hint's key, a different case) fold to
    the SAME key "vm-ss" (casefold maps sharp-s to "ss"; a lower()-only
    fold would keep "vm-ß" and orphan the stamp), and the GUID-keyed
    freshness read sees the bump after the merge."""
    vm = "vm-ß"
    console.record_console_input(vm_name=vm)          # cold name-branch bump
    assert console._last_input_seq_for("vm-ss") > 0, (
        "the name branch must casefold (ß -> ss), not merely lower"
    )
    assert console._last_input_seq_for(vm) == 0, (
        "the unfolded spelling must NOT be the ledger key"
    )
    console.note_name_guid_hint("VM-ß", GUID)         # different case, same fold
    assert console._last_input_seq_for(GUID) >= 1, (
        "the hint-learn merge must find the casefolded name-keyed stamp and "
        "carry it under the GUID key"
    )
    assert console._last_input_seq_for("vm-ss") == 0, (
        "the merge drains the name key it migrated"
    )


def test_ledger_key_resolution_parks_under_the_hint_lock(monkeypatch):
    """PRR-005 (review round 2, N3 — the concurrency-shape pin behind the
    black-box test above): the mutators resolve the ledger key INSIDE the
    held hint lock. Parking key resolution opens the reviewer's window; a
    concurrent note_name_guid_hint for the same name must stay BLOCKED on
    _HINT_LOCK for the whole park — it cannot interleave between the
    resolution and the ledger mutation, re-keying the map under a key the
    in-flight mutation will never see. Released, the bump lands under the
    NAME key it resolved, and the learn (running after it) migrates the
    stamp to the GUID key."""
    vm = "pr0005c-vm"
    entered = threading.Event()
    release = threading.Event()
    resolved: list[str] = []
    real = console._ledger_key_unlocked

    def parked(vm_name, vm_id):
        entered.set()
        assert release.wait(timeout=10), "the parked resolution was never released"
        key = real(vm_name, vm_id)
        resolved.append(key)
        return key

    monkeypatch.setattr(console, "_ledger_key_unlocked", parked)

    bump = threading.Thread(
        target=lambda: console.record_console_input(vm_name=vm),
        name="pr0005c-bump")
    bump.start()
    assert entered.wait(timeout=10), "the bump never reached key resolution"

    learned: list[bool] = []
    learn = threading.Thread(
        target=lambda: (console.note_name_guid_hint(vm, GUID),
                        learned.append(True)),
        name="pr0005c-learn")
    learn.start()
    learn.join(timeout=0.3)
    assert learned == [], (
        "the hint learn must stay BLOCKED while key resolution holds "
        "_HINT_LOCK — resolution and mutation are one atomic chain"
    )
    release.set()
    bump.join(timeout=10)
    learn.join(timeout=10)
    assert not bump.is_alive() and not learn.is_alive()

    assert resolved == [vm], (
        "the bump resolved its key BEFORE the learn ran, so the key is the "
        f"folded name ({vm!r}), not the GUID"
    )
    assert console._last_input_seq_for(vm) == 0, (
        "the learn must have drained the name key it migrated"
    )
    assert console._last_input_seq_for(GUID) >= 1, (
        "the name-keyed stamp must land under the GUID after the merge"
    )
