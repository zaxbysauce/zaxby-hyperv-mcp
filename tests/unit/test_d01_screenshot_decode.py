"""Workstream D PR 1 (issue #17): native RGB565 decode and one PNG encode per image.

RED at base c475681, GREEN after the fix. Six checks bind AC1-AC6 of the issue; the
PRESERVING criteria (AC7-AC12) are the existing tests named in the trace's
01-issue-summary.md and are replayed from their own files.

Why the shapes here are what they are:

* The encode counter must be installed AFTER `Image.init()`, otherwise plugin
  registration overwrites the patch and the counter reads zero (a vacuous pass).
* Every tool-layer check runs as a pytest test. Outside pytest this box is a real
  Hyper-V host, `wmiconsole.COM_AVAILABLE` is true, and the in-process WMI backend is
  selected — the `run_ps` stub is bypassed and the call fails with a WMI transport
  error. tests/unit/conftest.py's autouse `_ps_transport_default` fixture forces the
  PowerShell transport, which is what these checks assert against.
* The server object is an mcp 2.x `MCPServer` (not FastMCP); tools are invoked with
  `asyncio.run(mcp.call_tool(name, args))` after a reload + bootstrap, mirroring
  tests/unit/test_image_content.py.
* Assertions are on recorded facts (trace counts, pixel bytes, encode counts), never
  on wall-clock time.
"""

import asyncio
import base64
import importlib
import json
import sys

import pytest
from conftest import content_blocks
from PIL import Image

import hyperv_mcp.server as server_module
from hyperv_mcp import console as console_module
from hyperv_mcp import pswindows

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
HEAD_RES = '{"horizontal": 1024, "vertical": 768}'


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def encode_counter(monkeypatch):
    """Count PNG encodes. Image.init() first: without it the SAVE registry does
    not exist yet and a patch made earlier is overwritten by plugin registration."""
    Image.init()
    original = Image.SAVE["PNG"]
    box = {"encodes": 0}

    def counting_encode(fp, *args, **kwargs):
        box["encodes"] += 1
        return original(fp, *args, **kwargs)

    monkeypatch.setitem(Image.SAVE, "PNG", counting_encode)
    return box


def _is_folded_op_script(script: str) -> bool:
    """True when a generated script is a folded-protocol op script (issue #18:
    the whole op in ONE process, the VM bound in-script). Dual-protocol
    arbitration keys on this: the replay legs run these checks against BOTH
    console protocols — the trace-17 recorded base c475681, where every op leg
    interpolates the resolved GUID literally (resolve, head resolution,
    capture and the poll loop are separate processes), and the head tree,
    where the folded op scripts look the VM up through the in-script
    $vmTarget binding (Msvm_ComputerSystem -Filter "Name='$vmTarget'"). The
    standalone resolvers (the by-name PR #4 loop, the by-id Get-VM lookup)
    also mention $vmTarget but never through that filter, and they expect the
    same response at both eras, so they stay on the legacy queue at both
    ends."""
    return "Name='$vmTarget'" in script


class _ResponseQueue:
    """Stand-in for pswindows.run_ps with dual-protocol response arbitration:
    every received script is classified from its text and answered from the
    matching queue — folded op scripts from ``folded``, every pre-fold leg and
    the era-agnostic resolvers from ``legacy``. Each queue keeps the original
    one-response-per-call discipline: an extra call on an empty queue fails
    loudly, exactly as the single-protocol stub did."""

    def __init__(self, legacy=(), folded=()):
        self.legacy = list(legacy)
        self.folded = list(folded)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        queue = self.folded if _is_folded_op_script(script) else self.legacy
        assert queue, "unexpected extra run_ps call"
        return queue.pop(0)


def _ok(stdout):
    return pswindows.PSResult(stdout=stdout, returncode=0)


def _assert_era_queue_drained(stub: _ResponseQueue) -> None:
    """CUB-d01-92: the dual-queue stub lets unused responses of the OTHER
    era sit unconsumed, which softened the single-protocol stub's strict
    call-count discipline. After each tool body, the queue for the era
    that actually ran must be fully drained — leftover responses there
    mean the call count regressed (fewer op legs than the check queued),
    while an extra call on an empty queue already fails loudly in the
    stub itself."""
    era_folded = any(_is_folded_op_script(s) for s in stub.scripts)
    leftover = stub.folded if era_folded else stub.legacy
    era = "folded" if era_folded else "legacy"
    assert not leftover, (
        f"{len(leftover)} unconsumed {era}-era response(s) after the tool "
        "call — the run_ps call count for the running era regressed"
    )


def _guid_leg():
    return _ok(GUID)


def _folded_screenshot(payload: bytes, w: int, h: int):
    """One folded capture: VMID/HEAD/SIZES/USED metadata ahead of the payload
    JSON (issue #18: the whole capture runs in one process)."""
    return _ok(
        "VMID=" + GUID + "\n"
        + "HEAD=1024x768" + "\n"
        + "SIZES=" + str(w) + "x" + str(h) + "\n"
        + "USED=" + str(w) + "x" + str(h) + "\n"
        + _capture_leg(payload).stdout
    )


def _head_leg():
    return _ok(HEAD_RES)


def _capture_leg(payload):
    return _ok(json.dumps({
        "returnValue": 0,
        "imageDataB64": base64.b64encode(payload).decode(),
    }))


def _thumbnail(width, height):
    """4-byte opaque prefix + width*height little-endian RGB565 pixels."""
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            pixels.append(v & 0xFF)
            pixels.append((v >> 8) & 0xFF)
    return b"\x00\x00\x96\x04" + bytes(pixels)


def _all_values_frame():
    """A 256x256 frame holding every RGB565 value 0..65535, little-endian,
    behind the 4-byte opaque prefix."""
    pixels = bytearray()
    for v in range(65536):
        pixels.append(v & 0xFF)
        pixels.append((v >> 8) & 0xFF)
    return b"\x00\x00\x96\x04" + bytes(pixels)


@pytest.fixture()
def tool_server(monkeypatch):
    """A freshly bootstrapped server exposing the registered tool surface."""
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
    yield mod.get_mcp()
    importlib.reload(server_module)


def _image_blocks(result):
    return [c for c in content_blocks(result) if getattr(c, "type", "") == "image"]


# ---------------------------------------------------------------------------
# AC1 — no per-pixel Python loop
# ---------------------------------------------------------------------------

def test_decode_runs_no_per_pixel_python_loop():
    """AC1: RED at base (589835 line events for a 256x256 frame), GREEN after the
    fix. A trace count is machine-speed independent, so it replaces a wall-clock
    budget. The threshold of 1000 leaves room for the handful of lines a native
    decode plus its length checks executes, and is far below any per-pixel loop."""
    raw = _all_values_frame()
    events = {"n": 0}

    def tracer(frame, event, arg):
        if event == "line" and frame.f_code.co_filename.endswith("console.py"):
            events["n"] += 1
        return tracer

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        console_module._decode_rgb565(raw, 256, 256)
    finally:
        sys.settrace(previous)

    assert events["n"] < 1000, (
        f"AC1: {events['n']} line events in console.py for a 256x256 frame; "
        "a per-pixel Python loop executes about 9 lines per pixel"
    )


# ---------------------------------------------------------------------------
# AC2 — the image-returning decode helper matches the 424919f formula exactly
# ---------------------------------------------------------------------------

def test_decode_image_matches_formula_for_all_65536_values():
    """AC2: the image-returning decode helper does not exist at base
    (AttributeError), so this is a NEW-SURFACE check. RED at base with that
    absence signature, GREEN after the fix. It pins the exact quantisation
    formula the shipped loop used: (r5*255)//31, (g6*255)//63, (b5*255)//31."""
    raw = _all_values_frame()
    img = console_module._decode_rgb565_image(raw, 256, 256)

    assert img.size == (256, 256)
    assert img.mode == "RGB"
    got = img.tobytes()
    assert len(got) == 256 * 256 * 3

    expected = bytearray()
    for v in range(65536):
        r5 = (v >> 11) & 0x1F
        g6 = (v >> 5) & 0x3F
        b5 = v & 0x1F
        expected.append((r5 * 255) // 31)
        expected.append((g6 * 255) // 63)
        expected.append((b5 * 255) // 31)

    mismatches = sum(1 for a, b in zip(got, bytes(expected), strict=True) if a != b)
    assert mismatches == 0, f"AC2: {mismatches} pixel bytes differ from the formula"


# ---------------------------------------------------------------------------
# AC3 — screenshot encodes once
# ---------------------------------------------------------------------------

def test_screenshot_tool_encodes_png_once(monkeypatch, encode_counter, tool_server):
    """AC3: RED at base with `assert 2 == 1` (console._decode_rgb565 encodes, then
    the tool encodes again), GREEN after the fix. One PNG encode per returned image."""
    payload = _thumbnail(320, 240)
    stub = _ResponseQueue(
        legacy=[
            _guid_leg(),          # by-name resolve (pre-fold leg 1)
            _head_leg(),          # head resolution (pre-fold leg 2)
            _capture_leg(payload)  # capture (pre-fold leg 3)
        ],
        folded=[_folded_screenshot(payload, 320, 240)],
    )
    monkeypatch.setattr(pswindows, "run_ps", stub)
    encode_counter["encodes"] = 0

    result = asyncio.run(tool_server.call_tool(
        "hyperv_console_screenshot",
        {"vm_name": "test-vm-1", "width": 320, "height": 240},
    ))

    assert _image_blocks(result), "AC3: no image block returned"
    assert encode_counter["encodes"] == 1, (
        f"AC3: {encode_counter['encodes']} PNG encodes for one returned image"
    )
    _assert_era_queue_drained(stub)  # CUB-d01-92: era queue drained fully


# ---------------------------------------------------------------------------
# AC4 — wait_frame_change encodes once
# ---------------------------------------------------------------------------

def test_wait_frame_change_tool_encodes_png_once(monkeypatch, encode_counter, tool_server):
    """AC4: RED at base with `assert 2 == 1` (console.py encodes inside the decode
    and server.py encodes again), GREEN after the fix."""
    width, height = 320, 240
    payload = b"\x00\x00\x00\x00" + b"\x00\x00" * (width * height)
    frame_line = "STOP=changed POLLS=2 HASH=" + "a" * 64 + "\nFRAME=" + base64.b64encode(payload).decode()
    stub = _ResponseQueue(
        legacy=[
            _guid_leg(),   # by-name resolve (pre-fold)
            _ok(frame_line)  # the poll loop itself (identical shape pre-fold)
        ],
        folded=[_ok(frame_line)],
    )
    monkeypatch.setattr(pswindows, "run_ps", stub)
    encode_counter["encodes"] = 0

    result = asyncio.run(tool_server.call_tool(
        "hyperv_console_wait_frame_change",
        {
            "vm_name": "test-vm-1",
            "baseline_hash": "b" * 64,
            "width": width,
            "height": height,
        },
    ))

    assert _image_blocks(result), "AC4: no image block returned for a changed frame"
    assert encode_counter["encodes"] == 1, (
        f"AC4: {encode_counter['encodes']} PNG encodes for one returned image"
    )
    _assert_era_queue_drained(stub)  # CUB-d01-92: era queue drained fully


# ---------------------------------------------------------------------------
# AC5 — capture_sequence encodes each returned image once
# ---------------------------------------------------------------------------

def test_capture_sequence_tool_encodes_each_returned_png_once(monkeypatch, encode_counter, tool_server):
    """AC5: RED at base with `assert (4, 2) == (2, 2)` — console.py encodes the
    first and last frame and server.py re-encodes both. GREEN after the fix: one
    encode per returned image (a 3-frame sequence returns the first and last)."""
    width, height = 320, 240
    payload = _thumbnail(width, height)
    stub = _ResponseQueue(
        legacy=[_guid_leg()] + [_capture_leg(payload) for _ in range(3)],
        folded=[_capture_leg(payload) for _ in range(3)],
    )
    monkeypatch.setattr(pswindows, "run_ps", stub)
    encode_counter["encodes"] = 0

    result = asyncio.run(tool_server.call_tool(
        "hyperv_console_capture_sequence",
        {"vm_name": "test-vm-1", "count": 3, "width": width, "height": height},
    ))

    image_blocks = _image_blocks(result)
    assert len(image_blocks) == 2, f"AC5: {len(image_blocks)} image blocks, expected 2"
    assert (encode_counter["encodes"], len(image_blocks)) == (2, 2), (
        f"AC5: ({encode_counter['encodes']}, {len(image_blocks)}) — one encode per image"
    )
    _assert_era_queue_drained(stub)  # CUB-d01-92: era queue drained fully


# ---------------------------------------------------------------------------
# AC6 — capture_evidence encodes once
# ---------------------------------------------------------------------------

def test_capture_evidence_tool_encodes_png_once(monkeypatch, encode_counter, tool_server):
    """AC6: RED at base with `assert 2 == 1` — evidence reuses console.screenshot
    (one encode) and server._image_meta_content encodes again. GREEN after the fix.

    capture_evidence resolves the VM itself before the screenshot leg. The two
    resolvers (evidence's own by-name resolve, the screenshot's by-id resolve)
    are era-agnostic legs served from the legacy queue at BOTH ends; the
    capture leg differs: pre-fold the head resolution and the capture are two
    more legacy responses, folded it is ONE folded capture."""
    payload = _thumbnail(320, 240)
    stub = _ResponseQueue(
        legacy=[
            _guid_leg(),          # evidence's own by-name resolve
            _ok("test-vm-1"),     # console's by-id resolve (policy on the real name)
            _head_leg(),          # head resolution (pre-fold)
            _capture_leg(payload)  # capture (pre-fold)
        ],
        folded=[_folded_screenshot(payload, 320, 240)],
    )
    monkeypatch.setattr(pswindows, "run_ps", stub)
    encode_counter["encodes"] = 0

    result = asyncio.run(tool_server.call_tool(
        "hyperv_capture_evidence",
        {"vm_name": "test-vm-1", "width": 320, "height": 240},
    ))

    assert _image_blocks(result), "AC6: no image block returned"
    assert encode_counter["encodes"] == 1, (
        f"AC6: {encode_counter['encodes']} PNG encodes for one returned image"
    )
    _assert_era_queue_drained(stub)  # CUB-d01-92: era queue drained fully
