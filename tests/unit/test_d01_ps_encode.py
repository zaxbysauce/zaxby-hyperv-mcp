"""Workstream D PR 1 (issue #17), PowerShell transport: the frame contract.

`tests/unit/test_d01_screenshot_decode.py` is byte-frozen by the issue-tracer
red checkpoint, and `tests/unit/test_d01_wmi_encode.py` covers the in-process
WMI transport. The PowerShell transport is the one `tests/unit/conftest.py`
forces for every tool-layer test — and the only transport on non-Windows hosts
and wherever the in-process backend cannot connect — so the invariants the two
frozen files pin for the other transports are pinned here for this one.

Findings closed here (swarm-pr-review PR #73):

* **PRR-001** — the PowerShell leg's `save_path` <-> `ImageContent` byte
  identity was unpinned. `test_console.py`'s only assertion was
  `dest.stat().st_size > 8`, which is satisfied by any valid PNG (and by no
  valid PNG at all). A mutation writing a pixel-identical `optimize=True`
  re-encode, and one writing the raw RGB565 payload, both left the full suite
  green. Both are now RED.
* **PRR-008** — the frozen bit-exactness check compares with `zip` without
  `strict=True`, so a future length divergence would report
  `mismatches == 0` and pass. The frozen file cannot be edited, so the
  compensating length guard lives here.
* **PRR-002 / PRR-010** — the frame's `png` is a read-only snapshot of its
  pixels. A mutation of the image must be observable (a re-save differs) and a
  reassignment of `png` must be refused, so the two representations cannot
  silently diverge without a test noticing.

Every assertion is on recorded facts — counts, bytes, and raised exceptions —
never on wall-clock time.
"""

import asyncio
import base64
import importlib
import io
import json

import pytest
from PIL import Image

import hyperv_mcp.server as server_module
from hyperv_mcp import console as console_module
from hyperv_mcp import pswindows

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
HEAD_RES = '{"horizontal": 1024, "vertical": 768}'


def _thumbnail(width: int, height: int) -> bytes:
    """4-byte opaque prefix + width*height little-endian RGB565 pixels."""
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            pixels.append(v & 0xFF)
            pixels.append((v >> 8) & 0xFF)
    return b"\x00\x00\x96\x04" + bytes(pixels)


class _ResponseQueue:
    """Stand-in for pswindows.run_ps: pops one PSResult per call."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        assert self.responses, "unexpected extra run_ps call"
        return self.responses.pop(0)


def _ok(stdout):
    return pswindows.PSResult(stdout=stdout, returncode=0)


def _capture_leg(payload):
    return _ok(json.dumps({
        "returnValue": 0,
        "imageDataB64": base64.b64encode(payload).decode(),
    }))


@pytest.fixture()
def tool_server(monkeypatch):
    """A freshly bootstrapped server whose console tools take the PS transport."""
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
    yield mod.get_mcp()
    importlib.reload(server_module)


def _blocks(result):
    from conftest import content_blocks

    return content_blocks(result)


def _image_blocks(result):
    return [c for c in _blocks(result) if getattr(c, "type", "") == "image"]


def _text_block(result) -> dict:
    texts = [c for c in _blocks(result) if getattr(c, "type", "") == "text"]
    assert texts, "expected a metadata text block"
    return json.loads(texts[0].text)


# ---------------------------------------------------------------------------
# PRR-001 — save_path bytes ARE the returned ImageContent bytes (PS transport)
# ---------------------------------------------------------------------------

def test_ps_screenshot_save_path_bytes_match_returned(monkeypatch, tool_server, tmp_path):
    """RED at base: the PowerShell leg's save_path write was guarded only by
    `st_size > 8`, so a pixel-identical re-encode with different bytes, or an
    outright non-PNG payload, both passed the whole suite. GREEN after the fix."""
    w, h = 320, 240
    payload = _thumbnail(w, h)
    monkeypatch.setattr(pswindows, "run_ps", _ResponseQueue([
        _ok(GUID), _ok(HEAD_RES), _capture_leg(payload),
    ]))
    dest = tmp_path / "shots" / "frame.png"

    result = asyncio.run(tool_server.call_tool(
        "hyperv_console_screenshot",
        {"vm_name": "test-vm-1", "width": w, "height": h, "save_path": str(dest)},
    ))

    images = _image_blocks(result)
    assert len(images) == 1, f"{len(images)} image blocks, expected 1"
    on_disk = dest.read_bytes()
    assert on_disk == base64.b64decode(images[0].data), (
        "the bytes written to save_path differ from the bytes returned as "
        "ImageContent (PRR-001: this leg was unpinned)"
    )
    # The artifact is a decodable PNG of the requested size, not merely >8 bytes.
    decoded = Image.open(io.BytesIO(on_disk))
    assert decoded.size == (w, h)
    assert _text_block(result)["saved_path"] == str(dest)


def test_ps_screenshot_save_path_write_is_png_not_raw_payload(monkeypatch, tool_server, tmp_path):
    """PRR-001, wider form: the file is a real PNG, not the raw RGB565 payload.
    A mutation writing `raw` (~614 KB, undecodable) passed `st_size > 8`."""
    w, h = 320, 240
    payload = _thumbnail(w, h)
    monkeypatch.setattr(pswindows, "run_ps", _ResponseQueue([
        _ok(GUID), _ok(HEAD_RES), _capture_leg(payload),
    ]))
    dest = tmp_path / "frame.png"

    asyncio.run(tool_server.call_tool(
        "hyperv_console_screenshot",
        {"vm_name": "test-vm-1", "width": w, "height": h, "save_path": str(dest)},
    ))

    on_disk = dest.read_bytes()
    assert on_disk.startswith(b"\x89PNG\r\n\x1a\n"), (
        "save_path did not receive a PNG; the raw payload would satisfy a bare "
        "size check (PRR-001)"
    )
    # ...and it is far smaller than the payload, i.e. it was actually encoded.
    assert len(on_disk) < len(payload)


# ---------------------------------------------------------------------------
# PRR-008 — compensating length guard for the frozen bit-exactness check
# ---------------------------------------------------------------------------

def test_decode_image_expected_buffer_length_matches_output():
    """PRR-008: the frozen check compares with `zip(got, bytes(expected))` and
    no `strict=`, so a length divergence would silently truncate and report
    `mismatches == 0`. The frozen file cannot be edited, so the length
    invariant it relies on is pinned here."""
    raw = b"\x00\x00\x96\x04" + bytes(
        b for v in range(65536) for b in (v & 0xFF, (v >> 8) & 0xFF)
    )
    img = console_module._decode_rgb565_image(raw, 256, 256)
    got = img.tobytes()

    expected = bytearray()
    for v in range(65536):
        expected.append(((v >> 11) & 0x1F) * 255 // 31)
        expected.append(((v >> 5) & 0x3F) * 255 // 63)
        expected.append((v & 0x1F) * 255 // 31)

    assert len(got) == len(expected) == 256 * 256 * 3, (
        f"length divergence: got {len(got)} bytes, expected {len(expected)} — "
        "a plain zip() would truncate and report zero mismatches (PRR-008)"
    )
    mismatches = sum(1 for a, b in zip(got, bytes(expected), strict=True) if a != b)
    assert mismatches == 0, f"{mismatches} pixel bytes differ from the formula"


# ---------------------------------------------------------------------------
# PRR-002 / PRR-010 — the frame's png is a read-only snapshot of its pixels
# ---------------------------------------------------------------------------

def test_frame_png_is_read_only_snapshot_of_its_pixels():
    """PRR-002 + PRR-010: `png` cannot be reassigned (so no caller can install
    bytes that are not an encoding of this frame), and a mutation of the image
    is observable — a re-save differs — so the two representations cannot
    silently diverge without a test noticing."""
    raw = b"\x00\x00\x96\x04" + b"\x5a\xa5" * 12
    frame = console_module._decode_frame(raw, 4, 3)

    # png is a genuine encoding of the frame's own pixels.
    reencoded = io.BytesIO()
    frame.save(reencoded, format="PNG")
    assert reencoded.getvalue() == frame.png

    # Reassignment is refused rather than silently accepted.
    with pytest.raises(AttributeError, match="read-only"):
        frame.png = b"not a png"

    # Mutating the image is observable: a re-save no longer matches png.
    frame.putpixel((0, 0), (255, 0, 0))
    after = io.BytesIO()
    frame.save(after, format="PNG")
    assert after.getvalue() != frame.png, (
        "mutating the image left png byte-identical; the snapshot and the "
        "pixels diverged silently (PRR-002)"
    )


def test_frame_is_a_pil_image():
    """PRR-005 / PRR-006 / PRR-009: a frame IS a PIL.Image.Image, so the
    protocols the pre-#17 return value satisfied still work — isinstance,
    the context manager, numpy interop — and any consumer written against the
    old contract keeps working."""
    raw = b"\x00\x00\x96\x04" + b"\x5a\xa5" * 12
    frame = console_module._decode_frame(raw, 4, 3)

    assert isinstance(frame, Image.Image)
    assert isinstance(frame.image, Image.Image) if hasattr(frame, "image") else True
    assert frame.size == (4, 3)
    assert frame.mode == "RGB"
    with frame as opened:
        assert isinstance(opened, Image.Image)
    assert isinstance(frame.__array_interface__, dict)
    assert frame.getpixel((0, 0)) == (164, 170, 213)


def test_console_frame_is_a_public_nameable_type():
    """PRR-011: the public operations advertise a type a downstream consumer
    can name and import, not an underscore-private detail."""
    import hyperv_mcp.console as console_pkg

    assert "Frame" in console_pkg.__all__
    from hyperv_mcp.console import Frame  # noqa: F401  (importability is the point)

    assert console_pkg.Frame is Frame
