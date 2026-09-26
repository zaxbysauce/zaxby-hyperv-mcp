"""Image-content contract test: the screenshot tool must return real MCP
ImageContent through FastMCP's conversion path (not base64-in-text).

Critic-round-1 item 10: a regression to dict{png_b64} would pass every
mocked test — this test invokes the registered tool through FastMCP.
"""

import base64
import io

import pytest
from mcp.types import ImageContent
from PIL import Image

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows


def _raw_thumbnail(w: int, h: int) -> bytes:
    pixels = bytearray()
    for y in range(h):
        for x in range(w):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            pixels.append(v & 0xFF)
            pixels.append((v >> 8) & 0xFF)
    return b"\x00\x00\x96\x04" + bytes(pixels)


@pytest.fixture()
def fresh_server():
    import importlib

    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
    yield mod
    importlib.reload(server_module)


def _mock_capture(monkeypatch, w, h):
    payload = _raw_thumbnail(w, h)
    head_res = '{"horizontal": 1024, "vertical": 768}'
    responses = [
        pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),  # guid
        pswindows.PSResult(stdout=head_res, returncode=0),  # head resolution
        pswindows.PSResult(
            stdout=persona_json(payload), returncode=0),  # capture
    ]
    fake = FakeCapture(responses)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    return fake


class FakeCapture:
    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return self.responses.pop(0)


def persona_json(payload: bytes) -> str:
    import json

    return json.dumps({
        "returnValue": 0,
        "imageDataB64": base64.b64encode(payload).decode(),
    })


def test_screenshot_returns_image_content(monkeypatch, fresh_server):
    _mock_capture(monkeypatch, 320, 240)
    mcp = fresh_server.get_mcp()

    import asyncio

    result = asyncio.run(mcp.call_tool(
        "hyperv_console_screenshot",
        {"vm_name": "test-vm-1", "width": 320, "height": 240},
    ))
    content = result[0] if isinstance(result, tuple) else result
    image_blocks = [c for c in content if getattr(c, "type", "") == "image"]
    assert image_blocks, f"no image content in {[type(c).__name__ for c in content]}"
    block = image_blocks[0]
    assert isinstance(block, ImageContent)
    assert block.mimeType == "image/png"
    # the image decodes to the requested dimensions
    img = Image.open(io.BytesIO(base64.b64decode(block.data)))
    assert img.size == (320, 240)
    # a metadata text block carries vm_id and frame_hash
    text_blocks = [c for c in content if getattr(c, "type", "") == "text"]
    assert text_blocks, "metadata text block missing"
    assert "e953c649" in text_blocks[0].text and "frame_hash" in text_blocks[0].text


def test_wait_frame_change_changed_returns_image_content(monkeypatch, fresh_server):
    import asyncio

    w, h = 320, 240
    payload = b"\x00\x00\x00\x00" + b"\x00\x00" * (w * h)
    fake = FakeCapture([pswindows.PSResult(
        stdout=(
            "STOP=changed POLLS=2 HASH=abc\nFRAME="
            + base64.b64encode(payload).decode()
        ),
        returncode=0,
    )])
    # first run_ps call is the guid resolution
    fake.responses.insert(0, pswindows.PSResult(
        stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0))
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = fresh_server.get_mcp()
    result = asyncio.run(mcp.call_tool(
        "hyperv_console_wait_frame_change",
        {"vm_name": "test-vm-1", "baseline_hash": "a" * 64, "width": w, "height": h},
    ))
    content = result[0] if isinstance(result, tuple) else result
    image_blocks = [c for c in content if getattr(c, "type", "") == "image"]
    assert image_blocks and image_blocks[0].mimeType == "image/png"


def test_deadline_wait_returns_no_image_block(monkeypatch, fresh_server):
    import asyncio

    fake = FakeCapture([
        pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
        pswindows.PSResult(stdout="STOP=deadline POLLS=10 HASH=abc", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = fresh_server.get_mcp()
    result = asyncio.run(mcp.call_tool(
        "hyperv_console_wait_frame_change",
        {"vm_name": "test-vm-1", "timeout_s": 5, "interval_s": 1},
    ))
    content = result[0] if isinstance(result, tuple) else result
    assert not [c for c in content if getattr(c, "type", "") == "image"]
