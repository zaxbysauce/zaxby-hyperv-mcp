"""Workstream D PR 1 (issue #17), in-process WMI transport: one PNG encode.

The frozen checks in `test_d01_screenshot_decode.py` count PNG encodes through the
registered tool, which `tests/unit/conftest.py`'s autouse `_ps_transport_default`
fixture pins to the PowerShell transport. The in-process WMI legs are the default
transport on a real Hyper-V host, so a PowerShell-only rewiring would green every
frozen check while real hosts still encoded twice. These tests close that gap by
driving the same tools with a fake in-process backend installed.

They are regression evidence, not frozen acceptance checks: the issue's AC set maps
1:1 onto C1-C12 and the Phase 2.5 freeze forbids a second row per AC. They run against
a minimal fake backend installed the way `test_wmiconsole.py` does it
(`wmiconsole.backend` + `COM_AVAILABLE = True`), with no pywin32 and no real COM.

The encode count is only meaningful through the tool layer: at the module layer the
console leg's own encode is the only one, so a module-level count reads the same before
and after the fix. Every test here therefore goes through `mcp.call_tool`.
"""

import asyncio
import base64
import importlib
import json

import pytest

# PRR-016: the encode oracle and the payload builder are the single source of
# truth for the headline invariant, and the copy in the frozen
# test_d01_screenshot_decode.py cannot be updated. Import rather than duplicate
# so the two files cannot drift.
from test_d01_screenshot_decode import _thumbnail

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows, vmident, wmiconsole
from hyperv_mcp.config import Config

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


class _FakeBackend:
    """The minimum surface console.py's WMI legs reach the backend through."""

    def __init__(self, head: tuple[int, int], payload: bytes):
        self.head = head
        self.payload = payload
        self.captures: list[tuple[int, int]] = []

    def resolve_vm(self, cfg: Config, vm_name: str = "", vm_id: str = "") -> vmident.VMRef:
        return vmident.VMRef(id=GUID, name=vm_name or "vm1")

    def head_resolution(self, guid: str) -> tuple[tuple[int, int], dict]:
        return self.head, {}

    def capture(self, guid: str, width: int, height: int) -> tuple[bytes, dict]:
        self.captures.append((width, height))
        return self.payload, {}


@pytest.fixture()
def wmi_server(monkeypatch):
    """A freshly bootstrapped server whose console tools take the WMI leg."""
    def _install(backend: _FakeBackend):
        monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", True)
        monkeypatch.setattr(wmiconsole, "backend", lambda cfg: backend)
        monkeypatch.setattr(wmiconsole, "_backends", {})
        monkeypatch.setattr(wmiconsole, "_connect_failures", {})

        def no_powershell(script, **kwargs):
            raise AssertionError(
                "the WMI transport was selected but a PowerShell leg still ran; "
                "the transport fell back"
            )

        monkeypatch.setattr(pswindows, "run_ps", no_powershell)
        mod = importlib.reload(server_module)
        mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
        return mod

    yield _install
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


def test_wmi_screenshot_tool_encodes_png_once(monkeypatch, png_encode_counter, wmi_server):
    """RED at base (the WMI leg encodes inside the decode and the tool encodes
    again), GREEN after the fix."""
    w, h = 320, 240
    backend = _FakeBackend((w, h), _thumbnail(w, h))
    mcp = wmi_server(backend).get_mcp()
    png_encode_counter["encodes"] = 0

    result = asyncio.run(mcp.call_tool(
        "hyperv_console_screenshot",
        {"vm_name": "vm1", "width": w, "height": h},
    ))

    images = _image_blocks(result)
    assert len(images) == 1, f"{len(images)} image blocks, expected 1"
    assert _text_block(result)["capture_method"].startswith(
        "GetVirtualSystemThumbnailImage (in-process WMI"
    ), "the test did not exercise the WMI transport"
    assert png_encode_counter["encodes"] == 1, (
        f"WMI screenshot: {png_encode_counter['encodes']} PNG encodes for one returned image"
    )
    # PRR-015: the requested size is what the backend was asked for.
    assert backend.captures == [(w, h)], (
        f"WMI screenshot requested {backend.captures}, expected one {(w, h)} capture"
    )


def test_wmi_capture_sequence_tool_encodes_each_returned_png_once(
    monkeypatch, png_encode_counter, wmi_server
):
    """RED at base (4 encodes for the 2 returned images), GREEN after the fix."""
    w, h = 320, 240
    backend = _FakeBackend((w, h), _thumbnail(w, h))
    mcp = wmi_server(backend).get_mcp()
    png_encode_counter["encodes"] = 0

    result = asyncio.run(mcp.call_tool(
        "hyperv_console_capture_sequence",
        {"vm_name": "vm1", "count": 3, "width": w, "height": h},
    ))

    images = _image_blocks(result)
    assert len(images) == 2, f"{len(images)} image blocks, expected 2"
    assert (png_encode_counter["encodes"], len(images)) == (2, 2), (
        f"WMI capture_sequence: ({png_encode_counter['encodes']}, {len(images)}) — "
        "one encode per returned image"
    )
    # PRR-015: the requested capture-size chain is verified, not just recorded.
    assert backend.captures == [(w, h)] * 3, (
        f"WMI capture_sequence requested {backend.captures}, expected three "
        f"{(w, h)} captures"
    )


def test_wmi_wait_frame_change_tool_encodes_png_once(monkeypatch, png_encode_counter, wmi_server):
    """RED at base (the decode encodes and the tool encodes again), GREEN after the
    fix. The fake returns a different payload on the second poll so the loop stops
    with `changed` and decodes a frame."""
    w, h = 320, 240
    first = _thumbnail(w, h)
    second = b"\x00\x00\x00\x00" + b"\xff\xff" * (w * h)

    class _ChangingBackend(_FakeBackend):
        def __init__(self):
            super().__init__((w, h), first)
            self.calls = 0

        def capture(self, guid, width, height):
            self.calls += 1
            self.captures.append((width, height))
            return (first if self.calls == 1 else second), {}

    backend = _ChangingBackend()
    mcp = wmi_server(backend).get_mcp()
    png_encode_counter["encodes"] = 0

    result = asyncio.run(mcp.call_tool(
        "hyperv_console_wait_frame_change",
        {"vm_name": "vm1", "width": w, "height": h, "timeout_s": 5, "interval_s": 1},
    ))

    meta = _text_block(result)
    assert meta["changed"] is True, f"expected a changed frame, got {meta.get('stop_reason')}"
    assert len(_image_blocks(result)) == 1
    assert png_encode_counter["encodes"] == 1, (
        f"WMI wait_frame_change: {png_encode_counter['encodes']} PNG encodes for one image"
    )
    # PRR-015: two polls at the requested size, then the changed frame.
    assert backend.captures == [(w, h), (w, h)], (
        f"WMI wait_frame_change requested {backend.captures}, expected two "
        f"{(w, h)} captures"
    )


def test_wmi_screenshot_save_path_bytes_match_returned(
    monkeypatch, png_encode_counter, wmi_server, tmp_path
):
    """The bytes written to save_path are the bytes returned as ImageContent, and
    the whole call costs one encode. RED at base on the encode count."""
    w, h = 320, 240
    backend = _FakeBackend((w, h), _thumbnail(w, h))
    mcp = wmi_server(backend).get_mcp()
    dest = tmp_path / "shots" / "frame.png"
    png_encode_counter["encodes"] = 0

    result = asyncio.run(mcp.call_tool(
        "hyperv_console_screenshot",
        {"vm_name": "vm1", "width": w, "height": h, "save_path": str(dest)},
    ))

    meta = _text_block(result)
    assert meta["saved_path"] == str(dest)
    on_disk = dest.read_bytes()
    images = _image_blocks(result)
    assert len(images) == 1
    assert base64.b64decode(images[0].data) == on_disk, (
        "the bytes returned as ImageContent differ from the bytes written to save_path"
    )
    assert png_encode_counter["encodes"] == 1, (
        f"WMI screenshot with save_path: {png_encode_counter['encodes']} PNG encodes"
    )
