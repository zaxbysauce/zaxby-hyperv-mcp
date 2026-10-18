"""Frozen acceptance check for issue #19 AC9: the pixel-only frame hash makes
an unchanged screen produce ONE hash.

The issue's own AC9 asks for 10 live captures of an idle console 2 s apart and
observes that "an unchanged screen must produce one hash regardless". That
property is fully exercisable without a hypervisor: what makes the host hash
unstable on an unchanged screen is the opaque 4-byte prefix, so a synthetic
sequence of 10 captures whose payloads are pixel-identical and differ ONLY in
that prefix is the isolated instance of the same criterion. This check drives
that sequence through the REGISTERED tool with a stubbed transport, prints
each capture's prefix_hex exactly as the live test does, and asserts one
distinct frame_hash across all 10.

The live-host form ships alongside it in
tests/integration/test_d03_frame_prefix_live.py::test_prefix_stability_on_static_screen
and remains the confirmation on real hardware; this file is the check that can
run everywhere.

Every check here is RED at the pre-fix base and GREEN after the fix.
"""

import asyncio
import base64
import importlib
import json

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
W, H = 320, 240
CAPTURES = 10


def _pixels() -> bytes:
    """A deterministic, non-uniform RGB565 pixel block."""
    out = bytearray()
    for y in range(H):
        for x in range(W):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            out.append(v & 0xFF)
            out.append((v >> 8) & 0xFF)
    return bytes(out)


def _thumbnail(prefix: bytes) -> bytes:
    return prefix + _pixels()


class FakeCapture:
    """Queue-ordered run_ps stand-in (the test_image_content model)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return self.responses.pop(0)


def _folded_response(payload: bytes) -> pswindows.PSResult:
    body = json.dumps({
        "returnValue": 0,
        "imageDataB64": base64.b64encode(payload).decode(),
    })
    return pswindows.PSResult(
        stdout="VMID=" + GUID + "\nHEAD=1024x768\nSIZES=" + str(W) + "x" + str(H)
               + "\nUSED=" + str(W) + "x" + str(H) + "\n" + body,
        returncode=0,
    )


@pytest.fixture()
def fresh_server():
    def make(environ=None):
        mod = importlib.reload(server_module)
        mod.bootstrap(dict(environ or {}))
        return mod

    yield make
    importlib.reload(server_module)


def _call(mcp, arguments: dict):
    from conftest import content_blocks as _blocks

    result = asyncio.run(mcp.call_tool("hyperv_console_screenshot", arguments))
    blocks = _blocks(result)
    images = [c for c in blocks if getattr(c, "type", "") == "image"]
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    return images, texts


def test_unchanged_screen_yields_one_frame_hash(monkeypatch, fresh_server):
    """AC9: 10 captures whose payloads differ ONLY in the opaque 4-byte prefix
    return one frame_hash, and each capture's prefix_hex is printed so the
    record shows whether the prefix varied. RED at the pre-fix base (the hash
    covers the prefix, so the 10 hashes differ), GREEN after the fix."""
    # A distinct prefix per capture, identical pixels: exactly the shape of an
    # idle console whose opaque prefix drifts between captures.
    prefixes = [bytes([i, 0x5A, 0xA5, 0x96]) for i in range(CAPTURES)]
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    rows = []
    for i, prefix in enumerate(prefixes):
        # Re-seed the transport per capture so each call serves its own
        # prefix: the queue is consumed in order, and an explicit re-seed
        # makes the pairing visible rather than implied by list order.
        monkeypatch.setattr(
            pswindows, "run_ps", FakeCapture([_folded_response(_thumbnail(prefix))])
        )
        images, texts = _call(mcp, {
            "vm_name": "test-vm-1", "width": W, "height": H,
        })
        assert len(images) == 1, (
            f"AC9: capture {i}: expected one image block, got {len(images)}"
        )
        meta = json.loads(texts[0].text)
        assert meta.get("prefix_hex") == prefix.hex(), (
            f"AC9: capture {i}: expected prefix_hex {prefix.hex()}, "
            f"got {meta.get('prefix_hex')!r} — the stub pairing drifted"
        )
        rows.append((i, str(meta.get("prefix_hex", "")),
                     str(meta.get("frame_hash", ""))))

    print("\nAC9 prefix stability: 10 captures, pixels identical, prefix varied")
    print("idx | prefix_hex  | frame_hash")
    for i, prefix, frame_hash in rows:
        print(f"{i:>3} | {prefix:<11} | {frame_hash}")
    hashes = [h for _, _, h in rows]
    print(f"distinct frame_hash values: {len(set(hashes))}; "
          f"distinct prefix_hex values: {len({p for _, p, _ in rows})}")

    assert len(set(hashes)) == 1, (
        f"AC9: an unchanged screen produced {len(set(hashes))} distinct "
        f"frame_hash values {sorted(set(hashes))}; the hash must cover the "
        f"pixel payload only, not the opaque 4-byte prefix"
    )
