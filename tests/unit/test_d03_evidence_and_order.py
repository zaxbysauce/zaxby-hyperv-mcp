"""Frozen acceptance checks for issue #19, second pack: the properties the
first pack left unpinned.

Three gaps, each found by the independent implementation review:

1. Crop-then-scale ORDER. C5 pins scale alone and C6 pins crop alone, so an
   implementation that scales first and crops second satisfies both while
   producing a different image. AC21 pins the order with a combined call whose
   two possible answers differ.
2. The `hyperv_capture_evidence` response path. Both registrations gain the
   five options and deliver through `_image_meta_content`, but no check drove
   `capture_evidence` with an option — so an implementation that declares the
   parameters and then crashes on a shaped or unchanged result would leave
   every first-pack check green. AC22 and AC23 pin both branches.
3. `if_changed_from` validation. The issue requires it be validated like
   `baseline_hash` (empty or 64 lowercase hex); no check exercised a malformed
   value. AC24 pins the rejection.

Every check here is RED at the pre-fix base and GREEN after the fix.
"""

import asyncio
import base64
import importlib
import io
import json

import pytest
from PIL import Image

import hyperv_mcp.server as server_module
from hyperv_mcp import console, pswindows

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
W, H = 320, 240


def _raw_thumbnail(w: int, h: int) -> bytes:
    pixels = bytearray()
    for y in range(h):
        for x in range(w):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            pixels.append(v & 0xFF)
            pixels.append((v >> 8) & 0xFF)
    return b"\x00\x00\x96\x04" + bytes(pixels)


class FakeCapture:
    """Queue-ordered run_ps stand-in (the test_image_content model)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return self.responses.pop(0)


def _folded_response(payload: bytes, w: int, h: int) -> pswindows.PSResult:
    body = json.dumps({
        "returnValue": 0,
        "imageDataB64": base64.b64encode(payload).decode(),
    })
    return pswindows.PSResult(
        stdout="VMID=" + GUID + "\nHEAD=1024x768\nSIZES=" + str(w) + "x" + str(h)
               + "\nUSED=" + str(w) + "x" + str(h) + "\n" + body,
        returncode=0,
    )


@pytest.fixture()
def fresh_server(tmp_path):
    def make(environ=None, config_doc=None):
        environ = dict(environ or {})
        if config_doc is not None:
            p = tmp_path / "d03b-config.json"
            p.write_text(json.dumps(config_doc), encoding="utf-8")
            environ["HYPERV_MCP_CONFIG"] = str(p)
        mod = importlib.reload(server_module)
        mod.bootstrap(environ)
        return mod

    yield make
    importlib.reload(server_module)


def _blocks(result):
    from conftest import content_blocks as _cb

    content = _cb(result)
    images = [c for c in content if getattr(c, "type", "") == "image"]
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    return images, texts


def _call(mcp, arguments: dict):
    return _blocks(asyncio.run(mcp.call_tool("hyperv_console_screenshot", arguments)))


class RoutingCapture:
    """run_ps stand-in that routes by script SHAPE, never by position.

    The capture leg emits a JSON payload (`ConvertTo-Json`); the resolver leg
    does not. Routing on shape rather than queue order means any number of
    resolver spawns — capture_evidence resolves once, and console.screenshot
    resolves again by id — cannot silently misalign the responses.
    """

    def __init__(self, payload):
        self.payload = payload
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "ConvertTo-Json" in script:
            return _folded_response(self.payload, W, H)
        return pswindows.PSResult(stdout=GUID, returncode=0)


def _call_evidence(mcp, arguments: dict):
    return _blocks(asyncio.run(mcp.call_tool("hyperv_capture_evidence", arguments)))


def _mime(block) -> str:
    return getattr(block, "mimeType", None) or getattr(block, "mime_type", None)


def _decoded(block) -> Image.Image:
    return Image.open(io.BytesIO(base64.b64decode(block.data)))


def _meta(texts) -> dict:
    assert texts, "no metadata text block in the result"
    return json.loads(texts[0].text)


def _note(texts) -> str:
    if not texts:
        return "no text block at all"
    try:
        env = json.loads(texts[0].text)
    except ValueError:
        return "unparsable text block"
    return str(env.get("error", "")) if env.get("ok") is False else ""


# ---------------------------------------------------------------------------
# AC21 — crop runs BEFORE scale
# ---------------------------------------------------------------------------

def test_crop_applies_before_scale(monkeypatch, fresh_server):
    """AC21: with crop=[40, 40, 280, 200] (a 240x160 region) and scale=0.5, the
    returned image is 120x80 — the crop's dimensions halved. Scaling first and
    cropping second would yield 120x80 from a different region, so the two
    orders are distinguished by the CONTENT, not just the size. RED at the
    pre-fix base (both arguments are unknown), GREEN after the fix."""
    payload = _raw_thumbnail(W, H)
    monkeypatch.setattr(
        pswindows, "run_ps", FakeCapture([_folded_response(payload, W, H)])
    )
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    images, texts = _call(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": W, "height": H,
        "crop": [40, 40, 280, 200], "scale": 0.5,
    })
    assert len(images) == 1, (
        f"AC21: expected one image block, got {len(images)} ({_note(texts)})"
    )
    size = _decoded(images[0]).size
    assert size == (120, 80), (
        f"AC21: crop [40,40,280,200] then scale 0.5 returned {size}, expected (120, 80)"
    )
    # An independent reimplementation of the required order: crop the UNSHAPED
    # decode, then downscale with BOX. Scaling first and cropping second yields
    # a different raster, so this comparison distinguishes the two orders.
    original = console._decode_rgb565_image(payload, W, H)
    expected = original.crop((40, 40, 280, 200)).resize(
        (120, 80), Image.Resampling.BOX
    )
    got = _decoded(images[0])
    assert got.tobytes() == expected.tobytes(), (
        "AC21: the returned raster is not crop-then-scale of the captured "
        "frame; crop must run before scale"
    )


# ---------------------------------------------------------------------------
# AC22 / AC23 — capture_evidence honours the options and the None frame
# ---------------------------------------------------------------------------

def test_capture_evidence_returns_shaped_image(monkeypatch, fresh_server):
    """AC22: hyperv_capture_evidence with format=jpeg returns one ImageContent
    with mimeType image/jpeg — the shared delivery helper is format-aware, so a
    shaped frame is not forced back through .png. RED at the pre-fix base
    (format is unknown), GREEN after the fix."""
    payload = _raw_thumbnail(W, H)
    monkeypatch.setattr(
        pswindows, "run_ps", RoutingCapture(payload)
    )
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    images, texts = _call_evidence(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": W, "height": H,
        "format": "jpeg", "quality": 80,
    })
    assert len(images) == 1, (
        f"AC22: expected one image block, got {len(images)} ({_note(texts)})"
    )
    assert _mime(images[0]) == "image/jpeg", (
        f"AC22: capture_evidence must deliver the frame's own encoding, got "
        f"{_mime(images[0])!r}"
    )
    assert _decoded(images[0]).format == "JPEG", (
        "AC22: the returned bytes do not decode as JPEG"
    )


def test_capture_evidence_unchanged_returns_metadata_only(monkeypatch, fresh_server):
    """AC23: hyperv_capture_evidence with if_changed_from matching the current
    capture returns NO image block and metadata with unchanged true — the
    shared delivery helper is None-aware. RED at the pre-fix base
    (if_changed_from is unknown), GREEN after the fix."""
    payload = _raw_thumbnail(W, H)
    # Two captures, each preceded by its own resolver spawn.
    monkeypatch.setattr(
        pswindows, "run_ps", RoutingCapture(payload)
    )
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()
    images, texts = _call_evidence(mcp, {
        "vm_name": "test-vm-1", "width": W, "height": H,
    })
    assert len(images) == 1, (
        f"AC23: the priming capture must return one image block, got {len(images)}"
    )
    baseline = _meta(texts)["frame_hash"]
    images2, texts2 = _call_evidence(mcp, {
        "vm_name": "test-vm-1", "width": W, "height": H,
        "if_changed_from": baseline,
    })
    unchanged = _meta(texts2).get("unchanged") if texts2 else None
    assert (len(images2), unchanged) == (0, True), (
        f"AC23: expected (0 image blocks, unchanged=True) from capture_evidence "
        f"when if_changed_from matches, got ({len(images2)}, {unchanged})"
    )
    # the issue's stated response shape for a match
    meta = _meta(texts2)
    for key in ("frame_hash", "vm_id", "width", "height", "captured_at"):
        assert key in meta, f"AC23: unchanged metadata is missing {key!r}: {sorted(meta)}"


# ---------------------------------------------------------------------------
# AC24 — if_changed_from is validated like baseline_hash
# ---------------------------------------------------------------------------

def test_malformed_if_changed_from_is_rejected(monkeypatch, fresh_server):
    """AC24: a malformed if_changed_from (not empty, not 64 lowercase hex) is
    rejected as error_class invalid, exactly like baseline_hash. RED at the
    pre-fix base (the argument is unknown), GREEN after the fix."""
    payload = _raw_thumbnail(W, H)
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()
    for label, bad in [
        ("too short", "abc123"),
        ("uppercase hex", "A" * 64),
        ("non-hex", "z" * 64),
        ("65 chars", "0" * 65),
    ]:
        monkeypatch.setattr(
            pswindows, "run_ps", FakeCapture([_folded_response(payload, W, H)])
        )
        images, texts = _call(mcp, {
            "vm_name": "test-vm-1", "width": W, "height": H,
            "if_changed_from": bad,
        })
        assert texts, f"AC24 ({label}): expected a failure envelope text block"
        env = json.loads(texts[0].text)
        assert len(images) == 0, (
            f"AC24 ({label}): a malformed if_changed_from must return no image block"
        )
        assert env.get("error_class") == "invalid", (
            f"AC24 ({label}): error_class {env.get('error_class')!r} != 'invalid'"
        )
        assert "unknown argument" not in str(env.get("error", "")), (
            f"AC24 ({label}): the rejection must come from the tool's own "
            f"validation, not the unknown-argument guard"
        )
