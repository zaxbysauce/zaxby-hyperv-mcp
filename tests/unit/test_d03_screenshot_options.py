"""Frozen acceptance checks for issue #19 (Workstream D, slot D-03): the
screenshot output options (format, quality, scale, crop, if_changed_from)
and the pixel-only frame hash.

Every check here is RED at the pre-fix base and GREEN after the fix. The
base behaviour being pinned: the five options are absent from
hyperv_console_screenshot's inputSchema, so every call that passes one is
rejected by the unknown-argument guard with error_class "invalid" and no
image; console._frame_hash covers the opaque 4-byte prefix; and the
wait_frame_change poll script hashes the whole $r.ImageData.

The checks drive the REGISTERED tool through the real SDK call_tool path
with a stubbed PowerShell transport (the test_image_content.py harness):
the option names, the guard wording and the metadata contract are all read
through the public surface, never from production internals.
"""

import asyncio
import base64
import hashlib
import importlib
import io
import json
import re

import pytest
from PIL import Image, features

import hyperv_mcp.server as server_module
from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
REQUIRED_OPTIONS = {"format", "quality", "scale", "crop", "if_changed_from"}


def _raw_thumbnail(w: int, h: int) -> bytes:
    """Deterministic RGB565 payload: opaque 4-byte prefix + pixels."""
    pixels = bytearray()
    for y in range(h):
        for x in range(w):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            pixels.append(v & 0xFF)
            pixels.append((v >> 8) & 0xFF)
    return b"\x00\x00\x96\x04" + bytes(pixels)


class FakeCapture:
    """Queue-ordered run_ps stand-in (test_image_content model)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return self.responses.pop(0)


def _folded_response(payload: bytes, w: int, h: int) -> pswindows.PSResult:
    """One folded screenshot stdout: metadata lines ahead of the payload JSON."""
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
    """Reloaded, bootstrapped server module; optional config-file document
    (HYPERV_MCP_CONFIG) for tests that need host_write_roots."""
    def make(environ=None, config_doc=None):
        environ = dict(environ or {})
        if config_doc is not None:
            p = tmp_path / "d03-config.json"
            p.write_text(json.dumps(config_doc), encoding="utf-8")
            environ["HYPERV_MCP_CONFIG"] = str(p)
        mod = importlib.reload(server_module)
        mod.bootstrap(environ)
        return mod

    yield make
    importlib.reload(server_module)


def _call_screenshot(mcp, arguments: dict):
    """Registered-tool call -> (image blocks, text blocks)."""
    from conftest import content_blocks as _blocks

    result = asyncio.run(mcp.call_tool("hyperv_console_screenshot", arguments))
    blocks = _blocks(result)
    images = [c for c in blocks if getattr(c, "type", "") == "image"]
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    return images, texts


def _error_note(texts) -> str:
    """The envelope error when the call failed, '' on success/no text."""
    if not texts:
        return "no text block at all"
    try:
        env = json.loads(texts[0].text)
    except ValueError:
        return "unparsable text block"
    return str(env.get("error", "")) if env.get("ok") is False else ""


def _meta(texts) -> dict:
    assert texts, "no metadata text block in the success result"
    return json.loads(texts[0].text)


def _mime(block) -> str:
    return getattr(block, "mimeType", None) or getattr(block, "mime_type", None)


def _decoded(block) -> Image.Image:
    return Image.open(io.BytesIO(base64.b64decode(block.data)))


# ---------------------------------------------------------------------------
# AC1 — the schema declares the five output options
# ---------------------------------------------------------------------------

def test_screenshot_schema_exposes_output_options(fresh_server):
    """AC1: format, quality, scale, crop and if_changed_from are declared in
    hyperv_console_screenshot's inputSchema (missing set == set()). RED at the
    pre-fix base (none are declared), GREEN after the fix."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    tools = asyncio.run(mod.get_mcp().list_tools())
    schema = next(
        (getattr(t, "input_schema", None) or t.inputSchema)
        for t in tools if t.name == "hyperv_console_screenshot"
    )
    declared = set((schema or {}).get("properties", {}))
    missing = REQUIRED_OPTIONS - declared
    assert missing == set(), (
        f"AC1: hyperv_console_screenshot inputSchema lacks output options: "
        f"{sorted(missing)} (declared: {sorted(declared)})"
    )


# ---------------------------------------------------------------------------
# AC2..AC7 — the options shape the returned image
# ---------------------------------------------------------------------------

def test_jpeg_format_returns_jpeg(monkeypatch, fresh_server):
    """AC2: format="jpeg" with quality=70 returns one ImageContent whose
    mimeType is image/jpeg. RED at the pre-fix base (the argument is unknown
    so no image is returned at all), GREEN after the fix."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    images, texts = _call_screenshot(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "format": "jpeg", "quality": 70,
    })
    assert len(images) == 1, (
        f"AC2: expected one image block, got {len(images)} ({_error_note(texts)})"
    )
    assert _mime(images[0]) == "image/jpeg", (
        f"AC2: mimeType {_mime(images[0])!r} != 'image/jpeg'"
    )
    assert _decoded(images[0]).format == "JPEG", (
        "AC2: the returned bytes do not decode as JPEG"
    )


def test_jpg_alias_maps_to_image_jpeg(monkeypatch, fresh_server):
    """AC3: format="jpg" normalises to mimeType image/jpeg — never the
    non-standard image/jpg. RED at the pre-fix base, GREEN after the fix."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    images, texts = _call_screenshot(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": 320, "height": 240, "format": "jpg",
    })
    assert len(images) == 1, (
        f"AC3: expected one image block, got {len(images)} ({_error_note(texts)})"
    )
    mime = _mime(images[0])
    assert mime == "image/jpeg", (
        f"AC3: 'jpg' must normalise to 'image/jpeg', got {mime!r}"
    )


def test_webp_format_returns_webp(monkeypatch, fresh_server):
    """AC4: format="webp" returns mimeType image/webp; and IF this Pillow
    build lacks WebP the tool returns error_class "invalid" rather than
    crashing. RED at the pre-fix base (WebP-capable Pillow: no image is
    returned at all), GREEN after the fix."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    images, texts = _call_screenshot(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": 320, "height": 240, "format": "webp",
    })
    if not features.check("webp"):
        env = json.loads(texts[0].text)
        assert env.get("ok") is False and env.get("error_class") == "invalid", (
            f"AC4: a WebP-less Pillow build must yield invalid, got {env!r}"
        )
        return
    assert len(images) == 1, (
        f"AC4: expected one image block, got {len(images)} ({_error_note(texts)})"
    )
    assert _mime(images[0]) == "image/webp", (
        f"AC4: mimeType {_mime(images[0])!r} != 'image/webp'"
    )


def test_scale_halves_returned_dimensions(monkeypatch, fresh_server):
    """AC5: scale=0.5 on a 320x240 capture returns a 160x120 image. RED at the
    pre-fix base, GREEN after the fix."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    images, texts = _call_screenshot(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": 320, "height": 240, "scale": 0.5,
    })
    assert len(images) == 1, (
        f"AC5: expected one image block, got {len(images)} ({_error_note(texts)})"
    )
    size = _decoded(images[0]).size
    assert size == (160, 120), (
        f"AC5: scale=0.5 on a 320x240 capture returned {size}, expected (160, 120)"
    )


def test_crop_returns_crop_size(monkeypatch, fresh_server):
    """AC6: crop=[10, 20, 110, 70] (left, top, right, bottom in captured-frame
    pixels) returns a 100x50 image. RED at the pre-fix base, GREEN after the
    fix."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    images, texts = _call_screenshot(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "crop": [10, 20, 110, 70],
    })
    assert len(images) == 1, (
        f"AC6: expected one image block, got {len(images)} ({_error_note(texts)})"
    )
    size = _decoded(images[0]).size
    assert size == (100, 50), (
        f"AC6: crop [10, 20, 110, 70] returned {size}, expected (100, 50)"
    )


def test_if_changed_from_matching_hash_returns_no_image(
        monkeypatch, fresh_server, png_encode_counter):
    """AC7: when if_changed_from equals the current capture's frame_hash the
    tool returns no image block and metadata with unchanged true, skipping
    decode and encode. RED at the pre-fix base (if_changed_from is rejected
    by the unknown-argument guard, so unchanged is never reported), GREEN
    after the fix."""
    payload = _raw_thumbnail(320, 240)
    resp = _folded_response(payload, 320, 240)
    monkeypatch.setattr(pswindows, "run_ps", FakeCapture([resp, resp]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()
    images, texts = _call_screenshot(mcp, {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
    })
    assert len(images) == 1, (
        f"AC7: the priming capture must return one image block, got {len(images)} "
        f"({_error_note(texts)})"
    )
    baseline = _meta(texts)["frame_hash"]
    encodes_before = png_encode_counter["encodes"]
    images2, texts2 = _call_screenshot(mcp, {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "if_changed_from": baseline,
    })
    unchanged = None
    if texts2:
        try:
            unchanged = json.loads(texts2[0].text).get("unchanged")
        except ValueError:
            pass
    assert (len(images2), unchanged) == (0, True), (
        f"AC7: expected (0 image blocks, unchanged=True) when if_changed_from "
        f"matches the current frame_hash, got ({len(images2)}, {unchanged})"
    )
    assert png_encode_counter["encodes"] == encodes_before, (
        f"AC7: an unchanged frame must skip the encode; "
        f"{png_encode_counter['encodes'] - encodes_before} encode(s) ran"
    )


# ---------------------------------------------------------------------------
# AC8 — strict validation inside the tool body (re-shaped: a bare
# (0, "invalid") tuple is already true at base because the guard fires, so
# the check also proves the rejection is NOT the guard's)
# ---------------------------------------------------------------------------

def test_unknown_format_is_rejected_as_invalid(monkeypatch, fresh_server):
    """AC8: format="bmp", out-of-range quality/scale and an out-of-frame crop
    each return {ok: false, error_class: "invalid"} from the tool's OWN
    validation — the error must not be the unknown-argument guard's. RED at
    the pre-fix base (the guard fires first), GREEN after the fix."""
    payload = _raw_thumbnail(320, 240)
    cases = [
        ("format=bmp (unsupported)", {"format": "bmp"}),
        ("quality=0", {"quality": 0}),
        ("quality=101", {"quality": 101}),
        ("scale=0", {"scale": 0}),
        ("scale=1.5", {"scale": 1.5}),
        ("crop box outside the frame", {"crop": [0, 0, 9999, 9999]}),
    ]
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()
    for label, extra in cases:
        monkeypatch.setattr(pswindows, "run_ps",
                            FakeCapture([_folded_response(payload, 320, 240)]))
        images, texts = _call_screenshot(mcp, {
            "vm_name": "test-vm-1", "width": 320, "height": 240, **extra,
        })
        assert texts, f"AC8 ({label}): expected a failure envelope text block"
        env = json.loads(texts[0].text)
        assert len(images) == 0, (
            f"AC8 ({label}): an invalid option must return no image block"
        )
        assert env.get("error_class") == "invalid", (
            f"AC8 ({label}): error_class {env.get('error_class')!r} != 'invalid'"
        )
        assert "unknown argument" not in str(env.get("error", "")), (
            f"AC8 ({label}): the rejection must come from the tool's own option "
            f"validation, not the unknown-argument guard: {env.get('error')!r}"
        )


# ---------------------------------------------------------------------------
# AC10 / AC11 — the pixel-only frame hash, host side and poll loop
# ---------------------------------------------------------------------------

def test_frame_hash_ignores_opaque_prefix():
    """AC10: two payloads differing only in their first 4 bytes produce the
    same console._frame_hash (the SHA-256 of the pixel payload after the
    opaque prefix). RED at the pre-fix base (the hash covers the prefix),
    GREEN after the fix."""
    payload = _raw_thumbnail(64, 48)
    twin = b"\xde\xad\xbe\xef" + payload[console._PREFIX_LEN:]
    assert len(twin) == len(payload), "AC10: the twin payload must replace, not insert"
    assert console._frame_hash(payload) == console._frame_hash(twin), (
        "AC10: payloads differing only in the opaque 4-byte prefix must hash equal"
    )
    assert console._frame_hash(payload) == hashlib.sha256(
        payload[console._PREFIX_LEN:]
    ).hexdigest(), (
        "AC10: frame_hash must equal the SHA-256 of the pixel payload after the prefix"
    )


def test_wait_script_hashes_pixels_after_prefix(monkeypatch):
    """AC11: the generated wait_frame_change poll script hashes the pixels
    AFTER the opaque prefix — the literal ComputeHash($r.ImageData, 4, form —
    so the poll-loop hash stays byte-identical to the host-side _frame_hash.
    RED at the pre-fix base (the script hashes the whole $r.ImageData),
    GREEN after the fix.

    The assertion pins the WHOLE expression, not a prefix of it. Review
    PRR-020b: asserting only `ComputeHash($r.ImageData, 4,` let a mutant that
    changed the byte count from `- 4` to `- 5` pass every check in the suite,
    because a wrong count still produces a valid-looking digest. A length
    guard is pinned too, because ComputeHash's error on a short buffer is
    non-terminating and would otherwise be swallowed into a full-timeout
    `changed: false` (review PRR-011)."""
    fake = FakeCapture([
        pswindows.PSResult(stdout="STOP=deadline POLLS=1 HASH=abc", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.wait_frame_change(Config(unrestricted=True), "vm1", width=320, height=240)
    assert fake.scripts, "AC11: wait_frame_change spawned no poll script"
    script = fake.scripts[0]
    assert "ComputeHash($r.ImageData, 4, $r.ImageData.Length - 4)" in script, (
        "AC11: the poll loop must hash the pixels after the 4-byte prefix, "
        "counting exactly the pixels (ComputeHash($r.ImageData, 4, "
        "$r.ImageData.Length - 4)); it currently hashes a different slice or "
        "count, disagreeing with the host-side pixel-only hash"
    )
    assert "$pxLen -ne $pxWant" in script and "throw" in script, (
        "AC11: the poll loop must refuse a payload whose length is not exactly "
        "4 + width*height*2, so a short or truncated buffer surfaces as a "
        "structured error instead of a swallowed non-terminating method error "
        "that polls to the deadline and reports changed: false (review PRR-011)"
    )


# ---------------------------------------------------------------------------
# AC16 / AC17 — save_path fidelity and metadata echo
# ---------------------------------------------------------------------------

def test_save_path_writes_returned_bytes(monkeypatch, fresh_server, tmp_path):
    """AC16: a non-PNG format with save_path writes exactly the bytes that
    are returned, at the requested path, and the metadata reports the format
    written. RED at the pre-fix base (format is unknown, so nothing is
    returned or written), GREEN after the fix."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    dest = tmp_path / "shots" / "frame.jpg"
    mod = fresh_server(config_doc={
        "allowed_vm_patterns": ["test-vm-*"], "unrestricted": True,
        "host_write_roots": [str(tmp_path)],
    })
    images, texts = _call_screenshot(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "format": "jpeg", "quality": 80, "save_path": str(dest),
    })
    assert len(images) == 1, (
        f"AC16: expected one image block, got {len(images)} ({_error_note(texts)})"
    )
    assert _mime(images[0]) == "image/jpeg", (
        f"AC16: mimeType {_mime(images[0])!r} != 'image/jpeg'"
    )
    returned = base64.b64decode(images[0].data)
    assert dest.is_file(), "AC16: save_path did not write the requested path"
    assert dest.read_bytes() == returned, (
        f"AC16: save_path wrote {dest.stat().st_size} bytes but the returned "
        f"image is {len(returned)} bytes; it must write exactly the bytes returned"
    )
    meta = _meta(texts)
    assert "jpeg" in json.dumps(meta).lower(), (
        f"AC16: metadata must report the format written; keys: {sorted(meta)}"
    )


def test_metadata_echoes_returned_dimensions(monkeypatch, fresh_server):
    """AC17: with scale applied the metadata reports the RETURNED dimensions
    (so mouse tools get the right frame_width/frame_height), echoes the
    option, and states that cropped/scaled coordinates are not head-space
    coordinates. RED at the pre-fix base, GREEN after the fix."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    images, texts = _call_screenshot(mod.get_mcp(), {
        "vm_name": "test-vm-1", "width": 320, "height": 240, "scale": 0.5,
    })
    assert len(images) == 1, (
        f"AC17: expected one image block, got {len(images)} ({_error_note(texts)})"
    )
    size = _decoded(images[0]).size
    assert size == (160, 120), (
        f"AC17: scale=0.5 on a 320x240 capture returned {size}, expected (160, 120)"
    )
    meta = _meta(texts)
    reported = (meta.get("width"), meta.get("height"))
    assert reported == size, (
        f"AC17: metadata dimensions {reported} do not echo the returned "
        f"dimensions {size}; mouse tools would be given the wrong frame dims"
    )
    assert meta.get("scale") == 0.5, (
        f"AC17: metadata must echo the applied scale, got {meta.get('scale')!r}"
    )
    assert re.search(r"not.{0,60}head[ \-]?space", json.dumps(meta), re.I), (
        "AC17: metadata must state that cropped or scaled coordinates are not "
        "head-space coordinates"
    )
