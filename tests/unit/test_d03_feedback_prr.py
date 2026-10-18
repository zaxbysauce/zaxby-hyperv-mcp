"""swarm-pr-feedback checks for PR #87 (issue #19, workstream D-03).

These are the checks that close the review findings the frozen D-03 pack left
open. Each one names the PRR finding it kills and states the mutant it is
designed to die on — the frozen pack's checks were shown, by execution, to
survive mutants that change real behaviour (review PRR-020), so a check that
does not say which mutation kills it is not yet evidence.

Every check drives the REGISTERED tool through `mcp.call_tool` with a stubbed
transport, or calls a console-layer function whose contract is the finding's
subject. Nothing here reads a private symbol to build its expectation.
"""

import asyncio
import base64
import builtins
import copy
import importlib
import json
import pickle

import pytest
from PIL import Image

import hyperv_mcp.server as server_module
from hyperv_mcp import console, evidence, pswindows, vmident, wmiconsole
from hyperv_mcp.config import Config

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


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
            p = tmp_path / "feedback-config.json"
            p.write_text(json.dumps(config_doc), encoding="utf-8")
            environ["HYPERV_MCP_CONFIG"] = str(p)
        mod = importlib.reload(server_module)
        mod.bootstrap(environ)
        return mod

    yield make
    importlib.reload(server_module)


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


def _blocks(result):
    from conftest import content_blocks

    return content_blocks(result)


def _split(result):
    blocks = _blocks(result)
    images = [c for c in blocks if getattr(c, "type", "") == "image"]
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    return images, texts


def _meta(texts) -> dict:
    assert texts, "no metadata text block in the success result"
    return json.loads(texts[0].text)


def _base_meta() -> dict:
    """A screenshot metadata block in the shape console.screenshot returns."""
    return {
        "vm_name": "test-vm-1",
        "vm_id": "e953c649-abcd",
        "width": 320, "height": 240,
        "frame_hash": "f" * 64,
        "captured_at": "2026-10-18T12:00:00.000+00:00",
        "capture_method": "GetVirtualSystemThumbnailImage",
        "scale_note": "mouse tools accept frame_width/frame_height",
    }


def _call(mcp, tool, arguments):
    return asyncio.run(mcp.call_tool(tool, arguments))


# ---------------------------------------------------------------------------
# PRR-005 — saved_format on the default save_path path
# ---------------------------------------------------------------------------

def test_default_save_path_adds_no_key_the_base_did_not_emit(
    monkeypatch, fresh_server, tmp_path
):
    """PRR-005: issue #19's first constraint is "no option means a full-frame
    PNG with identical bytes and metadata keys". A default call that only adds
    `save_path` must not gain `saved_format`, and a call that names a format
    must. The mutant this kills: emitting `saved_format` unconditionally inside
    `if save_path:`."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)] * 2))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    default_dest = tmp_path / "default.png"
    images, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "save_path": str(default_dest),
    }))
    assert len(images) == 1, "the default save_path call must still return an image"
    default_meta = _meta(texts)
    assert "saved_path" in default_meta, "the default save must report its path"
    assert "saved_format" not in default_meta, (
        "PRR-005: a default (no-format) save_path call emitted "
        f"{sorted(k for k in default_meta if k.startswith('saved'))}; "
        "'saved_format' is a key the base never produced, so the "
        "'identical metadata keys' constraint is violated"
    )
    assert default_dest.read_bytes(), "the default save must still write the file"

    jpeg_dest = tmp_path / "asked.jpg"
    images, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "save_path": str(jpeg_dest), "format": "jpeg",
    }))
    assert len(images) == 1, "the jpeg save_path call must still return an image"
    jpeg_meta = _meta(texts)
    assert jpeg_meta.get("saved_format") == "image/jpeg", (
        "PRR-005: a caller-supplied format must be reported in saved_format, "
        f"got {jpeg_meta.get('saved_format')!r}"
    )
    assert jpeg_dest.read_bytes(), "the jpeg save must write the file"


# ---------------------------------------------------------------------------
# PRR-010 — scale_note for a no-op scale, and the head-resolution hint
# ---------------------------------------------------------------------------

def test_scale_one_is_a_no_op_and_keeps_the_head_resolution_hint(
    monkeypatch, fresh_server
):
    """PRR-010: `scale=1.0` resizes nothing, so the response must be
    byte-identical to the default and `scale_note` must stay the transport's
    head-resolution hint rather than claiming the coordinates moved. The mutant
    this kills: emitting the crop/scale warning whenever `scale` is supplied."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)] * 2))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    _, plain_texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
    }))
    plain = _meta(plain_texts)
    images, scaled_texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240, "scale": 1.0,
    }))
    scaled = _meta(scaled_texts)

    assert "scale_note" in scaled, "scale_note must survive on every path"
    assert "NOT head-space" not in scaled["scale_note"] and (
        "NOT head-space" not in plain["scale_note"]
    ), "PRR-010: scale=1.0 is a no-op, so the note must not claim the coordinates moved"
    assert scaled["scale_note"] == plain["scale_note"], (
        "PRR-010: scale=1.0 must leave scale_note as the transport's "
        "head-resolution hint, not replace it with the crop/scale warning"
    )
    assert (scaled["width"], scaled["height"]) == (320, 240), (
        "PRR-010: scale=1.0 must not change the output dimensions"
    )
    # The echo key is present (the option was supplied) but is not a shaping
    # request, so it does not trigger the warning.
    assert scaled.get("scale") == 1.0, "the supplied scale must still be echoed"


def test_cropped_frame_note_says_the_coordinates_have_no_head_equivalent(
    monkeypatch, fresh_server
):
    """PRR-010: `_scale_to_head` has no crop-offset term and the mouse tools
    take no offset parameter, so telling a caller to pass frame_width/
    frame_height for a cropped frame sends them to a wrong head coordinate with
    an `ok: true` result. The note must say the mapping does not exist. The
    mutant this kills: the generic 'pass frame_width/frame_height' advice."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    images, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "crop": [10, 20, 110, 70],
    }))
    meta = _meta(texts)
    assert len(images) == 1, "the cropped call must still return an image"
    note = meta["scale_note"]
    assert "CROPPED" in note, f"PRR-010: the note must name the crop, got {note!r}"
    assert "head-space" in note and "NO head-space equivalent" in note, (
        f"PRR-010: the note must say a cropped frame's coordinates have no "
        f"head-space equivalent, got {note!r}"
    )
    assert "mouse_move/click" in note, (
        f"PRR-010: the note must name the tools the coordinates must not be "
        f"passed to, got {note!r}"
    )
    assert meta.get("crop") == [10, 20, 110, 70], "the crop box must be echoed"


# ---------------------------------------------------------------------------
# PRR-012 — the unchanged path drops the option echoes and mislabels dims
# ---------------------------------------------------------------------------

def test_unchanged_path_echoes_the_options_and_labels_its_dimensions(
    monkeypatch, fresh_server
):
    """PRR-012: the `unchanged: true` short-circuit used to return a metadata
    block with no option echoes, and its `width`/`height` meant the CAPTURED
    size while the changed path's meant the OUTPUT size. The echoes must appear
    on both paths and the unchanged dimensions must be labelled. The mutant this
    kills: returning before the echo keys are set."""
    payload = _raw_thumbnail(320, 240)
    resp = _folded_response(payload, 320, 240)
    monkeypatch.setattr(pswindows, "run_ps", FakeCapture([resp, resp]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    _, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
    }))
    baseline = _meta(texts)["frame_hash"]

    images, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "if_changed_from": baseline, "format": "jpeg", "quality": 40,
        "scale": 0.5, "crop": [0, 0, 160, 120],
    }))
    unchanged = _meta(texts)
    assert images == [], "an unchanged frame must return no image block"
    assert unchanged.get("unchanged") is True, "the match must be reported"
    for key, expected in (("format", "image/jpeg"), ("quality", 40),
                          ("scale", 0.5), ("crop", [0, 0, 160, 120])):
        assert unchanged.get(key) == expected, (
            f"PRR-012: the unchanged path dropped the {key!r} echo; an "
            f"unchanged result must be as informative about the request as a "
            f"changed one, expected {expected!r}, got {unchanged.get(key)!r}"
        )
    assert (unchanged["width"], unchanged["height"]) == (320, 240), (
        "PRR-012: on the unchanged path width/height are the CAPTURED size, "
        f"because no output image exists; got "
        f"({unchanged['width']}, {unchanged['height']})"
    )


def test_default_unchanged_path_has_the_same_key_set_as_the_default_changed_path(
    monkeypatch, fresh_server
):
    """PRR-005/PRR-012 together: with no options supplied, the changed and the
    unchanged metadata must carry the SAME key set, so a polling client can read
    one shape. The mutant this kills: adding an option-echo key unconditionally
    (the changed path gains it, the unchanged path does not, or vice versa)."""
    payload = _raw_thumbnail(320, 240)
    resp = _folded_response(payload, 320, 240)
    monkeypatch.setattr(pswindows, "run_ps", FakeCapture([resp, resp]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    _, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
    }))
    changed_keys = set(_meta(texts))
    baseline = _meta(texts)["frame_hash"]

    _, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "if_changed_from": baseline,
    }))
    unchanged_keys = set(_meta(texts))

    assert unchanged_keys - {"unchanged"} == changed_keys, (
        "PRR-005/PRR-012: apart from the `unchanged` marker issue #19's own "
        "match shape mandates, the default-path metadata key set must be "
        f"identical on both paths. changed-only: "
        f"{sorted(changed_keys - unchanged_keys)}; unchanged-only: "
        f"{sorted(unchanged_keys - changed_keys - {'unchanged'})}"
    )


# ---------------------------------------------------------------------------
# PRR-002 — the unchanged path's save_path policy verdict
# ---------------------------------------------------------------------------

def test_unchanged_path_applies_the_save_path_policy(
    monkeypatch, fresh_server, tmp_path
):
    """PRR-002: the short-circuit used to skip `check_host_write`, so the same
    call was allowed or denied purely on whether the frame had changed. The
    policy verdict must be identical on both paths. The mutant this kills:
    returning from the short-circuit before the policy check runs.

    The assertion names the ERROR, not merely `ok: false`: a check that accepts
    any failure envelope passes vacuously the moment its stub runs dry, which
    is the test-theater class this PR exists to close."""
    payload = _raw_thumbnail(320, 240)
    resp = _folded_response(payload, 320, 240)
    # One response per tool call: the priming capture, the changed denial and
    # the unchanged denial each drive exactly one spawn.
    monkeypatch.setattr(pswindows, "run_ps", FakeCapture([resp] * 3))
    outside = tmp_path / "outside-roots.png"
    mod = fresh_server(config_doc={
        "allowed_vm_patterns": ["test-vm-*"],
        "host_write_roots": [str(tmp_path / "allowed")],
    })
    mcp = mod.get_mcp()

    _, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
    }))
    baseline = _meta(texts)["frame_hash"]

    # A CHANGED frame with an out-of-roots save_path is denied.
    _, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "save_path": str(outside),
    }))
    changed = _meta(texts)
    assert changed.get("ok") is False, (
        f"the changed frame must be denied for an out-of-roots save_path, got {changed}"
    )
    assert "host_write_roots" in str(changed.get("error", "")), (
        f"the changed frame must be denied by the host-write POLICY, got {changed}"
    )

    # An UNCHANGED frame with the same out-of-roots save_path must be denied
    # too, by the same policy — not waved through because nothing was written.
    images, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "save_path": str(outside), "if_changed_from": baseline,
    }))
    unchanged = _meta(texts)
    assert images == [], "a denied call must not return an image block"
    assert unchanged.get("ok") is False, (
        "PRR-002: the unchanged path must apply the same save_path policy as "
        f"the changed path; got an allowed result {unchanged}"
    )
    assert "host_write_roots" in str(unchanged.get("error", "")), (
        f"PRR-002: the unchanged path must be denied by the host-write POLICY "
        f"specifically, not by any incidental failure; got {unchanged}"
    )


def test_unchanged_path_reports_that_no_file_was_written(
    monkeypatch, fresh_server, tmp_path
):
    """PRR-002's client-facing half: an unchanged frame skips the write, and a
    polling loop that reuses one path must be able to tell that the file on
    disk is not this call's artifact. The mutant this kills: omitting the
    disclosure key."""
    payload = _raw_thumbnail(320, 240)
    resp = _folded_response(payload, 320, 240)
    monkeypatch.setattr(pswindows, "run_ps", FakeCapture([resp, resp]))
    dest = tmp_path / "shots" / "frame.png"
    mod = fresh_server(config_doc={
        "allowed_vm_patterns": ["test-vm-*"],
        "host_write_roots": [str(tmp_path / "shots")],
    })
    mcp = mod.get_mcp()

    _, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "save_path": str(dest),
    }))
    assert dest.exists(), "the priming (changed) capture must write the file"
    baseline = _meta(texts)["frame_hash"]

    _, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "save_path": str(dest), "if_changed_from": baseline,
    }))
    unchanged = _meta(texts)
    assert unchanged.get("unchanged") is True, "the frame must be unchanged"
    assert "save_path_skipped" in unchanged, (
        f"PRR-002: an unchanged save_path call must disclose that no file was "
        f"written this call; keys present: {sorted(unchanged)}"
    )
    assert "saved_path" not in unchanged, (
        "PRR-002: an unchanged call must not claim it wrote a file"
    )


# ---------------------------------------------------------------------------
# PRR-003 — fail-fast on the frame-independent options
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_options", [
    {"fmt": "bmp"},
    {"quality": 150},
    {"quality": 0},
    {"scale": 1.5},
    {"scale": 0},
    {"if_changed_from": "not-a-hash"},
])
def test_bad_frame_independent_options_cost_no_capture(monkeypatch, unrestricted, bad_options):
    """PRR-003: a bad format, quality, scale or baseline is a deterministic
    caller error, so it must be refused BEFORE a PowerShell spawn takes a
    `max_host_powershell` slot (or the WMI chain runs). Only `crop` genuinely
    needs the captured dimensions. The mutant this kills: validating the
    options inside `_finish_screenshot`, after the capture."""
    fake = FakeCapture([_folded_response(_raw_thumbnail(320, 240), 320, 240)])
    monkeypatch.setattr(pswindows, "run_ps", fake)

    with pytest.raises(ValueError):
        console.screenshot(unrestricted, "test-vm-1", 320, 240, "", **bad_options)

    assert fake.scripts == [], (
        f"PRR-003: {bad_options} must be refused before the capture; "
        f"{len(fake.scripts)} script(s) were spawned"
    )


def test_out_of_frame_crop_is_still_refused(monkeypatch, unrestricted):
    """The other half of PRR-003: `crop` is validated against the ACTUAL
    captured dimensions, so it cannot fail fast — but it must still be refused,
    and the capture that ran is the price of the fallback chain, not of a
    skipped check."""
    fake = FakeCapture([_folded_response(_raw_thumbnail(320, 240), 320, 240)])
    monkeypatch.setattr(pswindows, "run_ps", fake)

    with pytest.raises(ValueError):
        console.screenshot(unrestricted, "test-vm-1", 320, 240, "",
                           crop=[0, 0, 9999, 9999])

    assert len(fake.scripts) == 1, (
        "the crop check needs the captured dimensions, so exactly one capture "
        f"is expected; got {len(fake.scripts)}"
    )


# ---------------------------------------------------------------------------
# PRR-009 — a format that normalises away is not a default
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("degenerate", ["image/", "  ", "image/ "])
def test_a_format_that_normalises_away_is_refused_not_defaulted(
    monkeypatch, unrestricted, degenerate
):
    """PRR-009: `"image/"` and `"  "` normalise to the empty string, which used
    to fall through to the PNG default while the response echoed
    `format: "image/png"` — an explicit-looking confirmation for a value the
    caller never asked for. The mutant this kills: keying the default on the
    NORMALISED value instead of on whether the caller supplied one."""
    fake = FakeCapture([_folded_response(_raw_thumbnail(320, 240), 320, 240)])
    monkeypatch.setattr(pswindows, "run_ps", fake)

    with pytest.raises(ValueError, match="unsupported format"):
        console.screenshot(unrestricted, "test-vm-1", 320, 240, "", fmt=degenerate)

    assert fake.scripts == [], "a degenerate format must cost no capture"


def test_no_format_means_png_with_no_format_echo(monkeypatch, unrestricted):
    """The other half of PRR-009: a caller who supplied NO format gets the PNG
    default and no `format` key, so the key's presence stays the discriminator
    issue #19's constraint depends on."""
    payload = _raw_thumbnail(320, 240)
    fake = FakeCapture([_folded_response(payload, 320, 240)])
    monkeypatch.setattr(pswindows, "run_ps", fake)

    frame, meta = console.screenshot(unrestricted, "test-vm-1", 320, 240)

    assert frame is not None and frame.mime == "image/png"
    assert "format" not in meta, (
        f"PRR-009: no format was supplied, so no `format` key may be echoed; "
        f"got {meta.get('format')!r}"
    )


# ---------------------------------------------------------------------------
# PRR-014 — copy / deepcopy / pickle keep the encoding and the quality
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mime,quality", [
    ("image/png", None),
    ("image/jpeg", 30),
    ("image/webp", 30),
])
def test_copy_and_pickle_reuse_the_encoding_bytes(mime, quality):
    """PRR-014: `__copy__`/`__reduce__` used to decode and re-encode, so every
    copy, deepcopy or pickle of a lossy frame was a generational re-encode and
    `quality` was lost from the rebuild tuple (a quality-95 JPEG frame copied to
    Pillow's default-75 bytes). The mutant this kills: routing `__copy__`
    through `_rebuild_frame`/`from_image`, or omitting `_quality` from the
    rebuild tuple."""
    if mime == "image/webp" and not console._PILFeatures.check("webp"):
        pytest.skip("this Pillow build has no WebP support")
    img = Image.new("RGB", (64, 48), (10, 120, 240))
    for x in range(64):
        for y in range(48):
            img.putpixel((x, y), (x * 3 % 256, y * 5 % 256, 128))
    frame = console.Frame.from_image(img, mime, quality)

    for label, dup in (("copy.copy", copy.copy(frame)),
                       ("copy.deepcopy", copy.deepcopy(frame)),
                       ("pickle round-trip", pickle.loads(pickle.dumps(frame)))):
        assert isinstance(dup, console.Frame), (
            f"PRR-014: {label} must return a console.Frame, got {type(dup).__name__}"
        )
        assert dup.encoded == frame.encoded, (
            f"PRR-014: {label} must reuse the frame's single encoding bytes, "
            f"not spend a second encode; {len(dup.encoded)} vs {len(frame.encoded)} bytes"
        )
        assert dup.mime == frame.mime, f"PRR-014: {label} lost the mime"
        assert dup._quality == frame._quality, (
            f"PRR-014: {label} lost the quality ({dup._quality!r} vs "
            f"{frame._quality!r})"
        )
        assert dup.size == frame.size, f"PRR-014: {label} lost the dimensions"


def test_copying_a_frame_does_not_alias_its_raster():
    """The copy must be independent: mutating the copy's pixels must not change
    the original's. The mutant this kills: a `__copy__` that shares `im`."""
    img = Image.new("RGB", (32, 32), (200, 30, 30))
    frame = console.Frame.from_image(img, "image/png")
    dup = copy.copy(frame)
    dup.putpixel((0, 0), (1, 2, 3))
    assert frame.getpixel((0, 0)) == (200, 30, 30), (
        "PRR-014: a copied frame must not alias the original's raster"
    )


def test_frame_png_is_refused_for_a_non_png_frame():
    """PRR-013: `Frame.png` raises for a jpeg/webp frame. It is a public
    exported type, so the refusal must be explicit and instructive, and
    `encoded` must still carry the bytes. The mutant this kills: a `.png` that
    silently returns empty or wrong-format bytes."""
    img = Image.new("RGB", (16, 16), (5, 5, 5))
    frame = console.Frame.from_image(img, "image/jpeg", 50)
    with pytest.raises(AttributeError, match="Frame.encoded"):
        frame.png  # noqa: B018 — the property access IS the check
    assert frame.encoded[:2] == b"\xff\xd8", "the jpeg encoding must survive"
    assert frame.pil_format == "JPEG", "pil_format must name the save format"
    assert frame.mime == "image/jpeg"


def test_frame_pil_format_refuses_an_out_of_table_mime():
    """PRR-025: an out-of-table `Frame.mime` used to raise a bare `KeyError`
    inside the server layer, which `errors.classify` reports as
    `error_class: "transport"` — a host problem — masking a code-level defect.
    The public accessor must raise `invalid` instead."""
    img = Image.new("RGB", (16, 16), (5, 5, 5))
    frame = console.Frame.from_image(img, "image/png")
    frame._mime = "image/tiff"
    with pytest.raises(ValueError, match="no Pillow save format"):
        frame.pil_format  # noqa: B018


# ---------------------------------------------------------------------------
# PRR-001 — changed_bytes_vs_previous shares frame_hash's domain
# ---------------------------------------------------------------------------

def test_changed_pixel_bytes_ignores_the_opaque_prefix():
    """PRR-001: `capture_sequence`'s `changed_bytes_vs_previous` zipped the FULL
    payload while `frame_hash` in the same entry hashes `raw[4:]`, so on exactly
    the prefix-drift input this PR exists to fix, one entry reported an
    identical hash AND a nonzero byte count. The mutant this kills: diffing the
    whole payload."""
    prefix_a = b"\x00\x00\x96\x04"
    prefix_b = b"\xde\xad\xbe\xef"  # the same pixels, a drifted prefix
    pixels = bytes(range(256)) * 4

    a, b = prefix_a + pixels, prefix_b + pixels
    assert console._frame_hash(a) == console._frame_hash(b), (
        "the two payloads must hash equal (identical pixels, drifted prefix)"
    )
    assert console._changed_pixel_bytes(a, b) == 0, (
        "PRR-001: identical pixels must report zero changed bytes even when "
        "the opaque prefix drifted, so the two change signals in one frames[] "
        "entry cannot contradict each other"
    )

    drifted = prefix_a + bytes([pixels[0] ^ 0xFF]) + pixels[1:]
    assert console._changed_pixel_bytes(a, drifted) == 1, (
        "PRR-001: a real pixel change must still be counted"
    )
    assert console._changed_pixel_bytes(None, a) == 0, (
        "the first frame has no predecessor, so it reports zero"
    )


def test_capture_sequence_frames_agree_with_their_hashes(
    monkeypatch, unrestricted
):
    """PRR-001, end to end through the tool: a prefix that drifts between
    frames must not produce a nonzero `changed_bytes_vs_previous` beside an
    unchanged `frame_hash`."""
    base = _raw_thumbnail(320, 240)
    drifted_prefix = b"\x01\x02\x03\x04" + base[4:]
    responses = [
        pswindows.PSResult(
            stdout="STOP=deadline POLLS=1 HASH=abc\n"
                   + json.dumps({"returnValue": 0,
                                 "imageDataB64": base64.b64encode(p).decode()}),
            returncode=0,
        )
        for p in (base, drifted_prefix, base)
    ]
    monkeypatch.setattr(pswindows, "run_ps", FakeCapture(responses))

    out = console.capture_sequence(unrestricted, "test-vm-1", count=3,
                                   interval_s=1, width=320, height=240)

    frames = out["frames"]
    assert len(frames) == 3
    hashes = [f["frame_hash"] for f in frames]
    assert hashes[0] == hashes[1] == hashes[2], (
        "all three frames have identical pixels, so all three hashes must match"
    )
    assert [f["changed_bytes_vs_previous"] for f in frames] == [0, 0, 0], (
        "PRR-001: the prefix drifted between frames 0 and 1, but the pixels did "
        "not change, so changed_bytes_vs_previous must stay 0 — "
        f"{[f['changed_bytes_vs_previous'] for f in frames]}"
    )


# ---------------------------------------------------------------------------
# PRR-015 — a machine-readable hash domain
# ---------------------------------------------------------------------------

def test_wait_frame_change_reports_its_hash_domain(monkeypatch, unrestricted):
    """PRR-015: both hash domains are 64 lowercase hex characters, so a
    pre-0.4.0 `baseline_hash` passes validation and produces a fabricated
    `changed: true` at poll 1. The tool must name its domain so a client can
    refuse a baseline recorded in the other one. The mutant this kills:
    dropping the `hash_domain` key."""
    monkeypatch.setattr(
        pswindows, "run_ps",
        FakeCapture([pswindows.PSResult(
            stdout="STOP=deadline POLLS=1 HASH=" + "a" * 64, returncode=0)]),
    )
    out = console.wait_frame_change(unrestricted, "test-vm-1", width=320, height=240)
    assert out.get("hash_domain") == console.HASH_DOMAIN, (
        f"PRR-015: wait_frame_change must report its hash domain, got "
        f"{out.get('hash_domain')!r}"
    )


def test_wait_frame_change_wmi_reports_the_same_hash_domain(monkeypatch, unrestricted):
    """PRR-015 on the in-process WMI leg: the two transports must not drift on
    the marker."""
    from hyperv_mcp import vmident as _vmident

    class _Backend:
        def capture(self, guid, width, height):
            return _raw_thumbnail(width, height), {}

    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", True)
    monkeypatch.setattr(wmiconsole, "backend", lambda cfg: _Backend())
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})
    ref = _vmident.VMRef(id=GUID, name="test-vm-1")

    out = console._wait_frame_change_wmi(
        _Backend(), 0.0, ref, "", 320, 240, timeout_s=1, interval_s=1
    )
    assert out.get("hash_domain") == console.HASH_DOMAIN, (
        "PRR-015: the WMI leg must report the same hash domain as the "
        f"PowerShell leg, got {out.get('hash_domain')!r}"
    )


# ---------------------------------------------------------------------------
# PRR-004 — the in-process WMI leg's option coverage
# ---------------------------------------------------------------------------

class _OptionBackend:
    """A WMI backend that records what the capture leg asked it for."""

    def __init__(self, payload: bytes):
        self.payload = payload
        self.captures: list[tuple[int, int]] = []

    def resolve_vm(self, cfg, vm_name="", vm_id=""):
        return vmident.VMRef(id=GUID, name=vm_name or "vm1")

    def head_resolution(self, guid):
        return (320, 240), {}

    def capture(self, guid, width, height):
        self.captures.append((width, height))
        return self.payload, {}


@pytest.mark.parametrize("options,expected_mime,expected_size", [
    ({"fmt": "jpeg", "quality": 40}, "image/jpeg", (320, 240)),
    ({"scale": 0.5}, "image/png", (160, 120)),
    ({"crop": [0, 0, 160, 120]}, "image/png", (160, 120)),
    ({"fmt": "jpeg", "scale": 0.5, "crop": [0, 0, 160, 120]},
     "image/jpeg", (80, 60)),
])
def test_wmi_leg_honours_every_output_option(
    monkeypatch, unrestricted, options, expected_mime, expected_size
):
    """PRR-004: the in-process WMI leg had zero coverage for any new option —
    deleting the five options from the `_screenshot_wmi` call left the whole
    committed unit suite green while a sanity check confirmed the mutant WAS
    behaviour-changing on that leg. These checks make that mutant die. The
    WMI transport is the default on a real Hyper-V host, so it is the leg that
    actually matters."""
    payload = _raw_thumbnail(320, 240)
    backend = _OptionBackend(payload)
    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", True)
    monkeypatch.setattr(wmiconsole, "backend", lambda cfg: backend)
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})

    def no_powershell(script, **kwargs):
        raise AssertionError("the WMI transport was selected but PowerShell ran")

    monkeypatch.setattr(pswindows, "run_ps", no_powershell)

    frame, meta = console.screenshot(unrestricted, "test-vm-1", 320, 240, "", **options)

    assert backend.captures, "the WMI leg never reached the backend"
    assert meta["capture_method"].startswith("GetVirtualSystemThumbnailImage (in-process WMI"), (
        f"PRR-004: this check did not exercise the WMI leg: {meta['capture_method']!r}"
    )
    assert frame is not None, f"PRR-004: {options} returned no frame"
    assert frame.mime == expected_mime, (
        f"PRR-004: the WMI leg must honour the format for {options}; got "
        f"{frame.mime!r}, expected {expected_mime!r}"
    )
    assert frame.size == expected_size, (
        f"PRR-004: the WMI leg must apply scale/crop for {options}; got "
        f"{frame.size}, expected {expected_size}"
    )
    # The metadata echo key is `format` even though the argument is `fmt`.
    for key in ("format", "quality", "scale", "crop"):
        if key in options:
            assert key in meta, (
                f"PRR-004: the WMI leg dropped the {key!r} echo for {options}"
            )
    assert "frame_hash" in meta and "width" in meta and "height" in meta, (
        "PRR-004: the WMI leg must produce the same metadata contract as the "
        "PowerShell leg"
    )


def test_wmi_leg_default_path_matches_the_powershell_default_key_set(
    monkeypatch, unrestricted
):
    """PRR-004's contract half: with no options, the WMI leg's metadata key set
    must equal the PowerShell leg's, so the two transports cannot drift on the
    shape issue #19 pins. The mutant this kills: an option-echo key emitted on
    one leg only."""
    payload = _raw_thumbnail(320, 240)
    backend = _OptionBackend(payload)
    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", True)
    monkeypatch.setattr(wmiconsole, "backend", lambda cfg: backend)
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})
    _, wmi_meta = console.screenshot(unrestricted, "test-vm-1", 320, 240)

    fake = FakeCapture([_folded_response(payload, 320, 240)])
    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", False)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    _, ps_meta = console.screenshot(unrestricted, "test-vm-1", 320, 240)

    assert set(wmi_meta) == set(ps_meta), (
        "PRR-004: the default-path metadata key set must be identical on both "
        f"transports. WMI-only: {sorted(set(wmi_meta) - set(ps_meta))}; "
        f"PowerShell-only: {sorted(set(ps_meta) - set(wmi_meta))}"
    )
    assert wmi_meta["frame_hash"] == ps_meta["frame_hash"], (
        "PRR-004: the same payload must hash the same on both transports"
    )


# ---------------------------------------------------------------------------
# PRR-012 — capture_evidence's unchanged short-circuit skips the UIA leg
# ---------------------------------------------------------------------------

VM_GUID = "e953c649-1234-5678-9abc-def012345678"


def _resolve_only_ps(monkeypatch):
    """capture_evidence resolves the target first (vmident by-name leg); serve
    that one spawn so no real PowerShell runs."""
    monkeypatch.setattr(
        pswindows, "run_ps",
        lambda script, **kw: pswindows.PSResult(stdout=VM_GUID, returncode=0),
    )


class _ExplodingUIA:
    """A run_guest_inner stand-in that fails the test if it is reached."""

    def __call__(self, *args, **kwargs):
        raise AssertionError(
            "PRR-012: the UI-tree leg ran for an UNCHANGED frame; the "
            "credentialed 60 s PowerShell Direct session must be skipped when "
            "the screenshot short-circuited"
        )


def test_capture_evidence_skips_the_ui_leg_when_the_frame_is_unchanged(
    monkeypatch, unrestricted
):
    """PRR-012: `capture_evidence`'s short-circuit did not skip the guest UIA
    fetch — after `console.screenshot` had determined the frame was unchanged,
    the credentialed session still ran and its tree was still merged into the
    `unchanged: true` metadata, contradicting both docstrings' "nothing is
    decoded, encoded or written". The mutant this kills: leaving the UIA leg
    outside the short-circuit."""
    from hyperv_mcp import credentials as creds

    _resolve_only_ps(monkeypatch)
    cred = creds.CredentialSet(username="u", password="p")
    seen: dict = {}

    def fake_screenshot(cfg, vm_name="", width=1024, height=768, save_path="",
                        vm_id="", fmt="", quality=None, scale=None, crop=None,
                        if_changed_from=""):
        seen["vm_id"] = vm_id
        seen["vm_name"] = vm_name
        if if_changed_from == "f" * 64:
            # The unchanged leg: console.screenshot's own short-circuit.
            return None, {**_base_meta(), "unchanged": True}
        return Image.new("RGB", (8, 8), (1, 2, 3)), _base_meta()

    monkeypatch.setattr(evidence.console, "screenshot", fake_screenshot)

    # Prime: a changed frame, which DOES fetch the tree.
    monkeypatch.setattr(evidence, "run_guest_inner",
                        lambda *a, **k: {"elements": 1, "truncated": False,
                                         "tree": {"name": "root"}})
    out = evidence.capture_evidence(
        unrestricted, "test-vm-1", 320, 240, ui_tree=True, cred=cred,
    )
    assert out["image"] is not None, "the priming capture must return a frame"
    assert out["meta"]["ui_tree"].get("ok") is True, (
        "a changed frame must still fetch the UI tree"
    )

    # Now the unchanged frame: the UIA leg must not run at all.
    monkeypatch.setattr(evidence, "run_guest_inner", _ExplodingUIA())
    out = evidence.capture_evidence(
        unrestricted, "test-vm-1", 320, 240, ui_tree=True, cred=cred,
        if_changed_from="f" * 64,
    )

    assert out["image"] is None, "an unchanged frame must return no image"
    assert out["meta"].get("unchanged") is True
    ui = out["meta"]["ui_tree"]
    assert ui.get("requested") is True, "the request must still be acknowledged"
    assert ui.get("skipped") is True, (
        f"PRR-012: the UI-tree leg must be skipped for an unchanged frame and "
        f"say so; got {ui}"
    )
    assert "tree" not in ui, (
        f"PRR-012: no guest content may be merged into an unchanged result; "
        f"got {sorted(ui)}"
    )
    # The screenshot leg still receives ONLY the resolved GUID (PRR-006).
    assert seen["vm_id"] == VM_GUID and seen["vm_name"] == "", (
        "the screenshot leg must still receive only the resolved GUID"
    )


def test_capture_evidence_without_a_ui_request_is_unchanged_by_the_frame_state(
    monkeypatch, unrestricted
):
    """PRR-012's other half: the skip must be gated on the REQUEST. A caller
    who passed `ui_tree=false` must get exactly `{"requested": False}` whether
    the frame changed or not — otherwise the frame's change state changes a key
    set the caller never varied, which is the same changed/unchanged asymmetry
    this round exists to close, reintroduced inside `meta["ui_tree"]`. The
    mutant this kills: an unconditional `if meta.get("unchanged"):` branch."""
    from hyperv_mcp import credentials as creds  # noqa: F401  (import keeps the module honest)

    _resolve_only_ps(monkeypatch)

    def fake_screenshot(cfg, vm_name="", width=1024, height=768, save_path="",
                        vm_id="", fmt="", quality=None, scale=None, crop=None,
                        if_changed_from=""):
        if if_changed_from == "f" * 64:
            return None, {**_base_meta(), "unchanged": True}
        return Image.new("RGB", (8, 8), (1, 2, 3)), _base_meta()

    monkeypatch.setattr(evidence.console, "screenshot", fake_screenshot)
    monkeypatch.setattr(evidence, "run_guest_inner", _ExplodingUIA())

    changed = evidence.capture_evidence(unrestricted, "test-vm-1", 320, 240)
    unchanged = evidence.capture_evidence(
        unrestricted, "test-vm-1", 320, 240, if_changed_from="f" * 64,
    )

    assert changed["meta"]["ui_tree"] == {"requested": False}, (
        f"a changed frame with no UI request must report exactly "
        f"{{'requested': False}}, got {changed['meta']['ui_tree']}"
    )
    assert unchanged["meta"]["ui_tree"] == {"requested": False}, (
        f"PRR-012: an unchanged frame with no UI request must report the same "
        f"shape as a changed one — the frame's change state is not the "
        f"caller's business when they asked for no tree; got "
        f"{unchanged['meta']['ui_tree']}"
    )
    assert unchanged["meta"].get("unchanged") is True
    assert unchanged["image"] is None


def test_save_path_temp_name_is_unique_per_save(monkeypatch, unrestricted, tmp_path):
    """PRR-022: the atomic write's temp name carries the pid and a per-process
    counter, so two concurrent saves to the same path cannot open the same
    `.mcp-partial` file and interleave their bytes. The mutant this kills: a
    fixed temp name."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)] * 2))
    dest = tmp_path / "shots" / "frame.png"
    cfg_doc = {
        "allowed_vm_patterns": ["test-vm-*"],
        "host_write_roots": [str(tmp_path / "shots")],
    }
    import hyperv_mcp.server as sm

    p = tmp_path / "unique-cfg.json"
    p.write_text(json.dumps(cfg_doc), encoding="utf-8")
    mod = importlib.reload(sm)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    mcp = mod.get_mcp()

    opened: list[str] = []
    real_open = builtins.open

    def recording_open(file, *args, **kwargs):
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    try:
        _call(mcp, "hyperv_console_screenshot", {
            "vm_name": "test-vm-1", "width": 320, "height": 240,
            "save_path": str(dest),
        })
        _call(mcp, "hyperv_console_screenshot", {
            "vm_name": "test-vm-1", "width": 320, "height": 240,
            "save_path": str(dest),
        })
    finally:
        monkeypatch.undo()

    partials = [p for p in opened if p.endswith(".mcp-partial")]
    assert len(partials) == 2, (
        f"expected two partial writes, got {partials}"
    )
    assert partials[0] != partials[1], (
        f"PRR-022: two saves to the same path must not share a temp file, or "
        f"concurrent writers interleave their bytes; both used {partials[0]}"
    )
    assert dest.exists() and dest.read_bytes(), "the final artifact must still exist"


# ---------------------------------------------------------------------------
# PRR-020 — the encode-count oracle must cover the shaped paths too
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("options", [
    {},
    {"scale": 0.5},
    {"crop": [0, 0, 160, 120]},
    {"scale": 0.5, "crop": [0, 0, 160, 120]},
])
def test_each_returned_image_is_encoded_exactly_once(
    monkeypatch, fresh_server, options
):
    """PRR-020a: the PR body claims "exactly 1 encode on the
    default/scale/crop/crop+scale paths", but the only oracle patched
    `Image.SAVE["PNG"]` and only the DEFAULT path was asserted — a
    double-encode mutant confined to the shaped branch survived the whole
    suite. This check counts encodes in EVERY format on every shaped path. The
    mutant this kills: a second encode inside the shaping branch."""
    from PIL import Image as _Image

    _Image.init()
    box = {"encodes": 0}
    originals = {fmt: _Image.SAVE[fmt] for fmt in ("PNG", "JPEG", "WEBP")
                 if fmt in _Image.SAVE}

    def _make_counting(fmt):
        original = originals[fmt]

        def counting(fp, *args, **kwargs):
            box["encodes"] += 1
            return original(fp, *args, **kwargs)

        return counting

    for fmt in originals:
        monkeypatch.setitem(_Image.SAVE, fmt, _make_counting(fmt))

    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([_folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    images, _ = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240, **options,
    }))

    assert len(images) == 1, f"{options}: expected one image block"
    assert box["encodes"] == 1, (
        f"PRR-020a: {options} must encode exactly once; {box['encodes']} "
        f"encodes ran across every format"
    )


def test_poll_hash_byte_count_is_pinned_to_the_pixels(monkeypatch, unrestricted):
    """PRR-020b: AC11 asserted only the substring `ComputeHash($r.ImageData, 4,`,
    so a mutant that changed the byte count from `- 4` to `- 5` passed all 74
    D03+test_console tests — a wrong count still yields a valid-looking digest,
    and the real consequence is silent (host and poll loop disagree, so every
    `frame_hash` round-trips as a broken `baseline_hash`). The full expression
    is pinned here as well, from the console layer rather than the frozen pack,
    so the two assertions cannot be edited in lockstep by mistake."""
    fake = FakeCapture([pswindows.PSResult(
        stdout="STOP=deadline POLLS=1 HASH=" + "b" * 64, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.wait_frame_change(unrestricted, "test-vm-1", width=320, height=240)
    assert fake.scripts, "wait_frame_change spawned no poll script"
    script = fake.scripts[0]

    assert "ComputeHash($r.ImageData, 4, $r.ImageData.Length - 4)" in script, (
        "PRR-020b: the poll loop must count exactly the pixels; a different "
        "byte count produces a different digest and breaks host/poll "
        "equivalence silently"
    )
    assert script.count("ComputeHash(") == 1, (
        f"PRR-020b: the poll loop must hash exactly once per poll; "
        f"{script.count('ComputeHash(')} hash sites found"
    )
