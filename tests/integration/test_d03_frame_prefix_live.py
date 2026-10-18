"""Real-Hyper-V integration tests for issue #19 (Workstream D PR 3): the
pixel-only frame hash on a live unchanging console, and the output-option
size matrix.

Opt-in like every file here (see tests/integration/conftest.py): the suite
skips unless the shared gate holds — HYPERV_MCP_INTEGRATION=1,
HYPERV_MCP_TEST_VM names a disposable VM, guest credentials set (see that
conftest for the full gate). Console capture is host-side WMI/PowerShell,
so these tests need no guest credentials of their own — the shared gate is
simply stricter.

Both tests drive the REGISTERED hyperv_console_screenshot tool through the
SDK (the surface the issue's acceptance criteria name), not the module
layer, and print their evidence tables so a `-s` run records it.
"""

import asyncio
import base64
import importlib
import json
import time

import pytest
from PIL import features

pytestmark = [pytest.mark.hyperv_real]

import hyperv_mcp.server as server_module  # noqa: E402


@pytest.fixture(scope="module")
def sdk():
    """A bootstrapped unrestricted server whose registered tools drive the
    real host (the test_image_content harness shape, minus the stub)."""
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
    return mod.get_mcp()


def _call_screenshot(mcp, arguments: dict):
    result = asyncio.run(mcp.call_tool("hyperv_console_screenshot", arguments))
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    images = [c for c in content if getattr(c, "type", "") == "image"]
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    return images, texts


def test_prefix_stability_on_static_screen(it, sdk):
    """AC9: 10 captures of an idle, unchanging console taken 2 s apart all
    report the same frame_hash, and each capture's prefix_hex is printed so
    the record shows whether the opaque prefix itself varied."""
    vm = it.vm
    rows = []
    for i in range(10):
        images, texts = _call_screenshot(
            sdk, {"vm_name": vm, "width": 320, "height": 240})
        assert len(images) == 1, (
            f"AC9: capture {i}: expected one image block, got {len(images)}"
        )
        meta = json.loads(texts[0].text)
        rows.append((i, str(meta.get("prefix_hex", "")),
                     str(meta.get("frame_hash", ""))))
        if i < 9:
            time.sleep(2)
    print("\nAC9 prefix stability: 10 captures of an idle console, 2 s apart")
    print("idx | prefix_hex  | frame_hash")
    for i, prefix, frame_hash in rows:
        print(f"{i:>3} | {prefix:<11} | {frame_hash}")
    hashes = {h for _, _, h in rows}
    prefixes = {p for _, p, _ in rows}
    print(f"distinct frame_hash values: {len(hashes)}; "
          f"distinct prefix_hex values: {len(prefixes)}")
    assert len(hashes) == 1, (
        f"AC9: an unchanged console produced {len(hashes)} distinct frame_hash "
        f"values: {sorted(hashes)}"
    )


def test_output_option_sizes_live(it, sdk):
    """AC12: the real VM desktop captured at 1024x768 under each output
    option (png default, jpeg q80, webp q80, png scale 0.5); each returned
    image's byte size and encode/wall time is printed. No assertion on which
    is smallest — format and scale are not a guaranteed win (a flat desktop
    can make PNG smallest and BOX downscaling can enlarge it).

    PRR-021: the matrix used to assert only `len(images) == 1` and then print
    the mime/size it had just measured, so a transport that dropped every
    option and returned the default PNG still passed. The measurements are now
    compared against what each row ASKED for — the mime, the requested scale's
    effect on the dimensions, and the echoed options — and the webp row carries
    the same `features.check("webp")` skip unit AC4 has, so a WebP-less Pillow
    reports a skip instead of hard-failing.
    """
    vm = it.vm
    options = [
        ("png (default)", {}, "image/png", (1024, 768)),
        ("jpeg q80", {"format": "jpeg", "quality": 80}, "image/jpeg", (1024, 768)),
        ("webp q80", {"format": "webp", "quality": 80}, "image/webp", (1024, 768)),
        ("png scale 0.5", {"scale": 0.5}, "image/png", (512, 384)),
    ]
    print("\nAC12 output-option sizes: 1024x768 desktop")
    print("option           |    bytes | wall_ms | mime         | dims      | timings")
    for label, extra, expected_mime, expected_dims in options:
        if extra.get("format") == "webp" and not features.check("webp"):
            print(f"{label:<16} | SKIPPED (this Pillow build has no WebP support)")
            continue
        args = {"vm_name": vm, "width": 1024, "height": 768, **extra}
        started = time.monotonic()
        images, texts = _call_screenshot(sdk, args)
        wall_ms = int((time.monotonic() - started) * 1000)
        note = texts[0].text[:160] if texts else "no text block"
        assert len(images) == 1, (
            f"AC12 ({label}): expected one image block, got {len(images)} ({note})"
        )
        block = images[0]
        mime = getattr(block, "mimeType", None) or getattr(block, "mime_type", None)
        assert mime == expected_mime, (
            f"PRR-021 ({label}): the wire mimeType must be {expected_mime}, got "
            f"{mime!r} — the option was dropped somewhere between the request "
            f"and the response"
        )
        size = len(base64.b64decode(block.data))
        meta = json.loads(texts[0].text) if texts else {}
        dims = (meta.get("width"), meta.get("height"))
        assert dims == expected_dims, (
            f"PRR-021 ({label}): the returned dimensions must be {expected_dims}, "
            f"got {dims} — scale was not applied"
        )
        for key in ("format", "quality", "scale", "crop"):
            if key in extra:
                assert key in meta, (
                    f"PRR-021 ({label}): the metadata must echo {key!r}; got "
                    f"{sorted(meta)}"
                )
        timings = json.dumps(meta.get("timings"))
        print(f"{label:<16} | {size:>8} | {wall_ms:>7} | {mime:<12} | "
              f"{dims[0]}x{dims[1]:<6} | {timings}")
