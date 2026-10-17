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
    can make PNG smallest and LANCZOS downscaling can enlarge it)."""
    vm = it.vm
    options = [
        ("png (default)", {}),
        ("jpeg q80", {"format": "jpeg", "quality": 80}),
        ("webp q80", {"format": "webp", "quality": 80}),
        ("png scale 0.5", {"scale": 0.5}),
    ]
    print("\nAC12 output-option sizes: 1024x768 desktop")
    print("option           |    bytes | wall_ms | mime         | timings")
    for label, extra in options:
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
        size = len(base64.b64decode(block.data))
        timings = "-"
        if texts:
            try:
                timings = json.dumps(json.loads(texts[0].text).get("timings"))
            except ValueError:
                pass
        print(f"{label:<16} | {size:>8} | {wall_ms:>7} | {mime:<12} | {timings}")
