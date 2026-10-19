"""Acceptance checks for issue #74 in the #74/#72/#88 bundle: `console.Frame`
must retain only the encoding until a consumer touches pixels.

C1 (AC1, DISCRIMINATING) — an untouched 1024x768 frame retains no more than the
PNG encoding plus a bounded constant. RED at base (the raster is materialised at
decode and held), GREEN after the fix.

C2 (AC2, PRESERVING) — a consumer reading pixels from a frame after construction
gets the same pixels as before. GREEN at base and after: the lazy path must not
change observable pixel behaviour.

Measurement notes, because the instrument is the whole difficulty here:

- The retention number is the MARGINAL working-set cost per held frame between a
  1-frame and an 8-frame CHILD PROCESS. A single-frame RSS delta is dominated by
  one-time interpreter and import noise, which would swamp the signal; the
  marginal cancels it.
- `tracemalloc` cannot be used: PIL's raster comes from its own allocator, which
  `tracemalloc` does not track, so an in-process measurement reads a few
  kilobytes and proves nothing either way. That is why issue #74 prescribes a
  separate-process RSS probe.
- A POSITIVE CONTROL is mandatory: the same children reading a pixel from every
  frame must cost at least half the raster, which proves the probe can see a
  raster when one exists. Without it, a probe that could not see a raster at all
  would pass vacuously — the exact vacuity shape the #87/#89 review rounds kept
  finding.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from hyperv_mcp import console as console_mod

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = str(_REPO_ROOT / "src")

_L = chr(10)
# Built with chr(10) joins rather than a nested literal: a backslash-bearing
# literal inside this file is mangled by the shell that writes it, and the
# mangling surfaces as a SyntaxError at the first affected string.
_CHILD = _L.join([
    "import json, sys",
    "sys.path.insert(0, " + repr(_SRC) + ")",
    "from hyperv_mcp import console as console_mod",
    "import psutil",
    "n = int(sys.argv[1])",
    "touch = len(sys.argv) > 2 and sys.argv[2] == 'touch'",
    "w, h = 1024, 768",
    "px = bytearray()",
    "for y in range(h):",
    "    for x in range(w):",
    "        v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)",
    "        px += bytes([v & 0xFF, (v >> 8) & 0xFF])",
    "raw = bytes([0, 0, 0x96, 4]) + bytes(px)",
    "frames = []",
    "for _ in range(n):",
    "    img = console_mod._decode_rgb565_image(raw, w, h)",
    "    frames.append(console_mod.Frame.from_image(img, 'image/png'))",
    "    del img",
    "if touch:",
    "    for f in frames:",
    "        f.getpixel((0, 0))",
    "        f.tobytes()",
    "print(json.dumps({'rss': psutil.Process().memory_info().rss,",
    "                'png': len(frames[0].encoded)}))",
])

_LOW_N = 1
_HIGH_N = 8
#: The PNG encoding plus a bounded constant. 64 KiB is two orders of magnitude
#: of slack over the largest PNG a 4096x4096 frame can produce, and far more
#: than any per-frame bookkeeping a lazy design needs.
_CONSTANT = 64 * 1024
_RASTER = 1024 * 768 * 3


def _child(script: str, *args: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", script, *args],
        capture_output=True, text=True, timeout=300, cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"retention child failed: {proc.stderr[-800:]}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _payload(w: int, h: int) -> bytes:
    px = bytearray()
    for y in range(h):
        for x in range(w):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            px += bytes([v & 0xFF, (v >> 8) & 0xFF])
    return bytes([0, 0, 0x96, 4]) + bytes(px)


def test_untouched_frame_retains_only_the_encoding():
    """C1 / AC1: an untouched frame retains the encoding plus a constant."""
    hold_low = _child(_CHILD, str(_LOW_N))
    hold_high = _child(_CHILD, str(_HIGH_N))
    touch_low = _child(_CHILD, str(_LOW_N), "touch")
    touch_high = _child(_CHILD, str(_HIGH_N), "touch")

    png = int(hold_low["png"])
    frames = _HIGH_N - _LOW_N
    hold_per_frame = (int(hold_high["rss"]) - int(hold_low["rss"])) / frames
    touch_per_frame = (int(touch_high["rss"]) - int(touch_low["rss"])) / frames
    ceiling = png + _CONSTANT

    # Positive control first: if the probe cannot see a raster at all, the
    # untouched number below is meaningless and must not be believed.
    assert touch_per_frame >= _RASTER // 2, (
        f"positive control failed: touching pixels costs "
        f"{touch_per_frame:.0f} bytes per frame, so this probe cannot see the "
        f"{_RASTER}-byte raster at all"
    )
    assert hold_per_frame < ceiling, (
        f"AC1: an untouched 1024x768 frame retains {hold_per_frame:.0f} bytes, "
        f"expected under {ceiling} (png {png} + {_CONSTANT} constant). The "
        f"{_RASTER}-byte raster is materialised at decode time and held for the "
        f"frame's lifetime."
    )


def test_pixels_available_on_demand():
    """C2 / AC2: pixels are readable and identical on the lazy path."""
    raw = _payload(320, 240)
    img = console_mod._decode_rgb565_image(raw, 320, 240)
    frame = console_mod.Frame.from_image(img, "image/png")

    assert isinstance(frame, console_mod.Frame), "Frame must stay a Frame"
    assert frame.size == (320, 240), f"size changed: {frame.size}"
    assert frame.mode == "RGB", f"mode changed: {frame.mode}"

    assert frame.getpixel((10, 20)) == img.getpixel((10, 20)), (
        "AC2: getpixel must return the same pixel as the reference decode"
    )
    assert frame.tobytes() == img.tobytes(), (
        "AC2: tobytes must return the same raster as the reference decode"
    )
    # `save` must still work: it is the one path that materialises from the
    # encoding rather than from a live raster.
    import io

    buf = io.BytesIO()
    frame.save(buf, format="PNG")
    assert buf.getvalue(), "AC2: save must produce bytes"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
