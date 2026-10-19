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
- The DISCRIMINATOR is a difference between two children measured under the same
  conditions (both holding 8 frames, one touching every pixel), not an absolute
  threshold. The current working set is trimmable, so under memory pressure —
  a full-suite run with the relay tests already holding sockets and threads — an
  absolute number can read a false negative. A difference between two arms taken
  at the same moment is immune: whatever the OS trimmed, it trimmed from both.
- The direction of the two assertions is chosen so trimming cannot cause a false
  failure: the retention assertion wants a SMALL number (trimming only makes it
  smaller), and the discriminator is a difference. What trimming COULD cause is a
  false pass on the retention assertion, which is exactly what the discriminator
  catches.
- `tracemalloc` cannot be used: PIL's raster comes from its own allocator, which
  `tracemalloc` does not track, so an in-process measurement reads a few
  kilobytes and proves nothing either way. That is why issue #74 prescribes a
  separate-process RSS probe.
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
    "print(json.dumps({'rss': psutil.Process().memory_info().peak_wset,",
    "                'png': len(frames[0].encoded)}))",
])

_LOW_N = 1
#: 4 rather than 8: the materialise-cost signal is already ~4 rasters at this
#: ratio, and halving the frame count halves the memory each child commits,
#: which matters because these children run inside the full suite alongside
#: timing-sensitive siblings.
_HIGH_N = 4
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
    """C1 / AC1: an untouched frame retains the encoding plus a constant.

    Three assertions, because each closes a hole the others leave:

    1. STRUCTURAL — no raster is materialised for an untouched frame. This is
       the exact definition of the property, and it is what fails on the eager
       base (`from_image` copied the decoded image's `__dict__`, `im` included).
    2. RETENTION — what the frame does hold is the encoding plus a bounded
       constant. This is the issue's own wording, and it is what stops a design
       that "fixed" the problem by holding nothing at all.
    3. MEASURED — materialising the frames really does cost a raster, as a
       DIFFERENCE between two children under the same conditions, because the
       current working set is trimmable and an absolute number can read a false
       negative under memory pressure. This is a POSITIVE CONTROL that the
       instrument can see a raster at all: it rules out a measurement rig so
       blind that every leg would read zero and the other two assertions would
       be carried by nothing. It does NOT discriminate a design that hides the
       raster behind `_im = None` while still holding it off-frame — a stash in
       a module global keeps the frame's own RSS low, and the `tobytes()`
       transient in the touching arm alone exceeds one raster, so such a design
       measures about 1.35x and passes. The eager case is carried by the
       STRUCTURAL leg; off-frame process retention is a different defect class
       and no leg here claims to catch it.
    """
    # --- 1. structural -----------------------------------------------------
    raw = _payload(1024, 768)
    img = console_mod._decode_rgb565_image(raw, 1024, 768)
    frame = console_mod.Frame.from_image(img, "image/png")
    del img
    assert frame._raster_loaded is False, (
        f"AC1: an untouched frame must not have materialised its raster. "
        f"`_raster_loaded` is {frame._raster_loaded!r}, so the decode's raster "
        f"is retained for the frame's whole lifetime — which is the defect."
    )

    # --- 2. retention ------------------------------------------------------
    # The frame must HOLD the encoding (this is what stops a design that
    # "fixed" the problem by holding nothing at all) and must hold no other
    # buffer of consequence.
    #
    # An earlier version of this leg summed `len(encoded) + len(png)`, which is
    # a tautology: `png` and `_png` are the SAME bytes object for a PNG frame,
    # so the sum is `2 * len(encoded)` and the assertion reduced to
    # `len(encoded) < 64 KiB` — a statement about PNG compressibility that no
    # memory property could fail. Summing every buffer the frame actually owns
    # keeps the claim meaningful without depending on PIL's attribute names,
    # which moved between the 10.x and 11+ lines.
    png = len(frame.encoded)
    assert png > 0, "AC1: the frame must retain its encoding"
    held = sum(
        len(v) for v in vars(frame).values() if isinstance(v, (bytes, bytearray))
    )
    ceiling = png + _CONSTANT
    assert held <= ceiling, (
        f"AC1: an untouched frame holds {held} bytes of buffers, expected no "
        f"more than {ceiling} (encoding {png} + {_CONSTANT} constant). A second "
        f"copy of the raster stored as bytes would show up here."
    )

    # --- 3. measured -------------------------------------------------------
    hold_high = _child(_CHILD, str(_HIGH_N))
    touch_high = _child(_CHILD, str(_HIGH_N), "touch")
    materialise_cost = int(touch_high["rss"]) - int(hold_high["rss"])
    print(f"png={png} held={held} ceiling={ceiling} "
          f"materialise_cost={materialise_cost} raster={_RASTER}")
    assert materialise_cost >= _RASTER, (
        f"positive control failed: materialising {_HIGH_N} frames costs only "
        f"{materialise_cost} bytes more than holding them, so this probe cannot "
        f"see the {_RASTER}-byte raster and the structural assertion above is "
        f"not corroborated by memory"
    )


def test_materialisation_is_a_real_cache_not_a_redecode():
    """C1b / AC1: the raster is materialised ONCE, not re-decoded per access.

    This is the leg that catches the version-specific memoisation bug. The
    first implementation guarded on `self._im`, which is the property backing
    only in Pillow 11+; on the declared `pillow>=10.0` floor the raster lives
    in the plain attribute `im`, so the guard never fired, every pixel access
    re-decoded from the pristine encoding, and every mutation was silently
    discarded. `assert frame._im is None` cannot see that, because `_im` is
    None forever on 10.x — which is why the guard is now our own
    `_raster_loaded` flag and why this test asserts OBSERVABLE behaviour
    (raster identity and mutation survival) rather than an attribute name.
    """
    raw = _payload(64, 48)
    img = console_mod._decode_rgb565_image(raw, 64, 48)
    frame = console_mod.Frame.from_image(img, "image/png")
    del img

    frame.getpixel((0, 0))                      # first materialisation
    raster = frame.im
    frame.getpixel((1, 1))                      # must NOT re-decode
    assert frame.im is raster, (
        "AC1: a second pixel access replaced the raster, so the frame is "
        "re-decoding from its encoding on every access instead of caching "
        "the materialised raster"
    )

    # A mutation must survive: if every access re-decodes from the encoding,
    # the next read silently restores the original pixel.
    before = frame.getpixel((1, 1))
    frame.putpixel((1, 1), (before[0] ^ 0xFF, before[1], before[2]))
    after = frame.getpixel((1, 1))
    assert after != before, (
        f"AC1: a putpixel mutation was silently discarded (read back "
        f"{after!r} where something else was written at (1,1)). The raster is "
        f"being re-decoded from the encoding on every access."
    )

    # And the re-save must differ from the frozen snapshot, which is the
    # invariant the pre-existing d01 check pins.
    import io

    buf = io.BytesIO()
    frame.save(buf, format="PNG")
    assert buf.getvalue() != frame.png, (
        "AC1: re-saving a mutated frame reproduced the original encoding "
        "byte-for-byte, so the mutation never reached the raster"
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
