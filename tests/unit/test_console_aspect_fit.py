"""Issue #125 acceptance checks: letterbox-aware capture and click mapping.

Authored BEFORE the fix exists (arm's-length check author): these tests are
the frozen contract the implementation must satisfy, pinned to the issue's
own probe numbers (head 1920x1010; a 1024x768 capture letterboxes with 115
fully black rows top and bottom, content rows 115..652 = height 538).

Pinned module surface (names from the issue's own vocabulary):

  - Screenshot/capture metadata gains `content_rect`: [left, top, right,
    bottom] of the non-letterbox pixels, right/bottom EXCLUSIVE (the same
    box semantics as the `crop` output option). The capture-time head
    resolution is the existing `head_resolution` metadata key.
  - `_scale_to_head` gains an optional `content_rect` parameter: frame
    points map through the rect — offset into the rect, scaled by
    head/content size, rounded, clamped to the head bounds (the anchor's
    semantics applied rect-relative). A full-frame rect reproduces the
    anchor mapping exactly (AC6).
  - Mouse tools accept a cited capture `frame_hash=`; citations resolve
    against `console.register_capture(...)` records. A click aimed inside a
    letterbox band, and a click citing a capture whose recorded head
    resolution differs from the current head, are refused with structured
    ConsoleErrors and send no mouse input.
  - `screenshot(width=W, height=0)` captures at the head's aspect for W,
    with the requested size as host-side literal WidthPixels/HeightPixels
    lines (the anchor's folded-script structure).
  - `console.reset_input_ledger()` clears the module's citation state (the
    per-VM input ledger and the capture-citation registry) for isolation.

Every Hyper-V leg is the FakePS folded-transport stub pattern from
tests/unit/test_console.py; payloads are synthetic RGB565 bytes (4-byte
opaque prefix + 2 bytes per pixel). No live host, no sleeps, no cross-test
state.

Expected on the PRE-FIX tree: every test fails on the missing surface —
AssertionError on absent `content_rect` metadata, TypeError on the absent
`content_rect`/`frame_hash` parameters, AttributeError on the absent
`console.register_capture`, ValueError on the absent height=0 default —
never on collection.
"""

import base64
import json
import re

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError, _scale_to_head

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

# Issue #125 claim 1's probe numbers: head 1920x1010, 1024x768 capture.
HEAD_WIDE = (1920, 1010)
# content height = 1024 * 1010 // 1920 = 538; bands = (768 - 538) // 2 = 115
# top and bottom; content rows 115..652 inclusive -> the exclusive rect is
# [0, 115, 1024, 653] (right/bottom exclusive, like the crop option).
LETTERBOX_RECT = [0, 115, 1024, 653]


def _rgb565_payload(w: int, h: int) -> bytes:
    """4-byte opaque prefix + width*height little-endian RGB565 pixels
    (all black — a letterboxed capture is black in the bands by
    construction, and content_rect is derived from the geometry, not the
    pixels)."""
    return b"\x00\x00\x00\x00" + b"\x00\x00" * (w * h)


def _folded_size(script: str) -> tuple[int, int]:
    """The requested size of a folded capture script (its literal
    WidthPixels/HeightPixels seed, with the $sizes fallback), after
    tests/unit/test_console.py's helper."""
    w = h = 0
    for line in script.splitlines():
        ls = line.strip()
        if ls.startswith("WidthPixels"):
            raw = ls.split("=", 1)[1].strip()
            if raw.isdigit():
                w = int(raw)
        elif ls.startswith("HeightPixels"):
            raw = ls.split("=", 1)[1].strip()
            if raw.isdigit():
                h = int(raw)
    if not (w and h):
        m = re.search(r"\$sizes = @\([,(@]*(\d+),(\d+)\)", script)
        if m:
            w, h = int(m.group(1)), int(m.group(2))
    return w, h


def _folded_position(script: str, head: tuple[int, int]) -> tuple[int, int] | None:
    """The head-space position a folded positional-mouse script computes
    (the in-script replica of console._scale_to_head), after
    tests/unit/test_console.py's helper but against a configurable head."""
    x = y = fw = fh = 0
    seen = False
    for line in script.splitlines():
        ls = line.strip()
        for name in ("$x", "$y", "$fw", "$fh"):
            if ls.startswith(name + " ="):
                raw = ls.split("=", 1)[1].strip()
                if raw.lstrip("-").isdigit():
                    val = int(raw)
                    seen = True
                    if name == "$x":
                        x = val
                    elif name == "$y":
                        y = val
                    elif name == "$fw":
                        fw = val
                    else:
                        fh = val
    if not seen:
        return None
    if fw or fh:
        hx = round(x * head[0] / fw) if fw else x
        hy = round(y * head[1] / fh) if fh else y
    else:
        hx, hy = x, y
    return max(0, min(hx, head[0] - 1)), max(0, min(hy, head[1] - 1))


class FakePS:
    """Adaptive folded-transport stub after tests/unit/test_console.py's
    FakePS, with the head configurable so a test can pin the world's head
    resolution on every head-answering leg (folded HEAD= line, display
    info, Msvm_VideoHead lookup)."""

    def __init__(self, responses=(), head=(1024, 768)):
        self.scripts = []
        self.kwargs = []
        self.responses = list(responses)
        self.head = head

    def _payload(self, w: int, h: int) -> bytes:
        return _rgb565_payload(w, h)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if self.responses:
            item = self.responses.pop(0)
        elif "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            item = pswindows.PSResult(stdout=GUID, returncode=0)
        elif "GetVirtualSystemThumbnailImage" in script:
            w, h = _folded_size(script)
            payload = self._payload(w, h)
            body = json.dumps({
                "returnValue": 0,
                "imageDataB64": base64.b64encode(payload).decode(),
            })
            item = pswindows.PSResult(
                stdout="VMID=" + GUID + "\nHEAD=" + str(self.head[0]) + "x"
                       + str(self.head[1]) + "\nSIZES=" + str(w) + "x"
                       + str(h) + "\nUSED=" + str(w) + "x" + str(h) + "\n"
                       + body,
                returncode=0)
        elif "EnabledState" in script:
            body = json.dumps({
                "enabled_state": 2,
                "head_horizontal": self.head[0], "head_vertical": self.head[1],
                "keyboard_present": True, "keyboard_enabled": 2,
                "mouse_present": True, "mouse_enabled": 2,
            })
            item = pswindows.PSResult(stdout="VMID=" + GUID + "\n" + body, returncode=0)
        elif "SetAbsolutePosition" in script:
            pos = _folded_position(script, self.head)
            lines = []
            if pos is not None:
                lines.append("HEADX=" + str(pos[0]))
                lines.append("HEADY=" + str(pos[1]))
            lines.append("RC=0")
            item = pswindows.PSResult(stdout="\n".join(lines), returncode=0)
        elif "Msvm_VideoHead" in script:
            item = pswindows.PSResult(
                stdout=json.dumps(
                    {"horizontal": self.head[0], "vertical": self.head[1]}),
                returncode=0)
        elif "RC=" in script or "CHUNK" in script or "SETPOS" in script or "DOWN" in script:
            item = pswindows.PSResult(stdout="RC=1 CHUNK=1/1", returncode=0)
        else:
            item = pswindows.PSResult(stdout="", returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


@pytest.fixture(autouse=True)
def _clean_citation_state():
    """Isolate the console module's capture-citation registry between tests:
    reset before and after so no registration leaks across tests. The reset
    function is itself part of the pinned surface; it is guarded so the
    PRE-FIX tree fails inside the tests on their own missing surface, not
    in this fixture."""
    reset = getattr(console, "reset_input_ledger", None)
    if reset:
        reset()
    yield
    if reset:
        reset()


# ---------------------------------------------------------------------------
# #125 AC1: content_rect in capture metadata
# ---------------------------------------------------------------------------

def test_content_rect_excludes_letterbox_bands(monkeypatch, unrestricted):
    # AC1 (125): a capture at an aspect different from the head reports a
    # content_rect that excludes the letterbox bands, with the head at capture.
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    img, meta = console.screenshot(unrestricted, "vm1", width=1024, height=768)
    assert img.size == (1024, 768)
    assert "content_rect" in meta, (
        "issue #125: capture metadata must carry content_rect "
        "([left, top, right, bottom] of the non-letterbox pixels)"
    )
    # 1024 wide at a 1920x1010 head: content height 538, bands 115/115,
    # content rows 115..652 -> exclusive rect [0, 115, 1024, 653].
    assert meta["content_rect"] == LETTERBOX_RECT
    # the capture-time head resolution is the existing metadata key
    assert meta["head_resolution"] == {"horizontal": 1920, "vertical": 1010}


# ---------------------------------------------------------------------------
# #125 AC2: mapping goes through the content rect
# ---------------------------------------------------------------------------

def test_scale_maps_through_content_rect():
    # AC2 (125): frame coordinates map through the content rect — the first
    # content row maps to head row 0 and the last content row to the bottom
    # of the head (the anchor's round+clamp semantics, applied rect-relative;
    # the base's full-frame mapping is pinned alongside as the defect).
    # first content row (image y=115) -> head row 0 (base maps it to 151)
    assert _scale_to_head(
        512, 115, 1024, 768, HEAD_WIDE) == (960, 151)
    assert _scale_to_head(
        512, 115, 1024, 768, HEAD_WIDE, content_rect=LETTERBOX_RECT) == (960, 0)
    # last content row (image y=652): the rect mapping reaches head row 1008
    # of 1010 (round((652-115) * 1010/538)); the base maps it to 857 — 151
    # head rows short, the systematic error the issue reports.
    assert _scale_to_head(
        512, 652, 1024, 768, HEAD_WIDE) == (960, 857)
    assert _scale_to_head(
        512, 652, 1024, 768, HEAD_WIDE, content_rect=LETTERBOX_RECT) == (960, 1008)
    # rect equivalence (coordinator class-compliance edit): a full-frame rect
    # and no rect at all are the SAME mapping — the property AC6's PRESERVING
    # row cannot pin at base because the parameter does not exist there.
    assert _scale_to_head(320, 240, 640, 480, (1024, 768)) == (512, 384)
    assert _scale_to_head(
        9999, 9999, 640, 480, (1024, 768),
        content_rect=[0, 0, 640, 480]) == (1023, 767)


# ---------------------------------------------------------------------------
# #125 AC3: band clicks are refused, no mouse input
# ---------------------------------------------------------------------------

def test_click_in_band_is_refused(monkeypatch, unrestricted):
    # AC3 (125): a click targeting a point inside a letterbox band is
    # refused with a structured error and sends no mouse input.
    fake = FakePS(head=HEAD_WIDE)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture(
        "b" * 64, head_resolution=HEAD_WIDE,
        content_rect=list(LETTERBOX_RECT), vm_name="vm1")
    # y=10 is inside the top band (content starts at row 115)
    with pytest.raises(ConsoleError, match="letterbox"):
        console.click(unrestricted, "vm1", 512, 10,
                      frame_width=1024, frame_height=768, frame_hash="b" * 64)
    assert not any("ClickButton" in s for s in fake.scripts), (
        "a band point has no head-space meaning; no mouse input may be sent"
    )
    assert not any("SetAbsolutePosition" in s for s in fake.scripts)


# ---------------------------------------------------------------------------
# #125 AC4: height-omitted capture defaults to the head's aspect
# ---------------------------------------------------------------------------

def test_default_height_follows_head_aspect(monkeypatch, unrestricted):
    # AC4 (125): a screenshot requested with a width and no height
    # (height=0) captures at the head's aspect for that width — 1024 wide
    # at a 1920x1080 head is 1024x576, which is band-free.
    fake = FakePS(head=(1920, 1080))
    monkeypatch.setattr(pswindows, "run_ps", fake)
    img, meta = console.screenshot(unrestricted, "vm1", width=1024, height=0)
    capture = next(
        s for s in fake.scripts if "GetVirtualSystemThumbnailImage" in s)
    assert _folded_size(capture) == (1024, 576), (
        "the capture request must be 1024 x round(1024 * 1080 / 1920) = 1024x576"
    )
    assert img.size == (1024, 576)
    assert meta["width"] == 1024 and meta["height"] == 576
    # a head-aspect capture has no letterbox bands: the rect is the full frame
    assert meta["content_rect"] == [0, 0, 1024, 576]


# ---------------------------------------------------------------------------
# #125 AC5: stale head resolution refuses the click
# ---------------------------------------------------------------------------

def test_click_on_stale_head_resolution_is_refused(monkeypatch, unrestricted):
    # AC5 (125): a click citing a capture whose recorded head resolution
    # differs from the current head is refused with a stale-frame error and
    # sends no mouse input.
    fake = FakePS(head=(1920, 1200))  # the head changed after the capture
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture(
        "c" * 64, head_resolution=(1920, 1080),
        content_rect=[0, 0, 1024, 576], vm_name="vm1")
    with pytest.raises(ConsoleError, match="stale"):
        console.click(unrestricted, "vm1", 512, 288,
                      frame_width=1024, frame_height=576, frame_hash="c" * 64)
    assert not any("ClickButton" in s for s in fake.scripts), (
        "a frame captured at a different head resolution must not be clicked "
        "through: the refusal precedes any mouse input"
    )
    assert not any("SetAbsolutePosition" in s for s in fake.scripts)


# ---------------------------------------------------------------------------
# #125 AC6: same-aspect mapping unchanged (regression floor)
# ---------------------------------------------------------------------------

def test_same_aspect_mapping_unchanged():
    # AC6 (125): same-aspect frames map EXACTLY as the anchor does — the base
    # (no-rect) call signature keeps the base round+clamp results, including
    # the clamped bounds. Rect-equivalence (full-frame rect == no rect) is
    # pinned by test_scale_maps_through_content_rect (AC2), because a test
    # that passes content_rect cannot be GREEN at the base for the PRESERVING
    # class (the parameter does not exist there).
    base_head = (1024, 768)
    # anchor values already pinned by tests/unit/test_console.py
    assert _scale_to_head(320, 240, 640, 480, base_head) == (512, 384)
    assert _scale_to_head(9999, 9999, 640, 480, base_head) == (1023, 767)
    assert _scale_to_head(100, 50, 1024, 768, base_head) == (100, 50)
