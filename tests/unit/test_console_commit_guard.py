"""Issue #126 acceptance checks: the opt-in commit guard on console clicks.

Authored BEFORE the fix exists (arm's-length check author): these tests are
the frozen contract the implementation must satisfy. A guarded click must
cite a FRESH verification — a `verified_frame_hash` captured after the most
recent input to that VM — and the cited hash must match the live frame.

Pinned module surface (names from the issue's own vocabulary):

  - `console.click` gains `commit_guard: bool = False` and
    `verified_frame_hash: str = ""` (plus the issue #125 `frame_hash=`
    citation parameter). Without `commit_guard` the click is exactly the
    base call path and result (AC5).
  - `console.record_console_input(vm_name="", vm_id="")` — records an input
    to that VM in the module's input ledger ("the most recent input to that
    VM"; the guard treats a capture at-or-before that stamp as stale).
  - `console.register_capture(frame_hash, head_resolution=None,
    content_rect=None, vm_name="", vm_id="")` — registers a capture for
    citation (freshness ordering and, with issue #125, the content rect and
    head at capture).
  - `console.reset_input_ledger()` — clears the input ledger and the
    capture-citation registry (test isolation).
  - A guarded click verifies against a live capture taken at the caller's
    cited frame size (the cited hash's pixel domain — any other size could
    never match), inside the locked region, before any mouse input.
  - Refusals are structured ConsoleErrors ("commit_unverified" when no
    verification is cited, "stale" when the cited capture predates the last
    input, the live hash reported in the message on a mismatch) and send no
    mouse input. An allowed guarded click audits its decision through the
    existing audit log (auditlog's configured audit_log_path sink).

Every Hyper-V leg is the FakePS folded-transport stub pattern from
tests/unit/test_console.py; payloads are synthetic RGB565 bytes. No live
host, no sleeps, no cross-test state (the ledger is reset around each
test).

Expected on the PRE-FIX tree: every test fails on the missing surface —
TypeError on the absent `commit_guard` parameter, AttributeError on the
absent `console.register_capture`/`console.record_console_input` — never
on collection.
"""

import base64
import json
import re

import pytest

from hyperv_mcp import auditlog, console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

FRAME_W, FRAME_H = 320, 240   # 4:3, same aspect as the fake 1024x768 head


def _marker_payload(w: int, h: int) -> bytes:
    """Deterministic non-uniform RGB565 payload (4-byte opaque prefix +
    w*h little-endian pixels) so the live frame hash is stable and never
    accidentally equals a cited dummy hash."""
    return b"\x00\x00\x00\x00" + b"\x5a\xa5" * (w * h)


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
    FakePS. The live frame is the marker payload at whatever size a capture
    script requests, so a test can know the live hash ahead of the call."""

    def __init__(self, responses=(), head=(1024, 768)):
        self.scripts = []
        self.kwargs = []
        self.responses = list(responses)
        self.head = head

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if self.responses:
            item = self.responses.pop(0)
        elif "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            item = pswindows.PSResult(stdout=GUID, returncode=0)
        elif "GetVirtualSystemThumbnailImage" in script:
            w, h = _folded_size(script)
            payload = _marker_payload(w, h)
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
def _clean_ledger():
    """Reset the module's input ledger and capture-citation registry around
    every test so freshness ordering never leaks across tests. The reset is
    itself part of the pinned surface; it is guarded so the PRE-FIX tree
    fails inside the tests on their own missing surface, not here."""
    reset = getattr(console, "reset_input_ledger", None)
    if reset:
        reset()
    yield
    if reset:
        reset()


# ---------------------------------------------------------------------------
# #126 AC1: no verification cited -> commit_unverified, no mouse input
# ---------------------------------------------------------------------------

def test_guarded_click_without_verification_is_refused(monkeypatch, unrestricted):
    # AC1 (126): commit_guard with no verified_frame_hash cited refuses
    # with commit_unverified and sends no mouse input.
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ConsoleError, match="commit_unverified"):
        console.click(unrestricted, "vm1", 160, 120,
                      frame_width=FRAME_W, frame_height=FRAME_H,
                      commit_guard=True)
    assert not any("ClickButton" in s for s in fake.scripts), (
        "an unverified commit click must send no mouse input"
    )
    assert not any("SetAbsolutePosition" in s for s in fake.scripts)


# ---------------------------------------------------------------------------
# #126 AC2: verification captured at-or-before the last input is stale
# ---------------------------------------------------------------------------

def test_verification_older_than_last_input_is_stale(monkeypatch, unrestricted):
    # AC2 (126): a cited hash captured before the most recent input to that
    # VM proves nothing about the selection — the guarded click is refused
    # as stale and sends no mouse input.
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture("d" * 64, vm_name="vm1")   # the verification
    console.record_console_input(vm_name="vm1")         # the selecting click
    with pytest.raises(ConsoleError, match="stale"):
        console.click(unrestricted, "vm1", 160, 120,
                      frame_width=FRAME_W, frame_height=FRAME_H,
                      commit_guard=True, verified_frame_hash="d" * 64)
    assert not any("ClickButton" in s for s in fake.scripts)
    assert not any("SetAbsolutePosition" in s for s in fake.scripts)


# ---------------------------------------------------------------------------
# #126 AC3: hash mismatch refuses and reports the live hash
# ---------------------------------------------------------------------------

def test_hash_mismatch_refuses_with_live_hash(monkeypatch, unrestricted):
    # AC3 (126): a fresh but non-matching cited hash refuses inside the
    # locked region and the error REPORTS THE LIVE hash; no mouse input.
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.register_capture("e" * 64, vm_name="vm1")   # fresh, wrong hash
    with pytest.raises(ConsoleError) as excinfo:
        console.click(unrestricted, "vm1", 160, 120,
                      frame_width=FRAME_W, frame_height=FRAME_H,
                      commit_guard=True, verified_frame_hash="e" * 64)
    # the live hash: the guard must have taken a real capture, and the
    # refusal must name the hash of the frame it actually saw
    captures = [s for s in fake.scripts if "GetVirtualSystemThumbnailImage" in s]
    assert captures, "the guard must capture the live frame to hash it"
    w, h = _folded_size(captures[-1])
    assert (w, h) != (0, 0), "the live capture size must be inspectable"
    live_hash = console._frame_hash(_marker_payload(w, h))
    assert live_hash != "e" * 64  # sanity: the fixture really mismatches
    assert live_hash in str(excinfo.value), (
        "the mismatch refusal must report the live frame hash"
    )
    assert not any("ClickButton" in s for s in fake.scripts)
    assert not any("SetAbsolutePosition" in s for s in fake.scripts)


# ---------------------------------------------------------------------------
# #126 AC4: fresh + matching verification clicks and audits
# ---------------------------------------------------------------------------

def test_fresh_verification_allows_click_and_audits(monkeypatch, tmp_path):
    # AC4 (126): a guarded click citing a fresh, matching verification
    # performs the click AND records the guard decision in the audit log.
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    # route auditlog's sink at this config without leaking it past the test
    monkeypatch.setattr(auditlog, "_config", cfg)
    # the live capture at the caller's frame size serves the marker payload,
    # so its pixel-domain hash is known before the click
    verified_hash = console._frame_hash(_marker_payload(FRAME_W, FRAME_H))
    console.record_console_input(vm_name="vm1")          # the selecting click
    console.register_capture(verified_hash, vm_name="vm1")  # captured AFTER it
    out = console.click(cfg, "vm1", 160, 120,
                        frame_width=FRAME_W, frame_height=FRAME_H,
                        commit_guard=True, verified_frame_hash=verified_hash)
    # the click proceeded: same positional behavior as an unguarded click
    assert out["ok"] is True
    assert out["vm_name"] == "vm1"
    assert out["head_x"] == 512 and out["head_y"] == 384
    assert any("ClickButton" in s for s in fake.scripts), (
        "a fresh matching verification must let the click through"
    )
    # the guard's decision landed in the existing audit log
    assert audit.exists(), "the guard decision must be audited"
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [
        r for r in rows
        if r.get("vm_name") == "vm1" and "commit_guard" in json.dumps(r)
    ]
    assert guard_rows, (
        "an audit row for vm1 must record the commit_guard decision"
    )


# ---------------------------------------------------------------------------
# #126 AC5: unguarded click unchanged (regression floor)
# ---------------------------------------------------------------------------

def test_unguarded_click_unchanged(monkeypatch, unrestricted):
    # AC5 (126): without commit_guard the click behaves exactly as base —
    # the base call signature (no new kwarg: a PRESERVING check must stay
    # GREEN at the base, where the parameter does not exist; the opt-in
    # parameter's existence is pinned by the guard tests above) drives the
    # same call path (positional script, no verification capture) and the
    # same result keys and values as the anchor's click.
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.click(unrestricted, "vm1", 160, 120,
                        frame_width=FRAME_W, frame_height=FRAME_H)
    # the anchor's positional-click result, key for key
    assert set(out) == {"ok", "operation", "vm_name", "head_x", "head_y", "timings"}
    assert out["ok"] is True
    assert out["operation"] == "click button 1"
    assert out["vm_name"] == "vm1"
    assert out["head_x"] == 512 and out["head_y"] == 384
    # the anchor's call path: one folded positional script, no capture leg
    assert any("ClickButton" in s for s in fake.scripts)
    assert any("SetAbsolutePosition" in s for s in fake.scripts)
    assert not any("GetVirtualSystemThumbnailImage" in s for s in fake.scripts), (
        "an unguarded click must not take a verification capture"
    )
