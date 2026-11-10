"""WMI-transport guard pins for the opt-in console commit guard (issue #126)
and the sequence-guard plan-build refusals (review round 1, trace
125-126-console-accuracy-commit-guard, findings 2 and 3).

The frozen contract (tests/unit/test_console_commit_guard.py and
tests/unit/test_console_commit_guard_sequence.py) scopes to the folded
PowerShell transport — conftest pins wmiconsole.COM_AVAILABLE False — which
left the WMI lane's guard legs unpinned. These tests drive the WMI transport
over a FAKE backend (never real COM) after the FakeWMI/wmi_path pattern in
tests/unit/test_f04_sequence_wmi.py (console._try_backend monkeypatched to
hand back the fake, which bypasses the COM gate) and pin:

  - the single-click guard (_commit_guard_check_wmi): the live verification
    capture is be.capture at the CALLER'S CITED (frame_width, frame_height)
    — any other size could never match — and it runs BEFORE any mouse call;
  - a fresh-but-mismatching citation refuses naming the LIVE frame hash and
    performs no mouse call;
  - the allow path performs the click with the mapped head coordinates and
    audits the decision (auditlog._config sink, after the frozen
    test_console_commit_guard.py::test_fresh_verification_allows_click_and_audits
    pattern);
  - the sequence guard inside _run_sequence_wmi: a stale verification (older
    than a recorded input) refuses with ZERO device calls, and a fresh,
    matching, composed precondition clicks and audits;
  - review Fix 2: a guarded sequence click step whose point is outside the
    cited content rect refuses at PLAN-BUILD (before the boot-epoch read,
    the precondition capture, or any input) with the letterbox refusal;
  - review Fix 3: a guarded click step must carry frame_width/frame_height
    equal to the sequence's width/height (ValueError at plan-build, before
    any backend selection).

No live host, no sleeps; the input ledger is reset around every test.
"""

import json

import pytest

from hyperv_mcp import auditlog, console, vmident, wmiconsole
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
FRAME_W, FRAME_H = 320, 240   # 4:3, same aspect as the fake 1024x768 head
RECT_FULL = [0, 0, FRAME_W, FRAME_H]


def _pixels(w: int, h: int, fill: int = 7) -> bytes:
    """Synthetic RGB565 payload (4-byte opaque prefix + w*h 2-byte pixels)
    after the f04 pattern, so a test knows the live frame hash ahead of the
    call: _frame_hash(_pixels(w, h)) is what be.capture serves."""
    return bytes([0, 0, 0, 0]) + bytes([fill]) * (w * h * 2)


class FakeWMI:
    """Minimal backend surface for the guard lanes (only what console.click
    and console.run_sequence call), after tests/unit/test_f04_sequence_wmi.py.
    Records capture sizes and click arguments so the tests can pin the
    guard's live-capture size and the mapped head coordinates."""

    def __init__(self, epoch: int = 1000, frame_fill: int = 7,
                 head: tuple[int, int] = (1024, 768)):
        self.calls: list[str] = []
        self.epoch = epoch
        self.frame_fill = frame_fill
        self.head = head
        self.capture_sizes: list[tuple[int, int]] = []
        self.clicks: list[tuple] = []

    def resolve_vm(self, cfg, vm_name="", vm_id=""):
        self.calls.append("resolve_vm")
        return vmident.VMRef(id=GUID, name=vm_name or "wmi-vm")

    def boot_epoch(self, guid):
        self.calls.append("boot_epoch")
        return self.epoch

    def capture(self, guid, width, height):
        self.calls.append("capture")
        self.capture_sizes.append((width, height))
        return _pixels(width, height, self.frame_fill), {}

    def head_resolution(self, guid):
        self.calls.append("head_resolution")
        return self.head, {}

    def mouse_move(self, guid, hx, hy):
        self.calls.append("mouse_move")
        return None, {}

    def mouse_click(self, guid, button, hx=None, hy=None):
        self.calls.append("mouse_click")
        self.clicks.append((guid, button, hx, hy))
        return None, {}

    def mouse_button(self, guid, button, is_down):
        self.calls.append("mouse_button")
        return None, {}

    def mouse_scroll(self, guid, delta):
        self.calls.append("mouse_scroll")
        return None, {}

    def type_text(self, guid, text):
        self.calls.append("type_text")
        return None, {}

    def type_scancodes(self, guid, codes):
        self.calls.append("type_scancodes")
        return None, {}


_DEVICE_CALLS = ("mouse_move", "mouse_click", "mouse_button", "mouse_scroll",
                 "type_text", "type_scancodes")


@pytest.fixture()
def wmi_path(monkeypatch):
    """Force the WMI transport selection with a fake backend factory (the
    conftest COM gate is bypassed exactly as in test_f04_sequence_wmi.py)."""
    def _install(backend: FakeWMI):
        monkeypatch.setattr(console, "_try_backend", lambda cfg: (backend, 0.0))
        return backend

    yield _install


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


@pytest.fixture(autouse=True)
def _clean_ledger():
    console.reset_input_ledger()
    yield
    console.reset_input_ledger()


def _live_hash() -> str:
    """The hash of the frame the fake backend serves at the cited size."""
    return console._frame_hash(_pixels(FRAME_W, FRAME_H))


def _register_verification(vhash: str, content_rect=RECT_FULL) -> None:
    console.register_capture(
        vhash, vm_name="wmi-vm", vm_id=GUID, frame_size=(FRAME_W, FRAME_H),
        head_resolution=(1024, 768), content_rect=list(content_rect))


def _guarded_step(vhash: str, x: int = 160, y: int = 120) -> dict:
    return {
        "action": "click", "x": x, "y": y,
        "frame_width": FRAME_W, "frame_height": FRAME_H, "button": 1,
        "commit_guard": True, "verified_frame_hash": vhash,
    }


# ---------------------------------------------------------------------------
# single-click guard on the WMI transport (_commit_guard_check_wmi)
# ---------------------------------------------------------------------------

def test_wmi_guarded_click_captures_at_the_cited_frame_size(
        wmi_path, unrestricted):
    """The guard's live verification capture is requested at the caller's
    cited (frame_width, frame_height) — the cited verification's pixel
    domain — and it runs BEFORE any mouse input (a guard that captured at
    any other size could never honestly match)."""
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    _register_verification(vhash)
    out = console.click(
        unrestricted, "wmi-vm", 160, 120,
        frame_width=FRAME_W, frame_height=FRAME_H,
        commit_guard=True, verified_frame_hash=vhash)
    assert out["ok"] is True
    assert be.capture_sizes == [(FRAME_W, FRAME_H)], (
        "the guard's live capture must run at exactly the caller's cited "
        f"frame size; saw {be.capture_sizes}"
    )
    assert be.calls.index("capture") < be.calls.index("mouse_click"), (
        "the guard must verify the live frame BEFORE any mouse input"
    )


def test_wmi_guarded_click_mismatch_refuses_naming_the_live_hash(
        wmi_path, unrestricted):
    """A fresh but non-matching cited hash refuses with no mouse call, and
    the refusal REPORTS the live frame hash (the hash of the frame the guard
    actually captured, not the citation)."""
    be = wmi_path(FakeWMI())
    _register_verification("e" * 64)   # fresh, wrong hash
    live = _live_hash()
    assert live != "e" * 64            # sanity: the fixture really mismatches
    with pytest.raises(ConsoleError) as excinfo:
        console.click(
            unrestricted, "wmi-vm", 160, 120,
            frame_width=FRAME_W, frame_height=FRAME_H,
            commit_guard=True, verified_frame_hash="e" * 64)
    assert live in str(excinfo.value), (
        "the mismatch refusal must report the live frame hash"
    )
    assert be.calls.count("mouse_click") == 0
    assert be.calls.count("mouse_move") == 0


def test_wmi_guarded_click_fresh_matching_allows_and_audits(
        wmi_path, monkeypatch, tmp_path):
    """A fresh, matching verification lets the click through with the mapped
    head coordinates AND records the guard decision in the audit log (the
    auditlog._config sink, after the frozen
    test_console_commit_guard.py::test_fresh_verification_allows_click_and_audits
    pattern)."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # selecting input
    _register_verification(vhash)                               # captured AFTER it
    out = console.click(
        cfg, "wmi-vm", 160, 120,
        frame_width=FRAME_W, frame_height=FRAME_H,
        commit_guard=True, verified_frame_hash=vhash)
    assert out["ok"] is True
    assert out["head_x"] == 512 and out["head_y"] == 384
    assert be.clicks == [(GUID, 1, 512, 384)], (
        "the allow path must click at the head-mapped coordinates"
    )
    assert audit.exists(), "the guard decision must be audited"
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [
        r for r in rows
        if r.get("vm_name") == "wmi-vm" and "commit_guard" in json.dumps(r)
    ]
    assert guard_rows, "an audit row for wmi-vm must record the guard decision"
    assert guard_rows[0]["category"] == "console_input", (
        "the guard's audit row must carry the console_input category "
        f"(saw {guard_rows[0].get('category')!r})"
    )


# ---------------------------------------------------------------------------
# sequence guard inside _run_sequence_wmi (freshness + audit at dispatch)
# ---------------------------------------------------------------------------

def test_wmi_sequence_guard_stale_refusal_before_any_input(
        wmi_path, monkeypatch, tmp_path, unrestricted):
    """A verification older than a recorded input refuses STALE at dispatch,
    after the frame precondition matched but before any device input: zero
    mouse/keyboard calls escape the refused guard, and (the PRR-018
    audit-on-ok rule) no allow-shaped guard row is written."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    _register_verification(vhash)
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # now stale
    with pytest.raises(ConsoleError, match="stale"):
        console.run_sequence(
            cfg, "wmi-vm", [_guarded_step(vhash)],
            expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    device = [c for c in be.calls if c in _DEVICE_CALLS]
    assert device == [], (
        f"a stale sequence guard must dispatch ZERO device calls; saw {device}"
    )
    rows = (
        [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
        if audit.exists() else []
    )
    guard_rows = [
        r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert guard_rows == [], (
        "a stale-refused sequence guard must write no allow-shaped row"
    )


def test_wmi_sequence_guard_allow_clicks_and_audits(
        wmi_path, monkeypatch, tmp_path):
    """A fresh, matching, composed guarded click step passes the precondition
    (which IS the live-frame leg), clicks at the head-mapped coordinates, and
    audits the guard decision."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # selecting input
    _register_verification(vhash)                               # captured AFTER it
    out = console.run_sequence(
        cfg, "wmi-vm", [_guarded_step(vhash)],
        expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    assert out["ok"] is True, out
    assert out["steps"][0]["ok"] is True
    assert be.clicks == [(GUID, 1, 512, 384)], (
        "the allowed sequence guard must click at the head-mapped coordinates"
    )
    assert audit.exists(), "the allowed sequence guard must be audited"
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [
        r for r in rows
        if r.get("vm_name") == "wmi-vm" and "commit_guard" in json.dumps(r)
    ]
    assert guard_rows, "an audit row for wmi-vm must record the sequence guard"


# ---------------------------------------------------------------------------
# review round 1, Fix 2 and Fix 3: plan-build refusals before any dispatch
# ---------------------------------------------------------------------------

def test_wmi_guard_band_point_refused_at_plan_build(wmi_path, unrestricted):
    """Fix 2: a guarded click step whose point is outside the cited content
    rect refuses at PLAN-BUILD — before the boot-epoch read, the frame
    precondition capture, or any input — with the letterbox refusal naming
    the cited rect (a dispatch-time-only refusal would first hit the
    backend's boot_epoch/capture legs and report a failed step entry)."""
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    # a letterboxed 320x240 at a 1010-tall head: the top band starts at y=115
    _register_verification(
        vhash, content_rect=[0, 115, FRAME_W, 115 + 238])
    with pytest.raises(ConsoleError, match="letterbox band") as excinfo:
        console.run_sequence(
            unrestricted, "wmi-vm",
            [_guarded_step(vhash, x=160, y=10)],   # y=10 is inside the band
            expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    assert "outside the cited capture's content rect" in str(excinfo.value), (
        "the plan-build refusal must name the cited content rect"
    )
    assert "boot_epoch" not in be.calls and "capture" not in be.calls, (
        "the refusal must fire before the sequence runs any backend leg"
    )
    device = [c for c in be.calls if c in _DEVICE_CALLS]
    assert device == [], "a plan-build refusal must dispatch nothing"


def test_wmi_guarded_step_requires_frame_dims(wmi_path, unrestricted):
    """Fix 3: a guarded click step must carry frame_width/frame_height equal
    to the sequence's width/height — the guard maps the step's coordinates
    through the cited verification's pixel domain. Both a missing and a
    mismatched pair raise the frame-domain ValueError at plan-build, before
    any backend selection (the fake records no call at all)."""
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    _register_verification(vhash)
    missing = {
        "action": "click", "x": 160, "y": 120, "button": 1,
        "commit_guard": True, "verified_frame_hash": vhash,
    }
    with pytest.raises(ValueError, match="frame_width/frame_height equal"):
        console.run_sequence(
            unrestricted, "wmi-vm", [missing],
            expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    mismatched = {
        "action": "click", "x": 160, "y": 120,
        "frame_width": 640, "frame_height": 480, "button": 1,
        "commit_guard": True, "verified_frame_hash": vhash,
    }
    with pytest.raises(ValueError, match="frame_width/frame_height equal"):
        console.run_sequence(
            unrestricted, "wmi-vm", [mismatched],
            expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    assert be.calls == [], (
        "the frame-domain ValueError must fire before any backend call"
    )


# ---------------------------------------------------------------------------
# review round 2: the rect-less citation no-op + the no-coordinate refusal
# ---------------------------------------------------------------------------

def test_wmi_sequence_guard_rectless_verification_maps_through_base(
        wmi_path, unrestricted):
    """Review round 2, Finding 1: a verification registered WITHOUT a
    content_rect (a headless-provenance capture) keeps the anchor's
    FULL-FRAME mapping — the plan-build band check is a no-op for a rect-less
    citation instead of crashing on None, and the step's coordinates map
    through the base scaling (320x240 frame at the 1024x768 head:
    (160,120) -> (512,384))."""
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # selecting input
    console.register_capture(                     # captured AFTER it, NO rect
        vhash, vm_name="wmi-vm", vm_id=GUID,
        frame_size=(FRAME_W, FRAME_H), head_resolution=(1024, 768))
    out = console.run_sequence(
        unrestricted, "wmi-vm", [_guarded_step(vhash)],
        expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    assert out["ok"] is True, out
    step = out["steps"][0]
    assert step["ok"] is True, step
    assert step["head_x"] == 512 and step["head_y"] == 384, (
        "a rect-less citation must map through the full-frame base scaling"
    )
    assert be.clicks == [(GUID, 1, 512, 384)], (
        "the click must dispatch at the base-mapped head coordinates"
    )


def test_no_coordinate_guarded_click_step_refused(wmi_path, unrestricted):
    """Review round 2, Finding 2: a click-at-current-position step carrying
    commit_guard/verified_frame_hash is refused at plan-build — there is no
    point to band-check or map through the cited pixel domain, and silently
    dropping the opt-in safety parameter (the previous behavior: the guard
    keys vanished from the mouse_click_here plan entry and the click
    dispatched UNGUARDED) is worse than a rejection. Zero backend calls."""
    be = wmi_path(FakeWMI())
    steps = [{"action": "click", "button": 1,
              "commit_guard": True, "verified_frame_hash": "a" * 64}]
    with pytest.raises(ValueError, match="not supported on a click step without x/y"):
        console.run_sequence(
            unrestricted, "wmi-vm", steps,
            expect_frame_hash="a" * 64, width=FRAME_W, height=FRAME_H)
    assert be.calls == [], (
        "the no-coordinate guard refusal must fire at plan-build, before any "
        "backend call"
    )


# ---------------------------------------------------------------------------
# final-critic round 1: the size-less citation fall-through
# ---------------------------------------------------------------------------

def test_wmi_sequence_guard_sizeless_verification_falls_through(
        wmi_path, unrestricted):
    """Final-critic round 1, Finding 2: a verification registered WITHOUT a
    frame_size (frame_size=None — e.g. an explicitly registered out-of-band
    capture) FALLS THROUGH _sequence_guard_prepare's pixel-domain check, the
    same None fallback the single-click path's _commit_guard_record applies
    (console.py's two `is not None` guards are deliberately identical): the
    guarded sequence proceeds, the precondition capture is the live-frame
    leg, and the click dispatches at the base-mapped head coordinates."""
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # selecting input
    console.register_capture(                  # captured AFTER it, NO frame_size
        vhash, vm_name="wmi-vm", vm_id=GUID, head_resolution=(1024, 768))
    out = console.run_sequence(
        unrestricted, "wmi-vm", [_guarded_step(vhash)],
        expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    assert out["ok"] is True, out
    step = out["steps"][0]
    assert step["ok"] is True, step
    assert step["head_x"] == 512 and step["head_y"] == 384
    assert be.clicks == [(GUID, 1, 512, 384)], (
        "the size-less citation must let the guarded click dispatch"
    )


# ---------------------------------------------------------------------------
# feedback round (trace 125-126-console-accuracy-commit-guard, PR #139):
# the WMI no-coordinates head check, the single-click guard coordinate
# requirement, (vm_key, hash) registry keying + cap, the negative vhash pin,
# no-row refusals, dims validation, and audit attribution
# ---------------------------------------------------------------------------

def test_wmi_no_coords_cited_click_runs_head_check(wmi_path, unrestricted):
    """NEW-13: a frame_hash citation on a click WITHOUT coordinates still
    gets the stale-head refusal on the WMI lane (parity with the PS lane's
    head-only preflight): the recorded head differs from the live head →
    ConsoleError 'stale frame' with ZERO mouse calls (the head compare needs
    no positional script)."""
    be = wmi_path(FakeWMI(head=(1920, 1010)))
    console.register_capture(
        "1" * 64, vm_name="wmi-vm", vm_id=GUID, frame_size=(FRAME_W, FRAME_H),
        head_resolution=(1024, 768))
    with pytest.raises(ConsoleError, match="stale frame"):
        console.click(unrestricted, "wmi-vm", frame_hash="1" * 64)
    assert "head_resolution" in be.calls, "the head compare must actually run"
    assert be.calls.count("mouse_click") == 0
    assert be.calls.count("mouse_move") == 0


def test_single_click_guard_requires_coordinates(unrestricted):
    """PRR-015: a single guarded click without x/y refuses with the sequence
    wording's mirror — click-at-current-position has no point to band-check
    or map through the cited pixel domain, so the guard fails CLOSED rather
    than silently dispatching an unverified commit click."""
    with pytest.raises(ValueError) as excinfo:
        console.click(
            unrestricted, "wmi-vm",
            commit_guard=True, verified_frame_hash="2" * 64)
    message = str(excinfo.value)
    assert "not supported on a click without x/y" in message
    assert "give x/y or drop the guard" in message, (
        "the refusal must mirror the sequence wording's remedy"
    )


def test_registry_keyed_per_vm(unrestricted):
    """PRR-006: the capture registry keys on the (vm_key, frame_hash) TUPLE —
    the SAME pixel hash registered for two VMs (login screens, black
    consoles) keeps BOTH records, and a re-registration for one VM refreshes
    only its own entry."""
    h = "3" * 64
    console.register_capture(h, vm_name="pr0006-a", frame_size=(320, 240))
    first = console._lookup_capture(h, "pr0006-a")
    console.register_capture(h, vm_name="pr0006-b", frame_size=(320, 240))
    second = console._lookup_capture(h, "pr0006-b")
    assert first is not None and second is not None, (
        "two VMs citing pixel-identical frames must keep independent records"
    )
    again = console._lookup_capture(h, "pr0006-a")
    assert again is not None and again["seq"] == first["seq"], (
        "registering the hash for VM B must not refresh VM A's entry"
    )
    assert second["seq"] > first["seq"]  # one monotonic counter, sane order


def test_registry_capped(unrestricted):
    """PRR-016: the registry is FIFO-capped at _REGISTRY_CAP entries — 520
    distinct registrations leave at most the cap, the OLDEST evicted, the
    newest retained."""
    vm = "pr0016-vm"
    hashes = [f"{i:064x}" for i in range(520)]
    for entry in hashes:
        console.register_capture(entry, vm_name=vm, frame_size=(320, 240))
    assert len(console._CAPTURE_REGISTRY) <= console._REGISTRY_CAP, (
        f"the registry must stay bounded at {console._REGISTRY_CAP}; "
        f"saw {len(console._CAPTURE_REGISTRY)}"
    )
    assert console._lookup_capture(hashes[0], vm) is None, (
        "FIFO eviction must drop the oldest insertion first"
    )
    assert console._lookup_capture(hashes[-1], vm) is not None


def test_vhash_without_commit_guard_refuses(unrestricted):
    """PRR-021 (negative pin, console.py): a verified_frame_hash with the
    commit guard left OFF refuses — the citation is meaningless without the
    guard it verifies, and silently ignoring it would invite a false sense
    of verification."""
    with pytest.raises(ValueError,
                       match="verified_frame_hash requires commit_guard=True"):
        console.click(
            unrestricted, "wmi-vm", 160, 120,
            verified_frame_hash="4" * 64)


def test_refusal_writes_no_audit_row(
        wmi_path, monkeypatch, tmp_path, unrestricted):
    """PRR-020: a guarded click refused for staleness writes NO guard row —
    only the ALLOW decision is audited (the refusal raises; nothing writes
    an allow-shaped console_click_commit_guard row)."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    be = wmi_path(FakeWMI())
    vhash = _live_hash()
    _register_verification(vhash)
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # now stale
    with pytest.raises(ConsoleError, match="stale verification"):
        console.click(
            cfg, "wmi-vm", 160, 120,
            frame_width=FRAME_W, frame_height=FRAME_H,
            commit_guard=True, verified_frame_hash=vhash)
    assert be.calls.count("mouse_click") == 0
    rows = (
        [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
        if audit.exists() else []
    )
    guard_rows = [
        r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert guard_rows == [], (
        "a refused guard must write no allow-shaped audit row"
    )


def test_guard_capture_dims_validated(wmi_path, unrestricted):
    """PRR-029: the caller-cited pixel domain is re-validated against the
    160..4096 window inside _commit_guard_record — on the size-less record
    path (the record cannot supply the domain) an out-of-window pair refuses
    BEFORE the live verification capture ever spawns."""
    be = wmi_path(FakeWMI())
    console.register_capture(   # size-less: frame_size omitted entirely
        "5" * 64, vm_name="wmi-vm", vm_id=GUID, head_resolution=(1024, 768))
    with pytest.raises(ConsoleError) as excinfo:
        console.click(
            unrestricted, "wmi-vm", 160, 120,
            frame_width=100000, frame_height=240,
            commit_guard=True, verified_frame_hash="5" * 64)
    assert "160..4096" in str(excinfo.value)
    assert "100000x240" in str(excinfo.value), (
        "the refusal must report the offending dimensions"
    )
    assert "capture" not in be.calls, (
        "the dims refusal must fire before the live verification capture"
    )
    assert be.calls.count("mouse_click") == 0


def test_guard_audit_row_attributed(
        wmi_path, monkeypatch, tmp_path, unrestricted):
    """PRR-012: the guard's allow row attributes the authenticated caller —
    agent_id resolves from the auth-context sentinel (an explicit None used
    to override it and serialize null, losing the attribution the paired
    click row carries)."""
    from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
    from mcp.server.auth.provider import AccessToken

    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    wmi_path(FakeWMI())
    vhash = _live_hash()
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # selecting input
    _register_verification(vhash)                               # captured AFTER it
    token = auth_context_var.set(AuthenticatedUser(AccessToken(
        token="t", client_id="pr0012-agent", scopes=[])))
    try:
        out = console.click(
            cfg, "wmi-vm", 160, 120,
            frame_width=FRAME_W, frame_height=FRAME_H,
            commit_guard=True, verified_frame_hash=vhash)
    finally:
        auth_context_var.reset(token)
    assert out["ok"] is True
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [
        r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert guard_rows, "the allow decision must be audited"
    assert guard_rows[0]["agent_id"] == "pr0012-agent", (
        "the guard row must carry the authenticated caller's id, not null"
    )


# ---------------------------------------------------------------------------
# review round 2 (trace 125-126-console-accuracy-commit-guard, PR #139):
# PRR-028 sequence head parity, PRR-018 disposition-by-first-refusal and the
# step-gated WMI sequence audit
# ---------------------------------------------------------------------------

def test_wmi_sequence_guard_cited_head_refuses_before_dispatch(
        wmi_path, unrestricted):
    """PRR-028: a guarded sequence click whose cited verification was
    recorded at a DIFFERENT head than the live one refuses with the
    single-click path's 'stale frame' wording — the head compare runs after
    the frame precondition matched but BEFORE the positional step
    dispatches (parity with _check_cited_head and the PS lane's in-script
    %CITEDHEAD): zero device calls escape."""
    be = wmi_path(FakeWMI(head=(1920, 1080)))
    vhash = _live_hash()
    _register_verification(vhash)          # recorded head (1024, 768)
    with pytest.raises(ConsoleError) as excinfo:
        console.run_sequence(
            unrestricted, "wmi-vm", [_guarded_step(vhash)],
            expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    message = str(excinfo.value)
    assert "stale frame" in message
    assert "1024x768" in message and "1920x1080" in message, (
        "the refusal must name both the cited and the current head"
    )
    device = [c for c in be.calls if c in _DEVICE_CALLS]
    assert device == [], (
        f"a head-refused sequence guard must dispatch ZERO device calls; "
        f"saw {device}"
    )


def test_wmi_guarded_click_head_refusal_precedes_guard_audit(
        wmi_path, monkeypatch, tmp_path, unrestricted):
    """PRR-018 (disposition by the first refusing leg): a guarded click
    whose citation's head differs from the live head refuses 'stale frame'
    BEFORE the guard check runs — the guard itself would PASS (fresh,
    matching live hash), but the refusal must precede any guard decision,
    so the audit sink carries NO console_click_commit_guard row."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    be = wmi_path(FakeWMI(head=(1920, 1010)))
    vhash = _live_hash()
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # selecting input
    _register_verification(vhash)     # fresh, matching — only the head differs
    with pytest.raises(ConsoleError) as excinfo:
        console.click(
            cfg, "wmi-vm", 160, 120,
            frame_width=FRAME_W, frame_height=FRAME_H,
            commit_guard=True, verified_frame_hash=vhash)
    assert "stale frame" in str(excinfo.value)
    device = [c for c in be.calls if c in _DEVICE_CALLS]
    assert device == [], "the head refusal must precede any mouse input"
    rows = (
        [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
        if audit.exists() else []
    )
    guard_rows = [
        r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert guard_rows == [], (
        "a head-refused guarded click must write NO guard allow row — the "
        "refusal precedes the guard decision itself"
    )


def test_wmi_sequence_guard_precondition_refused_writes_no_row(
        wmi_path, monkeypatch, tmp_path, unrestricted):
    """PRR-018 (WMI audit-on-ok): a guarded sequence plan whose frame
    precondition REFUSES (the live hash differs from the cited one) returns
    the precondition envelope and writes no allow-shaped guard row on the
    WMI transport — the same audit-on-ok rule the PS lane pins."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    be = wmi_path(FakeWMI())
    _register_verification("e" * 64)      # fresh but NOT the live hash
    out = console.run_sequence(
        cfg, "wmi-vm", [_guarded_step("e" * 64)],
        expect_frame_hash="e" * 64, width=FRAME_W, height=FRAME_H)
    assert out["ok"] is False and out["error_class"] == "precondition"
    assert out["precondition"] == "frame_hash"
    device = [c for c in be.calls if c in _DEVICE_CALLS]
    assert device == [], "a precondition-refused plan dispatches nothing"
    rows = (
        [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
        if audit.exists() else []
    )
    guard_rows = [
        r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert guard_rows == [], (
        "a precondition-refused WMI sequence must write no allow row"
    )


class FailingClickWMI(FakeWMI):
    """The guarded step dispatches and the DEVICE fails: the per-step
    contract reports the failed entry (the plan result stays ok), and the
    guard's ALLOW audit must NOT have been written before the step ran."""

    def mouse_click(self, guid, button, hx=None, hy=None):
        self.calls.append("mouse_click")
        self.clicks.append((guid, button, hx, hy))
        raise wmiconsole.WMIError("ClickButton failed with ReturnValue=5")


def test_wmi_sequence_guard_failed_step_writes_no_row(
        wmi_path, monkeypatch, tmp_path, unrestricted):
    """PRR-018 (the moved audit): a guarded sequence click step whose DEVICE
    leg fails after the guard passed reports the failed step entry and
    writes NO allow-shaped guard row — the WMI lane's audit is gated on the
    guarded step's parsed entry being ok, exactly like the PS lane's (the
    row used to land at the precondition, before the step even ran)."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    be = wmi_path(FailingClickWMI())
    vhash = _live_hash()
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)  # selecting input
    _register_verification(vhash)                               # captured AFTER it
    out = console.run_sequence(
        cfg, "wmi-vm", [_guarded_step(vhash)],
        expect_frame_hash=vhash, width=FRAME_W, height=FRAME_H)
    assert out["ok"] is True, out
    assert out["steps"][0]["ok"] is False, (
        "the failed device leg must surface as the step's own failure"
    )
    assert "ReturnValue=5" in out["steps"][0]["error"]
    assert be.calls.count("mouse_click") == 1, (
        "the step must really have dispatched and failed its device leg"
    )
    rows = (
        [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
        if audit.exists() else []
    )
    guard_rows = [
        r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert guard_rows == [], (
        "a guarded step that FAILED after the guard passed must write no "
        "allow-shaped row"
    )
