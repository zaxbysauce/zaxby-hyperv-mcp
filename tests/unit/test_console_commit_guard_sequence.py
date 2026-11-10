"""Sequence-side guard pins for the opt-in console commit guard (issue #126,
plan F3b; regular post-anchor tests — the frozen contract lives in
tests/unit/test_console_commit_guard.py and tests/unit/test_console_aspect_fit.py).

Pins the folded-sequence click-step guard:
  - the guarded click must be the FIRST EXECUTED step (no wait steps, no
    anything, before it — a wait observes without input, so the frame can
    change during it and a verification taken before the wait proves nothing
    at dispatch);
  - expect_frame_hash == verified_frame_hash composition is REQUIRED (the
    sequence's precondition capture IS the guard's live-frame verification);
  - the cited record's frame_size must equal the sequence's (width, height)
    (pixel-domain alignment);
  - an unknown citation refuses at plan-build time;
  - freshness is re-checked at dispatch under the sequence lock (a stale
    verification refuses BEFORE the sequence command spawns);
  - an allowed sequence guard audits its decision through auditlog's
    configured sink.

Transport: the folded PowerShell one, with pswindows.run_ps stubbed after the
SeqPS pattern in tests/unit/test_f04_sequences.py (canned VMID/EPOCH/STEP
success — the host-side guard legs are what these pins drive; the frozen
precondition envelope tests already pin the in-script leg). No live host, no
sleeps; the ledger is reset around every test.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager

import pytest

from hyperv_mcp import auditlog, console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
SEQ_W, SEQ_H = 320, 240


class SeqPS:
    """Recording run_ps stub answering the folded sequence leg with the
    frozen success protocol (VMID/EPOCH + per-step OK), after the pattern in
    tests/unit/test_f04_sequences.py."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(
            stdout="VMID=" + GUID + "\nEPOCH=4242\nSTEP=0 OK=1\n",
            returncode=0,
        )


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


def _verification(head=(1024, 768), size=(SEQ_W, SEQ_H)) -> str:
    """Register a fresh unshaped verification at the sequence pixel domain
    and return its hash."""
    h = "a" * 64
    console.register_capture(
        h, head_resolution=head,
        content_rect=[0, 0, size[0], size[1]],
        vm_name="vm1", frame_size=size)
    return h


def _guarded_steps(vhash: str, x: int = 160, y: int = 120) -> list[dict]:
    return [{
        "action": "click", "x": x, "y": y,
        "frame_width": SEQ_W, "frame_height": SEQ_H, "button": 1,
        "commit_guard": True, "verified_frame_hash": vhash,
    }]


# ---------------------------------------------------------------------------
# plan-shape validation
# ---------------------------------------------------------------------------

def test_guarded_click_must_be_the_first_executed_step(unrestricted):
    """A guarded click at index > 0 is a step-indexed ValueError: nothing may
    precede it (the first executed step is plan[0] by construction)."""
    vhash = _verification()
    steps = [
        {"action": "press_key", "key": "enter"},
    ] + _guarded_steps(vhash)
    with pytest.raises(ValueError, match=r"step 1:.*first executed step"):
        console.run_sequence(
            unrestricted, "vm1", steps, expect_frame_hash=vhash,
            width=SEQ_W, height=SEQ_H)


def test_guarded_click_refuses_a_preceding_wait_step(unrestricted):
    """A wait step before the guarded click is refused with the no-wait
    wording: a wait observes without input, so the frame can change during
    it and a verification taken before it proves nothing at dispatch."""
    vhash = _verification()
    steps = [
        {"action": "wait_frame_stable", "stable_ms": 100, "timeout_s": 2,
         "interval_ms": 100},
    ] + _guarded_steps(vhash)
    with pytest.raises(ValueError, match=r"step 1:"):
        console.run_sequence(
            unrestricted, "vm1", steps, expect_frame_hash=vhash,
            width=SEQ_W, height=SEQ_H)


def test_guarded_click_requires_a_well_formed_hash(unrestricted):
    with pytest.raises(ValueError, match=r"step 0:.*64-char hex"):
        console.run_sequence(
            unrestricted, "vm1",
            [{"action": "click", "x": 1, "y": 1, "frame_width": SEQ_W,
              "frame_height": SEQ_H, "commit_guard": True,
              "verified_frame_hash": "not-a-hash"}],
            width=SEQ_W, height=SEQ_H)


def test_verified_frame_hash_requires_commit_guard(unrestricted):
    with pytest.raises(ValueError, match=r"step 0:.*requires commit_guard"):
        console.run_sequence(
            unrestricted, "vm1",
            [{"action": "click", "x": 1, "y": 1, "frame_width": SEQ_W,
              "frame_height": SEQ_H,
              "verified_frame_hash": "b" * 64}],
            width=SEQ_W, height=SEQ_H)


# ---------------------------------------------------------------------------
# composition + pixel-domain alignment
# ---------------------------------------------------------------------------

def test_guard_requires_expect_frame_hash_composition(unrestricted):
    """expect_frame_hash must EQUAL the step's verified_frame_hash: the
    precondition capture is the guard's live-frame verification, so the guard
    adds no capture of its own inside the plan."""
    vhash = _verification()
    with pytest.raises(ValueError, match="expect_frame_hash equal"):
        console.run_sequence(
            unrestricted, "vm1", _guarded_steps(vhash),
            expect_frame_hash="c" * 64, width=SEQ_W, height=SEQ_H)


def test_guard_refuses_wrong_pixel_domain(unrestricted, monkeypatch):
    """The cited record's registered frame_size must equal the sequence's
    (width, height): the precondition capture hashes that size, so any other
    domain could never match."""
    vhash = _verification(size=(640, 480))
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(console.ConsoleError, match="pixel domain"):
        console.run_sequence(
            unrestricted, "vm1", _guarded_steps(vhash),
            expect_frame_hash=vhash, width=SEQ_W, height=SEQ_H)
    assert stub.scripts == [], (
        "a pixel-domain misalignment must refuse before the sequence command "
        "spawns"
    )


def test_guard_refuses_unknown_citation(unrestricted, monkeypatch):
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(console.ConsoleError, match="commit_unverified"):
        console.run_sequence(
            unrestricted, "vm1", _guarded_steps("d" * 64),
            expect_frame_hash="d" * 64, width=SEQ_W, height=SEQ_H)
    assert stub.scripts == []


def test_guard_refuses_shaped_citation(unrestricted, monkeypatch):
    console.register_capture(
        "e" * 64, vm_name="vm1", frame_size=(SEQ_W, SEQ_H), shaped=True)
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(console.ConsoleError, match="shaped frame"):
        console.run_sequence(
            unrestricted, "vm1", _guarded_steps("e" * 64),
            expect_frame_hash="e" * 64, width=SEQ_W, height=SEQ_H)
    assert stub.scripts == []


# ---------------------------------------------------------------------------
# freshness re-check at dispatch + the allowed-and-audited path
# ---------------------------------------------------------------------------

def test_stale_verification_refuses_at_dispatch(unrestricted, monkeypatch):
    """The plan validates, but the input ledger moved between registration
    and dispatch: the freshness re-check inside the sequence lock refuses
    BEFORE the sequence command spawns."""
    vhash = _verification()
    console.record_console_input(vm_name="vm1")
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(console.ConsoleError, match="stale"):
        console.run_sequence(
            unrestricted, "vm1", _guarded_steps(vhash),
            expect_frame_hash=vhash, width=SEQ_W, height=SEQ_H)
    assert stub.scripts == [], "a stale guard must dispatch nothing"


def test_allowed_sequence_guard_clicks_and_audits(
        monkeypatch, unrestricted, tmp_path):
    """A fresh, aligned, composed guarded click dispatches the sequence and
    records the guard decision in the audit log (the allow path is audited
    exactly like the single-click guard)."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    vhash = _verification()
    console.record_console_input(vm_name="vm1")   # the selecting input
    vhash = "f" * 64                              # captured AFTER it
    console.register_capture(
        vhash, vm_name="vm1", frame_size=(SEQ_W, SEQ_H),
        head_resolution=(1024, 768),
        content_rect=[0, 0, SEQ_W, SEQ_H])
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        cfg, "vm1", _guarded_steps(vhash),
        expect_frame_hash=vhash, width=SEQ_W, height=SEQ_H)
    assert out["ok"] is True
    assert stub.scripts, "the allowed guard must dispatch the sequence"
    assert any("ClickButton" in s for s in stub.scripts)
    assert audit.exists(), "the allowed sequence guard must be audited"
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [
        r for r in rows
        if r.get("vm_name") == "vm1" and "commit_guard" in json.dumps(r)
    ]
    assert guard_rows, "an audit row for vm1 must record the sequence guard"


def test_guarded_sequence_threads_the_cited_rect_into_the_step(
        unrestricted, monkeypatch):
    """The verified record's content_rect reaches the sequence-step mapper:
    the emitted script carries the band literals and the rect-relative
    arithmetic (executed for real under the folded-protocol harness in
    test_console_aspect_fit_guardrail.py)."""
    head = (1024, 1010)
    rect = [0, 115, SEQ_W, 115 + 238]  # a letterboxed 320x240 at that head
    vhash = "1" * 64
    console.register_capture(
        vhash, vm_name="vm1", frame_size=(SEQ_W, SEQ_H),
        head_resolution=head, content_rect=rect)
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    steps = [{
        "action": "click", "x": 160, "y": 115 + 100,
        "frame_width": SEQ_W, "frame_height": 240, "button": 1,
        "commit_guard": True, "verified_frame_hash": vhash,
    }]
    out = console.run_sequence(
        unrestricted, "vm1", steps,
        expect_frame_hash=vhash, width=SEQ_W, height=SEQ_H)
    assert out["ok"] is True
    script = stub.scripts[-1]
    assert "$bandl = 0" in script and "$bandt = 115" in script, (
        "the cited rect's band literals must thread into the step mapper"
    )
    assert "($x - $bandl) * $hw / ($bandr - $bandl)" in script, (
        "the rect-relative arithmetic must be present"
    )


# ---------------------------------------------------------------------------
# feedback round (trace 125-126-console-accuracy-commit-guard, PR #139):
# audit-on-ok placement, strict-bool step keys, and the PRR-017 bump rule
# ---------------------------------------------------------------------------

class RefusedSeqPS:
    """Serves the folded sequence leg the in-script precondition's refusal
    protocol (exit 1 + the mismatch stderr line the frozen script emits)."""

    def __init__(self, expected: str, actual: str) -> None:
        self.scripts: list[str] = []
        self.expected = expected
        self.actual = actual

    def __call__(self, script: str, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(
            stdout="VMID=" + GUID + "\n",
            stderr="console sequence precondition mismatch: frame_hash "
                   "expected " + self.expected + " actual " + self.actual
                   + "\n",
            returncode=1,
        )


class TimeoutSeqPS:
    """The timed-out leg shim after test_f04_sequences.py's TimeoutSeqPS: the
    sequence command reports PSResult timed_out=True exactly the way the real
    run_ps does, so the post-dispatch outcome is unknowable."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(
            timed_out=True, returncode=None, duration_ms=7)


def test_guarded_step_audit_not_written_on_precondition_refusal(
        monkeypatch, unrestricted, tmp_path):
    """PRR-004: the guard's ALLOW audit row lands only after the in-script
    preconditions pass AND the guarded step parsed ok — a precondition-
    refused guarded plan returns the precondition envelope and writes NO
    audit row at all (audit-on-ok, never audit-on-attempt)."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    vhash = _verification()
    stub = RefusedSeqPS(vhash, "f" * 64)
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        cfg, "vm1", _guarded_steps(vhash),
        expect_frame_hash=vhash, width=SEQ_W, height=SEQ_H)
    assert out["ok"] is False
    assert out["error_class"] == "precondition"
    assert out["frame_hash"] == "f" * 64
    rows = (
        [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
        if audit.exists() else []
    )
    guard_rows = [
        r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert guard_rows == [], (
        "a precondition-refused plan must write no guard allow row"
    )


def test_allow_row_written_only_when_ok(monkeypatch, unrestricted, tmp_path):
    """PRR-020: the allowed sequence guard writes EXACTLY ONE audit row,
    tightened to field asserts — tool console_click_commit_guard, ok True,
    the VM's name, and the console_input category."""
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    console.record_console_input(vm_name="vm1")   # the selecting input
    vhash = "0" * 64                              # captured AFTER it
    console.register_capture(
        vhash, vm_name="vm1", frame_size=(SEQ_W, SEQ_H),
        head_resolution=(1024, 768), content_rect=[0, 0, SEQ_W, SEQ_H])
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        cfg, "vm1", _guarded_steps(vhash),
        expect_frame_hash=vhash, width=SEQ_W, height=SEQ_H)
    assert out["ok"] is True
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [
        r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert len(guard_rows) == 1, (
        f"exactly one allow row must be written; saw {len(guard_rows)}"
    )
    row = guard_rows[0]
    assert row["ok"] is True
    assert row["vm_name"] == "vm1"
    assert row["category"] == "console_input"


def test_strict_bool_commit_guard_rejected(unrestricted):
    """PRR-003: a truthy non-bool commit_guard on a click step is a
    step-indexed ValueError naming the key and the offending type — a string
    'false' must never silently ENABLE the guard (the guard keys ride
    untyped list[dict] steps; pydantic covers only the envelope)."""
    vhash = "a" * 64
    with pytest.raises(ValueError) as excinfo:
        console.run_sequence(
            unrestricted, "vm1",
            [{"action": "click", "x": 160, "y": 120,
              "frame_width": SEQ_W, "frame_height": SEQ_H, "button": 1,
              "commit_guard": "false", "verified_frame_hash": vhash}],
            expect_frame_hash=vhash, width=SEQ_W, height=SEQ_H)
    message = str(excinfo.value)
    assert "step 0" in message
    assert "commit_guard must be a boolean" in message
    assert "str" in message, "the refusal must name the offending type"


def test_strict_bool_is_down_rejected(unrestricted):
    """NEW-14: the same strict-bool rule for mouse_button's is_down — the
    key rides an untyped dict step, and a truthy string must not coerce into
    a button press."""
    with pytest.raises(ValueError) as excinfo:
        console.run_sequence(
            unrestricted, "vm1",
            [{"action": "mouse_button", "button": 1, "is_down": "false"}])
    message = str(excinfo.value)
    assert "step 0" in message
    assert "is_down must be a boolean" in message
    assert "str" in message, "the refusal must name the offending type"


def test_wait_only_plan_does_not_bump(monkeypatch, unrestricted):
    """PRR-017: a wait-only plan dispatches no input and must not stale a
    later guard — the per-VM high-water is unchanged after the plan
    succeeds, checked under BOTH possible keys (the pre-hint name and the
    transport-reported GUID the result parse may have learned)."""
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        unrestricted, "vm1",
        [{"action": "wait_frame_stable", "stable_ms": 100, "timeout_s": 2,
          "interval_ms": 100}])
    assert out["ok"] is True
    assert console._last_input_seq_for("vm1") == 0, (
        "a wait-only plan must not bump the input ledger"
    )
    assert console._last_input_seq_for(GUID) == 0


def test_precondition_refusal_does_not_bump(monkeypatch, unrestricted):
    """PRR-017: a plan the in-script precondition REFUSED dispatched no input
    (the refusal exits the script before the first step block) and must not
    stale a later guard either — the ledger is unchanged under both keys."""
    stub = RefusedSeqPS("b" * 64, "f" * 64)
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        unrestricted, "vm1",
        [{"action": "press_key", "key": "enter"}],
        expect_frame_hash="b" * 64)
    assert out["ok"] is False and out["error_class"] == "precondition"
    assert console._last_input_seq_for("vm1") == 0, (
        "a precondition-refused plan must not bump the input ledger"
    )
    assert console._last_input_seq_for(GUID) == 0


def test_timed_out_plan_still_bumps(monkeypatch, unrestricted):
    """PRR-017 (the conservative arm): a plan whose leg times out after
    dispatch leaves delivery unknowable, so an input-bearing plan STILL
    bumps — the timeout shim after test_f04_sequences.py's TimeoutSeqPS
    pattern, with one text step that times out."""
    stub = TimeoutSeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.run_sequence(
        unrestricted, "vm1",
        [{"action": "type_text", "text": "maybe-sent"}])
    assert out["ok"] is False and out["error_class"] == "unknown"
    assert max(console._last_input_seq_for("vm1"),
               console._last_input_seq_for(GUID)) > 0, (
        "a timed-out input-bearing plan must leave the bump behind"
    )


def test_bump_lands_before_lock_release(monkeypatch, unrestricted):
    """PRR-017 (review round 2, F2): the sequence's result parse AND its
    ledger bump run INSIDE the per-VM console input lock, so the bump lands
    BEFORE the lock releases. Parking the parse helper opens the reviewer's
    window; a fresh-guarded click on the SAME VM that runs in that window
    is REFUSED stale (it sees the landed bump once it acquires the lock),
    never allowed against a ledger the bump had not reached yet. The hint
    is pre-learned so BOTH calls key the lock and the ledger on the GUID —
    the state every real guarded click is in (a citable capture's VMID line
    teaches the hint; the cold name-keyed window is the disclosed residual
    in _input_lock's docstring)."""
    console.note_name_guid_hint("vm1", GUID)
    vhash = "9" * 64
    console.register_capture(          # fresh: registered before any input
        vhash, vm_name="vm1", frame_size=(SEQ_W, SEQ_H),
        head_resolution=(1024, 768), content_rect=[0, 0, SEQ_W, SEQ_H])

    entered = threading.Event()
    release = threading.Event()
    real_parse = console._parse_sequence_steps

    def parked_parse(stdout: str):
        entered.set()
        assert release.wait(timeout=10), "the parked parse was never released"
        return real_parse(stdout)

    monkeypatch.setattr(console, "_parse_sequence_steps", parked_parse)
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)

    # The lock spy: at the LAST statement of every lock scope that exits
    # normally, snapshot the ledger while the lock is STILL held — the
    # sequence's own scope must already carry the bump, observed
    # deterministically at the release boundary itself (the click's scope
    # raises through the yield and never appends).
    real_lock = console._input_lock
    ledger_at_release: list[int] = []

    @contextmanager
    def spying_lock(ref):
        with real_lock(ref):
            yield
            ledger_at_release.append(console._last_input_seq_for(GUID))

    monkeypatch.setattr(console, "_input_lock", spying_lock)

    seq_result: list[dict] = []
    seq_thread = threading.Thread(
        target=lambda: seq_result.append(console.run_sequence(
            unrestricted, "vm1", [{"action": "type_text", "text": "window"}])),
        name="pr0017-sequence")
    seq_thread.start()
    assert entered.wait(timeout=10), "the sequence never reached its parse"

    click_error: list[BaseException] = []

    def run_click():
        try:
            console.click(
                unrestricted, "vm1", 160, 120,
                frame_width=SEQ_W, frame_height=SEQ_H,
                commit_guard=True, verified_frame_hash=vhash)
        except ConsoleError as exc:
            click_error.append(exc)

    click_thread = threading.Thread(target=run_click, name="pr0017-click")
    click_thread.start()   # blocks on the same VM's console lock, then proceeds
    release.set()
    seq_thread.join(timeout=10)
    click_thread.join(timeout=15)
    assert not seq_thread.is_alive() and not click_thread.is_alive()

    assert seq_result and seq_result[0]["ok"] is True
    assert ledger_at_release, "the sequence's lock scope must exit normally"
    assert ledger_at_release[0] > 0, (
        "the ledger bump must land INSIDE the lock: the snapshot taken while "
        "the lock was still held must already see the input stamp"
    )
    assert click_error and "stale verification" in str(click_error[0]), (
        "the guarded click racing the parked parse must be refused stale — "
        "the bump landed before the lock released"
    )
    assert not any("SetAbsolutePosition" in s for s in stub.scripts), (
        "the refused click must dispatch no positional script"
    )
