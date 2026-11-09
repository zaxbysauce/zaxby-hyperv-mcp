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

import pytest

from hyperv_mcp import auditlog, console, pswindows
from hyperv_mcp.config import Config

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
