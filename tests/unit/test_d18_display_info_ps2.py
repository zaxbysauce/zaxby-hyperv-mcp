"""Acceptance checks AC14/AC15 (issue #83): display-info reports PS/2 mice.

RED at base b1ed4f7, GREEN after the fix.

The display-info script queries Msvm_SyntheticMouse only, while the mouse
input ops (mouse_button, scroll, click-at-current-position) fall back to
Msvm_Ps2Mouse — so on a VM with only a PS/2 mouse the diagnostic answers
mouse_present=false and a caller concludes nothing can act on the console,
which is wrong (the non-positional ops work fine over PS/2). The issue's
sanctioned fix is Design (b): an additive `mouse_ps2_present` field, with the
synthetic-mouse case preserved (AC15).

The stubs serve the folded display-info response the POST-FIX script emits
(``VMID=`` ahead of the snake_case JSON). Base passes unknown JSON keys
through verbatim, so the PS/2-present leg's pass-through is disclosed as
green-at-base; the leg discriminates through its other two assertions, both
RED at base for the issue's reason: the field must be reported on the
synthetic-only response too (base carries no ``mouse_ps2_present`` key at
all) and the display-info script must query Msvm_Ps2Mouse (base queries
Msvm_SyntheticMouse only — 02-reproduction.md Attempt 5).

Amended under the sanctioned CHECK_WRONG procedure (the C13/R2-A overfit
precedent, issue #84): every response assertion in this file checks only the
stub-served JSON, which the host passes through verbatim — so an emitter
that keeps the device queries but hard-codes the emitted field (the
reviewer's probe B2 pinned a constant ``mouse_ps2_present``) passed both
checks. The amendment adds EMISSION PIN legs to AC14 asserting the
generated script's literal emission expressions — delivery invariants are
asserted from emitted script text, per the trace's own standard: the PS/2
presence must be emitted from the queried device, not a constant, and the
synthetic presence likewise. Existing legs and assertions are unchanged.
"""

from __future__ import annotations

import json

from hyperv_mcp import console, pswindows

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


class _QueuedPS:
    """pswindows.run_ps replacement serving queued folded responses while
    recording every generated script (the FakePS/MetaStub pattern from
    test_console.py, reduced to what these checks need)."""

    def __init__(self, responses=()):
        self.scripts: list[str] = []
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return self.responses.pop(0)


def _display_info_response(body: dict) -> pswindows.PSResult:
    """A folded display-info response: VMID= metadata ahead of the JSON."""
    return pswindows.PSResult(stdout="VMID=" + GUID + "\n" + json.dumps(body), returncode=0)


def test_display_info_reports_the_ps2_mouse(monkeypatch, unrestricted_cfg):
    """AC14: no synthetic mouse + PS/2 mouse present must not read as absence.

    A Gen1/PS/2 VM is exactly the population this diagnostic inspects, and
    the input ops CAN act on it — the result must carry ``mouse_ps2_present``
    true while ``mouse_present`` (the synthetic device) stays false, the
    field must be reported on every response shape (a synthetic-only response
    answers ``mouse_ps2_present`` false, never an absent key), and the script
    must query the PS/2 device class at all."""
    # -- leg 1: synthetic-only VM — the field is ALWAYS reported (the primary
    # base red: the result carries no mouse_ps2_present key at all)
    body_synthetic_only = {
        "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
        "keyboard_present": True, "keyboard_enabled": 2,
        "mouse_present": True, "mouse_enabled": 2,
    }
    stub_syn = _QueuedPS([_display_info_response(body_synthetic_only)])
    monkeypatch.setattr(pswindows, "run_ps", stub_syn)
    out_syn = console.get_display_info(unrestricted_cfg, "vm1")
    assert out_syn["mouse_ps2_present"] is False, (
        "AC14: mouse_ps2_present must always be reported — a synthetic-only "
        "response answers false, never an absent key"
    )
    # EMISSION PIN (overfit amendment): mouse_present passes through the
    # served JSON untouched, so nothing above would notice an emitter that
    # hard-codes it. The synthetic presence must be EMITTED from the queried
    # device — pin the literal emission expression from the generated script.
    assert "mouse_present = [bool]$mouse\n" in stub_syn.scripts[-1], (
        "AC14: the display-info script must emit mouse_present from the "
        "queried synthetic device ([bool]$mouse), not a hard-coded constant"
    )

    # -- leg 2: PS/2-only VM (the post-fix script reports both device classes)
    body_ps2_only = {
        "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
        "keyboard_present": True, "keyboard_enabled": 2,
        "mouse_present": False, "mouse_enabled": None,
        # what a post-fix script reports for a VM whose only mouse is PS/2
        "mouse_ps2_present": True,
    }
    stub = _QueuedPS([_display_info_response(body_ps2_only)])
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert out["ok"] is True
    assert out["mouse_present"] is False, (
        "AC14: mouse_present (the synthetic device) must stay false on a PS/2-only VM"
    )
    assert out["mouse_ps2_present"] is True, (
        "AC14: display-info claims absence alone — mouse_ps2_present must report "
        "the PS/2 device the non-positional input ops act on"
    )
    # the script must query the PS/2 device class: without the lookup the
    # field can never be true on a real host (base queries synthetic only)
    assert "Msvm_Ps2Mouse" in stub.scripts[-1], (
        "AC14: the display-info script never queries Msvm_Ps2Mouse, so it "
        "cannot report the device class the input ops fall back to"
    )
    # EMISSION PIN (overfit amendment, the reviewer's probe B2): the class
    # membership check above still passes when the query's answer is ignored
    # and the field is hard-coded. The PS/2 presence must be EMITTED from the
    # queried device — pin the literal emission expression (the $m reassigned
    # by the Msvm_Ps2Mouse lookup, after $mouse captured the synthetic answer)
    # so a constant emission fails even with a correctly-shaped stub response.
    assert "mouse_ps2_present = [bool]$m\n" in stub.scripts[-1], (
        "AC14: the display-info script must emit mouse_ps2_present from the "
        "queried PS/2 device ([bool]$m), not a hard-coded constant"
    )


def test_display_info_synthetic_case_unchanged(monkeypatch, unrestricted_cfg):
    """AC15 (preserving): the synthetic-mouse case keeps its pre-fix answer.

    GREEN at base and must stay GREEN after the fix: a VM with a synthetic
    mouse reports mouse_present true and a truthy mouse_enabled exactly as it
    always has. The mouse_ps2_present assertions live in the AC14 check only,
    so this row pins the preserved keys alone."""
    body_synthetic = {
        "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
        "keyboard_present": True, "keyboard_enabled": 2,
        "mouse_present": True, "mouse_enabled": 2,
    }
    stub = _QueuedPS([_display_info_response(body_synthetic)])
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert out["mouse_present"] is True, (
        "AC15: a present synthetic mouse must keep reporting mouse_present true"
    )
    assert out["mouse_enabled"], (
        "AC15: a present synthetic mouse must keep reporting its EnabledState"
    )
