"""Non-frozen pins for issue #83 (trace 75-76-78-81-83-84-collated): the
by-name keyboard/mouse/wait ops surface a validated GUID through the #82
``VMID=`` seam and feed the host-side name->GUID hint map.

The frozen AC20 check (test_d18_meta_protocol.py) pins one op per family
(type_scancodes / mouse_button / wait_frame_change) for emission + garbage
refusal. These pins add the OUTCOMES the frozen file does not carry:

- a successful by-name call with a VALID ``VMID=`` served records the hint
  (``note_name_guid_hint`` observed through ``_hint_for`` — the map is what
  lets the NEXT by-name call lock and act on the canonical GUID, issue #77)
  for every input-bearing family, including type_text, press_key and the
  positional mouse ops the frozen file does not drive;
- a garbage ``VMID=`` refuses AND records no hint (a bad identity must never
  enter the map);
- an ABSENT ``VMID=`` (older protocol) succeeds with no hint recorded — the
  conditional-present contract that keeps empty-stub transports working.

The conftest isolates ``console._NAME_GUID_HINTS`` per test; each leg uses
its own VM name so a recorded hint cannot change a later leg's prelude.
"""

from __future__ import annotations

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
_VMID_EMIT = "Write-Output ('VMID=' + $vmTarget)"


class _QueuedPS:
    """pswindows.run_ps replacement serving queued responses while recording
    every generated script (the MetaStub pattern from test_console.py)."""

    def __init__(self, responses=()):
        self.scripts: list[str] = []
        self.count = 0
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.count += 1
        return self.responses.pop(0)


# One (family, vm name, valid-VMID response, no-VMID response, op) per
# input-bearing family; the ops are driven BY NAME (the hint map is a by-name
# concept — by-id callers already know the GUID).
_FAMILIES = [
    ("keyboard/type_text", "vm-hint-text",
     "VMID={g}\nRC=0 CHUNK=1/1",
     "RC=0 CHUNK=1/1",
     lambda cfg, name: console.type_text(cfg, name, "hi")),
    ("keyboard/type_scancodes", "vm-hint-codes",
     "VMID={g}\nRC=0 CHUNK=1/1",
     "RC=0 CHUNK=1/1",
     lambda cfg, name: console.type_scancodes(cfg, name, [0x1C, 0x9C])),
    ("keyboard/press_key", "vm-hint-press",
     "VMID={g}\nRC=0 CHUNK=1/1",
     "RC=0 CHUNK=1/1",
     lambda cfg, name: console.press_key(cfg, name, "enter")),
    ("mouse/mouse_button", "vm-hint-button",
     "VMID={g}\nRC=0",
     "RC=0",
     lambda cfg, name: console.mouse_button(cfg, name, 1, True)),
    ("mouse/mouse_move", "vm-hint-move",
     "VMID={g}\nHEADX=5\nHEADY=5",
     "HEADX=5\nHEADY=5",
     lambda cfg, name: console.mouse_move(cfg, name, 5, 5)),
    ("mouse/click", "vm-hint-click",
     "VMID={g}\nHEADX=5\nHEADY=5\nRC=0",
     "HEADX=5\nHEADY=5\nRC=0",
     lambda cfg, name: console.click(cfg, name, 5, 5)),
    ("wait/wait_frame_change", "vm-hint-wait",
     "VMID={g}\nSTOP=deadline POLLS=1 HASH=abc",
     "STOP=deadline POLLS=1 HASH=abc",
     lambda cfg, name: console.wait_frame_change(cfg, name, timeout_s=6, interval_s=2)),
    ("wait/wait_frame_stable", "vm-hint-stable",
     "VMID={g}\nSTOP=deadline POLLS=1 HASH=abc",
     "STOP=deadline POLLS=1 HASH=abc",
     lambda cfg, name: console.wait_frame_stable(cfg, name, stable_ms=100, timeout_s=2)),
]


def test_by_name_call_with_valid_vmid_records_the_hint(monkeypatch, unrestricted_cfg):
    """A successful by-name call whose response carries a well-formed VMID=
    records the name->GUID hint for every input-bearing family, and the
    generated script emits VMID= from $vmTarget (the seam that makes the
    identity visible host-side at all)."""
    cfg = unrestricted_cfg
    for family, vm_name, with_vmid, _without, op in _FAMILIES:
        stub = _QueuedPS([
            pswindows.PSResult(stdout=with_vmid.format(g=GUID), returncode=0)])
        monkeypatch.setattr(pswindows, "run_ps", stub)
        out = op(cfg, vm_name)
        assert out["ok"] is True, f"{family}: a valid VMID must not break the op"
        assert console._hint_for(vm_name) == GUID, (
            f"{family}: the by-name call did not record the name->GUID hint "
            "from its VMID= line (note_name_guid_hint never observed)"
        )
        assert _VMID_EMIT in stub.scripts[-1], (
            f"{family}: the by-name script never emits VMID= from $vmTarget"
        )


def test_by_name_call_with_garbage_vmid_refuses_and_records_no_hint(
    monkeypatch, unrestricted_cfg
):
    """A garbage VMID= is refused (ConsoleError) AND leaves the hint map
    untouched — an unvalidated identity must never become a lock key."""
    cfg = unrestricted_cfg
    for family, vm_name, _with_vmid, _without, op in _FAMILIES:
        stub = _QueuedPS([
            pswindows.PSResult(stdout="VMID=not-a-guid\nRC=0", returncode=0)])
        monkeypatch.setattr(pswindows, "run_ps", stub)
        with pytest.raises(ConsoleError):
            op(cfg, vm_name)
        assert console._hint_for(vm_name) is None, (
            f"{family}: a garbage VMID= must not record a hint"
        )


def test_by_name_call_without_vmid_succeeds_and_records_no_hint(
    monkeypatch, unrestricted_cfg
):
    """An absent VMID= (older protocol / minimal stub) skips validation
    silently: the op still succeeds and no hint is recorded."""
    cfg = unrestricted_cfg
    for family, vm_name, _with_vmid, without, op in _FAMILIES:
        stub = _QueuedPS([pswindows.PSResult(stdout=without, returncode=0)])
        monkeypatch.setattr(pswindows, "run_ps", stub)
        out = op(cfg, vm_name)
        assert out["ok"] is True, (
            f"{family}: an absent VMID= must not break the op (conditional-present)"
        )
        assert console._hint_for(vm_name) is None, (
            f"{family}: no VMID= was served, so no hint may exist"
        )
