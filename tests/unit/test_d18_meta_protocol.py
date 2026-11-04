"""Acceptance checks AC18-AC21 (issue #83): folded-protocol metadata edges.

RED at base b1ed4f7, GREEN after the fix (each check's docstring names its
base state precisely — AC18 is a NEW-SURFACE contract whose base run is an
expected ERROR, the others are DISCRIMINATING reds for the issue's reason).

Covered here, per the collated trace (02-reproduction.md Attempt 5):

- AC18: ``_meta_lines`` folds per-chunk ``RC=`` lines last-wins, so a 3-chunk
  keyboard response collapses to one indistinguishable value. The parser seam
  must expose per-key ordered values while ``meta['RC']`` keeps last-wins for
  existing consumers.
- AC19: ``spawn_ms`` mixes two undocumented bases (the resolve leg records
  host-side wall-clock including policy/compose/slot-wait; op legs record the
  child's ``duration_ms`` excluding slot wait). The issue sanctions
  DOCUMENTING the two bases; the behavioral half pins the entry parity the
  documentation describes.
- AC20: the by-name keyboard/mouse/wait ops never emit or validate ``VMID=``
  (capture/screenshot/sequence already do, issue #82) — the resolved GUID is
  invisible to host-side validation on exactly the input-bearing families.
- AC21: a folded screenshot response without ``USED=`` is silently assumed to
  be the requested size (console.py:1813) — the degradation must surface as a
  result signal.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from hyperv_mcp import console, pswindows
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
_VMID_EMIT = "Write-Output ('VMID=' + $vmTarget)"


class _QueuedPS:
    """pswindows.run_ps replacement serving queued responses while recording
    every generated script."""

    def __init__(self, responses=()):
        self.scripts: list[str] = []
        self.count = 0
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.count += 1
        return self.responses.pop(0)


# ---------------------------------------------------------------------------
# AC18: per-chunk RC= lines stay distinguishable
# ---------------------------------------------------------------------------

def test_per_chunk_rc_lines_stay_distinguishable():
    """AC18: the metadata parser exposes per-key ordered values.

    Three ``RC=0 CHUNK=n/3`` lines are the exact 3-chunk keyboard shape from
    the reproduction; last-wins folding leaves only ``'0 CHUNK=3/3'`` and the
    first two chunks' outcomes are indistinguishable from a loss. The minimal
    post-fix API is a third return value — an ordered per-key list mapping —
    while ``meta['RC']`` keeps last-wins so existing consumers are unchanged.

    NEW-SURFACE note: base ``_meta_lines`` returns a 2-tuple, so the base run
    of this check is an ERROR at the unpack ("not enough values to unpack
    (expected 3, got 2)") — an honest red for a contract on a surface that
    does not exist at base."""
    result = pswindows.PSResult(
        stdout="RC=0 CHUNK=1/3\nRC=0 CHUNK=2/3\nRC=0 CHUNK=3/3", returncode=0)
    meta, payload, all_values = console._meta_lines(result)
    assert all_values["RC"] == ["0 CHUNK=1/3", "0 CHUNK=2/3", "0 CHUNK=3/3"], (
        "AC18: the parser must expose every per-chunk RC= value in order"
    )
    assert meta["RC"] == "0 CHUNK=3/3", (
        "AC18: meta['RC'] keeps last-wins — existing consumers are unchanged"
    )
    assert payload == ""


# ---------------------------------------------------------------------------
# AC19: spawn_ms bases documented (+ behavioral parity)
# ---------------------------------------------------------------------------

def test_spawn_ms_entries_share_one_basis(monkeypatch, unrestricted_cfg):
    """AC19: README documents the two spawn_ms bases; entries stay in parity.

    (a) RED at base: the README's spawn_ms prose (README:1952 region)
    documents NEITHER basis — it says "one float per powershell.exe spawn"
    without stating that the resolve-leg entry is host-side wall-clock
    (including policy/compose/slot-wait) while op-leg entries are the
    child's duration_ms (excluding slot wait). A paragraph mentioning
    spawn_ms must name the slot-wait distinction and the resolve/duration
    legs.
    (b) GREEN at base (disclosed): a by-id display-info makes exactly two
    run_ps calls (the resolve leg, then the folded op), and both bases land
    as numeric entries — the parity the documented contract describes. This
    half pins that the fix does not re-plumb the field (the issue sanctions
    documentation, not a basis change)."""
    # (a) the documented two-basis contract
    readme = Path(__file__).resolve().parents[2].joinpath("README.md").read_text(
        encoding="utf-8")
    paragraphs = [p for p in readme.split("\n\n") if "spawn_ms" in p]
    assert paragraphs, "AC19: README no longer documents spawn_ms at all"
    # PRR-106 + CUB-meta-109: BOTH bases must appear in the SAME paragraph
    # AND in the documented direction — the wall-clock (resolve-leg) wording
    # precedes the duration_ms (op-leg) wording; the executed inversion
    # mutant (duration_ms before wall-clock) must fail here, as must a
    # paragraph naming only one basis.
    def _two_basis(p: str) -> bool:
        low = p.lower()
        return (
            "wall-clock" in low and "duration_ms" in low and "slot" in low
            and low.index("wall-clock") < low.index("duration_ms")
        )

    two_basis = [p for p in paragraphs if _two_basis(p)]
    assert two_basis, (
        "AC19: no spawn_ms paragraph states the two bases — the resolve-leg "
        "entry is wall-clock including policy/compose/slot-wait and op-leg "
        "entries are the child's duration_ms excluding slot wait"
    )

    # (b) behavioral parity: 2 spawns -> 2 numeric entries (mixed bases today)
    body = json.dumps({
        "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
        "keyboard_present": True, "keyboard_enabled": 2,
        "mouse_present": True, "mouse_enabled": 2,
    })
    stub = _QueuedPS([
        pswindows.PSResult(stdout="vm1", returncode=0),  # by-id resolve leg
        pswindows.PSResult(
            stdout="VMID=" + GUID + "\n" + body, returncode=0, duration_ms=7),
    ])
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.get_display_info(unrestricted_cfg, vm_id=GUID)
    spawn_ms = out["timings"]["spawn_ms"]
    assert stub.count == 2, f"AC19: expected 2 run_ps calls, got {stub.count}"
    assert len(spawn_ms) == 2, (
        f"AC19: spawn_ms parity broken — {stub.count} spawns produced "
        f"{len(spawn_ms)} entries: {spawn_ms!r}"
    )
    assert all(isinstance(v, (int, float)) for v in spawn_ms), (
        f"AC19: every spawn_ms entry must be numeric: {spawn_ms!r}"
    )


# ---------------------------------------------------------------------------
# AC20: by-name keyboard/mouse/wait ops surface a validated GUID
# ---------------------------------------------------------------------------

def test_by_name_ops_surface_a_validated_guid(monkeypatch, unrestricted_cfg):
    """AC20: one op per family emits VMID= and the host validates it.

    For each family — keyboard (type_scancodes), mouse (mouse_button), wait
    (wait_frame_change) — driven BY NAME:

    - the generated script must emit ``VMID=`` from ``$vmTarget`` (the #82
      seam; RED at base — these families emit nothing), and
    - a response carrying ``VMID=<garbage>`` must be REFUSED (RED at base:
      base ignores the line entirely and reports success — the resolved GUID
      never reaches host-side validation on the input-bearing families).

    The valid-GUID success legs (base-green, disclosed) pin that validation
    does not break the working path: a well-formed VMID still returns ok."""
    cfg = unrestricted_cfg

    families = [
        ("keyboard/type_scancodes",
         lambda vmid: pswindows.PSResult(
             stdout=vmid + "\nRC=0 CHUNK=1/1", returncode=0),
         lambda: console.type_scancodes(cfg, "vm1", [0x1C, 0x9C])),
        ("mouse/mouse_button",
         lambda vmid: pswindows.PSResult(stdout=vmid + "\nRC=0", returncode=0),
         lambda: console.mouse_button(cfg, "vm1", 1, True)),
        ("wait/wait_frame_change",
         lambda vmid: pswindows.PSResult(
             stdout=vmid + "\nSTOP=deadline POLLS=1 HASH=abc", returncode=0),
         lambda: console.wait_frame_change(cfg, "vm1", timeout_s=6, interval_s=2)),
    ]
    for name, response_for, op in families:
        # garbage GUID first (the issue's canonical red: base ignores the line
        # entirely and reports success) — the module must refuse the identity
        stub_bad = _QueuedPS([response_for("VMID=not-a-guid")])
        monkeypatch.setattr(pswindows, "run_ps", stub_bad)
        try:
            op()
        except ConsoleError:
            pass
        else:
            raise AssertionError(
                f"AC20: {name} accepted VMID=not-a-guid — the by-name resolved "
                "GUID is never validated through the _parse_guid/validate_vm_guid "
                "seam on this family"
            )
        # valid GUID: the emission pin + the success path stay green
        stub = _QueuedPS([response_for("VMID=" + GUID)])
        monkeypatch.setattr(pswindows, "run_ps", stub)
        out = op()
        assert out["ok"] is True, f"AC20: {name} broke on a valid VMID"
        assert _VMID_EMIT in stub.scripts[-1], (
            f"AC20: the by-name {name} script never emits VMID= from $vmTarget — "
            "the resolved GUID is invisible to host-side validation"
        )


# ---------------------------------------------------------------------------
# AC21: missing USED= is a result signal, not a silent assumption
# ---------------------------------------------------------------------------

def _screenshot_response(w: int, h: int, used_line: str) -> pswindows.PSResult:
    payload = b"\x00" * (w * h * 2 + 4)
    body = json.dumps({
        "returnValue": 0,
        "imageDataB64": base64.b64encode(payload).decode(),
    })
    lines = ["VMID=" + GUID, "HEAD=1024x768", "SIZES=" + str(w) + "x" + str(h)]
    if used_line:
        lines.append(used_line)
    return pswindows.PSResult(stdout="\n".join(lines) + "\n" + body, returncode=0)


def test_missing_used_line_is_reported(monkeypatch, unrestricted_cfg):
    """AC21: a folded screenshot without a (usable) USED= line must surface
    the degradation as ``used_fallback: true`` in the metadata.

    RED at base: console.py:1813 does ``_parse_size(meta_lines, "USED") or
    (width, height)`` — the absent/malformed line silently renames the frame
    as the requested size and no result key says so. When USED= IS present
    and parses, ``used_fallback`` must be false (or absent) — that leg is
    green at base and pins the exact-when contract."""
    # absent USED= -> degradation signal true (RED at base: no such key)
    stub = _QueuedPS([_screenshot_response(320, 240, "")])
    monkeypatch.setattr(pswindows, "run_ps", stub)
    _frame, meta = console.screenshot(unrestricted_cfg, "vm1", 320, 240)
    assert meta.get("used_fallback") is True, (
        "AC21: a folded screenshot response without USED= is silently assumed "
        "to be the requested size — the degradation must surface as "
        "used_fallback=true"
    )

    # malformed USED= -> same degradation signal (RED at base)
    stub_malformed = _QueuedPS([_screenshot_response(320, 240, "USED=abc")])
    monkeypatch.setattr(pswindows, "run_ps", stub_malformed)
    _frame, meta_malformed = console.screenshot(unrestricted_cfg, "vm1", 320, 240)
    assert meta_malformed.get("used_fallback") is True, (
        "AC21: a malformed USED= line must degrade exactly like an absent one"
    )

    # present, parseable USED= -> no degradation signal (GREEN at base)
    stub_present = _QueuedPS([_screenshot_response(320, 240, "USED=320x240")])
    monkeypatch.setattr(pswindows, "run_ps", stub_present)
    _frame, meta_present = console.screenshot(unrestricted_cfg, "vm1", 320, 240)
    assert meta_present.get("used_fallback") in (False, None), (
        "AC21: used_fallback must be false/absent exactly when USED= was "
        "present and parseable"
    )
