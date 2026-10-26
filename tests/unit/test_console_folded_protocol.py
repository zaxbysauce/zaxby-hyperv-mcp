"""Folded single-process protocol pins for the console ops (issue #18 review).

The frozen D-02 pack (tests/unit/test_d02_console_spawns.py) proves the SPAWN
COUNTS of the fold. This file proves the other half of the contract — that the
generated scripts actually EMIT the metadata the host parses, and that the
in-script arithmetic (the frame->head scaling) does what the Python reference
does when it runs under real PowerShell 5.1.

Why it exists: the stubs used by every other console test SYNTHESIZE the
folded protocol in their responses (VMID=, HEADX=, STOP=, ...), so a script
that stopped emitting a line left the whole suite green — mutation-verified
during the PR #80 review (deleting the VMID=/HEADX=/HEADY= emissions, and
swapping $hw/$hh in the scaling block, all survived the full unit suite). One
member of that gap class is a silent wrong answer: if wait_frame_change's
script stopped emitting STOP=/FRAME=, the host parser would default to
stop_reason="deadline", polls=0 and drop the frame while still reporting
ok=true.

Not frozen by the issue #18 trace: new coverage lives here rather than in the
frozen pack (an amendment to that pack is tracked separately).
"""

from __future__ import annotations

import base64
import json
import re

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

# The real transport, captured before any test patches it: the executed-scaling
# check runs the generated arithmetic through real PowerShell 5.1.
_REAL_RUN_PS = pswindows.run_ps


class _ScriptCollector:
    """Records every generated script and answers with an empty success, so an
    op either completes or fails on parsing AFTER its script exists — either
    way the emitted text is available to assert on."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, timeout_s: float | None = None, stdin_b64: str | None = None):
        self.scripts.append(script)
        return pswindows.PSResult(stdout="", returncode=0)


def _script_for(monkeypatch, op) -> str:
    rec = _ScriptCollector()
    monkeypatch.setattr(pswindows, "run_ps", rec)
    try:
        op()
    except Exception:  # noqa: BLE001 - the script exists before any parse can fail
        pass
    assert rec.scripts, "the operation generated no script"
    return rec.scripts[-1]


# ---------------------------------------------------------------------------
# screenshot: the size chain is built, de-duplicated and reported in-script
# ---------------------------------------------------------------------------

def test_screenshot_script_emits_chain_and_metadata(monkeypatch, unrestricted_cfg):
    """The folded screenshot must emit its identity/head metadata AND build its
    fallback chain in the script: the requested size, the head-native entry
    with its duplicate guard, the 640x480 and 320x240 entries, the $seen
    de-duplication, and the SIZES=/USED=/ATTEMPTED= report lines."""
    script = _script_for(monkeypatch, lambda: console.screenshot(unrestricted_cfg, "vm1", 1024, 768))
    assert "Write-Output ('VMID=' + $vmTarget)" in script, "no VMID= emission"
    assert "Write-Output ('HEAD='" in script, "no HEAD= emission"
    assert "$sizes = @(,(1024,768))" in script, "the requested size is not the chain seed"
    assert "$sizes += ,(640,480)" in script, "the 640x480 fallback entry is missing"
    assert "$sizes += ,(320,240)" in script, "the 320x240 fallback entry is missing"
    assert "$dup = $false" in script, "no head-duplicate guard for the chain"
    assert "if (-not $dup) { $sizes += ,($hh,$vv) }" in script, (
        "the head-native size is not appended to the chain"
    )
    assert "if ($seen.ContainsKey($key)) { continue }" in script, (
        "the in-script de-duplication guard is missing"
    )
    assert "Write-Output ('SIZES='" in script, "no SIZES= report"
    assert "Write-Output ('USED=' + $used)" in script, "no USED= report"
    assert "ATTEMPTED=" in script, "no ATTEMPTED= report for the all-sizes-failed path"


def test_screenshot_script_seed_tracks_the_request(monkeypatch, unrestricted_cfg):
    """The chain seed is the REQUESTED size, not a constant: a different request
    must re-seed the chain (a hardcoded 1024x768 seed would silently capture the
    wrong size for every other request)."""
    script = _script_for(monkeypatch, lambda: console.screenshot(unrestricted_cfg, "vm1", 640, 480))
    assert "$sizes = @(,(640,480))" in script
    assert "WidthPixels  = $s[0]" in script, "the loop must drive the CIM call from the chain"


# ---------------------------------------------------------------------------
# positional mouse: HEADX=/HEADY= report the position the script computed
# ---------------------------------------------------------------------------

def test_positional_mouse_script_emits_head_position(monkeypatch, unrestricted_cfg):
    script = _script_for(
        monkeypatch,
        lambda: console.mouse_move(unrestricted_cfg, "vm1", 160, 120, frame_width=320, frame_height=240),
    )
    assert "Write-Output ('HEADX=' + $hx)" in script, "no HEADX= emission"
    assert "Write-Output ('HEADY=' + $hy)" in script, "no HEADY= emission"
    # the raw inputs ride as literals so the scaling runs in-script
    assert "$x = 160" in script and "$fw = 320" in script
    assert "$hw = $vh.CurrentHorizontalResolution" in script


def test_click_with_coordinates_emits_head_position(monkeypatch, unrestricted_cfg):
    script = _script_for(
        monkeypatch,
        lambda: console.click(unrestricted_cfg, "vm1", 160, 120, frame_width=320, frame_height=240),
    )
    assert "Write-Output ('HEADX=' + $hx)" in script
    assert "Write-Output ('HEADY=' + $hy)" in script
    assert "ClickButton" in script


# ---------------------------------------------------------------------------
# non-positional mouse: the PS/2 fallback branch and its no-device message
# ---------------------------------------------------------------------------

def test_non_positional_mouse_script_emits_rc_and_fallback(monkeypatch, unrestricted_cfg):
    script = _script_for(monkeypatch, lambda: console.mouse_button(unrestricted_cfg, "vm1", 1, True))
    assert "Write-Output ('RC=' + $r.ReturnValue)" in script, "no RC= emission"
    assert "ClassName Msvm_Ps2Mouse " in script, "no PS/2 fallback branch"
    assert "SystemName='$vmTarget'" in script, "the fallback is not scoped to this VM"
    # the message covers BOTH device classes now that PS/2 is tried: pin the
    # generic text the renamed branch emits (the synthetic-specific wording
    # survives only in the positional script, which has no PS/2 equivalent)
    assert "throw 'no mouse device associated with the VM'" in script


def test_positional_mouse_head_guard_rejects_a_zero_resolution(monkeypatch, unrestricted_cfg):
    """PRR-003's fix: the guard must reject a head that REPORTS no resolution,
    not only an absent head object — a 0/null resolution would clamp to (0,0)
    and position at the origin, where wmiconsole.head_resolution, _scale_to_head
    and _parse_head all treat that state as unavailable."""
    script = _script_for(monkeypatch, lambda: console.mouse_move(unrestricted_cfg, "vm1", 10, 10))
    guard = "display head resolution unavailable"
    assert guard in script
    # pin the GUARD's own resolution tests (not the scaling block's reads of the
    # same properties, which a bare property-name substring would also match)
    assert "(-not $vh.CurrentHorizontalResolution)" in script, (
        "the head guard tests object truthiness only; a zero-resolution head "
        "would scale to (0,0) and click the origin"
    )
    assert "(-not $vh.CurrentVerticalResolution)" in script
    assert script.index("(-not $vh.CurrentHorizontalResolution)") < script.index("SetAbsolutePosition"), (
        "the resolution guard must precede any positioning call"
    )


# ---------------------------------------------------------------------------
# USED= parsing (PRR-030's fix): a non-positive dimension is as unusable as a
# malformed one, and the length message must name the frame it was computed from
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["", "0x0", "-5x10", "abc", "10x", "x10", "10xabc"])
def test_parse_size_rejects_unusable_dimensions(raw):
    assert console._parse_size({"USED": raw}, "USED") is None, f"USED={raw!r} must parse as absent"
    assert console._parse_size({}, "USED") is None


def test_screenshot_length_message_names_the_frame(monkeypatch, unrestricted_cfg):
    """A wrong-length payload's error must name the frame size the expectation
    was computed from, so a caller can tell which size the payload came from."""
    w, h = 1024, 768
    payload = b"\x00" * (640 * 480 * 2 + 4)  # a 640x480 payload under a 1024x768 USED
    body = json.dumps({"returnValue": 0, "imageDataB64": base64.b64encode(payload).decode()})
    fake = pswindows.PSResult(
        stdout="VMID=" + GUID + "\nHEAD=1024x768\nSIZES=" + str(w) + "x" + str(h)
               + "\nUSED=" + str(w) + "x" + str(h) + "\n" + body,
        returncode=0,
    )
    monkeypatch.setattr(pswindows, "run_ps", lambda *a, **k: fake)
    with pytest.raises(ConsoleError) as excinfo:
        console.screenshot(unrestricted_cfg, "vm1")
    assert "for the 1024x768 frame" in str(excinfo.value)


def test_positional_mouse_script_names_the_missing_synthetic_mouse(monkeypatch, unrestricted_cfg):
    script = _script_for(monkeypatch, lambda: console.mouse_move(unrestricted_cfg, "vm1", 10, 10))
    assert "no synthetic mouse device associated with the VM" in script
    assert "Msvm_Ps2Mouse" not in script, "positional ops must not fall back to PS/2"


# ---------------------------------------------------------------------------
# keyboard: per-chunk RC=/CHUNK= progress lines
# ---------------------------------------------------------------------------

def test_keyboard_scripts_emit_per_chunk_progress(monkeypatch, unrestricted_cfg):
    script = _script_for(monkeypatch, lambda: console.type_text(unrestricted_cfg, "vm1", "hi"))
    assert "Write-Output ('RC=' + $r.ReturnValue + ' CHUNK=' + ($i+1) + '/' + $n)" in script
    assert "[Console]::In.ReadLine()" in script

    codes = _script_for(monkeypatch, lambda: console.type_scancodes(unrestricted_cfg, "vm1", [0x1C, 0x9C]))
    assert "Write-Output ('RC=' + $r.ReturnValue + ' CHUNK=' + ($i+1) + '/' + $n)" in codes
    assert "$chunks = @(28,156)" in codes


# ---------------------------------------------------------------------------
# wait_frame_change: STOP=/FRAME= are the parser's only input — a script that
# stopped emitting them would answer "deadline, 0 polls, no image" silently
# ---------------------------------------------------------------------------

def test_wait_frame_script_emits_stop_and_frame(monkeypatch, unrestricted_cfg):
    script = _script_for(
        monkeypatch,
        lambda: console.wait_frame_change(unrestricted_cfg, "vm1", timeout_s=6, interval_s=2),
    )
    assert "STOP=deadline" in script, "no deadline stop report"
    assert "STOP=changed" in script, "no changed stop report"
    assert "FRAME=" in script, "the changed frame is never emitted"
    assert "HASH=" in script, "no hash report"
    # the emitted hash must be the full lowercase-hex sha256 of the raw payload,
    # byte-identical to the host _frame_hash, so it round-trips as a baseline
    assert "-replace '-','').ToLowerInvariant()" in script


def test_wait_frame_changed_response_still_decodes(monkeypatch, unrestricted_cfg):
    """The parser half of the same contract: a STOP=changed + FRAME= response
    must yield the image and its hash (so the emission pin above and this pin
    together fail if either side drifts)."""
    w, h = 320, 240
    payload = b"\x00\x00\x00\x00" + b"\x5a\xa5" * (w * h)
    fake = pswindows.PSResult(
        stdout="STOP=changed POLLS=2 HASH=" + console._frame_hash(payload).upper()
        + "\nFRAME=" + base64.b64encode(payload).decode(),
        returncode=0,
    )
    monkeypatch.setattr(pswindows, "run_ps", lambda *a, **k: fake)
    out = console.wait_frame_change(unrestricted_cfg, "vm1", width=w, height=h)
    assert out["stop_reason"] == "changed" and out["changed"] is True
    assert out["image"].size == (w, h)
    assert out["frame_hash"] == console._frame_hash(payload)


# ---------------------------------------------------------------------------
# capture_sequence: each frame is its own self-contained folded process
# ---------------------------------------------------------------------------

def test_capture_sequence_frames_are_self_contained(monkeypatch, unrestricted_cfg):
    """Every frame's script resolves the VM itself — one folded process per
    frame. The frames carry no cross-frame CHANNEL: all coordination stays
    host-side between independent processes (the per-frame VMID= emission the
    capture_sequence identity pin adds is per-process output, not a channel)."""
    rec = _ScriptCollector()

    def _serve_capture(script: str, timeout_s: float | None = None, stdin_b64: str | None = None):
        rec.scripts.append(script)
        w = h = 0
        for line in script.splitlines():
            ls = line.strip()
            if ls.startswith("WidthPixels"):
                w = int(ls.split("=", 1)[1])
            elif ls.startswith("HeightPixels"):
                h = int(ls.split("=", 1)[1])
        raw = b"\x00" * (w * h * 2 + 4)
        return pswindows.PSResult(
            stdout=json.dumps(
                {"returnValue": 0, "imageDataB64": base64.b64encode(raw).decode()}
            ),
            returncode=0,
        )

    monkeypatch.setattr(pswindows, "run_ps", _serve_capture)
    out = console.capture_sequence(unrestricted_cfg, "vm1", count=2, interval_s=1, width=320, height=240)
    assert len(out["frames"]) == 2
    assert len(rec.scripts) == 2, "capture_sequence must run one folded process per frame"
    for script in rec.scripts:
        assert "GetVirtualSystemThumbnailImage" in script
        assert "$vmTarget" in script, "each frame's script must bind the VM target itself"
        # The VMID=-absence assert this file once carried here was the wrong
        # owner for the identity fork it cited (#77): per-frame identity is
        # owned by the capture_sequence identity pin (issue #82), which
        # freezes its own emission-and-compare contract. This file pins the
        # self-containment contract: one folded process per frame, each
        # resolving and binding its own VM target.


# ---------------------------------------------------------------------------
# get_display_info: absence is DATA, not an error (PR #80 review F2)
# ---------------------------------------------------------------------------

def test_display_info_script_reports_keyboard_absence(monkeypatch, unrestricted_cfg):
    """The observing op must not carry the input ops' throwing keyboard guard:
    base and the WMI transport both answer keyboard_present=false, and a stopped
    VM (the population this tool inspects) has no keyboard association at all."""
    script = _script_for(monkeypatch, lambda: console.get_display_info(unrestricted_cfg, "vm1"))
    assert "no keyboard device associated with the VM" not in script, (
        "display-info still carries the throwing input-op keyboard guard"
    )
    assert "keyboard_present = [bool]$kb" in script, (
        "the graceful keyboard_present branch is missing"
    )
    assert "keyboard_enabled = if ($kb)" in script
    assert "Write-Output ('VMID=' + $vmTarget)" in script


def test_display_info_parses_keyboard_absence(monkeypatch, unrestricted_cfg):
    """The graceful branches are live, not dead code: a folded response with
    keyboard_present=false (and no mouse) must parse through to the result."""
    body = json.dumps({
        "enabled_state": 3, "head_horizontal": None, "head_vertical": None,
        "keyboard_present": False, "keyboard_enabled": None,
        "mouse_present": False, "mouse_enabled": None,
    })
    fake = pswindows.PSResult(stdout="VMID=" + GUID + "\n" + body, returncode=0)
    monkeypatch.setattr(pswindows, "run_ps", lambda *a, **k: fake)
    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert out["ok"] is True
    assert out["enabled_state"] == 3
    assert out["keyboard_present"] is False and out["keyboard_enabled"] is None
    assert out["mouse_present"] is False and out["mouse_enabled"] is None
    assert out["vm_id"] == GUID


# ---------------------------------------------------------------------------
# the in-script scaling arithmetic, EXECUTED in real PowerShell 5.1 (PR #80
# review F7): the stubs re-implement _scale_to_head in Python and synthesize
# HEADX=/HEADY=, so a defect in the emitted [math]::Round/clamp lines left the
# whole unit suite green. Same approach as the frozen pack's AC19.
# ---------------------------------------------------------------------------

def _executed_scale(script: str, head: tuple[int, int]) -> tuple[int, int]:
    """Run the generated positional-mouse script's scaling block in real
    PowerShell 5.1 against a synthetic $vh and return the (hx, hy) it computes.

    The VM-resolution prelude and the CIM calls need a live VM and are
    irrelevant to the arithmetic, so the harness re-runs exactly the emitted
    `$x/$y/$fw/$fh` literals and the scaling/clamp block — verbatim strings
    from the generated script, whose PS 5.1 rounding and clamping semantics are
    what the Python reference claims to replicate."""
    import os

    if not os.path.exists(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
        pytest.skip("no PowerShell on this host")
    pswindows.init(Config(unrestricted=True))  # the transport gate, as tests do
    lines = script.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("$x = "))
    end = next(
        i for i, ln in enumerate(lines)
        if ln.startswith("$hy = [math]::Max(0, [math]::Min($hy, $hh - 1))")
    )
    block = "\n".join(lines[start:end + 1])
    assert "$hw = $vh.CurrentHorizontalResolution" in block
    body = (
        "$vh = [PSCustomObject]@{ CurrentHorizontalResolution = "
        + str(head[0]) + "; CurrentVerticalResolution = " + str(head[1]) + " }\n"
        + block + "\n"
        + "Write-Output ('HX=' + $hx + ' HY=' + $hy)\n"
    )
    result = _REAL_RUN_PS(body, timeout_s=60)
    assert result.returncode == 0, f"scaling script failed: {result.stderr[:200]}"
    m = re.search(r"HX=(-?\d+) HY=(-?\d+)", result.stdout)
    assert m, f"the scaling block emitted no position: {result.stdout[:200]!r}"
    return int(m.group(1)), int(m.group(2))


# (x, y, frame_w, frame_h) cases against the fixed (1024, 768) head: identity,
# downscale, upscale, the two banker's-rounding MIDPOINTS that discriminate
# (0.5 and 2.5 both round DOWN to even in Python's round() and in
# [math]::Round's default ToEven, while [MidpointRounding]::AwayFromZero would
# round them up — 1.5 is deliberately absent: it rounds to 2 either way), and an
# out-of-frame clamp.
_SCALE_CASES = [
    (100, 50, 1024, 768),
    (320, 240, 640, 480),
    (160, 120, 320, 240),
    (1, 1, 2048, 1536),     # 0.5 midpoint -> 0
    (5, 5, 2048, 1536),     # 2.5 midpoint -> 2
    (9999, 9999, 640, 480),
]


@pytest.mark.parametrize("x,y,fw,fh", _SCALE_CASES)
def test_emitted_scaling_matches_the_python_reference(monkeypatch, unrestricted_cfg, x, y, fw, fh):
    """The emitted [math]::Round/clamp arithmetic must produce exactly what
    console._scale_to_head produces (both round half to even; the grouping is
    the same expression order)."""
    head = (1024, 768)
    script = _script_for(
        monkeypatch,
        lambda: console.mouse_move(unrestricted_cfg, "vm1", x, y, frame_width=fw, frame_height=fh),
    )
    assert _executed_scale(script, head) == console._scale_to_head(x, y, fw, fh, head)


def test_emitted_scaling_midpoints_round_to_even(monkeypatch, unrestricted_cfg):
    """The two discriminating midpoints must round to EVEN, not away from zero:
    a [MidpointRounding]::AwayFromZero regression would return 1 and 3 here.
    Both the reference and the emitted arithmetic are checked, so the case
    fails if either side changes rounding mode."""
    head = (1024, 768)
    assert console._scale_to_head(1, 1, 2048, 1536, head) == (0, 0)
    assert console._scale_to_head(5, 5, 2048, 1536, head) == (2, 2)
    script = _script_for(
        monkeypatch,
        lambda: console.mouse_move(unrestricted_cfg, "vm1", 5, 5, frame_width=2048, frame_height=1536),
    )
    assert _executed_scale(script, head) == (2, 2), (
        "the emitted arithmetic must round the 2.5 midpoint to even (2), not away from zero (3)"
    )


def test_emitted_scaling_head_space_branch_matches_reference(monkeypatch, unrestricted_cfg):
    """With no frame dims the emitted block takes head-space coordinates
    directly and still clamps — the same contract as _scale_to_head."""
    head = (1024, 768)
    script = _script_for(monkeypatch, lambda: console.mouse_move(unrestricted_cfg, "vm1", 5000, 10))
    assert _executed_scale(script, head) == console._scale_to_head(5000, 10, 0, 0, head)
