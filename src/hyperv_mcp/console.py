"""Host-side VM console observation and input via Hyper-V WMI.

Transport selection (issue #45): every public operation runs over the
in-process WMI backend (``wmiconsole``, optional pywin32 dependency — zero
powershell.exe spawns per call) when it is available and can serve the
target, and over the generated-PowerShell transport below otherwise
(automatic fallback, including a remote Hyper-V host whose DCOM endpoint is
unreachable — the WS-Man hop composes exactly as before). A WMI METHOD
failure (or a mid-op backend unavailability) is a structured error and is
never retried through PowerShell so input can never double-send. Every
SUCCESSFUL result reports a per-call ``timings`` breakdown (failure
envelopes carry the standard error shape without timings), and the
image-returning operations additionally carry the issue-#20 ``timing``
block — ``lock_wait_ms``, ``ps_ms``, ``ps_spawns``, ``total_ms`` plus the
three guest marker keys (``ps_startup_ms``, ``psdirect_session_ms``,
``guest_ms``), null when no marker was emitted; the WMI
transport additionally has no per-call COM timeout — a hung provider
blocks that VM's operations until it returns, where the PowerShell
transport's child process is killed at its timeout.

One process per call (issue #18): the PowerShell transport folds the VM
resolution, the device/head lookups and the operation into ONE script per
call. The prelude binds ``$vmTarget`` — the PR #4 resolver embedded for
by-name callers, the validated GUID preamble for by-id callers — and the
script emits its metadata (``VMID=``, ``HEAD=``, ``SIZES=``/``USED=``,
``ATTEMPTED=``, ``HEADX=``/``HEADY=``, ``RC=``/``CHUNK=``,
``STOP=``/``POLLS=``/``HASH=``, ``FRAME=``) as KEY=value stdout lines ahead
of the payload JSON. Chunked keyboard input loops inside the script (typed
text rides stdin as base64 lines; scancodes ride in the script), the
screenshot fallback chain loops its de-duplicated size list in the script,
and the mouse lookup is scoped to the VM with a ``SystemName`` key filter
with an ``Msvm_Ps2Mouse`` fallback for non-positional operations. A by-id
call resolves host-side first, because policy must run on the GUID's
resolved name before any guest mutation — so by-id starts two processes
(resolve + folded op) and by-name starts exactly one. The one exception is
``capture_sequence``: it has no payload to carry between frames, so each
frame is its own self-contained folded process (``count`` processes by
name, ``count + 1`` by id).

All operations target root\\virtualization\\v2 WMI objects — independent of
VMConnect windows, the host foreground window, guest login, and guest
networking. Verified against the live host (see tasks/console-controller
probes):

  - Screenshot: Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage
    takes TargetSystem/WidthPixels/HeightPixels (parameter is TargetSystem —
    there is no Vm parameter on this build). Returns ReturnValue UInt32
    (0 = success) plus ImageData of length w*h*2 + 4: an opaque 4-byte prefix
    followed by little-endian RGB565 pixels. Any other length is a structured
    error — a corrupt image is never returned as success.
  - Keyboard: Msvm_Keyboard associated to the VM (association works directly).
    TypeText(AsciiText), TypeKey(KeyCode:UInt32), TypeScancodes(UInt8Array),
    PressKey/ReleaseKey(KeyCode:UInt32), TypeCtrlAltDel.
  - Mouse: Msvm_SyntheticMouse selected by its SystemName key (a
    CIM_LogicalDevice key whose value is the VM's Msvm_ComputerSystem Name) —
    a direct class query keeps the derived type, whose methods
    SetAbsolutePosition(HorizontalPosition:SInt32, VerticalPosition:SInt32),
    ClickButton(ButtonIndex:UInt32), SetButtonState(ButtonIndex, IsDown),
    GetButtonState(ButtonIndex), SetScrollPosition(ScrollPositionDelta) are
    invokable. A VM without a synthetic mouse (Gen1 without integration
    services) falls back to Msvm_Ps2Mouse for button, scroll and
    click-at-current-position; absolute positioning has no PS/2 equivalent, so
    positional ops report the structured error instead of acting.
  - Coordinate mapping: the thumbnail is a scaled snapshot of the display
    head; mouse coordinates are in head space (Msvm_VideoHead
    CurrentHorizontal/VerticalResolution). Frame-space inputs are scaled by
    head/frame — in the PowerShell script, with the same rounding and
    clamping as the Python reference _scale_to_head — and when neither frame
    dims nor head resolution are available the tools error instead of
    clicking somewhere unverified.

WinPE / MDT note: screenshots and input work from firmware through WinPE —
PowerShell Direct is unavailable there by design. Tool results return IMAGES
plus frame hashes for visual interpretation; no OCR text is ever invented.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import itertools
import json
import math
import operator
import os
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from PIL import Image as PILImage
from PIL import features as _PILFeatures

from . import guestexec, policy, pswindows, vmident, vmlocks, wmiconsole
from . import timing as timing_mod
from .config import Config

_WMI_NS = "root\\virtualization\\v2"

# ---------------------------------------------------------------------------
# host-side name->GUID hint map (issue #77)
#
# The folded one-process transport (issue #18) resolves a by-name caller
# INSIDE the op script, so the host does not know the GUID before the spawn
# and the console-input lock key used to be the caller-supplied name — which
# split the exclusion namespace against every by-id caller. The hint map
# closes that without giving back the one-process property: every op whose
# stdout already carries a `VMID=` line feeds it, and a hinted by-name call
# locks on the GUID and embeds an in-script identity guard that fails closed
# BEFORE any input when the live resolution disagrees (the stale-hint
# invalidation rule — the guard plus refresh, never a TTL guess). With no
# hint the call stays name-keyed until a feeding read/sequence operation
# supplies one: raw input scripts neither emit nor parse VMID, so an
# input-only by-name caller stays unhinted (disclosed residual, tracked in
# the _input_lock docstring). Hints are process-local host-derived facts (a
# GUID and the name that produced it — no secrets), bounded, and never
# trusted for action: only the in-script compare against the live $vmTarget
# decides identity.
# ---------------------------------------------------------------------------

_HINT_CAP = 512
_NAME_GUID_HINTS: dict[str, str] = {}
_HINT_LOCK = threading.Lock()


def note_name_guid_hint(vm_name: str, guid: str) -> None:
    """Record a host-side name->GUID hint (no spawn, no guest effect).

    Called by every consumer of a folded script's `VMID=` stdout line and
    available as a seam for hosts that already know the mapping. The GUID is
    shape-validated; an invalid or empty value is ignored, never stored.
    """
    try:
        guid = guestexec.validate_vm_guid(guid).lower()
    except ValueError:
        return
    if not vm_name or not vm_name.strip():
        return
    key = vm_name.strip().casefold()
    with _HINT_LOCK:
        _NAME_GUID_HINTS.pop(key, None)
        _NAME_GUID_HINTS[key] = guid
        while len(_NAME_GUID_HINTS) > _HINT_CAP:
            _NAME_GUID_HINTS.pop(next(iter(_NAME_GUID_HINTS)))


def _hint_for(vm_name: str) -> str | None:
    if not vm_name:
        return None
    with _HINT_LOCK:
        return _NAME_GUID_HINTS.get(vm_name.strip().casefold())


_IDENTITY_MARKER_PREFIX = "console input precondition: VM identity changed under name "


def _identity_guard(expected_guid: str, vm_name: str) -> str:
    """The fail-closed in-script identity check (issue #77): emitted right
    after the resolver binds $vmTarget and BEFORE any input. On a stale hint
    the child exits 1 with the marker on stderr before the op script's first
    action; the host refreshes the hint from the resolved GUID the marker
    carries (_check_input_rc)."""
    quoted_name = pswindows.ps_quote(vm_name)
    return (
        'if ("$vmTarget" -ne ' + pswindows.ps_quote(expected_guid) + ") {\n"
        "  [Console]::Error.WriteLine(" + pswindows.ps_quote(_IDENTITY_MARKER_PREFIX) +
        " + " + quoted_name + " + " +
        pswindows.ps_quote(": locked " + expected_guid + " but resolved ") + " + $vmTarget)\n"
        "  exit 1\n"
        "}\n"
    )


@contextmanager
def _input_lock(ref: vmident.VMRef) -> Iterator[None]:
    """Console input lock scope (issue #14): READ on the VM key so guest
    work proceeds during typing, plus WRITE on the second (vm, "console")
    key so two agents cannot interleave keystrokes. VM key is always
    outermost — no other site takes the console key, so no ordering cycle.

    Both keys are derived from ``ref.id``, which is the resolved GUID on the
    WMI transport, on the by-id PowerShell path, and — since issue #77 — on the
    by-name PowerShell path whenever the host-side hint map knows the name
    (the ref then carries the hinted GUID and the op script carries the
    in-script identity guard). With no hint the by-name path still keys on the
    caller-supplied NAME, where issue #18's fold resolves the VM inside the op
    script and the GUID is not known host-side before the spawn: the call
    stays name-keyed until a feeding read/sequence operation supplies a hint
    (raw input scripts neither emit nor parse VMID). Exclusion therefore spans
    name-vs-GUID addressing once a hint exists; the unhinted window is the
    disclosed residual, and the hinted-state guard keeps a stale hint from
    ever ACTING on the wrong identity.
    """
    with vmlocks.vm_lock(ref.id, mode="read"), vmlocks.vm_lock((ref.id, "console")):
        yield
_PREFIX_LEN = 4

# Distinguishes the sibling temp files of two concurrent saves to the same
# path within one process; os.getpid() separates the processes.
_save_counter = itertools.count()

# Frame is the public return type of the image-producing operations, so it is
# nameable by downstream consumers rather than an underscore-private detail.
__all__ = ["ConsoleError", "Frame"]

# PS/2 scan-code set 1: (make, break) without the 0xE0 prefix. Keys in
# _EXTENDED_KEYS are emitted with 0xE0 before make and before break.
_KEY_SCANCODES: dict[str, tuple[int, int]] = {
    "enter": (0x1C, 0x9C),
    "escape": (0x01, 0x81),
    "esc": (0x01, 0x81),
    "tab": (0x0F, 0x8F),
    "backspace": (0x0E, 0x8E),
    "space": (0x39, 0xB9),
    "capslock": (0x3A, 0xBA),
    "delete": (0x53, 0xD3),
    "insert": (0x52, 0xD2),
    "home": (0x47, 0xC7),
    "end": (0x4F, 0xCF),
    "pageup": (0x49, 0xC9),
    "pagedown": (0x51, 0xD1),
    "up": (0x48, 0xC8),
    "down": (0x50, 0xD0),
    "left": (0x4B, 0xCB),
    "right": (0x4D, 0xCD),
    "f1": (0x3B, 0xBB),
    "f2": (0x3C, 0xBC),
    "f3": (0x3D, 0xBD),
    "f4": (0x3E, 0xBE),
    "f5": (0x3F, 0xBF),
    "f6": (0x40, 0xC0),
    "f7": (0x41, 0xC1),
    "f8": (0x42, 0xC2),
    "f9": (0x43, 0xC3),
    "f10": (0x44, 0xC4),
    "f11": (0x57, 0xD7),
    "f12": (0x58, 0xD8),
    "leftshift": (0x2A, 0xAA),
    "rightshift": (0x36, 0xB6),
    "leftctrl": (0x1D, 0x9D),
    "rightctrl": (0x1D, 0x9D),
    "leftalt": (0x38, 0xB8),
    "rightalt": (0x38, 0xB8),
    # letters (set 1 make codes; break = make | 0x80)
    "q": (0x10, 0x90), "w": (0x11, 0x91), "e": (0x12, 0x92), "r": (0x13, 0x93),
    "t": (0x14, 0x94), "y": (0x15, 0x95), "u": (0x16, 0x96), "i": (0x17, 0x97),
    "o": (0x18, 0x98), "p": (0x19, 0x99),
    "a": (0x1E, 0x9E), "s": (0x1F, 0x9F), "d": (0x20, 0xA0), "f": (0x21, 0xA1),
    "g": (0x22, 0xA2), "h": (0x23, 0xA3), "j": (0x24, 0xA4), "k": (0x25, 0xA5),
    "l": (0x26, 0xA6),
    "z": (0x2C, 0xAC), "x": (0x2D, 0xAD), "c": (0x2E, 0xAE), "v": (0x2F, 0xAF),
    "b": (0x30, 0xB0), "n": (0x31, 0xB1), "m": (0x32, 0xB2),
    # digits row
    "1": (0x02, 0x82), "2": (0x03, 0x83), "3": (0x04, 0x84), "4": (0x05, 0x85),
    "5": (0x06, 0x86), "6": (0x07, 0x87), "7": (0x08, 0x88), "8": (0x09, 0x89),
    "9": (0x0A, 0x8A), "0": (0x0B, 0x8B),
    # punctuation (set 1 make codes; break = make | 0x80)
    "minus": (0x0C, 0x8C), "equals": (0x0D, 0x8D),
    "leftbracket": (0x1A, 0x9A), "rightbracket": (0x1B, 0x9B),
    "semicolon": (0x27, 0xA7), "apostrophe": (0x28, 0xA8), "grave": (0x29, 0xA9),
    "backslash": (0x2B, 0xAB),
    "comma": (0x33, 0xB3), "period": (0x34, 0xB4), "slash": (0x35, 0xB5),
    # numeric keypad: unprefixed except numdivide/numenter, which the
    # controller emits with the 0xE0 prefix (see _EXTENDED_KEYS)
    "num0": (0x52, 0xD2), "num1": (0x4F, 0xCF), "num2": (0x50, 0xD0),
    "num3": (0x51, 0xD1), "num4": (0x4B, 0xCB), "num5": (0x4C, 0xCC),
    "num6": (0x4D, 0xCD), "num7": (0x47, 0xC7), "num8": (0x48, 0xC8),
    "num9": (0x49, 0xC9), "numdecimal": (0x53, 0xD3),
    "nummultiply": (0x37, 0xB7), "numsubtract": (0x4A, 0xCA),
    "numadd": (0x4E, 0xCE), "numlock": (0x45, 0xC5),
    "numdivide": (0x35, 0xB5), "numenter": (0x1C, 0x9C),
    # Windows (GUI) and Application keys: extended, E0 before make and break
    "leftwin": (0x5B, 0xDB), "rightwin": (0x5C, 0xDC), "apps": (0x5D, 0xDD),
}
# Extended (0xE0-prefixed) keys per the PS/2 set-1 controller stream.
# rightctrl/rightalt share the left-side make/break bytes but the controller
# requires the 0xE0 prefix to distinguish them from left-ctrl/left-alt.
# Membership is keyed by the CALLED name: the aliases win/menu are listed
# here so they encode with the same E0 prefix as leftwin/apps (issue #25).
_EXTENDED_KEYS = {"up", "down", "left", "right", "delete", "insert",
                  "home", "end", "pageup", "pagedown", "rightctrl", "rightalt",
                  "leftwin", "rightwin", "apps", "win", "menu",
                  "numdivide", "numenter"}
# Aliases that map onto other entries.
_KEY_SCANCODES["ctrl"] = _KEY_SCANCODES["leftctrl"]
_KEY_SCANCODES["alt"] = _KEY_SCANCODES["leftalt"]
_KEY_SCANCODES["shift"] = _KEY_SCANCODES["leftshift"]
_KEY_SCANCODES["win"] = _KEY_SCANCODES["leftwin"]
_KEY_SCANCODES["menu"] = _KEY_SCANCODES["apps"]
# Single-character punctuation aliases (populated by the loop below; kept as
# a set so the recovery message can list them as a separate space-separated
# clause instead of interleaving them into the comma-separated name list).
_PUNCT_ALIASES: set[str] = set()
for _punct_alias, _punct_name in (
        ("-", "minus"), ("=", "equals"), ("[", "leftbracket"),
        ("]", "rightbracket"), ("\\", "backslash"), (";", "semicolon"),
        ("'", "apostrophe"), ("`", "grave"), (",", "comma"), (".", "period"),
        ("/", "slash")):
    _KEY_SCANCODES[_punct_alias] = _KEY_SCANCODES[_punct_name]
    _PUNCT_ALIASES.add(_punct_alias)
del _punct_alias, _punct_name


class ConsoleError(RuntimeError):
    """Structured console-operation failure."""


# ---------------------------------------------------------------------------
# script fragments (all single-purpose, parse-tested)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# folded single-process script construction (issue #18)
#
# Every console call used to resolve the VM GUID, then the display head, then
# the device, each in its own powershell.exe (2-6 cold PowerShell 5.1 starts
# per call). Each op now builds ONE script: a prelude binds $vmTarget (the PR
# #4 resolver embedded by name, or the validated GUID preamble by id), one
# in-process WMI lookup fetches $vm, and the operation runs — chunked input
# and the screenshot fallback chain loop inside the script.
# ---------------------------------------------------------------------------

def _vm_prelude(
    cfg: Config, vm_name: str, vm_id: str, timing: _PsTiming, guarded: bool = False,
) -> tuple[str, vmident.VMRef]:
    """(prelude, ref): the script lines binding $vmTarget, plus the ref the
    caller needs (the console-input lock key and the result's display name).

    By id: vmident.resolve runs first (one spawn) so policy.vm_allowed sees the
    GUID's resolved name BEFORE any guest mutation (issue #8's contract), then
    the preamble binds the validated GUID directly. By name: the caller-name
    validation and policy.vm_allowed run host-side with no spawn (a denied name
    still starts nothing), the PR #4 resolver is embedded unchanged, and the
    GUID arrives on stdout when the process runs. With a host-side hint
    (issue #77) the ref carries the hinted GUID — the lock keys on the
    canonical identity — and `guarded=True` embeds the in-script identity
    guard that fails closed on a stale hint before any input; with no hint the
    ref carries the caller-supplied name as its lock key (the disclosed cold
    path)."""
    if vm_id:
        ref = _resolve_ps(cfg, vm_name, vm_id, timing)
        return guestexec.vm_target_preamble(ref.id), ref
    vmident.checked_caller_name(vm_name)
    policy.vm_allowed(cfg, vm_name)
    hint = _hint_for(vm_name) if guarded else None
    if hint is not None:
        return (
            vmident.resolver_prelude(vm_name) + _identity_guard(hint, vm_name),
            vmident.VMRef(id=hint, name=vm_name),
        )
    return vmident.resolver_prelude(vm_name), vmident.VMRef(id=vm_name, name=vm_name)


_VM_LOOKUP = (
    "$vm = Get-CimInstance -Namespace '" + _WMI_NS + "' -ClassName Msvm_ComputerSystem "
    "-Filter \"Name='$vmTarget'\"\n"
    "if (-not $vm) { throw 'VM not found in WMI namespace (is it running?)' }\n"
)

_KEYBOARD_LOOKUP = (
    "$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard "
    "| Select-Object -First 1\n"
    "if (-not $kb) { throw 'no keyboard device associated with the VM' }\n"
)

# The OBSERVING variant (get_display_info): absence is data, not an error — the
# base script and the WMI transport both report keyboard_present=false, and a
# stopped VM (which is exactly what this tool inspects) carries no keyboard
# association, so the throwing input-op guard must not be folded in here.
_KEYBOARD_LOOKUP_SOFT = (
    "$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard "
    "| Select-Object -First 1\n"
)

# The synthetic mouse is selected with a SystemName key filter (FND-16): the
# per-device association scan this replaces was O(#mice on host) WMI calls.
_MOUSE_SYNTHETIC = (
    "$m = Get-CimInstance -Namespace '" + _WMI_NS + "' -ClassName Msvm_SyntheticMouse "
    "-Filter \"SystemName='$vmTarget'\"\n"
)

# PS/2 fallback (AC14): Msvm_Ps2Mouse supports SetButtonState, SetScrollPosition
# and ClickButton but NOT SetAbsolutePosition, so it serves non-positional ops
# only — positional ops raise the structured error instead of acting.
_MOUSE_PS2 = (
    "$m = Get-CimInstance -Namespace '" + _WMI_NS + "' -ClassName Msvm_Ps2Mouse "
    "-Filter \"SystemName='$vmTarget'\"\n"
)

_HEAD_LOOKUP = (
    "$vh = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VideoHead "
    "| Select-Object -First 1\n"
)

# In-script replication of _scale_to_head (issue #18): the head resolution is
# only known inside the script, so the frame->head scaling runs there. Python
# round() and [math]::Round both round half to even, and the grouping below is
# the same expression order, so the results are bit-identical to the Python
# reference (AC16 keeps _scale_to_head as that reference).
_SCALE_TO_HEAD = (
    "$x = %X\n"
    "$y = %Y\n"
    "$fw = %FW\n"
    "$fh = %FH\n"
    "$hw = $vh.CurrentHorizontalResolution\n"
    "$hh = $vh.CurrentVerticalResolution\n"
    "if ($fw -or $fh) {\n"
    "    $hx = [math]::Round($x * $hw / $fw)\n"
    "    $hy = [math]::Round($y * $hh / $fh)\n"
    "} else {\n"
    "    $hx = $x\n"
    "    $hy = $y\n"
    "}\n"
    "$hx = [math]::Max(0, [math]::Min($hx, $hw - 1))\n"
    "$hy = [math]::Max(0, [math]::Min($hy, $hh - 1))\n"
)


def _folded_mouse_positional_script(
    prelude: str, x: int, y: int, frame_w: int, frame_h: int,
    click: bool, button: int,
) -> str:
    """One positional mouse op (mouse_move, click with coordinates) in one
    process. The synthetic mouse is REQUIRED — absolute positioning has no PS/2
    equivalent, so its absence raises the structured error instead of acting.
    The head is looked up in-script and its absence throws rather than clicking
    blind, and _scale_to_head's arithmetic runs here with the same grouping as
    the Python reference."""
    parts = [
        prelude,
        _VM_LOOKUP,
        _MOUSE_SYNTHETIC,
        "if (-not $m) { throw 'no synthetic mouse device associated with the VM; "
        "absolute positioning is unavailable (the PS/2 fallback supports button, "
        "scroll and click-at-current-position only)' }",
        _HEAD_LOOKUP,
        # The guard rejects a head that reports no resolution as well as a head
        # that is absent: wmiconsole.head_resolution, _scale_to_head and
        # _parse_head all treat a zero-resolution head as unavailable, and the
        # in-script clamp would otherwise collapse a 0/null resolution to (0,0)
        # and position at the origin instead of erroring.
        "if ((-not $vh) -or (-not $vh.CurrentHorizontalResolution) "
        "-or (-not $vh.CurrentVerticalResolution)) { throw 'display head "
        "resolution unavailable: pass frame_width/frame_height equal to the "
        "display resolution to skip scaling' }",
        _SCALE_TO_HEAD
        .replace("%X", str(x)).replace("%Y", str(y))
        .replace("%FW", str(frame_w)).replace("%FH", str(frame_h)),
        "$r0 = Invoke-CimMethod -InputObject $m -MethodName SetAbsolutePosition "
        "-ErrorAction Stop -Arguments @{ HorizontalPosition = $hx; VerticalPosition = $hy }",
        "if ($r0.ReturnValue -ne 0) { throw ('SetAbsolutePosition failed with "
        "ReturnValue=' + $r0.ReturnValue) }",
    ]
    if click:
        parts += [
            "$r = Invoke-CimMethod -InputObject $m -MethodName ClickButton "
            "-ErrorAction Stop -Arguments @{ ButtonIndex = " + str(button) + " }",
            "if ($r.ReturnValue -ne 0) { throw ('ClickButton failed with "
            "ReturnValue=' + $r.ReturnValue) }",
            "Write-Output ('RC=' + $r.ReturnValue)",
        ]
    parts += [
        "Write-Output ('HEADX=' + $hx)",
        "Write-Output ('HEADY=' + $hy)",
    ]
    return "\n".join(parts)


def _require_int(meta: dict[str, str], key: str, ctx: str) -> int:
    raw = meta.get(key, "")
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ConsoleError(f"console {ctx}: missing {key} in the folded result") from None


def _folded_screenshot_script(prelude: str, width: int, height: int) -> str:
    """One script for the whole capture: the de-duplicated size chain
    (requested -> head native if different -> 640x480 -> 320x240) is built and
    looped in-process, never attempting a size twice; metadata rides stdout
    ahead of the payload JSON."""
    return "\n".join([
        prelude,
        _VM_LOOKUP,
        "$svc = Get-CimInstance -Namespace '" + _WMI_NS + "' "
        "-ClassName Msvm_VirtualSystemManagementService\n",
        _HEAD_LOOKUP,
        "if ($vh) { Write-Output ('HEAD=' + $vh.CurrentHorizontalResolution + 'x' "
        "+ $vh.CurrentVerticalResolution) }\n",
        "Write-Output ('VMID=' + $vmTarget)\n",
        "$sizes = @(,(" + str(width) + "," + str(height) + "))\n",
        "if ($vh) {\n",
        "    $hh = $vh.CurrentHorizontalResolution\n",
        "    $vv = $vh.CurrentVerticalResolution\n",
        "    $dup = $false\n",
        "    foreach ($s in $sizes) { if ($s[0] -eq $hh -and $s[1] -eq $vv) { $dup = $true } }\n",
        "    if (-not $dup) { $sizes += ,($hh,$vv) }\n",
        "}\n",
        "$sizes += ,(640,480)\n",
        "$sizes += ,(320,240)\n",
        "$seen = @{}\n",
        "$attempted = @()\n",
        "$used = $null\n",
        "$payload = $null\n",
        "$lastError = ''\n",
        "foreach ($s in $sizes) {\n",
        "    $key = '' + $s[0] + 'x' + $s[1]\n",
        "    if ($seen.ContainsKey($key)) { continue }\n",
        "    $seen[$key] = $true\n",
        "    $attempted += $key\n",
        "    try {\n",
        "        $r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage "
        "-ErrorAction Stop -Arguments @{\n",
        "            TargetSystem = $vm\n",
        "            WidthPixels  = $s[0]\n",
        "            HeightPixels = $s[1]\n",
        "        }\n",
        "        if ($r.ReturnValue -ne 0) { throw ('GetVirtualSystemThumbnailImage failed "
        "with ReturnValue=' + $r.ReturnValue) }\n",
        "        $used = $key\n",
        "        $payload = $r.ImageData\n",
        "        break\n",
        "    } catch {\n",
        "        $lastError = $_.Exception.Message\n",
        "    }\n",
        "}\n",
        "if ($used -eq $null) {\n",
        "    Write-Output ('ATTEMPTED=' + ($attempted -join ','))\n",
        "    throw $lastError\n",
        "}\n",
        "Write-Output ('SIZES=' + ($attempted -join ','))\n",
        "Write-Output ('USED=' + $used)\n",
        "[PSCustomObject]@{\n",
        "    returnValue = 0\n",
        "    imageDataB64 = [Convert]::ToBase64String($payload)\n",
        "} | ConvertTo-Json -Compress\n",
    ])


def _folded_capture_script(prelude: str, width: int, height: int) -> str:
    """One self-contained capture at a single size (capture_sequence's per-frame
    script: each frame resolves the VM itself, so no separate GUID process)."""
    return "\n".join([
        prelude,
        _VM_LOOKUP,
        "$svc = Get-CimInstance -Namespace '" + _WMI_NS + "' "
        "-ClassName Msvm_VirtualSystemManagementService\n",
        "$r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage "
        "-ErrorAction Stop -Arguments @{\n",
        "    TargetSystem = $vm\n",
        "    WidthPixels  = " + str(width) + "\n",
        "    HeightPixels = " + str(height) + "\n",
        "}\n",
        "if ($r.ReturnValue -ne 0) { throw ('GetVirtualSystemThumbnailImage failed "
        "with ReturnValue=' + $r.ReturnValue) }\n",
        # Per-frame identity emission (issue #82): each folded process resolves
        # the VM by name, so the frame reports the GUID it actually captured
        # and the host can refuse a sequence that spans two identities.
        # $vmTarget IS the validated GUID on both addressing paths (the PR #4
        # resolver binds it by name, the preamble binds it by id) —
        # Msvm_ComputerSystem has no Id property (Name carries the GUID), so
        # the emission must read $vmTarget like the screenshot script does.
        "Write-Output ('VMID=' + $vmTarget)\n",
        "[PSCustomObject]@{\n",
        "    returnValue = $r.ReturnValue\n",
        "    imageDataB64 = [Convert]::ToBase64String($r.ImageData)\n",
        "} | ConvertTo-Json -Compress\n",
    ])


# Poll loop: bounded by max_polls. When the baseline is empty the FIRST polled
# frame becomes the baseline (first-poll-is-baseline semantics); change is
# reported only when a later poll's hash differs from that baseline. HASH is
# always the full lowercase-hex sha256 of the PIXEL payload (the ImageData bytes
# after the 4-byte opaque prefix) — byte-identical to the host-side _frame_hash,
# so a returned frame_hash round-trips as a baseline_hash for cross-call change
# detection.
def _folded_wait_frame_script(
    prelude: str, baseline_hash: str, width: int, height: int,
    timeout_s: int, interval_s: int,
) -> str:
    max_polls = math.ceil(timeout_s / interval_s)
    return "\n".join([
        prelude,
        _VM_LOOKUP,
        "$svc = Get-CimInstance -Namespace '" + _WMI_NS + "' "
        "-ClassName Msvm_VirtualSystemManagementService\n",
        "$deadline = (Get-Date).AddSeconds(" + str(int(timeout_s)) + ")\n",
        "$polls = 0\n",
        "$baseline = '" + baseline_hash + "'\n",
        "$lastHash = ''\n",
        "$sha = New-Object Security.Cryptography.SHA256Managed\n",
        "while ($polls -lt " + str(max_polls) + ") {\n",
        "    if ((Get-Date) -ge $deadline) { Write-Output ('STOP=deadline POLLS=' + $polls + ' HASH=' + $lastHash); break }\n",
        "    $r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -ErrorAction Stop -Arguments @{\n",
        "        TargetSystem = $vm\n",
        "        WidthPixels  = " + str(width) + "\n",
        "        HeightPixels = " + str(height) + "\n",
        "    }\n",
        "    if ($r.ReturnValue -ne 0) { throw ('GetVirtualSystemThumbnailImage failed with ReturnValue=' + $r.ReturnValue) }\n",
        "    $polls++\n",
        # A short buffer makes the count negative, and ComputeHash's method
        # error is NON-terminating: without this guard the exception is
        # swallowed, $hash keeps its stale value, the loop polls to the
        # deadline and the caller is told {ok: true, changed: false}. The
        # in-process WMI leg checks the payload against the dimensions it
        # asked for; this leg does the same, so a truncated payload is a
        # structured error on both transports rather than a silently wrong
        # digest.
        "    $pxLen = 0; if ($r.ImageData -ne $null) { $pxLen = $r.ImageData.Length }\n",
        "    $pxWant = 4 + (" + str(width) + " * " + str(height) + " * 2)\n",
        "    if ($pxLen -ne $pxWant) { throw ('thumbnail payload length mismatch: got ' + $pxLen + ' bytes, expected ' + $pxWant) }\n",
        "    $hash = ([System.BitConverter]::ToString($sha.ComputeHash($r.ImageData, 4, $r.ImageData.Length - 4)) -replace '-','').ToLowerInvariant()\n",
        "    $lastHash = $hash\n",
        "    if ($baseline -eq '') { $baseline = $hash }\n",
        "    if ($hash -ne $baseline) {\n",
        "        Write-Output ('STOP=changed POLLS=' + $polls + ' HASH=' + $hash)\n",
        "        Write-Output ('FRAME=' + [Convert]::ToBase64String($r.ImageData))\n",
        "        break\n",
        "    }\n",
        "    if ($polls -ge " + str(max_polls) + " -or (Get-Date) -ge $deadline) { Write-Output ('STOP=deadline POLLS=' + $polls + ' HASH=' + $hash); break }\n",
        "    Start-Sleep -Milliseconds " + str(interval_s * 1000) + "\n",
        "}\n",
    ])


# Settle loop: bounded by max_polls (derived from timeout_s*1000/interval_ms).
# A quiet window of stable_ms must elapse after the most recent CHANGE before
# the loop reports STOP=stable with that settled frame. Without a supplied
# baseline the FIRST polled frame starts the window (first-poll-is-baseline,
# same as the change wait); with a baseline the window starts only at the
# first frame that DIFFERS from it, so "my input did nothing" (STOP=unchanged)
# is distinguishable from "already settled" (STOP=stable). HASH is the full
# lowercase-hex sha256 of the PIXEL payload (bytes after the 4-byte opaque
# prefix) — byte-identical to the host-side _frame_hash, so a returned
# frame_hash round-trips as a baseline_hash. A quiet window longer than
# (max_polls - 1) * interval_ms cannot be observed within the poll cap and
# honestly reports STOP=deadline.
def _folded_wait_stable_script(
    prelude: str, baseline_hash: str, stable_ms: int, width: int, height: int,
    timeout_s: int, interval_ms: int,
) -> str:
    max_polls = math.ceil(timeout_s * 1000 / interval_ms)
    return "\n".join([
        prelude,
        _VM_LOOKUP,
        "$svc = Get-CimInstance -Namespace '" + _WMI_NS + "' "
        "-ClassName Msvm_VirtualSystemManagementService\n",
        "$deadline = (Get-Date).AddSeconds(" + str(int(timeout_s)) + ")\n",
        "$polls = 0\n",
        "$baseline = '" + baseline_hash + "'\n",
        # The reference STARTS at the supplied baseline (empty when none): a
        # frame that still matches the baseline must NOT start the quiet
        # window — only the first frame that DIFFERS from it does (the WMI
        # leg performs the identical init through ref_hash = baseline or None).
        "$refHash = '" + baseline_hash + "'\n",
        "$lastHash = ''\n",
        "$lastChange = $null\n",
        "$moveSeen = $false\n",
        "$sha = New-Object Security.Cryptography.SHA256Managed\n",
        "while ($polls -lt " + str(max_polls) + ") {\n",
        "    if ((Get-Date) -ge $deadline) {\n",
        "        if (($baseline -ne '') -and ($polls -gt 0) -and (-not $moveSeen)) { Write-Output ('STOP=unchanged POLLS=' + $polls + ' HASH=' + $lastHash) }\n",
        "        else { Write-Output ('STOP=deadline POLLS=' + $polls + ' HASH=' + $lastHash) }\n",
        "        break\n",
        "    }\n",
        "    $r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -ErrorAction Stop -Arguments @{\n",
        "        TargetSystem = $vm\n",
        "        WidthPixels  = " + str(width) + "\n",
        "        HeightPixels = " + str(height) + "\n",
        "    }\n",
        "    if ($r.ReturnValue -ne 0) { throw ('GetVirtualSystemThumbnailImage failed with ReturnValue=' + $r.ReturnValue) }\n",
        "    $polls++\n",
        # Same payload guard as the change wait: ComputeHash's method error is
        # NON-terminating, so a truncated payload must be a structured error
        # rather than a silently stale digest (see the change-wait template).
        "    $pxLen = 0; if ($r.ImageData -ne $null) { $pxLen = $r.ImageData.Length }\n",
        "    $pxWant = 4 + (" + str(width) + " * " + str(height) + " * 2)\n",
        "    if ($pxLen -ne $pxWant) { throw ('thumbnail payload length mismatch: got ' + $pxLen + ' bytes, expected ' + $pxWant) }\n",
        "    $hash = ([System.BitConverter]::ToString($sha.ComputeHash($r.ImageData, 4, $r.ImageData.Length - 4)) -replace '-','').ToLowerInvariant()\n",
        "    $lastHash = $hash\n",
        # ONE clock read per poll, reused for both the window stamp and the
        # comparison: PS 5.1's DateTime granularity (~15.6 ms) would let a
        # fresh Get-Date read >= stable_ms on the very poll that OBSERVED the
        # change (stable_ms=1 is legal), reporting a mid-animation frame as
        # settled. Reusing $now pins the change poll's elapsed at exactly 0,
        # which is the WMI leg's behavior by construction.
        "    $now = Get-Date\n",
        "    if ($refHash -eq '') { $refHash = $hash; $lastChange = $now }\n",
        "    elseif ($hash -ne $refHash) { $refHash = $hash; $lastChange = $now; $moveSeen = $true }\n",
        "    if (($null -ne $lastChange) -and ((($now) - ($lastChange)).TotalMilliseconds -ge " + str(stable_ms) + ")) {\n",
        "        Write-Output ('STOP=stable POLLS=' + $polls + ' HASH=' + $hash + ' STABLE_MS=' + [int](($now) - ($lastChange)).TotalMilliseconds)\n",
        "        Write-Output ('FRAME=' + [Convert]::ToBase64String($r.ImageData))\n",
        "        break\n",
        "    }\n",
        "    if ($polls -ge " + str(max_polls) + " -or (Get-Date) -ge $deadline) {\n",
        "        if (($baseline -ne '') -and ($polls -gt 0) -and (-not $moveSeen)) { Write-Output ('STOP=unchanged POLLS=' + $polls + ' HASH=' + $hash) }\n",
        "        else { Write-Output ('STOP=deadline POLLS=' + $polls + ' HASH=' + $hash) }\n",
        "        break\n",
        "    }\n",
        "    Start-Sleep -Milliseconds " + str(interval_ms) + "\n",
        "}\n",
    ])


# ---------------------------------------------------------------------------
# folded-protocol stdout parsing
# ---------------------------------------------------------------------------

def _meta_lines(result: pswindows.PSResult) -> tuple[dict[str, str], str]:
    """(tagged metadata, payload line) from a folded script's stdout.

    The folded scripts emit KEY=value metadata lines (VMID=, HEAD=, SIZES=,
    USED=, HEADX=, HEADY=, RC=) and, where the op returns a payload, the
    payload/op JSON as the final stdout line. Metadata lines are recognized by
    shape, so an op whose whole stdout is metadata (the mouse ops) keeps all of
    it; a response with no payload line at all is a structured error for the
    ops that need one, exactly as a malformed capture JSON is.
    """
    meta: dict[str, str] = {}
    payload = ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            meta[key] = value.strip()
        else:
            payload = line
    return meta, payload


def _parse_guid(meta: dict[str, str], vm_name: str) -> str:
    """The script-resolved GUID, re-validated through the same shape gate a
    host-resolved GUID passes (review PRR-028)."""
    guid = meta.get("VMID", "")
    if not guid:
        raise ConsoleError(f"VM '{vm_name}' resolved to an empty Id")
    try:
        return guestexec.validate_vm_guid(guid).lower()
    except ValueError as exc:
        raise ConsoleError(f"VM '{vm_name}' resolved to an invalid Id: {exc}") from None


def _parse_head(meta: dict[str, str]) -> tuple[int, int] | None:
    raw = meta.get("HEAD", "")
    if not raw or "x" not in raw:
        return None
    try:
        h, v = raw.split("x", 1)
        hi, vi = int(h), int(v)
    except ValueError:
        return None
    return (hi, vi) if hi > 0 and vi > 0 else None


def _parse_size(meta: dict[str, str], key: str) -> tuple[int, int] | None:
    raw = meta.get(key, "")
    if not raw or "x" not in raw:
        return None
    try:
        w, h = raw.split("x", 1)
        wi, hi = int(w), int(h)
    except ValueError:
        return None
    # A zero or negative dimension is as unusable as a malformed one: it would
    # decode a 0-byte (or negative-length) frame and mis-name the length
    # expectation, so the caller falls back exactly as it does when the line is
    # absent (the payload-length check then reports the real mismatch).
    return (wi, hi) if wi > 0 and hi > 0 else None


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------

def _check_rc(result: pswindows.PSResult, ctx: str) -> pswindows.PSResult:
    try:
        return pswindows.check_result(result, ctx)
    except RuntimeError as exc:
        raise ConsoleError(str(exc)) from None


def _check_input_rc(
    result: pswindows.PSResult, ctx: str, vm_name: str,
) -> pswindows.PSResult:
    """_check_rc for console_input ops, plus the issue #77 stale-hint
    invalidation: when the folded script's identity guard fired (its marker
    names the GUID the resolver actually produced), refresh the hint map from
    that live GUID before surfacing the structured error, so the caller's
    retry locks on the identity the VM really has."""
    try:
        return pswindows.check_result(result, ctx)
    except RuntimeError as exc:
        message = str(exc)
        if "VM identity changed under name" in message:
            match = re.search(
                r"locked [0-9a-f-]+ but resolved ([0-9a-fA-F-]{36})", message)
            if match:
                note_name_guid_hint(vm_name, match.group(1))
        raise ConsoleError(message) from None


# ---------------------------------------------------------------------------
# transport selection (issue #45)
# ---------------------------------------------------------------------------

class _PsTiming:
    """Per-op PowerShell timing accumulator: one float per run_ps call the
    operation made (the vmident.resolve leg included)."""

    __slots__ = ("spawn_ms",)

    def __init__(self) -> None:
        self.spawn_ms: list[float] = []


def _ps_timings(timing: _PsTiming) -> dict:
    return {"transport": "powershell", "spawn_ms": timing.spawn_ms}


def _wmi_timings(connect_ms: float, *phase_dicts: dict) -> dict:
    rebind = sum(float(t.get("rebind_ms", 0.0)) for t in phase_dicts)
    method = sum(float(t.get("method_ms", 0.0)) for t in phase_dicts)
    return {
        "transport": "wmi",
        "connect_ms": float(connect_ms),
        "rebind_ms": float(rebind),
        "method_ms": float(method),
    }


def _meta_timing(t0: float, ps_timing: _PsTiming | None, *, wmi: bool = False) -> dict:
    """The per-call `timing` block for an image tool's metadata (issue #20).

    Prefers the active audit operation's collector. That is the value the
    server records ONLY IF this snapshot is taken at the operation's end: a
    caller that runs further legs after it (evidence.capture_evidence's UI
    tree) must re-snapshot from the collector, or its metadata disagrees with
    the audit row for the same call (feedback PRR-007). With no collector (a
    direct module call — the consolebench operator CLI drives
    console.screenshot that way), the block is derived from the op's own
    accumulators so it is never a fabricated zero.

    `t0` is `time.monotonic()` taken at the op's entry, before transport
    selection; it is unused when a collector is active, because the collector's
    own `total_ms` wins.

    On the in-process WMI path no PowerShell process is started at all, so
    `ps_spawns`/`ps_ms` are honestly zero rather than defaults.
    """
    collector = timing_mod.current()
    if collector is not None:
        return collector.snapshot()
    total_ms = int((time.monotonic() - t0) * 1000)
    if wmi:
        return {**timing_mod.zeroed(), "total_ms": total_ms}
    spawns = list(ps_timing.spawn_ms) if ps_timing is not None else []
    return {
        "lock_wait_ms": 0,
        "ps_ms": int(sum(spawns)),
        "ps_spawns": len(spawns),
        "total_ms": total_ms,
        "ps_startup_ms": None,
        "psdirect_session_ms": None,
        "guest_ms": None,
    }


def _try_backend(cfg: Config) -> tuple[Any | None, float]:
    """(backend, connect_ms) when the in-process WMI transport can serve
    this call, (None, 0.0) otherwise.

    Selection: COM_AVAILABLE is read at CALL time via the module attribute
    (tests patch it). BackendUnavailable raised while constructing the
    backend (connect failure, unusable namespace) selects the PowerShell
    transport — as does a VM that the WMI plane cannot resolve. A WMIError
    from a backend METHOD never falls back: input must never double-send.
    """
    if not wmiconsole.COM_AVAILABLE:
        return None, 0.0
    t0 = time.monotonic()
    try:
        be = wmiconsole.backend(cfg)
    except wmiconsole.BackendUnavailable:
        return None, 0.0
    return be, (time.monotonic() - t0) * 1000.0


def _wmi_ref(be, cfg: Config, vm_name: str, vm_id: str) -> vmident.VMRef:
    """Resolve the VM in-process. BackendUnavailable propagates so the
    caller can select the PowerShell transport; WMIError becomes
    ConsoleError (mirrors vmident's ValueError surfacing). BackendUnavailable
    raised MID-OPERATION (after selection) is converted to ConsoleError by
    the op handlers together with WMIError — no mid-op transport switch."""
    try:
        return be.resolve_vm(cfg, vm_name=vm_name, vm_id=vm_id)
    except wmiconsole.WMIError as exc:
        # selection-time BackendUnavailable must PROPAGATE past here so the
        # caller's selection wrapper can fall back to PowerShell; only
        # WMIError (a resolution failure on a present plane) normalizes.
        raise ConsoleError(str(exc)) from None


def _resolve_ps(cfg: Config, vm_name: str, vm_id: str, timing: _PsTiming) -> vmident.VMRef:
    """vmident.resolve with the resolve leg's wall-clock recorded as one
    spawn_ms entry (vmident makes exactly one run_ps call per resolve, so
    the count parity with a recording run_ps stub is exact)."""
    t0 = time.monotonic()
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    timing.spawn_ms.append((time.monotonic() - t0) * 1000.0)
    return ref


def _run(
    cfg: Config,
    script: str,
    *,
    timeout_s: float | None = None,
    stdin_b64: str | None = None,
    payload_lines: int = 0,
    timing: _PsTiming | None = None,
):
    """console's PowerShell choke (issue #43): composes the remote hop from
    the CALLER's cfg before spawning; identity in local mode. The optional
    timing accumulator records one entry per spawn (issue #45).

    payload_lines is the number of stdin payload lines the script reads (issue
    #18: one folded process carries every chunk's base64 line). In remote mode
    the composer emits one $__pN read per line and forwards the values as
    scriptblock parameters; in local mode the script reads them itself.
    """
    if payload_lines and stdin_b64 is None:
        raise ValueError("payload_lines > 0 requires stdin_b64")
    script, stdin = pswindows.compose_remote(
        cfg, script,
        payload_lines=payload_lines,
        stdin_b64=stdin_b64,
    )
    if stdin is None:
        result = pswindows.run_ps(script, timeout_s=timeout_s)
    else:
        result = pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=stdin)
    if timing is not None:
        timing.spawn_ms.append(float(result.duration_ms))
    return result


def _decode_rgb565(raw: bytes, width: int, height: int) -> bytes:
    """Decode a thumbnail payload (4-byte opaque prefix + RGB565) to PNG.

    Retained for callers that want the encoded bytes. Raises ConsoleError on any
    length/structure mismatch — never returns a corrupt image.
    """
    return _decode_frame(raw, width, height).png


class Frame(PILImage.Image):
    """A decoded console frame together with the single encoding made for it.

    Every returned image used to cost two PNG encodes: one inside the decode and
    one in the server layer that re-opened those bytes. `encoded` is that one
    encoding, so the server reuses the bytes instead of encoding again and
    `save_path` writes exactly the bytes the caller receives. `mime` names the
    format it was made in — `image/png` unless the caller asked for jpeg or
    webp — and `png` remains the PNG-only view, read-only, available only when
    the frame IS a PNG.

    A frame IS a `PIL.Image.Image`, not a wrapper around one: `isinstance`
    checks, the context-manager protocol, numpy interop and every read method
    behave exactly as they did on the return value this replaced. `png` is
    read-only — reassigning it is refused — and is the encoding of the frame's
    own pixels, so a caller that mutates the image and then re-saves it gets
    different bytes, which is what the frame-invariant tests pin.

    Memory: the RASTER is derived from the encoding on the first pixel access
    (see `load`), so an untouched frame retains only the encoded bytes plus the
    handful of scalars PIL needs. Until something reads a pixel, no
    `width*height*3` buffer exists. Dimensions are still clamped to 160..4096
    at every entry point and at most two frames are retained per
    `capture_sequence`, so the worst case after materialisation is roughly
    50 MB per held frame at the ceiling.

    Build one with `Frame.from_image`, not by calling the constructor: the
    class deliberately does not override `PIL.Image.Image.__init__`.
    """

    _png: bytes
    _encoded: bytes
    _mime: str
    _quality: int | None
    # Ours, not PIL's: see `from_image` for why the memoisation flag cannot be
    # keyed on a PIL attribute across the declared `pillow>=10.0` floor.
    _raster_loaded: bool
    # Pillow 10's pixel-access cache, which its `__init__` initialises and
    # Pillow 12 removed. See `from_image`.
    pyaccess: object | None

    @classmethod
    def from_image(
        cls, img: PILImage.Image, mime: str = "image/png", quality: int | None = None
    ) -> Frame:
        """Wrap an already-decoded image, encoding it exactly once.

        Only the ENCODING is retained. The decoded `img` is read for the
        handful of scalars PIL needs before any pixel access (`mode`, `size`,
        `info`, `palette`) — none of which touch the raster — and is then
        released by the caller. The raster comes back from the encoding when
        `load()` runs.
        """
        frame = cls.__new__(cls)
        frame._encoded = _encode(img, mime, quality)
        frame._mime = mime
        frame._png = frame._encoded if mime == "image/png" else b""
        frame._quality = quality
        frame._mode = img.mode
        frame._size = img.size
        frame.palette = img.palette
        frame.info = dict(img.info)
        frame.readonly = 0
        frame._exif = None
        frame._im = None
        # Our OWN materialisation flag. Deliberately not derived from any PIL
        # attribute: PIL moved the raster from the plain `im` attribute (10.x)
        # to a property backed by `_im` (11+), so a guard keyed on either one
        # is version-specific. On the declared floor `pillow>=10.0` a guard
        # reading `_im` never fires, which re-decodes on every pixel access
        # and silently discards mutations.
        frame._raster_loaded = False
        # Pillow 10's `putpixel` reads `self.pyaccess`, which its `__init__`
        # sets to None; Pillow 12 dropped the attribute entirely. Building with
        # `__new__` bypasses that initialiser, so supply it. An attribute a
        # newer Pillow ignores is harmless; a missing one an older Pillow reads
        # is an AttributeError.
        frame.pyaccess = None
        return frame

    def load(self):
        """Materialise the raster from the encoding, exactly once.

        PIL calls `load()` before every pixel access — `getpixel`, `tobytes`,
        `save`, `resize`, `crop`, `convert`, the numpy protocol — so overriding
        it is the single place the raster comes into being, and no other part
        of the class has to know it was ever lazy. The encoding is decoded by
        Pillow's own loader for the format, which is the same decoder that
        produced it, so the pixels are identical to the ones the frame was
        built from.
        """
        if not self._raster_loaded:
            img = PILImage.open(io.BytesIO(self._encoded))
            img.load()
            # The construction-time `info` is the frame's own: `__dict__.update`
            # would replace it wholesale with the decoder's, so a consumer
            # reading `frame.info` before and after a pixel access would see two
            # different dicts. Keep ours.
            info = self.info
            self.__dict__.update(img.__dict__)
            self.info = info
            self._raster_loaded = True
        # Delegate the rest to PIL's own load(), which is idempotent and does
        # the per-version bookkeeping this class must not reimplement: Pillow
        # 10's `putpixel` reads `self.pyaccess`, which only `Image.load()` sets,
        # and Pillow 11+ wraps `_im` in a property that asserts it is not None.
        # Returning PIL's value also honours the documented
        # `-> PixelAccess | None` contract, so `px = img.load(); px[x, y]` works.
        return PILImage.Image.load(self)

    @classmethod
    def from_png(cls, png: bytes) -> Frame:
        """Rebuild a frame from a PNG encoding.

        `_rebuild_frame` handles the general case (any format), so the internal
        copy/deepcopy/pickle path no longer routes through here; this remains
        the explicit PNG entry point for a caller holding PNG bytes. Note that
        rebuilding re-encodes, so it is not a byte-identity guarantee for a
        frame that was created in another format.
        """
        return cls.from_image(PILImage.open(io.BytesIO(png)), "image/png")

    def __copy__(self) -> Frame:
        # PIL.Image.__copy__ returns a plain Image, which would silently drop
        # both the class and the encoding. Clone the raster and carry the
        # SAME encoding bytes across: a copy must not spend a second encode
        # and must not hand back different bytes (bytes are immutable, so
        # sharing them is safe). A copy needs pixels, so the source is
        # materialised here if it was still lazy.
        self.load()
        dup = Frame.__new__(Frame)
        dup.__dict__.update(self.__dict__)
        dup.im = self.im.copy()
        # `dup` now owns a real raster, so it is materialised in its own right.
        dup._raster_loaded = True
        # The copied dict carries the SOURCE's pixel-access cache, which is
        # bound to the source's raster and would alias it. Reset it so PIL
        # rebuilds one for the copy on its next access. Assigning None rather
        # than deleting: Pillow 10's `putpixel` reads the attribute, so it must
        # exist, and a newer Pillow that dropped it simply ignores it.
        dup.pyaccess = None
        return dup

    def __reduce__(self):
        return (_rebuild_frame, (self._encoded, self._mime, self._quality))

    @property
    def encoded(self) -> bytes:
        """The one encoding made for this frame, in the frame's own format."""
        return self._encoded

    @property
    def mime(self) -> str:
        """The MIME type of `encoded` (image/png, image/jpeg or image/webp)."""
        return self._mime

    @property
    def pil_format(self) -> str:
        """The Pillow save-format name for this frame ("PNG"/"JPEG"/"WEBP") —
        what `Image(data=..., format=...)` needs, derived from `mime` so the
        caller never reaches into the format table itself.

        An out-of-table mime is a code-level defect, so it raises ValueError
        (which `errors.classify` reports as `invalid`) rather than the bare
        KeyError that would otherwise surface as `error_class: "transport"`.
        """
        try:
            return _OUTPUT_FORMATS[_normalise_format(self._mime)][0]
        except KeyError:
            raise ValueError(
                f"no Pillow save format is registered for mime {self._mime!r}"
            ) from None

    @property
    def png(self) -> bytes:
        if self._mime != "image/png":
            raise AttributeError(
                f"Frame.png is only available for a PNG frame; this frame is "
                f"{self._mime}. Use Frame.encoded — encoding it a second time "
                f"as PNG would break the one-encode-per-image invariant."
            )
        return self._png

    @png.setter
    def png(self, value: bytes) -> None:
        raise AttributeError(
            "Frame.png is read-only: it is the single encoding of this frame's "
            "pixels. Mutate the image and re-save it instead."
        )


def _rebuild_frame(encoded: bytes, mime: str, quality: int | None = None) -> Frame:
    """Module-level rebuild target so a Frame pickles in its own format.

    The encoding is KEPT VERBATIM and becomes the frame's single encoding: a
    deepcopy or pickle of a frame must not spend a second encode and must not
    hand back different bytes. `quality` rides along so the rebuilt frame still
    knows what it was made with. The frame stays LAZY — `mode`/`size` are read
    from the encoding's header, which Pillow parses without decoding, so a
    pickled-and-restored frame costs no raster either.
    """
    img = PILImage.open(io.BytesIO(encoded))
    frame = Frame.__new__(Frame)
    frame._encoded = encoded
    frame._mime = mime
    frame._png = encoded if mime == "image/png" else b""
    frame._quality = quality
    frame._mode = img.mode
    frame._size = img.size
    frame.palette = img.palette
    frame.info = dict(img.info)
    frame.readonly = 0
    frame._exif = None
    frame._im = None
    frame._raster_loaded = False
    frame.pyaccess = None
    return frame


# Output formats: caller-facing name -> (Pillow save format, MIME type). "jpg"
# is an alias for "jpeg" because mcp's Image._get_mime_type derives the MIME
# type as f"image/{format.lower()}", which would otherwise publish the
# non-standard "image/jpg".
_OUTPUT_FORMATS: dict[str, tuple[str, str]] = {
    "png": ("PNG", "image/png"),
    "jpeg": ("JPEG", "image/jpeg"),
    "jpg": ("JPEG", "image/jpeg"),
    "webp": ("WEBP", "image/webp"),
}


def _encode(img: PILImage.Image, mime: str, quality: int | None = None) -> bytes:
    """Encode a decoded image once, in the format `mime` names.

    `quality` applies to the lossy formats only; PNG has no quality axis, so it
    is accepted and ignored there. A Pillow build without WebP support is a
    caller error, not a crash: the caller validates the format first.
    """
    pil_format = _OUTPUT_FORMATS[_normalise_format(mime)][0]
    buf = io.BytesIO()
    if pil_format == "PNG" or quality is None:
        img.save(buf, format=pil_format)
    else:
        img.save(buf, format=pil_format, quality=quality)
    return buf.getvalue()


def _normalise_format(mime: str) -> str:
    """Canonical key for a caller-supplied format/MIME name."""
    key = str(mime or "").strip().lower()
    if key.startswith("image/"):
        key = key[len("image/"):]
    return key


def _decode_frame(raw: bytes, width: int, height: int) -> Frame:
    """Decode a thumbnail payload to a frame carrying its single PNG encoding."""
    return Frame.from_image(_decode_rgb565_image(raw, width, height))


def _decode_rgb565_image(raw: bytes, width: int, height: int) -> PILImage.Image:
    """Decode a thumbnail payload (4-byte opaque prefix + RGB565) to a PIL image.

    Pillow's native raw decoder does the conversion in C. The output is
    byte-identical to the per-pixel loop this replaced for all 65,536 RGB565
    values, at roughly a hundredth of the cost.

    The length and structure checks run first and raise ConsoleError, because
    `frombuffer` reports a short buffer differently and the payload contract is a
    structured error, never an image.
    """
    expected = width * height * 2 + _PREFIX_LEN
    if len(raw) < _PREFIX_LEN:
        raise ConsoleError(
            f"thumbnail payload too short: {len(raw)} bytes (prefix alone is {_PREFIX_LEN})"
        )
    if len(raw) != expected:
        raise ConsoleError(
            f"thumbnail payload length mismatch: got {len(raw)} bytes, "
            f"expected {expected} ({width}x{height} RGB565 + {_PREFIX_LEN}-byte prefix)"
        )
    return PILImage.frombuffer(
        "RGB", (width, height), raw[_PREFIX_LEN:], "raw", "BGR;16", 0, 1
    )


def _frame_hash(raw: bytes) -> str:
    """SHA-256 of the PIXEL payload — the thumbnail bytes after the opaque
    4-byte prefix, which is exactly the domain `_decode_rgb565_image` decodes.

    Hashing the whole payload used to make an unchanged screen hash differently
    whenever the opaque prefix drifted, so a stored `baseline_hash` could stop
    matching a frame the agent already had. The prefix is outside the frame
    identity, so it is outside the hash. The in-guest poll loop hashes the same
    slice (`ComputeHash($r.ImageData, 4, ...)`) with the same canonical
    lowercase-hex encoding, so the two stay byte-identical.
    """
    return hashlib.sha256(raw[_PREFIX_LEN:]).hexdigest()


# The hash domain, stated so a consumer can tell a pixel-only hash from a
# whole-payload one. Both are 64 lowercase hex characters, so the shapes are
# indistinguishable: a `baseline_hash` recorded by a pre-0.4.0 build hashed
# the whole payload and can therefore never match, and without this marker
# that permanent mismatch is indistinguishable from a genuine screen change
# (poll 1 reports `changed: true` with an image). Record it beside the
# baseline and refuse a baseline from another domain.
HASH_DOMAIN = "sha256/pixels-after-4-byte-prefix"


def _changed_pixel_bytes(prev_raw: bytes | None, raw: bytes) -> int:
    """How many PIXEL bytes differ from the previous capture.

    Same domain as `frame_hash`: the payload after the 4-byte opaque prefix.
    Diffing the whole payload would put two change signals in one `frames[]`
    entry that disagree on exactly the prefix-drift input the pixel-only hash
    exists to handle — an identical `frame_hash` alongside a nonzero byte
    count, which reads as a contradiction to whoever is interpreting it.

    Two costs are avoided. The equal-payload case — an idle console, which is
    the common one — is a single C-level `memcmp` with no Python loop at all.
    When the payloads differ, the count is taken over fixed-size CHUNKS: an
    unchanged chunk is skipped by a single C-level `==`, so only the chunks
    that actually changed are walked. Inside a changed chunk the count uses
    `sum(map(operator.ne, ...))`, which is C-level on both sides and executes
    ZERO Python line events per byte — unlike the per-byte `zip` generator it
    replaced, which cost one line event per byte. So a change confined to one
    64 KiB chunk costs that chunk, and a change in every chunk costs the same
    C-level walk a whole-payload comparison always did.
    """
    if prev_raw is None:
        return 0
    a = prev_raw[_PREFIX_LEN:]
    b = raw[_PREFIX_LEN:]
    if len(a) != len(b):
        # The base implementation got this for free from a whole-payload
        # `zip(..., strict=True)`; chunking would otherwise let a trailing
        # length difference fall outside the last compared chunk and return a
        # silent prefix count. Both transports length-validate every frame
        # against the same fixed per-sequence dimensions, so this guards the
        # contract rather than a reachable path — but a silent 0 for mismatched
        # payloads is worse than a loud failure.
        raise ValueError(f"payload lengths differ: {len(a)} vs {len(b)}")
    if a == b:
        return 0
    # A chunk that divides evenly into the common frame sizes; 64 KiB keeps the
    # slice objects small and the boundary count negligible.
    chunk = 65536
    total = 0
    for start in range(0, len(a), chunk):
        piece_a = a[start:start + chunk]
        piece_b = b[start:start + chunk]
        if piece_a == piece_b:
            continue
        total += sum(map(operator.ne, piece_a, piece_b))
    return total


# ---------------------------------------------------------------------------
# output options (issue #19): format, quality, scale, crop, if_changed_from
#
# The caller's intent used to have nowhere to go: the tool declared no shaping
# parameter and the encode site hardcoded a whole-frame PNG. These options let
# the caller ask for a smaller payload, a region, or "only if it changed", and
# every one of them is validated here so an unsupported value is refused as
# `invalid` instead of being silently ignored.
# ---------------------------------------------------------------------------

def _validate_output_options(fmt: str, quality, scale) -> tuple[str, int | None, float | None]:
    """The frame-INDEPENDENT half of option validation: format, quality, scale.

    Split out so `screenshot` can run it BEFORE the capture. A bad format,
    quality or scale is a deterministic caller error, and charging a
    PowerShell spawn — which holds a `max_host_powershell` slot, or the whole
    WMI fallback chain — for it is avoidable. `crop` and the captured-
    dimension checks stay in `_resolve_output_options`, which runs after the
    capture because the fallback chain can hand back a size other than the one
    requested.
    """
    key = _normalise_format(fmt)
    if not fmt:
        # No format asked for: the PNG default, with no `format` echo key.
        mime = "image/png"
    elif not key:
        # A format the caller DID supply but that normalises away ("image/",
        # "  ") is not a default — it is a value we would otherwise ignore
        # while echoing "image/png" as if it had been honoured.
        raise ValueError(
            f"unsupported format {str(fmt)!r}; supported formats: "
            f"{', '.join(sorted({v[1] for v in _OUTPUT_FORMATS.values()}))}"
        )
    elif key in _OUTPUT_FORMATS:
        mime = _OUTPUT_FORMATS[key][1]
        # Both lossy formats are feature-detected: a Pillow built without
        # libjpeg or WebP would otherwise reach img.save and raise OSError,
        # which errors.classify reports as "transport" rather than the
        # "invalid" this module promises for an unsupported value.
        for feature, label in (("jpg", "jpeg"), ("webp", "webp")):
            if mime.endswith(f"/{label}") and not _PILFeatures.check(feature):
                raise ValueError(
                    f"format {label!r} is not supported by this Pillow build "
                    f"(PIL.features.check({feature!r}) is False)"
                )
    else:
        supported = ", ".join(sorted({v[1] for v in _OUTPUT_FORMATS.values()}))
        raise ValueError(
            f"unsupported format {str(fmt)!r}; supported formats: {supported}"
        )

    if quality is None:
        resolved_quality: int | None = None
    else:
        # bool is an int subclass; reject it explicitly so True cannot pass as 1.
        if isinstance(quality, bool) or not isinstance(quality, int):
            raise ValueError(f"quality must be an integer 1..100, got {quality!r}")
        if not (1 <= quality <= 100):
            raise ValueError(f"quality must be within 1..100, got {quality}")
        resolved_quality = quality

    if scale is None:
        resolved_scale: float | None = None
    else:
        if isinstance(scale, bool) or not isinstance(scale, (int, float)):
            raise ValueError(f"scale must be a number in (0, 1], got {scale!r}")
        if not (0 < float(scale) <= 1):
            raise ValueError(f"scale must be within (0, 1], got {scale}")
        resolved_scale = float(scale)

    return mime, resolved_quality, resolved_scale


def _validate_if_changed_from(if_changed_from: str) -> None:
    """The change-baseline is also frame-independent, so it fails fast too."""
    if if_changed_from and not re.fullmatch(r"[0-9a-f]{64}", if_changed_from):
        raise ValueError(
            "if_changed_from must be an empty string or a 64-char hex sha256"
        )


def _resolve_output_options(
    fmt: str,
    quality,
    scale,
    crop,
    frame_w: int,
    frame_h: int,
) -> tuple[str, int | None, float | None, tuple[int, int, int, int] | None]:
    """Validate and normalise the output options.

    Returns `(mime, quality, scale, crop_box)`. Raises `ValueError` — which
    `errors.classify` maps to `error_class: "invalid"` — for an unsupported
    format, a `quality` outside 1..100, a `scale` outside (0, 1], or a crop box
    that is empty or outside the frame. Nothing falls back silently: a rejected
    option never produces a differently-shaped image.

    `quality` is range-checked whatever the format — an out-of-range value is
    refused even for PNG — but it only has an effect on the lossy formats, so
    an in-range `quality` on a PNG frame is accepted and does nothing. The
    caller sees which options were applied because `_finish_screenshot` echoes
    each one that was supplied.

    The crop box is validated against the ACTUAL captured dimensions, because
    the fallback chain can hand back a size other than the one requested.
    """
    mime, resolved_quality, resolved_scale = _validate_output_options(
        fmt, quality, scale
    )

    if crop is None:
        resolved_crop: tuple[int, int, int, int] | None = None
    else:
        try:
            box = tuple(crop)  # type: ignore[arg-type]
        except TypeError:
            raise ValueError(
                f"crop must be a 4-element [left, top, right, bottom] box, got {crop!r}"
            ) from None
        if len(box) != 4 or any(
            isinstance(v, bool) or not isinstance(v, int) for v in box
        ):
            raise ValueError(
                f"crop must be four integers [left, top, right, bottom], got {crop!r}"
            )
        left, top, right, bottom = (int(v) for v in box)
        if not (0 <= left < right <= frame_w and 0 <= top < bottom <= frame_h):
            raise ValueError(
                f"crop box [{left}, {top}, {right}, {bottom}] is empty or outside "
                f"the {frame_w}x{frame_h} frame"
            )
        resolved_crop = (left, top, right, bottom)

    return mime, resolved_quality, resolved_scale, resolved_crop


def _shape_frame(
    img: PILImage.Image, scale, crop
) -> PILImage.Image:
    """Crop then scale a decoded image. Crop is in captured-frame pixels, so it
    runs first and `scale` then applies to the cropped result. `scale` of
    exactly 1.0 is a no-op, and the scaled dimension is never below one pixel."""
    if crop is not None:
        img = img.crop(crop)
    if scale is not None and scale != 1.0:
        w, h = img.size
        img = img.resize(
            (max(1, round(w * scale)), max(1, round(h * scale))),
            PILImage.Resampling.BOX,
        )
    return img


def _finish_screenshot(
    cfg: Config,
    raw: bytes,
    actual_w: int,
    actual_h: int,
    save_path: str,
    fmt: str,
    quality,
    scale,
    crop,
    if_changed_from: str,
    common: dict,
) -> tuple[Frame | None, dict]:
    """Hash, optionally short-circuit, then decode/crop/scale/encode once.

    Shared by both transports so the PowerShell and WMI legs cannot drift on
    the metadata contract. `frame_hash` is computed from the RAW capture — before
    crop, scale or format — so `if_changed_from` and `wait_frame_change` compare
    like with like whatever output options the caller picked.

    Returns `(None, meta)` with `unchanged: true` when `if_changed_from` matches;
    in that case no decode, no encode and no file write happen, and the metadata
    still carries the captured `width`/`height` — labelled as the captured size,
    since no output image exists to measure.

    Every option-echo key (`format`, `quality`, `scale`, `crop`) is emitted
    BEFORE the short-circuit and is gated on the caller having supplied that
    option, so an `unchanged: true` result is exactly as informative about the
    request as a changed one, and a request with no options produces the same
    key set on both paths (issue #19's "no option means identical metadata
    keys" constraint).
    """
    mime, resolved_quality, resolved_scale, crop_box = _resolve_output_options(
        fmt, quality, scale, crop, actual_w, actual_h
    )
    # `scale=1.0` is a no-op, so it is not a shaping request: a frame the
    # caller asked to leave alone must come back byte-identical to the base.
    shaped = crop_box is not None or (
        resolved_scale is not None and resolved_scale != 1.0
    )
    frame_hash = _frame_hash(raw)
    meta = dict(common)
    meta["frame_hash"] = frame_hash
    meta["prefix_hex"] = raw[:_PREFIX_LEN].hex()
    # `width`/`height` are the CAPTURED size here; the decode path below
    # overwrites them with the output size. On the unchanged path they stay
    # captured, because no output image exists.
    meta["width"] = actual_w
    meta["height"] = actual_h
    if fmt:
        meta["format"] = mime
    if resolved_quality is not None:
        meta["quality"] = resolved_quality
    if resolved_scale is not None:
        meta["scale"] = resolved_scale
    if crop_box is not None:
        meta["crop"] = list(crop_box)

    if if_changed_from:
        _validate_if_changed_from(if_changed_from)
        if if_changed_from == frame_hash:
            # The policy verdict must not depend on whether the frame
            # changed: check_host_write is a pure allow/deny, so running it
            # here costs nothing and keeps an out-of-roots save_path denied
            # on BOTH paths instead of silently allowed on a match.
            if save_path:
                policy.check_host_write(cfg, save_path)
                meta["save_path_skipped"] = (
                    "unchanged: no image was encoded, so no file was written"
                )
            return None, {**meta, "unchanged": True}

    # Decode to a bare image, shape it, then encode exactly once: routing the
    # shaped path through _decode_frame would encode a PNG that is immediately
    # discarded, which is the second encode issue #17 removed.
    img = _decode_rgb565_image(raw, actual_w, actual_h)
    if shaped:
        img = _shape_frame(img, resolved_scale, crop_box)
    frame = Frame.from_image(img, mime, resolved_quality)

    width, height = frame.size
    meta["width"] = width
    meta["height"] = height
    if shaped:
        # Compose onto the transport's head-resolution hint instead of
        # replacing it — the caller still needs to know how to reach head
        # space, and this is what tells them they can no longer do so
        # directly. `scale=1.0` is a no-op, so a frame byte-identical to the
        # base must not gain the warning at all.
        hint = meta.get("scale_note") or ""
        if crop_box is not None:
            # A crop offset has no head-space equivalent: _scale_to_head has
            # no crop term and mouse_move/click take no offset parameter, so
            # telling the caller to pass frame_width/frame_height here would
            # send them to a wrong head coordinate with an ok:true result.
            shaped_to = (
                f" and then scaled to {width}x{height}"
                if resolved_scale is not None and resolved_scale != 1.0
                else ""
            )
            meta["scale_note"] = (
                f"{hint} — this frame is CROPPED to "
                f"[{crop_box[0]}, {crop_box[1]}, {crop_box[2]}, {crop_box[3]}] of the "
                f"{actual_w}x{actual_h} capture{shaped_to}. "
                f"Its pixel coordinates have NO head-space equivalent (there is no "
                f"crop-offset parameter on the mouse tools), so do not pass them to "
                f"mouse_move/click — take an uncropped frame for pointer work."
            )
        else:
            meta["scale_note"] = (
                f"{hint} — this frame is SCALED to {width}x{height}, so its pixel "
                f"coordinates are NOT head-space coordinates. Pass "
                f"frame_width/frame_height matching the returned dimensions to the "
                f"mouse tools to scale them, or omit them to use head coordinates "
                f"directly."
            )
    if save_path:
        # check_host_write returns the CANONICAL path it just validated — the
        # realpath-resolved form, so every junction and symlink on the way has
        # already been followed once. Writing to THAT instead of re-traversing
        # the caller's string is what closes the check-then-use half of the
        # TOCTOU: the bytes land on the path the policy actually judged, not on
        # whatever the untrusted pathname resolves to a second time.
        canonical = policy.check_host_write(cfg, save_path)
        target = canonical.exists_prefix_resolved or save_path
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Write to a UNIQUE sibling temp file and replace, so a mid-write
        # failure cannot leave a truncated artifact where a complete one used
        # to be. The name carries the pid and a per-process counter because
        # two concurrent saves to the same path would otherwise open the same
        # ".mcp-partial" file and interleave their bytes; os.replace is atomic
        # on Windows, so the last writer wins with a complete image either way.
        tmp_path = f"{target}.{os.getpid()}-{next(_save_counter)}.mcp-partial"
        try:
            with open(tmp_path, "wb") as fh:
                fh.write(frame.encoded)
            os.replace(tmp_path, target)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        meta["saved_path"] = save_path
        # Only report a format the caller asked for: a default save writes a
        # PNG and must not add a key the base never emitted.
        if fmt:
            meta["saved_format"] = mime
    return frame, meta


def _capture_raw_with_meta(
    cfg: Config, prelude: str, width: int, height: int,
    timing: _PsTiming | None = None, ctx: str = "console screenshot",
) -> tuple[bytes, dict[str, str]]:
    """One self-contained capture plus its tagged metadata lines: the prelude
    binds $vmTarget (the PR #4 resolver by name or the GUID preamble by id),
    so a by-name frame resolves inside its own process and no separate GUID
    spawn is needed. The folded capture script reports the GUID it resolved
    (VMID=, issue #82) so the caller can pin a sequence's identity."""
    script = _folded_capture_script(prelude, width, height)
    result = _run(cfg, script, timeout_s=90, timing=timing)
    _check_rc(result, ctx)
    meta, payload_line = _meta_lines(result)
    try:
        data = json.loads(payload_line)
        payload = base64.b64decode(data["imageDataB64"], validate=True)
    except (json.JSONDecodeError, KeyError, binascii.Error, ValueError) as exc:
        raise ConsoleError(f"{ctx} result parse failed: {exc}") from None
    expected = width * height * 2 + _PREFIX_LEN
    if len(payload) != expected:
        raise ConsoleError(
            f"{ctx} thumbnail payload length mismatch: "
            f"got {len(payload)}, expected {expected}"
        )
    return payload, meta


def _capture_raw(
    cfg: Config, prelude: str, width: int, height: int, timing: _PsTiming | None = None
) -> bytes:
    """One self-contained capture: the prelude binds $vmTarget (the PR #4
    resolver by name or the GUID preamble by id), so a by-name frame resolves
    inside its own process and no separate GUID spawn is needed."""
    payload, _ = _capture_raw_with_meta(cfg, prelude, width, height, timing)
    return payload


def _scale_to_head(
    x: int, y: int, frame_w: int, frame_h: int, head: tuple[int, int] | None
) -> tuple[int, int]:
    """Scale frame-space coordinates to head space. Errors loudly rather than
    clicking at an unverified position. When frame dims are omitted (0), the
    coordinates are taken as head-space directly — and the head must then be
    available to bound them."""
    if frame_w or frame_h:
        if frame_w <= 0 or frame_h <= 0:
            raise ValueError("frame_width/frame_height must be positive when given")
        if head is None:
            raise ConsoleError(
                "display head resolution unavailable: pass frame_width/frame_height "
                "equal to the display resolution to skip scaling"
            )
        hx = round(x * head[0] / frame_w)
        hy = round(y * head[1] / frame_h)
        return max(0, min(hx, head[0] - 1)), max(0, min(hy, head[1] - 1))
    if head is None:
        raise ConsoleError(
            "display head resolution unavailable: pass frame_width/frame_height "
            "equal to the display resolution to skip scaling"
        )
    return max(0, min(x, head[0] - 1)), max(0, min(y, head[1] - 1))


def _scancodes_for_key(key: str) -> list[int]:
    """Named key -> scancode sequence (make+break; 0xE0 prefix for extended)."""
    name = key.strip().lower()
    entry = _KEY_SCANCODES.get(name)
    if entry is None:
        # Recovery surface: every supported name except the punctuation
        # aliases, comma-separated and sorted, then the aliases as a
        # space-separated trailing clause — a ", "-separated "," alias was
        # unreadable inside the comma list.
        names = sorted(set(_KEY_SCANCODES) - _PUNCT_ALIASES)
        raise ValueError(
            f"unknown key {key!r}; supported keys: {', '.join(names)}; "
            f"single-char aliases: {' '.join(sorted(_PUNCT_ALIASES))}"
        )
    make, brk = entry
    if name in _EXTENDED_KEYS:
        return [0xE0, make, 0xE0, brk]
    return [make, brk]


# Names the combo builder holds as modifiers (everything else in a combo
# is tapped in order).
_COMBO_MODIFIERS = frozenset((
    "ctrl", "alt", "shift", "leftctrl", "rightctrl", "leftalt", "rightalt",
    "leftshift", "rightshift", "win", "leftwin", "rightwin"))


def _scancodes_for_combo(keys: list[str]) -> list[int]:
    """Combo: modifier makes first, then each key in order, modifier breaks last.
    Modifiers go through the same extended-prefix rule as _scancodes_for_key
    (rightctrl/rightalt carry 0xE0 even as combo modifiers)."""
    mods = [k for k in keys if k.strip().lower() in _COMBO_MODIFIERS]
    rest = [k for k in keys if k not in mods]
    return _combo_codes(mods, rest)


def _combo_codes(mods: list[str], rest: list[str]) -> list[int]:
    """Encode an explicit modifier/rest split (press_key uses this so a
    modifier-named KEY is tapped, not silently reclassified as held)."""
    if not rest:
        raise ValueError("combo needs at least one non-modifier key")
    codes: list[int] = []

    def _mod_code(name: str, which: int) -> list[int]:
        n = name.strip().lower()
        codes_one = [_KEY_SCANCODES[n][which]]
        if n in _EXTENDED_KEYS:
            return [0xE0, codes_one[0]]
        return codes_one

    for m in mods:
        codes.extend(_mod_code(m, 0))
    for k in rest:
        codes.extend(_scancodes_for_key(k))
    for m in reversed(mods):
        codes.extend(_mod_code(m, 1))
    return codes


# ---------------------------------------------------------------------------
# public operations
# ---------------------------------------------------------------------------

def screenshot(
    cfg: Config,
    vm_name: str = "",
    width: int = 1024,
    height: int = 768,
    save_path: str = "",
    vm_id: str = "",
    fmt: str = "",
    quality=None,
    scale=None,
    crop=None,
    if_changed_from: str = "",
) -> tuple[Frame | None, dict]:
    """Capture the console; returns (frame, metadata). Caller wraps in
    MCP image content. Raises on failure (uniform list-form success shape).

    `fmt`, `quality`, `scale` and `crop` shape the returned image; `frame` is
    `None` with `unchanged: true` in the metadata when `if_changed_from` matches
    the current capture, in which case no image is decoded, encoded or written.
    """
    if not (160 <= width <= 4096 and 160 <= height <= 4096):
        raise ValueError("width/height must be within 160..4096")
    # Fail fast on everything that does not need the captured dimensions, so a
    # deterministic caller error is refused as `invalid` before a PowerShell
    # spawn takes a max_host_powershell slot (or the WMI chain runs).
    _validate_output_options(fmt, quality, scale)
    _validate_if_changed_from(if_changed_from)
    t0 = time.monotonic()
    be, connect_ms = _try_backend(cfg)
    ref: vmident.VMRef | None = None
    if be is not None:
        try:
            ref = _wmi_ref(be, cfg, vm_name, vm_id)
        except wmiconsole.BackendUnavailable:
            be = None
    if be is not None:
        assert ref is not None
        return _screenshot_wmi(
            cfg, be, connect_ms, ref, width, height, save_path, t0,
            fmt, quality, scale, crop, if_changed_from,
        )
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
    # One process for the whole capture: the chain (requested -> head native if
    # different -> 640x480 -> 320x240, duplicates removed) is built and looped
    # inside the script. The host timeout is the sum of the per-size budgets the
    # base allowed (four entries after de-duplication).
    script = _folded_screenshot_script(prelude, width, height)
    result = _run(cfg, script, timeout_s=90 * 4, timing=timing)
    _check_rc(result, "console screenshot")
    meta_lines, payload_line = _meta_lines(result)
    guid = _parse_guid(meta_lines, vm_name or ref.name)
    note_name_guid_hint(vm_name or ref.name, guid)
    head = _parse_head(meta_lines)
    used = _parse_size(meta_lines, "USED") or (width, height)
    try:
        data = json.loads(payload_line)
        raw = base64.b64decode(data["imageDataB64"], validate=True)
    except (json.JSONDecodeError, KeyError, binascii.Error, ValueError) as exc:
        raise ConsoleError(f"screenshot result parse failed: {exc}") from None
    actual_w, actual_h = used
    expected = actual_w * actual_h * 2 + _PREFIX_LEN
    if len(raw) != expected:
        raise ConsoleError(
            f"thumbnail payload length mismatch: got {len(raw)}, expected {expected} "
            f"for the {actual_w}x{actual_h} frame"
        )
    fallback_used = ""
    if used != (width, height):
        fallback_used = f"{width}x{height} failed; captured at {used[0]}x{used[1]}"
    common = {
        "vm_name": ref.name,
        "vm_id": guid,
        "fallback_used": fallback_used,
        "head_resolution": {"horizontal": head[0], "vertical": head[1]} if head else None,
        "scale_note": (
            "mouse tools accept frame_width/frame_height to scale image coords "
            f"to head space ({head[0]}x{head[1]})"
            if head else "head resolution unavailable: pass display resolution as frame dims"
        ),
        "capture_method": "GetVirtualSystemThumbnailImage (WMI root\\virtualization\\v2)",
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "timings": _ps_timings(timing),
        "timing": _meta_timing(t0, timing),
    }
    return _finish_screenshot(
        cfg, raw, actual_w, actual_h, save_path, fmt, quality, scale, crop,
        if_changed_from, common,
    )


def _screenshot_wmi(
    cfg: Config,
    be,
    connect_ms: float,
    ref: vmident.VMRef,
    width: int,
    height: int,
    save_path: str,
    t0: float = 0.0,
    fmt: str = "",
    quality=None,
    scale=None,
    crop=None,
    if_changed_from: str = "",
) -> tuple[Frame | None, dict]:
    """Screenshot over the in-process WMI backend: same metadata contract
    as the PowerShell path (the capture chain keeps its pre-existing
    per-size retry — same operation, next size)."""
    try:
        head, t_head = be.head_resolution(ref.id)
        chain: list[tuple[int, int]] = [(width, height)]
        if head and (width, height) != head:
            chain.append(head)
        chain.extend([(640, 480), (320, 240)])
        fallback_used = ""
        raw: bytes | None = None
        actual_w, actual_h = width, height
        phase_dicts = [t_head]
        for w, h in chain:
            try:
                raw, t = be.capture(ref.id, w, h)
                phase_dicts.append(t)
                actual_w, actual_h = w, h
                if (w, h) != chain[0]:
                    fallback_used = f"{chain[0][0]}x{chain[0][1]} failed; captured at {w}x{h}"
                break
            except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
                if (w, h) == chain[-1]:
                    raise ConsoleError(str(exc)) from None
                fallback_used = f"{chain[0][0]}x{chain[0][1]}: {exc}"
        assert raw is not None
        common = {
            "vm_name": ref.name,
            "vm_id": ref.id,
            "fallback_used": fallback_used,
            "head_resolution": {"horizontal": head[0], "vertical": head[1]} if head else None,
            "scale_note": (
                "mouse tools accept frame_width/frame_height to scale image coords "
                f"to head space ({head[0]}x{head[1]})"
                if head else "head resolution unavailable: pass display resolution as frame dims"
            ),
            "capture_method": "GetVirtualSystemThumbnailImage (in-process WMI, issue #45)",
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "timings": _wmi_timings(connect_ms, *phase_dicts),
            "timing": _meta_timing(t0, None, wmi=True),
        }
        return _finish_screenshot(
            cfg, raw, actual_w, actual_h, save_path, fmt, quality, scale, crop,
            if_changed_from, common,
        )
    except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
        raise ConsoleError(str(exc)) from None


def get_display_info(cfg: Config, vm_name: str = "", vm_id: str = "") -> dict:
    be, connect_ms = _try_backend(cfg)
    ref: vmident.VMRef | None = None
    if be is not None:
        try:
            ref = _wmi_ref(be, cfg, vm_name, vm_id)
        except wmiconsole.BackendUnavailable:
            be = None
    if be is not None:
        assert ref is not None
        try:
            info, t = be.display_info(ref.id)
        except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
            raise ConsoleError(str(exc)) from None
        return {
            "ok": True,
            **info,
            "vm_id": ref.id,
            "guest_channel": "ps_direct_unverified",
            "guest_channel_note": (
                "console input works from firmware/WinPE; PowerShell Direct requires a "
                "running supported guest OS with credentials — verify before switching"
            ),
            "vm_name": ref.name,
            "timings": _wmi_timings(connect_ms, t),
        }
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
    script = "\n".join([
        prelude,
        _VM_LOOKUP,
        _HEAD_LOOKUP,
        _KEYBOARD_LOOKUP_SOFT,
        _MOUSE_SYNTHETIC,
        "$mouse = $m | Select-Object -First 1\n",
        "$bootMs = $vm.OnTimeInMilliseconds\n",
        "$bootEpoch = [int]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - "
        "[int64]($bootMs / 1000))\n",
        "Write-Output ('EPOCH=' + $bootEpoch)\n",
        "Write-Output ('VMID=' + $vmTarget)\n",
        "[PSCustomObject]@{\n",
        "    enabled_state = $vm.EnabledState\n",
        "    head_horizontal = if ($vh) { $vh.CurrentHorizontalResolution } else { $null }\n",
        "    head_vertical = if ($vh) { $vh.CurrentVerticalResolution } else { $null }\n",
        "    keyboard_present = [bool]$kb\n",
        "    keyboard_enabled = if ($kb) { $kb.EnabledState } else { $null }\n",
        "    mouse_present = [bool]$mouse\n",
        "    mouse_enabled = if ($mouse) { $mouse.EnabledState } else { $null }\n",
        "} | ConvertTo-Json -Compress\n",
    ])
    result = _run(cfg, script, timeout_s=60, timing=timing)
    _check_rc(result, "console display info")
    meta_lines, payload_line = _meta_lines(result)
    guid = _parse_guid(meta_lines, vm_name or ref.name)
    note_name_guid_hint(vm_name or ref.name, guid)
    try:
        data = json.loads(payload_line)
    except json.JSONDecodeError as exc:
        raise ConsoleError(f"display info parse failed: {exc}") from None
    data["vm_id"] = guid
    # The host-side boot boundary (issue #28): optional in the parse — folded
    # responses without the EPOCH= line keep the legacy result shape.
    if meta_lines.get("EPOCH"):
        try:
            data["boot_epoch"] = int(meta_lines["EPOCH"])
        except ValueError:
            pass
    data["guest_channel"] = "ps_direct_unverified"
    data["guest_channel_note"] = (
        "console input works from firmware/WinPE; PowerShell Direct requires a "
        "running supported guest OS with credentials — verify before switching"
    )
    data["timings"] = _ps_timings(timing)
    return {"ok": True, **data, "vm_name": ref.name}


def type_text(cfg: Config, vm_name: str = "", text: str = "", vm_id: str = "") -> dict:
    policy.require_category(cfg, "console_input", f"type text into '{vm_name}' console")
    if not text:
        raise ValueError("text is required")
    if any(ord(c) > 127 for c in text):
        raise ValueError("text must be ASCII; use hyperv_console_type_scancodes for other input")
    be, connect_ms = _try_backend(cfg)
    ref: vmident.VMRef | None = None
    if be is not None:
        try:
            ref = _wmi_ref(be, cfg, vm_name, vm_id)
        except wmiconsole.BackendUnavailable:
            be = None
    if be is not None:
        assert ref is not None
        chunks = [text[i:i + 512] for i in range(0, len(text), 512)]
        calls = 0
        phase_dicts: list[dict] = []
        try:
            with _input_lock(ref):
                for i, chunk in enumerate(chunks):
                    _r, t = be.type_text(ref.id, chunk)
                    phase_dicts.append(t)
                    calls += 1
                    if i < len(chunks) - 1:
                        time.sleep(0.05)
        except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
            raise ConsoleError(str(exc)) from None
        return {
            "ok": True, "chunks": calls, "chars": len(text), "vm_name": ref.name,
            "timings": _wmi_timings(connect_ms, *phase_dicts),
        }
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    chunks = [text[i:i + 512] for i in range(0, len(text), 512)]
    # Text rides stdin as UTF-8 base64 — never in the script, argv, or error
    # records (CLIXML errors quote script lines). Every chunk is one stdin line
    # and the loop reads one line per iteration.
    # Remote mode: the composer's preamble read the lines and forwarded them as
    # scriptblock parameters ($__p0.., collected into $payloads) because a remote
    # block cannot read local stdin; local mode keeps the inline read.
    if pswindows.hyperv_host(cfg):
        read_expr = "$payloads[$i]"
        payload_init = (
            "$payloads = @("
            + ", ".join(f"$__p{i}" for i in range(len(chunks)))
            + ")\n"
        )
    else:
        read_expr = "[Console]::In.ReadLine()"
        payload_init = ""
    call = (
        "$text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
        + read_expr + "))\n"
        "    $r = Invoke-CimMethod -InputObject $kb -MethodName TypeText "
        "-ErrorAction Stop -Arguments @{ AsciiText = $text }\n"
        "    if ($r.ReturnValue -ne 0) { throw ('TypeText failed with ReturnValue=' "
        "+ $r.ReturnValue + ' at chunk ' + ($i+1) + '/' + $n) }\n"
        "    Write-Output ('RC=' + $r.ReturnValue + ' CHUNK=' + ($i+1) + '/' + $n)\n"
        "    if ($i -lt $n - 1) { Start-Sleep -Milliseconds 50 }\n"
    )
    script = "\n".join([
        prelude,
        _VM_LOOKUP,
        _KEYBOARD_LOOKUP,
        payload_init,
        "$n = " + str(len(chunks)),
        "for ($i = 0; $i -lt $n; $i++) {",
        call,
        "}",
    ])
    with _input_lock(ref):
        result = _run(
            cfg,
            script,
            timeout_s=90,
            stdin_b64="\n".join(pswindows.utf8_b64(chunk) for chunk in chunks),
            payload_lines=len(chunks),
            timing=timing,
        )
    _check_input_rc(result, "console type_text", vm_name)
    return {
        "ok": True, "chunks": len(chunks), "chars": len(text), "vm_name": ref.name,
        "timings": _ps_timings(timing),
    }


def _select_backend_and_ref(cfg: Config, vm_name: str, vm_id: str) -> tuple[Any | None, float, vmident.VMRef | None]:
    """Shared selection preamble for input ops: (backend, connect_ms, ref)
    with be=None when the PowerShell transport is selected. Policy checks
    stay in the callers (a denied name must reach neither transport)."""
    be, connect_ms = _try_backend(cfg)
    ref = None
    if be is not None:
        try:
            ref = _wmi_ref(be, cfg, vm_name, vm_id)
        except wmiconsole.BackendUnavailable:
            be = None
    return be, connect_ms, ref


def press_key(
    cfg: Config, vm_name: str = "", key: str = "", modifiers: list[str] | None = None, vm_id: str = "",
) -> dict:
    policy.require_category(cfg, "console_input", f"press {key} on '{vm_name}' console")
    # A bare key press has no modifiers to hold, so it encodes through the
    # plain key path — otherwise a modifier-named key (win, ctrl, ...) would
    # be rejected by the combo builder as modifier-only (issue #25: a bare
    # win press must reach the guest).
    if not modifiers:
        codes = _scancodes_for_key(key)
    else:
        # The key argument is ALWAYS the tapped key, even when it shares a
        # name with a modifier (win+ctrl holds ctrl and taps win) — the
        # modifiers list is what gets held (issue #25 review: role swap).
        held = [m for m in modifiers if m.strip().lower() in _COMBO_MODIFIERS]
        tapped = [key] + [m for m in modifiers if m not in held]
        codes = _combo_codes(held, tapped)
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        return _send_scancodes_locked(cfg, ref, codes, be=be, connect_ms=connect_ms)
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    return _send_scancodes_locked(cfg, ref, codes, timing=timing, prelude=prelude)


def key_combo(cfg: Config, vm_name: str = "", keys: list[str] | None = None, vm_id: str = "") -> dict:
    policy.require_category(cfg, "console_input", f"send combo {keys!r} on '{vm_name}' console")
    if not keys:
        raise ValueError("keys list is required")
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        codes = _scancodes_for_combo(keys)
        return _send_scancodes_locked(cfg, ref, codes, be=be, connect_ms=connect_ms)
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    codes = _scancodes_for_combo(keys)
    return _send_scancodes_locked(cfg, ref, codes, timing=timing, prelude=prelude)


def type_scancodes(cfg: Config, vm_name: str = "", scancodes: list[int] | None = None, vm_id: str = "") -> dict:
    policy.require_category(cfg, "console_input", f"send {len(scancodes or [])} scancodes to '{vm_name}' console")
    if not scancodes:
        raise ValueError("scancodes list is required")
    for code in scancodes:
        if type(code) is not int or not (0 <= code <= 255):
            raise ValueError(f"scancodes must be integers 0..255 (bools rejected); got {code!r}")
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        return _send_scancodes_locked(cfg, ref, list(scancodes), be=be, connect_ms=connect_ms)
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    return _send_scancodes_locked(cfg, ref, list(scancodes), timing=timing, prelude=prelude)


def _send_scancodes_locked(
    cfg: Config,
    ref: vmident.VMRef,
    codes: list[int],
    be=None,
    connect_ms: float = 0.0,
    timing: _PsTiming | None = None,
    prelude: str | None = None,
) -> dict:
    chunks = [codes[i:i + 64] for i in range(0, len(codes), 64)]
    if be is not None:
        sent = 0
        phase_dicts: list[dict] = []
        try:
            with _input_lock(ref):
                for i, chunk in enumerate(chunks):
                    _r, t = be.type_scancodes(ref.id, chunk)
                    phase_dicts.append(t)
                    sent += len(chunk)
                    if i < len(chunks) - 1:
                        time.sleep(0.02)  # pacing: let the Hyper-V input buffer drain
        except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
            raise ConsoleError(str(exc)) from None
        return {
            "ok": True, "scancodes_sent": sent, "chunks": len(chunks),
            "vm_name": ref.name, "timings": _wmi_timings(connect_ms, *phase_dicts),
        }
    assert prelude is not None, "the PowerShell path requires the $vmTarget prelude"
    # Scancodes ride IN the script as ONE flat code array and the loop slices
    # its 64-code window per chunk (a nested array-of-arrays is not safe here:
    # PS 5.1 flattens @(@(a,b)) for a single chunk, which would send one byte).
    # Unlike typed text they carry no stdin read, which keeps the pinned
    # ReadLine census at exactly one emission inside type_text.
    call = "\n".join([
        "$lo = $i * 64",
        "    $hi = [math]::Min($lo + 63, $chunks.Count - 1)",
        "    $r = Invoke-CimMethod -InputObject $kb -MethodName TypeScancodes "
        "-ErrorAction Stop -Arguments @{ ScanCodes = [byte[]]$chunks[$lo..$hi] }",
        "    if ($r.ReturnValue -ne 0) { throw ('TypeScancodes failed with ReturnValue=' "
        "+ $r.ReturnValue + ' at chunk ' + ($i+1) + '/' + $n) }",
        "    Write-Output ('RC=' + $r.ReturnValue + ' CHUNK=' + ($i+1) + '/' + $n)",
        "    if ($i -lt $n - 1) { Start-Sleep -Milliseconds 20 }",
    ]) + "\n"
    script = "\n".join([
        prelude,
        _VM_LOOKUP,
        _KEYBOARD_LOOKUP,
        "$chunks = @(" + ",".join(str(c) for c in codes) + ")",
        "$n = " + str(len(chunks)),
        "for ($i = 0; $i -lt $n; $i++) {",
        call,
        "}",
    ])
    with _input_lock(ref):
        result = _run(cfg, script, timeout_s=90, timing=timing)
    _check_input_rc(result, "console scancodes", ref.name)
    sent = sum(len(chunk) for chunk in chunks)
    out = {"ok": True, "scancodes_sent": sent, "chunks": len(chunks), "vm_name": ref.name}
    if timing is not None:
        out["timings"] = _ps_timings(timing)
    return out


def mouse_move(
    cfg: Config, vm_name: str = "", x: int | None = None, y: int | None = None,
    frame_width: int = 0, frame_height: int = 0, vm_id: str = "",
) -> dict:
    # x/y are semantically REQUIRED (PRR-014): omission must not silently
    # mean (0,0) — a real SetAbsolutePosition(0,0). Checked before any
    # policy/spawn so the invalid call costs nothing.
    if x is None or y is None:
        raise ValueError("x and y are required")
    if (frame_width or frame_height) and (frame_width <= 0 or frame_height <= 0):
        raise ValueError("frame_width/frame_height must be positive when given")
    policy.require_category(cfg, "console_input", f"move mouse on '{vm_name}' console")
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        try:
            with _input_lock(ref):
                head, t_head = be.head_resolution(ref.id)
                hx, hy = _scale_to_head(x, y, frame_width, frame_height, head)
                _r, t = be.mouse_move(ref.id, hx, hy)
        except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
            raise ConsoleError(str(exc)) from None
        return {
            "ok": True, "operation": f"move to ({hx},{hy})", "vm_name": ref.name,
            "head_x": hx, "head_y": hy,
            "timings": _wmi_timings(connect_ms, t_head, t),
        }
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    script = _folded_mouse_positional_script(
        prelude, x, y, frame_width, frame_height, click=False, button=1
    )
    with _input_lock(ref):
        result = _run(cfg, script, timeout_s=90, timing=timing)
    _check_input_rc(result, "console mouse move", vm_name)
    meta_lines, _payload = _meta_lines(result)
    hx = _require_int(meta_lines, "HEADX", "mouse move")
    hy = _require_int(meta_lines, "HEADY", "mouse move")
    return {
        "ok": True, "operation": f"move to ({hx},{hy})", "vm_name": ref.name,
        "head_x": hx, "head_y": hy,
        "timings": _ps_timings(timing),
    }


def click(
    cfg: Config, vm_name: str = "", x: int | None = None, y: int | None = None,
    frame_width: int = 0, frame_height: int = 0, button: int = 1, vm_id: str = "",
) -> dict:
    policy.require_category(cfg, "console_input", f"click on '{vm_name}' console")
    if button not in (1, 2):
        raise ValueError("button must be 1 (left) or 2 (right)")
    if (x is None) != (y is None):
        raise ValueError("x and y must be given together")
    if (frame_width or frame_height) and (frame_width <= 0 or frame_height <= 0):
        raise ValueError("frame_width/frame_height must be positive when given")
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        try:
            with _input_lock(ref):
                extra: dict = {}
                if x is not None and y is not None:
                    head, t_head = be.head_resolution(ref.id)
                    hx, hy = _scale_to_head(x, y, frame_width, frame_height, head)
                    _r, t = be.mouse_click(ref.id, button, hx, hy)
                    extra = {"head_x": hx, "head_y": hy}
                else:
                    t_head = {}
                    _r, t = be.mouse_click(ref.id, button)
        except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
            raise ConsoleError(str(exc)) from None
        return {
            "ok": True, "operation": f"click button {button}", "vm_name": ref.name,
            "timings": _wmi_timings(connect_ms, t_head, t), **extra,
        }
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    if x is not None and y is not None:
        script = _folded_mouse_positional_script(
            prelude, x, y, frame_width, frame_height, click=True, button=button
        )
        with _input_lock(ref):
            result = _run(cfg, script, timeout_s=90, timing=timing)
        _check_input_rc(result, "console mouse click", vm_name)
        meta_lines, _payload = _meta_lines(result)
        hx = _require_int(meta_lines, "HEADX", "click")
        hy = _require_int(meta_lines, "HEADY", "click")
        return {
            "ok": True, "operation": f"click button {button}", "vm_name": ref.name,
            "head_x": hx, "head_y": hy,
            "timings": _ps_timings(timing),
        }
    # No coordinates means 'click at current position' — no positioning leg
    # at all; (0,0) is a real coordinate and takes the positional leg.
    call = (
        "$r = Invoke-CimMethod -InputObject $m -MethodName ClickButton "
        + "-ErrorAction Stop -Arguments @{ ButtonIndex = " + str(button) + " }\n"
        + "if ($r.ReturnValue -ne 0) { throw ('ClickButton failed with ReturnValue=' + $r.ReturnValue) }\n"
        + "Write-Output ('RC=' + $r.ReturnValue)\n"
    )
    return _mouse_op(cfg, ref, f"click button {button}", prelude, call=call, timing=timing)


def mouse_button(
    cfg: Config, vm_name: str = "", button: int = 1, is_down: bool = False, vm_id: str = "",
) -> dict:
    policy.require_category(cfg, "console_input", f"button {'down' if is_down else 'up'} on '{vm_name}' console")
    if button not in (1, 2):
        raise ValueError("button must be 1 (left) or 2 (right)")
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        try:
            with _input_lock(ref):
                _r, t = be.mouse_button(ref.id, button, is_down)
        except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
            raise ConsoleError(str(exc)) from None
        return {
            "ok": True, "operation": f"button {button} {'down' if is_down else 'up'}",
            "vm_name": ref.name, "timings": _wmi_timings(connect_ms, t),
        }
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    return _mouse_op(
        cfg, ref, f"button {button} {'down' if is_down else 'up'}",
        prelude,
        "SetButtonState",
        f"@{{ ButtonIndex = {button}; IsDown = ${'true' if is_down else 'false'} }}",
        timing=timing,
    )


def scroll(cfg: Config, vm_name: str = "", delta: int = 0, vm_id: str = "") -> dict:
    policy.require_category(cfg, "console_input", f"scroll on '{vm_name}' console")
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        try:
            with _input_lock(ref):
                _r, t = be.mouse_scroll(ref.id, delta)
        except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
            raise ConsoleError(str(exc)) from None
        return {
            "ok": True, "operation": f"scroll {delta}", "vm_name": ref.name,
            "timings": _wmi_timings(connect_ms, t),
        }
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    return _mouse_op(cfg, ref, f"scroll {delta}", prelude,
                     "SetScrollPosition", f"@{{ ScrollPositionDelta = {int(delta)} }}",
                     timing=timing)


def _mouse_op(
    cfg: Config,
    ref: vmident.VMRef,
    detail: str,
    prelude: str,
    method: str | None = None,
    args_literal: str = "",
    call: str | None = None,
    extra: dict | None = None,
    timing: _PsTiming | None = None,
) -> dict:
    """One non-positional mouse op in one process: the synthetic mouse, or
    the PS/2 fallback under the same SystemName filter (AC14)."""
    if call is None:
        assert method is not None
        call = (
            "$r = Invoke-CimMethod -InputObject $m -MethodName " + method + " "
            "-ErrorAction Stop -Arguments " + args_literal + "\n"
            "if ($r.ReturnValue -ne 0) { throw ('" + method + " failed with ReturnValue=' + $r.ReturnValue) }\n"
            "Write-Output ('RC=' + $r.ReturnValue)\n"
        )
    script = "\n".join([
        prelude,
        _VM_LOOKUP,
        _MOUSE_SYNTHETIC,
        "if (-not $m) {\n",
        _MOUSE_PS2,
        "    if (-not $m) { throw 'no mouse device associated with the VM' }\n",
        "}\n",
        call,
    ])
    with _input_lock(ref):
        result = _run(cfg, script, timeout_s=90, timing=timing)
    _check_input_rc(result, f"console mouse {detail}", ref.name)
    out = {"ok": True, "operation": detail, "vm_name": ref.name}
    if extra:
        out.update(extra)
    if timing is not None:
        out["timings"] = _ps_timings(timing)
    return out


def wait_frame_change(
    cfg: Config,
    vm_name: str = "",
    baseline_hash: str = "",
    width: int = 640,
    height: int = 480,
    timeout_s: int = 60,
    interval_s: int = 2,
    vm_id: str = "",
) -> dict:
    if interval_s < 1:
        raise ValueError("interval_s must be >= 1")
    if timeout_s < 1:
        raise ValueError("timeout_s must be >= 1")
    if not (160 <= width <= 4096 and 160 <= height <= 4096):
        raise ValueError("width/height must be within 160..4096")
    if baseline_hash and not re.fullmatch(r"[0-9a-f]{64}", baseline_hash):
        raise ValueError("baseline_hash must be an empty string or a 64-char hex sha256")
    be, connect_ms, ref_wmi = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref_wmi is not None:
        return _wait_frame_change_wmi(
            be, connect_ms, ref_wmi, baseline_hash, width, height, timeout_s, interval_s
        )
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
    # On the WMI transport the deadline is enforced BETWEEN polls (a single
    # in-flight COM capture is not interruptible; the PowerShell transport's
    # child process is killed at timeout_s + 15). See README console-transport.
    script = _folded_wait_frame_script(
        prelude, baseline_hash, width, height, timeout_s, interval_s
    )
    started = time.monotonic()
    result = _run(cfg, script, timeout_s=int(timeout_s) + 15, timing=timing)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    _check_rc(result, "console wait_frame_change")

    stop_reason, polls, last_hash, frame_b64 = "deadline", 0, "", ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("STOP="):
            parts = dict(
                kv.split("=", 1) for kv in line.split(" ") if "=" in kv
            )
            stop_reason = parts.get("STOP", "deadline")
            polls = int(parts.get("POLLS", "0") or 0)
            last_hash = parts.get("HASH", "")
        elif line.startswith("FRAME="):
            frame_b64 = line[len("FRAME="):]

    out: dict = {
        "ok": True,
        "vm_name": ref.name,
        "stop_reason": stop_reason,
        "changed": stop_reason == "changed",
        "polls": polls,
        "elapsed_ms": elapsed_ms,
        "width": width,
        "height": height,
        "hash_domain": HASH_DOMAIN,
        "timings": _ps_timings(timing),
    }
    if last_hash:
        out["frame_hash"] = last_hash
    if frame_b64:
        raw = base64.b64decode(frame_b64)
        out["image"] = _decode_frame(raw, width, height)
        out["frame_hash"] = _frame_hash(raw)
    return out


def _wait_frame_change_wmi(
    be, connect_ms: float, ref: vmident.VMRef, baseline_hash: str,
    width: int, height: int, timeout_s: int, interval_s: int,
) -> dict:
    """wait_frame_change over the in-process WMI backend: the poll loop runs
    in Python, preserving the PowerShell contract (first-poll-baseline,
    supplied-baseline discrimination, deadline stop, hash round-tripping,
    polls bounded by the derived max_polls, deadline keeps the last hash)."""
    max_polls = math.ceil(timeout_s / interval_s)
    phase_dicts: list[dict] = []
    stop_reason, polls, last_hash = "deadline", 0, ""
    raw: bytes | None = None
    started = time.monotonic()
    deadline_t = started + timeout_s
    try:
        baseline = baseline_hash
        while polls < max_polls:
            if time.monotonic() >= deadline_t:
                stop_reason = "deadline"
                break
            raw, t = be.capture(ref.id, width, height)
            phase_dicts.append(t)
            polls += 1
            h = _frame_hash(raw)
            last_hash = h
            if not baseline:
                baseline = h
            if h != baseline:
                stop_reason = "changed"
                break
            if polls >= max_polls or time.monotonic() >= deadline_t:
                stop_reason = "deadline"
                break
            time.sleep(interval_s)
    except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
        raise ConsoleError(str(exc)) from None
    elapsed_ms = int((time.monotonic() - started) * 1000)
    out: dict = {
        "ok": True,
        "vm_name": ref.name,
        "stop_reason": stop_reason,
        "changed": stop_reason == "changed",
        "polls": polls,
        "elapsed_ms": elapsed_ms,
        "width": width,
        "height": height,
        "hash_domain": HASH_DOMAIN,
        "timings": _wmi_timings(connect_ms, *phase_dicts),
    }
    if last_hash:
        out["frame_hash"] = last_hash
    if stop_reason == "changed" and raw is not None:
        out["image"] = _decode_frame(raw, width, height)
        out["frame_hash"] = _frame_hash(raw)
    return out


def wait_frame_stable(
    cfg: Config,
    vm_name: str = "",
    stable_ms: int = 1500,
    timeout_s: int = 30,
    interval_ms: int = 250,
    width: int = 640,
    height: int = 480,
    baseline_hash: str = "",
    vm_id: str = "",
) -> dict:
    """Poll the console until the frame has been UNCHANGED for stable_ms (the
    settle wait, issue #27). One PowerShell process for the whole poll loop on
    the PS transport; the in-process WMI backend mirrors the same state
    machine. With baseline_hash, the quiet window starts only at the first
    frame that differs from it, so an input that did nothing reports
    stop_reason="unchanged" instead of "stable"."""
    if stable_ms < 1:
        raise ValueError("stable_ms must be >= 1")
    if interval_ms < 100:
        raise ValueError("interval_ms must be >= 100")
    if timeout_s < 1:
        raise ValueError("timeout_s must be >= 1")
    if stable_ms >= timeout_s * 1000:
        raise ValueError(
            "stable_ms must be less than timeout_s*1000 or the quiet window "
            "can never be observed within the deadline"
        )
    if not (160 <= width <= 4096 and 160 <= height <= 4096):
        raise ValueError("width/height must be within 160..4096")
    if baseline_hash and not re.fullmatch(r"[0-9a-f]{64}", baseline_hash):
        raise ValueError("baseline_hash must be an empty string or a 64-char hex sha256")
    be, connect_ms, ref_wmi = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref_wmi is not None:
        return _wait_frame_stable_wmi(
            be, connect_ms, ref_wmi, baseline_hash, stable_ms,
            width, height, timeout_s, interval_ms,
        )
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
    # The host-side deadline mirrors wait_frame_change: the child is killed at
    # timeout_s + 15 (a stuck WMI call cannot hold the call open indefinitely).
    script = _folded_wait_stable_script(
        prelude, baseline_hash, stable_ms, width, height, timeout_s, interval_ms
    )
    started = time.monotonic()
    result = _run(cfg, script, timeout_s=int(timeout_s) + 15, timing=timing)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    _check_rc(result, "console wait_frame_stable")

    stop_reason, polls, last_hash, stable_ms_reported, frame_b64 = "deadline", 0, "", None, ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("STOP="):
            parts = dict(
                kv.split("=", 1) for kv in line.split(" ") if "=" in kv
            )
            stop_reason = parts.get("STOP", "deadline")
            polls = int(parts.get("POLLS", "0") or 0)
            last_hash = parts.get("HASH", "")
            stable_ms_reported = parts.get("STABLE_MS")
        elif line.startswith("FRAME="):
            frame_b64 = line[len("FRAME="):]

    out: dict = {
        "ok": True,
        "vm_name": ref.name,
        "stop_reason": stop_reason,
        "stable": stop_reason == "stable",
        "polls": polls,
        "elapsed_ms": elapsed_ms,
        "width": width,
        "height": height,
        "hash_domain": HASH_DOMAIN,
        "timings": _ps_timings(timing),
    }
    if stable_ms_reported is not None:
        out["stable_ms_measured"] = int(stable_ms_reported)
    if last_hash:
        out["frame_hash"] = last_hash
    if frame_b64:
        raw = base64.b64decode(frame_b64)
        out["image"] = _decode_frame(raw, width, height)
        out["frame_hash"] = _frame_hash(raw)
    return out


def _wait_frame_stable_wmi(
    be, connect_ms: float, ref: vmident.VMRef, baseline_hash: str,
    stable_ms: int, width: int, height: int, timeout_s: int, interval_ms: int,
) -> dict:
    """wait_frame_stable over the in-process WMI backend: the same transition
    table as the PowerShell transport (first-poll window start, supplied
    baseline moves the window start to the first differing frame, quiet window
    >= stable_ms -> stable, unchanged only with a never-differed baseline)."""
    max_polls = math.ceil(timeout_s * 1000 / interval_ms)
    phase_dicts: list[dict] = []
    stop_reason, polls = "deadline", 0
    last_hash: str | None = None
    # With a supplied baseline the reference STARTS there (the quiet window
    # may not begin while frames still match it); without one, the first
    # frame seeds it (first-poll-is-baseline) — the same init the PS template
    # performs through $refHash = '<baseline>'.
    ref_hash: str | None = baseline_hash or None
    last_change: float | None = None
    move_seen = False
    raw: bytes | None = None
    started = time.monotonic()
    deadline_t = started + timeout_s
    # "unchanged" means "frames were observed and none moved away from the
    # baseline": a zero-poll deadline is a deadline, never unchanged.
    def _terminal() -> str:
        if baseline_hash and polls > 0 and not move_seen:
            return "unchanged"
        return "deadline"

    try:
        while polls < max_polls:
            if time.monotonic() >= deadline_t:
                stop_reason = _terminal()
                break
            raw, t = be.capture(ref.id, width, height)
            phase_dicts.append(t)
            polls += 1
            now = time.monotonic()
            h = _frame_hash(raw)
            last_hash = h
            if h != ref_hash:
                ref_hash = h
                last_change = now
                move_seen = True
            if last_change is not None and (now - last_change) * 1000 >= stable_ms:
                stop_reason = "stable"
                break
            if polls >= max_polls or time.monotonic() >= deadline_t:
                stop_reason = _terminal()
                break
            time.sleep(interval_ms / 1000)
    except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
        raise ConsoleError(str(exc)) from None
    elapsed_ms = int((time.monotonic() - started) * 1000)
    out: dict = {
        "ok": True,
        "vm_name": ref.name,
        "stop_reason": stop_reason,
        "stable": stop_reason == "stable",
        "polls": polls,
        "elapsed_ms": elapsed_ms,
        "width": width,
        "height": height,
        "hash_domain": HASH_DOMAIN,
        "timings": _wmi_timings(connect_ms, *phase_dicts),
    }
    if last_hash:
        out["frame_hash"] = last_hash
    if stop_reason == "stable" and last_change is not None:
        out["stable_ms_measured"] = int((time.monotonic() - last_change) * 1000)
        if raw is not None:
            out["image"] = _decode_frame(raw, width, height)
            out["frame_hash"] = _frame_hash(raw)
    return out


def capture_sequence(
    cfg: Config, vm_name: str = "", count: int = 3, interval_s: int = 2,
    width: int = 640, height: int = 480, vm_id: str = "",
) -> dict:
    if not (1 <= count <= 10):
        raise ValueError("count must be 1..10")
    if interval_s < 1:
        raise ValueError("interval_s must be >= 1")
    if not (160 <= width <= 4096 and 160 <= height <= 4096):
        raise ValueError("width/height must be within 160..4096")
    be, connect_ms, ref_wmi = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref_wmi is not None:
        return _capture_sequence_wmi(be, connect_ms, ref_wmi, count, interval_s, width, height)
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
    frames: list[dict] = []
    images: list = []
    prev_raw: bytes | None = None
    seq_guid: str | None = None
    seq_pin_frame = 0
    started = time.monotonic()
    for i in range(count):
        # Each frame is its own self-contained process (the prelude resolves the
        # VM), so there is no separate GUID process — at most one per frame.
        raw, meta = _capture_raw_with_meta(
            cfg, prelude, width, height, timing, ctx="console capture_sequence")
        # Identity pin (issue #82): a frame that reports a GUID joins the
        # sequence only under the first attributed frame's identity. A frame
        # with no VMID= line stays unattributed and never clears the pin.
        guid: str | None = None
        if "VMID" in meta:
            guid = _parse_guid(meta, ref.name)
            note_name_guid_hint(ref.name, guid)
            if seq_guid is None:
                seq_guid = guid
                seq_pin_frame = i
            elif guid != seq_guid:
                raise ConsoleError(
                    f"capture_sequence spanned two VM identities: frame "
                    f"{seq_pin_frame} resolved {seq_guid} but frame {i} "
                    f"resolved {guid}"
                )
        h = _frame_hash(raw)
        changed_bytes = _changed_pixel_bytes(prev_raw, raw)
        frames.append({
            "index": i,
            "vm_id": guid,
            "frame_hash": h,
            "changed_bytes_vs_previous": changed_bytes,
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        })
        if i == 0 or i == count - 1:
            images.append(_decode_frame(raw, width, height))
        prev_raw = raw
        if i < count - 1:
            time.sleep(interval_s)
    return {
        "ok": True,
        "vm_name": ref.name,
        "frames": frames,
        "images": images,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "width": width,
        "height": height,
        "timings": _ps_timings(timing),
    }


def _capture_sequence_wmi(
    be, connect_ms: float, ref: vmident.VMRef, count: int, interval_s: int,
    width: int, height: int,
) -> dict:
    """capture_sequence over the in-process WMI backend, preserving the
    per-frame bookkeeping contract (exact changed-byte counts over
    equal-length pixel slices, first-and-last-only images)."""
    frames: list[dict] = []
    images: list = []
    prev_raw: bytes | None = None
    phase_dicts: list[dict] = []
    started = time.monotonic()
    try:
        for i in range(count):
            raw, t = be.capture(ref.id, width, height)
            phase_dicts.append(t)
            h = _frame_hash(raw)
            changed_bytes = _changed_pixel_bytes(prev_raw, raw)
            frames.append({
                "index": i,
                "vm_id": ref.id,
                "frame_hash": h,
                "changed_bytes_vs_previous": changed_bytes,
                "captured_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            })
            if i == 0 or i == count - 1:
                images.append(_decode_frame(raw, width, height))
            prev_raw = raw
            if i < count - 1:
                time.sleep(interval_s)
    except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
        raise ConsoleError(str(exc)) from None
    return {
        "ok": True,
        "vm_name": ref.name,
        "frames": frames,
        "images": images,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "width": width,
        "height": height,
        "timings": _wmi_timings(connect_ms, *phase_dicts),
    }


# ---------------------------------------------------------------------------
# batched console action sequences (issue #28)
#
# One call = one validated plan = one lock acquisition = one PowerShell
# process (after GUID resolution). Steps validate host-side BEFORE anything
# spawns; preconditions (frame hash / boot epoch) evaluate INSIDE the locked
# region and exit the script before the first input on a mismatch; text rides
# stdin base64 exactly like type_text; the per-VM console WRITE key is held
# for the whole plan, so raw input from any agent cannot interleave (the
# actor is the lock itself — internal step execution never re-acquires).
# ---------------------------------------------------------------------------

_MAX_SEQUENCE_STEPS = 50

# Uncertain-dispatch records (issue #28 AC-28.15): a timed-out leg leaves
# "did the guest get the input?" unknowable, so the outcome is recorded once
# under the caller's request correlation key and a retry with the same key
# returns the recorded result instead of re-driving the guest. Process-local
# by design — a NEW process cannot know the guest state either, and the
# bounded map keeps a churning key space from growing without limit.
_UNKNOWN_RESULTS: dict[str, dict] = {}
_UNKNOWN_LOCK = threading.Lock()
_UNKNOWN_CAP = 256


def _record_unknown(request_key: str, result: dict) -> None:
    with _UNKNOWN_LOCK:
        _UNKNOWN_RESULTS.pop(request_key, None)
        _UNKNOWN_RESULTS[request_key] = result
        while len(_UNKNOWN_RESULTS) > _UNKNOWN_CAP:
            _UNKNOWN_RESULTS.pop(next(iter(_UNKNOWN_RESULTS)))


def _lookup_unknown(request_key: str) -> dict | None:
    with _UNKNOWN_LOCK:
        recorded = _UNKNOWN_RESULTS.get(request_key)
        return dict(recorded) if recorded is not None else None


def _step_fail(index: int, detail: str) -> ValueError:
    return ValueError(f"step {index}: {detail}")


def _validate_sequence_steps(
    steps: list[dict], call_timeout_s: int,
) -> list[dict]:
    """Normalize + validate the whole plan before anything spawns (frozen
    contract: every rejection names `step <i>`, the count cap names `steps`,
    and wait budgets are capped by the call timeout). Encoding mirrors the
    single-step tools so the semantics cannot drift."""
    if not isinstance(steps, list) or not steps:
        raise ValueError("steps must be a non-empty list of at most 50 step dicts")
    if len(steps) > _MAX_SEQUENCE_STEPS:
        raise ValueError(
            f"steps is limited to {_MAX_SEQUENCE_STEPS} per sequence; got {len(steps)}")
    plan: list[dict] = []
    wait_budget_total = 0
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise _step_fail(i, "every step must be a dict")
        action = step.get("action")
        try:
            if action == "press_key":
                key = step.get("key")
                if not isinstance(key, str) or not key:
                    raise ValueError("key is required")
                modifiers = step.get("modifiers") or []
                if not isinstance(modifiers, list) or not all(
                        isinstance(m, str) for m in modifiers):
                    raise ValueError("modifiers must be a list of strings")
                if modifiers:
                    held = [m for m in modifiers if m.strip().lower() in _COMBO_MODIFIERS]
                    tapped = [key] + [m for m in modifiers if m not in held]
                    codes = _combo_codes(held, tapped)
                else:
                    codes = _scancodes_for_key(key)
                plan.append({"action": "codes", "codes": codes})
            elif action == "key_combo":
                keys = step.get("keys")
                if not isinstance(keys, list) or not keys or not all(
                        isinstance(k, str) for k in keys):
                    raise ValueError("keys must be a non-empty list of strings")
                plan.append({"action": "codes", "codes": _scancodes_for_combo(keys)})
            elif action == "type_text":
                text = step.get("text")
                if not isinstance(text, str) or not text:
                    raise ValueError("text is required")
                if any(ord(c) > 127 for c in text):
                    raise ValueError("text must be ASCII")
                plan.append({"action": "text", "text": text})
            elif action == "type_scancodes":
                raw_codes = step.get("scancodes")
                if not isinstance(raw_codes, list) or not raw_codes:
                    raise ValueError("scancodes list is required")
                for code in raw_codes:
                    if type(code) is not int or not (0 <= code <= 255):
                        raise ValueError(
                            f"scancodes must be integers 0..255; got {code!r}")
                plan.append({"action": "codes", "codes": list(raw_codes)})
            elif action == "mouse_move":
                x, y = step.get("x"), step.get("y")
                if x is None or y is None:
                    raise ValueError("x and y are required")
                fw = int(step.get("frame_width") or 0)
                fh = int(step.get("frame_height") or 0)
                if (fw or fh) and (fw <= 0 or fh <= 0):
                    raise ValueError("frame_width/frame_height must be positive when given")
                plan.append({"action": "mouse_positional", "x": int(x), "y": int(y),
                             "fw": fw, "fh": fh, "click": False, "button": 1})
            elif action == "click":
                x, y = step.get("x"), step.get("y")
                if x is None or y is None:
                    if x is not None or y is not None:
                        raise ValueError("x and y must be given together")
                    button = step.get("button", 1)
                    if button not in (1, 2):
                        raise ValueError("button must be 1 (left) or 2 (right)")
                    plan.append({"action": "mouse_click_here", "button": button})
                else:
                    button = step.get("button", 1)
                    if button not in (1, 2):
                        raise ValueError("button must be 1 (left) or 2 (right)")
                    fw = int(step.get("frame_width") or 0)
                    fh = int(step.get("frame_height") or 0)
                    if (fw or fh) and (fw <= 0 or fh <= 0):
                        raise ValueError(
                            "frame_width/frame_height must be positive when given")
                    plan.append({"action": "mouse_positional", "x": int(x), "y": int(y),
                                 "fw": fw, "fh": fh, "click": True, "button": button})
            elif action == "mouse_button":
                button = step.get("button", 1)
                if button not in (1, 2):
                    raise ValueError("button must be 1 (left) or 2 (right)")
                plan.append({"action": "button", "button": button,
                             "is_down": bool(step.get("is_down", False))})
            elif action == "scroll":
                if "delta" not in step:
                    raise ValueError("delta is required")
                plan.append({"action": "scroll", "delta": int(step["delta"])})
            elif action == "wait_frame_stable":
                # PRR-005: the summed wait budgets must fit the call deadline —
                # a plan whose worst case exceeds it deterministically dies
                # mid-plan into the non-replayable UNKNOWN class.
                if wait_budget_total + min(step.get("timeout_s", call_timeout_s) or 0,
                                           call_timeout_s) > call_timeout_s:
                    raise ValueError(
                        f"wait budgets total more than the call timeout_s="
                        f"{call_timeout_s}; raise timeout_s or shorten the waits")
                wait_budget_total += min(step.get("timeout_s", call_timeout_s) or 0,
                                         call_timeout_s)
                stable_ms = step.get("stable_ms")
                if type(stable_ms) is not int or stable_ms < 1:
                    raise ValueError("stable_ms must be a positive integer")
                timeout = step.get("timeout_s", call_timeout_s)
                if type(timeout) is not int or timeout < 1:
                    raise ValueError("timeout_s must be a positive integer")
                capped = min(timeout, call_timeout_s)
                if stable_ms >= capped * 1000:
                    raise ValueError(
                        "stable_ms must be less than the capped wait timeout or the "
                        "quiet window can never be observed")
                interval_ms = step.get("interval_ms", 250)
                if type(interval_ms) is not int or interval_ms < 1:
                    raise ValueError("interval_ms must be a positive integer")
                baseline = step.get("baseline_hash", "")
                if baseline and not re.fullmatch(r"[0-9a-f]{64}", baseline):
                    raise ValueError("baseline_hash must be empty or 64-char hex sha256")
                plan.append({"action": "wait_stable", "stable_ms": stable_ms,
                             "timeout_s": capped, "interval_ms": interval_ms,
                             "baseline": baseline})
            else:
                raise ValueError(f"unknown action {action!r}")
        except ValueError as exc:
            raise _step_fail(i, str(exc)) from None
        except (TypeError, KeyError, AttributeError) as exc:
            raise _step_fail(i, f"invalid step fields: {exc}") from None
    return plan


def _sequence_step_block(
    index: int, step: dict, read_expr: str, seq_width: int, seq_height: int,
) -> list[str]:
    """One unrolled step block: guarded by $seqFailed (stop-on-failure; later
    steps report SKIPPED, never silently dropped), body in try/catch, result
    on one STEP= stdout line (ERR rides base64 so CLIXML cannot mangle it)."""
    body: list[str]
    if step["action"] == "codes":
        body = [
            "        $r = Invoke-CimMethod -InputObject $kb -MethodName TypeScancodes "
            "-ErrorAction Stop -Arguments @{ ScanCodes = [byte[]]@("
            + ",".join(str(c) for c in step["codes"]) + ") }",
            "        if ($r.ReturnValue -ne 0) { throw ('TypeScancodes failed with "
            "ReturnValue=' + $r.ReturnValue) }",
        ]
    elif step["action"] == "text":
        body = [
            "        $text = [System.Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String(" + read_expr + "))",
            "        $r = Invoke-CimMethod -InputObject $kb -MethodName TypeText "
            "-ErrorAction Stop -Arguments @{ AsciiText = $text }",
            "        if ($r.ReturnValue -ne 0) { throw ('TypeText failed with "
            "ReturnValue=' + $r.ReturnValue) }",
        ]
    elif step["action"] == "mouse_positional":
        body = [
            "        $x = " + str(step["x"]),
            "        $y = " + str(step["y"]),
            "        $fw = " + str(step["fw"]),
            "        $fh = " + str(step["fh"]),
            "        if ((-not $vh) -or (-not $vh.CurrentHorizontalResolution) "
            "-or (-not $vh.CurrentVerticalResolution)) { throw 'display head resolution "
            "unavailable for positional mouse input' }",
            "        $hw = $vh.CurrentHorizontalResolution",
            "        $hv = $vh.CurrentVerticalResolution",
            "        if ($fw -and $fh) {",
            "            $hx = [math]::Round($x * $hw / $fw)",
            "            $hy = [math]::Round($y * $hv / $fh)",
            "        } else { $hx = $x; $hy = $y }",
            "        $hx = [math]::Max(0, [math]::Min($hx, $hw - 1))",
            "        $hy = [math]::Max(0, [math]::Min($hy, $hv - 1))",
            "        $r0 = Invoke-CimMethod -InputObject $m -MethodName SetAbsolutePosition "
            "-ErrorAction Stop -Arguments @{ HorizontalPosition = $hx; VerticalPosition = $hy }",
            "        if ($r0.ReturnValue -ne 0) { throw ('SetAbsolutePosition failed with "
            "ReturnValue=' + $r0.ReturnValue) }",
        ]
        if step["click"]:
            body += [
                "        $r = Invoke-CimMethod -InputObject $m -MethodName ClickButton "
                "-ErrorAction Stop -Arguments @{ ButtonIndex = " + str(step["button"]) + " }",
                "        if ($r.ReturnValue -ne 0) { throw ('ClickButton failed with "
                "ReturnValue=' + $r.ReturnValue) }",
            ]
    elif step["action"] == "mouse_click_here":
        body = [
            "        $r = Invoke-CimMethod -InputObject $m -MethodName ClickButton "
            "-ErrorAction Stop -Arguments @{ ButtonIndex = " + str(step["button"]) + " }",
            "        if ($r.ReturnValue -ne 0) { throw ('ClickButton failed with "
            "ReturnValue=' + $r.ReturnValue) }",
        ]
    elif step["action"] == "button":
        body = [
            "        $r = Invoke-CimMethod -InputObject $m -MethodName SetButtonState "
            "-ErrorAction Stop -Arguments @{ ButtonIndex = " + str(step["button"])
            + "; IsDown = $" + ("true" if step["is_down"] else "false") + " }",
            "        if ($r.ReturnValue -ne 0) { throw ('SetButtonState failed with "
            "ReturnValue=' + $r.ReturnValue) }",
        ]
    elif step["action"] == "scroll":
        body = [
            "        $r = Invoke-CimMethod -InputObject $m -MethodName SetScrollPosition "
            "-ErrorAction Stop -Arguments @{ ScrollPositionDelta = "
            + str(step["delta"]) + " }",
            "        if ($r.ReturnValue -ne 0) { throw ('SetScrollPosition failed with "
            "ReturnValue=' + $r.ReturnValue) }",
        ]
    else:  # wait_stable
        max_polls = math.ceil(step["timeout_s"] * 1000 / step["interval_ms"])
        body = [
            "        $deadline = (Get-Date).AddSeconds(" + str(step["timeout_s"]) + ")",
            "        $polls = 0",
            "        $baseline = " + pswindows.ps_quote(step["baseline"]),
            "        $refHash = " + pswindows.ps_quote(step["baseline"]),
            "        $lastHash = ''",
            "        $lastChange = $null",
            "        $moveSeen = $false",
            "        $sha = New-Object Security.Cryptography.SHA256Managed",
            "        $waitStop = $null",
            "        while ($polls -lt " + str(max_polls) + ") {",
            "            if ((Get-Date) -ge $deadline) {",
            "                if (($baseline -ne '') -and ($polls -gt 0) -and (-not $moveSeen)) "
            "{ $waitStop = 'unchanged' } else { $waitStop = 'deadline' }",
            "                break",
            "            }",
            "            $wr = Invoke-CimMethod -InputObject $svc -MethodName "
            "GetVirtualSystemThumbnailImage -ErrorAction Stop -Arguments @{",
            "                TargetSystem = $vm",
            "                WidthPixels  = " + str(seq_width),
            "                HeightPixels = " + str(seq_height),
            "            }",
            "            if ($wr.ReturnValue -ne 0) { throw "
            "('GetVirtualSystemThumbnailImage failed with ReturnValue=' + $wr.ReturnValue) }",
            "            $polls++",
            "            $pxLen = 0; if ($wr.ImageData -ne $null) "
            "{ $pxLen = $wr.ImageData.Length }",
            "            $pxWant = 4 + (" + str(seq_width) + " * " + str(seq_height) + " * 2)",
            "            if ($pxLen -ne $pxWant) { throw ('thumbnail payload length "
            "mismatch: got ' + $pxLen + ' bytes, expected ' + $pxWant) }",
            "            $hash = ([System.BitConverter]::ToString("
            "$sha.ComputeHash($wr.ImageData, 4, $wr.ImageData.Length - 4)) "
            "-replace '-','').ToLowerInvariant()",
            "            $lastHash = $hash",
            "            $now = Get-Date",
            "            if ($refHash -eq '') { $refHash = $hash; $lastChange = $now }",
            "            elseif ($hash -ne $refHash) { $refHash = $hash; "
            "$lastChange = $now; $moveSeen = $true }",
            "            if (($null -ne $lastChange) -and ((($now) - ($lastChange))"
            ".TotalMilliseconds -ge " + str(step["stable_ms"]) + ")) "
            "{ $waitStop = 'stable'; break }",
            "            if ($polls -ge " + str(max_polls) + " -or (Get-Date) -ge $deadline) {",
            "                if (($baseline -ne '') -and ($polls -gt 0) -and (-not $moveSeen)) "
            "{ $waitStop = 'unchanged' } else { $waitStop = 'deadline' }",
            "                break",
            "            }",
            "            Start-Sleep -Milliseconds " + str(step["interval_ms"]),
            "        }",
            "        if (-not $waitStop) { $waitStop = 'deadline' }",
            "        Write-Output ('STEP=" + str(index) + " OK=1 STOP=' + $waitStop "
            "+ ' HASH=' + $lastHash)",
        ]
    lines = ["    if (-not $seqFailed) {", "      try {"]
    if step["action"] != "wait_stable":
        lines += body + [f"        Write-Output ('STEP={index} OK=1')"]
    else:
        lines += body
    lines += [
        "      } catch {",
        "        $seqFailed = $true",
        f"        Write-Output ('STEP={index} OK=0 ERR=' + [Convert]::ToBase64String("
        "[Text.Encoding]::UTF8.GetBytes($_.Exception.Message)))",
        "      }",
        f"    }} else {{ Write-Output ('STEP={index} SKIPPED=1') }}",
    ]
    return lines


def _sequence_script(
    prelude: str, plan: list[dict], expect_frame_hash: str, expect_boot_epoch: int | None,
    timeout_s: int, width: int, height: int, remote: bool,
) -> str:
    """The one folded sequence process (frozen protocol): prelude(+identity
    guard) -> lookups -> boot epoch -> VMID=/EPOCH= emission -> preconditions
    (exit before any input on mismatch) -> the unrolled step blocks."""
    uses_kb = any(s["action"] in ("codes", "text") for s in plan)
    uses_mouse = any(s["action"].startswith("mouse") or s["action"] == "button"
                     or s["action"] == "scroll" for s in plan)
    uses_positional = any(s["action"] == "mouse_positional" for s in plan)
    uses_frames = bool(expect_frame_hash) or any(
        s["action"] == "wait_stable" for s in plan)
    text_steps = [s for s in plan if s["action"] == "text"]
    parts = [prelude, _VM_LOOKUP]
    if uses_kb:
        parts.append(_KEYBOARD_LOOKUP)
    if uses_mouse:
        parts += [
            _MOUSE_SYNTHETIC,
            "if (-not $m) {",
            _MOUSE_PS2,
            "    if (-not $m) { throw 'no mouse device associated with the VM' }",
            "}",
        ]
    if uses_positional:
        parts.append(_HEAD_LOOKUP)
    if uses_frames:
        parts.append(
            "$svc = Get-CimInstance -Namespace '" + _WMI_NS + "' "
            "-ClassName Msvm_VirtualSystemManagementService")
    # Boot epoch (issue #28): host WMI, credential-free — OnTimeInMilliseconds
    # relative to the host clock, so it is meaningful in firmware/WinPE.
    parts += [
        "$bootMs = $vm.OnTimeInMilliseconds",
        "$bootEpoch = [int]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - "
        "[int64]($bootMs / 1000))",
        "Write-Output ('VMID=' + $vmTarget)",
        "Write-Output ('EPOCH=' + $bootEpoch)",
    ]
    if expect_frame_hash:
        parts += [
            "        $r = Invoke-CimMethod -InputObject $svc -MethodName "
            "GetVirtualSystemThumbnailImage -ErrorAction Stop -Arguments @{",
            "            TargetSystem = $vm",
            "            WidthPixels  = " + str(width),
            "            HeightPixels = " + str(height),
            "        }",
            "        if ($r.ReturnValue -ne 0) { throw ('GetVirtualSystemThumbnailImage "
            "failed with ReturnValue=' + $r.ReturnValue) }",
            "        $pxLen = 0; if ($r.ImageData -ne $null) { $pxLen = $r.ImageData.Length }",
            "        $pxWant = 4 + (" + str(width) + " * " + str(height) + " * 2)",
            "        if ($pxLen -ne $pxWant) { throw ('thumbnail payload length mismatch: "
            "got ' + $pxLen + ' bytes, expected ' + $pxWant) }",
            "        $sha0 = New-Object Security.Cryptography.SHA256Managed",
            "        $hash0 = ([System.BitConverter]::ToString("
            "$sha0.ComputeHash($r.ImageData, 4, $r.ImageData.Length - 4)) "
            "-replace '-','').ToLowerInvariant()",
            "        if ($hash0 -ne " + pswindows.ps_quote(expect_frame_hash) + ") {",
            "            [Console]::Error.WriteLine('console sequence precondition "
            "mismatch: frame_hash expected " + expect_frame_hash + " actual ' + $hash0)",
            "            exit 1",
            "        }",
        ]
    if expect_boot_epoch is not None:
        parts += [
            "        if ([math]::Abs($bootEpoch - " + str(int(expect_boot_epoch)) + ") -gt 5) {",
            "            [Console]::Error.WriteLine('console sequence precondition "
            "mismatch: boot_epoch expected " + str(int(expect_boot_epoch)) +
            " actual ' + $bootEpoch)",
            "            exit 1",
            "        }",
        ]
    # Text rides stdin, one base64 line per text step (the type_text rule).
    read_expr = "$payloads[$ti]" if remote else "[Console]::In.ReadLine()"
    if text_steps:
        if remote:
            parts.append(
                "$payloads = @("
                + ", ".join(f"$__p{i}" for i in range(len(text_steps))) + ")")
        parts.append("$ti = 0")
    parts.append("$seqFailed = $false")
    for i, step in enumerate(plan):
        parts += _sequence_step_block(i, step, read_expr, width, height)
        if step["action"] == "text":
            parts.append("    $ti++")
    return "\n".join(parts)


def _parse_sequence_steps(stdout: str) -> list[dict]:
    """Repeated STEP= records from RAW stdout lines (the single-value-per-key
    `_meta_lines` dict cannot carry them)."""
    steps: list[dict] = []
    for line in stdout.splitlines():
        m = re.match(
            r"STEP=(\d+) (OK=1|OK=0 ERR=([A-Za-z0-9+/=]+)|SKIPPED=1)( STOP=(\w+)"
            r"( HASH=([0-9a-f]*))?)?", line.strip())
        if not m:
            continue
        entry: dict = {"index": int(m.group(1))}
        if m.group(3):  # OK=0 ERR=<b64>
            try:
                entry["error"] = base64.b64decode(m.group(3)).decode("utf-8", "replace")
            except Exception:
                entry["error"] = "step failed"
            entry["ok"] = False
        elif "SKIPPED=1" in (m.group(2) or ""):
            entry["skipped"] = True
        else:
            entry["ok"] = True
        if m.group(5):
            entry["stop_reason"] = m.group(5)
        if m.group(7):
            entry["frame_hash"] = m.group(7)
        steps.append(entry)
    return steps


def _run_sequence_wmi(
    be, connect_ms: float, ref: vmident.VMRef, plan: list[dict],
    expect_frame_hash: str, expect_boot_epoch: int | None,
    timeout_s: int, width: int, height: int,
) -> dict:
    """run_sequence over the in-process WMI backend: the same contract as the
    folded script — ONE lock acquisition spanning the boot-epoch read, the
    preconditions, and every step (nothing a raw input could do can slip
    between a passed precondition and the first input), per-step results,
    stop-on-failure."""
    started = time.monotonic()
    phase_dicts: list[dict] = []
    steps_out: list[dict] = []
    try:
        with _input_lock(ref):
            try:
                boot_epoch: int | None = be.boot_epoch(ref.id)
            except (wmiconsole.WMIError, AttributeError) as exc:
                raise ConsoleError(str(exc)) from None
            if expect_boot_epoch is not None and (
                    boot_epoch is None or abs(boot_epoch - int(expect_boot_epoch)) > 5):
                return {
                    "ok": False, "error_class": "precondition", "steps": [],
                    "precondition": "boot_epoch",
                    "vm_name": ref.name, "boot_epoch": boot_epoch,
                    "timings": _wmi_timings(connect_ms),
                }
            if expect_frame_hash:
                raw, t = be.capture(ref.id, width, height)
                phase_dicts.append(t)
                actual = _frame_hash(raw)
                if actual != expect_frame_hash:
                    return {
                        "ok": False, "error_class": "precondition", "steps": [],
                        "precondition": "frame_hash",
                        "vm_name": ref.name, "boot_epoch": boot_epoch,
                        "frame_hash": actual, "hash_domain": HASH_DOMAIN,
                        "timings": _wmi_timings(connect_ms, *phase_dicts),
                    }
            for i, step in enumerate(plan):
                try:
                    _r, t = _sequence_wmi_step(be, ref, step, width, height)
                except (ConsoleError, wmiconsole.WMIError,
                        wmiconsole.BackendUnavailable) as exc:
                    # Per-step failure (issue-28 contract, both transports): the
                    # failed step is reported and the rest skipped — never a
                    # whole-call raise that drops the executed prefix.
                    phase_dicts.append({})
                    steps_out.append({"index": i, "ok": False, "error": str(exc)})
                    for j in range(i + 1, len(plan)):
                        steps_out.append({"index": j, "skipped": True})
                    break
                phase_dicts.append(t)
                entry: dict = {"index": i, **_r}
                steps_out.append(entry)
                if not entry.get("ok", True):
                    for j in range(i + 1, len(plan)):
                        steps_out.append({"index": j, "skipped": True})
                    break
    except (wmiconsole.WMIError, wmiconsole.BackendUnavailable) as exc:
        raise ConsoleError(str(exc)) from None
    out: dict = {
        "ok": True, "vm_name": ref.name,
        "steps": steps_out,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "timings": _wmi_timings(connect_ms, *phase_dicts),
    }
    if boot_epoch is not None:
        out["boot_epoch"] = boot_epoch
    return out


def _sequence_wmi_step(be, ref: vmident.VMRef, step: dict, width: int, height: int):
    """One validated plan step over the WMI backend primitives (lock-free:
    the caller holds the console lock). Waits reuse the frozen stable-poll
    state machine shape; deadline is a reported stop reason, not a failure."""
    action = step["action"]
    if action == "codes":
        _r, t = be.type_scancodes(ref.id, step["codes"])
        return {"ok": True}, t
    if action == "text":
        _r, t = be.type_text(ref.id, step["text"])
        return {"ok": True}, t
    if action == "mouse_positional":
        head, t_head = be.head_resolution(ref.id)
        # head_resolution returns None OR a (None, None) pair while the VM is
        # off / the video head reports no resolution (wmiconsole contract) —
        # both are the structured refusal, never a scale attempt.
        if not head or not head[0] or not head[1]:
            raise ConsoleError("display head resolution unavailable for positional mouse")
        hx, hy = _scale_to_head(step["x"], step["y"], step["fw"], step["fh"], head)
        _r, t = be.mouse_move(ref.id, hx, hy)
        if step["click"]:
            _r2, t2 = be.mouse_click(ref.id, step["button"], hx, hy)
            return {"ok": True, "head_x": hx, "head_y": hy}, {**t_head, **t2}
        return {"ok": True, "head_x": hx, "head_y": hy}, {**t_head, **t}
    if action == "mouse_click_here":
        _r, t = be.mouse_click(ref.id, step["button"])
        return {"ok": True}, t
    if action == "button":
        _r, t = be.mouse_button(ref.id, step["button"], step["is_down"])
        return {"ok": True}, t
    if action == "scroll":
        _r, t = be.mouse_scroll(ref.id, step["delta"])
        return {"ok": True}, t
    # wait_stable: poll be.capture under the same in-lock region, mirroring
    # _wait_frame_stable_wmi's transition table.
    max_polls = math.ceil(step["timeout_s"] * 1000 / step["interval_ms"])
    polls, last_hash, raw = 0, "", None
    baseline = step["baseline"]
    ref_hash = baseline
    last_change: float | None = None
    move_seen = False
    started = time.monotonic()
    stop = "deadline"
    while polls < max_polls:
        if time.monotonic() - started >= step["timeout_s"]:
            stop = "deadline"
            break
        raw, t = be.capture(ref.id, width, height)
        polls += 1
        h = _frame_hash(raw)
        last_hash = h
        now = time.monotonic()
        if not ref_hash:
            ref_hash = h
            last_change = now
        elif h != ref_hash:
            ref_hash = h
            last_change = now
            move_seen = True
        if last_change is not None and (now - last_change) * 1000 >= step["stable_ms"]:
            stop = "stable"
            break
        if polls >= max_polls or time.monotonic() - started >= step["timeout_s"]:
            # Transition table shared with the folded script AND the
            # in-sequence PS wait block (which emits the same unchanged/
            # deadline distinction since the PRR-004 fix): "my input did
            # nothing" (supplied baseline, never differed) is distinguishable
            # from an honest deadline.
            if baseline and polls > 0 and not move_seen:
                stop = "unchanged"
            else:
                stop = "deadline"
            break
        time.sleep(step["interval_ms"] / 1000.0)
    entry = {"ok": True, "stop_reason": stop}
    if last_hash:
        entry["frame_hash"] = last_hash
    return entry, {}


def run_sequence(
    cfg: Config, vm_name: str = "", steps: list[dict] | None = None, vm_id: str = "",
    expect_frame_hash: str = "", expect_boot_epoch: int | None = None,
    timeout_s: int = 60, request_key: str = "", width: int = 640, height: int = 480,
) -> dict:
    """Run a validated batch of console actions as ONE plan: host-side
    validation of every step before anything spawns, ONE per-VM console lock
    acquisition for the whole sequence, ONE PowerShell process after GUID
    resolution, preconditions (frame hash / boot epoch) evaluated inside the
    locked region before the first input, per-step results with
    stop-on-failure (later steps reported skipped, never dropped), and text
    riding stdin base64 exactly like type_text. Bounded: at most 50 steps,
    every wait budget capped by `timeout_s`, PowerShell child deadline at
    `timeout_s + 15`. Policy: console_input category; no confirm parameter.

    With `request_key`, an uncertain post-dispatch outcome (a timed-out leg)
    is recorded once as UNKNOWN and a retry with the same key returns the
    recorded result instead of re-driving the guest (no automatic replay).
    request_key is a caller-managed namespace — keep keys unique per plan; the
    replay lookup runs before addressing/policy checks. UNKNOWN recording and
    deadline enforcement are PowerShell-transport behaviors (the WMI transport
    has no per-call timeout and does not record UNKNOWN).

    vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

    Returns: {ok, vm_name, boot_epoch, steps: [{index, ok, ...}]} or
    {ok: false, error_class: "precondition"|"unknown", ...}
    """
    policy.require_category(cfg, "console_input", f"run {len(steps or [])}-step console sequence on '{vm_name}'")
    # Name gate only when a name was supplied (issue #8's both-forms contract):
    # a vm_id-only call is validated through the GUID shape gate in the resolve
    # leg; an empty name still falls through to that same both-empty check there.
    if vm_name:
        vmident.checked_caller_name(vm_name)
    if expect_frame_hash and not re.fullmatch(r"[0-9a-f]{64}", expect_frame_hash):
        raise ValueError("expect_frame_hash must be an empty string or a 64-char hex sha256")
    if expect_boot_epoch is not None and type(expect_boot_epoch) is not int:
        raise ValueError("expect_boot_epoch must be an integer epoch second value or None")
    if type(timeout_s) is not int or timeout_s < 1:
        raise ValueError("timeout_s must be a positive integer")
    if not (160 <= width <= 4096 and 160 <= height <= 4096):
        raise ValueError("width/height must be within 160..4096")
    plan = _validate_sequence_steps(steps or [], timeout_s)
    if request_key:
        recorded = _lookup_unknown(request_key)
        if recorded is not None:
            return recorded
    be, connect_ms = _try_backend(cfg)
    if be is not None:
        ref_wmi: vmident.VMRef | None = None
        try:
            ref_wmi = _wmi_ref(be, cfg, vm_name, vm_id)
        except wmiconsole.BackendUnavailable:
            be = None
        if be is not None:
            assert ref_wmi is not None
            return _run_sequence_wmi(
                be, connect_ms, ref_wmi, plan, expect_frame_hash,
                expect_boot_epoch, timeout_s, width, height)
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing, guarded=True)
    started = time.monotonic()
    remote = pswindows.hyperv_host(cfg) is not None
    script = _sequence_script(
        prelude, plan, expect_frame_hash, expect_boot_epoch, timeout_s,
        width, height, remote)
    text_payloads = [pswindows.utf8_b64(s["text"]) for s in plan if s["action"] == "text"]
    with _input_lock(ref):
        result = _run(
            cfg, script,
            timeout_s=timeout_s + 15,
            stdin_b64="\n".join(text_payloads) if text_payloads else None,
            payload_lines=len(text_payloads),
            timing=timing,
        )
    if result.timed_out:
        out: dict = {
            "ok": False, "error_class": "unknown", "vm_name": ref.name,
            "steps": _parse_sequence_steps(result.stdout or ""),
            "note": ("the sequence leg timed out after input may have been sent; "
                     "whether the guest received the plan is unknowable — never "
                     "automatically replayed; a new plan requires a fresh explicit "
                     "request and precondition"),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "timings": _ps_timings(timing),
        }
        if request_key:
            _record_unknown(request_key, out)
        return out
    if result.returncode not in (0, None):
        stderr = result.stderr or ""
        if "console sequence precondition mismatch" in stderr:
            kind = "boot_epoch" if "boot_epoch expected" in stderr else "frame_hash"
            actual = ""
            match = re.search(r"actual (\S+)", stderr)
            if match:
                actual = match.group(1)
            env: dict = {
                "ok": False, "error_class": "precondition", "steps": [],
                "vm_name": ref.name, "precondition": kind,
                "timings": _ps_timings(timing),
            }
            if kind == "frame_hash":
                env["frame_hash"] = actual
                env["hash_domain"] = HASH_DOMAIN
            else:
                with_suppress = None
                try:
                    with_suppress = int(actual)
                except ValueError:
                    pass
                env["boot_epoch"] = with_suppress
            return env
        _check_input_rc(result, "console sequence", vm_name)
    meta, _payload = _meta_lines(result)
    if "VMID" in meta:
        guid = _parse_guid(meta, vm_name or ref.name)
        note_name_guid_hint(vm_name or ref.name, guid)
    boot_epoch = None
    if meta.get("EPOCH"):
        try:
            boot_epoch = int(meta["EPOCH"])
        except ValueError:
            boot_epoch = None
    steps_out = _parse_sequence_steps(result.stdout or "")
    if not steps_out:
        steps_out = [{"index": i, "ok": True} for i in range(len(plan))]
    return {
        "ok": True, "vm_name": ref.name,
        **({"boot_epoch": boot_epoch} if boot_epoch is not None else {}),
        "steps": steps_out,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "timings": _ps_timings(timing),
    }
