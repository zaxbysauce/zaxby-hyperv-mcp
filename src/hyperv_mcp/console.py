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
envelopes carry the standard error shape without timings); the WMI
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
import json
import math
import os
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from PIL import Image as PILImage

from . import guestexec, policy, pswindows, vmident, vmlocks, wmiconsole
from . import timing as timing_mod
from .config import Config

_WMI_NS = "root\\virtualization\\v2"


@contextmanager
def _input_lock(ref: vmident.VMRef) -> Iterator[None]:
    """Console input lock scope (issue #14): READ on the VM key so guest
    work proceeds during typing, plus WRITE on the second (vm, "console")
    key so two agents cannot interleave keystrokes. VM key is always
    outermost — no other site takes the console key, so no ordering cycle.

    Both keys are derived from ``ref.id``, which is the resolved GUID on the
    WMI transport and on the by-id PowerShell path — but the caller-supplied
    NAME on the by-name PowerShell path, where issue #18's fold resolves the
    VM inside the op script and the GUID is not known host-side before the
    spawn. Exclusion therefore holds between calls that address the VM the
    same way; it does NOT span name-vs-GUID addressing, nor a by-name console
    call against a write-scope op (which always resolves first and keys on
    the GUID). That residual is disclosed in vmident and tracked in issue
    #77.
    """
    with vmlocks.vm_lock(ref.id, mode="read"), vmlocks.vm_lock((ref.id, "console")):
        yield
_PREFIX_LEN = 4

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
}
# Extended (0xE0-prefixed) keys per the PS/2 set-1 controller stream.
# rightctrl/rightalt share the left-side make/break bytes but the controller
# requires the 0xE0 prefix to distinguish them from left-ctrl/left-alt.
_EXTENDED_KEYS = {"up", "down", "left", "right", "delete", "insert",
                  "home", "end", "pageup", "pagedown", "rightctrl", "rightalt"}
# Aliases that map onto other entries.
_KEY_SCANCODES["ctrl"] = _KEY_SCANCODES["leftctrl"]
_KEY_SCANCODES["alt"] = _KEY_SCANCODES["leftalt"]
_KEY_SCANCODES["shift"] = _KEY_SCANCODES["leftshift"]


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

def _vm_prelude(cfg: Config, vm_name: str, vm_id: str, timing: _PsTiming) -> tuple[str, vmident.VMRef]:
    """(prelude, ref): the script lines binding $vmTarget, plus the ref the
    caller needs (the console-input lock key and the result's display name).

    By id: vmident.resolve runs first (one spawn) so policy.vm_allowed sees the
    GUID's resolved name BEFORE any guest mutation (issue #8's contract), then
    the preamble binds the validated GUID directly. By name: the caller-name
    validation and policy.vm_allowed run host-side with no spawn (a denied name
    still starts nothing), the PR #4 resolver is embedded unchanged, and the
    GUID arrives on stdout when the process runs — so the ref carries the
    caller-supplied name as its lock key.
    """
    if vm_id:
        ref = _resolve_ps(cfg, vm_name, vm_id, timing)
        return guestexec.vm_target_preamble(ref.id), ref
    vmident.checked_caller_name(vm_name)
    policy.vm_allowed(cfg, vm_name)
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
        "[PSCustomObject]@{\n",
        "    returnValue = $r.ReturnValue\n",
        "    imageDataB64 = [Convert]::ToBase64String($r.ImageData)\n",
        "} | ConvertTo-Json -Compress\n",
    ])


# Poll loop: bounded by max_polls. When the baseline is empty the FIRST polled
# frame becomes the baseline (first-poll-is-baseline semantics); change is
# reported only when a later poll's hash differs from that baseline. HASH is
# always the full lowercase-hex sha256 of the raw payload — byte-identical to
# the host-side _frame_hash, so a returned frame_hash round-trips as a
# baseline_hash for cross-call change detection.
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
        "    $hash = ([System.BitConverter]::ToString($sha.ComputeHash($r.ImageData)) -replace '-','').ToLowerInvariant()\n",
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

    Prefers the active audit operation's collector, which is the value the
    server records. With no collector (a direct module call — the
    consolebench operator CLI drives console.screenshot that way), the block is
    derived from the op's own accumulators so it is never a fabricated zero.

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
    """A decoded console frame together with the single PNG encoding made for it.

    Every returned image used to cost two PNG encodes: one inside the decode and
    one in the server layer that re-opened those bytes. `png` is that one
    encoding, so the server reuses the bytes instead of encoding again and
    `save_path` writes exactly the bytes the caller receives.

    A frame IS a `PIL.Image.Image`, not a wrapper around one: it is built by
    copying the decoded image's state onto this class, so `isinstance` checks,
    the context-manager protocol, numpy interop and every read method behave
    exactly as they did on the return value this replaced. `png` is read-only —
    reassigning it is refused — and is the encoding of the frame's own pixels,
    so a caller that mutates the image and then re-saves it gets different
    bytes, which is what the frame-invariant tests pin.

    Memory: because `"BGR;16"` is not one of Pillow's mappable raw modes, the
    decode materialises a `width*height*3` raster, and a frame retains it
    alongside its PNG for the frame's lifetime. That is a bounded increase over
    the lazy `PILImage.open` this replaced — dimensions are clamped to
    160..4096 at every entry point and at most two frames are retained per
    `capture_sequence`, so the worst case is roughly 50 MB per held frame at the
    ceiling. Making the raster lazy is tracked separately.

    Build one with `Frame.from_image`, not by calling the constructor: the
    class deliberately does not override `PIL.Image.Image.__init__`.
    """

    _png: bytes

    @classmethod
    def from_image(cls, img: PILImage.Image) -> Frame:
        """Wrap an already-decoded image, encoding it to PNG exactly once."""
        frame = cls.__new__(cls)
        frame.__dict__.update(img.__dict__)
        frame._png = _encode_png(img)
        return frame

    @classmethod
    def from_png(cls, png: bytes) -> Frame:
        """Rebuild a frame from its PNG encoding.

        The encoding IS the frame, so a copy, a deepcopy and a pickle all
        round-trip through here and keep the class and `png` intact.
        """
        return cls.from_image(PILImage.open(io.BytesIO(png)))

    def __copy__(self) -> Frame:
        # PIL.Image.__copy__ returns a plain Image, which would silently drop
        # both the class and `png`. Rebuild through the encoding instead.
        return Frame.from_png(self._png)

    def __reduce__(self):
        return (_rebuild_frame, (self._png,))

    @property
    def png(self) -> bytes:
        return self._png

    @png.setter
    def png(self, value: bytes) -> None:
        raise AttributeError(
            "Frame.png is read-only: it is the single encoding of this frame's "
            "pixels. Mutate the image and re-save it instead."
        )


def _rebuild_frame(png: bytes) -> Frame:
    """Module-level rebuild target so a Frame pickles."""
    return Frame.from_png(png)


def _encode_png(img: PILImage.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


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
    return hashlib.sha256(raw).hexdigest()


def _capture_raw(
    cfg: Config, prelude: str, width: int, height: int, timing: _PsTiming | None = None
) -> bytes:
    """One self-contained capture: the prelude binds $vmTarget (the PR #4
    resolver by name or the GUID preamble by id), so a by-name frame resolves
    inside its own process and no separate GUID spawn is needed."""
    script = _folded_capture_script(prelude, width, height)
    result = _run(cfg, script, timeout_s=90, timing=timing)
    _check_rc(result, "console screenshot")
    try:
        data = json.loads(result.stdout.strip().splitlines()[-1])
        payload = base64.b64decode(data["imageDataB64"], validate=True)
    except (json.JSONDecodeError, KeyError, binascii.Error, ValueError) as exc:
        raise ConsoleError(f"screenshot result parse failed: {exc}") from None
    expected = width * height * 2 + _PREFIX_LEN
    if len(payload) != expected:
        raise ConsoleError(
            f"thumbnail payload length mismatch: got {len(payload)}, expected {expected}"
        )
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
        known = ", ".join(sorted(_KEY_SCANCODES))
        raise ValueError(f"unknown key {key!r}; supported keys: {known}")
    make, brk = entry
    if name in _EXTENDED_KEYS:
        return [0xE0, make, 0xE0, brk]
    return [make, brk]


def _scancodes_for_combo(keys: list[str]) -> list[int]:
    """Combo: modifier makes first, then each key in order, modifier breaks last.
    Modifiers go through the same extended-prefix rule as _scancodes_for_key
    (rightctrl/rightalt carry 0xE0 even as combo modifiers)."""
    mods = [k for k in keys if k.strip().lower() in ("ctrl", "alt", "shift",
                                                     "leftctrl", "rightctrl",
                                                     "leftalt", "rightalt",
                                                     "leftshift", "rightshift")]
    rest = [k for k in keys if k not in mods]
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
) -> tuple[Frame, dict]:
    """Capture the console; returns (frame, metadata). Caller wraps in
    MCP image content. Raises on failure (uniform list-form success shape)."""
    if not (160 <= width <= 4096 and 160 <= height <= 4096):
        raise ValueError("width/height must be within 160..4096")
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
        return _screenshot_wmi(cfg, be, connect_ms, ref, width, height, save_path, t0)
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
    prefix_hex = raw[:_PREFIX_LEN].hex()
    frame = _decode_frame(raw, actual_w, actual_h)
    meta = {
        "vm_name": ref.name,
        "vm_id": guid,
        "width": actual_w,
        "height": actual_h,
        "frame_hash": _frame_hash(raw),
        "prefix_hex": prefix_hex,
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
    if save_path:
        policy.check_host_write(cfg, save_path)
        parent = os.path.dirname(save_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(save_path, "wb") as fh:
            fh.write(frame.png)
        meta["saved_path"] = save_path
    return frame, meta


def _screenshot_wmi(
    cfg: Config,
    be,
    connect_ms: float,
    ref: vmident.VMRef,
    width: int,
    height: int,
    save_path: str,
    t0: float = 0.0,
) -> tuple[Frame, dict]:
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
        prefix_hex = raw[:_PREFIX_LEN].hex()
        frame = _decode_frame(raw, actual_w, actual_h)
        meta = {
            "vm_name": ref.name,
            "vm_id": ref.id,
            "width": actual_w,
            "height": actual_h,
            "frame_hash": _frame_hash(raw),
            "prefix_hex": prefix_hex,
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
        if save_path:
            policy.check_host_write(cfg, save_path)
            parent = os.path.dirname(save_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(save_path, "wb") as fh:
                fh.write(frame.png)
            meta["saved_path"] = save_path
        return frame, meta
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
    try:
        data = json.loads(payload_line)
    except json.JSONDecodeError as exc:
        raise ConsoleError(f"display info parse failed: {exc}") from None
    data["vm_id"] = guid
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
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
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
    _check_rc(result, "console type_text")
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
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        codes = _scancodes_for_combo([key] + list(modifiers or []))
        return _send_scancodes_locked(cfg, ref, codes, be=be, connect_ms=connect_ms)
    timing = _PsTiming()
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
    codes = _scancodes_for_combo([key] + list(modifiers or []))
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
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
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
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
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
    _check_rc(result, "console scancodes")
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
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
    script = _folded_mouse_positional_script(
        prelude, x, y, frame_width, frame_height, click=False, button=1
    )
    with _input_lock(ref):
        result = _run(cfg, script, timeout_s=90, timing=timing)
    _check_rc(result, "console mouse move")
    meta_lines, _payload = _meta_lines(result)
    hx = _require_int(meta_lines, "HEADX", "mouse move")
    hy = _require_int(meta_lines, "HEADY", "mouse move")
    return {
        "ok": True, "operation": f"move to ({hx},{hy})", "vm_name": ref.name,
        "head_x": hx, "head_y": hy,
        "timings": _ps_timings(timing),
    }


def click(
    cfg: Config, vm_name: str = "", x: int = 0, y: int = 0, frame_width: int = 0,
    frame_height: int = 0, button: int = 1, vm_id: str = "",
) -> dict:
    policy.require_category(cfg, "console_input", f"click on '{vm_name}' console")
    if button not in (1, 2):
        raise ValueError("button must be 1 (left) or 2 (right)")
    if (frame_width or frame_height) and (frame_width <= 0 or frame_height <= 0):
        raise ValueError("frame_width/frame_height must be positive when given")
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        try:
            with _input_lock(ref):
                extra: dict = {}
                if x or y:
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
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
    if x or y:
        script = _folded_mouse_positional_script(
            prelude, x, y, frame_width, frame_height, click=True, button=button
        )
        with _input_lock(ref):
            result = _run(cfg, script, timeout_s=90, timing=timing)
        _check_rc(result, "console mouse click")
        meta_lines, _payload = _meta_lines(result)
        hx = _require_int(meta_lines, "HEADX", "click")
        hy = _require_int(meta_lines, "HEADY", "click")
        return {
            "ok": True, "operation": f"click button {button}", "vm_name": ref.name,
            "head_x": hx, "head_y": hy,
            "timings": _ps_timings(timing),
        }
    # x=0,y=0 means 'click at current position' — no positioning leg at all.
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
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
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
    prelude, ref = _vm_prelude(cfg, vm_name, vm_id, timing)
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
    _check_rc(result, f"console mouse {detail}")
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
        "timings": _wmi_timings(connect_ms, *phase_dicts),
    }
    if last_hash:
        out["frame_hash"] = last_hash
    if stop_reason == "changed" and raw is not None:
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
    started = time.monotonic()
    for i in range(count):
        # Each frame is its own self-contained process (the prelude resolves the
        # VM), so there is no separate GUID process — at most one per frame.
        raw = _capture_raw(cfg, prelude, width, height, timing)
        h = _frame_hash(raw)
        changed_bytes = (
            sum(1 for a, b in zip(prev_raw, raw, strict=True) if a != b) if prev_raw is not None else 0
        )
        frames.append({
            "index": i,
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
    per-frame bookkeeping contract (strict-zip changed-byte counts over
    equal-length payloads, first-and-last-only images)."""
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
            changed_bytes = (
                sum(1 for a, b in zip(prev_raw, raw, strict=True) if a != b)
                if prev_raw is not None else 0
            )
            frames.append({
                "index": i,
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
