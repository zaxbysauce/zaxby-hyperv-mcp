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
  - Mouse: instances must be enumerated from Msvm_SyntheticMouse directly and
    associated to Msvm_ComputerSystem for the VM match — the
    Get-CimAssociatedInstance -ResultClassName CIM_PointingDevice query
    returns a base-typed object whose derived methods (SetAbsolutePosition,
    ClickButton, ...) are NOT invokable. Methods:
    SetAbsolutePosition(HorizontalPosition:SInt32, VerticalPosition:SInt32),
    ClickButton(ButtonIndex:UInt32), SetButtonState(ButtonIndex, IsDown),
    GetButtonState(ButtonIndex), SetScrollPosition(ScrollPositionDelta).
  - Coordinate mapping: the thumbnail is a scaled snapshot of the display
    head; mouse coordinates are in head space (Msvm_VideoHead
    CurrentHorizontal/VerticalResolution). Frame-space inputs are scaled by
    head/frame; when neither frame dims nor head resolution are available the
    tools error instead of clicking somewhere unverified.

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

from . import policy, pswindows, vmident, vmlocks, wmiconsole
from .config import Config

_WMI_NS = "root\\virtualization\\v2"


@contextmanager
def _input_lock(ref: vmident.VMRef) -> Iterator[None]:
    """Console input lock scope (issue #14): READ on the VM key so guest
    work proceeds during typing, plus WRITE on the second (vm, "console")
    key so two agents can never interleave keystrokes. VM key is always
    outermost — no other site takes the console key, so no ordering cycle.
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

def _vm_lookup_script(guid: str) -> str:
    return (
        "$vm = Get-CimInstance -Namespace '" + _WMI_NS + "' -ClassName Msvm_ComputerSystem "
        "-Filter \"Name='" + guid.lower() + "'\"\n"
        "if (-not $vm) { throw 'VM not found in WMI namespace (is it running?)' }\n"
        "Write-Output ('VMSTATE=' + $vm.EnabledState)\n"
    )


_CAPTURE_SCRIPT_TMPL = """
$vm = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_ComputerSystem -Filter "Name='%GUID%'"
if (-not $vm) { throw 'VM not found in WMI namespace (is it running?)' }
$svc = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_VirtualSystemManagementService
$r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -ErrorAction Stop -Arguments @{
    TargetSystem = $vm
    WidthPixels  = %W
    HeightPixels = %H
}
if ($r.ReturnValue -ne 0) { throw ('GetVirtualSystemThumbnailImage failed with ReturnValue=' + $r.ReturnValue) }
[PSCustomObject]@{
    returnValue = $r.ReturnValue
    imageDataB64 = [Convert]::ToBase64String($r.ImageData)
} | ConvertTo-Json -Compress
"""

_KEYBOARD_SCRIPT_TMPL = """
$vm = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_ComputerSystem -Filter "Name='%GUID%'"
$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard | Select-Object -First 1
if (-not $kb) { throw 'no keyboard device associated with the VM' }
%CALL%
"""

_MOUSE_FOR_VM_SCRIPT = """
$vm = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_ComputerSystem -Filter "Name='%GUID%'"
if (-not $vm) { throw 'VM not found in WMI namespace (is it running?)' }
$mice = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_SyntheticMouse
foreach ($m in $mice) {
    $owner = Get-CimAssociatedInstance -InputObject $m -ResultClassName Msvm_ComputerSystem | Select-Object -First 1
    if ($owner -and $owner.Name -eq $vm.Name) {
        Write-Output ('MOUSEFOUND=' + $m.Name)
        break
    }
    $m = $null
}
if (-not $m) { throw 'no synthetic mouse device associated with the VM' }
%CALL%
"""

_HEAD_RES_SCRIPT = """
$vm = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_ComputerSystem -Filter "Name='%GUID%'"
$vh = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VideoHead | Select-Object -First 1
if (-not $vh) { throw 'no video head associated with the VM' }
[PSCustomObject]@{
    horizontal = $vh.CurrentHorizontalResolution
    vertical = $vh.CurrentVerticalResolution
} | ConvertTo-Json -Compress
"""

_DISPLAY_INFO_SCRIPT = """
$vm = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_ComputerSystem -Filter "Name='%GUID%'"
$vh = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VideoHead | Select-Object -First 1
$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard | Select-Object -First 1
$mice = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_SyntheticMouse
$mouse = $null
foreach ($m in $mice) {
    $owner = Get-CimAssociatedInstance -InputObject $m -ResultClassName Msvm_ComputerSystem | Select-Object -First 1
    if ($owner -and $owner.Name -eq $vm.Name) { $mouse = $m; break }
}
[PSCustomObject]@{
    enabled_state = $vm.EnabledState
    head_horizontal = if ($vh) { $vh.CurrentHorizontalResolution } else { $null }
    head_vertical = if ($vh) { $vh.CurrentVerticalResolution } else { $null }
    keyboard_present = [bool]$kb
    keyboard_enabled = if ($kb) { $kb.EnabledState } else { $null }
    mouse_present = [bool]$mouse
    mouse_enabled = if ($mouse) { $mouse.EnabledState } else { $null }
} | ConvertTo-Json -Compress
"""

# Poll loop: bounded by max_polls. When %BASELINE% is empty the FIRST polled
# frame becomes the baseline (first-poll-is-baseline semantics); change is
# reported only when a later poll's hash differs from that baseline. HASH is
# always the full lowercase-hex sha256 of the raw payload — byte-identical to
# the host-side _frame_hash, so a returned frame_hash round-trips as a
# baseline_hash for cross-call change detection.
_WAIT_FRAME_SCRIPT_TMPL = """
$vm = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_ComputerSystem -Filter "Name='%GUID%'"
if (-not $vm) { throw 'VM not found in WMI namespace (is it running?)' }
$svc = Get-CimInstance -Namespace '%NS%' -ClassName Msvm_VirtualSystemManagementService
$deadline = (Get-Date).AddSeconds(%TIMEOUT_S%)
$polls = 0
$baseline = '%BASELINE%'
$lastHash = ''
$sha = New-Object Security.Cryptography.SHA256Managed
while ($polls -lt %MAX_POLLS%) {
    if ((Get-Date) -ge $deadline) { Write-Output ('STOP=deadline POLLS=' + $polls + ' HASH=' + $lastHash); break }
    $r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -ErrorAction Stop -Arguments @{
        TargetSystem = $vm
        WidthPixels  = %W%
        HeightPixels = %H%
    }
    if ($r.ReturnValue -ne 0) { throw ('GetVirtualSystemThumbnailImage failed with ReturnValue=' + $r.ReturnValue) }
    $polls++
    $hash = ([System.BitConverter]::ToString($sha.ComputeHash($r.ImageData)) -replace '-','').ToLowerInvariant()
    $lastHash = $hash
    if ($baseline -eq '') { $baseline = $hash }
    if ($hash -ne $baseline) {
        Write-Output ('STOP=changed POLLS=' + $polls + ' HASH=' + $hash)
        Write-Output ('FRAME=' + [Convert]::ToBase64String($r.ImageData))
        break
    }
    if ($polls -ge %MAX_POLLS% -or (Get-Date) -ge $deadline) { Write-Output ('STOP=deadline POLLS=' + $polls + ' HASH=' + $hash); break }
    Start-Sleep -Milliseconds %INTERVAL_MS%
}
"""


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
    timing: _PsTiming | None = None,
):
    """console's PowerShell choke (issue #43): composes the remote hop from
    the CALLER's cfg before spawning; identity in local mode. The optional
    timing accumulator records one entry per spawn (issue #45)."""
    script, stdin = pswindows.compose_remote(
        cfg, script,
        payload_lines=1 if stdin_b64 is not None else 0,
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
    cfg: Config, guid: str, width: int, height: int, timing: _PsTiming | None = None
) -> bytes:
    script = (
        _CAPTURE_SCRIPT_TMPL.replace("%NS%", _WMI_NS)
        .replace("%GUID%", guid.lower())
        .replace("%W", str(width))
        .replace("%H", str(height))
    )
    result = _run(cfg, script.strip(), timeout_s=90, timing=timing)
    _check_rc(result, "console screenshot")
    try:
        data = json.loads(result.stdout)
        payload = base64.b64decode(data["imageDataB64"], validate=True)
    except (json.JSONDecodeError, KeyError, binascii.Error, ValueError) as exc:
        raise ConsoleError(f"screenshot result parse failed: {exc}") from None
    expected = width * height * 2 + _PREFIX_LEN
    if len(payload) != expected:
        raise ConsoleError(
            f"thumbnail payload length mismatch: got {len(payload)}, expected {expected}"
        )
    return payload


def _head_resolution(
    cfg: Config, guid: str, timing: _PsTiming | None = None
) -> tuple[int, int] | None:
    script = _HEAD_RES_SCRIPT.replace("%NS%", _WMI_NS).replace("%GUID%", guid.lower())
    result = _run(cfg, script.strip(), timeout_s=60, timing=timing)
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
        h, v = int(data["horizontal"]), int(data["vertical"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
    if h <= 0 or v <= 0:
        return None
    return h, v


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
    be, connect_ms = _try_backend(cfg)
    ref: vmident.VMRef | None = None
    if be is not None:
        try:
            ref = _wmi_ref(be, cfg, vm_name, vm_id)
        except wmiconsole.BackendUnavailable:
            be = None
    if be is not None:
        assert ref is not None
        return _screenshot_wmi(cfg, be, connect_ms, ref, width, height, save_path)
    timing = _PsTiming()
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    guid = ref.id
    head = _head_resolution(cfg, guid, timing)
    fallback_used = ""
    raw: bytes | None = None
    actual_w, actual_h = width, height
    chain: list[tuple[int, int]] = [(width, height)]
    if head and (width, height) != head:
        chain.append(head)
    chain.extend([(640, 480), (320, 240)])
    for w, h in chain:
        try:
            raw = _capture_raw(cfg, guid, w, h, timing)
            actual_w, actual_h = w, h
            if (w, h) != chain[0]:
                fallback_used = f"{chain[0][0]}x{chain[0][1]} failed; captured at {w}x{h}"
            break
        except ConsoleError as exc:
            if (w, h) == chain[-1]:
                raise
            fallback_used = f"{chain[0][0]}x{chain[0][1]}: {exc}"
    assert raw is not None
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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    script = _DISPLAY_INFO_SCRIPT.replace("%NS%", _WMI_NS).replace("%GUID%", ref.id)
    result = _run(cfg, script.strip(), timeout_s=60, timing=timing)
    _check_rc(result, "console display info")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ConsoleError(f"display info parse failed: {exc}") from None
    data["vm_id"] = ref.id
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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    guid = ref.id
    chunks = [text[i:i + 512] for i in range(0, len(text), 512)]
    calls = 0
    with _input_lock(ref):
        for i, chunk in enumerate(chunks):
            # Text rides stdin as UTF-8 base64 — never in the script, argv, or
            # error records (CLIXML errors quote script lines).
            # Remote mode: the composer's local preamble read the line and
            # forwarded it as scriptblock parameter $__p0 (a remote block
            # cannot read local stdin); local mode keeps the inline read
            # byte-identical to the historic emission.
            read_expr = (
                "[Convert]::FromBase64String($__p0)"
                if pswindows.hyperv_host(cfg) else
                "[Convert]::FromBase64String([Console]::In.ReadLine())"
            )
            call = (
                "$text = [System.Text.Encoding]::UTF8.GetString("
                + read_expr + ")\n"
                "$r = Invoke-CimMethod -InputObject $kb -MethodName TypeText "
                "-ErrorAction Stop -Arguments @{ AsciiText = $text }\n"
                "if ($r.ReturnValue -ne 0) { throw ('TypeText failed with ReturnValue=' + $r.ReturnValue) }\n"
                "Write-Output ('RC=' + $r.ReturnValue + ' CHUNK=' + %I + '/' + %N)\n"
            ).replace("%I", str(i + 1)).replace("%N", str(len(chunks)))
            script = _KEYBOARD_SCRIPT_TMPL.replace("%NS%", _WMI_NS).replace(
                "%GUID%", guid.lower()
            ).replace("%CALL%", call)
            result = _run(cfg,
                script.strip(), timeout_s=90, stdin_b64=pswindows.utf8_b64(chunk),
                timing=timing,
            )
            _check_rc(result, f"console type_text chunk {i + 1}/{len(chunks)}")
            calls += 1
            if i < len(chunks) - 1:
                time.sleep(0.05)
    return {
        "ok": True, "chunks": calls, "chars": len(text), "vm_name": ref.name,
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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    codes = _scancodes_for_combo([key] + list(modifiers or []))
    return _send_scancodes_locked(cfg, ref, codes, timing=timing)


def key_combo(cfg: Config, vm_name: str = "", keys: list[str] | None = None, vm_id: str = "") -> dict:
    policy.require_category(cfg, "console_input", f"send combo {keys!r} on '{vm_name}' console")
    if not keys:
        raise ValueError("keys list is required")
    be, connect_ms, ref = _select_backend_and_ref(cfg, vm_name, vm_id)
    if be is not None and ref is not None:
        codes = _scancodes_for_combo(keys)
        return _send_scancodes_locked(cfg, ref, codes, be=be, connect_ms=connect_ms)
    timing = _PsTiming()
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    codes = _scancodes_for_combo(keys)
    return _send_scancodes_locked(cfg, ref, codes, timing=timing)


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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    return _send_scancodes_locked(cfg, ref, list(scancodes), timing=timing)


def _send_scancodes_locked(
    cfg: Config,
    ref: vmident.VMRef,
    codes: list[int],
    be=None,
    connect_ms: float = 0.0,
    timing: _PsTiming | None = None,
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
    sent = 0
    with _input_lock(ref):
        for i, chunk in enumerate(chunks):
            arr = ",".join(str(c) for c in chunk)
            call = (
                "$r = Invoke-CimMethod -InputObject $kb -MethodName TypeScancodes "
                "-ErrorAction Stop -Arguments @{ ScanCodes = [byte[]](" + arr + ") }\n"
                "if ($r.ReturnValue -ne 0) { throw ('TypeScancodes failed with ReturnValue=' + $r.ReturnValue) }\n"
                "Write-Output ('RC=' + $r.ReturnValue + ' CHUNK=' + %I + '/' + %N)\n"
            ).replace("%I", str(i + 1)).replace("%N", str(len(chunks)))
            script = _KEYBOARD_SCRIPT_TMPL.replace("%NS%", _WMI_NS).replace(
                "%GUID%", ref.id
            ).replace("%CALL%", call)
            result = _run(cfg, script.strip(), timeout_s=90, timing=timing)
            _check_rc(result, f"console scancodes chunk {i + 1}/{len(chunks)}")
            sent += len(chunk)
            if i < len(chunks) - 1:
                time.sleep(0.02)  # pacing: let the Hyper-V input buffer drain
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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    head = _head_resolution(cfg, ref.id, timing)
    hx, hy = _scale_to_head(x, y, frame_width, frame_height, head)
    return _mouse_op(cfg, ref, f"move to ({hx},{hy})",
                     "SetAbsolutePosition",
                     f"@{{ HorizontalPosition = {hx}; VerticalPosition = {hy} }}",
                     extra={"head_x": hx, "head_y": hy}, timing=timing)


def click(
    cfg: Config, vm_name: str = "", x: int = 0, y: int = 0, frame_width: int = 0,
    frame_height: int = 0, button: int = 1, vm_id: str = "",
) -> dict:
    policy.require_category(cfg, "console_input", f"click on '{vm_name}' console")
    if button not in (1, 2):
        raise ValueError("button must be 1 (left) or 2 (right)")
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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    head = _head_resolution(cfg, ref.id, timing)
    if x or y:
        hx, hy = _scale_to_head(x, y, frame_width, frame_height, head)
        move_call = (
            "$r0 = Invoke-CimMethod -InputObject $m -MethodName SetAbsolutePosition "
            "-ErrorAction Stop -Arguments @{ HorizontalPosition = " + str(hx) +
            "; VerticalPosition = " + str(hy) + " }\n"
            "    if ($r0.ReturnValue -ne 0) { throw ('SetAbsolutePosition failed with ReturnValue=' + $r0.ReturnValue) }\n"
            "    "
        )
        extra = {"head_x": hx, "head_y": hy}
    else:
        move_call = ""
        extra = {}
    call = (
        move_call
        + "$r = Invoke-CimMethod -InputObject $m -MethodName ClickButton "
        + "-ErrorAction Stop -Arguments @{ ButtonIndex = " + str(button) + " }\n"
        + "    if ($r.ReturnValue -ne 0) { throw ('ClickButton failed with ReturnValue=' + $r.ReturnValue) }\n"
        + "    Write-Output ('RC=' + $r.ReturnValue)\n"
    )
    out = _mouse_op(cfg, ref, f"click button {button}", call=call, extra=extra, timing=timing)
    return out


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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    return _mouse_op(
        cfg, ref, f"button {button} {'down' if is_down else 'up'}",
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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    return _mouse_op(cfg, ref, f"scroll {delta}",
                     "SetScrollPosition", f"@{{ ScrollPositionDelta = {int(delta)} }}",
                     timing=timing)


def _mouse_op(
    cfg: Config,
    ref: vmident.VMRef,
    detail: str,
    method: str | None = None,
    args_literal: str = "",
    call: str | None = None,
    extra: dict | None = None,
    timing: _PsTiming | None = None,
) -> dict:
    if call is None:
        assert method is not None
        call = (
            "$r = Invoke-CimMethod -InputObject $m -MethodName " + method + " "
            "-ErrorAction Stop -Arguments " + args_literal + "\n"
            "    if ($r.ReturnValue -ne 0) { throw ('" + method + " failed with ReturnValue=' + $r.ReturnValue) }\n"
            "    Write-Output ('RC=' + $r.ReturnValue)\n"
        )
    script = (
        _MOUSE_FOR_VM_SCRIPT.replace("%NS%", _WMI_NS)
        .replace("%GUID%", ref.id)
        .replace("%CALL%", call)
    )
    with _input_lock(ref):
        result = _run(cfg, script.strip(), timeout_s=90, timing=timing)
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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    # On the WMI transport the deadline is enforced BETWEEN polls (a single
    # in-flight COM capture is not interruptible; the PowerShell transport's
    # child process is killed at timeout_s + 15). See README console-transport.
    max_polls = math.ceil(timeout_s / interval_s)
    script = (
        _WAIT_FRAME_SCRIPT_TMPL.replace("%NS%", _WMI_NS)
        .replace("%GUID%", ref.id)
        .replace("%TIMEOUT_S%", str(int(timeout_s)))
        .replace("%MAX_POLLS%", str(max_polls))
        .replace("%W%", str(width))
        .replace("%H%", str(height))
        .replace("%INTERVAL_MS%", str(interval_s * 1000))
        .replace("%BASELINE%", baseline_hash)
    )
    started = time.monotonic()
    result = _run(cfg, script.strip(), timeout_s=int(timeout_s) + 15, timing=timing)
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
    ref = _resolve_ps(cfg, vm_name, vm_id, timing)
    guid = ref.id
    frames: list[dict] = []
    images: list = []
    prev_raw: bytes | None = None
    started = time.monotonic()
    for i in range(count):
        raw = _capture_raw(cfg, guid, width, height, timing)
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
