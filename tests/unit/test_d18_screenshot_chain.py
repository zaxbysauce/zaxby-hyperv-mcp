"""Acceptance check for issue #81 (trace 75-76-78-81-83-84-collated): the
folded screenshot size chain must advance past a CORRUPT payload.

Length invariant (README + console.py module contract): a
GetVirtualSystemThumbnailImage payload's ImageData is exactly
``4 + W*H*2`` bytes (an opaque 4-byte prefix plus little-endian RGB565
pixels) — any other length is corrupt. The chain's in-script ``try`` commits
a size on ``ReturnValue -eq 0`` ALONE, so a corrupt payload at the first
size becomes the committed ``USED=`` size (no advance, host-side length
error) instead of advancing to the next chain size and erroring only when
EVERY size fails. The wait_frame_change/wait_frame_stable poll scripts
already carry the in-script length throw (console.py:615-617/682-684) — the
chain is the one capture loop without it.

Frozen-docstring wording note: the executed-chain leg below is RED at the
pre-fix tree (the script commits the corrupt first size) and GREEN after the
in-script length guard; the host-side leg is GREEN at both ends (the host
length check must keep refusing a corrupt payload as success).
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# The real transport, captured before any test patches it: the executed-chain
# check runs the emitted script through real PowerShell 5.1.
_REAL_RUN_PS = pswindows.run_ps


class _ScriptCollector:
    """Records every generated script and answers an empty success, so the
    op either completes or fails on parsing AFTER its script exists — either
    way the emitted text is available to execute."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, timeout_s: float | None = None, stdin_b64: str | None = None):
        self.scripts.append(script)
        return pswindows.PSResult(stdout="", returncode=0, duration_ms=0.0)


def _script_for(monkeypatch, op) -> str:
    rec = _ScriptCollector()
    monkeypatch.setattr(pswindows, "run_ps", rec)
    try:
        op()
    except Exception:  # noqa: BLE001 - the script exists before any parse can fail
        pass
    assert rec.scripts, "the operation generated no script"
    return rec.scripts[-1]


# PowerShell functions shadowing the CIM cmdlets the emitted chain script
# calls ([CmdletBinding()] so the script's -ErrorAction Stop binds). The
# shadow serves ReturnValue 0 with a WRONG-LENGTH (100-byte) ImageData for
# the FIRST chain size (the requested 640x480) and a length-correct payload
# for every other size, so the only thing that can make the chain advance is
# the script's own payload-length guard.
_SHADOW = f"""
function Get-CimInstance {{
    [CmdletBinding()]
    param([string]$Namespace, [string]$ClassName, [string]$Filter)
    if ($ClassName -eq 'Msvm_ComputerSystem') {{
        return [PSCustomObject]@{{ Name = '{GUID}'; ElementName = 'vm1' }}
    }}
    if ($ClassName -eq 'Msvm_VirtualSystemManagementService') {{
        return [PSCustomObject]@{{ Name = 'vm-management-service' }}
    }}
    return $null
}}
function Get-CimAssociatedInstance {{
    [CmdletBinding()]
    param($InputObject, [string]$ResultClassName)
    if ($ResultClassName -eq 'Msvm_VideoHead') {{
        return @([PSCustomObject]@{{ CurrentHorizontalResolution = 1024; CurrentVerticalResolution = 768 }})
    }}
    return @()
}}
function Invoke-CimMethod {{
    [CmdletBinding()]
    param($InputObject, [string]$MethodName, $Arguments)
    if ($MethodName -eq 'GetVirtualSystemThumbnailImage') {{
        $w = [int]$Arguments['WidthPixels']; $h = [int]$Arguments['HeightPixels']
        if ($w -eq 640 -and $h -eq 480) {{
            return [PSCustomObject]@{{ ReturnValue = 0; ImageData = (New-Object byte[] 100) }}
        }}
        $want = 4 + $w * $h * 2
        return [PSCustomObject]@{{ ReturnValue = 0; ImageData = (New-Object byte[] $want) }}
    }}
    return [PSCustomObject]@{{ ReturnValue = 0 }}
}}
"""


def test_chain_advances_past_a_corrupt_payload(monkeypatch, unrestricted_cfg):
    """AC12: executed in real PowerShell 5.1 — the emitted folded screenshot
    chain (requested 640x480 -> head 1024x768 -> 320x240) faces a
    ReturnValue-0 capture whose ImageData has the WRONG length at 640x480
    and a correct payload at the next size. The script must ADVANCE: stdout
    carries USED=1024x768 and the emitted payload passes the length
    invariant. RED at base (the chain commits the corrupt first size:
    USED=640x480 + wrong-length payload, no advance), GREEN after the
    in-script length throw in the chain's try."""
    if not os.path.exists(_POWERSHELL):
        pytest.skip("no PowerShell on this host")
    pswindows.init(Config(unrestricted=True))  # the transport gate, as tests do

    script = _script_for(
        monkeypatch, lambda: console.screenshot(unrestricted_cfg, "vm1", 640, 480)
    )
    assert "$sizes" in script and "GetVirtualSystemThumbnailImage" in script

    result = _REAL_RUN_PS(_SHADOW + "\n" + script, timeout_s=120)
    assert result.returncode == 0, (
        f"the chain script failed outright: {result.stderr[:400]!r}"
    )
    lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    used = [ln for ln in lines if ln.startswith("USED=")]
    assert used == ["USED=1024x768"], (
        "AC12: the chain must advance past the corrupt 640x480 payload and "
        f"commit the next size; stdout USED lines: {used!r} (stdout: {result.stdout[:300]!r})"
    )
    payload_line = lines[-1]
    data = json.loads(payload_line)
    raw = base64.b64decode(data["imageDataB64"], validate=True)
    assert len(raw) == 4 + 1024 * 768 * 2, (
        f"AC12: the committed payload must satisfy the length invariant for the "
        f"USED size; got {len(raw)} bytes"
    )


def test_corrupt_payload_at_every_size_is_console_error_never_success(
    monkeypatch, unrestricted_cfg
):
    """AC12 host-side leg: a folded response whose USED= size carries a
    wrong-length payload must surface as ConsoleError — never decoded, never
    returned as a corrupt success — even when every size serves the same
    corrupt shape. GREEN at base and after the fix (the host-side length
    check this pins lives at console.py's screenshot parser)."""
    payload = b"\x00" * 100  # wrong length for every chain size
    body = json.dumps(
        {"returnValue": 0, "imageDataB64": base64.b64encode(payload).decode()}
    )
    fake = pswindows.PSResult(
        stdout=(
            "VMID=" + GUID + "\nHEAD=1024x768\nSIZES=640x480\nUSED=640x480\n" + body
        ),
        returncode=0,
        duration_ms=0.0,
    )
    calls: list[str] = []

    def serve(script, timeout_s=None, stdin_b64=None):
        calls.append(script)
        return fake

    monkeypatch.setattr(pswindows, "run_ps", serve)
    with pytest.raises(ConsoleError, match="length mismatch"):
        console.screenshot(unrestricted_cfg, "vm1", 640, 480)
    assert calls, "the host-side check must run against a real folded response"
