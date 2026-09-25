"""Real-PS verification of the in-guest policy root assertion fragment.

Pure PowerShell behavior (no Hyper-V): pins the fragment that filetransfer
embeds into guest scripts, including the drive-root and boundary cases the
final critic flagged.
"""

import json

import pytest

from hyperv_mcp import pswindows
from hyperv_mcp.config import Config

BS = chr(92)  # backslash, kept explicit so the generated PS is unambiguous


def _fragment(path: str, roots: list[str]) -> str:
    b64 = pswindows.utf8_b64(json.dumps(roots))
    return (
        "$policyPath = [System.IO.Path]::GetFullPath(" + pswindows.ps_quote(path) + ")\n"
        "$policyRoots = [System.Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String('" + b64 + "')) | ConvertFrom-Json\n"
        "$policyOk = $false\n"
        "foreach ($r in $policyRoots) {\n"
        "    $rc = [System.IO.Path]::GetFullPath($r).TrimEnd(" + pswindows.ps_quote(BS) + ") + " + pswindows.ps_quote(BS) + "\n"
        "    $pp = $policyPath.TrimEnd(" + pswindows.ps_quote(BS) + ") + " + pswindows.ps_quote(BS) + "\n"
        "    if ($pp.StartsWith($rc, [System.StringComparison]::OrdinalIgnoreCase)) { $policyOk = $true }\n"
        "}\n"
        "if ($policyOk) { Write-Output ALLOW } else { Write-Output DENY }\n"
    )


CASES = [
    ("C:\\Windows\\Temp\\f.txt", ["C:\\"], "ALLOW"),                     # drive root
    ("c:\\anything", ["C:\\"], "ALLOW"),                                # case + drive root
    ("C:\\Windows\\Temp", ["C:\\Windows\\Temp"], "ALLOW"),              # exact root
    ("C:\\Windows\\Temp\\sub\\f", ["C:\\Windows\\Temp"], "ALLOW"),      # descendant
    ("C:\\Windows\\System32\\config\\SAM", ["C:\\Windows\\Temp"], "DENY"),
    ("C:\\TempX\\evil", ["C:\\Temp"], "DENY"),                          # boundary: C:\TempX vs C:\Temp
]

pytestmark = pytest.mark.skipif(
    not __import__("os").path.isfile(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    reason="Windows PowerShell not available",
)


@pytest.mark.parametrize("path,roots,expected", CASES)
def test_guest_root_assertion(path, roots, expected):
    pswindows.init(Config())
    result = pswindows.run_ps(_fragment(path, roots), timeout_s=60)
    assert result.ok(), result.stderr
    assert result.stdout.strip() == expected, (path, roots, result.stdout)
