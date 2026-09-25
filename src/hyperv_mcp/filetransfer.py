"""Guest file transfer via PowerShell Direct: put/get/read_file/list_dir.

Safety and integrity properties:
  - Every path passes host-side policy canonicalization (guest paths get the
    same Windows semantics) AND an in-guest canonical-root assertion
    ([IO.Path]::GetFullPath + case-insensitive prefix check) that also denies
    reparse points encountered along the path below the root — a junction
    inside an allowed root cannot be used to escape the boundary.
  - All file cmdlets use -LiteralPath (wildcards inert) except the guest
    parent-dir creation, where New-Item has no -LiteralPath and -Path was
    probed to treat brackets literally on PS 5.1.
  - put/get stage to a sibling temp file and Move-Item -Force into place; the
    try/finally region covers the COPY as well as the move, so any failed
    stage (copy or move) cleans up the staging file.
  - When verification is on, staged content is hashed BEFORE the move — a
    mismatch aborts with error_class "integrity" and never replaces the
    destination.
  - byte counts come from Get-Item lengths, never from stdout text parsing.
"""

from __future__ import annotations

import json
import os

from . import policy, pswindows, vmlocks
from .config import Config
from .credentials import CredentialSet
from .guestexec import psdirect_prefix

_STAGING_SUFFIX = ".mcptmp"


def _guest_root_assertion(path_literal: str, roots: list[str], category: str) -> str:
    """PS fragment that fails closed unless the canonical guest path is
    inside one of the canonical configured roots. Empty when no roots are
    configured (unrestricted mode) so the open path stays usable."""
    if not roots:
        return ""
    roots_json = json.dumps(roots)
    b64 = pswindows.utf8_b64(roots_json)
    return f"""
$policyPath = [System.IO.Path]::GetFullPath({pswindows.ps_quote(path_literal)})
$policyRoots = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}')) | ConvertFrom-Json
$policyOk = $false
foreach ($r in $policyRoots) {{
    # TrimEnd then re-add the separator so drive roots ("C:\\") and exact
    # roots ("C:\\Temp") both behave; TrimEnd('\\') on "C:\\" yields "C:".
    $rc = [System.IO.Path]::GetFullPath($r).TrimEnd('\\') + '\\'
    $pp = $policyPath.TrimEnd('\\') + '\\'
    if ($pp.StartsWith($rc, [System.StringComparison]::OrdinalIgnoreCase)) {{ $policyOk = $true }}
}}
if (-not $policyOk) {{ throw 'policy: guest {category} denied (path outside configured roots)' }}
# Deny reparse points below the root along the path: GetFullPath does not
# resolve junctions/symlinks, so a link inside an allowed root must not be
# traversable through the transfer tools.
$policyParts = $policyPath.Split('\\')
$policyAcc = $policyParts[0] + '\\'
for ($pi = 1; $pi -lt $policyParts.Count; $pi++) {{
    if ($policyParts[$pi] -eq '') {{ continue }}
    $policyAcc = Join-Path $policyAcc $policyParts[$pi]
    $item = Get-Item -LiteralPath $policyAcc -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {{
        throw 'policy: guest {category} denied (reparse point in path inside root)'
    }}
}}
"""


def _session_body(cred: CredentialSet, vm_name: str, script_body: str) -> str:
    n = pswindows.ps_name(vm_name)
    return f"""
{psdirect_prefix(cred)}
$s = New-PSSession -VMName {n} -Credential $cred -ErrorAction Stop
try {{
{script_body}
}} finally {{
    Remove-PSSession $s -ErrorAction SilentlyContinue
}}
"""


def _run_transfer(cfg: Config, vm_name: str, body: str, cred: CredentialSet, timeout_s: int = 300) -> dict:
    result = pswindows.run_ps(
        _session_body(cred, vm_name, body).strip(),
        timeout_s=timeout_s,
        stdin_b64=pswindows.utf8_b64(cred.password),
    )
    if result.timed_out:
        return {"ok": False, "error": f"host timeout after {timeout_s}s; transfer aborted", "error_class": "timeout"}
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        error_class = "integrity" if "SHA-256 mismatch" in detail else "transport"
        return {"ok": False, "error": detail, "error_class": error_class}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"result JSON parse failed: {exc} | raw: {result.stdout[:200]!r}", "error_class": "parse"}


def guest_put(
    cfg: Config,
    vm_name: str,
    local_path: str,
    remote_path: str,
    *,
    confirm: bool = False,
    verify: bool | None = None,
    cred: CredentialSet | None = None,
) -> dict:
    if not vm_name or not local_path or not remote_path:
        raise ValueError("vm_name, local_path, and remote_path are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)
    policy.check_host_read(cfg, local_path)
    policy.check_guest_write(cfg, remote_path)
    policy.require_destructive(cfg, "guest_write", confirm, f"write '{remote_path}' on '{vm_name}'")
    if not os.path.isfile(local_path):
        return {"ok": False, "error": f"local source not found: {local_path}", "error_class": "not_found"}

    do_verify = cfg.verify_sha256 if verify is None else verify
    lp = pswindows.ps_quote(os.path.abspath(local_path))
    rp = pswindows.ps_quote(remote_path)
    staged = pswindows.ps_quote(remote_path + _STAGING_SUFFIX)
    # Copy AND move both sit inside the try/catch that cleans the staging
    # file, and (when verifying) the STAGED copy is hashed BEFORE the move —
    # a mismatch aborts without ever replacing the destination.
    pre_hash = f"""
    $shaLocal = (Get-FileHash -LiteralPath {lp} -Algorithm SHA256).Hash
    try {{
        Copy-Item -ToSession $s -LiteralPath {lp} -Destination {staged} -Force -ErrorAction Stop
        $shaStaged = Invoke-Command -Session $s -ScriptBlock {{ param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }} -ArgumentList {staged} -ErrorAction Stop
        if ($shaLocal -ne $shaStaged) {{ throw 'SHA-256 mismatch (staged copy differs from source)' }}
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged, $final) Move-Item -LiteralPath $staged -Destination $final -Force -ErrorAction Stop
        }} -ArgumentList {staged}, {rp} -ErrorAction Stop
        $shaRemote = $shaStaged
    }} catch {{
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged) Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }} -ArgumentList {staged} -ErrorAction SilentlyContinue
        throw
    }}
""" if do_verify else f"""
    $shaLocal = $null
    try {{
        Copy-Item -ToSession $s -LiteralPath {lp} -Destination {staged} -Force -ErrorAction Stop
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged, $final) Move-Item -LiteralPath $staged -Destination $final -Force -ErrorAction Stop
        }} -ArgumentList {staged}, {rp} -ErrorAction Stop
        $shaRemote = $null
    }} catch {{
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged) Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }} -ArgumentList {staged} -ErrorAction SilentlyContinue
        throw
    }}
"""
    body = f"""
    {_guest_root_assertion(remote_path, cfg.guest_write_roots, 'write')}
    $dir = Split-Path -Path {rp} -Parent
    Invoke-Command -Session $s -ScriptBlock {{
        param($d) if ($d -and -not (Test-Path -LiteralPath $d)) {{ New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }}
    }} -ArgumentList $dir -ErrorAction Stop
{pre_hash}
    $bytesLocal  = (Get-Item -LiteralPath {lp}).Length
    $bytesRemote = Invoke-Command -Session $s -ScriptBlock {{ param($p) (Get-Item -LiteralPath $p).Length }} -ArgumentList {rp} -ErrorAction Stop
    [PSCustomObject]@{{
        ok = $true
        bytes_copied = $bytesRemote
        bytes_local = $bytesLocal
        bytes_remote = $bytesRemote
        sha256_local = $shaLocal
        sha256_remote = $shaRemote
    }} | ConvertTo-Json -Compress
"""
    with vmlocks.vm_lock(vm_name):
        return _run_transfer(cfg, vm_name, body, cred)


def guest_get(
    cfg: Config,
    vm_name: str,
    remote_path: str,
    local_path: str,
    *,
    verify: bool | None = None,
    cred: CredentialSet | None = None,
) -> dict:
    if not vm_name or not remote_path or not local_path:
        raise ValueError("vm_name, remote_path, and local_path are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)
    policy.check_guest_read(cfg, remote_path)
    local_abs = os.path.abspath(local_path)
    policy.check_host_write(cfg, local_abs)
    os.makedirs(os.path.dirname(local_abs) or ".", exist_ok=True)

    do_verify = cfg.verify_sha256 if verify is None else verify
    rp = pswindows.ps_quote(remote_path)
    lp = pswindows.ps_quote(local_abs)
    staged = pswindows.ps_quote(local_abs + _STAGING_SUFFIX)
    # Copy AND move both sit inside the try/catch that cleans the staging
    # file, and (when verifying) the STAGED copy is hashed BEFORE the move.
    pre_hash = f"""
    $shaRemote = $null
    try {{
        Copy-Item -FromSession $s -LiteralPath {rp} -Destination {staged} -Force -ErrorAction Stop
        $shaStaged = (Get-FileHash -LiteralPath {staged} -Algorithm SHA256).Hash
        $shaRemote = Invoke-Command -Session $s -ScriptBlock {{ param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }} -ArgumentList {rp} -ErrorAction Stop
        if ($shaStaged -ne $shaRemote) {{ throw 'SHA-256 mismatch (staged copy differs from guest source)' }}
        Move-Item -LiteralPath {staged} -Destination {lp} -Force -ErrorAction Stop
        $shaLocal = $shaStaged
    }} catch {{
        Remove-Item -LiteralPath {staged} -Force -ErrorAction SilentlyContinue
        throw
    }}
""" if do_verify else f"""
    $shaRemote = $null
    try {{
        Copy-Item -FromSession $s -LiteralPath {rp} -Destination {staged} -Force -ErrorAction Stop
        Move-Item -LiteralPath {staged} -Destination {lp} -Force -ErrorAction Stop
        $shaLocal = $null
    }} catch {{
        Remove-Item -LiteralPath {staged} -Force -ErrorAction SilentlyContinue
        throw
    }}
"""
    body = f"""
    {_guest_root_assertion(remote_path, cfg.guest_read_roots, 'read')}
{pre_hash}
    $bytesRemote = Invoke-Command -Session $s -ScriptBlock {{ param($p) (Get-Item -LiteralPath $p).Length }} -ArgumentList {rp} -ErrorAction Stop
    $bytesLocal  = (Get-Item -LiteralPath {lp}).Length
    [PSCustomObject]@{{
        ok = $true
        bytes_copied = $bytesLocal
        bytes_remote = $bytesRemote
        sha256_local = $shaLocal
        sha256_remote = $shaRemote
    }} | ConvertTo-Json -Compress
"""
    with vmlocks.vm_lock(vm_name):
        return _run_transfer(cfg, vm_name, body, cred)


def guest_read_file(
    cfg: Config,
    vm_name: str,
    remote_path: str,
    max_bytes: int = 256 * 1024,
    *,
    cred: CredentialSet | None = None,
) -> dict:
    if not vm_name or not remote_path:
        raise ValueError("vm_name and remote_path are required")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be an integer >= 1")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)
    policy.check_guest_read(cfg, remote_path)
    n = pswindows.ps_name(vm_name)
    body = f"""
{psdirect_prefix(cred)}
$r = Invoke-Command -VMName {n} -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($path, $maxb)
    {_guest_root_assertion(remote_path, cfg.guest_read_roots, 'read').strip()}
    $stream = [System.IO.File]::Open($path, 'Open', 'Read', 'Read')
    try {{
        $buf = New-Object byte[] ($maxb + 1)
        $read = 0
        while ($read -lt ($maxb + 1)) {{
            $n = $stream.Read($buf, $read, $maxb + 1 - $read)
            if ($n -le 0) {{ break }}
            $read += $n
        }}
    }} finally {{ $stream.Dispose() }}
    $truncated = $read -gt $maxb
    if ($truncated) {{ $read = $maxb }}
    [PSCustomObject]@{{
        content_b64 = [System.Convert]::ToBase64String($buf, 0, $read)
        bytes_read = $read
        truncated = $truncated
    }} | ConvertTo-Json -Compress
}} -ArgumentList {pswindows.ps_quote(remote_path)}, {int(max_bytes)}
$r | ConvertTo-Json -Compress
"""
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(
            body.strip(), timeout_s=120, stdin_b64=pswindows.utf8_b64(cred.password)
        )
    if result.timed_out:
        return {"ok": False, "error": "host timeout reading guest file", "error_class": "timeout"}
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        return {"ok": False, "error": detail, "error_class": "transport"}
    try:
        data = json.loads(result.stdout)
        # Explicit keys only: remoting metadata (PSComputerName, RunspaceId)
        # must not leak into the tool result.
        return {
            "ok": True,
            "content_b64": data.get("content_b64"),
            "bytes_read": data.get("bytes_read"),
            "truncated": data.get("truncated"),
        }
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"result JSON parse failed: {exc}", "error_class": "parse"}


def guest_list_dir(
    cfg: Config,
    vm_name: str,
    remote_path: str,
    *,
    cred: CredentialSet | None = None,
) -> dict:
    if not vm_name or not remote_path:
        raise ValueError("vm_name and remote_path are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)
    policy.check_guest_read(cfg, remote_path)
    n = pswindows.ps_name(vm_name)
    body = f"""
{psdirect_prefix(cred)}
$items = Invoke-Command -VMName {n} -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($path)
    {_guest_root_assertion(remote_path, cfg.guest_read_roots, 'read').strip()}
    Get-ChildItem -LiteralPath $path -ErrorAction Stop | ForEach-Object {{
        [PSCustomObject]@{{
            name       = $_.Name
            is_dir     = $_.PSIsContainer
            size_bytes = if ($_.PSIsContainer) {{ 0 }} else {{ $_.Length }}
            modified   = $_.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }}
    }}
}} -ArgumentList {pswindows.ps_quote(remote_path)}
if ($items) {{ @($items) | ConvertTo-Json -Compress }} else {{ '[]' }}
"""
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(
            body.strip(), timeout_s=60, stdin_b64=pswindows.utf8_b64(cred.password)
        )
    if result.timed_out:
        return {"ok": False, "error": "host timeout listing guest directory", "error_class": "timeout"}
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        return {"ok": False, "error": detail, "error_class": "transport"}
    try:
        raw = result.stdout.strip()
        if not raw or raw == "null":
            entries = []
        else:
            parsed = json.loads(raw)
            entries = [parsed] if isinstance(parsed, dict) else list(parsed)
        return {"ok": True, "entries": entries}
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"result JSON parse failed: {exc}", "error_class": "parse"}
