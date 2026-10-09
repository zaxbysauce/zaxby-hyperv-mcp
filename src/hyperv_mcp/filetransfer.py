r"""Guest file transfer via PowerShell Direct: put/get/read_file/list_dir.

Safety and integrity properties:
  - Every path passes host-side policy canonicalization (guest paths are
    compared PURELY LEXICALLY against their spelling — the host never
    resolves guest junctions) AND an in-guest canonical-root assertion
    ([IO.Path]::GetFullPath + case-insensitive prefix check) that walks
    every existing path component STRICTLY BELOW the matched configured
    root and denies reparse points there — a junction planted inside an
    allowed root cannot be used to escape the boundary. Reparse points at
    or above the configured root are the operator's own spelling of the
    root and are not walked.
  - put re-runs the in-guest assertion immediately before its final
    Move-Item; get's assertion is the statement immediately before the
    -FromSession copy. The irreducible window in each case is one
    statement boundary, and the per-transfer staging name is an
    unguessable uuid (an adversary cannot pre-plant it).
  - All file cmdlets use -LiteralPath (wildcards inert) except the guest
    parent-dir creation, where New-Item has no -LiteralPath and -Path was
    probed to treat brackets literally on PS 5.1.
  - put/get stage to a sibling temp file unique per transfer and Move-Item
    -Force into place; failed copy/move stages clean the staging file in
    the script's own catch. A host TIMEOUT kills the script before that
    catch runs: get removes its host-side staging file from Python; put
    sends one short best-effort cleanup (a dead guest can still leave the
    staged file behind — reported here, not hidden).
  - put/get refuse a destination spelled exactly like a configured root
    (the staging sibling would land outside the boundary) and refuse an
    existing directory destination (classified "invalid", no staged
    orphan inside the container).
  - When verification is on, staged content is hashed BEFORE the move — a
    mismatch aborts with error_class "integrity" and never replaces the
    destination.
  - byte counts come from Get-Item lengths, never from stdout text parsing.
"""

from __future__ import annotations

import json
import os
import secrets
from uuid import uuid4

from . import policy, pswindows, vmident, vmlocks
from .config import Config
from .credentials import CredentialSet
from .guestexec import psdirect_prefix, vm_target_preamble

_STAGING_SUFFIX = ".mcptmp"


def _staging_path(dest: str) -> str:
    r"""Temp path in the destination's OWN directory, unique per transfer.

    Sibling-of-destination (not dest + suffix) keeps the staging component
    at a fixed 39 chars (uuid4 hex 32 + suffix 7) regardless of how long
    the destination name is — appending to the full destination name would
    push a legal 216-char component past NTFS's 255-char component limit
    and fail the transfer. The uuid4 name is unguessable, so no adversary
    can pre-plant a reparse point under it.
    """
    return os.path.join(os.path.dirname(dest), f"{uuid4().hex}{_STAGING_SUFFIX}")


def _failure_class(detail: str) -> str:
    """Classify a PowerShell failure text for the transfer envelope.

    Integrity text first (preserves the pre-existing SHA-256 mapping), then
    in-guest policy denials, then in-guest input validation; everything
    else is transport.
    """
    if "SHA-256 mismatch" in detail:
        return "integrity"
    if "policy:" in detail:
        return "policy"
    if "invalid destination" in detail:
        return "invalid"
    return "transport"


def _guest_root_assertion(path_literal: str, roots: list[str], category: str) -> str:
    r"""PS fragment that fails closed unless the canonical guest path is
    inside one of the canonical configured roots, re-walking every existing
    component strictly below the matched root for reparse points.

    Empty when no roots are effective (unrestricted mode — the caller
    passes [] there — or nothing configured) so the open path stays usable.
    """
    if not roots:
        return ""
    norm_path = policy.canonicalize_windows_path(path_literal, resolve=False).normalized
    norm_roots = [
        policy.canonicalize_windows_path(r, resolve=False).normalized for r in roots
    ]
    roots_json = json.dumps(norm_roots)
    b64 = pswindows.utf8_b64(roots_json)
    return f"""
$policyRaw = {pswindows.ps_quote(norm_path)}
try {{
    $policyPath = [System.IO.Path]::GetFullPath($policyRaw)
}} catch {{
    # PS 5.1 GetFullPath throws on long (>260) paths; the host already
    # accepted this spelling, so fail closed here as a policy denial
    # rather than surfacing the throw as a transport error.
    throw 'policy: guest {category} denied (path cannot be canonicalized in guest)'
}}
$policyRoots = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}')) | ConvertFrom-Json
$policyOk = $false
$policyWalk = $null
$policyPp = $policyPath.TrimEnd('\\') + '\\'
foreach ($r in $policyRoots) {{
    # TrimEnd then re-add the separator so drive roots ("C:\\") and exact
    # roots ("C:\\Temp") both behave; TrimEnd('\\') on "C:\\" yields "C:".
    $policyRc = [System.IO.Path]::GetFullPath($r).TrimEnd('\\') + '\\'
    if ($policyPp.StartsWith($policyRc, [System.StringComparison]::OrdinalIgnoreCase)) {{
        $policyOk = $true
        $policyRcTrim = $policyRc.TrimEnd('\\')
        # The LONGEST matching root anchors the reparse walk: it is the
        # most specific spelling of the boundary, so a reparse at a
        # shallower root is the operator's own choice (documented contract:
        # only components strictly below the matched root are walked).
        if ($null -eq $policyWalk -or $policyRcTrim.Length -gt $policyWalk.Length) {{
            $policyWalk = $policyRcTrim
        }}
    }}
}}
if (-not $policyOk) {{ throw 'policy: guest {category} denied (path outside configured roots)' }}
# Deny reparse points below the matched root along the path. Components
# that do not exist yet are legal (put creates parents after this runs,
# and a missing component cannot be a reparse point). Any Get-Item failure
# OTHER than "item does not exist" (missing drive, access denied, ...)
# fails closed: an inspection error must never count as "no reparse
# here" — that would be a fail-open walk.
$policyRemain = $policyPath.TrimEnd('\\').Substring($policyWalk.Length)
$policyAcc = $policyWalk + '\\'
foreach ($policyComp in $policyRemain.Trim('\\').Split('\\')) {{
    if ($policyComp -eq '') {{ continue }}
    $policyAcc = $policyAcc.TrimEnd('\\') + '\\' + $policyComp
    $policyErrs = $null
    $policyItem = Get-Item -LiteralPath $policyAcc -Force -ErrorAction SilentlyContinue -ErrorVariable policyErrs
    if ($policyErrs) {{
        $policyMissing = $false
        foreach ($policyE in $policyErrs) {{
            if ($policyE.Exception -is [System.Management.Automation.ItemNotFoundException]) {{
                $policyMissing = $true
            }}
        }}
        if (-not $policyMissing) {{ throw 'policy: guest {category} denied (cannot inspect path component)' }}
    }}
    if ($policyItem -and ($policyItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {{
        throw 'policy: guest {category} denied (reparse point in path below root)'
    }}
}}
"""


def _effective_guest_roots(cfg: Config, key: str) -> list[str]:
    """Roots for the in-guest assertion; empty in unrestricted mode.

    unrestricted=True disables every host-side policy check, so the guest
    assertion must not contradict it by still denying host-allowed paths
    (policy.py: "unrestricted=True -> every check passes").
    """
    if cfg.unrestricted:
        return []
    return list(getattr(cfg, key))


def _guest_assert_block(fragment: str) -> str:
    """Wrap the assertion fragment in its terminating in-guest invocation.

    Shared by put and get so both build the exact same wrapper — a remote
    `throw` only terminates the transfer when the wrapper carries
    -ErrorAction Stop.
    """
    if not fragment:
        return ""
    return (
        "Invoke-Command -Session $s -ScriptBlock {\n"
        + fragment
        + "\n} -ErrorAction Stop\n"
    )


def _deny_root_destination(cfg: Config, cp: policy.CanonicalPath, key: str, category: str) -> None:
    """Deny a write destination spelled exactly like a configured root.

    The staged sibling lives in dirname(dest); at a root that directory is
    OUTSIDE the boundary, so the transfer must refuse before staging
    anything.
    """
    if cfg.unrestricted:
        return
    dest = cp.normalized.replace("/", "\\").casefold().rstrip("\\")
    for root in getattr(cfg, key):
        try:
            rr = policy.canonicalize_windows_path(root, resolve=False).normalized
        except policy.PolicyDenied:
            continue
        if rr.replace("/", "\\").casefold().rstrip("\\") == dest:
            raise policy.PolicyDenied(category, "destination equals a configured root")


def _session_body(cred: CredentialSet, vm_id: str, script_body: str, cfg=None) -> str:
    """GUID-native session wrapper: $vmTarget preamble, no name resolution."""
    return f"""
{psdirect_prefix(cred, cfg)}
{vm_target_preamble(vm_id)}
$s = New-PSSession -VMId $vmTarget -Credential $cred -ErrorAction Stop
try {{
{script_body}
}} finally {{
    Remove-PSSession $s -ErrorAction SilentlyContinue
}}
"""


def _run(cfg: Config, script: str, *, timeout_s: float | None = None, stdin_b64: str | None = None):
    """filetransfer's PowerShell choke (issue #43): composes the remote hop
    from the CALLER's cfg before spawning; identity in local mode."""
    script, stdin = pswindows.compose_remote(
        cfg, script,
        payload_lines=1 if stdin_b64 is not None else 0,
        stdin_b64=stdin_b64,
    )
    if stdin is None:
        return pswindows.run_ps(script, timeout_s=timeout_s)
    return pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=stdin)


# Per-chunk size for remote-mode byte crossing: safely under the default
# ~500 KiB WS-Man MaxEnvelopeSizeKB. Remote put/get trade Copy-Item
# -ToSession's single-stream for per-chunk round trips (README documents the
# performance caveat); local mode is untouched.
_CHUNK_B64_CHARS = 262144


def _hop(cfg: Config) -> str:
    """'Invoke-Command -ComputerName <host> [-Credential $__hostcred]' for a
    single remote leg inside a remote-mode transfer script (empty local)."""
    host = pswindows.hyperv_host(cfg)
    if not host:
        return ""
    args = f"-ComputerName {pswindows.ps_quote(host)}"
    return "Invoke-Command " + args + " -Credential $__hostcred"



def _guest_cred_lines(cred: CredentialSet) -> str:
    """Remote-block variant of psdirect_prefix: consumes the forwarded $__p0
    parameter instead of reading local stdin (psdirect_prefix(cred, cfg))."""
    return "\n".join([
        "$secText = [System.Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String($__p0))",
        "$sec = $secText | ConvertTo-SecureString -AsPlainText -Force",
        f"$gcred = [System.Management.Automation.PSCredential]::new("
        f"{pswindows.ps_quote(cred.username)}, $sec)",
        "$secText = $null; $sec = $null",
    ])


def _cleanup_guest_staged(vm_id: str, staged_raw: str, cred: CredentialSet, cfg=None) -> None:
    """Best-effort removal of a guest staged file after a host timeout.

    The timeout kill terminates the transfer script before its own catch
    cleanup runs; this follow-up gets a short timeout and its result is
    ignored — a guest that stays unreachable keeps the staged file (see
    the module docstring). Addressed by the pre-resolved GUID.
    """
    try:
        _run(
            cfg if cfg is not None else Config(),
            _session_body(
                cred,
                vm_id,
                "Remove-Item -LiteralPath "
                + pswindows.ps_quote(staged_raw)
                + " -Force -ErrorAction SilentlyContinue",
                cfg,
            ).strip(),
            timeout_s=30,
            stdin_b64=pswindows.utf8_b64(cred.password),
        )
    except Exception:  # noqa: BLE001 - cleanup is best-effort by design
        pass


def _makedirs_tracked(path: str) -> list[str]:
    """Create path (like makedirs) and return the directories this call
    created, leaf first, for pruning if the transfer then fails."""
    missing: list[str] = []
    probe = path
    while probe and not os.path.isdir(probe):
        missing.append(probe)
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    os.makedirs(path, exist_ok=True)
    return missing


def _cleanup_failed_get(staged_raw: str, created_dirs: list[str]) -> None:
    """Remove the host staged file, then prune directories this call
    created (leaf first; non-empty/pre-existing dirs rmdir-refuse and are
    left alone)."""
    try:
        os.remove(staged_raw)
    except OSError:
        pass
    for d in created_dirs:
        try:
            os.rmdir(d)
        except OSError:
            pass


def _remote_put_script(
    cfg: Config,
    cred: CredentialSet,
    vm_id: str,
    lp: str,
    rp: str,
    staged: str,
    staged_raw: str,
    fragment: str,
    assert_block: str,
    do_verify: bool,
) -> tuple[str, str | None]:
    """Remote-mode guest_put script + composed stdin (explicit ownership).

    Local legs (source hash/size/read) run on the MCP machine; the file
    crosses the WS-Man hop in bounded base64 chunks (each its own
    Invoke-Command, under MaxEnvelopeSizeKB); a final remote leg creates the
    PS-Direct session ON the Hyper-V host and runs the same staged-copy /
    verify / move semantics as the local body. D1 pin ordering: the local
    Get-FileHash precedes the first -ComputerName leg; New-PSSession -VMId
    follows it.
    """
    hop = _hop(cfg)
    prelude, stdin = pswindows.remote_prelude(
        cfg, payload_lines=1, stdin_b64=pswindows.utf8_b64(cred.password)
    )
    tag = secrets.token_hex(8)
    n_b64 = f"hyperv-mcp-put-{tag}.b64"
    n_bin = f"hyperv-mcp-put-{tag}.bin"
    local_hash = (
        "$shaLocal = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash"
        if do_verify else "$shaLocal = $null"
    )
    verify_move = f"""
        $shaStaged = Invoke-Command -Session $s -ScriptBlock {{ param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }} -ArgumentList $stagedGuest -ErrorAction Stop
        if ($shaLocal -and ($shaLocal -ne $shaStaged)) {{ throw 'SHA-256 mismatch (staged copy differs from source)' }}
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged, $final)
            {fragment.rstrip()}
            Move-Item -LiteralPath $staged -Destination $final -Force -ErrorAction Stop
        }} -ArgumentList $stagedGuest, $final -ErrorAction Stop
        $shaRemote = $shaStaged
""" if do_verify else """
        $shaRemote = $null
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged, $final)
            {fragment.rstrip()}
            Move-Item -LiteralPath $staged -Destination $final -Force -ErrorAction Stop
        }} -ArgumentList $stagedGuest, $final -ErrorAction Stop
"""
    return f"""{prelude}$src = {lp}
{local_hash}
$bytesLocal = (Get-Item -LiteralPath $src).Length
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($src))
$rsB64Name = '{n_b64}'
$rsBinName = '{n_bin}'
$pos = 0
while ($pos -lt $b64.Length) {{
    $take = [Math]::Min({_CHUNK_B64_CHARS}, $b64.Length - $pos)
    $chunk = $b64.Substring($pos, $take)
    {hop} -ScriptBlock {{
        param($n, $c)
        $p = Join-Path ([IO.Path]::GetTempPath()) $n
        [IO.File]::AppendAllText($p, $c)
    }} -ArgumentList $rsB64Name, $chunk
    $pos += $take
}}
$__put = {hop} -ScriptBlock {{
    param($__p0, $nB64, $nBin, $final, $stagedGuest, $shaLocal, $bytesLocal)
{_guest_cred_lines(cred)}
    $vmTarget = '{vm_id}'
    $s = New-PSSession -VMId $vmTarget -Credential $gcred -ErrorAction Stop
    $rb64 = $null; $rbin = $null
    try {{
        $rb64 = Join-Path ([IO.Path]::GetTempPath()) $nB64
        $rbin = Join-Path ([IO.Path]::GetTempPath()) $nBin
        [IO.File]::WriteAllBytes($rbin, [Convert]::FromBase64String([IO.File]::ReadAllText($rb64)))
        $dir = Split-Path -Path $final -Parent
        Invoke-Command -Session $s -ScriptBlock {{
            param($d, $dest)
            if (Test-Path -LiteralPath $dest -PathType Container) {{
                throw "invalid destination: $dest is an existing directory"
            }}
            if ($d -and -not (Test-Path -LiteralPath $d)) {{ New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }}
        }} -ArgumentList $dir, $final -ErrorAction Stop
{assert_block}        Copy-Item -ToSession $s -LiteralPath $rbin -Destination $stagedGuest -Force -ErrorAction Stop
{verify_move}        $bytesRemote = Invoke-Command -Session $s -ScriptBlock {{ param($p) (Get-Item -LiteralPath $p).Length }} -ArgumentList $final -ErrorAction Stop
        [PSCustomObject]@{{
            ok = $true
            bytes_copied = $bytesRemote
            bytes_local = $bytesLocal
            bytes_remote = $bytesRemote
            sha256_local = $shaLocal
            sha256_remote = $shaRemote
        }} | ConvertTo-Json -Compress
    }} catch {{
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged) Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }} -ArgumentList $stagedGuest -ErrorAction SilentlyContinue
        throw
    }} finally {{
        Remove-PSSession $s -ErrorAction SilentlyContinue
        if ($rb64) {{ Remove-Item -LiteralPath $rb64 -Force -ErrorAction SilentlyContinue }}
        if ($rbin) {{ Remove-Item -LiteralPath $rbin -Force -ErrorAction SilentlyContinue }}
    }}
}} -ArgumentList $__p0, $rsB64Name, $rsBinName, {rp}, {staged}, $shaLocal, $bytesLocal
$__put
""", stdin


def _remote_get_script(
    cfg: Config,
    cred: CredentialSet,
    vm_id: str,
    rp: str,
    lp: str,
    staged: str,
    staged_raw: str,
    fragment: str,
    assert_block: str,
    do_verify: bool,
) -> tuple[str, str | None]:
    """Remote-mode guest_get script + composed stdin (explicit ownership).

    The local verify scriptblock (destination write + hash + move) is
    DEFINED before the hop so the MCP-machine legs stay textually local; the
    first remote leg creates the PS-Direct session ON the Hyper-V host and
    pulls to remote staging; a chunked loop reads the staging file back in
    bounded base64 ranges; the local verify block then runs on the received
    bytes. Same staged-then-move semantics as the local body.
    """
    hop = _hop(cfg)
    prelude, stdin = pswindows.remote_prelude(
        cfg, payload_lines=1, stdin_b64=pswindows.utf8_b64(cred.password)
    )
    tag = secrets.token_hex(8)
    n_bin = f"hyperv-mcp-get-{tag}.bin"
    local_verify = (
        "$__verifyGet = {\n"
        "    param($stagedPath, $final, $b64, $shaExp)\n"
        "    [IO.File]::WriteAllBytes($stagedPath, [Convert]::FromBase64String($b64))\n"
        "    $sha = (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash\n"
        "    if ($shaExp -and ($sha -ne $shaExp)) { throw 'SHA-256 mismatch (received bytes differ from guest source)' }\n"
        "    Move-Item -LiteralPath $stagedPath -Destination $final -Force -ErrorAction Stop\n"
        "}\n"
        if do_verify else
        "$__verifyGet = {\n"
        "    param($stagedPath, $final, $b64, $shaExp)\n"
        "    [IO.File]::WriteAllBytes($stagedPath, [Convert]::FromBase64String($b64))\n"
        "    Move-Item -LiteralPath $stagedPath -Destination $final -Force -ErrorAction Stop\n"
        "}\n"
    )
    remote_sha = (
        "        $shaRemote = Invoke-Command -Session $s -ScriptBlock "
        "{ param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } "
        "-ArgumentList $src -ErrorAction Stop\n"
        if do_verify else "        $shaRemote = $null\n"
    )
    final_verify = (
        f"& $__verifyGet {staged} {lp} $outB64 $shaRemote\n"
        "$shaLocal = $shaRemote\n"
        if do_verify else
        f"& $__verifyGet {staged} {lp} $outB64 $null\n"
        "$shaLocal = $null\n"
    )
    return f"""{prelude}{local_verify}$src = {rp}
$__get = {hop} -ScriptBlock {{
    param($__p0, $nBin, $src, $stagedGuest)
{_guest_cred_lines(cred)}
    $vmTarget = '{vm_id}'
    $s = New-PSSession -VMId $vmTarget -Credential $gcred -ErrorAction Stop
    $rbin = $null
    try {{
        $rbin = Join-Path ([IO.Path]::GetTempPath()) $nBin
{assert_block}        Copy-Item -FromSession $s -LiteralPath $src -Destination $rbin -Force -ErrorAction Stop
{remote_sha}        $bytesRemote = Invoke-Command -Session $s -ScriptBlock {{ param($p) (Get-Item -LiteralPath $p).Length }} -ArgumentList $src -ErrorAction Stop
        $len = (Get-Item -LiteralPath $rbin).Length
        [PSCustomObject]@{{ len = $len; bytes_remote = $bytesRemote; sha_remote = $shaRemote }} | ConvertTo-Json -Compress
    }} catch {{
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged) Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }} -ArgumentList $stagedGuest -ErrorAction SilentlyContinue
        throw
    }} finally {{
        Remove-PSSession $s -ErrorAction SilentlyContinue
        if ($rbin) {{ Remove-Item -LiteralPath $rbin -Force -ErrorAction SilentlyContinue }}
    }}
}} -ArgumentList $__p0, '{n_bin}', {rp}, {staged}
$len = $__get.len
$bytesRemote = $__get.bytes_remote
$shaRemote = $__get.sha_remote
$outB64 = ''
$off = 0
while ($off -lt $len) {{
    $take = [Math]::Min({_CHUNK_B64_CHARS}, $len - $off)
    $outB64 += {hop} -ScriptBlock {{
        param($n, $o, $l)
        $p = Join-Path ([IO.Path]::GetTempPath()) $n
        $fs = [IO.File]::OpenRead($p)
        try {{
            $buf = New-Object byte[] $l
            [void]$fs.Read($buf, 0, $l)
            [Convert]::ToBase64String($buf)
        }} finally {{ $fs.Dispose() }}
    }} -ArgumentList '{n_bin}', $off, $take
    $off += $take
}}
{final_verify}$bytesLocal = (Get-Item -LiteralPath {lp}).Length
[PSCustomObject]@{{
    ok = $true
    bytes_copied = $bytesLocal
    bytes_local = $bytesLocal
    bytes_remote = $bytesRemote
    sha256_local = $shaLocal
    sha256_remote = $shaRemote
}} | ConvertTo-Json -Compress
""", stdin


def _run_transfer(
    cfg: Config,
    vm_id: str,
    body: str,
    cred: CredentialSet,
    timeout_s: int = 300,
    *,
    composed_script: str | None = None,
    composed_stdin: str | None = None,
) -> dict:
    """Run one transfer script.

    composed_script is the remote-mode transfer script built by the put/get
    builders themselves (explicit composition ownership): the local-FS legs
    stay on the MCP machine while each session/chunk leg carries its own
    -ComputerName hop, so no outer wrap is applied here. Local mode passes
    no composed_script and keeps the historic byte-identical body.
    """
    if composed_script is not None:
        script: str = composed_script
        stdin: str | None = composed_stdin
    else:
        script, stdin = pswindows.compose_remote(
            cfg,
            _session_body(cred, vm_id, body, cfg).strip(),
            payload_lines=1,
            stdin_b64=pswindows.utf8_b64(cred.password),
        )
    result = pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=stdin)
    if result.timed_out:
        return {"ok": False, "error": f"host timeout after {timeout_s}s; transfer aborted", "error_class": "timeout"}
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        return {"ok": False, "error": detail, "error_class": _failure_class(detail)}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"result JSON parse failed: {exc} | raw: {result.stdout[:200]!r}", "error_class": "parse"}


def guest_put(
    cfg: Config,
    vm_name: str = "",
    local_path: str = "",
    remote_path: str = "",
    *,
    confirm: bool = False,
    verify: bool | None = None,
    cred: CredentialSet | None = None,
    vm_id: str = "",
) -> dict:
    if (not vm_name and not vm_id) or not local_path or not remote_path:
        raise ValueError("vm_name (or vm_id), local_path, and remote_path are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.check_host_read(cfg, local_path)
    cpw = policy.check_guest_write(cfg, remote_path)
    _deny_root_destination(cfg, cpw, "guest_write_roots", "guest write")
    policy.require_destructive(cfg, "guest_write", confirm, f"write '{remote_path}' on '{vm_name or vm_id}'")
    if not os.path.isfile(local_path):
        return {"ok": False, "error": f"local source not found: {local_path}", "error_class": "not_found"}
    # Resolve AFTER the cheap host-side input/policy checks (no PowerShell
    # spawns on bad input) and BEFORE the lock: the lock key and the acted-on
    # VM are then the same identity even mid-rename.
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)

    do_verify = cfg.verify_sha256 if verify is None else verify
    # One canonical spelling drives the copy destination AND the assertion:
    # the in-guest check must test exactly the path the copy uses (\\?\
    # prefixes, mixed separators, and trailing separators are already
    # folded host-side, and GetFullPath in the guest sees only a clean
    # absolute path).
    remote = cpw.normalized
    lp = pswindows.ps_quote(os.path.abspath(local_path))
    rp = pswindows.ps_quote(remote)
    staged_raw = _staging_path(remote)
    staged = pswindows.ps_quote(staged_raw)
    fragment = _guest_root_assertion(
        remote, _effective_guest_roots(cfg, "guest_write_roots"), "write"
    )
    assert_block = _guest_assert_block(fragment)
    # Copy AND move both sit inside the try/catch that cleans the staging
    # file, and (when verifying) the STAGED copy is hashed BEFORE the move —
    # a mismatch aborts without ever replacing the destination. The final
    # Move-Item re-runs the root assertion first, closing the window that
    # opens when the assertion runs (before dir creation) — the residual
    # gap is the statement boundary between the re-walk and the move.
    pre_hash = f"""
    $shaLocal = (Get-FileHash -LiteralPath {lp} -Algorithm SHA256).Hash
    try {{
        Copy-Item -ToSession $s -LiteralPath {lp} -Destination {staged} -Force -ErrorAction Stop
        $shaStaged = Invoke-Command -Session $s -ScriptBlock {{ param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }} -ArgumentList {staged} -ErrorAction Stop
        if ($shaLocal -ne $shaStaged) {{ throw 'SHA-256 mismatch (staged copy differs from source)' }}
        Invoke-Command -Session $s -ScriptBlock {{
            param($staged, $final)
            {fragment.rstrip()}
            Move-Item -LiteralPath $staged -Destination $final -Force -ErrorAction Stop
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
            param($staged, $final)
            {fragment.rstrip()}
            Move-Item -LiteralPath $staged -Destination $final -Force -ErrorAction Stop
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
{assert_block}    $dir = Split-Path -Path {rp} -Parent
    Invoke-Command -Session $s -ScriptBlock {{
        param($d, $dest)
        if (Test-Path -LiteralPath $dest -PathType Container) {{
            throw "invalid destination: $dest is an existing directory"
        }}
        if ($d -and -not (Test-Path -LiteralPath $d)) {{ New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }}
    }} -ArgumentList $dir, {rp} -ErrorAction Stop
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
    remote_script, remote_stdin = _remote_put_script(
        cfg, cred, ref.id, lp, rp, staged, staged_raw,
        fragment, assert_block, do_verify,
    ) if pswindows.hyperv_host(cfg) else (None, None)
    with vmlocks.vm_lock(ref.id):
        result = _run_transfer(
            cfg, ref.id, body, cred,
            composed_script=remote_script, composed_stdin=remote_stdin,
        )
        if result.get("error_class") == "timeout":
            _cleanup_guest_staged(ref.id, staged_raw, cred, cfg)
    result["vm_name"] = ref.name
    return result


def guest_get(
    cfg: Config,
    vm_name: str = "",
    remote_path: str = "",
    local_path: str = "",
    *,
    verify: bool | None = None,
    cred: CredentialSet | None = None,
    vm_id: str = "",
) -> dict:
    if (not vm_name and not vm_id) or not remote_path or not local_path:
        raise ValueError("vm_name (or vm_id), remote_path, and local_path are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    cpr = policy.check_guest_read(cfg, remote_path)
    local_abs = os.path.abspath(local_path)
    hcp = policy.check_host_write(cfg, local_abs)
    _deny_root_destination(cfg, hcp, "host_write_roots", "host write")
    if os.path.isdir(local_abs):
        return {
            "ok": False,
            "error": f"invalid destination: {local_path} is a directory",
            "error_class": "invalid",
        }
    # Resolve AFTER the cheap host-side input/policy checks (no PowerShell
    # spawns on bad input) and BEFORE the local dir creation below — mirroring
    # guest_put's ordering: a denied or invalid call must not orphan host
    # directories, because the failure cleanup only runs post-resolve
    # (PRR-010).
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    # Destination dirs must exist before the -FromSession copy, which runs
    # before the guest assertion result is known; directories THIS call
    # creates are pruned again if the transfer fails, so a denied get
    # leaves no empty husks behind.
    created_dirs = _makedirs_tracked(os.path.dirname(local_abs) or ".")

    do_verify = cfg.verify_sha256 if verify is None else verify
    remote = cpr.normalized
    rp = pswindows.ps_quote(remote)
    lp = pswindows.ps_quote(local_abs)
    staged_raw = _staging_path(local_abs)
    staged = pswindows.ps_quote(staged_raw)
    fragment = _guest_root_assertion(
        remote, _effective_guest_roots(cfg, "guest_read_roots"), "read"
    )
    assert_block = _guest_assert_block(fragment)
    # get's assertion is the first statement of the guest body and the
    # -FromSession copy the first operation after it: the residual window
    # is that single statement boundary (the staging file is host-side,
    # inside host_write_roots, so it grants no boundary-crossing write).
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
{assert_block}{pre_hash}
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
    remote_script, remote_stdin = _remote_get_script(
        cfg, cred, ref.id, rp, lp, staged, staged_raw,
        fragment, assert_block, do_verify,
    ) if pswindows.hyperv_host(cfg) else (None, None)
    with vmlocks.vm_lock(ref.id):
        try:
            result = _run_transfer(
                cfg, ref.id, body, cred,
                composed_script=remote_script, composed_stdin=remote_stdin,
            )
        except Exception:
            _cleanup_failed_get(staged_raw, created_dirs)
            raise
    if result.get("ok") is False:
        _cleanup_failed_get(staged_raw, created_dirs)
    result["vm_name"] = ref.name
    return result


def guest_read_file(
    cfg: Config,
    vm_name: str = "",
    remote_path: str = "",
    max_bytes: int = 256 * 1024,
    *,
    cred: CredentialSet | None = None,
    vm_id: str = "",
) -> dict:
    if (not vm_name and not vm_id) or not remote_path:
        raise ValueError("vm_name (or vm_id) and remote_path are required")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be an integer >= 1")
    if cred is None:
        raise ValueError("guest credentials are required")
    cpr = policy.check_guest_read(cfg, remote_path)
    remote = cpr.normalized
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    body = f"""
{psdirect_prefix(cred, cfg)}
{vm_target_preamble(ref.id)}
$r = Invoke-Command -VMId $vmTarget -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($path, $maxb)
    {_guest_root_assertion(remote, _effective_guest_roots(cfg, 'guest_read_roots'), 'read').strip()}
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
}} -ArgumentList {pswindows.ps_quote(remote)}, {int(max_bytes)}
$r | ConvertTo-Json -Compress
"""
    with vmlocks.vm_lock(ref.id):
        result = _run(
            cfg, body.strip(), timeout_s=120, stdin_b64=pswindows.utf8_b64(cred.password)
        )
    if result.timed_out:
        return {"ok": False, "vm_name": ref.name, "error": "host timeout reading guest file", "error_class": "timeout"}
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        return {"ok": False, "vm_name": ref.name, "error": detail, "error_class": _failure_class(detail)}
    try:
        data = json.loads(result.stdout)
        # Explicit keys only: remoting metadata (PSComputerName, RunspaceId)
        # must not leak into the tool result.
        return {
            "ok": True,
            "vm_name": ref.name,
            "content_b64": data.get("content_b64"),
            "bytes_read": data.get("bytes_read"),
            "truncated": data.get("truncated"),
        }
    except json.JSONDecodeError as exc:
        return {"ok": False, "vm_name": ref.name, "error": f"result JSON parse failed: {exc}", "error_class": "parse"}


def guest_list_dir(
    cfg: Config,
    vm_name: str = "",
    remote_path: str = "",
    *,
    cred: CredentialSet | None = None,
    vm_id: str = "",
) -> dict:
    if (not vm_name and not vm_id) or not remote_path:
        raise ValueError("vm_name (or vm_id) and remote_path are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    cpr = policy.check_guest_read(cfg, remote_path)
    remote = cpr.normalized
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    body = f"""
{psdirect_prefix(cred, cfg)}
{vm_target_preamble(ref.id)}
$items = Invoke-Command -VMId $vmTarget -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($path)
    {_guest_root_assertion(remote, _effective_guest_roots(cfg, 'guest_read_roots'), 'read').strip()}
    Get-ChildItem -LiteralPath $path -ErrorAction Stop | ForEach-Object {{
        [PSCustomObject]@{{
            name       = $_.Name
            is_dir     = $_.PSIsContainer
            size_bytes = if ($_.PSIsContainer) {{ 0 }} else {{ $_.Length }}
            modified   = $_.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }}
    }}
}} -ArgumentList {pswindows.ps_quote(remote)}
if ($items) {{ @($items) | ConvertTo-Json -Compress }} else {{ '[]' }}
"""
    with vmlocks.vm_lock(ref.id):
        result = _run(
            cfg, body.strip(), timeout_s=60, stdin_b64=pswindows.utf8_b64(cred.password)
        )
    if result.timed_out:
        return {"ok": False, "vm_name": ref.name, "error": "host timeout listing guest directory", "error_class": "timeout"}
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        return {"ok": False, "vm_name": ref.name, "error": detail, "error_class": _failure_class(detail)}
    try:
        raw = result.stdout.strip()
        if not raw or raw == "null":
            entries = []
        else:
            parsed = json.loads(raw)
            entries = [parsed] if isinstance(parsed, dict) else list(parsed)
        return {"ok": True, "vm_name": ref.name, "entries": entries}
    except json.JSONDecodeError as exc:
        return {"ok": False, "vm_name": ref.name, "error": f"result JSON parse failed: {exc}", "error_class": "parse"}
