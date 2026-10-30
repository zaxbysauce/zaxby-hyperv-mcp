"""Element-level UI Automation through the in-session guest helper (issue #29).

The helper is a long-lived PowerShell 5.1 process running in the guest's
INTERACTIVE session (per-user AtLogOn task, ``RunLevel Highest``); it hosts
``System.Windows.Automation`` and serves newline-JSON request frames on a
local named pipe. The host reaches the pipe ONLY through PowerShell Direct
(``hyperv_mcp_guestexec.psdirect_prefix`` + ``Invoke-Command -VMId``): the
guest-side client leg (``CLIENT_LEG_SCRIPT``) opens the pipe with a raw
``CreateFileW`` P/Invoke and relays exactly one request frame, so the host
never needs network reach to the guest.

Security model (plan revision 7, fix-wave revisions for PR #109):
- VM identity uses the GUEST namespace, not the host's: provisioning reads
  the guest's ``Win32_ComputerSystemProduct.UUID`` and records it next to
  the helper as ``uuid.txt``; every request's ``target.vm_guid`` carries
  that RECORDED value (empty when the provision-time read failed, which the
  helper refuses -- fail-closed). A helper directory copied to another
  guest therefore refuses to serve. The HELPER enforces vm_guid + user_sid
  + session_id + the per-install nonce on every request; a session-less
  request is refused (``session_unverified``) without any UIA dispatch.
- The response frame must be an object carrying an explicit boolean ``ok``
  and the request's ``id``; a degraded or non-correlating frame is refused
  as ``helper_unavailable`` (never success). The reported
  ``session.helper.sha256`` is compared against the PACKAGED helper bytes
  (``helper.sha256_match``; a mismatch refuses with
  ``helper_integrity_mismatch``).
- The verb allowlist is closed on both ends; caller text is never evaluated
  as code. ``set_value`` payloads ride the framed stdin (line 1: the
  credential password, line 2: the base64 JSON request) — never script
  text, never argv, never error text; the result reports the length set,
  never the value.
- Policy: mutating verbs (invoke/set_value/focus) require
  ``destructive.ui_input``; helper provisioning requires
  ``destructive.ui_provision`` plus ``confirm``. Read verbs need only VM
  policy + guest credentials.
- The supplement's broker: helper registrations are keyed by
  (vm_guid, session_id) and looked up for the CURRENT session only; the
  transport is built PER CALL (a registration never pins a credential).
  Every MUTATING verb consults the #28 actor/lease gate before any
  transport leg; the Electron adapter gate runs on every routed request —
  an adapter must be explicitly requested (``adapter="electron"`` on
  find/inspect) and its capability registered before it is forwarded.
- ``wait_for`` polls in bounded slices so the per-VM lock is held only
  around each transport leg, never across the whole wait.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import threading
import time
import uuid
from typing import Any, cast

from . import auditlog, guestexec, policy, pswindows, vmident
from .credentials import CredentialSet
from .vmlocks import vm_lock

HELPER_VERSION = "1"
VERBS = {"inspect", "find", "invoke", "set_value", "wait_for", "focus",
         "session_state"}
MUTATING_VERBS = {"invoke", "set_value", "focus"}
BASE_CAPABILITIES = {"uia", "msaa"}
ELECTRON_CAPABILITY = "adapter:electron"
_CAPABILITIES = BASE_CAPABILITIES | {ELECTRON_CAPABILITY}
_MAX_SELECTOR_FIELD = 1024
_MAX_VALUE_BYTES = 64 * 1024
_SELECTORS = {
    "automation_id", "name", "name_contains", "control_type", "class_name",
    "window_title", "process_name", "hwnd", "element_id", "index",
}
_ADAPTERS = {"", "electron"}

#: One wait_for slice: the guest polls inside a single pipe request for at
#: most this long, then the host re-slices without holding the VM lock
#: between slices (the console-wait pattern — lock per leg, never across
#: the whole wait).
_WAIT_SLICE_S = 10
_WAIT_POLL_S = 0.25

#: The inspect bounds (PRR-117): ONE clamp for BOTH tree paths — the
#: helper path here and evidence's PS Direct walk (evidence._UIA_MAX_DEPTH
#: / _UIA_MAX_ELEMENTS carry the same numbers). The tool docstrings
#: promise 1..6 / 1..500; the host clamps before the request leaves, and
#: the packaged helper enforces the same ceiling on its side.
INSPECT_MAX_DEPTH = 6
INSPECT_MAX_ELEMENTS = 500


class UiAError(RuntimeError):
    """Base class for element-surface errors (issue #29)."""


class RegistrationMismatch(UiAError):
    """A request target does not match its helper registration (AC19)."""


# ---------------------------------------------------------------------------
# request framing
# ---------------------------------------------------------------------------

def build_request(verb: str, args: dict | None = None,
                  agent_id: str = "") -> dict:
    """Build one helper request frame {id, verb, args, agent_id}.

    The verb set is closed: anything outside ``VERBS`` raises ValueError
    naming the verb, so the pipe can never become a command channel. The
    per-request ``id`` doubles as the replay nonce on the frame; the helper
    echoes it and the host refuses a response whose id does not correlate.
    """
    if verb not in VERBS:
        raise ValueError(
            f"unknown verb: {verb!r} (allowed: {', '.join(sorted(VERBS))})")
    return {
        "id": uuid.uuid4().hex,
        "verb": verb,
        "args": dict(args or {}),
        "agent_id": agent_id or (auditlog.current_agent_id() or ""),
    }


def validate_selector(selector: Any) -> dict:
    """Validate a selector mapping and return a normalized copy.

    Empty (or None) selectors and unknown keys raise ValueError naming
    "selector"; an individual field longer than 1024 characters raises
    ValueError naming the field.
    """
    if not isinstance(selector, dict) or not selector:
        raise ValueError(
            "selector must be a non-empty mapping of UIA properties")
    unknown = set(selector) - _SELECTORS
    if unknown:
        raise ValueError(
            f"unknown selector key(s): {sorted(unknown)} "
            f"(allowed: {', '.join(sorted(_SELECTORS))})")
    for key, value in selector.items():
        if isinstance(value, str) and len(value) > _MAX_SELECTOR_FIELD:
            raise ValueError(f"selector field {key!r} exceeds "
                             f"{_MAX_SELECTOR_FIELD} characters")
    return dict(selector)


def _check_element_op(selector: Any, element_id: Any) -> None:
    """invoke/set_value/focus address exactly one of selector | element_id."""
    if (selector is None) == (element_id is None):
        raise ValueError(
            "address the target by exactly one of selector= or element_id=")


# ---------------------------------------------------------------------------
# transport (PowerShell Direct legs)
# ---------------------------------------------------------------------------

# The leg wrapper needs the VM GUID + credential; the frozen _run_uia_leg
# seam signature carries no ref, so callers bind them through this slot.
# THREAD-LOCAL: tool bodies run concurrently on worker threads and the
# per-VM lock is per-VM, so a module-global would let one VM's leg (and
# its framed credential payload) compose toward another VM's GUID. The
# slot is CLEARED (set to None) after every leg so a pooled worker thread
# never retains a credential past the call that used it.
_LEG = threading.local()

# The per-CALL transport context (cfg, ref, cred). Registrations are
# transport-free (they must never pin a credential), so the broker forward
# path (route -> _pipe_request -> _pipe_forward) rebuilds its transport
# from this thread-local slot, which _verb_request holds for exactly the
# duration of one verb call.
_CALL = threading.local()


def _run_uia_leg(cfg, script: str, *, stdin_b64: str | None = None,
                 timeout_s: int | None = None) -> pswindows.PSResult:
    """The single transport choke point for every UIA host PowerShell leg.

    ``script`` is the INNER guest script; this function composes the PS
    Direct wrapper around it (credential prefix + framed payload line +
    ``Invoke-Command -VMId`` with ``-ArgumentList $enc, $reqEnc``) so the
    frozen recorders capture the plaintext contract while the real
    transport embeds it as ``$enc``. Never routes via
    diagnostics.run_guest_inner: the pooled worker's stdin frame protocol
    cannot carry the second framed payload line, and reusing a pooled
    remoting session for pipe relay legs would couple helper liveness to
    pool lifetime. The leg's VM GUID and credential arrive through the
    thread-local ``_LEG`` slot (the frozen seam signature carries no ref),
    so concurrent calls for different VMs never cross — and the slot is
    cleared in the finally so the credential is not retained on the
    worker thread.
    """
    if timeout_s is None:
        timeout_s = max(30, (15_000 // 1000) + guestexec._GRACE_S)
    try:
        wrapper = _uia_guest_script(
            script, cast(CredentialSet, _LEG.cred), cfg)
        if pswindows.hyperv_host(cfg):
            body, payload = pswindows.compose_remote(
                cfg, wrapper, payload_lines=2 if stdin_b64 else 0,
                stdin_b64=stdin_b64)
            result = pswindows.run_ps(body, timeout_s=timeout_s,
                                      stdin_b64=payload)
        else:
            result = pswindows.run_ps(wrapper, timeout_s=timeout_s,
                                      stdin_b64=stdin_b64)
        pswindows.check_result(result)
        return result
    finally:
        # F18: never retain the leg credential on a pooled worker thread.
        _LEG.guid = None
        _LEG.cred = None


def _uia_guest_script(inner_script: str, cred: CredentialSet,
                      cfg=None) -> str:
    """Wrap an inner guest script for the framed two-line stdin transport.

    Line 1 of stdin is the credential (consumed by psdirect_prefix), line 2
    is the leg's data payload ($reqEnc — the request JSON for pipe legs,
    the helper bytes for the install leg, the autologon password bytes for
    the LSA leg). Local mode reads line 2 from this process's stdin; remote
    mode binds it to the composer's second payload parameter. The inner
    script travels as $enc and executes inside the guest scriptblock with
    both payloads forwarded via -ArgumentList — nothing secret ever lands
    in script text or the -EncodedCommand argv.
    """
    remote = bool(pswindows.hyperv_host(cfg))
    req_line = ("$reqEnc = $__p1" if remote
                else "$reqEnc = [Console]::In.ReadLine()")
    return "\n".join([
        guestexec.psdirect_prefix(cred, cfg),
        req_line,
        "$secRaw = $null",
        guestexec.vm_target_preamble(cast(str, _LEG.guid)),
        "$enc = '" + pswindows.utf8_b64(inner_script) + "'",
        "$out = Invoke-Command -VMId $vmTarget -Credential $cred "
        "-ErrorAction Stop -ScriptBlock {",
        "    param($enc, $reqEnc)",
        inner_script,
        "} -ArgumentList $enc, $reqEnc",
        "$out",
    ])


def _frame_leg(cfg, ref, cred: CredentialSet, inner_script: str,
               payload_b64: str, *, timeout_ms: int = 15000) -> pswindows.PSResult:
    """Frame one leg: two-line stdin + plaintext inner script, transported.

    Line 1 is the credential password (b64), line 2 the leg's data payload
    (b64). The plaintext inner script is what the frozen recorders capture.
    """
    framed = "\n".join([
        pswindows.utf8_b64(cred.password),
        payload_b64,
    ])
    _LEG.guid = ref.id
    _LEG.cred = cred
    return _run_uia_leg(cfg, inner_script, stdin_b64=framed,
                        timeout_s=max(30, timeout_ms // 1000
                                      + guestexec._GRACE_S))


# ---------------------------------------------------------------------------
# guest-side inner scripts
# ---------------------------------------------------------------------------

# The pipe CLIENT leg. The helper's server end is a raw CreateNamedPipeW
# P/Invoke (the .NET Framework PipeOptions value the old server used is
# invalid), so the client opens with the matching raw CreateFileW P/Invoke
# (GENERIC_READ|GENERIC_WRITE, OPEN_EXISTING) and serves the one-line-JSON
# in / one-line-JSON out protocol over WriteFile/ReadFile. The helper
# serves ONE instance, so a concurrent request sees ERROR_PIPE_BUSY (231):
# the client retries a bounded number of times on WaitNamedPipeW with a
# short backoff and throws the distinctive "helper pipe busy" marker the
# host maps to the retryable busy class (F13).
CLIENT_LEG_SCRIPT = r"""$line = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($reqEnc))
Add-Type -Namespace HypervMcp.Uia.Client -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool WaitNamedPipeW(string name, uint timeoutMs);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteFile(IntPtr handle, byte[] buffer, uint count, out uint written, IntPtr overlapped);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadFile(IntPtr handle, byte[] buffer, uint count, out uint read, IntPtr overlapped);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
'@
$pipePath = '\\.\pipe\hyperv-mcp-uia'
$invalid = [IntPtr]::new([Int64]-1)
$handle = $invalid
$sawBusy = $false
foreach ($attempt in 1..8) {
    # 3221225472 = GENERIC_READ|GENERIC_WRITE (0xC0000000); 3 = OPEN_EXISTING
    $handle = [HypervMcp.Uia.Client.Native]::CreateFileW($pipePath, [uint32]3221225472, [uint32]0, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -ne $invalid -and $handle -ne [IntPtr]::Zero) { break }
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($err -ne 231) { throw "hyperv-mcp-uia open failed (Win32 error $err)" }
    $sawBusy = $true
    [void][HypervMcp.Uia.Client.Native]::WaitNamedPipeW($pipePath, [uint32]500)
}
if ($handle -eq $invalid -or $handle -eq [IntPtr]::Zero) {
    if ($sawBusy) { throw 'hyperv-mcp-uia helper pipe busy after repeated attempts' }
    throw 'hyperv-mcp-uia open failed'
}
try {
    $payload = [System.Text.Encoding]::UTF8.GetBytes($line + "`n")
    $written = [uint32]0
    if (-not [HypervMcp.Uia.Client.Native]::WriteFile($handle, $payload, [uint32]$payload.Length, [ref]$written, [IntPtr]::Zero)) { throw 'helper pipe write failed' }
    $chunks = New-Object System.Collections.Generic.List[byte]
    $buffer = New-Object byte[] 4096
    $sawNewline = $false
    while (-not $sawNewline) {
        $read = [uint32]0
        if (-not [HypervMcp.Uia.Client.Native]::ReadFile($handle, $buffer, [uint32]$buffer.Length, [ref]$read, [IntPtr]::Zero)) { throw 'helper pipe read failed' }
        if ($read -eq 0) { break }
        for ($i = 0; $i -lt $read; $i++) {
            if ($buffer[$i] -eq 10) { $sawNewline = $true; break }
            $chunks.Add($buffer[$i])
        }
    }
    $resp = [System.Text.Encoding]::UTF8.GetString($chunks.ToArray())
    if (-not $resp) { throw 'the helper closed the pipe without a response' }
    $resp
} finally { [void][HypervMcp.Uia.Client.Native]::CloseHandle($handle) }"""

_INSTALL_INNER = """$dir = $env:HYPERVMCP_HELPER_DIR
if (Test-Path $dir) {
    # Re-provisioning over a prior install of the SAME versioned dir:
    # the creator-owner default of a fresh ProgramData child means the
    # provisioning identity can always clear its own previous directory.
    Remove-Item -Recurse -Force $dir
}
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$helperPath = Join-Path $dir 'uia_helper.ps1'
[IO.File]::WriteAllBytes($helperPath, [Convert]::FromBase64String($reqEnc))
$sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($helperPath))
[IO.File]::WriteAllText((Join-Path $dir 'sha256.txt'), ([BitConverter]::ToString($sha) -replace '-',''))
[IO.File]::WriteAllText((Join-Path $dir 'version.txt'), '""" + HELPER_VERSION + """')
# uuid.txt records the guest's SMBIOS UUID as read at provision time: the
# helper compares its LIVE UUID against this recorded value (F3). An empty
# record (the provision-time read failed) makes the helper refuse every
# request — fail-closed, never fail-open.
[IO.File]::WriteAllText((Join-Path $dir 'uuid.txt'), [string]$env:HYPERVMCP_HELPER_UUID)
[IO.File]::WriteAllText((Join-Path $dir 'nonce.txt'), [string]$env:HYPERVMCP_HELPER_NONCE)
[PSCustomObject]@{ ok = $true; installed = $true; helper_version = '""" + HELPER_VERSION + """' } | ConvertTo-Json -Compress"""

_AUTOLOGON_INNER = """$ErrorActionPreference = 'Stop'
$pw = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($reqEnc))
Add-Type -Namespace HypervMcp.Uia -Name Lsa -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError=true)] public static extern uint LsaOpenPolicy(IntPtr system, ref LSA_OBJECT_ATTRIBUTES attrs, uint access, out IntPtr policy);
[DllImport("advapi32.dll", CharSet=CharSet.Unicode)] public static extern uint LsaStorePrivateData(IntPtr policy, ref LSA_UNICODE_STRING name, ref LSA_UNICODE_STRING data);
[DllImport("advapi32.dll")] public static extern uint LsaClose(IntPtr policy);
[StructLayout(LayoutKind.Sequential)] public struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
[StructLayout(LayoutKind.Sequential)] public struct LSA_OBJECT_ATTRIBUTES { public uint Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
'@
function ConvertTo-LsaString([string]$s) {
    $u = New-Object HypervMcp.Uia.Lsa+LSA_UNICODE_STRING
    $u.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($s)
    $u.Length = [uint16]($s.Length * 2)
    $u.MaximumLength = [uint16](($s.Length + 1) * 2)
    $u
}
$attrs = New-Object HypervMcp.Uia.Lsa+LSA_OBJECT_ATTRIBUTES
$attrs.Length = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($attrs)
$policyPtr = [IntPtr]::Zero
$openHr = [HypervMcp.Uia.Lsa]::LsaOpenPolicy([IntPtr]::Zero, [ref]$attrs, 0x00000004, [ref]$policyPtr)
if ($openHr -ne 0) { throw "LsaOpenPolicy failed: $openHr" }
try {
    $secret = ConvertTo-LsaString 'DefaultPassword'
    $data = ConvertTo-LsaString $pw
    $storeHr = [HypervMcp.Uia.Lsa]::LsaStorePrivateData($policyPtr, [ref]$secret, [ref]$data)
    if ($storeHr -ne 0) { throw "LsaStorePrivateData failed: $storeHr" }
} finally { [void][HypervMcp.Uia.Lsa]::LsaClose($policyPtr) }
$pw = $null; $data = $null
$ku = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', $true)
if ($null -eq $ku) { throw 'the Winlogon key could not be opened for write' }
try {
    $ku.SetValue('AutoAdminLogon', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
    $ku.SetValue('DefaultUserName', $env:HYPERVMCP_AUTOLOGON_USER, [Microsoft.Win32.RegistryValueKind]::String)
    $ku.SetValue('DefaultDomainName', $env:COMPUTERNAME, [Microsoft.Win32.RegistryValueKind]::String)
    $ku.DeleteValue('DefaultPassword', $false)
} finally { $ku.Close() }
[PSCustomObject]@{ ok = $true; autologon = $true } | ConvertTo-Json -Compress"""

_TASK_INNER = """$ErrorActionPreference = 'Stop'
$user = $env:HYPERVMCP_AUTOLOGON_USER
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File ' + $env:HYPERVMCP_HELPER_DIR + '\\uia_helper.ps1')
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'hyperv-mcp-uia-helper' -Action $action -Principal $principal -Trigger $trigger -Settings $settings -Force | Out-Null
$started = $false
try { $loggedOn = quser 2>$null | Select-String -SimpleMatch $user }
catch { $loggedOn = $null }  # a logged-off guest raises instead of listing
if ($loggedOn) { Start-ScheduledTask -TaskName 'hyperv-mcp-uia-helper'; $started = $true }
[PSCustomObject]@{ ok = $true; task_registered = $true; started = $started } | ConvertTo-Json -Compress"""

# F14: provisioning's inverse. Running before every (re)install, this stops
# the helper's task instance and any surviving helper process (the old
# instance otherwise keeps the fixed-name pipe and the new bytes never
# serve), unregisters the task, and removes EVERY per-provision helper
# directory. The teardown path reuses the same leg before restoring
# Winlogon and deleting the LSA secret.
_RESET_INNER = """$ErrorActionPreference = 'Stop'
$taskName = 'hyperv-mcp-uia-helper'
$stopped = $false
$unregistered = $false
try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; $stopped = $true } catch { }
try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop; $unregistered = $true } catch { }
Get-CimInstance -ClassName Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -match 'uia_helper\\.ps1' } |
    ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch { } }
$root = 'C:\\ProgramData\\hyperv-mcp'
$removed = 0
if (Test-Path -LiteralPath $root) {
    Get-ChildItem -LiteralPath $root -Directory -Filter 'uia-helper-*' -ErrorAction SilentlyContinue |
        ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop; $removed = $removed + 1 } catch { } }
}
[PSCustomObject]@{ ok = $true; task_stopped = $stopped; task_unregistered = $unregistered; directories_removed = $removed } | ConvertTo-Json -Compress"""

# F14: the teardown's Winlogon/LSA restore leg. LsaStorePrivateData with a
# NULL data pointer DELETES the secret; AutoAdminLogon returns to 0 and the
# DefaultUserName/DefaultDomainName values are removed (DeleteValue with
# $false tolerates values a clean image never had).
_TEARDOWN_WINLOGON_INNER = """$ErrorActionPreference = 'Stop'
Add-Type -Namespace HypervMcp.Uia.LsaTeardown -Name Lsa -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError=true)] public static extern uint LsaOpenPolicy(IntPtr system, ref LSA_OBJECT_ATTRIBUTES attrs, uint access, out IntPtr policy);
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint="LsaStorePrivateData")] public static extern uint LsaStorePrivateDataNull(IntPtr policy, ref LSA_UNICODE_STRING name, IntPtr data);
[DllImport("advapi32.dll")] public static extern uint LsaClose(IntPtr policy);
[StructLayout(LayoutKind.Sequential)] public struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
[StructLayout(LayoutKind.Sequential)] public struct LSA_OBJECT_ATTRIBUTES { public uint Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
'@
function ConvertTo-LsaString([string]$s) {
    $u = New-Object HypervMcp.Uia.LsaTeardown.Lsa+LSA_UNICODE_STRING
    $u.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($s)
    $u.Length = [uint16]($s.Length * 2)
    $u.MaximumLength = [uint16](($s.Length + 1) * 2)
    $u
}
$attrs = New-Object HypervMcp.Uia.LsaTeardown.Lsa+LSA_OBJECT_ATTRIBUTES
$attrs.Length = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($attrs)
$policyPtr = [IntPtr]::Zero
$openHr = [HypervMcp.Uia.LsaTeardown.Lsa]::LsaOpenPolicy([IntPtr]::Zero, [ref]$attrs, 0x00000004, [ref]$policyPtr)
if ($openHr -ne 0) { throw "LsaOpenPolicy failed: $openHr" }
try {
    $secret = ConvertTo-LsaString 'DefaultPassword'
    $delHr = [HypervMcp.Uia.LsaTeardown.Lsa]::LsaStorePrivateDataNull($policyPtr, [ref]$secret, [IntPtr]::Zero)
    if ($delHr -ne 0) { throw "LsaStorePrivateData(delete) failed: $delHr" }
} finally { [void][HypervMcp.Uia.LsaTeardown.Lsa]::LsaClose($policyPtr) }
$ku = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', $true)
if ($null -eq $ku) { throw 'the Winlogon key could not be opened for write' }
try {
    $ku.SetValue('AutoAdminLogon', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
    $ku.DeleteValue('DefaultUserName', $false)
    $ku.DeleteValue('DefaultDomainName', $false)
} finally { $ku.Close() }
[PSCustomObject]@{ ok = $true; lsa_secret_deleted = $true; autologon_restored = $true } | ConvertTo-Json -Compress"""

#: Provision-time read of the guest's SMBIOS UUID (F3): the value recorded
#: in uuid.txt and sent as every request's target.vm_guid.
_UUID_READ_CMD = ("(Get-CimInstance -ClassName Win32_ComputerSystemProduct "
                  "-ErrorAction Stop).UUID")

#: The verb-path discovery of a recorded install: the newest per-provision
#: helper directory and the uuid/nonce/version files inside it (F3/F10c).
_UUID_DISCOVERY_CMD = (
    "$d = @(Get-ChildItem -LiteralPath 'C:\\ProgramData\\hyperv-mcp' "
    "-Directory -Filter 'uia-helper-*' -ErrorAction SilentlyContinue | "
    "Sort-Object LastWriteTime -Descending | Select-Object -First 1); "
    "if ($d) { "
    "$f = @{ dir = $d.FullName; uuid = ''; nonce = ''; version = '' }; "
    "foreach ($k in @('uuid','nonce','version')) { "
    "$p = Join-Path $d.FullName ($k + '.txt'); "
    "if (Test-Path -LiteralPath $p) { "
    "$f[$k] = ([IO.File]::ReadAllText($p)).Trim() } }; "
    "$f | ConvertTo-Json -Compress }"
)

_PACKAGED_SHA256: str | None = None


def _packaged_helper_sha256() -> str | None:
    """SHA-256 of the PACKAGED helper bytes (the bytes the host installs).

    The helper self-reports a hash of whatever is on disk; comparing that
    against the packaged bytes (not a second hardcoded constant) is what
    makes the integrity gate meaningful. Cached per process — the package
    data is static for the server's lifetime.
    """
    global _PACKAGED_SHA256
    if _PACKAGED_SHA256 is None:
        try:
            from importlib import resources

            data = (
                resources.files("hyperv_mcp")
                .joinpath("guest")
                .joinpath("uia_helper.ps1")
                .read_bytes()
            )
            _PACKAGED_SHA256 = hashlib.sha256(data).hexdigest()
        except Exception:
            return None
    return _PACKAGED_SHA256


# ---------------------------------------------------------------------------
# discovery seams (quser / LogonUI) — plain PS Direct text legs
# ---------------------------------------------------------------------------

def _ps_guest_text(cfg, ref, cred: CredentialSet, guest_command: str,
                   timeout_s: int = 30) -> str:
    """Run one read-only guest command and return its stdout text.

    The prefix consumes stdin line 1 as the guest credential, so the
    password MUST ride ``stdin_b64`` (F2: the leg used to spawn with no
    stdin, so the credential never arrived and every discovery leg failed);
    remote-host mode composes the WS-Man hop exactly like every other
    psdirect_prefix caller (compose_remote with payload_lines=1), so
    ``$__p0`` is defined instead of addressing the LOCAL host.
    """
    script = "\n".join([
        guestexec.psdirect_prefix(cred, cfg),
        guestexec.vm_target_preamble(ref.id),
        "$out = Invoke-Command -VMId $vmTarget -Credential $cred "
        "-ErrorAction Stop -ScriptBlock { " + guest_command + " }",
        "$out",
    ])
    if pswindows.hyperv_host(cfg):
        body, stdin = pswindows.compose_remote(
            cfg, script, payload_lines=1,
            stdin_b64=pswindows.utf8_b64(cred.password))
    else:
        body, stdin = script, pswindows.utf8_b64(cred.password)
    result = pswindows.run_ps(body, timeout_s=timeout_s, stdin_b64=stdin)
    pswindows.check_result(result)
    return result.stdout or ""


def _parse_quser(text: str, username: str) -> dict | None:
    """Parse quser output for the credential's single Active session.

    Only sessions whose user matches the credential's username with an
    Active state are eligible; more than one eligible session raises
    UiAError (ambiguous) rather than picking arbitrarily.
    """
    eligible: list[dict] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        fields = raw.split()
        if len(fields) < 3:
            continue
        user = fields[0]
        if ">" in user:
            user = user.lstrip(">")
        if user.casefold() != username.casefold():
            continue
        state = [f for f in fields if f.lower() in ("active", "disc")]
        if "active" not in [f.lower() for f in state]:
            continue
        digits = [f for f in fields[1:] if f.isdigit()]
        if not digits:
            continue
        eligible.append({"user": user, "session_id": int(digits[0])})
    if len(eligible) > 1:
        raise UiAError(
            f"ambiguous_session: {len(eligible)} active sessions for {username}")
    return eligible[0] if eligible else None


def _run_quser(cfg, ref, cred: CredentialSet) -> dict | None:
    """The PS Direct quser discovery seam: {user, session_id} | None.

    Raises UiAError naming ambiguous_session when the credential has more
    than one Active session (never picks arbitrarily). quser ERRORS
    ("No User exists for *") when the guest has no logon sessions — that
    is "nobody logged on" (None), not a transport failure.
    """
    try:
        text = _ps_guest_text(cfg, ref, cred, "quser")
    except pswindows.PowerShellTransportError as exc:
        if "no user exists" in str(exc).lower():
            return None
        raise
    return _parse_quser(text, cred.username)


def _session_has_logonui(cfg, ref, cred: CredentialSet, session_id: int) -> bool:
    """LogonUI.exe present in that session — the locked signal."""
    text = _ps_guest_text(
        cfg, ref, cred,
        "(Get-Process -Name LogonUI -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.SessionId -eq {int(session_id)} }} | "
        "Measure-Object).Count")
    return text.strip() not in ("", "0")


def _bootstrap_session(cfg, ref, cred: CredentialSet):
    """Best-effort session discovery: (session_id | None, fallback | None).

    Discovery is enrichment, never a gate: on failure the request proceeds
    with session_id None and the helper refuses it (session_unverified).
    The fallback block is returned only when the pipe itself is unusable
    (AC8), so the two failure modes stay distinguishable.
    """
    try:
        found = _run_quser(cfg, ref, cred)
    except UiAError:
        raise
    except Exception:
        return None, None
    if found is None:
        return None, None
    return found["session_id"], None


def _fallback_block(cfg, ref, cred: CredentialSet) -> dict:
    """The PS Direct session facts returned when the helper is unavailable."""
    try:
        found = _run_quser(cfg, ref, cred)
    except Exception:
        found = None
    if found is None:
        return {"interactive_user": None, "session_id": None, "locked": None}
    try:
        locked = _session_has_logonui(cfg, ref, cred, found["session_id"])
    except Exception:
        locked = None
    return {
        "interactive_user": found["user"],
        "session_id": found["session_id"],
        "locked": locked,
    }


_SID_CACHE: dict[tuple[str, str], str] = {}
_SID_CACHE_CAP = 64


def _sid_for(cfg, ref, cred: CredentialSet) -> str | None:
    """The credential user's SID inside the guest (best effort, cached).

    Only SUCCESSFUL reads are cached (F5/F18): a failed lookup returns
    None and the next call retries instead of pinning the failure forever.
    """
    key = (ref.id, cred.username)
    with _REGISTRY_LOCK:
        cached = _SID_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = _ps_guest_text(
            cfg, ref, cred, "whoami /user /fo csv /nh", timeout_s=20)
        for line in text.splitlines():
            if "," in line:
                fields = [f.strip().strip('"') for f in line.split(",")]
                if len(fields) >= 2 and fields[-1].startswith("S-1-"):
                    with _REGISTRY_LOCK:
                        _SID_CACHE[key] = fields[-1]
                        _bound_cache(_SID_CACHE, _SID_CACHE_CAP)
                    return fields[-1]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# recorded install facts (F3): the guest-namespace identity + nonce
# ---------------------------------------------------------------------------

#: vm GUID (the host's CIM namespace — the cache KEY) -> the recorded
#: install {dir, uuid, nonce, version} (the GUEST namespace the helper
#: enforces). Seeded at provision time; a verb that finds no entry (a
#: server restarted since provisioning) re-reads uuid.txt/nonce.txt/
#: version.txt from the newest helper directory with ONE discovery leg.
_INSTALLS: dict[str, dict] = {}
_INSTALL_CAP = 16


def _install_facts(cfg, ref, cred: CredentialSet) -> dict | None:
    """The recorded helper install for this VM, or None when absent.

    The RECORDED uuid (never the Hyper-V VM GUID) is what requests carry as
    ``target.vm_guid`` and what the helper compares its live UUID against.
    When no install is recorded the request keeps the host-namespace GUID:
    the helper then refuses it (the namespaces never agree by accident),
    which is the same fail-closed outcome the guest enforces anyway.
    """
    with _REGISTRY_LOCK:
        cached = _INSTALLS.get(ref.id)
    if cached is not None:
        return cached
    try:
        text = _ps_guest_text(cfg, ref, cred, _UUID_DISCOVERY_CMD,
                              timeout_s=30)
        facts = json.loads(text.strip() or "null")
    except Exception:
        return None
    if not isinstance(facts, dict) or not facts.get("dir"):
        return None
    record = {
        "dir": str(facts.get("dir")),
        "uuid": str(facts.get("uuid") or ""),
        "nonce": str(facts.get("nonce") or ""),
        "version": str(facts.get("version") or ""),
    }
    with _REGISTRY_LOCK:
        _INSTALLS[ref.id] = record
        _bound_cache(_INSTALLS, _INSTALL_CAP)
    return record


def _drop_install_facts(vm_guid: str) -> None:
    """Forget the recorded install and every registration for a VM."""
    with _REGISTRY_LOCK:
        _INSTALLS.pop(vm_guid, None)
        for key in [k for k in _REGISTRATIONS if k[0] == vm_guid]:
            del _REGISTRATIONS[key]


# ---------------------------------------------------------------------------
# broker: registrations, validation, routing
# ---------------------------------------------------------------------------

#: (vm_guid, session_id) -> registration. Keyed by the CURRENT session so a
#: guest re-login (a new session id) can never route through a stale row;
#: guarded by _REGISTRY_LOCK (readers and writers both hold it), bounded by
#: _REGISTRATION_CAP, and NEVER stores a transport — the transport (and its
#: credential) is built per call so a rotation cannot strand a registration
#: authenticating with a dead password (F5).
_REGISTRATIONS: dict[tuple[str, int], dict] = {}
_REGISTRATION_CAP = 16
_REGISTRY_LOCK = threading.Lock()


def _bound_cache(cache: dict, cap: int) -> None:
    """Evict oldest-inserted entries beyond cap. Caller holds the lock."""
    while len(cache) > cap:
        del cache[next(iter(cache))]


class _Transport:
    """The PER-CALL context a forward needs to reach its pipe.

    Built fresh for every request (never stored on a registration), so no
    credential is pinned beyond the call that supplied it.
    """

    def __init__(self, cfg, ref, cred: CredentialSet):
        self.cfg = cfg
        self.ref = ref
        self.cred = cred

    @property
    def agent_id(self) -> str:
        return auditlog.current_agent_id() or ""


def register_helper(*, vm_guid: str, user_sid: str, session_id: int,
                    capabilities, nonce: str = "",
                    target_guid: str | None = None) -> dict:
    """Validate and record a helper registration (AC19's contract shape).

    ``capabilities`` must include the baseline "uia" (a registration
    without it can never route); "msaa" and ELECTRON_CAPABILITY are opt-in.
    ``target_guid`` is the GUEST-namespace identity requests will carry
    (the recorded SMBIOS uuid); None defers that dimension to the
    registration's vm_guid. Returns a plain transport-free mapping — the
    transport is built per call by the verb layer.
    """
    vmident_guestexec_validate = getattr(guestexec, "validate_vm_guid", None)
    if vmident_guestexec_validate is not None:
        vmident_guestexec_validate(vm_guid)
    if not isinstance(user_sid, str) or not user_sid.startswith("S-1-"):
        raise ValueError(f"user_sid is not a SID: {user_sid!r}")
    if not isinstance(session_id, int) or session_id < 0:
        raise ValueError(f"session_id must be a non-negative int: {session_id!r}")
    if target_guid is not None and not isinstance(target_guid, str):
        raise ValueError(f"target_guid must be a string or None: {target_guid!r}")
    caps = set(capabilities or ())
    if not caps <= _CAPABILITIES:
        raise ValueError(
            f"unknown capabilities: {sorted(caps - _CAPABILITIES)}")
    if "uia" not in caps:
        raise ValueError("a helper registration requires the 'uia' capability")
    registration = {
        "registration_id": uuid.uuid4().hex,
        "vm_guid": vm_guid,
        "target_guid": target_guid,
        "user_sid": user_sid,
        "session_id": session_id,
        "capabilities": caps,
        "nonce": nonce or "",
    }
    key = (vm_guid, session_id)
    with _REGISTRY_LOCK:
        _REGISTRATIONS.pop(key, None)
        _REGISTRATIONS[key] = registration
        _bound_cache(_REGISTRATIONS, _REGISTRATION_CAP)
    return registration


def ensure_registration(cfg, ref, cred: CredentialSet,
                        frame: dict | None = None,
                        session_id: int | None = None, *,
                        target_guid: str | None = None) -> dict | None:
    """The CURRENT session's registration; seeded only from a response.

    With ``frame`` (a helper response) this SEEDS the (vm, session) row
    from the frame's session block. With ``session_id`` alone it only
    LOOKS UP that session's row — never a scan that could route a request
    through another session's row, and never a seed (the bootstrap request
    must reach the helper unregistered; it guards itself strictly). In
    both shapes the lookup is strictly by (vm, CURRENT session) (F5).
    """
    if isinstance(frame, dict):
        block = frame.get("session") or {}
        if session_id is None:
            session_id = block.get("session_id")
        helper = block.get("helper") or {}
        capabilities = helper.get("capabilities")
        nonce = helper.get("nonce") or ""
        try:
            key_session = int(session_id)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
        with _REGISTRY_LOCK:
            existing = _REGISTRATIONS.get((ref.id, key_session))
            if existing is not None:
                if target_guid is not None:
                    existing["target_guid"] = target_guid
                return existing
        try:
            return register_helper(
                vm_guid=ref.id,
                user_sid=_sid_for(cfg, ref, cred) or "S-1-0-0",
                session_id=key_session,
                capabilities=capabilities or {"uia"},
                nonce=nonce or "",
                target_guid=target_guid,
            )
        except ValueError:
            return None
    if session_id is None:
        return None
    with _REGISTRY_LOCK:
        return _REGISTRATIONS.get((ref.id, int(session_id)))


def validate_forward(registration: dict, request: dict) -> str:
    """Refuse unbound or unbounded requests; return a correlation id (AC19).

    The request target must match the registration on vm_guid, user_sid
    AND session_id exactly (vm_guid compares against the registration's
    recorded target_guid — the guest-namespace identity — when one was
    seeded, falling back to its vm_guid); a nonce carried by both sides
    must agree; and the request must respect the verb/selector/value
    bounds. The value bound covers BOTH the request top level and
    ``request["args"]["value"]`` — where the set_value verb actually
    carries it (F10d).
    """
    target = request.get("target") or {}
    # A dimension is enforced when BOTH sides carry a value; an unknown on
    # either side (discovery failed, a stubbed frame) defers to the helper,
    # which enforces every dimension strictly at dispatch time.
    mine_guid = registration.get("target_guid")
    if mine_guid is None:
        mine_guid = registration.get("vm_guid")
    for key, mine in (("vm_guid", mine_guid),
                      ("user_sid", registration.get("user_sid")),
                      ("session_id", registration.get("session_id"))):
        theirs = target.get(key)
        if mine is not None and theirs is not None and mine != theirs:
            raise RegistrationMismatch(
                f"request target {key} does not match the helper registration")
    if request.get("verb") not in VERBS:
        raise RegistrationMismatch(
            f"request verb is outside the closed allowlist: "
            f"{request.get('verb')!r}")
    reg_nonce = registration.get("nonce") or ""
    req_nonce = request.get("nonce") or ""
    if reg_nonce and req_nonce and reg_nonce != req_nonce:
        raise RegistrationMismatch("request nonce does not match registration")
    selector = request.get("selector")
    if selector is not None:
        validate_selector(selector)
    raw_args = request.get("args")
    args = raw_args if isinstance(raw_args, dict) else {}
    for value in (request.get("value"), args.get("value")):
        if isinstance(value, str) and len(value.encode("utf-8")) > _MAX_VALUE_BYTES:
            raise RegistrationMismatch("request value exceeds the 64 KiB bound")
    return uuid.uuid4().hex


def _adapter_gate(registration: dict | None, request: dict) -> dict | None:
    """Electron is refused unless a registered capability approves it."""
    if request.get("adapter") != "electron":
        return None
    caps = (registration or {}).get("capabilities") or set()
    if ELECTRON_CAPABILITY not in caps:
        return {"ok": False, "error_class": "adapter_unapproved"}
    return None


def _shared_mutation_gate(registration: dict, request: dict) -> None:
    """The #28 actor/lease seam: shared-VM mutations consult it first.

    Raising refuses the request before anything is forwarded. The default
    implementation consults the lease layer for the registration's VM;
    a transport-free registration (unit-test shape) cannot be verified and
    is refused fail-closed.
    """
    transport = registration.get("transport")
    if transport is None:
        raise UiAError(
            "shared-VM mutation requires a transport-bound registration")
    from . import leases  # late import: the lease tree is heavy

    leases.assert_unleased(
        transport.cfg, transport.agent_id, "console",
        vm_hint=str(registration.get("vm_guid") or ""))


def route(registration: dict, request: dict, *,
          shared_vm: bool = False) -> dict:
    """Validate, gate, and forward one bounded request to its helper."""
    correlation_id = validate_forward(registration, request)
    refusal = _adapter_gate(registration, request)
    if refusal is not None:
        return refusal
    if request.get("verb") in MUTATING_VERBS and shared_vm:
        _shared_mutation_gate(registration, request)
    frame = _pipe_request(registration, request, correlation_id)
    if not isinstance(frame, dict):
        frame = {"ok": False, "error_class": "helper_error"}
    return {**frame, "ok": frame.get("ok") is True,
            "correlation_id": correlation_id}


# ---------------------------------------------------------------------------
# the pipe seam (two pinned call shapes, dispatched on arity)
# ---------------------------------------------------------------------------

def _pipe_forward(transport: _Transport | None, request: dict,
                  correlation_id: str) -> dict:
    """One request frame through the guest pipe-client leg.

    ``transport`` is built PER CALL: the verb layer passes one it just
    built, and the broker forward (whose registrations are transport-free
    by design, F5) rebuilds it from the call-scoped ``_CALL`` slot. The
    response frame must correlate with the request id and carry an
    explicit boolean ok (F4); the reported helper sha256 is checked
    against the packaged bytes.
    """
    if transport is None:
        cfg = getattr(_CALL, "cfg", None)
        ref = getattr(_CALL, "ref", None)
        cred = getattr(_CALL, "cred", None)
        if cfg is None or ref is None or cred is None:
            raise UiAError(
                "no call context available to build a helper transport "
                "(registrations are transport-free; verbs bind one per call)")
        transport = _Transport(cfg, ref, cred)
    request = {**request, "min_version": request.get("min_version")
               or HELPER_VERSION}
    payload = json.dumps(request, ensure_ascii=False, default=str)
    framed_payload = pswindows.utf8_b64(payload)
    result = _frame_leg(transport.cfg, transport.ref, transport.cred,
                        CLIENT_LEG_SCRIPT, framed_payload,
                        timeout_ms=_verb_timeout_ms(request))
    return _parse_helper_frame(result, request)


def _parse_helper_frame(result: pswindows.PSResult, request: dict) -> dict:
    """F4: a degraded frame is NEVER success — the contract fails closed.

    Empty stdout, a non-object, a missing/non-boolean ``ok``, an absent or
    non-correlating response id, or a mismatched id raise (mapped to
    helper_unavailable by the verb layer). The helper attaches id and a
    session block to EVERY frame, so their absence is itself degradation.
    Integrity fails closed on ok frames: a helper-reported sha256 is
    compared with the packaged bytes (exposed as
    ``session.helper.sha256_match``), and an ok frame whose digest is
    absent, empty, or mismatching refuses with
    ``helper_integrity_mismatch``. Refusal frames tolerate an unusable
    digest — they are already not success, and the weaker contract is
    explicit here.
    """
    text = (result.stdout or "").strip()
    try:
        frame = json.loads(text) if text else None
    except json.JSONDecodeError as exc:
        raise UiAError(f"malformed helper response: {exc}") from None
    if not isinstance(frame, dict):
        raise UiAError("malformed helper response: not an object")
    if not isinstance(frame.get("ok"), bool):
        raise UiAError("degraded helper response: no explicit ok")
    response_id = frame.get("id")
    if response_id is None:
        raise UiAError("degraded helper response: no correlation id")
    if response_id != request.get("id"):
        raise UiAError(
            "helper response id does not correlate with the request id")
    session = frame.get("session")
    helper = session.get("helper") if isinstance(session, dict) else None
    reported = helper.get("sha256") if isinstance(helper, dict) else None
    usable = isinstance(reported, str) and bool(reported)
    if usable and isinstance(helper, dict):
        expected = _packaged_helper_sha256()
        match = (isinstance(expected, str)
                 and expected.lower() == str(reported).lower())
        helper["sha256_match"] = match
        if frame["ok"] and not match:
            return {"ok": False,
                    "error_class": "helper_integrity_mismatch",
                    "error": "the running helper's sha256 does not match "
                             "the packaged helper bytes",
                    "session": session}
    if frame["ok"] and not usable:
        return {"ok": False,
                "error_class": "helper_integrity_mismatch",
                "error": "the helper response carries no usable sha256 to "
                         "verify against the packaged helper bytes",
                "session": session}
    return frame


def _verb_timeout_ms(request: dict) -> int:
    """The pipe leg budget for one request.

    wait_for reads its budget from ``request["args"]["timeout_s"]`` — the
    level the verb actually puts it at (F6; the old top-level read always
    saw the 30 s default) — and the leg gets the requested budget plus the
    guest grace added by _frame_leg.
    """
    if request.get("verb") == "wait_for":
        raw_args = request.get("args")
        args = raw_args if isinstance(raw_args, dict) else {}
        budget = int(args.get("timeout_s") or 30)
        return min(120, max(15, budget)) * 1000
    return 15000


def _pipe_request(*args):
    """The helper-pipe seam — one name, two pinned call shapes.

    ``(cfg, vm, cred, request)`` is the VERB front door: best-effort
    session discovery, target binding, broker chain (registration when
    one is known for the CURRENT session, strictly-guarded bootstrap
    otherwise), transport round trip, and registration seeding from the
    response. ``(registration, request, correlation_id)`` is the BROKER
    forward: the transport round trip only (the transport is rebuilt from
    the call-scoped slot — registrations never pin credentials). The
    frozen tests stub this name with one shape per family; production
    dispatches on arity and both paths share one enforcement model.
    """
    if len(args) == 4:
        cfg, vm, cred, request = args
        return _front_door(cfg, vm, cred, request)
    registration, request, correlation_id = args
    return _pipe_forward((registration or {}).get("transport"), request,
                         correlation_id)


def _front_door(cfg, vm, cred: CredentialSet, request: dict) -> dict:
    """Bind the request's target from the RECORDED install + live session.

    ``target.vm_guid`` carries the recorded SMBIOS uuid from uuid.txt (F3)
    — the namespace the helper enforces. The nonce is the INSTALLED one
    (F10c: written at provision time, re-read from the guest when this
    process never provisioned), never a value copied from a registration.
    """
    ref = vm if isinstance(vm, vmident.VMRef) else vmident.resolve(
        cfg, vm_name=vm)
    request = dict(request)
    facts = _install_facts(cfg, ref, cred)
    recorded = (facts or {}).get("uuid")
    target_guid = recorded if recorded is not None else ref.id
    current_sid = _sid_for(cfg, ref, cred)
    request["target"] = {
        "vm_guid": target_guid,
        "user_sid": current_sid,
        "session_id": None,
    }
    if facts:
        if facts.get("nonce"):
            request["nonce"] = facts["nonce"]
        if facts.get("version"):
            request["min_version"] = facts["version"]
    try:
        session_id, _status = _bootstrap_session(cfg, ref, cred)
    except UiAError as exc:
        return {"ok": False, "error_class": "ambiguous_session",
                "error": str(exc), "session": _fallback_block(cfg, ref, cred)}
    registration = ensure_registration(
        cfg, ref, cred, session_id=session_id, target_guid=target_guid)
    if (registration is not None and current_sid
            and registration.get("user_sid") == "S-1-0-0"):
        # Upgrade the NULL-authority placeholder seeded when the SID lookup
        # failed — the current session's identity is the truth. A real,
        # DIFFERENT recorded SID is a genuine mismatch and stays one.
        with _REGISTRY_LOCK:
            registration["user_sid"] = current_sid
    request["target"]["session_id"] = session_id
    refusal = _adapter_gate(registration, request)
    if refusal is not None:
        return refusal
    if registration is not None:
        return route(registration, request)
    frame = _pipe_forward(_Transport(cfg, ref, cred), request,
                          uuid.uuid4().hex)
    if frame.get("ok") and isinstance(frame.get("session"), dict):
        ensure_registration(cfg, ref, cred, frame=frame,
                            target_guid=target_guid)
    return frame


# ---------------------------------------------------------------------------
# verbs
# ---------------------------------------------------------------------------

def _transport_failure(exc: Exception, cfg, ref, cred: CredentialSet) -> dict:
    """Map a transport failure to its envelope (fallback legs inside)."""
    if "pipe busy" in str(exc).lower():
        # F13: the helper's single pipe instance stayed contended past the
        # client leg's bounded retries — retryable via the busy class.
        return {"ok": False, "error_class": "busy",
                "error": str(exc),
                "session": _fallback_block(cfg, ref, cred)}
    return {"ok": False, "error_class": "helper_unavailable",
            "error": str(exc),
            "session": _fallback_block(cfg, ref, cred)}


def _frame_out(frame: Any, cfg, ref, cred: CredentialSet) -> dict:
    """Finish a helper frame into the verb answer (fallback legs inside)."""
    if not isinstance(frame, dict) or not isinstance(frame.get("ok"), bool):
        return {"ok": False, "error_class": "helper_error",
                "error": "the helper returned no usable frame",
                "session": _fallback_block(cfg, ref, cred)}
    if not frame["ok"]:
        out = {**frame, "ok": False}
        out.setdefault("session", _fallback_block(cfg, ref, cred))
        return out
    out = {"ok": True, **(frame.get("result") or {}),
           "session": frame.get("session")}
    helper = (frame.get("session") or {}).get("helper")
    if isinstance(helper, dict):
        # Promote the helper facts to top level: evidence's helper gate, the
        # provision probe, and the frozen AC17 shape all read
        # answer["helper"]. The frame's own running value is preserved
        # (never forced true); sha256_match rides along when reported.
        out["helper"] = dict(helper)
    return out


def _wait_answered(out: dict, gone: bool) -> bool:
    """Whether a wait_for slice's answer settles the wait."""
    if out.get("ok") is not True:
        return True  # errors stop the poll
    if gone:
        return bool(out.get("gone"))
    return bool(out.get("elements"))


def _verb_request(cfg, ref, cred: CredentialSet, verb: str, args: dict,
                  *, shared_vm: bool = False, selector: Any = None,
                  element_id: Any = None, adapter: str = "") -> dict:
    """Run one verb: gates, per-leg VM lock, wait_for slice polling.

    The mutating verbs ALWAYS consult the #28 actor/lease gate (F10a: the
    server-side mutating tools are console-scoped, so the gate is consulted
    on every mutating request — ``shared_vm`` is accepted for call-shape
    compatibility and no longer conditions the gate). The VM lock is held
    only around each transport leg INCLUDING its fallback/discovery legs
    (F12); wait_for re-slices its budget so the lock is never held across
    the whole wait.
    """
    request = build_request(verb, args=args)
    if selector is not None:
        request["selector"] = validate_selector(selector)
    if element_id is not None:
        request["element_id"] = str(element_id)
    if adapter:
        if adapter not in _ADAPTERS:
            raise ValueError(f"unknown adapter: {adapter!r}")
        request["adapter"] = adapter
    if verb in MUTATING_VERBS:
        # AC21's gate runs on EVERY mutating request, bootstrap included;
        # the transport is built per call so no credential is pinned.
        _shared_mutation_gate({"transport": _Transport(cfg, ref, cred),
                               "vm_guid": ref.id}, request)
    mode = "write" if verb in MUTATING_VERBS else "read"
    gone = bool((request.get("args") or {}).get("gone"))
    deadline = None
    if verb == "wait_for":
        budget = int((request.get("args") or {}).get("timeout_s") or 30)
        deadline = time.monotonic() + max(1, budget)
    _CALL.cfg = cfg
    _CALL.ref = ref
    _CALL.cred = cred
    try:
        while True:
            leg_request = request
            if deadline is not None:
                remaining = deadline - time.monotonic()
                leg_request = {
                    **request,
                    "id": uuid.uuid4().hex,
                    "args": {**request["args"],
                             "timeout_s": max(1, min(_WAIT_SLICE_S,
                                                     math.ceil(remaining)))},
                }
            with vm_lock(ref.id, mode=mode):
                try:
                    frame = _pipe_request(cfg, ref, cred, leg_request)
                except RegistrationMismatch:
                    raise
                except UiAError as exc:
                    if "ambiguous_session" in str(exc):
                        return {"ok": False,
                                "error_class": "ambiguous_session",
                                "error": str(exc),
                                "session": _fallback_block(cfg, ref, cred)}
                    return _transport_failure(exc, cfg, ref, cred)
                except (TimeoutError, pswindows.PowerShellTransportError,
                        OSError) as exc:
                    return _transport_failure(exc, cfg, ref, cred)
                out = _frame_out(frame, cfg, ref, cred)
            if deadline is None or _wait_answered(out, gone):
                if deadline is not None:
                    # PRR-117: the flag rides BOTH settled outcomes — False
                    # when the wait was answered (a hit, an error, or a
                    # gone verdict), True only on the budget-expiry path.
                    out = {**out, "timed_out": False}
                return out
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # The wait's whole budget expired unanswered: the last
                # slice's answer ships, now with timed_out True so a caller
                # can tell an expired empty poll from a settled one.
                return {**out, "timed_out": True}
            # Poll pace between slices (the console-wait pattern); the VM
            # lock is NOT held here.
            time.sleep(min(_WAIT_POLL_S, remaining))
    finally:
        _CALL.cfg = None
        _CALL.ref = None
        _CALL.cred = None


def inspect(cfg, vm_name="", cred: CredentialSet | None = None,
            selector: Any = None, depth: int = 3, max_elements: int = 200,
            *, vm_id: str = "", adapter: str = ""):
    """Bounded UIA element tree from the helper's session (read verb)."""
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    if adapter not in _ADAPTERS:
        raise ValueError(f"unknown adapter: {adapter!r}")
    ref = (vm_name if isinstance(vm_name, vmident.VMRef)
           else vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id))
    args = {"depth": max(1, min(int(depth), INSPECT_MAX_DEPTH)),
            "max_elements": max(1, min(int(max_elements),
                                       INSPECT_MAX_ELEMENTS))}
    return _verb_request(cfg, ref, cred, "inspect", args, selector=selector,
                         adapter=adapter)


def find(cfg, vm_name="", cred: CredentialSet | None = None,
         selector: Any = None, *, element_id: Any = None, vm_id: str = "",
         adapter: str = ""):
    """Resolve elements by selector (read verb)."""
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    if adapter not in _ADAPTERS:
        raise ValueError(f"unknown adapter: {adapter!r}")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id) if not isinstance(
        vm_name, vmident.VMRef) else vm_name
    return _verb_request(cfg, ref, cred, "find", {},
                         selector=selector, element_id=element_id,
                         adapter=adapter)


def invoke(cfg, vm_name="", cred: CredentialSet | None = None,
           selector: Any = None, *, element_id: Any = None, vm_id: str = "",
           shared_vm: bool = False):
    """Invoke a UIA pattern on the target element (mutating; ui_input)."""
    policy.require_category(cfg, "ui_input", f"invoke on '{vm_name}'")
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    _check_element_op(selector, element_id)
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id) if not isinstance(
        vm_name, vmident.VMRef) else vm_name
    return _verb_request(cfg, ref, cred, "invoke", {},
                         shared_vm=shared_vm, selector=selector,
                         element_id=element_id)


def set_value(cfg, vm_name="", cred: CredentialSet | None = None,
              selector: Any = None, value: Any = None, *,
              element_id: Any = None, vm_id: str = "",
              shared_vm: bool = False):
    """Set a UIA Value-pattern property (mutating; ui_input).

    The value rides the framed stdin payload — never script text, never
    argv, never error text — and the result reports the length set, never
    the value.
    """
    policy.require_category(cfg, "ui_input", f"set value on '{vm_name}'")
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    _check_element_op(selector, element_id)
    if value is None:
        raise ValueError("set_value requires value=")
    if isinstance(value, str) and len(value.encode("utf-8")) > _MAX_VALUE_BYTES:
        raise ValueError(f"value exceeds the {_MAX_VALUE_BYTES} byte bound")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id) if not isinstance(
        vm_name, vmident.VMRef) else vm_name
    args = {"value": value}
    return _verb_request(cfg, ref, cred, "set_value", args,
                         shared_vm=shared_vm, selector=selector,
                         element_id=element_id)


def wait_for(cfg, vm_name="", cred: CredentialSet | None = None,
             selector: Any = None, gone: bool = False, timeout_s: int = 30,
             *, vm_id: str = ""):
    """Wait for a selector to appear (or disappear) (read verb).

    The wait runs as bounded guest-side slices so the per-VM lock is held
    only around each transport leg, never across the whole wait.
    """
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id) if not isinstance(
        vm_name, vmident.VMRef) else vm_name
    args = {"gone": bool(gone), "timeout_s": max(1, min(int(timeout_s), 120))}
    return _verb_request(cfg, ref, cred, "wait_for", args,
                         selector=selector)


def focus(cfg, vm_name="", cred: CredentialSet | None = None,
          selector: Any = None, *, element_id: Any = None, vm_id: str = "",
          shared_vm: bool = False):
    """Focus the target element (mutating; ui_input). Locked sessions are
    refused by the helper with error_class "no_interactive_desktop"."""
    policy.require_category(cfg, "ui_input", f"focus on '{vm_name}'")
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    _check_element_op(selector, element_id)
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id) if not isinstance(
        vm_name, vmident.VMRef) else vm_name
    return _verb_request(cfg, ref, cred, "focus", {},
                         shared_vm=shared_vm, selector=selector,
                         element_id=element_id)


def session_state(cfg, vm_name="", cred: CredentialSet | None = None, *,
                  vm_id: str = ""):
    """Session, lock state, foreground window, and helper facts (read)."""
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id) if not isinstance(
        vm_name, vmident.VMRef) else vm_name
    return _verb_request(cfg, ref, cred, "session_state", {})


# ---------------------------------------------------------------------------
# provisioning (F14: idempotent install + a real teardown inverse)
# ---------------------------------------------------------------------------

def _provision_leg_frame(result: pswindows.PSResult) -> dict:
    """Parse a provisioning leg's JSON outcome; {} when degraded (F4 spirit)."""
    try:
        frame = json.loads((result.stdout or "").strip() or "null")
    except json.JSONDecodeError:
        return {}
    return frame if isinstance(frame, dict) else {}


def _teardown_helper(cfg, ref, cred: CredentialSet) -> dict:
    """Provisioning's inverse: task, directories, LSA secret, Winlogon."""
    out: dict = {"ok": True, "torn_down": True, "task_unregistered": False,
                 "helper_directories_removed": 0, "lsa_secret_deleted": False,
                 "autologon_restored": False}
    with vm_lock(ref.id, mode="write"):
        reset = _frame_leg(cfg, ref, cred, _RESET_INNER,
                           pswindows.utf8_b64("reset"), timeout_ms=60000)
        reset_frame = _provision_leg_frame(reset)
        if not reset_frame.get("ok"):
            return {"ok": False, "error_class": "helper_teardown_failed",
                    "error": str(reset_frame)[:500], **{
                        k: v for k, v in out.items() if k != "ok"}}
        out["task_unregistered"] = bool(
            reset_frame.get("task_unregistered"))
        out["helper_directories_removed"] = int(
            reset_frame.get("directories_removed") or 0)
        _drop_install_facts(ref.id)
        leg = _frame_leg(cfg, ref, cred, _TEARDOWN_WINLOGON_INNER,
                         pswindows.utf8_b64("teardown"), timeout_ms=60000)
        frame = _provision_leg_frame(leg)
        if not frame.get("ok"):
            return {"ok": False, "error_class": "helper_teardown_failed",
                    "error": str(frame)[:500], **{
                        k: v for k, v in out.items() if k != "ok"}}
        out["lsa_secret_deleted"] = bool(frame.get("lsa_secret_deleted"))
        out["autologon_restored"] = bool(frame.get("autologon_restored"))
    return out


def provision_helper(cfg, vm_name="", cred: CredentialSet | None = None,
                     autologon: bool = True, confirm: bool = False, *,
                     vm_id: str = "", teardown: bool = False):
    """Install + start the in-session UIA helper (ui_provision + confirm),
    or — with ``teardown=True`` — remove everything it persisted.

    Two policy denials fire BEFORE anything runs (frozen C9): a
    non-unrestricted config without destructive.ui_provision raises
    PolicyDenied naming ui_provision, and confirm=False raises
    PolicyDenied naming confirm. Secrets (the autologon password, the
    helper bytes) ride the framed stdin payload, never script text.

    The install is idempotent (F14a): the running helper's task instance
    and process are stopped and every previous per-provision directory is
    removed BEFORE the new bytes land, so the old instance cannot keep the
    fixed-name pipe. Provisioning also records the guest's SMBIOS UUID
    (uuid.txt — the identity the helper enforces) and the per-install
    nonce; a failed UUID read records an EMPTY uuid, which the helper
    refuses (fail-closed, F3).
    """
    action = ("tear down" if teardown else "provision")
    policy.require_destructive(
        cfg, "ui_provision", confirm,
        f"{action} the UIA helper on '{vm_name}'")
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError(
            "guest credentials are required for provisioning")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    if teardown:
        return _teardown_helper(cfg, ref, cred)
    from importlib import resources

    helper_bytes = (
        resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_bytes()
    )
    helper_b64 = base64.b64encode(helper_bytes).decode("ascii")
    results: dict = {"ok": True, "autologon_configured": False,
                     "task_registered": False,
                     "helper_version": HELPER_VERSION,
                     "helper_running": False, "reboot_required": False,
                     "guest_uuid_read": False, "helper_dir": ""}
    with vm_lock(ref.id, mode="write"):
        # F14(a): stop the running helper and clear the previous
        # directories first — re-provisioning must not leave the old
        # instance holding the fixed-name pipe.
        reset = _frame_leg(cfg, ref, cred, _RESET_INNER,
                           pswindows.utf8_b64("reset"), timeout_ms=60000)
        reset_frame = _provision_leg_frame(reset)
        if not reset_frame.get("ok"):
            # PRR-117: the failure result carries the SAME status keys as
            # success — spread over `results`, so every documented key is
            # present with the false/empty value it had at failure time.
            return {**results, "ok": False,
                    "error_class": "helper_install_failed",
                    "error": str(reset_frame)[:500]}
        _drop_install_facts(ref.id)
        guest_uuid = ""
        try:
            guest_uuid = _ps_guest_text(cfg, ref, cred, _UUID_READ_CMD,
                                        timeout_s=30).strip().lower()
        except Exception:
            guest_uuid = ""
        results["guest_uuid_read"] = bool(guest_uuid)
        helper_dir = (
            r"C:\ProgramData\hyperv-mcp\uia-helper-"
            + uuid.uuid4().hex[:8]
        )
        dir_line = ("$env:HYPERVMCP_HELPER_DIR = "
                    + pswindows.ps_quote(helper_dir) + "\n")
        helper_nonce = uuid.uuid4().hex
        install = _frame_leg(
            cfg, ref, cred,
            (dir_line
             + "$env:HYPERVMCP_HELPER_UUID = "
             + pswindows.ps_quote(guest_uuid) + "\n"
             + "$env:HYPERVMCP_HELPER_NONCE = "
             + pswindows.ps_quote(helper_nonce) + "\n"
             + "$env:HYPERVMCP_AUTOLOGON_USER = "
             + pswindows.ps_quote(cred.username) + "\n" + _INSTALL_INNER),
            helper_b64, timeout_ms=60000)
        install_frame = _provision_leg_frame(install)
        if not install_frame.get("ok"):
            return {**results, "ok": False,
                    "error_class": "helper_install_failed",
                    "error": str(install_frame)[:500]}
        with _REGISTRY_LOCK:
            _INSTALLS[ref.id] = {"dir": helper_dir, "uuid": guest_uuid,
                                 "nonce": helper_nonce,
                                 "version": HELPER_VERSION}
            _bound_cache(_INSTALLS, _INSTALL_CAP)
        results["helper_dir"] = helper_dir
        if autologon:
            # ps_quote emits the surrounding single quotes itself (with ''
            # doubling for embedded quotes) — never add another pair.
            user_line = ("$env:HYPERVMCP_AUTOLOGON_USER = "
                         + pswindows.ps_quote(cred.username))
            autologon_inner = user_line + "\n" + _AUTOLOGON_INNER
            leg = _frame_leg(cfg, ref, cred, autologon_inner,
                             pswindows.utf8_b64(cred.password),
                             timeout_ms=60000)
            frame = _provision_leg_frame(leg)
            results["autologon_configured"] = bool(frame.get("ok"))
            results["reboot_required"] = bool(frame.get("ok"))
        task_inner = ("$env:HYPERVMCP_HELPER_DIR = "
                      + pswindows.ps_quote(helper_dir) + "\n"
                      + "$env:HYPERVMCP_AUTOLOGON_USER = "
                      + pswindows.ps_quote(cred.username) + "\n" + _TASK_INNER)
        leg = _frame_leg(cfg, ref, cred, task_inner,
                         pswindows.utf8_b64("task"), timeout_ms=60000)
        frame = _provision_leg_frame(leg)
        results["task_registered"] = bool(frame.get("task_registered"))
    try:
        state = session_state(cfg, ref, cred=cred)
        helper = (state or {}).get("helper") or {}
        results["helper_running"] = bool(helper.get("running"))
    except Exception:
        pass
    return results
