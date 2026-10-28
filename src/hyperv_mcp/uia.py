"""Element-level UI Automation through the in-session guest helper (issue #29).

The helper is a long-lived PowerShell 5.1 process running in the guest's
INTERACTIVE session (per-user AtLogOn task, ``RunLevel Highest``); it hosts
``System.Windows.Automation`` and serves newline-JSON request frames on a
local named pipe. The host reaches the pipe ONLY through PowerShell Direct
(``hyperv_mcp_guestexec.psdirect_prefix`` + ``Invoke-Command -VMId``): the
guest-side client leg (``CLIENT_LEG_SCRIPT``) connects to the pipe and
relays exactly one request frame, so the host never needs network reach to
the guest.

Security model (plan revision 7):
- The pipe name is NOT session-scoped (Microsoft named-pipe security docs),
  so the HOST runs a best-effort quser discovery leg before every request
  and fills ``target.session_id``; the HELPER enforces vm_guid + user_sid +
  session_id STRICTLY on every request — a session-less request is refused
  (``session_unverified``) without any UIA dispatch, and a request that
  reaches a helper in a different interactive session is refused
  (``target_mismatch``). No verb ever executes without a verified session.
- The verb allowlist is closed on both ends; caller text is never evaluated
  as code. ``set_value`` payloads ride the framed stdin (line 1: the
  credential password, line 2: the base64 JSON request) — never script
  text, never argv, never error text; the result reports the length set,
  never the value.
- Policy: mutating verbs (invoke/set_value/focus) require
  ``destructive.ui_input``; helper provisioning requires
  ``destructive.ui_provision`` plus ``confirm``. Read verbs need only VM
  policy + guest credentials.
- The supplement's broker: helper registrations carry (vm_guid, user_sid,
  session_id, capabilities, nonce); ``validate_forward`` refuses
  cross-VM/cross-session routing before any forwarding; the Electron
  adapter is refused unless its capability was registered; shared-VM
  mutations consult the #28 actor/lease gate. Both gates run on EVERY
  request, bootstrap included.
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any, cast

from . import auditlog, guestexec, policy, pswindows, vmident
from .credentials import CredentialSet
from .vmlocks import vm_lock

HELPER_VERSION = "1"
VERBS = {"inspect", "find", "invoke", "set_value", "wait_for", "focus",
         "session_state"}
MUTATING_VERBS = {"invoke", "set_value", "focus"}
_ELEMENT_OPS = {"invoke", "set_value", "focus"}
BASE_CAPABILITIES = {"uia", "msaa"}
ELECTRON_CAPABILITY = "adapter:electron"
_CAPABILITIES = BASE_CAPABILITIES | {ELECTRON_CAPABILITY}
_MAX_SELECTOR_FIELD = 1024
_MAX_VALUE_BYTES = 64 * 1024
_SELECTORS = {
    "automation_id", "name", "name_contains", "control_type", "class_name",
    "window_title", "process_name", "hwnd", "element_id", "index",
}
_HELPER_DIR = r"C:\ProgramData\hyperv-mcp\uia-helper"
_HELPER_TASK = "hyperv-mcp-uia-helper"
_PIPE_NAME = "hyperv-mcp-uia"


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
    per-request ``id`` doubles as the replay nonce on the frame.
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
    pool lifetime. Callers hold the per-VM lock; this function only
    transports. The leg's VM GUID is passed through the ``_LEG_GUID`` slot
    (the frozen seam signature carries no ref).
    """
    if timeout_s is None:
        timeout_s = max(30, (15_000 // 1000) + guestexec._GRACE_S)
    wrapper = _uia_guest_script(
        script, cast(CredentialSet, _LEG_GUID["cred"]), cfg)
    if pswindows.hyperv_host(cfg):
        body, payload = pswindows.compose_remote(
            cfg, wrapper, payload_lines=2 if stdin_b64 else 0,
            stdin_b64=stdin_b64)
        result = pswindows.run_ps(body, timeout_s=timeout_s, stdin_b64=payload)
    else:
        result = pswindows.run_ps(wrapper, timeout_s=timeout_s,
                                  stdin_b64=stdin_b64)
    pswindows.check_result(result)
    return result


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
        guestexec.vm_target_preamble(cast(str, _LEG_GUID["guid"])),
        "$enc = '" + pswindows.utf8_b64(inner_script) + "'",
        "$out = Invoke-Command -VMId $vmTarget -Credential $cred "
        "-ErrorAction Stop -ScriptBlock {",
        "    param($enc, $reqEnc)",
        inner_script,
        "} -ArgumentList $enc, $reqEnc",
        "$out",
    ])


# The leg wrapper needs the VM GUID; the frozen _run_uia_leg seam carries no
# ref, so callers bind it (plus the credential for the prefix) through this
# slot immediately before each leg. Callers already hold the per-VM lock, so
# the slot never interleaves across VMs.
_LEG_GUID: dict[str, object] = {"guid": "", "cred": None}


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
    _LEG_GUID["guid"] = ref.id
    _LEG_GUID["cred"] = cred
    return _run_uia_leg(cfg, inner_script, stdin_b64=framed,
                        timeout_s=max(30, timeout_ms // 1000
                                      + guestexec._GRACE_S))


# ---------------------------------------------------------------------------
# guest-side inner scripts
# ---------------------------------------------------------------------------

CLIENT_LEG_SCRIPT = """$line = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($reqEnc))
$client = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'hyperv-mcp-uia', [System.IO.Pipes.PipeDirection]::InOut)
try {
    $client.Connect(3000)
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $writer.WriteLine($line)
    $reader = New-Object System.IO.StreamReader($client)
    $resp = $reader.ReadLine()
    if (-not $resp) { throw 'the helper closed the pipe without a response' }
    $resp
} finally { $client.Dispose() }"""

_INSTALL_INNER = """$dir = 'C:\\ProgramData\\hyperv-mcp\\uia-helper'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$helperPath = Join-Path $dir 'uia_helper.ps1'
[IO.File]::WriteAllBytes($helperPath, [Convert]::FromBase64String($reqEnc))
icacls $dir /inheritance:r /grant 'BUILTIN\\Administrators:F' /grant 'NT AUTHORITY\\SYSTEM:F' | Out-Null
$sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($helperPath))
[IO.File]::WriteAllText((Join-Path $dir 'sha256.txt'), ([BitConverter]::ToString($sha) -replace '-',''))
[IO.File]::WriteAllText((Join-Path $dir 'version.txt'), '""" + HELPER_VERSION + """')
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
    $ku.DeleteValue('DefaultPassword', $false)
} finally { $ku.Close() }
[PSCustomObject]@{ ok = $true; autologon = $true } | ConvertTo-Json -Compress"""

_TASK_INNER = """$ErrorActionPreference = 'Stop'
$user = $env:HYPERVMCP_AUTOLOGON_USER
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\hyperv-mcp\\uia-helper\\uia_helper.ps1'
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'hyperv-mcp-uia-helper' -Action $action -Principal $principal -Trigger $trigger -Settings $settings -Force | Out-Null
$started = $false
$loggedOn = quser 2>$null | Select-String -SimpleMatch $user
if ($loggedOn) { Start-ScheduledTask -TaskName 'hyperv-mcp-uia-helper'; $started = $true }
[PSCustomObject]@{ ok = $true; task_registered = $true; started = $started } | ConvertTo-Json -Compress"""


def _helper_text() -> str:
    from importlib import resources

    return (
        resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8")
    )


# ---------------------------------------------------------------------------
# discovery seams (quser / LogonUI) — plain PS Direct text legs
# ---------------------------------------------------------------------------

def _ps_guest_text(cfg, ref, cred: CredentialSet, guest_command: str,
                   timeout_s: int = 30) -> str:
    """Run one read-only guest command and return its stdout text."""
    script = "\n".join([
        guestexec.psdirect_prefix(cred, cfg),
        guestexec.vm_target_preamble(ref.id),
        "$out = Invoke-Command -VMId $vmTarget -Credential $cred "
        "-ErrorAction Stop -ScriptBlock { " + guest_command + " }",
        "$out",
    ])
    result = pswindows.run_ps(script, timeout_s=timeout_s)
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
    than one Active session (never picks arbitrarily).
    """
    text = _ps_guest_text(cfg, ref, cred, "quser")
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


_SID_CACHE: dict[tuple[str, str], str | None] = {}


def _sid_for(cfg, ref, cred: CredentialSet) -> str | None:
    """The credential user's SID inside the guest (best effort, cached)."""
    key = (ref.id, cred.username)
    if key in _SID_CACHE:
        return _SID_CACHE[key]
    try:
        text = _ps_guest_text(
            cfg, ref, cred, "whoami /user /fo csv /nh", timeout_s=20)
        for line in text.splitlines():
            if "," in line:
                fields = [f.strip().strip('"') for f in line.split(",")]
                if len(fields) >= 2 and fields[-1].startswith("S-1-"):
                    _SID_CACHE[key] = fields[-1]
                    return _SID_CACHE[key]
    except Exception:
        pass
    _SID_CACHE[key] = None
    return None


# ---------------------------------------------------------------------------
# broker: registrations, validation, routing
# ---------------------------------------------------------------------------

_REGISTRATIONS: dict[tuple[str, int], dict] = {}


class _Transport:
    """The production-bound context a registration needs to reach its pipe."""

    def __init__(self, cfg, ref, cred: CredentialSet):
        self.cfg = cfg
        self.ref = ref
        self.cred = cred

    @property
    def agent_id(self) -> str:
        return auditlog.current_agent_id() or ""


def register_helper(*, vm_guid: str, user_sid: str, session_id: int,
                    capabilities, nonce: str = "") -> dict:
    """Validate and record a helper registration (AC19's contract shape).

    ``capabilities`` must include the baseline "uia" (a registration
    without it can never route); "msaa" and ELECTRON_CAPABILITY are opt-in.
    Returns a plain transport-free mapping — production callers attach a
    ``transport`` key via :func:`ensure_registration`.
    """
    vmident_guestexec_validate = getattr(guestexec, "validate_vm_guid", None)
    if vmident_guestexec_validate is not None:
        vmident_guestexec_validate(vm_guid)
    if not isinstance(user_sid, str) or not user_sid.startswith("S-1-"):
        raise ValueError(f"user_sid is not a SID: {user_sid!r}")
    if not isinstance(session_id, int) or session_id < 0:
        raise ValueError(f"session_id must be a non-negative int: {session_id!r}")
    caps = set(capabilities or ())
    if not caps <= _CAPABILITIES:
        raise ValueError(
            f"unknown capabilities: {sorted(caps - _CAPABILITIES)}")
    if "uia" not in caps:
        raise ValueError("a helper registration requires the 'uia' capability")
    registration = {
        "registration_id": uuid.uuid4().hex,
        "vm_guid": vm_guid,
        "user_sid": user_sid,
        "session_id": session_id,
        "capabilities": caps,
        "nonce": nonce or "",
    }
    _REGISTRATIONS[(vm_guid, session_id)] = registration
    return registration


def ensure_registration(cfg, ref, cred: CredentialSet,
                        frame: dict | None = None) -> dict | None:
    """The production constructor: a transport-bound registration.

    Served from cache when the (vm, session) pair is known; seeded from a
    helper response's session block otherwise. Returns None when nothing
    is known yet (the bootstrap request, which the helper guards strictly).
    """
    session = None
    capabilities = None
    nonce = None
    if isinstance(frame, dict):
        block = frame.get("session") or {}
        session = block.get("session_id")
        helper = block.get("helper") or {}
        capabilities = helper.get("capabilities")
        nonce = helper.get("nonce")
    if session is None:
        cached = _REGISTRATIONS.get((ref.id, -1))
        # The registry is keyed by (vm_guid, session_id) tuples; unpack the
        # key before comparing, or the scan compares a tuple to the string
        # ref.id and never finds the cache (every verb call then re-bootstraps
        # and the broker chain is bypassed — pinned by test_f05_production_path).
        for (guid, _cached_session), reg in _REGISTRATIONS.items():
            if guid == ref.id:
                cached = reg
                break
        return cached
    existing = _REGISTRATIONS.get((ref.id, session))
    if existing is not None and existing.get("transport") is not None:
        return existing
    try:
        registration = register_helper(
            vm_guid=ref.id,
            user_sid=_sid_for(cfg, ref, cred) or "S-1-0-0",
            session_id=session,
            capabilities=capabilities or {"uia"},
            nonce=nonce or "",
        )
    except ValueError:
        return None
    registration["transport"] = _Transport(cfg, ref, cred)
    _REGISTRATIONS[(ref.id, session)] = registration
    return registration


def validate_forward(registration: dict, request: dict) -> str:
    """Refuse unbound or unbounded requests; return a correlation id (AC19).

    The request target must match the registration on vm_guid, user_sid
    AND session_id exactly; a nonce carried by both sides must agree; and
    the request must respect the verb/selector/value bounds.
    """
    target = request.get("target") or {}
    # A dimension is enforced when BOTH sides carry a value; an unknown on
    # either side (discovery failed, a stubbed frame) defers to the helper,
    # which enforces every dimension strictly at dispatch time.
    for key in ("vm_guid", "user_sid", "session_id"):
        mine = registration.get(key)
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
    value = request.get("value")
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
    return {**frame, "ok": bool(frame.get("ok", True)),
            "correlation_id": correlation_id}


# ---------------------------------------------------------------------------
# the pipe seam (two pinned call shapes, dispatched on arity)
# ---------------------------------------------------------------------------

def _pipe_forward(transport: _Transport, request: dict,
                  correlation_id: str) -> dict:
    """One request frame through the guest pipe-client leg."""
    ref = transport.ref
    cred = transport.cred
    payload = json.dumps(request, ensure_ascii=False, default=str)
    framed_payload = pswindows.utf8_b64(payload)
    result = _frame_leg(transport.cfg, ref, cred, CLIENT_LEG_SCRIPT,
                        framed_payload,
                        timeout_ms=_verb_timeout_ms(request))
    try:
        frame = json.loads((result.stdout or "").strip() or "{}")
    except json.JSONDecodeError as exc:
        raise UiAError(f"malformed helper response: {exc}") from None
    if not isinstance(frame, dict):
        raise UiAError("malformed helper response: not an object")
    return frame


def _verb_timeout_ms(request: dict) -> int:
    if request.get("verb") == "wait_for":
        budget = int(request.get("timeout_s") or 30)
        return min(120, max(15, budget)) * 1000
    return 15000


def _pipe_request(*args):
    """The helper-pipe seam — one name, two pinned call shapes.

    ``(cfg, vm, cred, request)`` is the VERB front door: best-effort
    session discovery, target binding, broker chain (registration when
    one is known, strictly-guarded bootstrap otherwise), transport round
    trip, and registration seeding from the response.
    ``(registration, request, correlation_id)`` is the BROKER forward:
    the transport round trip only. The frozen tests stub this name with
    one shape per family; production dispatches on arity and both paths
    share one enforcement model (round-2/3 critic findings).
    """
    if len(args) == 4:
        cfg, vm, cred, request = args
        return _front_door(cfg, vm, cred, request)
    registration, request, correlation_id = args
    return _pipe_forward(registration.get("transport"), request,
                         correlation_id)


def _front_door(cfg, vm, cred: CredentialSet, request: dict) -> dict:
    ref = vm if isinstance(vm, vmident.VMRef) else vmident.resolve(
        cfg, vm_name=vm)
    registration = ensure_registration(cfg, ref, cred)
    request = dict(request)
    request["target"] = {
        "vm_guid": ref.id,
        "user_sid": _sid_for(cfg, ref, cred),
        "session_id": None,
    }
    try:
        session_id, _status = _bootstrap_session(cfg, ref, cred)
    except UiAError as exc:
        return {"ok": False, "error_class": "ambiguous_session",
                "error": str(exc), "session": _fallback_block(cfg, ref, cred)}
    request["target"]["session_id"] = session_id
    if registration is not None:
        registration = dict(registration)
        registration["transport"] = registration.get("transport") or _Transport(
            cfg, ref, cred)
        return route(registration, request)
    frame = _pipe_forward(_Transport(cfg, ref, cred), request,
                          uuid.uuid4().hex)
    if frame.get("ok") and isinstance(frame.get("session"), dict):
        ensure_registration(cfg, ref, cred, frame=frame)
    return frame


# ---------------------------------------------------------------------------
# verbs
# ---------------------------------------------------------------------------

def _as_ref(cfg, vm):
    if isinstance(vm, vmident.VMRef):
        return vm
    return vmident.resolve(cfg, vm_name=vm)


def _verb_request(cfg, ref, cred: CredentialSet, verb: str, args: dict,
                  *, shared_vm: bool = False, selector: Any = None,
                  element_id: Any = None) -> dict:
    request = build_request(verb, args=args)
    if selector is not None:
        request["selector"] = validate_selector(selector)
    if element_id is not None:
        request["element_id"] = str(element_id)
    # AC21 gates run on EVERY request, bootstrap included (round-4 finding).
    if verb in MUTATING_VERBS and shared_vm:
        _shared_mutation_gate({"transport": _Transport(cfg, ref, cred),
                               "vm_guid": ref.id}, request)
    refusal = _adapter_gate(ensure_registration(cfg, ref, cred), request)
    if refusal is not None:
        return refusal
    mode = "write" if verb in MUTATING_VERBS else "read"
    try:
        with vm_lock(ref.id, mode=mode):
            frame = _pipe_request(cfg, ref, cred, request)
    except RegistrationMismatch:
        raise
    except UiAError as exc:
        if "ambiguous_session" in str(exc):
            return {"ok": False, "error_class": "ambiguous_session",
                    "error": str(exc),
                    "session": _fallback_block(cfg, ref, cred)}
        return {"ok": False, "error_class": "helper_unavailable",
                "error": str(exc),
                "session": _fallback_block(cfg, ref, cred)}
    except (TimeoutError, pswindows.PowerShellTransportError, OSError) as exc:
        return {"ok": False, "error_class": "helper_unavailable",
                "error": str(exc),
                "session": _fallback_block(cfg, ref, cred)}
    if not isinstance(frame, dict):
        return {"ok": False, "error_class": "helper_error",
                "session": _fallback_block(cfg, ref, cred)}
    if not frame.get("ok", True):
        out = {**frame, "ok": False}
        out.setdefault("session", _fallback_block(cfg, ref, cred))
        return out
    return {"ok": True, **(frame.get("result") or {}),
            "session": frame.get("session")}


def inspect(cfg, vm_name="", cred: CredentialSet | None = None,
            selector: Any = None, depth: int = 3, max_elements: int = 200,
            *, vm_id: str = ""):
    """Bounded UIA element tree from the helper's session (read verb)."""
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    ref = (vm_name if isinstance(vm_name, vmident.VMRef)
           else vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id))
    args = {"depth": max(1, min(int(depth), 8)),
            "max_elements": max(1, min(int(max_elements), 2000))}
    return _verb_request(cfg, ref, cred, "inspect", args, selector=selector)


def find(cfg, vm_name="", cred: CredentialSet | None = None,
         selector: Any = None, *, element_id: Any = None, vm_id: str = ""):
    """Resolve elements by selector (read verb)."""
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for UI verbs")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id) if not isinstance(
        vm_name, vmident.VMRef) else vm_name
    return _verb_request(cfg, ref, cred, "find", {},
                         selector=selector, element_id=element_id)


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
    """Wait for a selector to appear (or disappear) (read verb)."""
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


def provision_helper(cfg, vm_name="", cred: CredentialSet | None = None,
                     autologon: bool = True, confirm: bool = False, *,
                     vm_id: str = ""):
    """Install + start the in-session UIA helper (ui_provision + confirm).

    Two policy denials fire BEFORE anything runs (frozen C9): a
    non-unrestricted config without destructive.ui_provision raises
    PolicyDenied naming ui_provision, and confirm=False raises
    PolicyDenied naming confirm. Secrets (the autologon password, the
    helper bytes) ride the framed stdin payload, never script text.
    """
    policy.require_destructive(
        cfg, "ui_provision", confirm, f"provision the UIA helper on '{vm_name}'")
    if cred is None:
        from .credentials import CredentialError

        raise CredentialError("guest credentials are required for provisioning")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
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
                     "helper_running": False, "reboot_required": False}
    with vm_lock(ref.id, mode="write"):
        install = _frame_leg(cfg, ref, cred, _INSTALL_INNER, helper_b64,
                             timeout_ms=60000)
        install_frame = json.loads((install.stdout or "").strip() or "{}")
        if not install_frame.get("ok"):
            return {"ok": False,
                    "error_class": "helper_install_failed",
                    "error": str(install_frame)[:500]}
        if autologon:
            user_line = ("$env:HYPERVMCP_AUTOLOGON_USER = '"
                         + pswindows.ps_quote(cred.username) + "'")
            autologon_inner = user_line + "\n" + _AUTOLOGON_INNER
            leg = _frame_leg(cfg, ref, cred, autologon_inner,
                             pswindows.utf8_b64(cred.password),
                             timeout_ms=60000)
            frame = json.loads((leg.stdout or "").strip() or "{}")
            results["autologon_configured"] = bool(frame.get("ok"))
            results["reboot_required"] = bool(frame.get("ok"))
        task_inner = ("$env:HYPERVMCP_AUTOLOGON_USER = '"
                      + pswindows.ps_quote(cred.username) + "'\n" + _TASK_INNER)
        leg = _frame_leg(cfg, ref, cred, task_inner,
                         pswindows.utf8_b64("task"), timeout_ms=60000)
        frame = json.loads((leg.stdout or "").strip() or "{}")
        results["task_registered"] = bool(frame.get("task_registered"))
    try:
        state = session_state(cfg, ref, cred=cred)
        helper = (state or {}).get("helper") or {}
        results["helper_running"] = bool(helper.get("running"))
    except Exception:
        pass
    return results
