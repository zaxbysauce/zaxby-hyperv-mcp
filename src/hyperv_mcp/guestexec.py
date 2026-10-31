"""Guest command/script execution via PowerShell Direct (VMBus, no network).

Transport: the inner script is base64-encoded, and the guest temp .ps1 is
created INSIDE the guest scriptblock (PowerShell remoting does not carry
caller scope — host-side variables would arrive as $null), then executed by a
child powershell inside the guest:
  - non-elevated: Start-Process -RedirectStandardOutput/-RedirectStandardError
    gives TRUE stdout/stderr separation and a real exit code.
  - elevated: Start-Process -Verb RunAs cannot combine with the redirect
    parameters, so the child redirects its own merged stream (`*>`); stdout
    carries both streams and stderr is reported empty — documented behavior.
Start-Process parameters are splatted so the invocation is ONE statement (a
bare continuation line after `-ArgumentList @(...)` parses as a separate
command on PS 5.1 — regression-tested). The scriptblock emits its result
object raw and the host converts once (double-encoding would make the host
see a JSON string instead of a dict).

Host timeout kills the host-side process tree (Job Object); the guest-side
child may keep running — the result says so explicitly. Guest temp files are
removed in finally blocks; a host timeout can leak them in the guest %TEMP%
(documented residual, surfaced by integration cleanup reports).
"""

from __future__ import annotations

import json
import re

from . import credentials, policy, psdsessions, pswindows, timing, vmident, vmlocks
from .config import Config
from .credentials import CredentialSet

GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def validate_vm_guid(guid: str) -> str:
    """Raise ValueError unless guid is a well-formed VM GUID.

    Gate for every PYTHON-side binding of a caller-supplied id:
    vmident.resolve, vm_target_preamble and psdirect_vm_target_id all call
    this before the GUID reaches a generated script. (Console's %GUID%
    templating substitutes the already-validated ref.id returned by
    vmident.resolve; the resolver's own PS-side anchored match remains the
    authoritative shape filter.)
    """
    # fullmatch: a `$`-anchored match would accept a trailing newline, which
    # survives into VMRef.id and splits the vm_lock key space (review PRR-012).
    if not isinstance(guid, str) or not GUID_RE.fullmatch(guid):
        raise ValueError(f"vm_id is not a valid VM GUID: {guid!r}")
    return guid

_GRACE_S = 10

# Emitted immediately BEFORE the user's command/script invoke in every sync
# builder (PRR-003 / CUB-7): $LASTEXITCODE survives later cmdlets, so a stale
# code set before the invoke could mask the invoke's own failure in the
# LE-first tail below. With the reset, any code the tail sees was set by the
# invoked command itself. The tail keeps LE-first precedence: a native exit
# N still propagates N; a failing cmdlet with no code exits 1.
_LE_RESET = "$global:LASTEXITCODE = $null"

_EXIT_PROPAGATION = (
    "$ok = $?"
    "\nif ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE } "
    "elseif ($ok) { exit 0 } else { exit 1 }"
)


def psdirect_prefix(cred: CredentialSet, cfg=None) -> str:
    """PSCredential construction lines; the password arrives via stdin b64.

    Local mode (cfg None or no hyperv.host): byte-identical to the historic
    emission — the exact lines are pinned by tests/unit/test_guestexec.py.

    Remote mode (issue #43): the whole envelope executes inside the remote
    scriptblock, which cannot read local stdin; the password line was read
    by the composer's local preamble and crossed the hop as the scriptblock
    parameter $__p0, so the first line consumes that parameter instead.
    """
    first = (
        "$secRaw = $__p0"
        if pswindows.hyperv_host(cfg)
        else "$secRaw = [Console]::In.ReadLine()"
    )
    return "\n".join([
        first,
        "$secText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($secRaw))",
        "$sec = $secText | ConvertTo-SecureString -AsPlainText -Force",
        f"$cred = [System.Management.Automation.PSCredential]::new({pswindows.ps_quote(cred.username)}, $sec)",
        "$secRaw = $null; $secText = $null; $sec = $null",
    ])


def psdirect_vm_target(vm_name: str) -> str:
    """PowerShell lines resolving the VM GUID into $vmTarget (caller emits it).

    Invoke-Command -VMName and Get-VM -Name intermittently fail with 'does not
    resolve to a single virtual machine' or 'Call cancelled' when the vmms WMI
    provider is under stress, even with a unique name. Resolving the GUID once
    via the virtualization CIM namespace and binding by -VMId/-Id everywhere is
    deterministic; the bounded retry rides out transient WMI cancellations.
    The filter is a literal -eq (ps_quote, no wildcard escaping — wildcard
    chars are inert by construction) restricted to GUID-shaped Msvm_ComputerSystem
    instances (full 8-4-4-4-12 shape, anchored), because the namespace also contains the HOST computer system
    (observed live: ElementName='VSAN', Name='VSAN' — not a GUID), which would
    otherwise hijack resolution when the VM name equals the host name. A
    duplicate VM name is ambiguous exactly like the old -VMName binding, so it
    throws instead of silently picking one. NOTE: the emitted script only
    ASSIGNS $vmTarget — append a bare '$vmTarget' line (or consume it in a
    larger script) when the value itself must be captured.
    """
    return "\n".join([
        "$vmTarget = $null",
        "$vmResolveError = ''",
        "$vmFinal = $false",
        "foreach ($vmAttempt in 1..3) {",
        "    try {",
        "        $vmCandidates = @(",
        "            Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem"
        " -ErrorAction Stop |",
        f"            Where-Object {{ ($_.ElementName -eq {pswindows.ps_quote(vm_name)})"
        " -and ($_.Name -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') }",
        "        )",
        "        $vmResolveError = ''",
        "        if ($vmCandidates.Count -gt 1) {",
        "            $vmResolveError = 'target VM name is not unique; candidates: ' + (($vmCandidates | ForEach-Object { $_.ElementName + '=' + $_.Name }) -join ', ')",
        "            $vmFinal = $true",
        "            break",
        "        }",
        "        if ($vmCandidates.Count -eq 1) {",
        "            $vmTarget = $vmCandidates[0].Name",
        "            break",
        "        }",
        "        # A clean enumeration with no match is authoritative: do not retry.",
        "        $vmResolveError = 'target VM not found by name'",
        "        $vmFinal = $true",
        "        break",
        "    } catch {",
        "        $vmResolveError = $_.Exception.Message",
        "    }",
        "    if ($vmAttempt -lt 3) { Start-Sleep -Seconds 2 }",
        "}",
        "if (-not $vmTarget) {",
        "    if (-not $vmResolveError) { $vmResolveError = 'target VM not found by name' }",
        "    if ($vmFinal) { throw ('target VM resolution failed: {0}' -f $vmResolveError) }",
        "    throw ('target VM resolution failed after retries: {0}' -f $vmResolveError)",
        "}",
    ])


def psdirect_vm_target_id(guid: str) -> str:
    """PowerShell lines addressing a VM by its validated GUID and emitting the
    VM's NAME as the bare final stdout line (the by-id counterpart of the
    by-name resolver's bare `$vmTarget` emit; vmident.resolve consumes the
    name for the policy check). The GUID is regex-validated here and in
    vm_target_preamble, so only a well-formed literal can reach the script.
    """
    validate_vm_guid(guid)
    return "\n".join([
        f"$vmTarget = {pswindows.ps_quote(guid)}",
        "$vm = Get-VM -Id $vmTarget -ErrorAction Stop",
        "$vm.Name",
    ])


def vm_target_preamble(guid: str) -> str:
    """The action-script opener: bind $vmTarget to a validated GUID.

    Replaces the inline name-resolver embed in scripts whose caller has
    already resolved the identity host-side (vmident.resolve), so the lock
    key and the acted-on VM can never differ. Scripts that need a VM object
    keep their own `$vm = Get-VM -Id $vmTarget` fetch line after this.
    """
    validate_vm_guid(guid)
    return f"$vmTarget = {pswindows.ps_quote(guid)}"


def _truncate(value: str, limit_bytes: int) -> tuple[str, bool]:
    raw = value.encode("utf-8", "replace")
    if len(raw) <= limit_bytes:
        return value, False
    return raw[:limit_bytes].decode("utf-8", "ignore"), True


def _result_ok(cfg: Config, exit_code, stdout: str, stderr: str, vm_name: str = "") -> dict:
    stdout, t_out = _truncate(stdout, cfg.max_output_bytes)
    stderr, t_err = _truncate(stderr, cfg.max_output_bytes)
    return {
        "ok": True,
        "exit_code": int(exit_code) if exit_code is not None else None,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": False,
        "truncated": t_out or t_err,
        # Resolved display name (never the raw caller input) so the server's
        # audit adoption can attribute by-id calls (PRR-005).
        "vm_name": vm_name,
    }


def _result_err(cfg: Config, error: str, error_class: str) -> dict:
    error, _ = _truncate(pswindows.redact(error), cfg.max_output_bytes)
    return {"ok": False, "error": error, "error_class": error_class}


def _elevated_body() -> str:
    # -Verb RunAs rejects -RedirectStandardOutput; the child merges its own
    # streams via *> into one file, so stderr stays empty on this path.
    # Splatting keeps Start-Process a single statement.
    return """
$outf = [System.IO.Path]::GetTempFileName()
try {
    $q  = [char]39
    $dq = "$q$q"
    $cmdStr = '& ' + $q + $tmp.Replace($q, $dq) + $q + ' *> ' + $q + $outf.Replace($q, $dq) + $q
    $sp = @{
        FilePath     = 'powershell.exe'
        ArgumentList = @('-NonInteractive', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmdStr)
        Verb         = 'RunAs'
        Wait         = $true
        PassThru     = $true
    }
    $p = Start-Process @sp
    $ec = if ($null -ne $p) { $null = $p.Handle; $p.ExitCode } else { $null }
    $so = if (Test-Path -LiteralPath $outf) { [System.IO.File]::ReadAllText($outf) } else { '' }
    $se = ''
} finally {
    Remove-Item -LiteralPath $tmp, $outf -Force -ErrorAction SilentlyContinue
}
"""


def _normal_body() -> str:
    return """
$outf = [System.IO.Path]::GetTempFileName()
$errf = [System.IO.Path]::GetTempFileName()
try {
    $sp = @{
        FilePath               = 'powershell.exe'
        ArgumentList           = @('-NonInteractive', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $tmp)
        Wait                   = $true
        PassThru               = $true
        WindowStyle            = 'Hidden'
        RedirectStandardOutput = $outf
        RedirectStandardError  = $errf
    }
    $p = Start-Process @sp
    $ec = if ($null -ne $p) { $null = $p.Handle; $p.ExitCode } else { $null }
    $so = if (Test-Path -LiteralPath $outf) { [System.IO.File]::ReadAllText($outf) } else { '' }
    $se = if (Test-Path -LiteralPath $errf) { [System.IO.File]::ReadAllText($errf) } else { '' }
} finally {
    Remove-Item -LiteralPath $tmp, $outf, $errf -Force -ErrorAction SilentlyContinue
}
"""


def _host_script(vm_id: str, inner_script: str, cred: CredentialSet, elevated: bool, cfg=None) -> str:
    body = _elevated_body() if elevated else _normal_body()
    # $enc MUST be passed via -ArgumentList (the comment at the Invoke-Command
    # says so — regression F-A round 2 caught it missing) and the temp .ps1 is
    # created INSIDE the guest scriptblock: caller scope does not cross the
    # remoting boundary. GetRandomFileName avoids GetTempFileName's base .tmp
    # residue (a fresh unique name, no side-effect file to clean up). The VM
    # is addressed by the pre-resolved GUID ($vmTarget preamble, vmident).
    #
    # The trailing __MCP_TIMING= line is the per-call cost breakdown (issue
    # #20). pswindows.run_ps splits it off stdout BEFORE any tool parses that
    # stdout — including before _run_inner's json.loads, which would otherwise
    # see "Extra data" — and feeds the values to the active call's collector.
    # Emitter and stripper ship together for that reason.
    #
    #   ps_startup_ms         host process start -> this script's first
    #                         statement. Honestly ordered (feedback PRR-017):
    #                         that first statement runs AFTER the transport's
    #                         _PS_PIN preamble ($ProgressPreference and
    #                         [Console]::OutputEncoding — and, on a remote
    #                         Hyper-V host, the WS-Man hop's own pins), so the
    #                         number INCLUDES those pin statements and the
    #                         EncodedCommand decode, not just bare startup.
    #   psdirect_session_ms   the Invoke-Command: PS Direct session setup plus
    #                         the guest round trip (what session reuse removes)
    #   guest_ms              the guest-side work, measured inside the scriptblock
    #
    # Every literal brace below is doubled because this is an f-string; see the
    # `}} -ArgumentList $enc` and `[PSCustomObject]@{{ ... }}` lines that were
    # already doubled. ps_startup_ms and psdirect_session_ms are cast to [int]
    # so ConvertTo-Json emits JSON integers the int-only marker parser accepts.
    # guest_ms is NOT cast from $null: a result object with no duration_ms
    # emits JSON null (PRR-017), which the parser drops — the field reads as
    # absent in the audit record, never as a fabricated "zero milliseconds".
    return f"""
$__mcpBorn = [Diagnostics.Process]::GetCurrentProcess().StartTime
$__mcpBornMs = [int]((Get-Date) - $__mcpBorn).TotalMilliseconds
{psdirect_prefix(cred, cfg)}
{vm_target_preamble(vm_id)}
$enc = '{pswindows.utf8_b64(inner_script)}'
$__mcpSw = [Diagnostics.Stopwatch]::StartNew()
$r = Invoke-Command -VMId $vmTarget -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($enc)
    $__mcpGuest = [Diagnostics.Stopwatch]::StartNew()
    $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc))
    $tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName() + '.ps1')
    [System.IO.File]::WriteAllText($tmp, $text, [System.Text.UTF8Encoding]::new($false))
{body}
    [PSCustomObject]@{{ exit_code=$ec; stdout=$so; stderr=$se; duration_ms=$__mcpGuest.ElapsedMilliseconds }}
}} -ArgumentList $enc
$__mcpSessionMs = $__mcpSw.ElapsedMilliseconds
$r | ConvertTo-Json -Compress -Depth 2
$__mcpGuestMs = if ($null -ne $r.duration_ms) {{ [int]$r.duration_ms }} else {{ $null }}
"__MCP_TIMING=" + (@{{ ps_startup_ms=[int]$__mcpBornMs; psdirect_session_ms=[int]$__mcpSessionMs; guest_ms=$__mcpGuestMs }} | ConvertTo-Json -Compress)
"""


def _pooled_pool(cfg: Config):
    """The pool this call may use, or None.

    Four conditions, all required: the config switch is on, a pool is installed,
    the mode is LOCAL (a pooled worker would have to be spawned on the remote
    host through a second transport this change does not add — issue #43), and a
    credential is available. Anything else takes the per-call path unchanged,
    which is what every unit test and every flag-off deployment exercises.

    The flag is read with the SCHEMA's default, not `False`: an attribute-missing
    config object means "not configured", and `Config.psdirect_session_reuse`
    defaults to True, so a defensive `False` here would silently invert the
    documented default while `policy_summary` still printed `True`.
    """
    if not getattr(cfg, "psdirect_session_reuse", True):
        return None
    if pswindows.hyperv_host(cfg):
        return None
    pool = psdsessions.DEFAULT
    return pool if pool is not None and not pool.stats().get("closed") else None


def _session_key(
    vm_id: str, cred: CredentialSet, role: str = "guest",
) -> psdsessions.SessionKey:
    """The pool key for one guest call: (VM GUID, credential profile, agent id,
    boot epoch). The agent id is the authenticated bearer-token client_id and is
    None on the paths that carry no identity — README.md:906-909 documents that
    in those modes all callers form one local principal, so None is one bucket
    rather than a blocker.

    ``role`` separates the admin and victim identities (issue #30): both
    resolve through the SAME named profile on one VM, so the role must widen
    the credential-profile component or a victim call could inherit an admin
    session (pinned by C19/C27 as ``<profile>#victim``)."""
    from . import auditlog

    component = psdsessions.credential_profile(cred)
    if role == "victim":
        component = f"{component}#victim"
    return psdsessions.SessionKey(
        vm_guid=vm_id,
        cred_profile=component,
        agent_id=auditlog.current_agent_id(),
        boot_epoch=None,
    )


def _run_pooled_raw(
    cfg: Config,
    pool,
    vm_id: str,
    inner_script: str,
    cred: CredentialSet,
    timeout_ms: int,
    elevated: bool = False,
    session_role: str = "guest",
):
    """Run one inner script over a REUSED PowerShell Direct session.

    Returns the worker's result, or None to fall back to the per-call path.

    The fallback is the load-bearing property: the pooled path is an
    optimisation, so it must never be able to fail a call the per-call path
    would have served. It falls back whenever it cannot produce a DEFINITIVE
    guest result — the pool is busy, the worker could not be spawned, the worker
    died, or two consecutive attempts failed at the session phase. A guest-phase
    result is definitive and is reported as-is.

    On a session-phase failure the worker is discarded and the call is retried
    exactly once on a fresh session; a guest-phase failure is a RESULT, not a
    transport fault, and is never retried — the guest already ran the script.
    An "unknown" outcome (the worker died, or answered unreadably) is reported
    as a transport failure without a retry and without a per-call fallback,
    because neither can prove the guest script never ran.
    """
    if pool is None:
        return None
    key = _session_key(vm_id, cred, role=session_role)
    # Bounded by the VM-lock budget, not the host-PowerShell one: this wait runs
    # INSIDE `vm_lock(mode="read")`, and a 60 s park here would hold the read
    # lock far past the `vm_lock_wait_s` a queued lifecycle writer is prepared
    # to wait (FND-02).
    wait_s = min(
        float(getattr(cfg, "host_powershell_wait_s", 0.0) or 0.0),
        float(getattr(cfg, "vm_lock_wait_s", 0.0) or 0.0),
    )
    try:
        worker = pool.acquire(key, wait_s, cred=cred)
    except Exception:
        return None

    def _attempt(session):
        result = session.run(inner_script, elevated=elevated, timeout_ms=timeout_ms)
        if result.timed_out:
            # A per-call timeout kills the worker (the guest work may still be
            # running); it must never be handed out again. The result itself is
            # definitive and is reported.
            pool.discard(session)
        return result

    try:
        opened_ms = pool.take_open_cost(worker)
        result = _attempt(worker)
        _report_pooled_timing(result, opened_ms)
        if not result.timed_out and _phase(result) == "session":
            pool.discard(worker)
            try:
                worker = pool.acquire(key, wait_s, cred=cred)
            except Exception:
                return None
            try:
                result = _attempt(worker)
                _report_pooled_timing(result, pool.take_open_cost(worker))
            except Exception:
                pool.discard(worker)
                return None
            if not result.timed_out and _phase(result) == "session":
                # Two session-phase failures and still no guest-side effect:
                # hand the call to the per-call path rather than report a
                # transport error the caller could have avoided.
                pool.discard(worker)
                return None
        return result
    except Exception:
        pool.discard(worker)
        return None
    finally:
        pool.release(worker)


def _report_pooled_timing(result, opened_ms: int | None) -> None:
    """Feed the audit timing collector for one pooled call.

    Honest by construction: a call that OPENED the worker reports the spawn and
    session-establishment cost it actually paid (`ps_spawns` incremented, the
    full trio); a call that REUSED a session reports the host-side time the
    worker really spent and increments no spawn, because no process was started.
    Without this the pooled path would be invisible in the audit record and the
    before/after comparison `soak_bench --session-reuse` exists to make would
    have nothing to compare.
    """
    collector = timing.current()
    if collector is None:
        return
    payload = _pooled_payload(result) or {}
    guest_ms = payload.get("duration_ms")
    if not isinstance(guest_ms, int):
        guest_ms = getattr(result, "guest_ms", None)
    if opened_ms is None:
        # A reused session: charge the worker's real host-side round trip, which
        # is the work this call actually caused, and claim no spawn.
        collector.add_pooled(
            int(getattr(result, "duration_ms", 0) or 0),
            {"guest_ms": guest_ms},
            spawned=False,
        )
        return
    collector.add_pooled(
        opened_ms,
        {
            "ps_startup_ms": opened_ms,
            # The session-establishment cost, measured HOST-SIDE across the
            # spawn and the handshake read. `PooledResult` carries no
            # `session_ms`, so this is the pool's own measurement rather than
            # the worker's; the request's round trip is charged to `ps_ms`
            # instead, so the marker does not silently mean two things.
            "psdirect_session_ms": opened_ms,
            "guest_ms": guest_ms,
        },
        spawned=True,
    )


def pooled_guest_payload(result):
    """The guest-side payload from a pooled worker's response.

    A pooled worker reports the per-call wrapper — `{exit_code, stdout, stderr,
    duration_ms}` — because it runs the SAME capture body the per-call host
    script runs. Callers whose inner script's stdout IS the payload (diagnostics,
    filetransfer) therefore have to take one more step than the per-call path
    and read `stdout`. Returning it here keeps that unwrap in one place.
    """
    payload = _pooled_payload(result)
    if payload is None:
        return {}
    raw = payload.get("stdout")
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        return {}


def _pooled_payload(result) -> dict | None:
    """The JSON object a pooled worker's response carries, or None if there
    isn't one. Every caller already json.loads this on the per-call path, so the
    pooled path reuses that exact unwrap rather than inventing a second shape."""
    raw = (getattr(result, "stdout", "") or "").strip()
    if not raw:
        # NO wrapper at all. Parsing this as "{}" would make an empty answer
        # read as a completed guest run with no fields, which is exactly the
        # misreading `_phase`'s "unknown" class exists to prevent.
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _phase(result) -> str:
    """Classify a pooled worker's response as "session", "guest" or "unknown".

    - "session" — the worker's OWN failure frame says the session failed. Those
      frames are emitted by guards that run BEFORE the guest scriptblock is
      entered, so they prove no guest-side effect happened. Only this class is
      retryable on a fresh session.
    - "guest" — the guest scriptblock ran and produced a result. Definitive;
      never retried, because the guest already did the work.
    - "unknown" — the worker died or answered with something unreadable. This
      says nothing about whether the guest ran, so it is neither retried nor
      silently re-run through the per-call fallback: both would repeat a script
      that may already have had its effect.

    The distinction is load-bearing. Treating "unknown" as "session" — which is
    what a missing return code or an undecodable frame alone would suggest —
    makes the retry re-run a script that already ran in the guest.
    """
    payload = _pooled_payload(result)
    if payload is not None:
        # A wrapper exists, so the guest scriptblock ran far enough to report on
        # itself. Its own `phase` is the worker's statement about whether it
        # ever entered the inner script, and it is the ONLY retryable signal.
        return "session" if payload.get("phase") == "session" else "guest"
    # No wrapper: the worker died, timed out, or answered with something
    # unreadable. That says nothing about whether the guest ran.
    return "unknown"


def _run_pooled(
    cfg: Config,
    pool,
    vm_id: str,
    inner_script: str,
    cred: CredentialSet,
    timeout_ms: int,
    elevated: bool,
    session_role: str = "guest",
) -> dict | None:
    """The `_run_inner` envelope over a pooled call, or None to fall back."""
    result = _run_pooled_raw(
        cfg, pool, vm_id, inner_script, cred, timeout_ms, elevated, session_role,
    )
    if result is None:
        return None
    return _pooled_envelope(cfg, result, elevated, timeout_ms)


def _pooled_envelope(cfg: Config, result, elevated: bool, timeout_ms: int = 0) -> dict:
    """Turn a pooled worker's response into the same envelope _run_inner returns.

    The worker's own wrapper is read FIRST: it is the only thing that carries the
    worker's real error and its phase, and a failure frame deliberately has no
    `exit_code` — so testing the host-leg shape first would discard both and
    report a generic transport or parse error instead.
    """
    if result.timed_out:
        timeout_s = max(30, timeout_ms // 1000 + _GRACE_S) if timeout_ms else 30
        return {
            **_result_err(
                cfg,
                f"host timeout after {timeout_s}s; guest execution may still be running",
                "timeout",
            ),
            "timed_out": True,
        }
    raw = (result.stdout or "").strip()
    data = None
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            return _result_err(
                cfg, f"guest result JSON parse failed: {exc} | raw: {raw[:200]!r}", "parse"
            )
        if isinstance(parsed, dict):
            data = parsed
    if data is not None and data.get("ok") is False:
        return _result_err(
            cfg,
            str(data.get("error") or "pooled session failure"),
            "transport" if data.get("phase") == "session" else "guest",
        )
    if data is None or "exit_code" not in data:
        # No readable wrapper: this is a host-leg failure, not a guest result.
        if result.returncode is None:
            return _result_err(cfg, result.stderr or "pooled session failure", "transport")
        return _result_err(cfg, f"unexpected guest result shape: {raw[:200]!r}", "parse")
    exit_code = data.get("exit_code")
    if exit_code is None:
        return _result_err(cfg, "guest child process produced no exit code", "guest")
    out = _result_ok(
        cfg, exit_code, data.get("stdout") or "", data.get("stderr") or "", vm_name=""
    )
    if elevated:
        out["note"] = (
            "elevated run: guest stdout/stderr are merged (RunAs cannot redirect streams); "
            "stderr is reported empty"
        )
    return out


def _run_inner(
    cfg: Config,
    vm_id: str,
    inner_script: str,
    cred: CredentialSet,
    timeout_ms: int,
    elevated: bool,
    vm_name: str = "",
    session_role: str = "guest",
) -> dict:
    """Run one inner script on the VM identified by the pre-resolved GUID.

    GUID-native: the caller resolved the identity (vmident.resolve, which
    also ran the VM policy) and holds the per-VM lock on the same GUID.

    Takes the pooled path when reuse is enabled and a pool is installed, and the
    per-call path otherwise (issue #21). The two paths produce the same envelope.
    """
    pool = _pooled_pool(cfg)
    if pool is not None:
        pooled = _run_pooled(
            cfg, pool, vm_id, inner_script, cred, timeout_ms, elevated, session_role,
        )
        if pooled is not None:
            if vm_name:
                pooled["vm_name"] = vm_name
            return pooled
    timeout_s = max(30, timeout_ms // 1000 + _GRACE_S)
    try:
        script, stdin = pswindows.compose_remote(
            cfg,
            _host_script(vm_id, inner_script, cred, elevated, cfg).strip(),
            payload_lines=1,
            stdin_b64=pswindows.utf8_b64(cred.password),
        )
        result = pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=stdin)
    except credentials.CredentialError as exc:
        # Remote-mode host-credential configuration errors are caller
        # configuration, not transport (cubic PR #47 finding).
        return _result_err(cfg, str(exc), "invalid")
    except Exception as exc:  # transport-level failure, redacted by pswindows
        # issue #15: classify truthfully — PowerShellBusy reports busy/retryable
        # instead of a non-retryable transport result; unknown types still
        # default to "transport" inside classify. Late import: a module-level
        # errors import cycles (errors -> media -> lifecycle -> guestexec).
        from . import errors

        return _result_err(cfg, str(exc), errors.classify(exc))

    if result.timed_out:
        return {
            **_result_err(
                cfg,
                f"host timeout after {timeout_s}s; guest execution may still be running",
                "timeout",
            ),
            "timed_out": True,
        }
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        return _result_err(cfg, detail, "transport")

    raw = result.stdout.strip()
    if not raw:
        return _result_err(cfg, "no output from guest", "parse")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _result_err(cfg, f"guest result JSON parse failed: {exc} | raw: {raw[:200]!r}", "parse")

    if not isinstance(data, dict) or "exit_code" not in data:
        return _result_err(cfg, f"unexpected guest result shape: {raw[:200]!r}", "parse")

    exit_code = data.get("exit_code")
    if exit_code is None:
        return _result_err(cfg, "guest child process produced no exit code", "guest")

    out = _result_ok(cfg, exit_code, data.get("stdout") or "", data.get("stderr") or "", vm_name=vm_name)
    if elevated:
        out["note"] = (
            "elevated run: guest stdout/stderr are merged (RunAs cannot redirect streams); "
            "stderr is reported empty"
        )
    return out


# ---------------------------------------------------------------------------
# public operations
# ---------------------------------------------------------------------------

def guest_run_ps(
    cfg: Config,
    vm_name: str = "",
    script: str = "",
    *,
    timeout_ms: int = 60000,
    elevated: bool = False,
    confirm: bool = False,
    cred: CredentialSet | None = None,
    vm_id: str = "",
    session_role: str = "guest",
) -> dict:
    if (not vm_name and not vm_id) or not script:
        raise ValueError("vm_name (or vm_id) and script are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    if elevated:
        policy.require_destructive(cfg, "elevated_exec", confirm, f"run an elevated script on '{ref.name}'")
    with vmlocks.vm_lock(ref.id, mode="read"):
        inner = f"{_LE_RESET}\n{script}\n{_EXIT_PROPAGATION}"
        return _run_inner(
            cfg, ref.id, inner, cred, timeout_ms, elevated,
            vm_name=ref.name, session_role=session_role,
        )


def guest_run(
    cfg: Config,
    vm_name: str = "",
    command: str = "",
    args: list[str] | None = None,
    cwd: str | None = None,
    *,
    timeout_ms: int = 60000,
    elevated: bool = False,
    confirm: bool = False,
    cred: CredentialSet | None = None,
    vm_id: str = "",
    session_role: str = "guest",
) -> dict:
    if (not vm_name and not vm_id) or not command:
        raise ValueError("vm_name (or vm_id) and command are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    if elevated:
        policy.require_destructive(cfg, "elevated_exec", confirm, f"run '{command}' elevated on '{ref.name}'")

    arg_array = pswindows.ps_native_args(list(args or []))
    invoke = f"& {pswindows.ps_quote(command)} {arg_array}".strip()
    lines = []
    if cwd:
        lines.append("Push-Location")
        lines.append(f"try {{ Set-Location -LiteralPath {pswindows.ps_quote(cwd)} -ErrorAction Stop")
    # Reset stale $LASTEXITCODE AFTER the optional Set-Location and
    # immediately BEFORE the invoke (see _LE_RESET).
    lines.append(_LE_RESET)
    lines.append(invoke)
    if cwd:
        # The tail must sit INSIDE the try: outside it, `$ok = $?` would
        # capture Pop-Location's success (always $true) and a failing command
        # would still exit 0. `exit` inside a try still runs the finally
        # block and preserves the code (verified on PS 5.1).
        lines.append(_EXIT_PROPAGATION)
        lines.append("} finally { Pop-Location }")
    else:
        lines.append(_EXIT_PROPAGATION)
    with vmlocks.vm_lock(ref.id, mode="read"):
        return _run_inner(
            cfg, ref.id, "\n".join(lines), cred, timeout_ms, elevated,
            vm_name=ref.name, session_role=session_role,
        )


def victim_run_ps(
    cfg: Config,
    vm_name: str = "",
    script: str = "",
    *,
    timeout_ms: int = 60000,
    cred: CredentialSet | None = None,
    vm_id: str = "",
) -> dict:
    if cred is None:
        raise ValueError("victim credentials are required")
    if (not vm_name and not vm_id) or not script:
        raise ValueError("vm_name (or vm_id) and script are required")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    with vmlocks.vm_lock(ref.id, mode="read"):
        inner = f"{_LE_RESET}\n{script}\n{_EXIT_PROPAGATION}"
        return _run_inner(
            cfg, ref.id, inner, cred, timeout_ms, elevated=False,
            vm_name=ref.name, session_role="victim",
        )


def victim_run(
    cfg: Config,
    vm_name: str = "",
    command: str = "",
    args: list[str] | None = None,
    cwd: str | None = None,
    *,
    timeout_ms: int = 60000,
    cred: CredentialSet | None = None,
    vm_id: str = "",
) -> dict:
    if cred is None:
        raise ValueError("victim credentials are required")
    if (not vm_name and not vm_id) or not command:
        raise ValueError("vm_name (or vm_id) and command are required")
    # guest_run resolves once (VM policy included) — no double resolution.
    # The victim role rides the delegation so the pooled session key stays
    # victim-separated from an admin session on the same VM/profile (issue
    # #30, pinned by C19/C27).
    return guest_run(
        cfg, vm_name, command, args, cwd,
        timeout_ms=timeout_ms, elevated=False, confirm=False, cred=cred, vm_id=vm_id,
        session_role="victim",
    )
