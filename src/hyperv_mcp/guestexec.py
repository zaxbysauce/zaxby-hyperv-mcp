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

from . import policy, pswindows, vmlocks
from .config import Config
from .credentials import CredentialSet

_GRACE_S = 10

_EXIT_PROPAGATION = (
    "if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE } else { exit 0 }"
)


def psdirect_prefix(cred: CredentialSet) -> str:
    """PSCredential construction lines; the password arrives via stdin b64."""
    return "\n".join([
        "$secRaw = [Console]::In.ReadLine()",
        "$secText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($secRaw))",
        "$sec = $secText | ConvertTo-SecureString -AsPlainText -Force",
        f"$cred = [System.Management.Automation.PSCredential]::new({pswindows.ps_quote(cred.username)}, $sec)",
        "$secRaw = $null; $secText = $null; $sec = $null",
    ])


def _truncate(value: str, limit_bytes: int) -> tuple[str, bool]:
    raw = value.encode("utf-8", "replace")
    if len(raw) <= limit_bytes:
        return value, False
    return raw[:limit_bytes].decode("utf-8", "ignore"), True


def _result_ok(cfg: Config, exit_code, stdout: str, stderr: str) -> dict:
    stdout, t_out = _truncate(stdout, cfg.max_output_bytes)
    stderr, t_err = _truncate(stderr, cfg.max_output_bytes)
    return {
        "ok": True,
        "exit_code": int(exit_code) if exit_code is not None else None,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": False,
        "truncated": t_out or t_err,
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


def _host_script(vm_name: str, inner_script: str, cred: CredentialSet, elevated: bool) -> str:
    n = pswindows.ps_name(vm_name)
    body = _elevated_body() if elevated else _normal_body()
    # $enc MUST be passed via -ArgumentList (the comment at the Invoke-Command
    # says so — regression F-A round 2 caught it missing) and the temp .ps1 is
    # created INSIDE the guest scriptblock: caller scope does not cross the
    # remoting boundary. GetRandomFileName avoids GetTempFileName's base .tmp
    # residue (a fresh unique name, no side-effect file to clean up).
    return f"""
{psdirect_prefix(cred)}
$enc = '{pswindows.utf8_b64(inner_script)}'
$r = Invoke-Command -VMName {n} -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($enc)
    $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc))
    $tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName() + '.ps1')
    [System.IO.File]::WriteAllText($tmp, $text, [System.Text.UTF8Encoding]::new($false))
{body}
    [PSCustomObject]@{{ exit_code=$ec; stdout=$so; stderr=$se }}
}} -ArgumentList $enc
$r | ConvertTo-Json -Compress -Depth 2
"""


def _run_inner(
    cfg: Config,
    vm_name: str,
    inner_script: str,
    cred: CredentialSet,
    timeout_ms: int,
    elevated: bool,
) -> dict:
    policy.vm_allowed(cfg, vm_name)
    timeout_s = max(30, timeout_ms // 1000 + _GRACE_S)
    try:
        result = pswindows.run_ps(
            _host_script(vm_name, inner_script, cred, elevated).strip(),
            timeout_s=timeout_s,
            stdin_b64=pswindows.utf8_b64(cred.password),
        )
    except Exception as exc:  # transport-level failure, redacted by pswindows
        return _result_err(cfg, str(exc), "transport")

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

    out = _result_ok(cfg, exit_code, data.get("stdout") or "", data.get("stderr") or "")
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
    vm_name: str,
    script: str,
    *,
    timeout_ms: int = 60000,
    elevated: bool = False,
    confirm: bool = False,
    cred: CredentialSet | None = None,
) -> dict:
    if not vm_name or not script:
        raise ValueError("vm_name and script are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)
    if elevated:
        policy.require_destructive(cfg, "elevated_exec", confirm, f"run an elevated script on '{vm_name}'")
    with vmlocks.vm_lock(vm_name):
        inner = f"{script}\n{_EXIT_PROPAGATION}"
        return _run_inner(cfg, vm_name, inner, cred, timeout_ms, elevated)


def guest_run(
    cfg: Config,
    vm_name: str,
    command: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    *,
    timeout_ms: int = 60000,
    elevated: bool = False,
    confirm: bool = False,
    cred: CredentialSet | None = None,
) -> dict:
    if not vm_name or not command:
        raise ValueError("vm_name and command are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)
    if elevated:
        policy.require_destructive(cfg, "elevated_exec", confirm, f"run '{command}' elevated on '{vm_name}'")

    arg_array = pswindows.ps_native_args(list(args or []))
    invoke = f"& {pswindows.ps_quote(command)} {arg_array}".strip()
    lines = []
    if cwd:
        lines.append("Push-Location")
        lines.append(f"try {{ Set-Location -LiteralPath {pswindows.ps_quote(cwd)} -ErrorAction Stop")
    lines.append(invoke)
    if cwd:
        lines.append("} finally { Pop-Location }")
    lines.append(_EXIT_PROPAGATION)
    with vmlocks.vm_lock(vm_name):
        return _run_inner(cfg, vm_name, "\n".join(lines), cred, timeout_ms, elevated)


def victim_run_ps(
    cfg: Config,
    vm_name: str,
    script: str,
    *,
    timeout_ms: int = 60000,
    cred: CredentialSet | None = None,
) -> dict:
    if cred is None:
        raise ValueError("victim credentials are required")
    if not vm_name or not script:
        raise ValueError("vm_name and script are required")
    policy.vm_allowed(cfg, vm_name)
    with vmlocks.vm_lock(vm_name):
        inner = f"{script}\n{_EXIT_PROPAGATION}"
        return _run_inner(cfg, vm_name, inner, cred, timeout_ms, elevated=False)


def victim_run(
    cfg: Config,
    vm_name: str,
    command: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    *,
    timeout_ms: int = 60000,
    cred: CredentialSet | None = None,
) -> dict:
    if cred is None:
        raise ValueError("victim credentials are required")
    policy.vm_allowed(cfg, vm_name)
    return guest_run(
        cfg, vm_name, command, args, cwd,
        timeout_ms=timeout_ms, elevated=False, confirm=False, cred=cred,
    )
