"""Guest access diagnostics: one-call VM access health report and reboot
recovery verification.

Both tools ride PowerShell Direct (Invoke-Command -VMName), so they work
regardless of guest network configuration — the diagnostic answers "why
can't I reach this VM" from INSIDE the guest, including the reporter's
incident class where SSH stayed bound to obsolete guest IPs after a subnet
change.

Conventions (repo-wide): all host PowerShell goes through pswindows.run_ps;
guest credentials arrive via stdin base64 (never in script text); VM names
are wildcard-escaped with ps_name; every guest leg runs under vmlocks
vm_lock, acquired per leg and never held across a nested leg.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Any

from . import guestexec, policy, pswindows
from .config import Config
from .credentials import CredentialSet
from .vmlocks import vm_lock

# Addresses that are valid ListenAddress/target values regardless of the
# guest's current unicast IPs (wildcards and loopback).
_UNIVERSAL_ADDRESSES = {"0.0.0.0", "::", "[::]", "*", "0.0.0.0:0"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _err(cfg: Config, error: str, error_class: str) -> dict:
    text, _ = guestexec._truncate(pswindows.redact(error), cfg.max_output_bytes)
    return {"ok": False, "error": text, "error_class": error_class}


# -- host leg (no credentials) -------------------------------------------


def _host_leg_script(vm_name: str) -> str:
    n = pswindows.ps_name(vm_name)
    return f"""
$vm = Get-VM -Name {n} -ErrorAction Stop
$up = if ($vm.Uptime) {{ [int][math]::Floor($vm.Uptime.TotalSeconds) }} else {{ 0 }}
[PSCustomObject]@{{
    state      = [string]$vm.State
    vm_id      = $vm.Id.ToString()
    uptime_s   = $up
    memory_mb  = [int]($vm.MemoryAssigned / 1MB)
    cpu_usage  = [int]$vm.CPUUsage
}} | ConvertTo-Json -Compress
""".strip()


def _run_host_leg(cfg: Config, vm_name: str) -> dict:
    result = pswindows.run_ps(_host_leg_script(vm_name), timeout_s=90)
    if result.timed_out:
        raise RuntimeError(f"host leg timed out for '{vm_name}'")
    pswindows.check_result(result)
    payload = json.loads(result.stdout.strip() or "{}")
    if not isinstance(payload, dict) or "state" not in payload:
        raise RuntimeError("unexpected host leg payload shape")
    return payload


# -- guest leg (PowerShell Direct, sectioned) -----------------------------

_GUEST_PROBE_SCRIPT = r"""
$r = [ordered]@{}
$sshdCfg = 'C:\ProgramData\ssh\sshd_config'
function Save-Section($name, $script) {
    try { $r[$name] = & $script } catch { $r[$name] = @{ error = "probe failed: " + $_.Exception.Message } }
}
Save-Section 'identity' {
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs  = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    @{
        hostname   = [string]$cs.Name
        domain     = [string]$cs.Domain
        os         = [string]$os.Caption
        version    = [string]$os.Version
        build      = [string]$os.BuildNumber
        last_boot  = [string]$os.LastBootUpTime
    }
}
Save-Section 'ip_addresses' {
    $v4 = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object { @{ interface = [string]$_.InterfaceAlias; address = [string]$_.IPAddress; prefix = [int]$_.PrefixLength } })
    $v6 = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne '::1' -and $_.IPAddress -notlike 'fe80*' } |
        ForEach-Object { [string]$_.IPAddress })
    @{ ipv4 = $v4; ipv6 = $v6 }
}
Save-Section 'ssh' {
    $out = @{}
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    $agent = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
    $out.service = if ($svc) { @{ present = $true; status = [string]$svc.Status; start_type = [string]$svc.StartType } } else { @{ present = $false } }
    $out.agent_service = if ($agent) { @{ present = $true; status = [string]$agent.Status } } else { @{ present = $false } }
    $out.config_path = $sshdCfg
    $out.config_present = Test-Path -LiteralPath $sshdCfg
    $ports = @(); $listen = @()
    if ($out.config_present) {
        $lines = @(Get-Content -LiteralPath $sshdCfg | ForEach-Object { $_.Trim() })
        foreach ($ln in $lines) {
            if ($ln -match '^(?i)Port\s+(\d+)') { $ports += [int]$Matches[1] }
            if ($ln -match '^(?i)ListenAddress\s+(.+)$') { $listen += $Matches[1].Trim() }
        }
    }
    if ($ports.Count -eq 0) { $ports = @(22) }
    $out.effective_ports = $ports
    $out.config_listen = $listen
    $svcPids = @()
    if ($svc -and $svc.Status -eq 'Running') {
        $svcPids = @(Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessId })
    }
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $ports -contains [int]$_.LocalPort -and ($svcPids.Count -eq 0 -or ($svcPids -contains [int]$_.OwningProcess)) } |
        ForEach-Object { @{ address = [string]$_.LocalAddress; port = [int]$_.LocalPort } })
    $out.listeners = $listeners
    $out
}
Save-Section 'winrm' {
    $out = @{}
    $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    $out.service = if ($svc) { @{ present = $true; status = [string]$svc.Status; start_type = [string]$svc.StartType } } else { @{ present = $false } }
    $l = @{ error = 'WSMan listener query unavailable' }
    try {
        $items = @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop)
        $l = @($items | ForEach-Object {
            $transport = (Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Transport' } | Select-Object -First 1).Value
            $port = (Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Port' } | Select-Object -First 1).Value
            $addr = (Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Address' } | Select-Object -First 1).Value
            @{ transport = [string]$transport; port = [int]$port; address = [string]$addr }
        })
    } catch { $l = @{ error = 'WSMan listener query failed: ' + $_.Exception.Message } }
    $out.listeners = $l
    $out.tcp_listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { @(5985, 5986) -contains [int]$_.LocalPort } |
        ForEach-Object { @{ address = [string]$_.LocalAddress; port = [int]$_.LocalPort } })
    $out
}
Save-Section 'firewall' {
    function Test-PortAllowed($port) {
        $rules = @(Get-NetFirewallRule -Enabled True -Action Allow -Direction Inbound -ErrorAction SilentlyContinue | Select-Object -First 200)
        foreach ($rule in $rules) {
            $f = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            if ($null -ne $f) {
                $lp = @($f.LocalPort) | ForEach-Object { [string]$_ }
                if ($lp -contains 'Any' -or $lp -contains [string]$port) { return $true }
            }
        }
        return $false
    }
    @{ ssh22_allowed = (Test-PortAllowed 22); winrm5985_allowed = (Test-PortAllowed 5985) }
}
$r | ConvertTo-Json -Compress -Depth 6
"""


def _guest_leg_script(vm_name: str, inner_script: str, cred: CredentialSet) -> str:
    n = pswindows.ps_name(vm_name)
    return f"""
{guestexec.psdirect_prefix(cred)}
$enc = '{pswindows.utf8_b64(inner_script)}'
$out = Invoke-Command -VMName {n} -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($enc)
    $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc))
    $tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName() + '.ps1')
    [System.IO.File]::WriteAllText($tmp, $text, [System.Text.UTF8Encoding]::new($false))
    try {{ & $tmp }} finally {{ Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }}
}} -ArgumentList $enc
$out
""".strip()


def _run_guest_probe(cfg: Config, vm_name: str, cred: CredentialSet, timeout_ms: int) -> dict:
    """One PS Direct probe leg. Returns the parsed section dict or raises."""
    timeout_s = max(30, timeout_ms // 1000 + guestexec._GRACE_S)
    script = _guest_leg_script(vm_name, _GUEST_PROBE_SCRIPT, cred)
    result = pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=pswindows.utf8_b64(cred.password))
    if result.timed_out:
        raise TimeoutError(f"guest probe timed out for '{vm_name}'")
    pswindows.check_result(result)
    payload = json.loads(result.stdout.strip() or "{}")
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected guest probe payload shape")
    return payload


# -- findings engine -------------------------------------------------------


def _addr_host(value: str) -> str:
    """Strip a :port suffix (IPv6 brackets included) from a bind address."""
    v = value.strip()
    if v.startswith("["):
        end = v.find("]")
        return v[: end + 1] if end > 0 else v
    parts = v.split(":")
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return v


def _findings(_vm: dict, guest: dict | None) -> list[dict]:
    out: list[dict] = []
    if guest is None:
        # The guest leg never ran (PS Direct unavailable): no guest-derived
        # finding is supportable — the report already carries
        # ps_direct_unavailable (Copilot review, COP-1).
        return out
    if guest.get("identity", {}).get("error"):
        pass  # section error already surfaces in the report

    ip_section = guest.get("ip_addresses") or {}
    ip_ok = not ip_section.get("error")
    ipv4: set[str] = set()
    for entry in ip_section.get("ipv4") or []:
        addr = entry.get("address")
        if addr:
            ipv4.add(addr.strip())
    if ip_ok and not ipv4:
        out.append({
            "id": "guest_no_ipv4", "severity": "high", "route": "guest",
            "summary": "guest reports no non-loopback IPv4 addresses",
            "detail": "Get-NetIPAddress returned no usable IPv4; networking may be down or unset",
        })
    elif not ip_ok:
        out.append({
            "id": "guest_ip_probe_failed", "severity": "medium", "route": "guest",
            "summary": "the guest IP probe failed; binding checks skipped",
            "detail": ip_section.get("error", ""),
        })

    ssh = guest.get("ssh") or {}
    if not ssh.get("error"):
        svc = ssh.get("service") or {}
        if not svc.get("present"):
            out.append({
                "id": "ssh_service_missing", "severity": "info", "route": "ssh",
                "summary": "sshd service is not installed",
                "detail": "Get-Service sshd found no service; OpenSSH Server may not be installed",
            })
        elif svc.get("status") != "Running":
            out.append({
                "id": "ssh_service_stopped", "severity": "medium", "route": "ssh",
                "summary": f"sshd service is {svc.get('status')}",
                "detail": f"sshd StartType={svc.get('start_type')}",
            })
        stale: list[str] = []
        for cfg_addr in ssh.get("config_listen") or []:
            host = _addr_host(str(cfg_addr))
            if host.lower() in _UNIVERSAL_ADDRESSES or host in ipv4:
                continue
            # A hostname (non-IP literal) cannot be validated against the IP list.
            if any(c.isalpha() for c in host):
                continue
            stale.append(str(cfg_addr))
        for listener in ssh.get("listeners") or []:
            raw = str(listener.get("address", ""))
            laddr = _addr_host(raw)
            if laddr.lower() in _UNIVERSAL_ADDRESSES or laddr in ipv4:
                continue
            if any(c.isalpha() for c in laddr):
                continue
            if raw not in stale:
                stale.append(raw)
        # Stale-binding validation needs a trustworthy current-IP list; with
        # the IP probe errored, every non-wildcard binding would falsely
        # read as stale (Copilot review, COP-1).
        if stale and ip_ok:
            out.append({
                "id": "ssh_stale_binding", "severity": "high", "route": "ssh",
                "summary": "SSH is bound to addresses that are not current guest IPs",
                "detail": f"stale bindings {stale}; current IPv4 {sorted(ipv4)}",
            })
        fw = guest.get("firewall") or {}
        if not fw.get("error") and fw.get("ssh22_allowed") is False:
            out.append({
                "id": "ssh_firewall_no_allow", "severity": "medium", "route": "ssh",
                "summary": "no enabled inbound allow firewall rule covers TCP 22",
                "detail": "first 200 inbound allow rules checked; none matched port 22 or Any",
            })

    winrm = guest.get("winrm") or {}
    if not winrm.get("error"):
        svc = winrm.get("service") or {}
        if not svc.get("present"):
            out.append({
                "id": "winrm_service_missing", "severity": "info", "route": "winrm",
                "summary": "WinRM service is not present",
                "detail": "Get-Service WinRM found no service",
            })
        elif svc.get("status") != "Running":
            out.append({
                "id": "winrm_service_stopped", "severity": "low", "route": "winrm",
                "summary": f"WinRM service is {svc.get('status')}",
                "detail": "PowerShell Direct does not need WinRM; matters only for WS-Man routes",
            })
        fw = guest.get("firewall") or {}
        if not fw.get("error") and fw.get("winrm5985_allowed") is False:
            out.append({
                "id": "winrm_firewall_no_allow", "severity": "low", "route": "winrm",
                "summary": "no enabled inbound allow firewall rule covers TCP 5985",
                "detail": "first 200 inbound allow rules checked; none matched port 5985 or Any",
            })
    return out


def build_guest_script(vm_name: str, inner_script: str, cred: CredentialSet) -> str:
    """Host PS wrapper (PS Direct) around an inner guest script, no lock.

    The relay's per-request legs call this directly: they deliberately skip
    vm_lock (a proxied HTTP request must not fail because an unrelated tool
    call holds the VM) while every tool-call leg goes through
    run_guest_inner, which acquires the lock.
    """
    return _guest_leg_script(vm_name, inner_script, cred)


def run_guest_inner(
    cfg: Config, vm_name: str, inner_script: str, cred: CredentialSet,
    timeout_ms: int = 60000,
) -> dict:
    """Run one PS Direct inner script under vm_lock and return its parsed JSON.

    Shared leg runner for the guest-access tool family (diagnostics, repair).
    Raises on transport failure/timeout; callers own error envelopes.
    """
    timeout_s = max(30, timeout_ms // 1000 + guestexec._GRACE_S)
    script = _guest_leg_script(vm_name, inner_script, cred)
    with vm_lock(vm_name):
        result = pswindows.run_ps(
            script, timeout_s=timeout_s,
            stdin_b64=pswindows.utf8_b64(cred.password),
        )
    if result.timed_out:
        raise TimeoutError(f"guest leg timed out for '{vm_name}'")
    pswindows.check_result(result)
    return json.loads(result.stdout.strip() or "{}")


# -- public API ------------------------------------------------------------


def diagnose_vm_access(
    cfg: Config,
    vm_name: str,
    *,
    cred: CredentialSet | None = None,
    timeout_ms: int = 90000,
) -> dict:
    """One-call guest access diagnostic for a VM (AC8).

    Read-only: vm_allowed policy gate only (matches non-elevated guest_run_ps
    semantics). PS Direct failure is a RESULT, not an error: the report
    carries ps_direct={available: false, ...} and host-side findings only.
    """
    if not vm_name:
        raise ValueError("vm_name is required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)

    checked_at = _utc_now_iso()

    host_info: dict = {}
    host_error = ""
    with vm_lock(vm_name):
        try:
            host_info = _run_host_leg(cfg, vm_name)
        except Exception as exc:  # host WMI leg failure is a result, not fatal
            host_error = str(exc)

    guest: dict | None = None
    ps_direct: dict = {"available": False}
    with vm_lock(vm_name):
        try:
            guest = _run_guest_probe(cfg, vm_name, cred, timeout_ms)
            ps_direct = {"available": True}
        except TimeoutError as exc:
            ps_direct = {"available": False, "error": str(exc), "error_class": "timeout"}
        except Exception as exc:
            ps_direct = {"available": False, "error": str(exc), "error_class": "transport"}

    findings = _findings(host_info, guest)
    if not ps_direct.get("available"):
        findings.append({
            "id": "ps_direct_unavailable", "severity": "high", "route": "ps_direct",
            "summary": "PowerShell Direct could not reach the guest",
            "detail": ps_direct.get("error", ""),
        })
    if host_error:
        findings.append({
            "id": "host_query_failed", "severity": "low", "route": "host",
            "summary": "host-side Get-VM query failed",
            "detail": host_error,
        })

    report: dict[str, Any] = {
        "ok": True,
        "vm_name": vm_name,
        "checked_at": checked_at,
        "vm": host_info,
        "ps_direct": ps_direct,
        "guest": guest,
        "findings": findings,
    }
    return report


# -- reboot recovery (F4) ---------------------------------------------------

_VERIFY_SCRIPT = r"""
param($itemsJson)
$items = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($itemsJson)) | ConvertFrom-Json
$svcOut = @(); $procOut = @()
foreach ($name in @($items.services)) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $s) { $svcOut += @{ name = [string]$name; present = $false; status = 'missing'; ok = $false } }
    else {
        $st = [string]$s.Status
        $svcOut += @{ name = [string]$name; present = $true; status = $st; ok = ($st -eq 'Running') }
    }
}
foreach ($name in @($items.processes)) {
    $p = Get-Process -Name $name -ErrorAction SilentlyContinue
    $present = $null -ne $p
    $procOut += @{ name = [string]$name; present = $present; ok = $present }
}
@{ services = $svcOut; processes = $procOut } | ConvertTo-Json -Compress -Depth 4
"""


def _recovery_script(
    vm_name: str, cred: CredentialSet, services: list[str], processes: list[str],
    timeout_s: int, interval_s: int,
) -> str:
    n = pswindows.ps_name(vm_name)
    items_b64 = pswindows.utf8_b64(json.dumps({"services": services, "processes": processes}))
    verify_b64 = pswindows.utf8_b64(_VERIFY_SCRIPT)
    max_attempts = max(1, math.ceil(timeout_s / max(1, interval_s)))
    return f"""
{guestexec.psdirect_prefix(cred)}
$deadline = (Get-Date).AddSeconds({timeout_s})
$interval = {interval_s}
$maxAttempts = {max_attempts}
$attempts = 0
$ok = $false
$err = ''
while ((Get-Date) -lt $deadline -and $attempts -lt $maxAttempts) {{
    $attempts++
    try {{
        $null = Invoke-Command -VMName {n} -Credential $cred -ErrorAction Stop -ScriptBlock {{ param($probe) $probe }} -ArgumentList 'ok'
        $ok = $true
        break
    }} catch {{
        $err = $_.Exception.Message
        if ((Get-Date) -ge $deadline) {{ break }}
        Start-Sleep -Seconds $interval
    }}
}}
$ps = @{{
    available = $ok
    attempts  = $attempts
    error     = $err
}}
if (-not $ok) {{
    $out = @{{ ps_direct = $ps; services = @(); processes = @() }}
    $out | ConvertTo-Json -Compress -Depth 4
}} else {{
    $enc2 = '{verify_b64}'
    $itemsB64 = '{items_b64}'
    $verify = Invoke-Command -VMName {n} -Credential $cred -ErrorAction Stop -ScriptBlock {{
        param($enc2, $itemsB64)
        $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc2))
        $tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName() + '.ps1')
        [System.IO.File]::WriteAllText($tmp, $text, [System.Text.UTF8Encoding]::new($false))
        try {{ & $tmp $itemsB64 }} finally {{ Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }}
    }} -ArgumentList $enc2, $itemsB64
    $v = $verify | ConvertFrom-Json
    [ordered]@{{ ps_direct = $ps; services = $v.services; processes = $v.processes }} | ConvertTo-Json -Compress -Depth 4
}}
""".strip()


def wait_guest_recovery(
    cfg: Config,
    vm_name: str,
    services: list[str] | None = None,
    processes: list[str] | None = None,
    *,
    timeout_s: int = 300,
    interval_s: int = 3,
    cred: CredentialSet | None = None,
) -> dict:
    """Wait for PowerShell Direct, then verify services/processes (AC11)."""
    if not vm_name:
        raise ValueError("vm_name is required")
    if cred is None:
        raise ValueError("guest credentials are required")
    if timeout_s < 1 or interval_s < 1:
        raise ValueError("timeout_s and interval_s must be >= 1")
    services = [s.strip() for s in (services or []) if s and s.strip()]
    processes = [p.strip() for p in (processes or []) if p and p.strip()]
    policy.vm_allowed(cfg, vm_name)

    script = _recovery_script(vm_name, cred, services, processes, timeout_s, interval_s)
    with vm_lock(vm_name):
        result = pswindows.run_ps(
            script,
            timeout_s=timeout_s + 15,
            stdin_b64=pswindows.utf8_b64(cred.password),
        )
    if result.timed_out:
        return {
            "ok": False, "vm_name": vm_name,
            "error": f"recovery wait timed out after {timeout_s}s",
            "error_class": "timeout",
        }
    try:
        pswindows.check_result(result)
        payload = json.loads(result.stdout.strip() or "{}")
    except Exception as exc:
        return _err(cfg, str(exc), "transport")

    ps = payload.get("ps_direct") or {}
    svc_rows = payload.get("services") or []
    proc_rows = payload.get("processes") or []
    # Single-object ConvertFrom-Json quirk: a one-element list collapses.
    if isinstance(svc_rows, dict):
        svc_rows = [svc_rows]
    if isinstance(proc_rows, dict):
        proc_rows = [proc_rows]
    failures: list[str] = []
    if not ps.get("available"):
        failures.append("ps_direct")
    for row in svc_rows:
        if not row.get("ok"):
            failures.append(f"service:{row.get('name')}")
    for row in proc_rows:
        if not row.get("ok"):
            failures.append(f"process:{row.get('name')}")
    return {
        "ok": not failures,
        "vm_name": vm_name,
        "ps_direct": ps,
        "services": svc_rows,
        "processes": proc_rows,
        "failures": failures,
        "checked_at": _utc_now_iso(),
    }
