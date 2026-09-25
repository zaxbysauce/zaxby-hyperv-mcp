"""VM lifecycle, checkpoints, and KDNET/KDCOM setup — PowerShell builders.

All cmdlet name parameters go through pswindows.ps_name (wildcard-inert).
State transitions poll to the requested final state and report both the
initial and resulting state. Destructive operations are gated by
config.destructive categories and the confirm parameter.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import secrets
from datetime import datetime

from . import policy, pswindows, vmlocks
from .config import Config
from .credentials import CredentialSet
from .guestexec import psdirect_prefix  # re-exported for kd tools

_MAX_NAME_LEN = 260

_KEY_RE = re.compile(r"^[0-9a-f.]+$")


def _checked_vm(cfg: Config, vm_name: str) -> str:
    if not vm_name or not vm_name.strip():
        raise ValueError("vm_name is required")
    if len(vm_name) > _MAX_NAME_LEN:
        raise ValueError(f"vm_name exceeds {_MAX_NAME_LEN} characters")
    policy.vm_allowed(cfg, vm_name)
    return vm_name


def _checked_label(label: str, what: str) -> str:
    if not label or not label.strip():
        raise ValueError(f"{what} is required")
    if len(label) > 200:
        raise ValueError(f"{what} exceeds 200 characters")
    if "\n" in label or "\r" in label or "`" in label:
        raise ValueError(f"{what} must not contain line breaks or backticks")
    return label


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def _parse_json_objects(result: pswindows.PSResult, ctx: str) -> list[dict]:
    raw = result.stdout.strip()
    if not raw or raw == "null":
        return []
    data = json.loads(raw)
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    raise RuntimeError(f"{ctx}: unexpected PowerShell output shape")


def _add_legacy_aliases(obj: dict, mapping: dict[str, str]) -> dict:
    """snake_case canonical + deprecated PascalCase aliases through 0.2.x."""
    out = dict(obj)
    for snake, pascal in mapping.items():
        if snake in out and pascal not in out:
            out[pascal] = out[snake]
    return out


_VM_KEY_ALIASES = {
    "name": "Name", "state": "State", "status": "Status",
    "memory_mb": "MemoryMB", "cpu_count": "CpuCount",
    "uptime_seconds": "UptimeSeconds",
}
# get_vm_info emits more fields than the list view; alias them all so 0.1.x
# PascalCase consumers keep working through the 0.2.x deprecation window.
_INFO_KEY_ALIASES = {
    **_VM_KEY_ALIASES,
    "generation": "Generation", "dynamic_memory": "DynamicMemory",
    "checkpoint_count": "CheckpointCount", "com_ports": "ComPorts",
    "network_adapters": "NetworkAdapters", "hard_drives": "HardDrives",
}
_SNAPSHOT_KEY_ALIASES = {
    "name": "Name", "type": "SnapshotType", "created": "Created",
    "parent_name": "ParentName",
}


# ---------------------------------------------------------------------------
# state polling
# ---------------------------------------------------------------------------

def _wait_state_script(cfg: Config, vm_name: str, wanted: list[str], timeout_s: int) -> str:
    n = pswindows.ps_name(vm_name)
    wanted_ps = ", ".join(f"'{w}'" for w in wanted)
    return f"""
$vm = Get-VM -Name {n} -ErrorAction Stop
$deadline = (Get-Date).AddSeconds({int(timeout_s)})
while ([string]$vm.State -notin ({wanted_ps}) -and (Get-Date) -lt $deadline) {{
    Start-Sleep -Seconds 2
    $vm = Get-VM -Name {n} -ErrorAction SilentlyContinue
    if (-not $vm) {{
        # -f inserts the name as DATA (no expansion of $/sub-expressions).
        throw ('VM {{0}} disappeared while waiting for state' -f {pswindows.ps_name(vm_name)})
    }}
}}
[PSCustomObject]@{{ final_state=[string]$vm.State }} | ConvertTo-Json -Compress
if ([string]$vm.State -notin ({wanted_ps})) {{ exit 3 }}
"""


def _wait_for_state(cfg: Config, vm_name: str, wanted: list[str], timeout_s: int) -> str:
    result = pswindows.run_ps(_wait_state_script(cfg, vm_name, wanted, timeout_s), timeout_s=timeout_s + 15)
    if result.timed_out:
        raise RuntimeError(f"hyperv state wait timed out for '{vm_name}'")
    if result.returncode not in (0, 3):
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        raise RuntimeError(f"state wait for '{vm_name}': {detail}")
    rows = _parse_json_objects(result, "state wait")
    final = rows[0].get("final_state", "") if rows else ""
    if final not in wanted:
        raise RuntimeError(
            f"VM '{vm_name}' did not reach {'/'.join(wanted)} within {timeout_s}s "
            f"(last state: {final or 'unknown'})"
        )
    return final


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------

_LIST_VM_SCRIPT = """
Get-VM | Select-Object @{N='name';E={$_.Name}},
  @{N='state';E={[string]$_.State}},
  @{N='status';E={$_.Status}},
  @{N='memory_mb';E={[math]::Round($_.MemoryAssigned/1MB,1)}},
  @{N='cpu_count';E={$_.ProcessorCount}},
  @{N='uptime_seconds';E={$_.Uptime.TotalSeconds}} |
  ConvertTo-Json -Compress -Depth 3
"""


def list_vms(cfg: Config) -> list[dict]:
    """List VMs, filtered to allowed_vm_patterns (deny when unconfigured).

    The deny-by-default VM policy applies to inventory too: with no patterns
    configured, nothing is listed and nothing is sent to PowerShell.
    """
    if not cfg.unrestricted:
        if not cfg.allowed_vm_patterns:
            raise policy.PolicyDenied("vm", "no allowed_vm_patterns configured")
    result = pswindows.run_ps(_LIST_VM_SCRIPT)
    pswindows.check_result(result, "hyperv_list_vms")
    rows = [_add_legacy_aliases(row, _VM_KEY_ALIASES) for row in _parse_json_objects(result, "list_vms")]
    if cfg.unrestricted:
        return rows
    return [
        row
        for row in rows
        if any(
            fnmatch.fnmatchcase(str(row.get("name", "")).casefold(), pattern.casefold())
            for pattern in cfg.allowed_vm_patterns
        )
    ]


def get_vm_info(cfg: Config, vm_name: str) -> dict:
    _checked_vm(cfg, vm_name)
    n = pswindows.ps_name(vm_name)
    script = f"""
$vm  = Get-VM          -Name {n} -ErrorAction Stop
$com = Get-VMComPort   -VMName {n} | Select-Object Name, Path
$net = Get-VMNetworkAdapter -VMName {n} | Select-Object Name, SwitchName, MacAddress, IPAddresses
$hdd = Get-VMHardDiskDrive  -VMName {n} | Select-Object ControllerType, Path
$snaps = (Get-VMSnapshot -VMName {n} | Measure-Object).Count
[PSCustomObject]@{{
    name             = $vm.Name
    state            = [string]$vm.State
    status           = $vm.Status
    generation       = $vm.Generation
    memory_mb        = [math]::Round($vm.MemoryAssigned/1MB,1)
    dynamic_memory   = $vm.DynamicMemoryEnabled
    cpu_count        = $vm.ProcessorCount
    uptime_seconds   = $vm.Uptime.TotalSeconds
    checkpoint_count = $snaps
    com_ports        = @($com)
    network_adapters = @($net)
    hard_drives      = @($hdd)
}} | ConvertTo-Json -Compress -Depth 4
"""
    result = pswindows.run_ps(script, timeout_s=60)
    pswindows.check_result(result, f"hyperv_get_vm_info({vm_name})")
    rows = _parse_json_objects(result, "get_vm_info")
    if not rows:
        raise RuntimeError(f"hyperv_get_vm_info({vm_name}): no data returned")
    return _add_legacy_aliases(rows[0], _INFO_KEY_ALIASES)


def start_vm(cfg: Config, vm_name: str) -> dict:
    _checked_vm(cfg, vm_name)
    n = pswindows.ps_name(vm_name)
    script = f"""
$vm = Get-VM -Name {n} -ErrorAction Stop
$initial = [string]$vm.State
if ($initial -ne 'Running') {{ Start-VM -VM $vm -ErrorAction Stop }}
[PSCustomObject]@{{ initial_state=$initial }} | ConvertTo-Json -Compress
"""
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(script, timeout_s=60)
        pswindows.check_result(result, f"hyperv_start_vm({vm_name})")
        rows = _parse_json_objects(result, "start_vm")
        initial = rows[0].get("initial_state", "") if rows else ""
        final = _wait_for_state(cfg, vm_name, ["Running"], timeout_s=90)
        already = initial == "Running"
        return {
            "status": "already_running" if already else "started",
            "vm_name": vm_name,
            "state": final,
        }


_STOP_SPECS = {
    # method: (Stop-VM flags, wanted final state, needs guest integration)
    "shutdown": ("", ["Off"], True),
    "shutdown-force": ("-Force", ["Off"], True),
    "save": ("-Save", ["Saved"], False),
    "turnoff": ("-TurnOff", ["Off"], False),
}


def stop_vm(cfg: Config, vm_name: str, method: str = "shutdown", confirm: bool = False) -> dict:
    _checked_vm(cfg, vm_name)
    if method not in _STOP_SPECS:
        raise ValueError("method must be one of: shutdown, shutdown-force, save, turnoff")
    _require_destructive(cfg, "stop", confirm, f"stop VM '{vm_name}' ({method})")
    flags, wanted, _ = _STOP_SPECS[method]
    n = pswindows.ps_name(vm_name)
    script = f"""
$vm = Get-VM -Name {n} -ErrorAction Stop
$initial = [string]$vm.State
if ($initial -notin ({", ".join(f"'{w}'" for w in wanted)})) {{
    Stop-VM -VM $vm {flags} -ErrorAction Stop
}}
[PSCustomObject]@{{ initial_state=$initial }} | ConvertTo-Json -Compress
"""
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(script, timeout_s=60)
        pswindows.check_result(result, f"hyperv_stop_vm({vm_name}, {method})")
        rows = _parse_json_objects(result, "stop_vm")
        initial = rows[0].get("initial_state", "") if rows else ""
        final = _wait_for_state(cfg, vm_name, wanted, timeout_s=300 if method == "shutdown" else 120)
        return {
            "status": "already_stopped" if initial in wanted else "stopped",
            "vm_name": vm_name,
            "method": method,
            "state": final,
        }


def reset_vm(cfg: Config, vm_name: str, confirm: bool = False) -> dict:
    _checked_vm(cfg, vm_name)
    _require_destructive(cfg, "reset", confirm, f"hard reset VM '{vm_name}'")
    n = pswindows.ps_name(vm_name)
    script = f"""
Stop-VM -Name {n} -TurnOff -ErrorAction Stop
Start-VM -Name {n} -ErrorAction Stop
"""
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(script, timeout_s=60)
        pswindows.check_result(result, f"hyperv_reset_vm({vm_name})")
        final = _wait_for_state(cfg, vm_name, ["Running"], timeout_s=90)
        return {"status": "reset", "vm_name": vm_name, "state": final}


# ---------------------------------------------------------------------------
# checkpoints
# ---------------------------------------------------------------------------

def checkpoint_create(cfg: Config, vm_name: str, checkpoint_name: str = "") -> dict:
    _checked_vm(cfg, vm_name)
    if not checkpoint_name:
        checkpoint_name = f"MCP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    _checked_label(checkpoint_name, "checkpoint_name")
    n = pswindows.ps_name(vm_name)
    cn = pswindows.ps_name(checkpoint_name)
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(
            f"Checkpoint-VM -Name {n} -SnapshotName {cn} -ErrorAction Stop", timeout_s=300
        )
        pswindows.check_result(result, f"hyperv_checkpoint_create({vm_name})")
        return {"status": "created", "vm_name": vm_name, "checkpoint_name": checkpoint_name}


def checkpoint_list(cfg: Config, vm_name: str) -> list[dict]:
    _checked_vm(cfg, vm_name)
    script = """
Get-VMSnapshot -VMName %VM% |
  Select-Object @{N='name';E={$_.Name}},
                @{N='type';E={[string]$_.SnapshotType}},
                @{N='created';E={$_.CreationTime.ToString('o')}},
                @{N='parent_name';E={$_.ParentSnapshotName}} |
  ConvertTo-Json -Compress -Depth 2
""".replace("%VM%", pswindows.ps_name(vm_name))
    result = pswindows.run_ps(script, timeout_s=60)
    pswindows.check_result(result, f"hyperv_checkpoint_list({vm_name})")
    return [_add_legacy_aliases(row, _SNAPSHOT_KEY_ALIASES) for row in _parse_json_objects(result, "checkpoint_list")]


def checkpoint_restore(cfg: Config, vm_name: str, checkpoint_name: str, confirm: bool = False) -> dict:
    _checked_vm(cfg, vm_name)
    _checked_label(checkpoint_name, "checkpoint_name")
    _require_destructive(cfg, "checkpoint_restore", confirm, f"restore VM '{vm_name}' to '{checkpoint_name}'")
    n = pswindows.ps_name(vm_name)
    cn = pswindows.ps_name(checkpoint_name)
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(
            f"Restore-VMSnapshot -Name {cn} -VMName {n} -Confirm:$false -ErrorAction Stop",
            timeout_s=300,
        )
        pswindows.check_result(result, f"hyperv_checkpoint_restore({vm_name}, {checkpoint_name})")
        # Restoring a checkpoint whose subtree has descendants merges their
        # differencing disks; the VM can stay in transitional states for many
        # minutes (observed: >120s on a 10-deep tree). Wait generously.
        final = _wait_for_state(cfg, vm_name, ["Off", "Saved", "Paused"], timeout_s=600)
        return {
            "status": "restored",
            "vm_name": vm_name,
            "checkpoint_name": checkpoint_name,
            "state": final,
            "note": "VM is powered off after restore; call hyperv_start_vm to bring it back up.",
        }


def checkpoint_remove(
    cfg: Config, vm_name: str, checkpoint_name: str, include_subtree: bool = False, confirm: bool = False
) -> dict:
    _checked_vm(cfg, vm_name)
    _checked_label(checkpoint_name, "checkpoint_name")
    detail = f"remove checkpoint '{checkpoint_name}' on '{vm_name}'" + (" (subtree)" if include_subtree else "")
    _require_destructive(cfg, "checkpoint_remove", confirm, detail)
    n = pswindows.ps_name(vm_name)
    cn = pswindows.ps_name(checkpoint_name)
    subtree = "-IncludeAllChildSnapshots" if include_subtree else ""
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(
            f"Remove-VMSnapshot -Name {cn} -VMName {n} {subtree} -Confirm:$false -ErrorAction Stop",
            timeout_s=300,
        )
        pswindows.check_result(result, f"hyperv_checkpoint_remove({vm_name})")
        return {"status": "removed", "vm_name": vm_name, "checkpoint_name": checkpoint_name}


# ---------------------------------------------------------------------------
# destructive gate (shared implementation in policy)
# ---------------------------------------------------------------------------

def _require_destructive(cfg: Config, category: str, confirm: bool, detail: str) -> None:
    policy.require_destructive(cfg, category, confirm, detail)


# ---------------------------------------------------------------------------
# KDNET / KDCOM setup (host cmdlets + PowerShell Direct into the guest)
# ---------------------------------------------------------------------------

def _validate_host_ip(host_ip: str) -> str:
    try:
        return str(ipaddress.ip_address(host_ip))
    except ValueError:
        raise ValueError(f"host_ip is not a valid IP address: {host_ip!r}") from None


def _validate_key(key: str) -> str:
    if not _KEY_RE.match(key):
        raise ValueError("key must be hex groups separated by dots (e.g. a1b2c.d3e4f.5a6b7.c8d9e)")
    return key


def _generate_key() -> str:
    return ".".join(f"{secrets.randbits(20):05x}" for _ in range(4))


def _validate_pipe_name(pipe_name: str) -> str:
    if not re.match(r"^\\\\\.\\pipe\\[A-Za-z0-9_.\-]+$", pipe_name):
        raise ValueError(
            "pipe_name must look like \\\\.\\pipe\\<name> with only alphanumerics, dot, dash, underscore"
        )
    return pipe_name


def configure_kdnet(
    cfg: Config,
    vm_name: str,
    host_ip: str,
    port: int = 50000,
    key: str = "",
    reboot: bool = False,
    confirm: bool = False,
    cred: CredentialSet | None = None,
) -> dict:
    _checked_vm(cfg, vm_name)
    host_ip = _validate_host_ip(host_ip)
    if not (1024 <= port <= 65535):
        raise ValueError("port must be between 1024 and 65535")
    key = _generate_key() if not key else _validate_key(key)
    if cred is None:
        raise ValueError("guest credentials are required")
    _require_destructive(
        cfg, "kd_reboot", confirm,
        f"configure KDNET on '{vm_name}'" + (" and reboot it" if reboot else ""),
    )
    n = pswindows.ps_name(vm_name)
    eip = pswindows.ps_quote(host_ip)
    ekey = pswindows.ps_quote(key)
    cred_prefix = psdirect_prefix(cred)
    script = f"""
{cred_prefix}
$out = Invoke-Command -VMName {n} -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($ip, $p, $k)
    $r1 = & 'bcdedit.exe' '/dbgsettings' 'net' "hostip:$ip" "port:$p" "key:$k" 2>&1
    $r2 = & 'bcdedit.exe' '/debug' 'on' 2>&1
    [PSCustomObject]@{{
        DbgSettings = "$r1"
        DebugOn     = "$r2"
        Current     = (& 'bcdedit.exe' '/dbgsettings' 2>&1 | Out-String)
    }}
}} -ArgumentList {eip}, {port}, {ekey}
$out | ConvertTo-Json -Compress
"""
    with vmlocks.vm_lock(vm_name):
        result = pswindows.run_ps(script.strip(), timeout_s=60, stdin_b64=pswindows.utf8_b64(cred.password))
        pswindows.check_result(result, f"hyperv_configure_kdnet({vm_name})")
        bcd = json.loads(result.stdout)

        rebooting = False
        if reboot:
            reboot_script = f"""
{cred_prefix}
Invoke-Command -VMName {n} -Credential $cred -ScriptBlock {{ & 'shutdown.exe' '/r' '/t' '3' }} -ErrorAction Stop
"""
            rr = pswindows.run_ps(
                reboot_script.strip(), timeout_s=30, stdin_b64=pswindows.utf8_b64(cred.password)
            )
            pswindows.check_result(rr, f"hyperv_configure_kdnet reboot({vm_name})")
            rebooting = True

        return {
            "status": "configured",
            "vm_name": vm_name,
            "host_ip": host_ip,
            "port": port,
            "key": key,
            "kernel_attach_string": f"net:port={port},key={key}",
            "bcdedit_output": bcd,
            "rebooting": rebooting,
        }


def configure_kdcom(
    cfg: Config,
    vm_name: str,
    pipe_name: str = "",
    com_port: int = 1,
    reboot: bool = False,
    confirm: bool = False,
    cred: CredentialSet | None = None,
) -> dict:
    _checked_vm(cfg, vm_name)
    if com_port not in (1, 2):
        raise ValueError("com_port must be 1 or 2")
    if not pipe_name:
        safe = re.sub(r"[^A-Za-z0-9._\-]", "_", vm_name)
        pipe_name = f"\\\\.\\pipe\\kd_{safe}"
    _validate_pipe_name(pipe_name)
    if cred is None:
        raise ValueError("guest credentials are required")
    _require_destructive(cfg, "kd_reboot", confirm, f"configure KDCOM on '{vm_name}'" + (" and reboot it" if reboot else ""))

    n = pswindows.ps_name(vm_name)
    pn = pswindows.ps_name(pipe_name)
    cred_prefix = psdirect_prefix(cred)

    step1 = f"Set-VMComPort -VMName {n} -Number {com_port} -Path {pn} -ErrorAction Stop"
    step2 = f"""
{cred_prefix}
$out = Invoke-Command -VMName {n} -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($port)
    $r1 = & 'bcdedit.exe' '/dbgsettings' 'serial' "debugport:$port" 'baudrate:115200' 2>&1
    $r2 = & 'bcdedit.exe' '/debug' 'on' 2>&1
    [PSCustomObject]@{{
        DbgSettings = "$r1"
        DebugOn     = "$r2"
        Current     = (& 'bcdedit.exe' '/dbgsettings' 2>&1 | Out-String)
    }}
}} -ArgumentList {com_port}
$out | ConvertTo-Json -Compress
"""
    with vmlocks.vm_lock(vm_name):
        r1 = pswindows.run_ps(step1, timeout_s=60)
        pswindows.check_result(r1, f"hyperv_configure_kdcom Set-VMComPort({vm_name})")
        r2 = pswindows.run_ps(step2.strip(), timeout_s=60, stdin_b64=pswindows.utf8_b64(cred.password))
        pswindows.check_result(r2, f"hyperv_configure_kdcom bcdedit({vm_name})")
        bcd = json.loads(r2.stdout)

        rebooting = False
        if reboot:
            reboot_script = f"""
{cred_prefix}
Invoke-Command -VMName {n} -Credential $cred -ScriptBlock {{ & 'shutdown.exe' '/r' '/t' '3' }} -ErrorAction Stop
"""
            rr = pswindows.run_ps(
                reboot_script.strip(), timeout_s=30, stdin_b64=pswindows.utf8_b64(cred.password)
            )
            pswindows.check_result(rr, f"hyperv_configure_kdcom reboot({vm_name})")
            rebooting = True

        return {
            "status": "configured",
            "vm_name": vm_name,
            "com_port": com_port,
            "pipe_path": pipe_name,
            "kernel_attach_string": f"com:pipe,port={pipe_name},resets=0,reconnect",
            "bcdedit_output": bcd,
            "rebooting": rebooting,
        }
