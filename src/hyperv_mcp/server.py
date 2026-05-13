"""
hyperv_mcp.server -- MCP server for Hyper-V VM management.

Exposes Hyper-V VM lifecycle, checkpoint, kernel debug setup, and guest
execution as MCP tools. Requires the Hyper-V PowerShell module; must run on
a Hyper-V host as Administrator or as a member of the Hyper-V Administrators
group.

Guest credentials (for hyperv_configure_kdnet / hyperv_configure_kdcom and
all hyperv_guest_* tools) come from HYPERV_GUEST_USERNAME and
HYPERV_GUEST_PASSWORD env vars. Victim execution tools use the separate
HYPERV_GUEST_VICTIM_USERNAME / HYPERV_GUEST_VICTIM_PASSWORD pair.

Available tools (19 total):
    VM lifecycle:  hyperv_list_vms, hyperv_get_vm_info, hyperv_start_vm,
                   hyperv_stop_vm, hyperv_reset_vm
    Checkpoints:   hyperv_checkpoint_create, hyperv_checkpoint_list,
                   hyperv_checkpoint_restore, hyperv_checkpoint_remove
    KD setup:      hyperv_configure_kdnet, hyperv_configure_kdcom
    Guest exec:    hyperv_guest_run, hyperv_guest_run_ps,
                   hyperv_guest_put, hyperv_guest_get,
                   hyperv_guest_read_file, hyperv_guest_list_dir
    Victim exec:   hyperv_victim_run, hyperv_victim_run_ps
"""

import base64 as _base64
import json as _json
import os
import secrets
import subprocess
import sys
from datetime import datetime

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "hyperv_mcp",
    instructions=(
        "Hyper-V VM management MCP. Provides VM lifecycle control, checkpoint "
        "management, kernel debug setup (KDNET/KDCOM), and guest execution via "
        "PowerShell Direct (no WinRM required). "
        "Requires Hyper-V PowerShell module on a Hyper-V host. "
        "Call hyperv_list_vms to see available VMs. "
        "Use hyperv_guest_put/get for file transfer, hyperv_guest_run_ps to "
        "run PowerShell inside the guest, and hyperv_guest_run to execute "
        "a specific binary."
    ),
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ps_escape(s: str) -> str:
    """Escape a value for use inside a PowerShell single-quoted string."""
    return s.replace("'", "''")


def _run_ps(script: str, timeout: int = 120) -> dict:
    """Execute a PowerShell script and return {stdout, stderr, returncode}."""
    try:
        proc = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # Re-raise without cmd/script so credentials are never in the message.
        raise RuntimeError(f"PowerShell command timed out after {timeout}s") from None
    return {
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "returncode": proc.returncode,
    }


def _ps_ok(r: dict, ctx: str = "") -> str:
    """Raise RuntimeError if the PowerShell command failed."""
    if r["returncode"] != 0:
        err = r["stderr"] or r["stdout"] or "PowerShell error"
        raise RuntimeError(f"{ctx}: {err}" if ctx else err)
    return r["stdout"]


def _guest_creds(username: str = "", password: str = "") -> tuple[str, str]:
    """
    Resolve guest VM credentials from arguments, falling back to env vars.

    Env vars: HYPERV_GUEST_USERNAME, HYPERV_GUEST_PASSWORD
    """
    u = username or os.environ.get("HYPERV_GUEST_USERNAME", "")
    p = password or os.environ.get("HYPERV_GUEST_PASSWORD", "")
    if not u or not p:
        raise RuntimeError(
            "Guest credentials are required. Supply username/password arguments or set "
            "HYPERV_GUEST_USERNAME and HYPERV_GUEST_PASSWORD environment variables."
        )
    return u, p


def _victim_creds() -> tuple[str, str]:
    """
    Resolve victim (unprivileged) guest credentials from env vars.

    Env vars: HYPERV_GUEST_VICTIM_USERNAME, HYPERV_GUEST_VICTIM_PASSWORD
    """
    u = os.environ.get("HYPERV_GUEST_VICTIM_USERNAME", "")
    p = os.environ.get("HYPERV_GUEST_VICTIM_PASSWORD", "")
    if not u or not p:
        raise RuntimeError(
            "No victim credential configured. Set HYPERV_GUEST_VICTIM_USERNAME and "
            "HYPERV_GUEST_VICTIM_PASSWORD environment variables to an unprivileged "
            "guest account."
        )
    return u, p


def _ps_json_list(script: str, timeout: int = 120) -> list:
    """Run a PS command ending with ConvertTo-Json; always return a list."""
    r = _run_ps(script, timeout)
    _ps_ok(r)
    if not r["stdout"]:
        return []
    data = _json.loads(r["stdout"])
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


# ---------------------------------------------------------------------------
# MCP TOOLS — VM lifecycle
# ---------------------------------------------------------------------------

@mcp.tool()
def hyperv_list_vms() -> list:
    """
    List all Hyper-V virtual machines and their current state.

    Requires the Hyper-V PowerShell module (must run on a Hyper-V host).

    Returns: [{name, state, status, memory_mb, cpu_count, uptime_seconds}]
    """
    return _ps_json_list(
        "Get-VM | Select-Object Name, State, Status,"
        "@{N='MemoryMB';E={[math]::Round($_.MemoryAssigned/1MB,1)}},"
        "@{N='CpuCount';E={$_.ProcessorCount}},"
        "@{N='UptimeSeconds';E={$_.Uptime.TotalSeconds}}"
        " | ConvertTo-Json -Compress -Depth 3"
    )


@mcp.tool()
def hyperv_get_vm_info(vm_name: str) -> dict:
    """
    Get detailed information about a specific Hyper-V VM.

    Includes VM config, COM port settings (for kernel debugging), network
    adapters, hard drives, and checkpoint count.

    Args:
        vm_name: Name of the VM

    Returns: {name, state, generation, com_ports, network_adapters,
              hard_drives, memory_mb, cpu_count, checkpoint_count, ...}
    """
    if not vm_name:
        raise ValueError("vm_name is required")
    n = _ps_escape(vm_name)
    script = f"""
$vm  = Get-VM          -Name '{n}' -ErrorAction Stop
$com = Get-VMComPort   -VMName '{n}' | Select-Object Name, Path
$net = Get-VMNetworkAdapter -VMName '{n}' | Select-Object Name, SwitchName, MacAddress, IPAddresses
$hdd = Get-VMHardDiskDrive  -VMName '{n}' | Select-Object ControllerType, Path
$snaps = (Get-VMSnapshot -VMName '{n}' | Measure-Object).Count
[PSCustomObject]@{{
    Name             = $vm.Name
    State            = [string]$vm.State
    Status           = $vm.Status
    Generation       = $vm.Generation
    MemoryMB         = [math]::Round($vm.MemoryAssigned/1MB,1)
    DynamicMemory    = $vm.DynamicMemoryEnabled
    CpuCount         = $vm.ProcessorCount
    UptimeSeconds    = $vm.Uptime.TotalSeconds
    CheckpointCount  = $snaps
    ComPorts         = @($com)
    NetworkAdapters  = @($net)
    HardDrives       = @($hdd)
}} | ConvertTo-Json -Compress -Depth 4
"""
    r = _run_ps(script.strip())
    _ps_ok(r, f"hyperv_get_vm_info({vm_name})")
    return _json.loads(r["stdout"])


@mcp.tool()
def hyperv_start_vm(vm_name: str) -> dict:
    """
    Start a Hyper-V virtual machine.

    Args:
        vm_name: Name of the VM to start

    Returns: {status, vm_name, state}
    """
    if not vm_name:
        raise ValueError("vm_name is required")
    n = _ps_escape(vm_name)
    r = _run_ps(
        f"Start-VM -Name '{n}' -ErrorAction Stop; "
        f"(Get-VM -Name '{n}').State"
    )
    _ps_ok(r, f"hyperv_start_vm({vm_name})")
    return {"status": "started", "vm_name": vm_name, "state": r["stdout"]}


@mcp.tool()
def hyperv_stop_vm(vm_name: str, method: str = "shutdown") -> dict:
    """
    Stop a Hyper-V virtual machine.

    Args:
        vm_name: Name of the VM to stop
        method:  How to stop the VM:
                   "shutdown" — ask the guest OS to shut down gracefully (default)
                   "save"     — suspend and save VM state to disk
                   "turnoff"  — hard power-off (equivalent to pulling the power cord)

    Returns: {status, vm_name, method, state}
    """
    if not vm_name:
        raise ValueError("vm_name is required")
    if method not in ("shutdown", "save", "turnoff"):
        raise ValueError("method must be 'shutdown', 'save', or 'turnoff'")
    n = _ps_escape(vm_name)
    flag_map = {
        "shutdown": "-Force",
        "save":     "-Save",
        "turnoff":  "-TurnOff -Force",
    }
    flag = flag_map[method]
    r = _run_ps(
        f"Stop-VM -Name '{n}' {flag} -ErrorAction Stop; "
        f"(Get-VM -Name '{n}').State"
    )
    _ps_ok(r, f"hyperv_stop_vm({vm_name})")
    return {"status": "stopped", "vm_name": vm_name, "method": method, "state": r["stdout"]}


@mcp.tool()
def hyperv_reset_vm(vm_name: str) -> dict:
    """
    Hard-reset a Hyper-V VM (equivalent to pressing the physical Reset button).

    Powers the VM off immediately without graceful shutdown, then starts it.
    Use this to recover from a frozen or unresponsive guest during a debugging
    session.

    Args:
        vm_name: Name of the VM to reset

    Returns: {status, vm_name, state}
    """
    if not vm_name:
        raise ValueError("vm_name is required")
    n = _ps_escape(vm_name)
    r = _run_ps(
        f"Stop-VM -Name '{n}' -TurnOff -Force -ErrorAction Stop; "
        f"Start-VM -Name '{n}' -ErrorAction Stop; "
        f"(Get-VM -Name '{n}').State"
    )
    _ps_ok(r, f"hyperv_reset_vm({vm_name})")
    return {"status": "reset", "vm_name": vm_name, "state": r["stdout"]}


# ---------------------------------------------------------------------------
# MCP TOOLS — Checkpoints
# ---------------------------------------------------------------------------

@mcp.tool()
def hyperv_checkpoint_create(vm_name: str, checkpoint_name: str = "") -> dict:
    """
    Create a checkpoint (snapshot) of a Hyper-V VM.

    Captures the current state of VM memory, CPU, and disk so you can
    restore to a known-good state later — useful before a debugging or
    exploitation run.

    Args:
        vm_name:         Name of the VM
        checkpoint_name: Label for the checkpoint (default: auto timestamp)

    Returns: {status, vm_name, checkpoint_name}
    """
    if not vm_name:
        raise ValueError("vm_name is required")
    if not checkpoint_name:
        checkpoint_name = f"MCP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    n  = _ps_escape(vm_name)
    cn = _ps_escape(checkpoint_name)
    r  = _run_ps(
        f"Checkpoint-VM -Name '{n}' -SnapshotName '{cn}' -ErrorAction Stop",
        timeout=300,
    )
    _ps_ok(r, f"hyperv_checkpoint_create({vm_name})")
    return {"status": "created", "vm_name": vm_name, "checkpoint_name": checkpoint_name}


@mcp.tool()
def hyperv_checkpoint_list(vm_name: str) -> list:
    """
    List all checkpoints for a Hyper-V VM.

    Args:
        vm_name: Name of the VM

    Returns: [{name, type, created, parent_name}]
    """
    if not vm_name:
        raise ValueError("vm_name is required")
    n = _ps_escape(vm_name)
    return _ps_json_list(
        f"Get-VMSnapshot -VMName '{n}' | "
        "Select-Object Name, SnapshotType,"
        "@{N='Created';E={$_.CreationTime.ToString('o')}},"
        "@{N='ParentName';E={$_.ParentSnapshotName}}"
        " | ConvertTo-Json -Compress -Depth 2"
    )


@mcp.tool()
def hyperv_checkpoint_restore(vm_name: str, checkpoint_name: str) -> dict:
    """
    Restore a Hyper-V VM to a previously saved checkpoint.

    WARNING: All VM state since the checkpoint is discarded. The VM will be
    powered off after restore; call hyperv_start_vm to bring it back up.

    Args:
        vm_name:         Name of the VM
        checkpoint_name: Name of the checkpoint to restore

    Returns: {status, vm_name, checkpoint_name}
    """
    if not vm_name or not checkpoint_name:
        raise ValueError("vm_name and checkpoint_name are required")
    n  = _ps_escape(vm_name)
    cn = _ps_escape(checkpoint_name)
    r  = _run_ps(
        f"Restore-VMSnapshot -Name '{cn}' -VMName '{n}' -Confirm:$false -ErrorAction Stop",
        timeout=300,
    )
    _ps_ok(r, f"hyperv_checkpoint_restore({vm_name}, {checkpoint_name})")
    return {"status": "restored", "vm_name": vm_name, "checkpoint_name": checkpoint_name}


@mcp.tool()
def hyperv_checkpoint_remove(
    vm_name: str,
    checkpoint_name: str,
    include_subtree: bool = False,
) -> dict:
    """
    Remove a checkpoint from a Hyper-V VM.

    Args:
        vm_name:          Name of the VM
        checkpoint_name:  Name of the checkpoint to delete
        include_subtree:  Also remove all child checkpoints (default False)

    Returns: {status, vm_name, checkpoint_name}
    """
    if not vm_name or not checkpoint_name:
        raise ValueError("vm_name and checkpoint_name are required")
    n  = _ps_escape(vm_name)
    cn = _ps_escape(checkpoint_name)
    subtree = "-IncludeAllChildSnapshots" if include_subtree else ""
    r = _run_ps(
        f"Remove-VMSnapshot -Name '{cn}' -VMName '{n}' {subtree} -Confirm:$false -ErrorAction Stop",
        timeout=300,
    )
    _ps_ok(r, f"hyperv_checkpoint_remove({vm_name})")
    return {"status": "removed", "vm_name": vm_name, "checkpoint_name": checkpoint_name}


# ---------------------------------------------------------------------------
# MCP TOOLS — Kernel debug setup
# ---------------------------------------------------------------------------

@mcp.tool()
def hyperv_configure_kdnet(
    vm_name: str,
    host_ip: str,
    port: int = 50000,
    key: str = "",
    reboot: bool = False,
    username: str = "",
    password: str = "",
) -> dict:
    """
    Configure KDNET (network kernel debugging) on a Hyper-V VM. DEFAULT method.

    Runs bcdedit inside the guest via PowerShell Direct (no network, no RDP)
    to set up KDNET pointing back to this host. No host-side Hyper-V changes
    needed — the VM uses its existing virtual NIC.

    Credentials are resolved in order:
      1. username / password arguments (if provided)
      2. HYPERV_GUEST_USERNAME / HYPERV_GUEST_PASSWORD environment variables

    Args:
        vm_name:  Name of the VM
        host_ip:  IP address of the debugger host (this machine) that the VM
                  will connect to. Use the IP on the same vSwitch as the VM.
        port:     UDP port the debugger listens on (default 50000)
        key:      Encryption key in a.b.c.d hex format — auto-generated if omitted
        reboot:   Reboot the guest immediately after configuring (default False)
        username: Guest OS username — overrides HYPERV_GUEST_USERNAME env var
        password: Guest OS password — overrides HYPERV_GUEST_PASSWORD env var

    Returns: {
        status, vm_name, host_ip, port, key,
        kernel_attach_string,
        rebooting
    }
    """
    if not vm_name or not host_ip:
        raise ValueError("vm_name and host_ip are required")
    if not (1024 <= port <= 65535):
        raise ValueError("port must be between 1024 and 65535")
    if not key:
        key = ".".join(f"{secrets.randbits(20):05x}" for _ in range(4))
    u, pw = _guest_creds(username, password)
    n  = _ps_escape(vm_name)
    eu = _ps_escape(u)
    ep = _ps_escape(pw)
    eip  = _ps_escape(host_ip)
    ekey = _ps_escape(key)
    script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
$out = Invoke-Command -VMName '{n}' -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($ip, $p, $k)
    $r1 = & bcdedit /dbgsettings net hostip:$ip port:$p key:$k 2>&1
    $r2 = & bcdedit /debug on 2>&1
    [PSCustomObject]@{{
        DbgSettings = "$r1"
        DebugOn     = "$r2"
        Current     = (& bcdedit /dbgsettings 2>&1 | Out-String)
    }}
}} -ArgumentList '{eip}', {port}, '{ekey}'
$out | ConvertTo-Json -Compress
"""
    r = _run_ps(script.strip(), timeout=60)
    _ps_ok(r, f"hyperv_configure_kdnet({vm_name})")
    result = _json.loads(r["stdout"])

    rebooting = False
    if reboot:
        reboot_script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
Invoke-Command -VMName '{n}' -Credential $cred -ScriptBlock {{
    shutdown /r /t 3
}} -ErrorAction Stop
"""
        rr = _run_ps(reboot_script.strip(), timeout=30)
        _ps_ok(rr, f"hyperv_configure_kdnet reboot({vm_name})")
        rebooting = True

    return {
        "status": "configured",
        "vm_name": vm_name,
        "host_ip": host_ip,
        "port": port,
        "key": key,
        "kernel_attach_string": f"net:port={port},key={key}",
        "bcdedit_output": result,
        "rebooting": rebooting,
    }


@mcp.tool()
def hyperv_configure_kdcom(
    vm_name: str,
    pipe_name: str = "",
    com_port: int = 1,
    reboot: bool = False,
    username: str = "",
    password: str = "",
) -> dict:
    """
    Configure COM-port / named-pipe kernel debugging on a Hyper-V VM.
    SPECIAL CASE — prefer hyperv_configure_kdnet for normal use.

    Use this when KDNET is unavailable: no network adapter, network not yet
    configured in the guest, or when debugging very early boot before the NIC
    driver loads.

    Performs both steps in one call:
      1. Maps the VM COM port to a named pipe on the host (Set-VMComPort).
         The VM must be Off or Saved for this step.
      2. Runs bcdedit inside the guest via PowerShell Direct to configure
         serial kernel debugging on that COM port.

    Credentials are resolved in order:
      1. username / password arguments (if provided)
      2. HYPERV_GUEST_USERNAME / HYPERV_GUEST_PASSWORD environment variables

    Args:
        vm_name:   Name of the VM
        pipe_name: Named pipe path on the host — auto-generated if omitted
                   (e.g. "\\\\.\\pipe\\kd_MyVM")
        com_port:  COM port number on the VM (1 or 2, default 1)
        reboot:    Reboot the guest after configuring (default False)
        username:  Guest OS username — overrides HYPERV_GUEST_USERNAME env var
        password:  Guest OS password — overrides HYPERV_GUEST_PASSWORD env var

    Returns: {
        status, vm_name, com_port, pipe_path,
        kernel_attach_string,
        bcdedit_output, rebooting
    }
    """
    if not vm_name:
        raise ValueError("vm_name is required")
    if com_port not in (1, 2):
        raise ValueError("com_port must be 1 or 2")
    if not pipe_name:
        safe = vm_name.replace(" ", "_").replace("\\", "_").replace("/", "_")
        pipe_name = f"\\\\.\\pipe\\kd_{safe}"
    u, pw = _guest_creds(username, password)
    n  = _ps_escape(vm_name)
    pn = _ps_escape(pipe_name)
    eu = _ps_escape(u)
    ep = _ps_escape(pw)

    # Step 1 — host: map COM port to named pipe (VM must be Off/Saved)
    r = _run_ps(
        f"Set-VMComPort -VMName '{n}' -Number {com_port} -Path '{pn}' -ErrorAction Stop"
    )
    _ps_ok(r, f"hyperv_configure_kdcom Set-VMComPort({vm_name})")

    # Step 2 — guest: set bcdedit serial debug settings via PowerShell Direct
    script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
$out = Invoke-Command -VMName '{n}' -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($port)
    $r1 = & bcdedit /dbgsettings serial debugport:$port baudrate:115200 2>&1
    $r2 = & bcdedit /debug on 2>&1
    [PSCustomObject]@{{
        DbgSettings = "$r1"
        DebugOn     = "$r2"
        Current     = (& bcdedit /dbgsettings 2>&1 | Out-String)
    }}
}} -ArgumentList {com_port}
$out | ConvertTo-Json -Compress
"""
    r = _run_ps(script.strip(), timeout=60)
    _ps_ok(r, f"hyperv_configure_kdcom bcdedit({vm_name})")
    result = _json.loads(r["stdout"])

    rebooting = False
    if reboot:
        reboot_script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
Invoke-Command -VMName '{n}' -Credential $cred -ScriptBlock {{
    shutdown /r /t 3
}} -ErrorAction Stop
"""
        rr = _run_ps(reboot_script.strip(), timeout=30)
        _ps_ok(rr, f"hyperv_configure_kdcom reboot({vm_name})")
        rebooting = True

    return {
        "status": "configured",
        "vm_name": vm_name,
        "com_port": com_port,
        "pipe_path": pipe_name,
        "kernel_attach_string": f"com:pipe,port={pipe_name},resets=0,reconnect",
        "bcdedit_output": result,
        "rebooting": rebooting,
    }


# ---------------------------------------------------------------------------
# Helpers for guest execution
# ---------------------------------------------------------------------------

def _guest_run_encoded(
    vm_name: str, inner_script: str, u: str, pw: str, timeout_s: int,
    elevated: bool = False,
) -> dict:
    """Run a PS script in a guest via PowerShell Direct using [scriptblock]::Create.

    When elevated=True the script is written to a temp file and launched via
    Start-Process -Verb RunAs -Wait so that processes with highestAvailable /
    requireAdministrator manifests run at High IL and their exit code is
    captured reliably.  This works unconditionally for the built-in
    Administrator account; for non-built-in admin accounts the guest must have
    UAC auto-elevation enabled (ConsentPromptBehaviorAdmin=0) or UAC disabled.
    """
    n  = _ps_escape(vm_name)
    eu = _ps_escape(u)
    ep = _ps_escape(pw)
    enc = _base64.b64encode(inner_script.encode("utf-16-le")).decode("ascii")

    if elevated:
        # Write the script to a temp file in the guest, then run it elevated via
        # Start-Process -Verb RunAs -Wait -PassThru so we capture the real exit
        # code even when the process self-elevates or spawns an elevated child.
        host_script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
$r = Invoke-Command -VMName '{n}' -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($enc)
    $bytes = [Convert]::FromBase64String($enc)
    $text  = [Text.Encoding]::Unicode.GetString($bytes)
    $tmp   = [System.IO.Path]::GetTempFileName() + '.ps1'
    $outf  = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllText($tmp, $text, [Text.Encoding]::Unicode)
    $proc  = Start-Process powershell.exe `
        -ArgumentList "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$tmp`" *>`"$outf`"" `
        -Verb RunAs -Wait -PassThru -ErrorAction Stop
    $ec    = $proc.ExitCode
    $out   = if (Test-Path $outf) {{ [System.IO.File]::ReadAllText($outf) }} else {{ '' }}
    Remove-Item $tmp, $outf -Force -ErrorAction SilentlyContinue
    [PSCustomObject]@{{ exit_code=$ec; stdout=$out; stderr='' }}
}} -ArgumentList '{enc}'
$r | ConvertTo-Json -Compress
"""
    else:
        host_script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
$r = Invoke-Command -VMName '{n}' -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($enc)
    $bytes = [Convert]::FromBase64String($enc)
    $text  = [Text.Encoding]::Unicode.GetString($bytes)
    $sb    = [scriptblock]::Create($text)
    $out   = (& $sb 2>&1) | Out-String
    $ec    = if ($null -ne $LASTEXITCODE) {{ $LASTEXITCODE }} else {{ 0 }}
    [PSCustomObject]@{{ exit_code=$ec; stdout=$out; stderr='' }}
}} -ArgumentList '{enc}'
$r | ConvertTo-Json -Compress
"""
    r = _run_ps(host_script.strip(), timeout=timeout_s)
    if r["returncode"] != 0:
        return {"ok": False, "error": r["stderr"] or r["stdout"]}
    raw = r["stdout"].strip()
    if not raw:
        return {"ok": False, "error": f"no output from guest (stderr: {r['stderr']!r})"}
    try:
        data = _json.loads(raw)
        return {
            "ok": True,
            "exit_code": data["exit_code"],
            "stdout": (data.get("stdout") or "").strip(),
            "stderr": data.get("stderr") or "",
        }
    except Exception as exc:
        return {"ok": False, "error": f"json parse failed: {exc} | raw: {raw[:200]!r}"}


# ---------------------------------------------------------------------------
# MCP TOOLS — Guest execution (PowerShell Direct, no WinRM required)
# ---------------------------------------------------------------------------

@mcp.tool()
def hyperv_guest_run_ps(
    vm_name: str,
    script: str,
    timeout_ms: int = 60000,
    elevated: bool = False,
    username: str = "",
    password: str = "",
) -> dict:
    """
    Run a PowerShell script inside a guest VM via PowerShell Direct.

    No network or WinRM required — communicates over the VMBus channel.
    The script runs in an isolated child powershell process inside the guest;
    stdout and stderr are merged and returned as 'stdout'.

    Elevation: when elevated=True the script is launched via Start-Process
    -Verb RunAs -Wait so that processes requiring High IL (e.g. those with a
    highestAvailable or requireAdministrator manifest) run correctly and their
    exit code is captured.  Works without UAC prompts when the guest credential
    is the built-in Administrator account; for other admin accounts the guest
    must have auto-elevation enabled or UAC disabled.

    Args:
        vm_name:    Name of the VM
        script:     PowerShell script text (may be multi-line)
        timeout_ms: Timeout hint in milliseconds (default 60 s)
        elevated:   Run the script at High integrity level (default False)
        username:   Guest OS username — overrides HYPERV_GUEST_USERNAME env var
        password:   Guest OS password — overrides HYPERV_GUEST_PASSWORD env var

    Returns: {ok, exit_code, stdout, stderr}
    """
    if not vm_name or not script:
        raise ValueError("vm_name and script are required")
    u, pw = _guest_creds(username, password)
    timeout_s = max(30, timeout_ms // 1000 + 10)
    return _guest_run_encoded(vm_name, script, u, pw, timeout_s, elevated=elevated)


@mcp.tool()
def hyperv_guest_run(
    vm_name: str,
    command: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    timeout_ms: int = 60000,
    elevated: bool = False,
    username: str = "",
    password: str = "",
) -> dict:
    """
    Run an executable inside a guest VM via PowerShell Direct.

    No network or WinRM required — communicates over the VMBus channel.

    Elevation: when elevated=True the executable is launched via Start-Process
    -Verb RunAs -Wait so that binaries with highestAvailable or
    requireAdministrator manifests (e.g. mmc.exe, bcdedit.exe) run at High IL
    and their exit code is captured reliably.  Works without UAC prompts when
    the guest credential is the built-in Administrator account.

    Args:
        vm_name:    Name of the VM
        command:    Full path to the executable (e.g. C:\\Windows\\Temp\\poc.exe)
        args:       Command-line arguments
        cwd:        Working directory inside the guest (optional)
        timeout_ms: Timeout hint in milliseconds (default 60 s)
        elevated:   Run the executable at High integrity level (default False)
        username:   Guest OS username — overrides HYPERV_GUEST_USERNAME env var
        password:   Guest OS password — overrides HYPERV_GUEST_PASSWORD env var

    Returns: {ok, exit_code, stdout, stderr}
    """
    if not vm_name or not command:
        raise ValueError("vm_name and command are required")
    u, pw = _guest_creds(username, password)
    args_str = " ".join(f"'{_ps_escape(a)}'" for a in (args or []))
    cmd_expr = f"& '{_ps_escape(command)}' {args_str}".strip()
    if cwd:
        inner = (
            f"Push-Location '{_ps_escape(cwd)}'\n"
            f"try {{\n  {cmd_expr}\n}} finally {{\n  Pop-Location\n}}\n"
            f"exit $LASTEXITCODE"
        )
    else:
        inner = f"{cmd_expr}\nexit $LASTEXITCODE"
    timeout_s = max(30, timeout_ms // 1000 + 10)
    return _guest_run_encoded(vm_name, inner, u, pw, timeout_s, elevated=elevated)


@mcp.tool()
def hyperv_guest_put(
    vm_name: str,
    local_path: str,
    remote_path: str,
    username: str = "",
    password: str = "",
) -> dict:
    """
    Copy a local file to a guest VM via PowerShell Direct.

    No network or WinRM required — uses Copy-Item over a VMBus PSSession.
    Creates destination parent directories in the guest if they don't exist.

    Args:
        vm_name:     Name of the VM
        local_path:  Absolute path to the source file on this host
        remote_path: Absolute destination path inside the guest
        username:    Guest OS username — overrides HYPERV_GUEST_USERNAME env var
        password:    Guest OS password — overrides HYPERV_GUEST_PASSWORD env var

    Returns: {ok, bytes_copied}
    """
    if not vm_name or not local_path or not remote_path:
        raise ValueError("vm_name, local_path, and remote_path are required")
    u, pw = _guest_creds(username, password)
    n  = _ps_escape(vm_name)
    eu = _ps_escape(u)
    ep = _ps_escape(pw)
    lp = _ps_escape(local_path)
    rp = _ps_escape(remote_path)
    script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
$s = New-PSSession -VMName '{n}' -Credential $cred -ErrorAction Stop
try {{
    $dir = Split-Path '{rp}' -Parent
    if ($dir) {{
        Invoke-Command -Session $s -ScriptBlock {{
            param($d) New-Item -ItemType Directory -Path $d -Force | Out-Null
        }} -ArgumentList $dir -ErrorAction SilentlyContinue
    }}
    Copy-Item -ToSession $s -Path '{lp}' -Destination '{rp}' -Force -ErrorAction Stop
    (Get-Item -LiteralPath '{lp}').Length
}} finally {{
    Remove-PSSession $s -ErrorAction SilentlyContinue
}}
"""
    r = _run_ps(script.strip(), timeout=300)
    if r["returncode"] != 0:
        return {"ok": False, "error": r["stderr"] or r["stdout"]}
    try:
        n_bytes = int(r["stdout"].strip().splitlines()[-1])
    except (ValueError, IndexError):
        n_bytes = -1
    return {"ok": True, "bytes_copied": n_bytes}


@mcp.tool()
def hyperv_guest_get(
    vm_name: str,
    remote_path: str,
    local_path: str,
    username: str = "",
    password: str = "",
) -> dict:
    """
    Copy a file from a guest VM to the local machine via PowerShell Direct.

    No network or WinRM required — uses Copy-Item over a VMBus PSSession.

    Args:
        vm_name:     Name of the VM
        remote_path: Absolute path to the source file inside the guest
        local_path:  Absolute destination path on this host
        username:    Guest OS username — overrides HYPERV_GUEST_USERNAME env var
        password:    Guest OS password — overrides HYPERV_GUEST_PASSWORD env var

    Returns: {ok, bytes_copied}
    """
    if not vm_name or not remote_path or not local_path:
        raise ValueError("vm_name, remote_path, and local_path are required")
    u, pw = _guest_creds(username, password)
    n  = _ps_escape(vm_name)
    eu = _ps_escape(u)
    ep = _ps_escape(pw)
    rp = _ps_escape(remote_path)
    lp = _ps_escape(local_path)
    script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
$s = New-PSSession -VMName '{n}' -Credential $cred -ErrorAction Stop
try {{
    Copy-Item -FromSession $s -Path '{rp}' -Destination '{lp}' -Force -ErrorAction Stop
    (Get-Item -LiteralPath '{lp}').Length
}} finally {{
    Remove-PSSession $s -ErrorAction SilentlyContinue
}}
"""
    r = _run_ps(script.strip(), timeout=300)
    if r["returncode"] != 0:
        return {"ok": False, "error": r["stderr"] or r["stdout"]}
    try:
        n_bytes = int(r["stdout"].strip().splitlines()[-1])
    except (ValueError, IndexError):
        n_bytes = -1
    return {"ok": True, "bytes_copied": n_bytes}


@mcp.tool()
def hyperv_guest_read_file(
    vm_name: str,
    remote_path: str,
    max_bytes: int = 256 * 1024,
    username: str = "",
    password: str = "",
) -> dict:
    """
    Read a small file from a guest VM without copying to the host filesystem.

    Returns base64-encoded content. For files larger than ~1 MB, use
    hyperv_guest_get instead.

    Args:
        vm_name:     Name of the VM
        remote_path: Absolute path to the file inside the guest
        max_bytes:   Maximum bytes to read; content truncated at byte boundary
                     (default 256 KB)
        username:    Guest OS username — overrides HYPERV_GUEST_USERNAME env var
        password:    Guest OS password — overrides HYPERV_GUEST_PASSWORD env var

    Returns: {ok, content_b64, bytes_read, truncated}
    """
    if not vm_name or not remote_path:
        raise ValueError("vm_name and remote_path are required")
    u, pw = _guest_creds(username, password)
    n  = _ps_escape(vm_name)
    eu = _ps_escape(u)
    ep = _ps_escape(pw)
    rp = _ps_escape(remote_path)
    script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
$r = Invoke-Command -VMName '{n}' -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($path, $maxb)
    $b = [System.IO.File]::ReadAllBytes($path)
    $t = $false
    if ($b.Length -gt $maxb) {{ $b = $b[0..($maxb - 1)]; $t = $true }}
    [PSCustomObject]@{{
        content_b64 = [System.Convert]::ToBase64String($b)
        bytes_read  = $b.Length
        truncated   = $t
    }}
}} -ArgumentList '{rp}', {max_bytes}
$r | ConvertTo-Json -Compress
"""
    r = _run_ps(script.strip(), timeout=120)
    if r["returncode"] != 0:
        return {"ok": False, "error": r["stderr"] or r["stdout"]}
    try:
        data = _json.loads(r["stdout"])
        return {"ok": True, **data}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def hyperv_guest_list_dir(
    vm_name: str,
    remote_path: str,
    username: str = "",
    password: str = "",
) -> dict:
    """
    List entries in a directory on a guest VM via PowerShell Direct.

    Args:
        vm_name:     Name of the VM
        remote_path: Absolute path to the directory inside the guest
        username:    Guest OS username — overrides HYPERV_GUEST_USERNAME env var
        password:    Guest OS password — overrides HYPERV_GUEST_PASSWORD env var

    Returns: {ok, entries[{name, is_dir, size_bytes, modified}]}
    """
    if not vm_name or not remote_path:
        raise ValueError("vm_name and remote_path are required")
    u, pw = _guest_creds(username, password)
    n  = _ps_escape(vm_name)
    eu = _ps_escape(u)
    ep = _ps_escape(pw)
    rp = _ps_escape(remote_path)
    script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{eu}', [System.Net.NetworkCredential]::new('', '{ep}').SecurePassword)
$items = Invoke-Command -VMName '{n}' -Credential $cred -ErrorAction Stop -ScriptBlock {{
    param($path)
    Get-ChildItem -LiteralPath $path -ErrorAction Stop | ForEach-Object {{
        [PSCustomObject]@{{
            name       = $_.Name
            is_dir     = $_.PSIsContainer
            size_bytes = if ($_.PSIsContainer) {{ 0 }} else {{ $_.Length }}
            modified   = $_.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }}
    }}
}} -ArgumentList '{rp}'
if ($items) {{ @($items) | ConvertTo-Json -Compress }} else {{ '[]' }}
"""
    r = _run_ps(script.strip(), timeout=60)
    if r["returncode"] != 0:
        return {"ok": False, "error": r["stderr"] or r["stdout"]}
    try:
        raw = r["stdout"].strip()
        if not raw or raw == "null":
            entries = []
        else:
            parsed = _json.loads(raw)
            entries = [parsed] if isinstance(parsed, dict) else list(parsed)
        return {"ok": True, "entries": entries}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# MCP TOOLS — Victim-credential guest execution (Medium IL, EoP trigger side)
# ---------------------------------------------------------------------------

@mcp.tool()
def hyperv_victim_run(
    vm_name: str,
    command: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    timeout_ms: int = 60000,
) -> dict:
    """
    Run an executable inside a guest VM as the unprivileged victim account (Medium IL).

    Uses credentials from HYPERV_GUEST_VICTIM_USERNAME / HYPERV_GUEST_VICTIM_PASSWORD
    environment variables. Intended for EoP scenarios where the vulnerable code
    path must be triggered from a non-admin context.

    Args:
        vm_name:    Name of the VM
        command:    Full path to the executable (e.g. C:\\Windows\\Temp\\poc.exe)
        args:       Command-line arguments
        cwd:        Working directory inside the guest (optional)
        timeout_ms: Timeout hint in milliseconds (default 60 s)

    Returns: {ok, exit_code, stdout, stderr}
    """
    if not vm_name or not command:
        raise ValueError("vm_name and command are required")
    u, pw = _victim_creds()
    args_str = " ".join(f"'{_ps_escape(a)}'" for a in (args or []))
    cmd_expr = f"& '{_ps_escape(command)}' {args_str}".strip()
    if cwd:
        inner = (
            f"Push-Location '{_ps_escape(cwd)}'\n"
            f"try {{\n  {cmd_expr}\n}} finally {{\n  Pop-Location\n}}\n"
            f"exit $LASTEXITCODE"
        )
    else:
        inner = f"{cmd_expr}\nexit $LASTEXITCODE"
    timeout_s = max(30, timeout_ms // 1000 + 10)
    return _guest_run_encoded(vm_name, inner, u, pw, timeout_s, elevated=False)


@mcp.tool()
def hyperv_victim_run_ps(
    vm_name: str,
    script: str,
    timeout_ms: int = 60000,
) -> dict:
    """
    Run a PowerShell script inside a guest VM as the unprivileged victim account (Medium IL).

    Uses credentials from HYPERV_GUEST_VICTIM_USERNAME / HYPERV_GUEST_VICTIM_PASSWORD
    environment variables. Intended for EoP scenarios where the vulnerable code
    path must be triggered from a non-admin context.

    Args:
        vm_name:    Name of the VM
        script:     PowerShell script text (may be multi-line)
        timeout_ms: Timeout hint in milliseconds (default 60 s)

    Returns: {ok, exit_code, stdout, stderr}
    """
    if not vm_name or not script:
        raise ValueError("vm_name and script are required")
    u, pw = _victim_creds()
    timeout_s = max(30, timeout_ms // 1000 + 10)
    return _guest_run_encoded(vm_name, script, u, pw, timeout_s, elevated=False)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("Hyper-V MCP server starting (stdio transport)...", file=sys.stderr)
    print("Connect your MCP client to this process via stdio.", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
