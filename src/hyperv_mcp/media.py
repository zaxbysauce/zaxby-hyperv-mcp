"""VM and media preparation for repeatable deployment testing.

All operations are policy-scoped to the VM allowlist and host path roots.
Gate matrix (see README):
  - read-only: disk_list, media_list, firmware_get
  - media category, no confirm (reversible): media attach/detach, network set
  - vm_provision category + confirm: vm create, disk add, firmware boot
    order, TPM set, SecureBoot set

Every mutating op takes the per-VM lock and resolves the VM name through the
allowlist first. Host file paths (VHD/ISO) pass the canonicalization policy
before touching PowerShell. Deployment media is never created here.
"""

from __future__ import annotations

import json
import os

from . import policy, pswindows, vmlocks
from .config import Config

_BOOT_TYPES = ("Drive", "Network", "File")

_SECUREBOOT_ONOFF = {True: "On", False: "Off"}


class MediaError(RuntimeError):
    """Structured media/provisioning failure."""


def _checked_vm(cfg: Config, vm_name: str) -> str:
    if not vm_name or not vm_name.strip():
        raise ValueError("vm_name is required")
    policy.vm_allowed(cfg, vm_name)
    return vm_name


def _checked_new_name(cfg: Config, name: str) -> str:
    """A NEW VM name must match the allowlist so future operations stay
    policy-scoped (a created-but-unallowed VM would be unmanageable)."""
    if not name or not name.strip():
        raise ValueError("name is required")
    if len(name) > 200:
        raise ValueError("name exceeds 200 characters")
    policy.vm_allowed(cfg, name)
    return name


def _checked_file_path(cfg: Config, path: str, *, write: bool, must_exist: bool, extensions: tuple[str, ...]) -> str:
    if not path or not path.strip():
        raise ValueError("path is required")
    normalized = os.path.normpath(os.path.abspath(path))
    ext = os.path.splitext(normalized)[1].lower()
    if ext not in extensions:
        raise ValueError(f"path must have one of {extensions} (got {ext or 'none'})")
    if write:
        policy.check_host_write(cfg, normalized)
    else:
        policy.check_host_read(cfg, normalized)
    if must_exist and not os.path.isfile(normalized):
        raise MediaError(f"file not found: {normalized}")
    return normalized


def _run(cfg: Config, script: str, ctx: str, timeout_s: int = 300) -> pswindows.PSResult:
    result = pswindows.run_ps(script.strip(), timeout_s=timeout_s)
    try:
        return pswindows.check_result(result, ctx)
    except RuntimeError as exc:
        raise MediaError(str(exc)) from None


def _json_out(result: pswindows.PSResult, ctx: str) -> dict | list:
    raw = result.stdout.strip()
    if not raw or raw == "null":
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MediaError(f"{ctx}: output parse failed: {exc} | raw: {raw[:200]!r}") from None


def _generation_guard(cfg: Config, vm_name: str) -> None:
    """Explicit error for Gen1 VMs (Get-VMFirmware/TPM are Gen2-only)."""
    result = pswindows.run_ps(
        "(Get-VM -Name " + pswindows.ps_name(vm_name) + " -ErrorAction Stop).Generation.ToString()",
        timeout_s=60,
    )
    try:
        pswindows.check_result(result, f"resolve generation of '{vm_name}'")
    except RuntimeError as exc:
        raise MediaError(str(exc)) from None
    if result.stdout.strip() != "2":
        raise MediaError(
            f"VM '{vm_name}' is Generation {result.stdout.strip()}; this operation requires Generation 2"
        )


# ---------------------------------------------------------------------------
# provisioning (vm_provision category + confirm)
# ---------------------------------------------------------------------------

def vm_create(
    cfg: Config, name: str, memory_mb: int = 2048, cpu_count: int = 1,
    generation: int = 2, vhd_path: str = "", vhd_size_gb: int = 64,
    switch_name: str = "", confirm: bool = False,
) -> dict:
    _checked_new_name(cfg, name)
    policy.require_destructive(cfg, "vm_provision", confirm, f"create VM '{name}'")
    if memory_mb < 32 or memory_mb > 64 * 1024:
        raise ValueError("memory_mb must be within 32..65536")
    if not (1 <= cpu_count <= 64):
        raise ValueError("cpu_count must be within 1..64")
    if generation not in (1, 2):
        raise ValueError("generation must be 1 or 2")
    if not vhd_path:
        raise ValueError("vhd_path is required")
    vhd = _checked_file_path(cfg, vhd_path, write=True, must_exist=False, extensions=(".vhdx", ".vhd"))
    if not (1 <= vhd_size_gb <= 2048):
        raise ValueError("vhd_size_gb must be within 1..2048")

    parent = os.path.dirname(vhd)
    if parent:
        os.makedirs(parent, exist_ok=True)
    pre = ""
    if switch_name:
        pre = (
            "$vmsw = Get-VMSwitch -Name " + pswindows.ps_name(switch_name)
            + " -ErrorAction Stop\n"
        )
    lines = [pre] if pre else []
    lines += [
        f"$vhd = New-VHD -Path {pswindows.ps_quote(vhd)} -SizeBytes ({int(vhd_size_gb)}GB) -Fixed:$false -ErrorAction Stop",
        # If New-VM fails the fresh VHDX would orphan on the host and wedge
        # every retry against the exists-refusal below — clean it up first.
        "try {\n"
        f"  $vm = New-VM -Name {pswindows.ps_name(name)} -MemoryStartupBytes ({int(memory_mb)}MB) "
        f"-Generation {generation} -VHDPath $vhd.Path -ErrorAction Stop\n"
        "} catch {\n"
        f"  Remove-Item -LiteralPath {pswindows.ps_quote(vhd)} -Force -ErrorAction SilentlyContinue\n"
        "  throw\n"
        "}",
    ]
    if switch_name:
        lines.append(
            f"Connect-VMNetworkAdapter -VMNetworkAdapter (Get-VMNetworkAdapter -VM $vm) "
            f"-SwitchName {pswindows.ps_quote(switch_name)} -ErrorAction Stop"
        )
    lines.append(
        "[PSCustomObject]@{ id = $vm.Id.ToString(); name = $vm.Name; state = [string]$vm.State; "
        "generation = $vm.Generation } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(name):
        if os.path.isfile(vhd):
            raise MediaError(f"VHD already exists: {vhd} (refusing to overwrite)")
        result = _run(cfg, "\n".join(lines), f"vm_create({name})", timeout_s=300)
    out = _json_out(result, "vm_create")
    return {"ok": True, **out} if isinstance(out, dict) else {"ok": True}


def vm_disk_add(
    cfg: Config, vm_name: str, path: str, size_gb: int,
    controller_type: str = "SCSI", confirm: bool = False,
) -> dict:
    _checked_vm(cfg, vm_name)
    policy.require_destructive(cfg, "vm_provision", confirm, f"add {size_gb}GB disk '{path}' to '{vm_name}'")
    if controller_type not in ("SCSI", "IDE"):
        raise ValueError("controller_type must be SCSI or IDE")
    vhd = _checked_file_path(cfg, path, write=True, must_exist=False, extensions=(".vhdx", ".vhd"))
    if not (1 <= size_gb <= 2048):
        raise ValueError("size_gb must be within 1..2048")
    lines = [
        f"$vhd = New-VHD -Path {pswindows.ps_quote(vhd)} -SizeBytes ({int(size_gb)}GB) -Fixed:$false -ErrorAction Stop",
        # Same orphan hazard as vm_create: a failed attach must not leave the
        # staged VHDX behind to wedge retries.
        "try {\n"
        f"  Add-VMHardDiskDrive -VMName {pswindows.ps_name(vm_name)} -Path $vhd.Path "
        f"-ControllerType {controller_type} -ErrorAction Stop\n"
        "} catch {\n"
        f"  Remove-Item -LiteralPath {pswindows.ps_quote(vhd)} -Force -ErrorAction SilentlyContinue\n"
        "  throw\n"
        "}",
        f"(Get-VMHardDiskDrive -VMName {pswindows.ps_name(vm_name)} | Measure-Object).Count | "
        "ForEach-Object { [PSCustomObject]@{ disk_count = $_ } } | ConvertTo-Json -Compress",
    ]
    with vmlocks.vm_lock(vm_name):
        if os.path.isfile(vhd):
            raise MediaError(f"VHD already exists: {vhd} (refusing to overwrite)")
        result = _run(cfg, "\n".join(lines), f"vm_disk_add({vm_name})")
    out = _json_out(result, "vm_disk_add")
    return {"ok": True, "vhd_path": vhd, **out} if isinstance(out, dict) else {"ok": True, "vhd_path": vhd}


def vm_disk_list(cfg: Config, vm_name: str) -> dict:
    _checked_vm(cfg, vm_name)
    script = (
        "Get-VMHardDiskDrive -VMName " + pswindows.ps_name(vm_name) + " | ForEach-Object {\n"
        "  [PSCustomObject]@{ controller_type = [string]$_.ControllerType; controller_number = $_.ControllerNumber;\n"
        "    lun = $_.LunNumber; path = $_.Path }\n"
        "} | ConvertTo-Json -Compress\n"
    )
    result = _run(cfg, script, f"vm_disk_list({vm_name})")
    raw = result.stdout.strip()
    drives = [] if not raw or raw == "null" else json.loads(raw)
    if isinstance(drives, dict):
        drives = [drives]
    return {"ok": True, "disks": drives}


# ---------------------------------------------------------------------------
# media (media category, no confirm — reversible)
# ---------------------------------------------------------------------------

def vm_media_attach(cfg: Config, vm_name: str, iso_path: str) -> dict:
    _checked_vm(cfg, vm_name)
    policy.require_category(cfg, "media", f"attach ISO to '{vm_name}'")
    iso = _checked_file_path(cfg, iso_path, write=False, must_exist=True, extensions=(".iso",))
    script = (
        "Add-VMDvdDrive -VMName " + pswindows.ps_name(vm_name) + " -Path "
        + pswindows.ps_quote(iso) + " -ErrorAction Stop\n"
        "(Get-VMDvdDrive -VMName " + pswindows.ps_name(vm_name) + " | "
        "Where-Object { $_.Path -eq " + pswindows.ps_quote(iso) + " } | Measure-Object).Count | "
        "ForEach-Object { [PSCustomObject]@{ attached = ($_ -gt 0) } } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(vm_name):
        _run(cfg, script, f"vm_media_attach({vm_name})")
    return {"ok": True, "iso_path": iso}


def vm_media_detach(cfg: Config, vm_name: str) -> dict:
    _checked_vm(cfg, vm_name)
    policy.require_category(cfg, "media", f"detach media from '{vm_name}'")
    script = (
        "$drives = Get-VMDvdDrive -VMName " + pswindows.ps_name(vm_name) + " -ErrorAction Stop\n"
        "$paths = @($drives | ForEach-Object { $_.Path })\n"
        "$drives | Remove-VMDvdDrive -ErrorAction Stop\n"
        "[PSCustomObject]@{ removed = $paths } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(vm_name):
        result = _run(cfg, script, f"vm_media_detach({vm_name})")
    out = _json_out(result, "vm_media_detach")
    removed = out.get("removed", []) if isinstance(out, dict) else []
    return {"ok": True, "removed": removed}


def vm_media_list(cfg: Config, vm_name: str) -> dict:
    _checked_vm(cfg, vm_name)
    script = (
        "Get-VMDvdDrive -VMName " + pswindows.ps_name(vm_name) + " | ForEach-Object {\n"
        "  [PSCustomObject]@{ controller_number = $_.ControllerNumber; lun = $_.LunNumber; path = $_.Path }\n"
        "} | ConvertTo-Json -Compress\n"
    )
    result = _run(cfg, script, f"vm_media_list({vm_name})")
    raw = result.stdout.strip()
    drives = [] if not raw or raw == "null" else json.loads(raw)
    if isinstance(drives, dict):
        drives = [drives]
    return {"ok": True, "media": drives}


def vm_network_set(cfg: Config, vm_name: str, switch_name: str) -> dict:
    _checked_vm(cfg, vm_name)
    policy.require_category(cfg, "media", f"connect '{vm_name}' to switch '{switch_name}'")
    if not switch_name or not switch_name.strip():
        raise ValueError("switch_name is required")
    script = (
        "Connect-VMNetworkAdapter -VMName " + pswindows.ps_name(vm_name)
        + " -SwitchName " + pswindows.ps_quote(switch_name) + " -ErrorAction Stop\n"
        "(Get-VMNetworkAdapter -VMName " + pswindows.ps_name(vm_name) + " | "
        "Where-Object { $_.SwitchName -eq " + pswindows.ps_quote(switch_name) + " } | Measure-Object).Count | "
        "ForEach-Object { [PSCustomObject]@{ connected = ($_ -gt 0) } } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(vm_name):
        _run(cfg, script, f"vm_network_set({vm_name})")
    return {"ok": True, "switch_name": switch_name}


# ---------------------------------------------------------------------------
# firmware / security (read: open; write: vm_provision + confirm; Gen2-only)
# ---------------------------------------------------------------------------

def vm_firmware_get(cfg: Config, vm_name: str) -> dict:
    _checked_vm(cfg, vm_name)
    _generation_guard(cfg, vm_name)
    script = (
        "$f = Get-VMFirmware -VMName " + pswindows.ps_name(vm_name) + " -ErrorAction Stop\n"
        "$sec = Get-VMSecurity -VMName " + pswindows.ps_name(vm_name) + " -ErrorAction SilentlyContinue\n"
        "[PSCustomObject]@{ secure_boot = [string]$f.SecureBoot; secure_boot_template = $f.SecureBootTemplate; "
        "boot_order = @($f.BootOrder | ForEach-Object { [string]$_.BootType }); "
        "tpm_enabled = if ($sec) { [bool]$sec.TpmEnabled } else { $null } } | ConvertTo-Json -Compress"
    )
    result = _run(cfg, script, f"vm_firmware_get({vm_name})")
    out = _json_out(result, "vm_firmware_get")
    return {"ok": True, **out} if isinstance(out, dict) else {"ok": True}


def vm_firmware_set_boot_order(cfg: Config, vm_name: str, boot_type: str = "Drive", confirm: bool = False) -> dict:
    _checked_vm(cfg, vm_name)
    policy.require_destructive(cfg, "vm_provision", confirm, f"set '{vm_name}' first boot device to {boot_type}")
    if boot_type not in _BOOT_TYPES:
        raise ValueError(f"boot_type must be one of {_BOOT_TYPES}")
    _generation_guard(cfg, vm_name)
    script = (
        "$f = Get-VMFirmware -VMName " + pswindows.ps_name(vm_name) + " -ErrorAction Stop\n"
        "$device = $f.BootOrder | Where-Object { [string]$_.BootType -eq '" + boot_type + "' } | Select-Object -First 1\n"
        "if (-not $device) { throw ('no boot device of type " + boot_type + " present') }\n"
        "Set-VMFirmware -VMName " + pswindows.ps_name(vm_name) + " -FirstBootDevice $device -ErrorAction Stop\n"
        "$f2 = Get-VMFirmware -VMName " + pswindows.ps_name(vm_name) + "\n"
        "[PSCustomObject]@{ first_boot = [string]$f2.BootOrder[0].BootType } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(vm_name):
        result = _run(cfg, script, f"vm_firmware_set_boot_order({vm_name})")
    out = _json_out(result, "vm_firmware_set_boot_order")
    return {"ok": True, **out} if isinstance(out, dict) else {"ok": True}


def vm_tpm_set(cfg: Config, vm_name: str, enabled: bool, confirm: bool = False) -> dict:
    _checked_vm(cfg, vm_name)
    policy.require_destructive(cfg, "vm_provision", confirm, f"{'enable' if enabled else 'disable'} TPM on '{vm_name}'")
    _generation_guard(cfg, vm_name)
    cmdlet = "Enable-VMTPM" if enabled else "Disable-VMTPM"
    script = (
        cmdlet + " -VMName " + pswindows.ps_name(vm_name) + " -ErrorAction Stop\n"
        "$sec = Get-VMSecurity -VMName " + pswindows.ps_name(vm_name) + "\n"
        "[PSCustomObject]@{ tpm_enabled = [bool]$sec.TpmEnabled } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(vm_name):
        result = _run(cfg, script, f"vm_tpm_set({vm_name})")
    out = _json_out(result, "vm_tpm_set")
    return {"ok": True, **out} if isinstance(out, dict) else {"ok": True}


def vm_secureboot_set(cfg: Config, vm_name: str, enabled: bool, template: str = "", confirm: bool = False) -> dict:
    _checked_vm(cfg, vm_name)
    policy.require_destructive(cfg, "vm_provision", confirm, f"{'enable' if enabled else 'disable'} SecureBoot on '{vm_name}'")
    _generation_guard(cfg, vm_name)
    onoff = _SECUREBOOT_ONOFF[bool(enabled)]
    template_part = ""
    if template:
        if not template.strip():
            raise ValueError("template must be a non-empty name when given")
        template_part = " -SecureBootTemplate " + pswindows.ps_quote(template)
    script = (
        "Set-VMFirmware -VMName " + pswindows.ps_name(vm_name)
        + " -EnableSecureBoot " + onoff + template_part + " -ErrorAction Stop\n"
        "$f = Get-VMFirmware -VMName " + pswindows.ps_name(vm_name) + "\n"
        "[PSCustomObject]@{ secure_boot = [string]$f.SecureBoot; secure_boot_template = $f.SecureBootTemplate } "
        "| ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(vm_name):
        result = _run(cfg, script, f"vm_secureboot_set({vm_name})")
    out = _json_out(result, "vm_secureboot_set")
    return {"ok": True, **out} if isinstance(out, dict) else {"ok": True}
