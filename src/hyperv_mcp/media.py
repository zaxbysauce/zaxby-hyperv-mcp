"""VM and media preparation for repeatable deployment testing.

All operations are policy-scoped to the VM allowlist and host path roots.
Gate matrix (see README):
  - read-only: disk_list, media_list, firmware_get, video_get
  - media category, no confirm (reversible): media attach/detach, network set
  - display category, no confirm (reversible, applies at next start): video
    resolution set; its optional restart leg is additionally gated by the
    destructive stop category + confirm
  - vm_provision category + confirm: vm create, disk add, firmware boot
    order, TPM set, SecureBoot set

Every mutating op takes the per-VM lock keyed on the resolved VM GUID
(vmident.resolve, by name or by id) and gates on policy first. Host file
paths (VHD/ISO) pass the canonicalization policy before touching
PowerShell. Deployment media is never created here.
"""

from __future__ import annotations

import json
import os

from . import guestexec, lifecycle, policy, pswindows, vmident, vmlocks
from .config import Config

_BOOT_TYPES = ("Drive", "Network", "File")

_SECUREBOOT_ONOFF = {True: "On", False: "Off"}

_VIDEO_TYPES = ("single", "maximum", "default")

_VIDEO_RES_TYPE = {"single": "Single", "maximum": "Maximum"}


class MediaError(RuntimeError):
    """Structured media/provisioning failure."""


def _checked_new_name(cfg: Config, name: str) -> str:
    """A NEW VM name must match the allowlist so future operations stay
    policy-scoped (a created-but-unallowed VM would be unmanageable)."""
    if not name or not name.strip():
        raise ValueError("name is required")
    if len(name) > 200:
        raise ValueError("name exceeds 200 characters")
    policy.vm_allowed(cfg, name)
    return name


def _reject_remote_file_ops(cfg: Config, what: str) -> None:
    """Fail loud for file-backed media ops in remote mode (cubic PR #47 P1).

    VHD/ISO paths are validated against agent-box policy and local existence
    here, but in remote mode they are consumed BY the remote Hyper-V host —
    a host-local path would fail the local must_exist check, and a local
    path would create/attach the wrong machine's file. Fail with the honest
    limitation instead of silently operating on the wrong machine.
    """
    if pswindows.hyperv_host(cfg):
        raise MediaError(
            f"remote Hyper-V host mode does not support {what} in this "
            "release: the file path is validated on the agent box but the "
            "operation executes on the remote host, so the file must exist "
            "there. Run this operation in local mode (server on the Hyper-V "
            "host) or pre-place the file on the remote host."
        )


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
    script, stdin = pswindows.compose_remote(cfg, script.strip())
    if stdin is None:
        result = pswindows.run_ps(script, timeout_s=timeout_s)
    else:
        result = pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=stdin)
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


def _generation_guard(cfg: Config, ref: vmident.VMRef) -> None:
    """Explicit error for Gen1 VMs (Get-VMFirmware/TPM are Gen2-only)."""
    script = (
        guestexec.vm_target_preamble(ref.id)
        + "\n(Get-VM -Id $vmTarget -ErrorAction Stop).Generation.ToString()\n"
    )
    result = _run(cfg, script, f"resolve generation of '{ref.name}'", timeout_s=60)
    try:
        pswindows.check_result(result, f"resolve generation of '{ref.name}'")
    except RuntimeError as exc:
        raise MediaError(str(exc)) from None
    if result.stdout.strip() != "2":
        raise MediaError(
            f"VM '{ref.name}' is Generation {result.stdout.strip()}; this operation requires Generation 2"
        )


def _resolve_vm_prefix(ref: vmident.VMRef) -> str:
    """Validated GUID preamble + Get-VM -Id fetch; scripts below bind cmdlets
    with -VM $vm.

    Hyper-V cmdlets accept -VM (object) but not -VMId, and name-based binding
    intermittently fails under vmms WMI stress ('Call cancelled' / 'does not
    resolve to a single virtual machine'). The caller has already resolved the
    identity host-side (vmident.resolve); the preamble only binds $vmTarget,
    and this prefix also fetches the VM object.
    """
    return (
        guestexec.vm_target_preamble(ref.id)
        + "\n$vm = Get-VM -Id $vmTarget -ErrorAction Stop\n"
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
    _reject_remote_file_ops(cfg, "vm_create (VHD path)")
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
        # Refuse to shadow an existing VM of the same name BEFORE creating
        # anything. The predicate mirrors guestexec.psdirect_vm_target exactly
        # (literal ElementName -eq via ps_quote AND a GUID-shaped Name), so a
        # host or non-VM computer system sharing the name is not falsely
        # refused and "same name" is the resolver's notion.
        "if (@(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem"
        " -ErrorAction Stop | Where-Object { ($_.ElementName -eq "
        + pswindows.ps_quote(name)
        + ") -and ($_.Name -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
        "-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') }).Count)"
        " { throw 'VM name already exists' }",
        f"$vhd = New-VHD -Path {pswindows.ps_quote(vhd)} -SizeBytes ({int(vhd_size_gb)}GB) -Fixed:$false -ErrorAction Stop",
        # If New-VM fails the fresh VHDX would orphan on the host and wedge
        # every retry against the exists-refusal below — clean it up first.
        "try {\n"
        # New-VM -Name is a plain String parameter (no wildcard semantics at
        # creation), so the name is ps_quote'd: the created ElementName is the
        # literal the guard above tested (PRR-025 — a ps_name-escaped form
        # would plant backticks in ElementName for wildcard-bearing names).
        f"  $vm = New-VM -Name {pswindows.ps_quote(name)} -MemoryStartupBytes ({int(memory_mb)}MB) "
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
    cfg: Config, vm_name: str = "", path: str = "", size_gb: int = 0,
    controller_type: str = "SCSI", confirm: bool = False, vm_id: str = "",
) -> dict:
    policy.require_destructive(cfg, "vm_provision", confirm, f"add {size_gb}GB disk '{path}' to '{vm_name or vm_id}'")
    if controller_type not in ("SCSI", "IDE"):
        raise ValueError("controller_type must be SCSI or IDE")
    _reject_remote_file_ops(cfg, "vm_disk_add (VHD path)")
    vhd = _checked_file_path(cfg, path, write=True, must_exist=False, extensions=(".vhdx", ".vhd"))
    if not (1 <= size_gb <= 2048):
        raise ValueError("size_gb must be within 1..2048")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    lines = [
        f"$vhd = New-VHD -Path {pswindows.ps_quote(vhd)} -SizeBytes ({int(size_gb)}GB) -Fixed:$false -ErrorAction Stop",
        # Same orphan hazard as vm_create: a failed attach must not leave the
        # staged VHDX behind to wedge retries.
        "try {\n"
        f"  Add-VMHardDiskDrive -VM $vm -Path $vhd.Path "
        f"-ControllerType {controller_type} -ErrorAction Stop\n"
        "} catch {\n"
        f"  Remove-Item -LiteralPath {pswindows.ps_quote(vhd)} -Force -ErrorAction SilentlyContinue\n"
        "  throw\n"
        "}",
        # Informational count AFTER a completed, non-idempotent mutation: a
        # transient read failure must not fail the call (a retry would hit the
        # existing-VHD guard); report an unknown count instead.
        "$diskCount = $null\n"
        "try { $diskCount = (Get-VMHardDiskDrive -VM $vm -ErrorAction Stop | Measure-Object).Count } catch { }\n"
        "[PSCustomObject]@{ disk_count = $diskCount } | ConvertTo-Json -Compress",
    ]
    with vmlocks.vm_lock(ref.id):
        if os.path.isfile(vhd):
            raise MediaError(f"VHD already exists: {vhd} (refusing to overwrite)")
        result = _run(cfg, _resolve_vm_prefix(ref) + "\n".join(lines), f"vm_disk_add({ref.name})")
    out = _json_out(result, "vm_disk_add")
    if isinstance(out, dict):
        return {"ok": True, **out, "vhd_path": vhd, "vm_name": ref.name}
    return {"ok": True, "vhd_path": vhd, "vm_name": ref.name}


def vm_disk_list(cfg: Config, vm_name: str = "", vm_id: str = "") -> dict:
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    script = _resolve_vm_prefix(ref) + (
        "Get-VMHardDiskDrive -VM $vm -ErrorAction Stop | ForEach-Object {\n"
        "  [PSCustomObject]@{ controller_type = [string]$_.ControllerType; controller_number = $_.ControllerNumber;\n"
        "    lun = $_.LunNumber; path = $_.Path }\n"
        "} | ConvertTo-Json -Compress\n"
    )
    result = _run(cfg, script, f"vm_disk_list({ref.name})")
    raw = result.stdout.strip()
    drives = [] if not raw or raw == "null" else json.loads(raw)
    if isinstance(drives, dict):
        drives = [drives]
    return {"ok": True, "disks": drives, "vm_name": ref.name}


# ---------------------------------------------------------------------------
# media (media category, no confirm — reversible)
# ---------------------------------------------------------------------------

def vm_media_attach(cfg: Config, vm_name: str = "", iso_path: str = "", vm_id: str = "") -> dict:
    policy.require_category(cfg, "media", f"attach ISO to '{vm_name or vm_id}'")
    _reject_remote_file_ops(cfg, "vm_media_attach (ISO path)")
    iso = _checked_file_path(cfg, iso_path, write=False, must_exist=True, extensions=(".iso",))
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    script = _resolve_vm_prefix(ref) + (
        "Add-VMDvdDrive -VM $vm -Path "
        + pswindows.ps_quote(iso) + " -ErrorAction Stop\n"
        # Informational check AFTER a completed, non-idempotent attach: a
        # transient read failure must not fail the call (a retry would add a
        # duplicate drive); report an unknown result instead.
        "$attached = $null\n"
        "try { $attached = (Get-VMDvdDrive -VM $vm -ErrorAction Stop | "
        "Where-Object { $_.Path -eq " + pswindows.ps_quote(iso) + " } | Measure-Object).Count -gt 0 } catch { }\n"
        "[PSCustomObject]@{ attached = $attached } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(ref.id):
        result = _run(cfg, script, f"vm_media_attach({ref.name})")
    out = _json_out(result, "vm_media_attach")
    attached = out.get("attached") if isinstance(out, dict) else None
    return {"ok": True, "iso_path": iso, "attached": attached, "vm_name": ref.name}


def vm_media_detach(cfg: Config, vm_name: str = "", vm_id: str = "") -> dict:
    policy.require_category(cfg, "media", f"detach media from '{vm_name or vm_id}'")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    script = _resolve_vm_prefix(ref) + (
        "$drives = Get-VMDvdDrive -VM $vm -ErrorAction Stop\n"
        "$paths = @($drives | ForEach-Object { $_.Path })\n"
        "$drives | Remove-VMDvdDrive -ErrorAction Stop\n"
        "[PSCustomObject]@{ removed = $paths } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(ref.id):
        result = _run(cfg, script, f"vm_media_detach({ref.name})")
    out = _json_out(result, "vm_media_detach")
    removed = out.get("removed", []) if isinstance(out, dict) else []
    return {"ok": True, "removed": removed, "vm_name": ref.name}


def vm_media_list(cfg: Config, vm_name: str = "", vm_id: str = "") -> dict:
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    script = _resolve_vm_prefix(ref) + (
        "Get-VMDvdDrive -VM $vm -ErrorAction Stop | ForEach-Object {\n"
        "  [PSCustomObject]@{ controller_number = $_.ControllerNumber; lun = $_.LunNumber; path = $_.Path }\n"
        "} | ConvertTo-Json -Compress\n"
    )
    result = _run(cfg, script, f"vm_media_list({ref.name})")
    raw = result.stdout.strip()
    drives = [] if not raw or raw == "null" else json.loads(raw)
    if isinstance(drives, dict):
        drives = [drives]
    return {"ok": True, "media": drives, "vm_name": ref.name}


def vm_network_set(cfg: Config, vm_name: str = "", switch_name: str = "", vm_id: str = "") -> dict:
    policy.require_category(cfg, "media", f"connect '{vm_name or vm_id}' to switch '{switch_name}'")
    if not switch_name or not switch_name.strip():
        raise ValueError("switch_name is required")
    # Connect-VMNetworkAdapter has no -VM parameter; bind the adapter objects
    # instead. ALL adapters are connected, matching the former -VMName binding
    # (no -Name defaults to every adapter of the VM).
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    script = _resolve_vm_prefix(ref) + (
        "$adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)\n"
        "if ($adapters.Count -eq 0) { throw 'VM has no network adapter' }\n"
        "$adapters | Connect-VMNetworkAdapter -SwitchName " + pswindows.ps_quote(switch_name)
        + " -ErrorAction Stop\n"
        "$off = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | "
        "Where-Object { $_.SwitchName -ne " + pswindows.ps_quote(switch_name) + " }).Count\n"
        "[PSCustomObject]@{ connected = ($off -eq 0) } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(ref.id):
        result = _run(cfg, script, f"vm_network_set({ref.name})")
    out = _json_out(result, "vm_network_set")
    if isinstance(out, dict) and out.get("connected") is False:
        raise MediaError(f"vm_network_set({ref.name}): not every adapter is on switch '{switch_name}' after connect")
    return {"ok": True, "switch_name": switch_name, "vm_name": ref.name}


# ---------------------------------------------------------------------------
# firmware / security (read: open; write: vm_provision + confirm; Gen2-only)
# ---------------------------------------------------------------------------

def vm_firmware_get(cfg: Config, vm_name: str = "", vm_id: str = "") -> dict:
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    _generation_guard(cfg, ref)
    script = _resolve_vm_prefix(ref) + (
        "$f = Get-VMFirmware -VM $vm -ErrorAction Stop\n"
        "$sec = Get-VMSecurity -VM $vm -ErrorAction SilentlyContinue\n"
        "[PSCustomObject]@{ secure_boot = [string]$f.SecureBoot; secure_boot_template = $f.SecureBootTemplate; "
        "boot_order = @($f.BootOrder | ForEach-Object { [string]$_.BootType }); "
        "tpm_enabled = if ($sec) { [bool]$sec.TpmEnabled } else { $null } } | ConvertTo-Json -Compress"
    )
    result = _run(cfg, script, f"vm_firmware_get({ref.name})")
    out = _json_out(result, "vm_firmware_get")
    if isinstance(out, dict):
        return {"ok": True, **out, "vm_name": ref.name}
    return {"ok": True, "vm_name": ref.name}


def vm_firmware_set_boot_order(
    cfg: Config, vm_name: str = "", boot_type: str = "Drive", confirm: bool = False, vm_id: str = "",
) -> dict:
    policy.require_destructive(cfg, "vm_provision", confirm, f"set '{vm_name or vm_id}' first boot device to {boot_type}")
    if boot_type not in _BOOT_TYPES:
        raise ValueError(f"boot_type must be one of {_BOOT_TYPES}")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    _generation_guard(cfg, ref)
    script = _resolve_vm_prefix(ref) + (
        "$f = Get-VMFirmware -VM $vm -ErrorAction Stop\n"
        "$device = $f.BootOrder | Where-Object { [string]$_.BootType -eq '" + boot_type + "' } | Select-Object -First 1\n"
        "if (-not $device) { throw ('no boot device of type " + boot_type + " present') }\n"
        "Set-VMFirmware -VM $vm -FirstBootDevice $device -ErrorAction Stop\n"
        "$f2 = Get-VMFirmware -VM $vm -ErrorAction Stop\n"
        "[PSCustomObject]@{ first_boot = [string]$f2.BootOrder[0].BootType } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(ref.id):
        result = _run(cfg, script, f"vm_firmware_set_boot_order({ref.name})")
    out = _json_out(result, "vm_firmware_set_boot_order")
    if isinstance(out, dict):
        return {"ok": True, **out, "vm_name": ref.name}
    return {"ok": True, "vm_name": ref.name}


def vm_tpm_set(
    cfg: Config, vm_name: str = "", *, enabled: bool, confirm: bool = False, vm_id: str = "",
) -> dict:
    """`enabled` is keyword-only and REQUIRED (PRR-001): omission must be a
    signature-level error, never a silent default to disable."""
    policy.require_destructive(cfg, "vm_provision", confirm, f"{'enable' if enabled else 'disable'} TPM on '{vm_name or vm_id}'")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    _generation_guard(cfg, ref)
    cmdlet = "Enable-VMTPM" if enabled else "Disable-VMTPM"
    script = _resolve_vm_prefix(ref) + (
        cmdlet + " -VM $vm -ErrorAction Stop\n"
        "$sec = Get-VMSecurity -VM $vm -ErrorAction Stop\n"
        "[PSCustomObject]@{ tpm_enabled = [bool]$sec.TpmEnabled } | ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(ref.id):
        result = _run(cfg, script, f"vm_tpm_set({ref.name})")
    out = _json_out(result, "vm_tpm_set")
    if isinstance(out, dict):
        return {"ok": True, **out, "vm_name": ref.name}
    return {"ok": True, "vm_name": ref.name}


def vm_secureboot_set(
    cfg: Config, vm_name: str = "", *, enabled: bool, template: str = "",
    confirm: bool = False, vm_id: str = "",
) -> dict:
    """`enabled` is keyword-only and REQUIRED (PRR-001): omission must be a
    signature-level error, never a silent default to disable."""
    policy.require_destructive(cfg, "vm_provision", confirm, f"{'enable' if enabled else 'disable'} SecureBoot on '{vm_name or vm_id}'")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    _generation_guard(cfg, ref)
    onoff = _SECUREBOOT_ONOFF[bool(enabled)]
    template_part = ""
    if template:
        if not template.strip():
            raise ValueError("template must be a non-empty name when given")
        template_part = " -SecureBootTemplate " + pswindows.ps_quote(template)
    script = _resolve_vm_prefix(ref) + (
        "Set-VMFirmware -VM $vm"
        + " -EnableSecureBoot " + onoff + template_part + " -ErrorAction Stop\n"
        "$f = Get-VMFirmware -VM $vm -ErrorAction Stop\n"
        "[PSCustomObject]@{ secure_boot = [string]$f.SecureBoot; secure_boot_template = $f.SecureBootTemplate } "
        "| ConvertTo-Json -Compress"
    )
    with vmlocks.vm_lock(ref.id):
        result = _run(cfg, script, f"vm_secureboot_set({ref.name})")
    out = _json_out(result, "vm_secureboot_set")
    if isinstance(out, dict):
        return {"ok": True, **out, "vm_name": ref.name}
    return {"ok": True, "vm_name": ref.name}


# ---------------------------------------------------------------------------
# video (read: open; write: display category, no confirm; Gen1 unverified)
# ---------------------------------------------------------------------------

_CIM_HEAD_LOOKUP = (
    "$cs = Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem"
    " -Filter ('Name=' + \"'\" + $vm.Id.ToString() + \"'\") -ErrorAction Stop\n"
    "$vh = Get-CimAssociatedInstance -InputObject $cs -ResultClassName Msvm_VideoHead | Select-Object -First 1\n"
)

_VIDEO_READBACK = """
$v = Get-VMVideo -VM $vm -ErrorAction Stop | Select-Object -First 1
if (-not $v) { throw 'no video settings returned for the VM' }
$vh = $null
try {
""" + _CIM_HEAD_LOOKUP + """} catch { }
[PSCustomObject]@{
    resolution_type = [string]$v.ResolutionType
    horizontal = $v.HorizontalResolution
    vertical = $v.VerticalResolution
    observed_horizontal = if ($vh) { $vh.CurrentHorizontalResolution } else { $null }
    observed_vertical = if ($vh) { $vh.CurrentVerticalResolution } else { $null }
} | ConvertTo-Json -Compress
"""


def vm_get_video(cfg: Config, vm_name: str = "", vm_id: str = "") -> dict:
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    script = _resolve_vm_prefix(ref) + _VIDEO_READBACK
    result = _run(cfg, script, f"vm_get_video({ref.name})")
    out = _json_out(result, "vm_get_video")
    if isinstance(out, dict):
        return {"ok": True, **out, "vm_name": ref.name}
    return {"ok": True, "vm_name": ref.name}


def vm_set_resolution(
    cfg: Config, vm_name: str = "", width: int = 0, height: int = 0,
    resolution_type: str = "single", restart: bool = False,
    confirm: bool = False, vm_id: str = "",
) -> dict:
    """Set the VM's configured display resolution (Set-VMVideo, issue #44).

    `display` category, no confirm — the change is reversible (resolution_type
    "default"). The host REFUSES Set-VMVideo on a running VM (probe-verified:
    "must be turned off when setting resolution type, horizontal resolution or
    vertical resolution"), so without restart=true the call must target a
    stopped VM and the change applies at its next start
    (effective_after_restart: true). When `restart=true` the tool stops the VM
    FIRST (hard power-off via TurnOff, not a graceful shutdown; an
    already-stopped VM is simply started), sets the mode while off, then
    starts it and reports the observed post-start head; that leg is gated by
    the destructive `stop` category + confirm, and a mid-leg failure
    compensates with a best-effort start so the tool never strands a
    confirmed restart powered off. Observed values come only from
    Msvm_VideoHead, never from the request — and the guest's display driver
    may keep its own mode, so observed_* can legitimately differ from the
    configured values (null while the VM is off or the head cannot be read).
    """
    policy.require_category(cfg, "display", f"set display resolution of '{vm_name or vm_id}'")
    if restart:
        policy.require_destructive(
            cfg, "stop", confirm, f"restart VM '{vm_name or vm_id}' to apply the display resolution")
    if resolution_type not in _VIDEO_TYPES:
        raise ValueError(f"resolution_type must be one of {_VIDEO_TYPES}")
    if resolution_type != "default":
        # Coerce BEFORE the bounds check so the validated value is the value
        # emitted, and non-numeric input fails as ValueError ("invalid"),
        # not TypeError ("transport").
        try:
            width, height = int(width), int(height)
        except (TypeError, ValueError):
            raise ValueError("width and height must be integers") from None
        if width <= 0 or height <= 0:
            raise ValueError("width and height are required for resolution_type "
                             f"'{resolution_type}'")
        if not (160 <= width <= 4096 and 160 <= height <= 4096):
            raise ValueError("width and height must be within 160..4096")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    if resolution_type == "default":
        set_line = "Set-VMVideo -VM $vm -ResolutionType Default -ErrorAction Stop\n"
    else:
        set_line = (
            f"Set-VMVideo -VM $vm -HorizontalResolution {width} "
            f"-VerticalResolution {height} "
            f"-ResolutionType {_VIDEO_RES_TYPE[resolution_type]} -ErrorAction Stop\n"
        )
    script = _resolve_vm_prefix(ref) + set_line + _VIDEO_READBACK
    out: dict = {}
    with vmlocks.vm_lock(ref.id):
        if restart:
            # The host refuses Set-VMVideo on a running VM, so the stop comes
            # FIRST; the guard covers only the Stop line so an already-off VM
            # still starts below.
            stop_script = _resolve_vm_prefix(ref) + (
                "if ([string]$vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -ErrorAction Stop }\n"
            )
            _run(cfg, stop_script, f"vm_set_resolution stop({ref.name})", timeout_s=180)
        started = False
        try:
            result = _run(cfg, script, f"vm_set_resolution({ref.name})")
            parsed = _json_out(result, "vm_set_resolution")
            if isinstance(parsed, dict):
                out = parsed
            if restart:
                start_script = _resolve_vm_prefix(ref) + "Start-VM -VM $vm -ErrorAction Stop\n"
                _run(cfg, start_script, f"vm_set_resolution start({ref.name})", timeout_s=180)
                started = True
                try:
                    final = lifecycle._wait_for_state(cfg, ref, ["Running"], timeout_s=120)
                except pswindows.PowerShellBusy:
                    raise  # issue #15: pool saturation is busy/retryable, never a timeout
                except RuntimeError as exc:
                    # A wait timeout is a boot/timeout fault, not transport;
                    # reclassify so the envelope carries the timeout class.
                    raise TimeoutError(
                        f"vm_set_resolution({ref.name}): {exc}") from None
                # Best-effort observation: a failed head read must not erase a
                # committed change, and the pre-restart readback's observed_*
                # are stale (read while off) — replace them with the post-start
                # read or an explicit null.
                try:
                    head_script = _resolve_vm_prefix(ref) + (
                        "Start-Sleep -Seconds 2\n"
                        + _CIM_HEAD_LOOKUP
                        + "if (-not $vh) { throw 'no video head associated with the VM' }\n"
                        "[PSCustomObject]@{ observed_horizontal = $vh.CurrentHorizontalResolution;"
                        " observed_vertical = $vh.CurrentVerticalResolution }"
                        " | ConvertTo-Json -Compress\n"
                    )
                    head_result = _run(
                        cfg, head_script, f"vm_set_resolution observed({ref.name})", timeout_s=90)
                    head_out = _json_out(head_result, "vm_set_resolution observed")
                except MediaError:
                    head_out = {}
                out.pop("observed_horizontal", None)
                out.pop("observed_vertical", None)
                if isinstance(head_out, dict) and head_out:
                    out.update(head_out)
                out["observed_horizontal"] = out.get("observed_horizontal")
                out["observed_vertical"] = out.get("observed_vertical")
                out["state"] = final
        except Exception as exc:
            if restart and not started:
                # The stop leg already powered the VM off; compensate with a
                # best-effort start so a confirmed restart is never stranded.
                try:
                    start_script = _resolve_vm_prefix(ref) + "Start-VM -VM $vm -ErrorAction Stop\n"
                    _run(cfg, start_script, f"vm_set_resolution restart-recover({ref.name})",
                         timeout_s=180)
                    recovered = "the VM was restarted"
                except (MediaError, pswindows.PowerShellBusy):
                    # A busy compensation leg must not escape this handler:
                    # the original failure (and the "VM is still OFF" state
                    # note) has to survive into the envelope the caller sees.
                    recovered = "the VM is still OFF (start it with hyperv_start_vm)"
                if isinstance(exc, pswindows.PowerShellBusy):
                    # issue #15: re-raise busy itself (retryable) instead of
                    # wrapping it in a non-retryable MediaError; the
                    # compensation outcome rides the busy message.
                    raise pswindows.PowerShellBusy(
                        f"{exc} (this call stopped the VM; {recovered})") from None
                raise MediaError(
                    f"{str(exc)} (this call stopped the VM; {recovered})") from None
            raise
    return {"ok": True, **out, "effective_after_restart": not restart, "vm_name": ref.name}
