"""Offline log harvest from a stopped VM's virtual disk (issue #33, ENH-15).

The deployments that most need their logs read die before Windows boots
(WinPE crash, specialize-pass failure, reboot loop) — every guest file tool
rides PowerShell Direct and cannot run. The logs are still on the VM's
virtual disk: Panther ``setupact.log``/``setuperr.log``, MDT ``BDD.log`` and
the task-sequence ``smsts.log`` (KB 927521 + the MDT/ConfigMgr log
references). This module mounts the Off VM's disk chain READ-ONLY with no
drive letter, copies the FIXED documented log set (never a caller-supplied
guest path) with backup semantics, hashes each file, and ALWAYS dismounts.

Reading a guest disk from the host bypasses guest credentials AND
``guest_read_roots``, so the whole operation sits behind the deny-by-default
``destructive.offline_harvest`` category (read-only: no confirm leg, like
``media``), plus the ``host_write_roots`` check on the destination. The
per-VM write lock is held from the state gate through ``Dismount-VHD``; the
mount/copy/dismount cmdlets are host-local, so remote-host configs are
refused up front (media's ``_reject_remote_file_ops`` shape). Copying guest
files under ``Windows\\Panther`` needs SeBackupPrivilege: the precheck runs
BEFORE any mount and a session without it fails fast instead of returning a
partial result. Collected file content is untrusted data — returned only as
files + hashes, never interpolated into PowerShell.
"""

from __future__ import annotations

import json
import os

from . import guestexec, policy, pswindows, vmident, vmlocks
from .config import Config

#: The fixed guest-relative log set (KB 927521 Windows-setup phases, the MDT
#: LTI/OSD logs, and the ConfigMgr task-sequence log homes by phase; ``X:``
#: WinPE RAM-disk copies never reach the virtual disk and are excluded).
#: Callers cannot pass arbitrary guest paths — this set is the whole surface.
LOG_PATHS: frozenset[str] = frozenset({
    "$WINDOWS.~BT\\Sources\\Panther\\setupact.log",
    "$WINDOWS.~BT\\Sources\\Panther\\setuperr.log",
    "Windows\\Panther\\setupact.log",
    "Windows\\Panther\\setuperr.log",
    "Windows\\Panther\\UnattendGC\\setupact.log",
    "Windows\\INF\\setupapi.dev.log",
    "MININT\\SMSOSD\\OSDLOGS\\BDD.log",
    "MININT\\SMSOSD\\OSDLOGS\\*.log",
    "Windows\\Temp\\DeploymentLogs\\BDD.log",
    "Windows\\Temp\\DeploymentLogs\\*.log",
    "_SMSTaskSequence\\Logs\\smstslog\\smsts.log",
    "Windows\\CCM\\Logs\\smstslog\\smsts.log",
    "Windows\\CCM\\Logs\\smsts.log",
    "Windows\\System32\\CCM\\Logs\\smsts.log",
    "SMSTSLog\\smsts.log",
})

#: Bounds (robocopy /MAX per file; the running total is checked between
#: disks in-script and re-enforced in Python — over-budget files land in
#: ``skipped`` with reason ``cap_exceeded``).
_FILE_MAX_BYTES = 64 * 1024 * 1024
_TOTAL_MAX_BYTES = 2 * 1024 * 1024 * 1024


class HarvestError(RuntimeError):
    """Structured offline-harvest refusal/failure (caller/vm-state faults:
    not Off, remote-host mode — classified "invalid", never "transport").
    NOTE (M20 doctrine, recorded at review round 2): ``_run`` wraps every
    ``check_result`` transport failure in this class, so a genuine harvest
    leg timeout also classifies "invalid" — the shipped MediaError
    precedent (errors.py), deliberate: harvest failures are operation-
    scoped, and the wrapping context names the leg."""


class HarvestPrivilegeError(HarvestError):
    """The SeBackupPrivilege precheck refusal (issue #33 AC13: classified
    "privilege", deterministic and non-retryable)."""


def _run(cfg: Config, script: str, ctx: str, timeout_s: int = 600) -> pswindows.PSResult:
    script, stdin = pswindows.compose_remote(cfg, script.strip())
    if stdin is None:
        result = pswindows.run_ps(script, timeout_s=timeout_s)
    else:
        result = pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=stdin)
    try:
        return pswindows.check_result(result, ctx)
    except RuntimeError as exc:
        raise HarvestError(str(exc)) from None


def _privilege_ok(listing: str) -> bool:
    # `whoami /priv` lists the session's privileges; the frozen convention is
    # presence of SeBackupPrivilege in the listing. (A held-but-Disabled row
    # would also match; the elevated-vs-not distinction is exercised by the
    # live AC19 legs — disclosed, not re-derived here.)
    return "SeBackupPrivilege" in listing


def _action_script(guid: str, dest: str, mnt_root: str) -> str:
    """The ONE aggregate action script: mount → access-path → robocopy /B →
    hash → finally dismount, for every disk, emitting one JSON result.

    Shape notes (each pinned by review rounds): the final emission uses
    ``.ToArray()`` because ``@()`` around a ``List[object]`` throws
    "Argument types do not match" on PS 5.1 (the hazard documented in
    guest/uia_helper.ps1); robocopy is fully qualified (the same PATH-
    shadowing class as the whoami live-leg catch) and its exit code is
    inspected (>= 8 = real failure; 1 = "files copied" is success); glob
    entries are enumerated after the copy so every copied file is hashed,
    capped and manifested.
    """
    dest_q = pswindows.ps_quote(dest)
    mnt_q = pswindows.ps_quote(mnt_root)
    logs = ",".join(pswindows.ps_quote(p) for p in sorted(LOG_PATHS))
    return guestexec.vm_target_preamble(guid) + "\n" + "\n".join([
        "$vm = Get-VM -Id $vmTarget -ErrorAction Stop",
        f"$dest = {dest_q}",
        f"$mnt = {mnt_q}",
        f"$logs = @({logs})",
        f"$fileMax = {int(_FILE_MAX_BYTES)}",
        f"$totalMax = {int(_TOTAL_MAX_BYTES)}",
        "$files = New-Object System.Collections.Generic.List[object]",
        "$skipped = New-Object System.Collections.Generic.List[object]",
        "$total = 0",
        "$disks = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop | ForEach-Object { $_.Path })",
        "for ($i = 0; $i -lt $disks.Count; $i++) {",
        "  $p = $disks[$i]",
        "  $ap = Join-Path $mnt (('disk' + $i))",
        "  $mounted = $false",
        "  try {",
        "    $diskObj = Mount-VHD -Path $p -ReadOnly -NoDriveLetter -Passthru -ErrorAction Stop",
        "    $mounted = $true",
        "    foreach ($part in @($diskObj | Get-Disk -ErrorAction Stop | Get-Partition -ErrorAction SilentlyContinue)) {",
        "      New-Item -ItemType Directory -Force -Path $ap | Out-Null",
        "      try {",
        "        Add-PartitionAccessPath -Partition $part -AccessPath $ap -ErrorAction Stop",
        "      } catch {",
        "        $skipped.Add([PSCustomObject]@{ path = $ap; reason = 'volume_locked' })",
        "        continue",
        "      }",
        "      try {",
        "        foreach ($rel in $logs) {",
        "          $src = Join-Path $ap $rel",
        "          $srcDir = Split-Path $src -Parent",
        "          $name = Split-Path $src -Leaf",
        "          $dst = Join-Path $dest $rel",
        "          $dstDir = Split-Path $dst -Parent",
        "          $isGlob = $name -like '*[*?]*'",
        "          if ($isGlob) {",
        "            if (-not (Test-Path -LiteralPath $srcDir)) {",
        "              $skipped.Add([PSCustomObject]@{ path = $rel; reason = 'missing' })",
        "              continue",
        "            }",
        "          } elseif (-not (Test-Path -LiteralPath $src)) {",
        "            $skipped.Add([PSCustomObject]@{ path = $rel; reason = 'missing' })",
        "            continue",
        "          }",
        "          New-Item -ItemType Directory -Force -Path $dstDir | Out-Null",
        "          # A stale copy from an earlier run must never be hashed as",
        "          # this run's result: clear the destination match(es) first.",
        "          if ($isGlob) {",
        "            Get-ChildItem -LiteralPath $dstDir -Filter $name -File -ErrorAction SilentlyContinue |",
        "              Remove-Item -Force -ErrorAction SilentlyContinue",
        "          } else {",
        "            Remove-Item -LiteralPath (Join-Path $dstDir $name) -Force -ErrorAction SilentlyContinue",
        "          }",
        "          & $env:SystemRoot\\System32\\robocopy.exe $srcDir $dstDir $name /B /XJ /R:0 /W:0 /MAX:$fileMax /NFL /NDL /NJH /NJS /NP | Out-Null",
        "          if ($LASTEXITCODE -ge 8) {",
        "            $skipped.Add([PSCustomObject]@{ path = $rel; reason = ('copy_failed: robocopy exit ' + $LASTEXITCODE) })",
        "            continue",
        "          }",
        "          if ($isGlob) {",
        "            $copiedList = Get-ChildItem -LiteralPath $dstDir -Filter $name -File -ErrorAction SilentlyContinue",
        "          } else {",
        "            $copiedList = @(Get-Item -LiteralPath (Join-Path $dstDir $name) -ErrorAction SilentlyContinue)",
        "          }",
        "          foreach ($copied in @($copiedList)) {",
        "            $len = $copied.Length",
        "            if (($total + $len) -gt $totalMax) {",
        "              Remove-Item -LiteralPath $copied.FullName -Force -ErrorAction SilentlyContinue",
        "              $skipped.Add([PSCustomObject]@{ path = $rel; reason = 'cap_exceeded' })",
        "              continue",
        "            }",
        "            $total = $total + $len",
        "            $h = (Get-FileHash -LiteralPath $copied.FullName -Algorithm SHA256 -ErrorAction Stop).Hash",
        "            $files.Add([PSCustomObject]@{ path = $rel; bytes = [int]$len; sha256 = $h })",
        "          }",
        "        }",
        "      } finally {",
        "        Remove-PartitionAccessPath -Partition $part -AccessPath $ap -ErrorAction SilentlyContinue",
        "        Remove-Item -LiteralPath $ap -Recurse -Force -ErrorAction SilentlyContinue",
        "      }",
        "    }",
        "  } finally {",
        "    if ($mounted) { Dismount-VHD -Path $p -ErrorAction Stop }",
        "  }",
        "}",
        "[PSCustomObject]@{ files = $files.ToArray(); skipped = $skipped.ToArray() } | ConvertTo-Json -Compress -Depth 4",
    ])


def _recovery_script(guid: str) -> str:
    """Best-effort dismount of every disk of the VM (M6: a killed action
    process never runs its in-script finally, so the Python side dismounts
    in a FRESH process after any action-script failure)."""
    return guestexec.vm_target_preamble(guid) + "\n" + "\n".join([
        "$vm = Get-VM -Id $vmTarget -ErrorAction SilentlyContinue",
        "if ($vm) {",
        "  foreach ($d in @(Get-VMHardDiskDrive -VM $vm -ErrorAction SilentlyContinue)) {",
        "    Dismount-VHD -Path $d.Path -ErrorAction SilentlyContinue",
        "  }",
        "}",
        "'recovery-done'",
    ])


def harvest_offline_logs(cfg: Config, vm_name: str = "", vm_id: str = "", dest_dir: str = "") -> dict:
    """Mount an Off VM's disk chain read-only and copy the fixed log set.

    Preflight order (each refusal observes zero PowerShell processes):
    offline_harvest category → remote-host refusal → dest host_write_roots.
    Then resolve → state gate (Off only) → SeBackup privilege precheck →
    ONE aggregate mount/copy/hash/dismount action script, all under the
    per-VM write lock keyed on the resolved GUID.
    """
    if not dest_dir or not dest_dir.strip():
        raise ValueError("dest_dir is required")
    # Category gate first (deny-by-default; read-only op so no confirm leg).
    policy.require_category(
        cfg, "offline_harvest",
        f"harvest offline logs from '{vm_name or vm_id}' into '{dest_dir}'")
    # Mount-VHD/Add-PartitionAccessPath/robocopy are host-local cmdlets: in
    # remote mode compose_remote would run them against the wrong machine.
    if pswindows.hyperv_host(cfg):
        raise HarvestError(
            "remote Hyper-V host mode does not support offline log harvest in "
            "this release: the disk is mounted on the Hyper-V host, not the "
            "agent box. Run this operation in local mode (server on the "
            "Hyper-V host).")
    dest = policy.check_host_write(
        cfg, os.path.normpath(os.path.abspath(dest_dir))).normalized
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    with vmlocks.vm_lock(ref.id):
        # State gate (Saved refused too: the unflushed guest cache lives in
        # the saved-state file, so on-disk logs can be stale or the file
        # system dirty).
        state = _run(
            cfg,
            guestexec.vm_target_preamble(ref.id)
            + "\n$vm = Get-VM -Id $vmTarget -ErrorAction Stop\n"
            + "[string]$vm.State",
            f"harvest_state({ref.name})", timeout_s=60,
        ).stdout.strip()
        if state != "Off":
            raise HarvestError(
                f"VM '{ref.name}' is in state {state or 'unknown'}: offline "
                "log harvest requires state Off")
        # SeBackupPrivilege precheck BEFORE any mount: guest files under
        # Windows\Panther carry ACLs for the guest's Administrators/SYSTEM,
        # and only backup-semantics copying under an elevated token reads
        # every log — fail fast instead of returning a partial result. The
        # fully-qualified whoami.exe matters: a bare `whoami` can resolve
        # GNU whoami from a Git-Bash PATH ahead of System32 (live-leg catch,
        # 2026-10-31) and die on "/priv".
        listing = _run(
            cfg, "& $env:SystemRoot\\System32\\whoami.exe /priv",
            f"harvest_priv({ref.name})", timeout_s=30).stdout
        if not _privilege_ok(listing):
            raise HarvestPrivilegeError(
                "offline log harvest requires SeBackupPrivilege (an elevated "
                "token) for backup-semantics copying of guest ACL'd files; "
                "this session does not hold it — refusing before any mount. "
                "Re-run from an elevated deployment (see README Permissions).")

        mnt_root = os.path.join(dest, ".mnt")
        os.makedirs(mnt_root, exist_ok=True)
        try:
            try:
                out = json.loads(_run(
                    cfg, _action_script(ref.id, dest, mnt_root),
                    f"harvest({ref.name})", timeout_s=720,
                ).stdout.strip() or "{}")
            except Exception:
                # M6 recovery: a killed action process (timeout/cancel) never
                # runs its in-script finally, so the VHD can stay mounted.
                # Best-effort dismount from a FRESH process; never masks the
                # original error.
                try:
                    _run(cfg, _recovery_script(ref.id),
                         f"harvest_recovery({ref.name})", timeout_s=120)
                except Exception:
                    pass
                raise
        finally:
            try:
                os.rmdir(mnt_root)
            except OSError:
                pass
        if not isinstance(out, dict):
            out = {}
        files = list(out.get("files") or [])
        skipped = list(out.get("skipped") or [])
        # Python-side total re-enforcement (the in-script guard demotes per
        # file; this pass keeps the promise even if the script shape drifts).
        total = 0
        kept_files: list[dict] = []
        for f in files:
            if not isinstance(f, dict):
                continue
            total += int(f.get("bytes") or 0)
            if total > _TOTAL_MAX_BYTES:
                skipped.append({"path": str(f.get("path") or ""), "reason": "cap_exceeded"})
                continue
            kept_files.append({
                "path": str(f.get("path") or ""),
                "bytes": int(f.get("bytes") or 0),
                "sha256": str(f.get("sha256") or ""),
            })
        return {
            "ok": True,
            "dest_dir": dest,
            "files": kept_files,
            "skipped": [
                {"path": str(s.get("path") or ""), "reason": str(s.get("reason") or "unknown")}
                if isinstance(s, dict) else {"path": str(s), "reason": "unknown"}
                for s in skipped
            ],
            "vm_name": ref.name,
        }
