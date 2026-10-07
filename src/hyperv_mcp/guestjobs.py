"""Managed guest jobs: start a guest command without waiting, then poll,
collect bounded output, and stop exactly that guest PID (AC10).

Design (plan D1a): the start leg writes a per-job wrapper .ps1 under the
guest's %TEMP%\\hyperv-mcp-job-<job_id>\\ that runs the target with stream
redirection and records $LASTEXITCODE to a file, then launches it with
Start-Process via the repo's SPLAT idiom WITHOUT -Wait (the deliberate
inversion of guestexec._normal_body — one statement, PS 5.1-safe). The
host-side registry maps job_id -> {pid, paths, cred, ...} so status/output/
stop later address exactly that process.

Identity (issue #8): job_start resolves the target ONCE via vmident.resolve
and the registry entry stores the resolved GUID (`vm_id`) alongside the
display name; every follow-up leg (status/output/stop) addresses the guest
by that stored GUID, so a VM rename between legs can never retarget a leg
at a different VM.

Lock policy: every guest leg (start/status/output/stop) runs under vm_lock
acquired per leg inside diagnostics.run_guest_inner (keyed on the GUID);
registry bookkeeping
uses only the registry lock. Credential lifetime disclosure: the stored
credential set outlives the starting call until a SUCCESSFUL stop, cap
eviction, or process exit; successful stop and eviction null the field (a
failed stop keeps the entry stoppable, so its credential is retained for
the retry). The registry is capped with an atomic reservation: a slot is
reserved before the guest start leg (oldest stopped entries are evicted
first) and released if the start fails, so concurrent starts can never
collectively exceed _MAX_JOBS.
Elevated start is not offered: -Verb RunAs cannot redirect streams, so an
elevated job could not capture output.
"""

from __future__ import annotations

import base64
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from . import pswindows, vmident
from .config import Config
from .credentials import CredentialSet
from .diagnostics import run_guest_inner

_MAX_JOBS = 128

_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def clear_registry_for_tests() -> None:
    """Test seam: drop all registry entries (unit suites call this per test)."""
    with _jobs_lock:
        for entry in _jobs.values():
            entry["cred"] = None
        _jobs.clear()


def _reserve_slot(job_id: str) -> None:
    """Atomically reserve a registry slot BEFORE the guest start leg.

    Evicts oldest stopped entries when at capacity; rejects when the
    registry is still full of active jobs. The reservation (an in-flight
    placeholder) counts against the cap from the moment it is taken, so
    concurrent starts on different VMs cannot collectively exceed
    _MAX_JOBS (review round 2, N2); on a failed start the caller must
    _release_slot it.
    """
    with _jobs_lock:
        if len(_jobs) >= _MAX_JOBS:
            stopped = sorted(
                (k for k, v in _jobs.items() if v.get("stopped")),
                key=lambda k: _jobs[k]["started_at"],
            )
            for key in stopped[: max(1, len(_jobs) - _MAX_JOBS + 1)]:
                _jobs[key]["cred"] = None
                del _jobs[key]
        if len(_jobs) >= _MAX_JOBS:
            raise RuntimeError(
                f"guest job registry is full ({_MAX_JOBS} active jobs); "
                "stop jobs before starting more"
            )
        _jobs[job_id] = {
            "job_id": job_id, "vm_name": "", "vm_id": "", "pid": 0,
            "in_flight": True,
            "started_at": _utc_now_iso(), "cred": None, "stopped": False,
        }


def _release_slot(job_id: str) -> None:
    with _jobs_lock:
        entry = _jobs.get(job_id)
        if entry is not None and entry.get("in_flight"):
            del _jobs[job_id]


def _register(job: dict[str, Any]) -> None:
    with _jobs_lock:
        _jobs[job["job_id"]] = job


def _lookup(job_id: str) -> dict[str, Any]:
    if not job_id:
        raise ValueError("job_id is required")
    with _jobs_lock:
        entry = _jobs.get(job_id)
    if entry is None:
        raise ValueError(f"unknown job_id {job_id!r}")
    if entry.get("in_flight"):
        raise ValueError(f"job {job_id!r} is still starting")
    return entry


# -- inner guest scripts ----------------------------------------------------


def _wrapper_script(command: str, args: list[str] | None, cwd: str) -> str:
    cmd = pswindows.ps_quote(command)
    argv = " ".join(pswindows.ps_quote(a) for a in (args or []))
    lines = [
        "$dir = Split-Path -Parent $MyInvocation.MyCommand.Path",
        "$outf = Join-Path $dir 'stdout.log'",
        "$errf = Join-Path $dir 'stderr.log'",
        "$exitf = Join-Path $dir 'exitcode.txt'",
    ]
    if cwd:
        lines.append(f"Set-Location -LiteralPath {pswindows.ps_quote(cwd)} -ErrorAction SilentlyContinue")
    # Reset any stale $LASTEXITCODE from the preamble so the tail can never
    # mistake an earlier code for this command's outcome (PRR-003/CUB-7):
    # placed immediately BEFORE the invoke, after the optional Set-Location.
    lines.append("$global:LASTEXITCODE = $null")
    lines.append(f"& {cmd}{' ' + argv if argv else ''} 1> $outf 2> $errf")
    lines.append(
        "$ok = $?\n"
        "if ($null -ne $LASTEXITCODE) { $LASTEXITCODE | Set-Content -LiteralPath $exitf }\n"
        "elseif ($ok) { 0 | Set-Content -LiteralPath $exitf }\n"
        "else { 1 | Set-Content -LiteralPath $exitf }"
    )
    return "\n".join(lines)


def _start_script(job_id: str, wrapper_text: str) -> str:
    enc = pswindows.utf8_b64(wrapper_text)
    ident = pswindows.ps_quote(job_id)
    return f"""
$enc = '{enc}'
$id = {ident}
$dir = Join-Path ([System.IO.Path]::GetTempPath()) ('hyperv-mcp-job-' + $id)
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$wrapper = Join-Path $dir 'job.ps1'
$text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc))
[System.IO.File]::WriteAllText($wrapper, $text, [System.Text.UTF8Encoding]::new($false))
$sp = @{{
    FilePath     = 'powershell.exe'
    ArgumentList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wrapper)
    WindowStyle  = 'Hidden'
    PassThru     = $true
}}
$p = Start-Process @sp
$st = $null
try {{ $st = $p.StartTime.ToUniversalTime().Ticks }} catch {{ $st = $null }}
[PSCustomObject]@{{ pid = $p.Id; job_dir = $dir; start_time_ticks = $st }} | ConvertTo-Json -Compress
""".strip()


def _status_script(pid: int, exit_path: str, start_time_ticks: int | None = None) -> str:
    """Observe the job process, pinned by start time when it was recorded.

    A live PID whose start time differs from the recorded one belongs to a
    different process (PID reuse), so it is treated as NOT this job and the
    exit-file branch answers instead of reporting 'running'.
    """
    want = f"$want = {int(start_time_ticks)}" if start_time_ticks is not None else "$want = $null"
    return f"""
$proc = Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue
{want}
if ($null -ne $proc -and $null -ne $want) {{
    try {{ if ([long]$proc.StartTime.ToUniversalTime().Ticks -ne $want) {{ $proc = $null }} }}
    catch {{ $proc = $null }}
}}
if ($null -ne $proc) {{
    [PSCustomObject]@{{ status = 'running'; process_name = $proc.ProcessName }} | ConvertTo-Json -Compress
}} else {{
    $exitPath = {pswindows.ps_quote(exit_path)}
    if (Test-Path -LiteralPath $exitPath) {{
        $code = (Get-Content -LiteralPath $exitPath -ErrorAction SilentlyContinue | Select-Object -First 1)
        [PSCustomObject]@{{ status = 'exited'; exit_code = "$code" }} | ConvertTo-Json -Compress
    }} else {{
        [PSCustomObject]@{{ status = 'exiting' }} | ConvertTo-Json -Compress
    }}
}}
""".strip()


def _output_script(path: str, tail_bytes: int) -> str:
    return f"""
$path = {pswindows.ps_quote(path)}
$tail = {int(tail_bytes)}
$r = @{{ head_hex = ''; tail_b64 = ''; size = 0; truncated = $false }}
if (Test-Path -LiteralPath $path) {{
    $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {{
        $r.size = $fs.Length
        $head = New-Object byte[] 4
        $n = $fs.Read($head, 0, 4)
        $r.head_hex = ([System.BitConverter]::ToString($head, 0, $n) -replace '-', '')
        $take = [int][Math]::Min($tail, $fs.Length)
        $null = $fs.Seek(-$take, 'End')
        $buf = New-Object byte[] $take
        $read = $fs.Read($buf, 0, $take)
        $r.tail_b64 = [Convert]::ToBase64String($buf, 0, $read)
        $r.truncated = ($fs.Length -gt $take)
    }} finally {{ $fs.Close() }}
}}
$r | ConvertTo-Json -Compress
""".strip()


def _stop_script(pid: int, job_dir: str, start_time_ticks: int | None = None) -> str:
    """Kill the job's recorded process AND its descendants, and report what
    was actually observed.

    Identity comes first: when a start time was recorded, a live PID whose
    start time differs is a stranger's process, so nothing is killed and the
    payload says `pid_reused` (a mismatch is strong evidence the recorded
    process is already gone — StartTime is immutable for a live PID's
    lifetime; an UNREADABLE start time is an unknown, not a mismatch, and
    never reports `pid_reused`). `stopped` is true only when no member of
    the recorded tree (wrapper or descendants) is observed alive afterward,
    and the job directory is removed only in that case (otherwise it stays
    for a retry). Descendants are enumerated and killed EVEN WHEN the
    wrapper has already exited: an orphaned child keeps the dead recorded
    PID as its Win32_Process ParentProcessId, so the parent-chain walk from
    the recorded PID still finds it.
    """
    want = f"$want = {int(start_time_ticks)}" if start_time_ticks is not None else "$want = $null"
    pid_i = int(pid)
    return f"""
$jobDir = {pswindows.ps_quote(job_dir)}
{want}
$ours = $true
$readFailed = $false
$p = Get-Process -Id {pid_i} -ErrorAction SilentlyContinue
if ($null -ne $p) {{
    if ($null -ne $want) {{
        try {{ $ours = ([long]$p.StartTime.ToUniversalTime().Ticks -eq $want) }}
        catch {{ $ours = $false; $readFailed = $true }}
    }}
}}
$stopped = $false
$alive = @()
$reused = $false
if ($null -ne $p -and -not $ours) {{
    if (-not $readFailed) {{ $reused = $true }}
    $stopped = $true
}} else {{
    $all = @(Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId, ParentProcessId)
    $tree = New-Object 'System.Collections.Generic.List[int]'
    $tree.Add({pid_i}) | Out-Null
    $frontier = @({pid_i})
    while ($frontier.Count -gt 0) {{
        $next = @()
        foreach ($pp in $frontier) {{
            foreach ($proc in $all) {{
                if ($proc.ParentProcessId -eq $pp -and -not $tree.Contains([int]$proc.ProcessId)) {{
                    $tree.Add([int]$proc.ProcessId) | Out-Null
                    $next += [int]$proc.ProcessId
                }}
            }}
        }}
        $frontier = $next
    }}
    & taskkill /PID {pid_i} /T /F 2>$null | Out-Null
    Stop-Process -Id {pid_i} -Force -ErrorAction SilentlyContinue
    foreach ($t in $tree) {{
        & taskkill /PID $t /T /F 2>$null | Out-Null
        Stop-Process -Id $t -Force -ErrorAction SilentlyContinue
    }}
    foreach ($t in $tree) {{
        if ($null -ne (Get-Process -Id $t -ErrorAction SilentlyContinue)) {{ $alive += $t }}
    }}
    if ($alive.Count -eq 0) {{ $stopped = $true }}
}}
$removed = $false
if ($stopped) {{
    if (Test-Path -LiteralPath $jobDir) {{
        Remove-Item -LiteralPath $jobDir -Recurse -Force -ErrorAction SilentlyContinue
    }}
    $removed = -not (Test-Path -LiteralPath $jobDir)
}}
[pscustomobject]@{{ stopped = $stopped; alive_pids = @($alive); job_dir_removed = $removed; pid_reused = $reused }} | ConvertTo-Json -Compress
""".strip()


def _decode_stream(head_hex: str, tail_b64: str) -> tuple[str, str]:
    """BOM-sniff via the stream head (the tail slice may lack the BOM)."""
    head = bytes.fromhex(head_hex or "")
    raw = base64.b64decode(tail_b64) if tail_b64 else b""
    if raw[:2] == b"\xff\xfe":
        # Full read (or a tail that starts at the BOM): strip the BOM so it
        # does not leak as U+FEFF into the decoded text (Copilot review,
        # COP-2).
        return raw[2:].decode("utf-16-le", "replace"), "utf-16"
    if head[:2] == b"\xff\xfe":
        # Truncated UTF-16 tail: align to a codeunit boundary before decode.
        if len(raw) % 2 == 1:
            raw = raw[1:]
        return raw.decode("utf-16-le", "replace"), "utf-16"
    return raw.decode("utf-8", "replace"), "utf-8"


# -- public API --------------------------------------------------------------


def job_start(
    cfg: Config,
    vm_name: str = "",
    command: str = "",
    args: list[str] | None = None,
    cwd: str = "",
    vm_id: str = "",
    *,
    cred: CredentialSet | None = None,
    timeout_ms: int = 60000,
) -> dict:
    """Start a guest command as a tracked job; returns without waiting.

    The VM may be addressed by `vm_name` or `vm_id` (exactly one required;
    vmident.resolve enforces identity and policy). The start leg runs against
    the RESOLVED GUID, and the registry entry stores it, so every follow-up
    leg below addresses the same VM even if it is renamed mid-job.
    """
    if not command:
        raise ValueError("command is required")
    if cred is None:
        raise ValueError("guest credentials are required")

    job_id = uuid.uuid4().hex[:12]
    # Identity resolution BEFORE the slot reservation (PRR-008): a rejected
    # resolve (unknown GUID, denied name) must not evict stopped-job history
    # or null stored credentials — the reservation's eviction side effects
    # are only ever paid by starts that pass identity. The reservation still
    # precedes the guest start leg, preserving the pinned behavior that a
    # registry-full start is rejected before any guest work.
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    _reserve_slot(job_id)
    try:
        # Wrapper building and pid parsing stay inside the release window so
        # no exception between reservation and registration can strand an
        # in-flight placeholder (review round 3 question, adopted).
        wrapper = _wrapper_script(command, args, cwd)
        outcome = run_guest_inner(
            cfg, ref.id, _start_script(job_id, wrapper), cred, timeout_ms=timeout_ms,
        )
        pid = int(outcome.get("pid") or 0)
    except BaseException:
        _release_slot(job_id)
        raise
    if pid <= 0:
        _release_slot(job_id)
        raise RuntimeError("guest job start returned no pid")
    job_dir = str(outcome.get("job_dir") or "")
    # Start time identifies the process behind the PID: without it a later
    # stop could kill an unrelated process that reused the PID. A missing,
    # non-numeric, or overflowing value (e.g. a JSON inf) degrades to the
    # legacy PID-only path (no false pin) instead of stranding the reserved
    # slot (PRR-015).
    raw_ticks = outcome.get("start_time_ticks")
    try:
        start_time_ticks: int | None = int(raw_ticks) if raw_ticks is not None else None
    except (TypeError, ValueError, OverflowError):
        start_time_ticks = None
    entry: dict[str, Any] = {
        "job_id": job_id,
        "vm_name": ref.name,
        "vm_id": ref.id,
        "pid": pid,
        "start_time_ticks": start_time_ticks,
        "command": command,
        "args": list(args or []),
        "job_dir": job_dir,
        "out_path": f"{job_dir}\\stdout.log" if job_dir else "",
        "err_path": f"{job_dir}\\stderr.log" if job_dir else "",
        "exit_path": f"{job_dir}\\exitcode.txt" if job_dir else "",
        "started_at": _utc_now_iso(),
        "cred": cred,
        "stopped": False,
    }
    _register(entry)
    return {
        "ok": True,
        "job_id": job_id,
        "vm_name": ref.name,
        "pid": pid,
        "job_dir": job_dir,
        "out_path": entry["out_path"],
        "err_path": entry["err_path"],
        "exit_path": entry["exit_path"],
        "started_at": entry["started_at"],
        "start_time_ticks": entry["start_time_ticks"],
    }


def job_status(cfg: Config, job_id: str) -> dict:
    entry = _lookup(job_id)
    if entry.get("stopped"):
        return {
            "ok": True, "job_id": job_id, "vm_name": entry["vm_name"],
            "status": "stopped", "pid": entry["pid"],
        }
    cred = entry["cred"]
    if cred is None:
        raise RuntimeError(f"job {job_id} has no stored credentials (stopped or evicted)")
    outcome = run_guest_inner(
        cfg, entry["vm_id"],
        _status_script(entry["pid"], entry["exit_path"], entry.get("start_time_ticks")),
        cred,
    )
    return {
        "ok": True,
        "job_id": job_id,
        "vm_name": entry["vm_name"],
        "pid": entry["pid"],
        "status": str(outcome.get("status", "unknown")),
        "process_name": outcome.get("process_name"),
        "exit_code": outcome.get("exit_code"),
    }


def job_output(cfg: Config, job_id: str, *, tail_bytes: int = 65536) -> dict:
    if tail_bytes < 1:
        raise ValueError("tail_bytes must be >= 1")
    entry = _lookup(job_id)
    cred = entry["cred"]
    if cred is None:
        raise RuntimeError(f"job {job_id} has no stored credentials (stopped or evicted)")
    result: dict[str, Any] = {
        "ok": True, "job_id": job_id, "vm_name": entry["vm_name"],
        "pid": entry["pid"], "tail_bytes": tail_bytes,
    }
    for key, path_key in (("stdout", "out_path"), ("stderr", "err_path")):
        path = entry[path_key]
        if not path:
            result[key] = ""
            result[f"{key}_truncated"] = False
            result[f"{key}_encoding"] = "utf-8"
            continue
        outcome = run_guest_inner(cfg, entry["vm_id"], _output_script(path, tail_bytes), cred)
        text, encoding = _decode_stream(
            str(outcome.get("head_hex") or ""), str(outcome.get("tail_b64") or ""),
        )
        result[key] = text
        result[f"{key}_truncated"] = bool(outcome.get("truncated"))
        result[f"{key}_encoding"] = encoding
        result[f"{key}_size"] = outcome.get("size")
    return result


def job_stop(cfg: Config, job_id: str) -> dict:
    """Stop this job's guest process and its descendants, reporting what
    actually happened.

    The guest leg observes the kill instead of asserting it: the result is
    honored verbatim, so a survivor (or an unreadable process) is reported
    as `stopped: false` with `ok: false` and the entry stays stoppable with
    its credential retained for a retry (review round 1, finding 12).
    Descendants are enumerated and killed even when the wrapper has already
    exited (an orphaned child keeps the dead recorded PID as its
    ParentProcessId, so the walk still finds it); `stopped` is true only
    when no member of the recorded tree was observed alive afterward, which
    is strong evidence the tree is gone (StartTime-based identity aside).
    The registry entry flips to stopped and the credential is nulled only
    when the guest reported the tree gone; the tool never reports stopped
    for a process it could not kill. The documented key set holds on every
    path — success, survivor, repeat, and transport-error alike (an error
    adds `error`/`error_class` with `stopped: false`).
    """
    entry = _lookup(job_id)
    if entry.get("stopped"):
        # Same key set as a real stop, so a client written to the documented
        # contract never hits a missing key on a repeat call. These are the
        # documented repeat-contract constants (this call observed nothing
        # new), not fresh observations.
        return {
            "ok": True, "job_id": job_id, "vm_name": entry["vm_name"],
            "pid": entry["pid"],
            "stopped": True, "alive_pids": [], "job_dir_removed": None,
            "pid_reused": False, "note": "was already stopped",
        }
    cred = entry["cred"]
    if cred is None:
        raise RuntimeError(f"job {job_id} has no stored credentials (evicted)")
    try:
        outcome = run_guest_inner(
            cfg, entry["vm_id"],
            _stop_script(entry["pid"], entry["job_dir"], entry.get("start_time_ticks")),
            cred,
        )
    except Exception as exc:
        # Same documented key set as a successful stop plus the error pair,
        # so the 7-key contract holds on the error path too (PRR-004); the
        # entry stays stoppable and the credential retained for a retry.
        return {
            "ok": False, "job_id": job_id, "vm_name": entry["vm_name"],
            "pid": entry["pid"],
            "stopped": False, "alive_pids": [], "job_dir_removed": None,
            "pid_reused": False,
            "error": pswindows.redact(str(exc)), "error_class": "transport",
        }
    # The guest payload is the truth. A legacy single-key response
    # ({"stopped": true}) leaves the observation fields as honest unknowns.
    raw_alive = outcome.get("alive_pids")
    try:
        alive_pids = [int(p) for p in raw_alive] if isinstance(raw_alive, list) else []
    except (TypeError, ValueError):
        # A malformed survivor list must not raise out of the kill leg's
        # aftermath (PRR-016): report the same full-key error envelope with
        # error_class "invalid"; the entry stays stoppable for a retry.
        return {
            "ok": False, "job_id": job_id, "vm_name": entry["vm_name"],
            "pid": entry["pid"],
            "stopped": False, "alive_pids": [], "job_dir_removed": None,
            "pid_reused": False,
            "error": "guest stop payload carried a non-numeric alive_pids member",
            "error_class": "invalid",
        }
    # Survivors win over a contradictory `stopped: true`.
    stopped = bool(outcome.get("stopped")) and not alive_pids
    job_dir_removed = outcome.get("job_dir_removed")
    if stopped:
        # Registry bookkeeping (registry lock only, outside any vm_lock).
        with _jobs_lock:
            current = _jobs.get(job_id)
            if current is not None:
                current["stopped"] = True
                current["cred"] = None
    return {
        "ok": stopped,
        "job_id": job_id,
        "vm_name": entry["vm_name"],
        "pid": entry["pid"],
        "stopped": stopped,
        "alive_pids": alive_pids,
        "job_dir_removed": job_dir_removed,
        "pid_reused": bool(outcome.get("pid_reused")),
    }
