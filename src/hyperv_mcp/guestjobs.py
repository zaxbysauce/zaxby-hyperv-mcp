"""Managed guest jobs: start a guest command without waiting, then poll,
collect bounded output, and stop exactly that guest PID (AC10).

Design (plan D1a): the start leg writes a per-job wrapper .ps1 under the
guest's %TEMP%\\hyperv-mcp-job-<job_id>\\ that runs the target with stream
redirection and records $LASTEXITCODE to a file, then launches it with
Start-Process via the repo's SPLAT idiom WITHOUT -Wait (the deliberate
inversion of guestexec._normal_body — one statement, PS 5.1-safe). The
host-side registry maps job_id -> {pid, paths, cred, ...} so status/output/
stop later address exactly that process.

Lock policy: every guest leg (start/status/output/stop) runs under vm_lock
acquired per leg inside diagnostics.run_guest_inner; registry bookkeeping
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

from . import policy, pswindows
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
            "job_id": job_id, "vm_name": "", "pid": 0, "in_flight": True,
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
    lines.append(f"& {cmd}{' ' + argv if argv else ''} 1> $outf 2> $errf")
    lines.append(
        "if ($null -ne $LASTEXITCODE) { $LASTEXITCODE | Set-Content -LiteralPath $exitf } "
        "else { 0 | Set-Content -LiteralPath $exitf }"
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
[PSCustomObject]@{{ pid = $p.Id; job_dir = $dir }} | ConvertTo-Json -Compress
""".strip()


def _status_script(pid: int, exit_path: str) -> str:
    return f"""
$proc = Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue
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


def _stop_script(pid: int, job_dir: str) -> str:
    return f"""
Stop-Process -Id {int(pid)} -Force -ErrorAction SilentlyContinue
$dir = {pswindows.ps_quote(job_dir)}
if (Test-Path -LiteralPath $dir) {{ Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }}
[PSCustomObject]@{{ stopped = $true }} | ConvertTo-Json -Compress
""".strip()


def _decode_stream(head_hex: str, tail_b64: str) -> tuple[str, str]:
    """BOM-sniff via the stream head (the tail slice may lack the BOM)."""
    head = bytes.fromhex(head_hex or "")
    raw = base64.b64decode(tail_b64) if tail_b64 else b""
    if raw[:2] == b"\xff\xfe" or (len(raw) < 2 and head[:2] == b"\xff\xfe"):
        if raw[:2] != b"\xff\xfe":
            if len(raw) % 2 == 1:
                raw = raw[1:]
        return raw.decode("utf-16-le", "replace"), "utf-16"
    if head[:2] == b"\xff\xfe":
        # Truncated UTF-16 tail: align to a codeunit boundary before decode.
        if len(raw) % 2 == 1:
            raw = raw[1:]
        return raw.decode("utf-16-le", "replace"), "utf-16"
    return raw.decode("utf-8", "replace"), "utf-8"


# -- public API --------------------------------------------------------------


def job_start(
    cfg: Config,
    vm_name: str,
    command: str,
    args: list[str] | None = None,
    cwd: str = "",
    *,
    cred: CredentialSet | None = None,
    timeout_ms: int = 60000,
) -> dict:
    """Start a guest command as a tracked job; returns without waiting."""
    if not vm_name or not command:
        raise ValueError("vm_name and command are required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)

    job_id = uuid.uuid4().hex[:12]
    _reserve_slot(job_id)
    try:
        # Wrapper building and pid parsing stay inside the release window so
        # no exception between reservation and registration can strand an
        # in-flight placeholder (review round 3 question, adopted).
        wrapper = _wrapper_script(command, args, cwd)
        outcome = run_guest_inner(
            cfg, vm_name, _start_script(job_id, wrapper), cred, timeout_ms=timeout_ms,
        )
        pid = int(outcome.get("pid") or 0)
    except BaseException:
        _release_slot(job_id)
        raise
    if pid <= 0:
        _release_slot(job_id)
        raise RuntimeError("guest job start returned no pid")
    job_dir = str(outcome.get("job_dir") or "")
    entry: dict[str, Any] = {
        "job_id": job_id,
        "vm_name": vm_name,
        "pid": pid,
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
        "vm_name": vm_name,
        "pid": pid,
        "job_dir": job_dir,
        "out_path": entry["out_path"],
        "err_path": entry["err_path"],
        "exit_path": entry["exit_path"],
        "started_at": entry["started_at"],
    }


def job_status(cfg: Config, job_id: str) -> dict:
    entry = _lookup(job_id)
    if entry.get("stopped"):
        return {"ok": True, "job_id": job_id, "status": "stopped", "pid": entry["pid"]}
    cred = entry["cred"]
    if cred is None:
        raise RuntimeError(f"job {job_id} has no stored credentials (stopped or evicted)")
    outcome = run_guest_inner(
        cfg, entry["vm_name"], _status_script(entry["pid"], entry["exit_path"]), cred,
    )
    return {
        "ok": True,
        "job_id": job_id,
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
    result: dict[str, Any] = {"ok": True, "job_id": job_id, "pid": entry["pid"], "tail_bytes": tail_bytes}
    for key, path_key in (("stdout", "out_path"), ("stderr", "err_path")):
        path = entry[path_key]
        if not path:
            result[key] = ""
            result[f"{key}_truncated"] = False
            result[f"{key}_encoding"] = "utf-8"
            continue
        outcome = run_guest_inner(cfg, entry["vm_name"], _output_script(path, tail_bytes), cred)
        text, encoding = _decode_stream(
            str(outcome.get("head_hex") or ""), str(outcome.get("tail_b64") or ""),
        )
        result[key] = text
        result[f"{key}_truncated"] = bool(outcome.get("truncated"))
        result[f"{key}_encoding"] = encoding
        result[f"{key}_size"] = outcome.get("size")
    return result


def job_stop(cfg: Config, job_id: str) -> dict:
    """Stop exactly this job's guest PID and release its credentials.

    The registry entry flips to stopped (and the stored credential is
    nulled) ONLY when the guest kill leg succeeds — a failed stop keeps the
    entry stoppable so a retry can reach the guest again (review round 1,
    finding 12); the tool never reports stopped for a process it could not
    kill.
    """
    entry = _lookup(job_id)
    if entry.get("stopped"):
        return {
            "ok": True, "job_id": job_id, "pid": entry["pid"],
            "stopped": True, "note": "was already stopped",
        }
    cred = entry["cred"]
    if cred is None:
        raise RuntimeError(f"job {job_id} has no stored credentials (evicted)")
    try:
        run_guest_inner(
            cfg, entry["vm_name"], _stop_script(entry["pid"], entry["job_dir"]), cred,
        )
    except Exception as exc:
        return {
            "ok": False,
            "job_id": job_id,
            "pid": entry["pid"],
            "stopped": False,
            "error": pswindows.redact(str(exc)),
            "error_class": "transport",
        }
    # Registry bookkeeping (registry lock only, outside any vm_lock).
    with _jobs_lock:
        current = _jobs.get(job_id)
        if current is not None:
            current["stopped"] = True
            current["cred"] = None
    return {
        "ok": True,
        "job_id": job_id,
        "pid": entry["pid"],
        "stopped": True,
    }
