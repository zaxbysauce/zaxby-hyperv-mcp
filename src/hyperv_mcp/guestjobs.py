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

Ownership (issue #11): every entry records the starting agent's verified
identity (`owner`, the bearer token's client_id; None = the unattributed
local principal on stdio/anonymous/direct-module paths). A follow-up from
a different agent gets the SAME `unknown job_id` response as an absent id
— no guest leg runs and no stored credential is touched for a foreign
caller — and the check precedes the in-flight check so an in-flight start
is never disclosed to a foreign probe. Job ids are full-width 32-hex
v4 UUIDs (122 random bits of the 128 encoded); ids appear in transcripts
and audit rows, so ownership is the authorization and the width removes
guessing as a residual vector.

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

from . import credentials, errors, pswindows, statestore, vmident, vmlocks
from .config import Config
from .credentials import CredentialError, CredentialSet
from .diagnostics import run_guest_inner

_MAX_JOBS = 128

# Process-local write-through cache by design (issue #22): the authoritative
# copy of anything whose lifetime exceeds this process lives in the durable
# state store, and this dict is the fast in-process view of it. It stays a real
# dict because existing tests read and poke it directly.
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _store(cfg: Config) -> statestore.Store:
    """The durable store for this config, cached per process by resolved path."""
    return statestore.store_for(cfg)


def _cred_ref(cred: CredentialSet | None) -> str:
    """The credential reference a row records. Never the secret itself."""
    if cred is None:
        return "inline"
    return str(getattr(cred, "source", "inline") or "inline")


def _row(entry: dict[str, Any], state: str) -> statestore.JobRow:
    """Project a registry entry onto a store row. command/args/cred are
    deliberately absent: the store holds no secret and no command text."""
    return statestore.JobRow(
        job_id=str(entry["job_id"]),
        vm_name=str(entry.get("vm_name") or ""),
        vm_id=str(entry.get("vm_id") or ""),
        pid=int(entry.get("pid") or 0),
        start_time_ticks=entry.get("start_time_ticks"),
        job_dir=str(entry.get("job_dir") or ""),
        out_path=str(entry.get("out_path") or ""),
        err_path=str(entry.get("err_path") or ""),
        exit_path=str(entry.get("exit_path") or ""),
        started_at=str(entry.get("started_at") or ""),
        state=state,
        cred_ref=str(entry.get("cred_ref") or _cred_ref(entry.get("cred"))),
        owner=entry.get("owner"),
    )


def _restored_credential(cfg: Config, entry: dict[str, Any]) -> CredentialSet:
    """Re-resolve the credential a restored job started WITH.

    An `env`/`file` reference re-resolves through credentials.resolve_guest(),
    which registers the secret for redaction exactly as at start. An `inline`
    reference is not re-resolvable: substituting a different identity would run
    guest legs as the wrong account, so it fails honestly instead.
    """
    ref = str(entry.get("cred_ref") or "inline")
    if ref != "inline":
        return credentials.resolve_guest()
    raise CredentialError(
        f"job {entry.get('job_id')!r} was started with inline credentials, "
        "which are never persisted; it cannot be re-attached after a restart"
    )


def _entry_credential(cfg: Config, entry: dict[str, Any]) -> CredentialSet:
    """The credential for a guest leg: the live object, or a re-resolution."""
    cred = entry.get("cred")
    if cred is not None:
        return cred
    return _restored_credential(cfg, entry)


def _restore_entry(cfg: Config, job_id: str, owner: str | None) -> dict[str, Any] | None:
    """Rebuild a process-local entry from a persisted row (issue #22).

    Returns None for an absent row and for a foreign one, so the caller raises
    the SAME `unknown job_id` ValueError either way — ids cannot be probed for
    existence, exactly as for the in-memory path.
    """
    row = _store(cfg).job_get(job_id)
    if row is None:
        return None
    if owner is not None and (row.owner or None) != owner:
        return None
    return {
        "job_id": row.job_id,
        "vm_name": row.vm_name,
        "vm_id": row.vm_id,
        "pid": row.pid,
        "start_time_ticks": row.start_time_ticks,
        "job_dir": row.job_dir,
        "out_path": row.out_path,
        "err_path": row.err_path,
        "exit_path": row.exit_path,
        "started_at": row.started_at,
        "owner": row.owner,
        "stopped": row.state == statestore.JOB_STOPPED,
        "row_state": row.state,
        "cred_ref": row.cred_ref,
        "cred": None,
    }


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def clear_registry_for_tests() -> None:
    """Test seam: drop all registry entries (unit suites call this per test)."""
    with _jobs_lock:
        for entry in _jobs.values():
            entry["cred"] = None
        _jobs.clear()


def peek_vm_name(job_id: str, cfg: Config | None = None) -> str:
    """Read-only vm_name lookup for audit rows (issue #10).

    Unlike _lookup this never raises: an unknown, empty, or still-in-flight
    id reads as "" (an honest absence), so a follow-up call's audit row can
    name the VM even when the tool leg itself fails. Read-only by design —
    it never touches credentials or stop state.
    """
    key = job_id or ""
    with _jobs_lock:
        entry = _jobs.get(key)
    if entry is not None:
        if entry.get("in_flight"):
            return ""
        return str(entry.get("vm_name") or "")
    # issue #22: after a restart the entry only exists in the store, and the
    # pre-dispatch audit path still wants to name the VM.
    if cfg is not None:
        row = _store(cfg).job_get(key)
        if row is not None:
            return str(row.vm_name or "")
    return ""


def _reserve_slot(job_id: str, owner: str | None = None,
                   cfg: Config | None = None) -> None:
    """Atomically reserve a registry slot BEFORE the guest start leg.

    Evicts oldest stopped entries when at capacity; rejects when the
    registry is still full of active jobs. The reservation (an in-flight
    placeholder) counts against the cap from the moment it is taken, so
    concurrent starts on different VMs cannot collectively exceed
    _MAX_JOBS (review round 2, N2); on a failed start the caller must
    _release_slot it. The placeholder carries the owning agent so the
    slot cannot be re-registered under a different owner (issue #11).

    Issue #22: the cap counts the UNION of the in-memory view and the store
    rows, because separate stdio server processes share one store and tests
    inject entries straight into `_jobs`. Eviction therefore deletes from
    both. The store write transaction is the OUTER lock and `_jobs_lock` the
    inner one — the process-wide order that keeps a concurrent `_register`
    from deadlocking against this path.
    """
    if cfg is None:
        # No store: memory-only, exactly the pre-issue-#22 behaviour. Direct
        # callers (tests that inject entries into _jobs) use this shape.
        _reserve_slot_local(job_id, owner)
        return
    store = _store(cfg)
    with store.transaction():
        with _jobs_lock:
            rows = {row.job_id: row for row in store.job_rows()}

            def _started_at(key: str) -> str:
                entry = _jobs.get(key)
                if entry is not None:
                    return str(entry.get("started_at") or "")
                row = rows.get(key)
                return row.started_at if row is not None else ""

            def _stopped(key: str) -> bool:
                entry = _jobs.get(key)
                if entry is not None:
                    return bool(entry.get("stopped"))
                row = rows.get(key)
                # `orphaned` is evictable too: the crash left no PID to stop,
                # so nothing can ever clear it, and leaving it would let 128
                # hard crashes permanently fill the cap.
                return row is not None and row.state in (
                    statestore.JOB_STOPPED, statestore.JOB_ORPHANED,
                )

            known = set(_jobs) | set(rows)
            if len(known) >= _MAX_JOBS:
                evictable = sorted((k for k in known if _stopped(k)), key=_started_at)
                for key in evictable[: max(1, len(known) - _MAX_JOBS + 1)]:
                    entry = _jobs.get(key)
                    if entry is not None:
                        entry["cred"] = None
                        del _jobs[key]
                    store.job_delete(key)
                    known.discard(key)
            if len(known) >= _MAX_JOBS:
                raise RuntimeError(
                    f"guest job registry is full ({_MAX_JOBS} active jobs); "
                    "stop jobs before starting more"
                )
            started_at = _utc_now_iso()
            _jobs[job_id] = {
                "job_id": job_id, "vm_name": "", "vm_id": "", "pid": 0,
                "in_flight": True, "owner": owner,
                "started_at": started_at, "cred": None, "stopped": False,
            }
            # The `starting` row is committed BEFORE the guest leg runs, so a
            # hard kill inside the leg leaves an addressable row (issue #22).
            store.job_upsert(statestore.JobRow(
                job_id=job_id, started_at=started_at, owner=owner,
                state=statestore.JOB_STARTING, cred_ref="inline",
            ))


def _reserve_slot_local(job_id: str, owner: str | None) -> None:
    """The in-memory half of the reservation: evict, check the cap, insert."""
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
            "in_flight": True, "owner": owner,
            "started_at": _utc_now_iso(), "cred": None, "stopped": False,
        }


def _release_slot(job_id: str, cfg: Config | None = None) -> None:
    with _jobs_lock:
        entry = _jobs.get(job_id)
        if entry is None or not entry.get("in_flight"):
            return
        del _jobs[job_id]
    if cfg is not None:
        # Registry lock released first: store-lock is the outer order.
        _store(cfg).job_delete(job_id)


def _register(job: dict[str, Any], cfg: Config | None = None) -> None:
    with _jobs_lock:
        _jobs[job["job_id"]] = job
    if cfg is not None:
        # Registry lock released first: store-lock is the outer order, so
        # holding _jobs_lock across this write would deadlock AB-BA against a
        # reservation.
        _store(cfg).job_upsert(_row(job, statestore.JOB_ACTIVE))


def _lookup(job_id: str, owner: str | None = None,
             cfg: Config | None = None) -> dict[str, Any]:
    """Resolve a job entry for the calling principal (issue #11).

    A non-None owner (the verified agent id from the bearer token) may
    only address its OWN entries: a foreign id raises the SAME
    `unknown job_id` ValueError as an absent one — same message shape,
    same envelope — so ids cannot be probed for existence, and the check
    runs BEFORE the in-flight check so an in-flight start is never
    disclosed to a foreign caller. None (stdio in-process, anonymous,
    direct module calls) is the unattributed local principal and skips
    the ownership check entirely — the documented single-principal
    contract these callers have always had.
    """
    if not job_id:
        raise ValueError("job_id is required")
    with _jobs_lock:
        entry = _jobs.get(job_id)
    if entry is None and cfg is not None:
        # issue #22: the entry died with a previous process; rebuild it from
        # the store. The store lock is taken with _jobs_lock already released.
        entry = _restore_entry(cfg, job_id, owner)
        if entry is not None and entry.get("row_state") == statestore.JOB_STARTING:
            # A `starting` row belongs to a LIVE peer's in-flight start (this
            # process already ran recovery, so nothing of ours is left in that
            # state). Answer it the way an in-flight placeholder is answered,
            # and never cache it: caching would poison later reads, because the
            # placeholder's cred_ref is "inline" by construction.
            raise ValueError(f"job {job_id!r} is still starting")
        if entry is not None and entry.get("row_state") != statestore.JOB_ORPHANED:
            # An orphaned row is answered WITHOUT caching a live-looking entry:
            # a `starting` placeholder is pid 0 with empty paths, and caching it
            # would let a second read fall into the guest leg and report
            # "exiting" instead of "orphaned".
            with _jobs_lock:
                _jobs.setdefault(job_id, entry)
    if entry is None:
        raise ValueError(f"unknown job_id {job_id!r}")
    if owner is not None and entry.get("owner") != owner:
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
    owner: str | None = None,
) -> dict:
    """Start a guest command as a tracked job; returns without waiting.

    The VM may be addressed by `vm_name` or `vm_id` (exactly one required;
    vmident.resolve enforces identity and policy). The start leg runs against
    the RESOLVED GUID, and the registry entry stores it, so every follow-up
    leg below addresses the same VM even if it is renamed mid-job.
    `owner` (issue #11) is the verified agent identity — follow-ups from a
    different agent are refused with the unknown-id response; None records
    the unattributed local principal.
    """
    if not command:
        raise ValueError("command is required")
    if cred is None:
        raise ValueError("guest credentials are required")

    # Issue #11: full-width ids — job ids appear in transcripts and audit
    # rows; ownership makes them non-authoritative, and the 122 random
    # bits of a v4 UUID (32 hex chars) remove guessing as a residual
    # vector.
    job_id = uuid.uuid4().hex
    # Identity resolution BEFORE the slot reservation (PRR-008): a rejected
    # resolve (unknown GUID, denied name) must not evict stopped-job history
    # or null stored credentials — the reservation's eviction side effects
    # are only ever paid by starts that pass identity. The reservation still
    # precedes the guest start leg, preserving the pinned behavior that a
    # registry-full start is rejected before any guest work.
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    _reserve_slot(job_id, owner, cfg=cfg)
    try:
        # Wrapper building and pid parsing stay inside the release window so
        # no exception between reservation and registration can strand an
        # in-flight placeholder (review round 3 question, adopted).
        wrapper = _wrapper_script(command, args, cwd)
        outcome = run_guest_inner(
            cfg, ref.id, _start_script(job_id, wrapper), cred, timeout_ms=timeout_ms,
            mode="read",
        )
        pid = int(outcome.get("pid") or 0)
    except BaseException:
        _release_slot(job_id, cfg=cfg)
        raise
    if pid <= 0:
        _release_slot(job_id, cfg=cfg)
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
        "owner": owner,
        "stopped": False,
    }
    _register(entry, cfg=cfg)
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


def job_status(cfg: Config, job_id: str, *, owner: str | None = None) -> dict:
    entry = _lookup(job_id, owner, cfg)
    if entry.get("stopped"):
        return {
            "ok": True, "job_id": job_id, "vm_name": entry["vm_name"],
            "status": "stopped", "pid": entry["pid"],
        }
    if entry.get("row_state") == statestore.JOB_ORPHANED:
        # A `starting` placeholder is pid 0 with an empty exit_path, so a guest
        # leg would report "exiting" rather than "orphaned" — and _stop_script
        # rooted at PID 0 would taskkill the Win32 children of PID 0 as guest
        # admin. Answer the restored observation directly (issue #22).
        return {
            "ok": True, "job_id": job_id, "vm_name": entry["vm_name"],
            "pid": entry["pid"], "status": statestore.JOB_ORPHANED,
        }
    cred = _entry_credential(cfg, entry)
    outcome = run_guest_inner(
        cfg, entry["vm_id"],
        _status_script(entry["pid"], entry["exit_path"], entry.get("start_time_ticks")),
        cred, mode="read",
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


def job_output(cfg: Config, job_id: str, *, tail_bytes: int = 65536,
               owner: str | None = None) -> dict:
    if tail_bytes < 1:
        raise ValueError("tail_bytes must be >= 1")
    entry = _lookup(job_id, owner, cfg)
    if entry.get("row_state") == statestore.JOB_ORPHANED:
        # A `starting` placeholder never created its stream files, so there is
        # nothing to read and no leg to run. Answer the empty-stream result
        # directly: running _entry_credential here would raise a FALSE
        # CredentialError, because the placeholder's cred_ref is "inline" by
        # construction even when the job was started from the environment.
        return {
            "ok": True, "job_id": job_id, "vm_name": entry["vm_name"],
            "pid": entry["pid"], "tail_bytes": tail_bytes,
            "stdout": "", "stdout_truncated": False, "stdout_encoding": "utf-8",
            "stderr": "", "stderr_truncated": False, "stderr_encoding": "utf-8",
        }
    cred = _entry_credential(cfg, entry)
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
        outcome = run_guest_inner(
            cfg, entry["vm_id"], _output_script(path, tail_bytes), cred, mode="read",
        )
        text, encoding = _decode_stream(
            str(outcome.get("head_hex") or ""), str(outcome.get("tail_b64") or ""),
        )
        result[key] = text
        result[f"{key}_truncated"] = bool(outcome.get("truncated"))
        result[f"{key}_encoding"] = encoding
        result[f"{key}_size"] = outcome.get("size")
    return result


def job_stop(cfg: Config, job_id: str, *, owner: str | None = None) -> dict:
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
    entry = _lookup(job_id, owner, cfg)
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
    if entry.get("row_state") == statestore.JOB_ORPHANED:
        # A crash inside the guest start leg leaves the `starting` placeholder,
        # which is pid 0 with an empty job_dir by construction: there is no PID
        # to stop. Refuse rather than run _stop_script(0, ""), which would
        # enumerate and taskkill the Win32 children of PID 0 as guest admin
        # (issue #22). Nothing is written, so the row stays `orphaned` and
        # remains evictable at cap time.
        return {
            "ok": False, "job_id": job_id, "vm_name": entry["vm_name"],
            "pid": entry["pid"],
            "stopped": False, "alive_pids": [], "job_dir_removed": None,
            "pid_reused": False,
            "error": (f"job {job_id} was orphaned before its guest process was "
                      "recorded, so there is no PID to stop"),
            "error_class": "invalid",
        }
    cred = _entry_credential(cfg, entry)
    try:
        outcome = run_guest_inner(
            cfg, entry["vm_id"],
            _stop_script(entry["pid"], entry["job_dir"], entry.get("start_time_ticks")),
            cred, mode="read",
        )
    except vmlocks.VMBusy:
        # Feedback PRR-002: a lock-contention expiry must surface as the
        # server's busy envelope (error_class=busy + holder), not be
        # rewritten to a non-retryable transport result after waiting the
        # full bounded window. Re-raise; the tool wrapper envelopes it.
        raise
    except Exception as exc:
        # Same documented key set as a successful stop plus the error pair,
        # so the 7-key contract holds on the error path too (PRR-004); the
        # entry stays stoppable and the credential retained for a retry.
        return {
            "ok": False, "job_id": job_id, "vm_name": entry["vm_name"],
            "pid": entry["pid"],
            "stopped": False, "alive_pids": [], "job_dir_removed": None,
            "pid_reused": False,
            "error": pswindows.redact(str(exc)), "error_class": errors.classify(exc),
            # issue #15: a PowerShellBusy stop leg is busy/retryable, not
            # transport; the key set is unchanged (PRR-004 shape).
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
    recorded_ref = ""
    if stopped:
        # Registry bookkeeping (registry lock only, outside any vm_lock).
        with _jobs_lock:
            current = _jobs.get(job_id)
            if current is not None:
                current["stopped"] = True
                # Captured before the null: a live entry carries no cred_ref of
                # its own, so reading it afterwards would silently rewrite the
                # persisted provenance to "inline".
                recorded_ref = current.get("cred_ref") or _cred_ref(current.get("cred"))
                current["cred"] = None
        # Store write AFTER the registry lock is released: store-lock is the
        # outer order process-wide. A failed stop writes nothing, which is what
        # keeps the entry stoppable and the credential retained for a retry.
        if not recorded_ref:
            recorded_ref = entry.get("cred_ref") or _cred_ref(entry.get("cred"))
        stopped_row = _row(entry, statestore.JOB_STOPPED)
        _store(cfg).job_upsert(statestore.JobRow(
            **{**stopped_row.as_dict(), "cred_ref": recorded_ref}
        ))
    result = {
        "ok": stopped,
        "job_id": job_id,
        "vm_name": entry["vm_name"],
        "pid": entry["pid"],
        "stopped": stopped,
        "alive_pids": alive_pids,
        "job_dir_removed": job_dir_removed,
        "pid_reused": bool(outcome.get("pid_reused")),
    }
    if not stopped:
        # Issue #9 review PRR-004: an ok:false result is a failure envelope
        # and must carry the `error` key (the server wrapper enriches
        # error_class/retryable/retry_after_ms on top of this).
        result["error"] = (
            f"job not fully stopped: {len(alive_pids)} guest process(es) "
            "still alive" if alive_pids else
            "guest reported the job as not stopped"
        )
    return result
