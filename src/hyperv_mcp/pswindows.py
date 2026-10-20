"""Host-side PowerShell execution — the ONLY module allowed to spawn powershell.

Design facts verified empirically on Windows PowerShell 5.1 (probe matrix,
2026-09-19, host VSAN):
  - `-EncodedCommand` (UTF-16LE base64) works and keeps secrets out of argv.
  - Secrets ride stdin as ASCII base64; the script decodes with
    `[Text.Encoding]::UTF8` — immune to Console input-codepage issues.
  - Pinning `[Console]::OutputEncoding` to UTF-8 makes output decode cleanly.
  - Array-form native calls `& 'exe' @('a','b')` pass empty strings, embedded
    quotes, brackets, unicode and CRLF intact through PS 5.1 native binding.
  - `CREATE_SUSPENDED` + toolhelp thread-resume works for PowerShell children,
    which lets us assign the process to a kill-on-close Job Object before any
    grandchild can exist (process-tree kill on timeout).

Every returned string and every exception message passes the redaction filter
registered by credentials, so secrets never reach MCP clients.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, TypeVar

import anyio

from . import timing
from .config import Config, HttpPolicy

if os.name == "nt":
    import msvcrt
else:
    import fcntl

_CREATE_SUSPENDED = 0x00000004
# Console-less servers (stdio child of a GUI host) make every console app
# they spawn allocate a NEW VISIBLE console window unless this flag suppresses
# it. Orthogonal to CREATE_SUSPENDED; safe to combine.
CREATE_NO_WINDOW = 0x08000000
_CREATE_NO_WINDOW = CREATE_NO_WINDOW
_TH32CS_SNAPTHREAD = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_JOB_OBJECT_EXTENDED_LIMIT = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

_PS_PIN = (
    "$ProgressPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);\n"
)
_DEFAULT_PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PS51_SYSTEM_MODULES = r"C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
_PWSH7_SHARED_MODULES = r"C:\Program Files\PowerShell\Modules"
# Server-side secrets that must never reach a spawned child process. Compared
# case-insensitively (Windows env names); the configured http.token_env name is
# unioned in at call time by child_env(), together with the literal default
# HYPERV_MCP_HTTP_TOKEN name (so customizing token_env never re-enables the
# default variable) and every env variable named by http.agents (the per-agent
# bearer-token variables, issue #10).
_SECRET_ENV_NAMES = frozenset({
    "HYPERV_GUEST_PASSWORD",
    "HYPERV_GUEST_PASSWORD_FILE",
    "HYPERV_GUEST_VICTIM_PASSWORD",
    "HYPERV_GUEST_VICTIM_PASSWORD_FILE",
    "HYPERV_HOST_PASSWORD",
    "HYPERV_HOST_PASSWORD_FILE",
})
# Inheriting these would redirect the git provenance probe (server.py
# _git_revision spawns under child_env()); they are not secrets but must not
# ride the child environment either.
_GIT_ENV_NAMES = frozenset({"GIT_DIR", "GIT_WORK_TREE"})


class PowerShellTransportError(RuntimeError):
    """powershell.exe missing or process machinery failed."""


class PowerShellBusy(RuntimeError):
    """The host-wide PowerShell slot pool is saturated and the bounded wait
    expired (issue #15 / FND-13). Maps to error_class "busy" — retryable."""


@dataclass
class PSResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False
    duration_ms: int = 0
    # Timing markers a script emitted, parsed off its stdout by run_ps. Kept out
    # of __eq__ and repr so existing comparisons and error messages are
    # byte-stable.
    timing: dict | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        # Every PSResult this process builds feeds the active call's spawn
        # accounting, so a stubbed or directly-invoked run_ps is counted
        # exactly like a real spawn. Doing it here rather than inside run_ps
        # is what makes the accounting visible to tests that replace run_ps
        # wholesale, and it also covers vmident's resolve legs, whose results
        # are discarded everywhere above this layer.
        collector = timing.current()
        if collector is not None:
            collector.add_spawn(self.duration_ms, self.timing)

    def ok(self) -> bool:
        return not self.timed_out and self.returncode == 0


# ---------------------------------------------------------------------------
# quoting / encoding helpers
# ---------------------------------------------------------------------------

def ps_quote(value: str) -> str:
    """Single-quoted PowerShell literal ('' doubling). Safe for text context."""
    return "'" + value.replace("'", "''") + "'"


def ps_wildcard_escape(value: str) -> str:
    """Backtick-escape PowerShell wildcard metacharacters (* ? [ ]).

    Matches [System.Management.Automation.WildcardPattern]::Escape behavior,
    verified against PS 5.1 on this host (Escape does NOT escape backtick).
    """
    return (
        value.replace("*", "`*")
        .replace("?", "`?")
        .replace("[", "`[")
        .replace("]", "`]")
    )


def ps_name(value: str) -> str:
    """Literal, wildcard-inert, single-quoted form for cmdlet -Name params."""
    return ps_quote(ps_wildcard_escape(value))


def ps_native_args(args: list[str]) -> str:
    """Direct quoted arguments for a native executable call.

    PS 5.1 native binding CONCATENATES inline arrays: `& exe @('a','b')`
    delivers the single argument 'a b' (verified empirically on this host).
    Always call with separate quoted arguments — this helper emits that form.
    """
    return " ".join(ps_quote(a) for a in args)


def encode_command(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def utf8_b64(data: str) -> str:
    """ASCII base64 of UTF-8 bytes — the safe shape for stdin secrets."""
    return base64.b64encode(data.encode("utf-8")).decode("ascii")


def find_powershell(config_path: str | None) -> str:
    if config_path:
        return config_path
    if os.path.isfile(_DEFAULT_PS):
        return _DEFAULT_PS
    return "powershell"


# ---------------------------------------------------------------------------
# child environment sanitization (FND-03: never leak server env into children)
# ---------------------------------------------------------------------------

def _norm_path(value: str) -> str:
    """Canonical form for module-directory comparison.

    Order matters: convert forward slashes to backslashes BEFORE stripping
    trailing separators, otherwise a ``C:/.../Modules/`` spelling keeps its
    trailing separator and no longer compares equal to the canonical dir.
    """
    return value.strip().replace("/", "\\").rstrip("\\").lower()


def _is_pwsh7_module_entry(entry: str) -> bool:
    """A PSModulePath entry is a PowerShell 7 (pwsh7) entry when it lies
    under a PowerShell 7 install directory — segment-aware, so the GA ``7``
    root, preview/daily roots (``7-preview``, ``7-daily``) and versioned
    side-by-side roots (``7.x``) all match — equals the pwsh7 program-files
    shared module directory, or is a pwsh7 user Documents module directory.
    Windows PowerShell 5.1 directories (WindowsPowerShell) never match."""
    norm = _norm_path(entry)
    wrapped = "\\" + norm + "\\"
    # Check every "\powershell\" segment occurrence, not just the first, so
    # nested install parents (...\PowerShell\PowerShell\7\Modules) still match.
    idx = wrapped.find("\\powershell\\")
    while idx != -1:
        segment = wrapped[idx + len("\\powershell\\"):].split("\\", 1)[0]
        if segment == "7" or segment.startswith(("7-", "7.")):
            return True
        idx = wrapped.find("\\powershell\\", idx + 1)
    if norm == _norm_path(_PWSH7_SHARED_MODULES):
        return True
    return norm.endswith("\\documents\\powershell\\modules")


def child_env() -> dict[str, str]:
    """Environment for every process spawned from this module.

    Inherit the server environment minus credential and HTTP-token variable
    names (case-insensitive): the configured http.token_env name (trimmed, so
    a whitespace-padded config value still matches), the literal default
    HYPERV_MCP_HTTP_TOKEN name even when token_env is customized, every env
    variable named by http.agents (the per-agent bearer-token variables,
    issue #10), and GIT_DIR/GIT_WORK_TREE (they would redirect the git
    provenance probe).

    The child always receives a PowerShell 5.1-only PSModulePath: pwsh7 module
    directories and empty entries are dropped, the 5.1 system module directory
    is appended when missing, and a PSModulePath with no surviving entries is
    removed entirely. An absent PSModulePath stays absent.

    Edition note (limitation): the 5.1 shape is unconditional. If
    host_powershell_path is pointed at a pwsh7 executable, the child loses the
    pwsh7 module directories on every spawn — see the host_powershell_path
    documentation in README.md.
    """
    env = dict(os.environ)
    token_name = _config.http.token_env if _config is not None else HttpPolicy().token_env
    agents = _config.http.agents if _config is not None else {}
    agent_env_names = {name.strip().upper() for name in agents.values()}
    secret_names = (
        _SECRET_ENV_NAMES
        | {"HYPERV_MCP_HTTP_TOKEN", token_name.strip().upper()}
        | agent_env_names
    )
    strip_names = secret_names | _GIT_ENV_NAMES
    for key in [k for k in env if k.upper() in strip_names]:
        del env[key]
    psmk = next((k for k in env if k.upper() == "PSMODULEPATH"), None)
    if psmk is not None:
        entries = [e for e in env[psmk].split(";") if e.strip()]
        kept = [e for e in entries if not _is_pwsh7_module_entry(e)]
        if kept:
            if _norm_path(PS51_SYSTEM_MODULES) not in {_norm_path(e) for e in kept}:
                kept.append(PS51_SYSTEM_MODULES)
            env[psmk] = ";".join(kept)
        else:
            del env[psmk]
    return env


# ---------------------------------------------------------------------------
# Job Object plumbing (ctypes, no pywin32)
# ---------------------------------------------------------------------------

class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BASIC_LIMIT_INFO(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _EXTENDED_LIMIT_INFO(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BASIC_LIMIT_INFO),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
    ]


def _make_kill_on_close_job() -> int | None:
    k32 = ctypes.windll.kernel32
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = _EXTENDED_LIMIT_INFO()
    info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not k32.SetInformationJobObject(
        job, _JOB_OBJECT_EXTENDED_LIMIT, ctypes.byref(info), ctypes.sizeof(info)
    ):
        k32.CloseHandle(job)
        return None
    return job


def _assign_to_job(job: int, process_handle: int) -> bool:
    return bool(ctypes.windll.kernel32.AssignProcessToJobObject(job, process_handle))


def _resume_process(pid: int) -> bool:
    """Resume the initial (suspended) thread of a process. Best effort."""
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    if snap == _INVALID_HANDLE_VALUE:
        return False
    entry = _THREADENTRY32()
    entry.dwSize = ctypes.sizeof(_THREADENTRY32)
    resumed = False
    try:
        if k32.Thread32First(snap, ctypes.byref(entry)):
            while True:
                if entry.th32OwnerProcessID == pid:
                    handle = k32.OpenThread(_THREAD_SUSPEND_RESUME, False, entry.th32ThreadID)
                    if handle:
                        k32.ResumeThread(handle)
                        k32.CloseHandle(handle)
                        resumed = True
                        break
                if not k32.Thread32Next(snap, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(snap)
    return resumed


def _taskkill_tree(pid: int) -> None:
    subprocess.run(
        ["taskkill", "/T", "/F", "/PID", str(pid)],
        capture_output=True, timeout=15, check=False,
        env=child_env(),
        creationflags=_CREATE_NO_WINDOW if os.name == "nt" else 0,
    )


# ---------------------------------------------------------------------------
# the runner
# ---------------------------------------------------------------------------

_config: Config | None = None
_redact = None  # callable[str, str]
_ps_path: str | None = None
_init_lock = threading.Lock()


def init(cfg: Config, redact_fn=None) -> None:
    global _config, _redact, _ps_path
    with _init_lock:
        _config = cfg
        _redact = redact_fn if redact_fn is not None else (lambda s: s)
        _ps_path = find_powershell(cfg.host_powershell_path)


def redact(text: str) -> str:
    if _redact is not None:
        return _redact(text)
    return text


# ---------------------------------------------------------------------------
# host-wide PowerShell slot pool (issue #15 / FND-13)
#
# Every run_ps call — from any tool leg, any relay request thread, any of the
# several server processes agents start on one host — must hold one of N slot
# lock files before it may spawn a child. The locks are OS file locks
# (msvcrt.locking on Windows, fcntl.flock elsewhere), so the host-wide count
# is bounded across processes AND a holder that dies has its slot released by
# the OS (a named kernel semaphore would leak capacity instead). A fresh
# open per acquisition excludes correctly between threads of one process
# (separate file objects / open file descriptions) and across processes.

@dataclass
class PooledResult:
    """The pooled-path counterpart of :class:`PSResult`.

    Deliberately NOT a PSResult: ``PSResult.__post_init__`` feeds the active
    timing collector's spawn counter, and a REUSED session must not claim a host
    spawn that never happened (issue #21, AC21). Same field names, so every
    consumer that reads ``stdout`` / ``stderr`` / ``returncode`` / ``timed_out``
    works unchanged.
    """

    stdout: str
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False
    duration_ms: int = 0
    #: Guest-side work, reported by the worker from inside the session.
    guest_ms: int | None = None
    #: "session" when the PSSession itself broke before any guest-side effect
    #: (retryable on a fresh session), "guest" when the inner script ran.
    phase: str = "guest"
    #: The guest's current boot epoch, reported by the worker on every response.
    boot_epoch: str | None = None


class _ResultLike(Protocol):
    """What :func:`check_result` reads. Both PSResult and PooledResult
    satisfy it, so the per-call and pooled paths share one validator without
    either losing its concrete type at the call site."""

    stdout: str
    stderr: str
    returncode: int | None
    timed_out: bool


_ResultT = TypeVar("_ResultT", bound=_ResultLike)


_REAL_POPEN = subprocess.Popen  # bound at import: survives test patches of the module attribute

_POLL_SLICE_S = 0.2  # communicate() polling slice; also the cancellation window
_DRAIN_TIMEOUT_S = 2.0  # bound on the post-kill partial-output drain
_SLOT_RETRY_S = 0.05
_SLOT_ACLS_DONE: set[str] = set()  # directories already hardened (best effort)


def _ps_slot_dir() -> Path:
    """Resolve (and create) the slot directory from config or platform default.
    An uncreatable/unwritable directory is a config/environment fault, so it
    fails the LEG as PowerShellTransportError, never the server."""
    import tempfile

    if _config is not None and _config.ps_slot_dir:
        directory = Path(_config.ps_slot_dir)
        hardening_scope = False  # caller-named dirs keep the caller's ACL policy
    elif os.name == "nt" and os.environ.get("ProgramData"):
        directory = Path(os.environ["ProgramData"]) / "hyperv-mcp" / "ps-slots"
        hardening_scope = True
    else:
        # tempdir default keeps the pool host-wide (a cwd fallback would not
        # be shared by processes with different working directories). On
        # Windows this resolves under the calling account's %LOCALAPPDATA%,
        # so the pool is per-account there (README documents this); it is not
        # ACL-hardened because hardening a shared temp root is wrong.
        directory = Path(tempfile.gettempdir()) / "hyperv-mcp-ps-slots"
        hardening_scope = False
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # directory.name only (like the sibling slot-file error): the full
        # path would disclose the host filesystem layout - and on the tempdir
        # fallback the local account name - to MCP clients.
        raise PowerShellTransportError(
            f"cannot create PowerShell slot directory {directory.name}: {redact(str(exc))}"
        ) from None
    if hardening_scope and os.name == "nt":
        # Harden the derived ProgramData default once per process whether or
        # not THIS process created it: a pre-existing (or squatted) directory
        # must not be adopted unhardened — the issue's constraint is that the
        # slot directory must not be writable by non-administrative users.
        # _SLOT_ACLS_DONE keeps it once-per-directory per process.
        _harden_slot_dir_acl(directory)
    return directory


def _harden_slot_dir_acl(directory: Path) -> None:
    """Best-effort ACL restriction of the derived default slot directory to
    Administrators, Hyper-V Administrators (both by well-known SID, so the
    grant survives localized group names) and the running account. Failure
    is a warning, never fatal: the cap still works, only the
    non-admin-starvation hardening is weaker (README documents this)."""
    key = str(directory)
    if key in _SLOT_ACLS_DONE:
        return
    _SLOT_ACLS_DONE.add(key)
    if os.name != "nt":
        return

    argv = [
        "icacls", str(directory), "/inheritance:r",
        "/grant", "*S-1-5-32-544:(OI)(CI)F",      # BUILTIN\Administrators
        "/grant", "*S-1-5-32-578:(OI)(CI)F",      # BUILTIN\Hyper-V Administrators
    ]
    # The account grant is best-effort: getpass.getuser() falls back to the
    # pwd module (absent on Windows) when the environment carries no user
    # name, so it must never be able to fail the leg. A derived-but-unknown
    # account simply skips the grant (Administrators + Hyper-V
    # Administrators still hold the directory).
    try:
        import getpass

        account = getpass.getuser()
    except Exception:
        account = ""
    if account:
        argv += ["/grant", f"{account}:(OI)(CI)F"]
    try:
        # Deliberately the import-time _REAL_POPEN, never the (patchable)
        # module attribute: unit tests intercept run_ps spawns by patching
        # subprocess.Popen and their fakes have no context-manager/timeout
        # surface — infrastructure must not route through them.
        proc = _REAL_POPEN(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env(),
            creationflags=_CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        try:
            _, err_b = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        if proc.returncode != 0:
            print(
                "pswindows: slot-dir ACL hardening failed (continuing): "
                + redact((err_b or b"").decode("utf-8", "replace").strip()),
                file=sys.stderr,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        # Type + message only: a TimeoutExpired stringifies as the whole
        # command line (slot-directory path and account name included).
        print(
            f"pswindows: slot-dir ACL hardening failed (continuing): "
            f"{type(exc).__name__}: {redact(str(exc)) if not isinstance(exc, subprocess.TimeoutExpired) else 'timed out after 30s'}",
            file=sys.stderr,
        )


def _try_lock_slot(path: Path) -> int | None:
    """Open `path` fresh and take a non-blocking exclusive lock on byte 0.
    Returns the held fd, or None (after closing the attempt) when taken."""
    flags = os.O_RDWR | os.O_CREAT
    if os.name == "nt":
        flags |= os.O_BINARY
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PowerShellTransportError(
            f"cannot open PowerShell slot file {path.name}: {redact(str(exc))}"
        ) from None
    try:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
        return fd
    except OSError:
        os.close(fd)  # never strand per-attempt fds
        return None


def _acquire_ps_slot() -> int:
    """Acquire one slot, round-robin, waiting up to the configured bound.

    The wait itself observes anyio cancellation each retry tick, so a
    cancelled caller never sits out the full bound and never gets told to
    retry a call it cancelled.
    """
    if _config is None:
        raise PowerShellTransportError("pswindows.init() was not called")
    cap = _config.max_host_powershell
    wait_s = float(_config.host_powershell_wait_s)
    directory = _ps_slot_dir()
    names = [directory / f"slot-{i:02d}.lock" for i in range(cap)]
    started = time.monotonic()
    deadline = started + wait_s
    start_index = (threading.get_ident() + int(started * 1000)) % cap
    while True:
        for offset in range(cap):
            if wait_s and time.monotonic() >= deadline:
                break  # check the deadline inside the sweep: never overshoot
            fd = _try_lock_slot(names[(start_index + offset) % cap])
            if fd is not None:
                return fd
        waited = time.monotonic() - started
        if waited >= wait_s:
            raise PowerShellBusy(
                f"host PowerShell pool saturated: {cap} concurrent children "
                f"already running; waited {waited:.3g}s"
            )
        _check_ps_cancellation()
        time.sleep(_SLOT_RETRY_S)


def _release_ps_slot(fd: int) -> None:
    try:
        try:
            if os.name == "nt":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)  # type: ignore[attr-defined]
        except OSError:
            pass  # closing the fd releases the lock anyway
    finally:
        try:
            os.close(fd)  # unconditional: an unlock failure must never strand the fd
        except OSError:
            pass  # never mask the exception this release is unwinding past


def _check_ps_cancellation() -> None:
    """Observe anyio host-task cancellation from inside a worker thread.

    anyio.to_thread.run_sync workers (the dispatch shape MCP request
    cancellation will use once tool calls move off the event loop, issue #16)
    get their cancellation exception raised here. Anywhere else — including
    the event-loop thread mcp 1.x uses for sync tools today — this raises
    RuntimeError (NoEventLoopError included), which is swallowed, so plain
    threads and CLI callers keep today's behavior."""
    try:
        anyio.from_thread.check_cancelled()
    except RuntimeError:
        pass


def run_ps(
    script: str,
    *,
    timeout_s: float | None = None,
    stdin_b64: str | None = None,
) -> PSResult:
    """Run a script under Windows PowerShell and capture stdout/stderr/exit.

    The script is passed via -EncodedCommand so no secret ever lands on the
    process command line; the optional stdin_b64 payload (e.g. the base64
    guest password) arrives on stdin. The call must hold one of the
    host-wide slot pool's lock files before spawning (issue #15): an
    oversubscribed caller waits up to the configured bound and then raises
    PowerShellBusy. On ANY exit other than normal completion — timeout,
    exception, cancellation observed from an anyio worker thread — the whole
    host-side process tree is killed via the Job Object (taskkill fallback),
    the Job handle is closed, and the slot is released. All output text is
    redacted before return.
    """
    if _ps_path is None:
        raise PowerShellTransportError("pswindows.init() was not called")
    effective_timeout = float(timeout_s if timeout_s is not None else (_config.ps_timeout_s if _config else 120))
    argv = [_ps_path, "-NonInteractive", "-NoProfile", "-EncodedCommand", encode_command(_PS_PIN + script)]
    stdin_bytes = (stdin_b64 + "\n").encode("ascii") if stdin_b64 is not None else None

    # One protected region from slot acquisition to release: no exit path —
    # timeout, injected exception, cancellation, spawn failure, or an
    # exception raised by job assignment/resume — may strand a slot fd, the
    # Job handle, a spawned child, or mask a propagating exception (issue #15).
    slot = _acquire_ps_slot()
    # The leg clock starts AFTER the slot wait: the bounded wait is its own
    # budget (host_powershell_wait_s) and must not consume the caller's
    # script timeout, or saturation would surface as a non-retryable timeout
    # with empty output instead of the retryable busy envelope.
    start = time.monotonic()
    job = None
    proc = None
    job_assigned = False
    completed = False
    timed_out = False
    first_slice = True
    out_b = err_b = b""
    try:
        job = _make_kill_on_close_job() if os.name == "nt" else None
        try:
            creationflags = _CREATE_SUSPENDED if os.name == "nt" else 0
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=(
                    creationflags | _CREATE_NO_WINDOW if os.name == "nt" else creationflags
                ),
                env=child_env(),
            )
        except OSError as exc:
            raise PowerShellTransportError(
                f"failed to spawn powershell: {redact(str(exc))}"
            ) from None

        if job is not None:
            job_assigned = _assign_to_job(job, int(proc._handle))  # type: ignore[attr-defined]
        if os.name == "nt" and not _resume_process(proc.pid):
            raise PowerShellTransportError("could not resume suspended powershell process")
            # the finally below kills the still-suspended child and cleans up

        deadline = start + effective_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                out_b, err_b = proc.communicate(
                    input=stdin_bytes if first_slice else None,
                    timeout=min(_POLL_SLICE_S, remaining),
                )
                completed = True
                break
            except subprocess.TimeoutExpired:
                first_slice = False
                _check_ps_cancellation()
    finally:
        if proc is not None and not completed:
            # Best-effort tree kill; never masks a propagating exception. Each
            # kill step is independent: a failing taskkill must not skip the
            # direct-child kill, and the whole block must not skip close/release.
            try:
                if job is not None and job_assigned:
                    ctypes.windll.kernel32.TerminateJobObject(job, 1)
            except Exception:
                pass
            try:
                if job is None or not job_assigned:
                    if os.name == "nt":
                        _taskkill_tree(proc.pid)
            except Exception:
                pass
            try:
                proc.kill()
            except OSError:
                pass
        if timed_out and proc is not None:
            # Bounded drain: a surviving grandchild holding the inherited
            # stdout handle must not be able to wedge the cleanup forever
            # while this leg still holds its slot (issue #15 review).
            try:
                out_b, err_b = proc.communicate(timeout=_DRAIN_TIMEOUT_S)
            except Exception:
                out_b = err_b = b""  # partial output is best-effort
        if job is not None:
            try:
                ctypes.windll.kernel32.CloseHandle(job)  # kill-on-close safety net
            except OSError:
                pass
        _release_ps_slot(slot)

    duration_ms = int((time.monotonic() - start) * 1000)
    # The timing marker is split off BEFORE redaction and before .strip(), so a
    # marker line can never reach a tool's stdout (an unparseable or hostile
    # one is removed just as unconditionally as a valid one) and never reaches
    # the redaction filter. PSResult.__post_init__ then feeds the parsed values
    # to the active collector.
    stdout_text, markers = timing.parse_marker(out_b.decode("utf-8", "replace"))
    result = PSResult(
        stdout=redact(stdout_text).strip(),
        stderr=redact(_decode_clixml(err_b.decode("utf-8", "replace"))).strip(),
        returncode=None if timed_out else proc.returncode,
        timed_out=timed_out,
        duration_ms=duration_ms,
        timing=markers,
    )
    return result


_CLIXML_ERROR_RE = re.compile(r'<S S="Error">(.*?)</S>', re.DOTALL)
_CLIXML_ESCAPES = {
    "_x000D_": "\r", "_x000A_": "\n", "_x0009_": "\t",
    "_x0020_": " ", "_x003C_": "<", "_x003E_": ">", "_x0026_": "&",
}


def _decode_clixml(text: str) -> str:
    """Decode PowerShell CLIXML-serialized stderr into plain text.

    With -EncodedCommand, error records reach stderr as '#< CLIXML' XML
    (observed live against Hyper-V: Start-VM failures serialize as
    <S S="Error"> elements with _xNNNN_ character escapes). Human-readable
    errors matter; without this, every real Hyper-V failure surfaces as
    an XML blob.
    """
    if not text.startswith("#< CLIXML"):
        return text
    lines: list[str] = []
    for raw in _CLIXML_ERROR_RE.findall(text):
        for esc, ch in _CLIXML_ESCAPES.items():
            raw = raw.replace(esc, ch)
        for part in raw.split("\n"):
            part = part.strip()
            if part:
                lines.append(part)
    return "\n".join(lines) if lines else text


def check_result(result: _ResultT, ctx: str = "") -> _ResultT:
    """Raise PowerShellTransportError (redacted) when a completed run failed or
    timed out.

    PowerShellTransportError is already a RuntimeError subclass, so every
    existing caller that catches RuntimeError keeps working; the narrower type
    is what the rest of the codebase maps to ``error_class: "transport"``.
    """
    if result.timed_out:
        raise PowerShellTransportError(
            f"{ctx}: PowerShell timed out" if ctx else "PowerShell timed out"
        )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        raise PowerShellTransportError(f"{ctx}: {detail}" if ctx else detail)
    return result


# ---------------------------------------------------------------------------
# remote Hyper-V host composition (issue #43)
# ---------------------------------------------------------------------------

def hyperv_host(cfg) -> str | None:
    """The configured remote Hyper-V host, or None for local mode.

    Reads the CALLER's config object — never the pswindows module global —
    so per-call tool configs (and tests mixing local and remote configs in
    one process) each compose correctly.
    """
    target = getattr(cfg, "hyperv", None)
    return getattr(target, "host", None) if target is not None else None


def _remote_parts(cfg, *, payload_lines: int, stdin_b64: str | None):
    """Shared internals of the remote composition: resolve host credentials
    per call and build (preamble_lines, composed_stdin, host_cred, params).

    Local mode: ([], stdin_b64, None, []).
    """
    from . import credentials  # local import: credentials does not import pswindows

    host = hyperv_host(cfg)
    if not host:
        return [], stdin_b64, None, []
    if payload_lines and stdin_b64 is None:
        raise ValueError("payload_lines > 0 requires stdin_b64")
    host_cred = credentials.resolve_host()
    params = [f"$__p{i}" for i in range(payload_lines)]
    lines: list[str] = []
    new_stdin = stdin_b64
    if host_cred is not None:
        lines.append("$__hostpwRaw = [Console]::In.ReadLine()")
        new_stdin = utf8_b64(host_cred.password)
        if stdin_b64 is not None:
            new_stdin = new_stdin + "\n" + stdin_b64
    lines.extend(f"$__p{i} = [Console]::In.ReadLine()" for i in range(payload_lines))
    if host_cred is not None:
        lines.extend([
            "$__hostpwText = [System.Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String($__hostpwRaw))",
            "$__hostsec = $__hostpwText | ConvertTo-SecureString -AsPlainText -Force",
            "$__hostcred = [System.Management.Automation.PSCredential]::new("
            f"{ps_quote(host_cred.username)}, $__hostsec)",
            "$__hostpwRaw = $null; $__hostpwText = $null; $__hostsec = $null",
        ])
    return lines, new_stdin, host_cred, params


def remote_prelude(cfg, *, payload_lines: int = 0, stdin_b64: str | None = None) -> tuple[str, str | None]:
    """Local preamble lines + composed stdin for a remote-mode script.

    Shared by compose_remote (single outer wrap) and filetransfer's transfer
    builders (multiple per-leg hops): emits the stdin reads — host password
    first (when a complete HYPERV_HOST_* pair resolves; decoded locally into
    $__hostcred, never forwarded, never in script text), caller payload
    lines after ($__p0…) — and returns (preamble_text, stdin_b64) where the
    stdin is the fully composed multi-line payload. Identity ("", unchanged
    stdin) in local mode.
    """
    lines, new_stdin, _cred, _params = _remote_parts(
        cfg, payload_lines=payload_lines, stdin_b64=stdin_b64
    )
    if not lines:
        return "", new_stdin
    return "\n".join(lines) + "\n", new_stdin


def hop_line(cfg) -> str:
    """Invoke-Command opening for ONE remote leg; empty string in local mode.

    Single source for the hop shape so per-leg emitters (filetransfer's
    transfer builders) cannot drift from compose_remote: ``-Credential
    $__hostcred`` is appended only when a complete HYPERV_HOST_* pair
    resolves — mirroring the preamble that defines ``$__hostcred`` — so
    implicit-auth deployments never reference an undefined variable
    (PRR-006). Callers append ``-ScriptBlock { ... } [-ArgumentList ...]
    -ErrorAction Stop``.
    """
    host = hyperv_host(cfg)
    if not host:
        return ""
    from . import credentials  # local import: credentials does not import pswindows

    line = f"Invoke-Command -ComputerName {ps_quote(host)}"
    if credentials.resolve_host() is not None:
        line += " -Credential $__hostcred"
    return line


def compose_remote(
    cfg,
    body: str,
    *,
    payload_lines: int = 0,
    stdin_b64: str | None = None,
) -> tuple[str, str | None]:
    """Compose the WS-Man hop for a script body (issue #43).

    Identity in local mode: returns (body, stdin_b64) untouched, so local
    scripts stay byte-identical to the pre-feature emissions.

    Remote mode wraps the body in ``Invoke-Command -ComputerName '<host>'``
    (hostname ps_quote'd; charset-validated at config load — defense in
    depth). Host credentials resolve PER CALL from HYPERV_HOST_* (so the
    environment is read at tool-call time, matching every other credential
    resolution in this server); when a complete pair exists the host
    password becomes the FIRST stdin line — decoded locally, never embedded
    in script text — and ``-Credential`` rides the Invoke-Command. Caller
    payload lines follow on stdin and cross the hop as scriptblock
    parameters (``param($__p0, ...)`` + ``-ArgumentList``), because a remote
    scriptblock cannot read the local process's stdin. Inside the block only
    $ProgressPreference is pinned; the OutputEncoding assignment is
    try/catch-guarded (a console-less remote runspace may reject it).
    """
    host = hyperv_host(cfg)
    if not host:
        return body, stdin_b64
    lines, new_stdin, _host_cred, params = _remote_parts(
        cfg, payload_lines=payload_lines, stdin_b64=stdin_b64
    )

    inner = (
        (f"param({', '.join(params)})\n" if params else "")
        + "$ProgressPreference='SilentlyContinue';\n"
        + "try { [Console]::OutputEncoding="
        "[System.Text.UTF8Encoding]::new($false) } catch { }\n"
        + body
    )
    script = (
        "\n".join(lines)
        + "\n"
        + hop_line(cfg)
        + " -ScriptBlock {\n"
        + inner
        + "\n}"
        + (f" -ArgumentList {', '.join(params)}" if params else "")
        + " -ErrorAction Stop"
    )
    return script, new_stdin


# ---------------------------------------------------------------------------
# long-lived workers (issue #21)
#
# `run_ps` above spawns a child, runs ONE script and tears the child down with
# the Job Object. A pooled session needs the opposite: a child that outlives the
# call and answers many requests over stdin/stdout. This is the only other place
# in the module that spawns, and it reuses every piece of the plumbing above —
# the host-wide slot pool (held for the worker's WHOLE lifetime), the
# kill-on-close Job Object, suspended start + resume, `child_env`,
# CREATE_NO_WINDOW, and a finally-guarded teardown that kills the tree and
# releases the slot. A worker therefore dies with the server process even if
# nobody closes it politely.
# ---------------------------------------------------------------------------

_WORKER_EXIT = "__MCP_WORKER_EXIT__"
#: Slack added to a per-call timeout so the host does not kill a worker that
#: is about to answer. Same 10 s guestexec uses for the per-call path.
_WORKER_GRACE_S = 10


class PooledWorker:
    """One long-lived host `powershell.exe` hosting a single PSSession.

    The protocol is one base64 JSON line per request on stdin and one base64
    JSON line per response on stdout. Responses are framed that way — rather
    than being the guest script's raw stdout — so a guest script that prints
    arbitrary bytes can never desynchronise the host.

    Reads happen on a daemon thread that pushes lines onto a queue, because a
    blocking `readline()` cannot honour a per-call timeout and Windows pipes are
    not selectable.
    """

    def __init__(self, proc, job, slot, boot_epoch, session_ms):
        self._proc = proc
        self._job = job
        self._slot = slot
        self.boot_epoch = boot_epoch
        self.session_ms = session_ms
        self._lines: queue.Queue = queue.Queue()
        self._reader = threading.Thread(
            target=self._pump, name="pswindows-worker-reader", daemon=True
        )
        self._reader.start()
        self._dead = False

    # -- lifecycle ---------------------------------------------------------

    def _pump(self) -> None:
        try:
            while True:
                raw = self._proc.stdout.readline()
                if not raw:
                    break
                self._lines.put(raw)
        except Exception:
            pass
        finally:
            self._lines.put(None)  # EOF sentinel

    def is_alive(self) -> bool:
        return not self._dead and self._proc.poll() is None

    def close(self) -> None:
        """Kill the worker tree and release its slot. Idempotent.

        The release runs on EVERY call, including after a timeout already marked
        the worker dead: `run` kills the tree on a timeout but leaves the slot to
        this method, and an early return there would strand one of the
        host-wide `max_host_powershell` slots for the life of the process.
        """
        first_close = not self._dead
        self._dead = True
        if first_close:
            try:
                if self._proc.stdin is not None:
                    self._proc.stdin.write((_WORKER_EXIT + "\n").encode("ascii"))
                    self._proc.stdin.flush()
            except Exception:
                pass
            try:
                self._proc.wait(timeout=5)
            except Exception:
                pass
            self._kill_tree()
        try:
            self._proc.stdout.close()
        except Exception:
            pass
        try:
            self._proc.stdin.close()
        except Exception:
            pass
        if self._job is not None:
            try:
                ctypes.windll.kernel32.CloseHandle(self._job)
            except OSError:
                pass
        if self._slot is not None:
            _release_ps_slot(self._slot)

    def _kill_tree(self) -> None:
        try:
            if self._job is not None:
                ctypes.windll.kernel32.TerminateJobObject(self._job, 1)
        except Exception:
            pass
        try:
            self._proc.kill()
        except OSError:
            pass

    # -- requests ----------------------------------------------------------

    def run(self, inner_script: str, *, elevated: bool = False,
            timeout_ms: int | None = None) -> PooledResult:
        """Run one inner guest script over the pooled session.

        `elevated` is accepted for signature parity with the per-call path; the
        guest-side elevation happens inside the inner script (Start-Process
        -Verb RunAs), exactly as it does today, so it needs nothing here.
        """
        if self._dead or self._proc.poll() is not None:
            return PooledResult(
                stdout="", stderr="the pooled worker is not running",
                returncode=None, phase="session",
            )
        timeout_s = (
            float(timeout_ms) / 1000.0 + _WORKER_GRACE_S
            if timeout_ms is not None
            else float(_config.ps_timeout_s if _config else 120)
        )
        started = time.monotonic()
        frame = json.dumps({
            "script": inner_script,
            "expect_epoch": self.boot_epoch,
            "elevated": bool(elevated),
        })
        try:
            if self._proc.stdin is None:
                raise OSError("the pooled worker has no stdin")
            self._proc.stdin.write(
                (base64.b64encode(frame.encode("utf-8")).decode("ascii") + "\n").encode("ascii")
            )
            self._proc.stdin.flush()
        except OSError as exc:
            self._dead = True
            return PooledResult(
                stdout="", stderr=redact(str(exc)), returncode=None, phase="session",
            )
        try:
            line = self._lines.get(timeout=timeout_s)
        except queue.Empty:
            self._kill_tree()
            self._dead = True
            return PooledResult(
                stdout="",
                stderr=f"pooled worker timeout after {timeout_s:g}s",
                returncode=None,
                timed_out=True,
                duration_ms=int((time.monotonic() - started) * 1000),
                phase="session",
            )
        if line is None:
            self._dead = True
            return PooledResult(
                stdout="", stderr="the pooled worker exited", returncode=None,
                phase="session",
            )
        duration_ms = int((time.monotonic() - started) * 1000)
        return _decode_worker_response(line, duration_ms)


def _decode_worker_response(line: bytes, duration_ms: int) -> PooledResult:
    """Turn one base64 JSON response frame into a PooledResult."""
    try:
        payload = json.loads(
            base64.b64decode(line.strip()).decode("utf-8", "replace")
        )
    except Exception:
        return PooledResult(
            stdout="", stderr="unreadable pooled worker response",
            returncode=None, phase="session", duration_ms=duration_ms,
        )
    if not isinstance(payload, dict):
        return PooledResult(
            stdout="", stderr="unexpected pooled worker response shape",
            returncode=None, phase="session", duration_ms=duration_ms,
        )
    # `stdout` always carries a JSON object, so every caller can unwrap it with
    # the SAME json.loads it already runs on the per-call host script's output.
    # On success that object is {exit_code, stdout, stderr, duration_ms} — the
    # wrapper the guest body emits — and on failure it is {ok: false, error,
    # phase}, which is what tells the caller whether the failure is retryable.
    if not payload.get("ok"):
        return PooledResult(
            stdout=json.dumps({
                "ok": False,
                "error": str(payload.get("error") or "pooled worker failure"),
                "phase": str(payload.get("phase") or "session"),
                "boot_epoch": payload.get("boot_epoch"),
            }),
            returncode=0,
            duration_ms=duration_ms,
            phase=str(payload.get("phase") or "session"),
            boot_epoch=payload.get("boot_epoch"),
        )
    return PooledResult(
        stdout=json.dumps({
            "exit_code": payload.get("exit_code"),
            "stdout": str(payload.get("stdout") or ""),
            "stderr": str(payload.get("stderr") or ""),
            "duration_ms": payload.get("guest_ms"),
        }),
        returncode=0,
        timed_out=False,
        duration_ms=duration_ms,
        guest_ms=payload.get("guest_ms"),
        phase=str(payload.get("phase") or "guest"),
        boot_epoch=payload.get("boot_epoch"),
    )


def spawn_worker(script: str, credential_b64: str | None = None) -> PooledWorker:
    """Start a long-lived host PowerShell worker running `script`.

    Same plumbing as `run_ps`: one host-wide slot (held for the worker's whole
    lifetime, released on close), a kill-on-close Job Object assigned before the
    process is resumed, `child_env`, CREATE_NO_WINDOW, and a finally-guarded
    teardown. The credential arrives on the worker's stdin as its first line and
    appears nowhere else.

    Returns a `PooledWorker` whose `run` answers one request at a time.
    """
    if _ps_path is None:
        raise PowerShellTransportError("pswindows.init() was not called")
    argv = [_ps_path, "-NonInteractive", "-NoProfile", "-EncodedCommand",
            encode_command(_PS_PIN + script)]
    slot = _acquire_ps_slot()
    job = None
    proc = None
    try:
        job = _make_kill_on_close_job() if os.name == "nt" else None
        creationflags = _CREATE_SUSPENDED if os.name == "nt" else 0
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=(
                creationflags | _CREATE_NO_WINDOW if os.name == "nt" else creationflags
            ),
            env=child_env(),
        )
        if job is not None:
            _assign_to_job(job, int(proc._handle))  # type: ignore[attr-defined]
        if os.name == "nt" and not _resume_process(proc.pid):
            raise PowerShellTransportError("could not resume suspended worker process")
    except OSError as exc:
        _release_ps_slot(slot)
        raise PowerShellTransportError(
            f"failed to spawn pooled worker: {redact(str(exc))}"
        ) from None
    except Exception:
        if proc is not None:
            try:
                proc.kill()
            except OSError:
                pass
        if job is not None:
            try:
                ctypes.windll.kernel32.CloseHandle(job)
            except OSError:
                pass
        _release_ps_slot(slot)
        raise

    # The worker reads its credential as its first stdin line. Writing one short
    # line cannot fill the pipe buffer, so there is no ordering hazard.
    if credential_b64 is not None and proc.stdin is not None:
        try:
            proc.stdin.write((credential_b64 + "\n").encode("ascii"))
            proc.stdin.flush()
        except OSError as exc:
            _abandon_worker(proc, job, slot)
            raise PowerShellTransportError(
                f"could not deliver the credential to the pooled worker: "
                f"{redact(str(exc))}"
            ) from None

    # The worker's open handshake is one response frame reporting the guest's
    # boot epoch; it is what makes the epoch part of the key meaningful.
    boot_epoch = None
    session_ms = None
    line = _read_first_line(proc, timeout=60.0)
    if line:
        try:
            payload = json.loads(base64.b64decode(line.strip()).decode("utf-8", "replace"))
            if isinstance(payload, dict) and payload.get("ok"):
                boot_epoch = payload.get("boot_epoch")
                session_ms = payload.get("session_ms")
        except Exception:
            boot_epoch = None
    return PooledWorker(proc, job, slot, boot_epoch, session_ms)


def _abandon_worker(proc, job, slot) -> None:
    """Kill a half-started worker and release everything it holds."""
    try:
        proc.kill()
    except OSError:
        pass
    if job is not None:
        try:
            ctypes.windll.kernel32.CloseHandle(job)
        except OSError:
            pass
    _release_ps_slot(slot)


def _read_first_line(proc, timeout: float) -> bytes:
    """Read one line from `proc.stdout` with a deadline, on a throwaway thread.

    A blocking `readline()` cannot honour a deadline and Windows pipes are not
    selectable, so the read happens on a daemon thread and this call waits on a
    queue.
    """
    q: queue.Queue = queue.Queue()

    def _pump() -> None:
        try:
            q.put(proc.stdout.readline())
        except Exception:
            q.put(b"")

    threading.Thread(target=_pump, daemon=True).start()
    try:
        return q.get(timeout=timeout)
    except queue.Empty:
        return b""
