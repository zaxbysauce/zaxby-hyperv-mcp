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
import os
import re
import subprocess
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass

from .config import Config

_CREATE_SUSPENDED = 0x00000004
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


class PowerShellTransportError(RuntimeError):
    """powershell.exe missing or process machinery failed."""


@dataclass
class PSResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False
    duration_ms: int = 0

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


def run_ps(
    script: str,
    *,
    timeout_s: float | None = None,
    stdin_b64: str | None = None,
) -> PSResult:
    """Run a script under Windows PowerShell and capture stdout/stderr/exit.

    The script is passed via -EncodedCommand so no secret ever lands on the
    process command line; the optional stdin_b64 payload (e.g. the base64
    guest password) arrives on stdin. On timeout the whole host-side process
    tree is killed via the Job Object (taskkill fallback). All output text is
    redacted before return.
    """
    if _ps_path is None:
        raise PowerShellTransportError("pswindows.init() was not called")
    effective_timeout = float(timeout_s if timeout_s is not None else (_config.ps_timeout_s if _config else 120))
    argv = [_ps_path, "-NonInteractive", "-NoProfile", "-EncodedCommand", encode_command(_PS_PIN + script)]
    stdin_bytes = (stdin_b64 + "\n").encode("ascii") if stdin_b64 is not None else None

    start = time.monotonic()
    job = _make_kill_on_close_job() if os.name == "nt" else None
    try:
        creationflags = _CREATE_SUSPENDED if os.name == "nt" else 0
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
        )
    except OSError as exc:
        if job:
            ctypes.windll.kernel32.CloseHandle(job)
        raise PowerShellTransportError(f"failed to spawn powershell: {redact(str(exc))}") from None

    job_assigned = False
    if job is not None:
        job_assigned = _assign_to_job(job, int(proc._handle))  # type: ignore[attr-defined]
    resumed = _resume_process(proc.pid) if os.name == "nt" else True
    if not resumed:
        proc.kill()
        if job:
            ctypes.windll.kernel32.CloseHandle(job)
        raise PowerShellTransportError("could not resume suspended powershell process")

    timed_out = False
    try:
        out_b, err_b = proc.communicate(input=stdin_bytes, timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if job is not None and job_assigned:
            ctypes.windll.kernel32.TerminateJobObject(job, 1)
        else:
            _taskkill_tree(proc.pid)
        try:
            proc.kill()
        except OSError:
            pass
        out_b, err_b = proc.communicate()

    duration_ms = int((time.monotonic() - start) * 1000)
    if job is not None:
        ctypes.windll.kernel32.CloseHandle(job)  # kill-on-close safety net

    result = PSResult(
        stdout=redact(out_b.decode("utf-8", "replace")).strip(),
        stderr=redact(_decode_clixml(err_b.decode("utf-8", "replace"))).strip(),
        returncode=None if timed_out else proc.returncode,
        timed_out=timed_out,
        duration_ms=duration_ms,
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


def check_result(result: PSResult, ctx: str = "") -> PSResult:
    """Raise RuntimeError (redacted) when a completed run failed or timed out."""
    if result.timed_out:
        raise RuntimeError(f"{ctx}: PowerShell timed out" if ctx else "PowerShell timed out")
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        raise RuntimeError(f"{ctx}: {detail}" if ctx else detail)
    return result
