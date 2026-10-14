"""Real-Hyper-V integration check for issue 15 (FND-13): cancellation hygiene.

AC6: cancelling the async scope around a PowerShell Direct guest leg (an
anyio worker thread - the shape every MCP tool call uses) must return
promptly, leave ZERO surviving powershell.exe descendants of this test
process on the host, and release the VM lock so an immediate
checkpoint_create succeeds.

Opt-in like every test in this directory (see tests/integration/conftest.py):
HYPERV_MCP_INTEGRATION=1 plus a disposable HYPERV_MCP_TEST_VM and guest
credentials. RED at the pre-fix base, GREEN after the fix.
"""

import ctypes
import os
import time
from ctypes import wintypes

import pytest

pytestmark = [pytest.mark.hyperv_real]

_TH32CS_SNAPPROCESS = 0x00000002
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _powershell_descendant_pids() -> list[int]:
    """Pids of powershell.exe descendants of THIS process.

    Walks a toolhelp process snapshot recursively by ParentProcessId - the
    same parent/child relationship Win32_Process exposes - with pure ctypes:
    the check itself must spawn no child processes (a PowerShell-based walk
    would be its own false positive) and must not depend on psutil.
    """
    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot == _INVALID_HANDLE_VALUE:
        raise RuntimeError("CreateToolhelp32Snapshot failed")
    rows: dict[int, tuple[str, int]] = {}
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
    try:
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            rows[entry.th32ProcessID] = (entry.szExeFile, entry.th32ParentProcessID)
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    found: list[int] = []
    frontier = [os.getpid()]
    seen = {os.getpid()}
    while frontier:
        parent = frontier.pop()
        for pid, (name, ppid) in rows.items():
            if ppid == parent and pid not in seen:
                seen.add(pid)
                if name.lower() == "powershell.exe":
                    found.append(pid)
                frontier.append(pid)
    return found


def test_cancelled_guest_leg_leaves_no_host_powershell(it):
    """AC6: a real PS Direct leg (Start-Sleep -Seconds 60) runs inside an
    anyio worker thread; its scope is cancelled after 3 s. The call must
    return within 5 s, no powershell.exe descendant of this test process
    may survive on the host, and an immediate checkpoint_create on the VM
    must succeed (the VM lock was released). RED at the pre-fix base, GREEN
    after the fix."""
    import anyio

    from hyperv_mcp import guestexec, lifecycle

    start = time.monotonic()
    leg_starts: list[float] = []

    def leg():
        leg_starts.append(time.monotonic() - start)
        return guestexec.guest_run_ps(
            it.cfg, it.vm, "Start-Sleep -Seconds 60",
            timeout_ms=90000, cred=it.creds,
        )

    async def scenario():
        with anyio.move_on_after(3):
            await anyio.to_thread.run_sync(leg)

    anyio.run(scenario)
    elapsed = time.monotonic() - start
    assert elapsed <= 5, (
        f"the cancelled guest leg returned after {elapsed:.1f}s (bound: 5s); "
        "cancellation must stop the host-side leg promptly"
    )
    # Anti-vacuity oracle: the cancel budget must land on the GUEST leg, not
    # on the earlier vmident.resolve leg. If resolve alone consumed the 3 s
    # budget the guest leg never starts and the assertions below would pass
    # without exercising cancellation at all — so require the guest leg to
    # have started before the 3 s deadline.
    assert leg_starts and leg_starts[0] < 3.0, (
        f"the guest leg started at {leg_starts[0] if leg_starts else 'never'}s "
        "into a 3s cancel budget — the scope cancelled an earlier leg "
        "(vmident.resolve), so guest-leg cancellation was never exercised"
    )

    survivors = _powershell_descendant_pids()
    deadline = time.monotonic() + 2
    while survivors and time.monotonic() < deadline:
        time.sleep(0.2)
        survivors = _powershell_descendant_pids()
    assert survivors == [], (
        f"host powershell.exe descendants survived the cancelled leg: {survivors}"
    )

    checkpoint = f"mcp-it-c02-cancel-{time.strftime('%Y%m%d-%H%M%S')}"
    created = lifecycle.checkpoint_create(it.cfg, it.vm, checkpoint)
    assert created["status"] == "created", (
        f"immediate checkpoint_create failed after the cancelled leg "
        f"(VM lock not released?): {created}"
    )
    try:
        lifecycle.checkpoint_remove(it.cfg, it.vm, checkpoint, confirm=True)
    except Exception:
        pass  # best-effort cleanup; the test VM is disposable and guarded
