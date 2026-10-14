"""AC14 real-host integration: tool calls stop serializing on the event loop.

Drives the REAL deployment shape over streamable-http: one
`hyperv-mcp-http` controller on loopback (bearer-token protected) and two
independent MCP client sessions.

  1. client A runs `hyperv_guest_run_ps` with `Start-Sleep -Seconds 60` on
     the test VM while client B calls `hyperv_console_screenshot` on the
     SAME VM — the screenshot must return while the guest command is still
     running (at the pre-fix base the fast call queued behind the slow one
     for its full duration);
  2. when client A then cancels its call, its host `powershell.exe` tree
     must be gone within 5 s (the request cancellation crosses the HTTP
     transport into the server's worker thread and PR #61's kill path).

Opt-in like every test in this directory (see tests/integration/conftest.py):
HYPERV_MCP_INTEGRATION=1 plus a disposable HYPERV_MCP_TEST_VM and guest
credentials. RED at the pre-fix base (the screenshot waits behind the guest
command), GREEN after the fix.
"""

import ctypes
import os
import secrets
import socket
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

import pytest

pytestmark = [pytest.mark.hyperv_real]

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = str(REPO_ROOT / "src")

GUEST_COMMAND = "Start-Sleep -Seconds 60"

_TH32CS_SNAPPROCESS = 0x00000002
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_size_t),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _descendant_pids(root_pid: int, exe_name: str) -> list[int]:
    """Pids of `exe_name` descendants of `root_pid`, via a toolhelp snapshot
    walked by ParentProcessId. Pure ctypes: the check spawns no child of its
    own (a PowerShell-based walk would be its own false positive) and needs
    no psutil."""
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
    frontier = [root_pid]
    seen = {root_pid}
    while frontier:
        parent = frontier.pop()
        for pid, (name, ppid) in rows.items():
            if ppid == parent and pid not in seen:
                seen.add(pid)
                if name.lower() == exe_name:
                    found.append(pid)
                frontier.append(pid)
    return found


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_listening(port: int, timeout_s: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def test_screenshot_not_queued_behind_guest_command(it):
    """AC14: over the real transport, a console screenshot on the test VM
    returns while another client's 60 s guest command is still running, and
    cancelling that command kills its host PowerShell tree within 5 s."""
    import anyio
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    vm = it.vm
    token = secrets.token_urlsafe(32)
    port = _free_port()
    env = dict(os.environ)
    env["HYPERV_MCP_HTTP_TOKEN"] = token
    env.setdefault("HYPERV_MCP_UNRESTRICTED", "1")
    env["PYTHONPATH"] = SRC_DIR

    controller = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hyperv_mcp.http_entry",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        assert _wait_listening(port), "the controller did not listen on loopback"
        url = f"http://127.0.0.1:{port}/mcp"

        async def scenario():
            import httpx2

            headers = {"Authorization": f"Bearer {token}"}
            client_kw = {"http_client": httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(120.0))}
            async with (
                streamable_http_client(url, **client_kw) as (r1, w1),
                streamable_http_client(url, **client_kw) as (r2, w2),
            ):
                async with ClientSession(r1, w1) as agent_a, ClientSession(r2, w2) as agent_b:
                    await agent_a.initialize()
                    await agent_b.initialize()

                    # client A: the 60 s guest command, cancelled later
                    a_scope = anyio.CancelScope()

                    async def run_guest_command():
                        with a_scope:
                            await agent_a.call_tool(
                                "hyperv_guest_run_ps",
                                {"vm_name": vm, "script": GUEST_COMMAND},
                            )

                    async def screenshot():
                        # the fast call must not queue behind the slow one
                        started = time.monotonic()
                        result = await agent_b.call_tool(
                            "hyperv_console_screenshot",
                            {"vm_name": vm, "width": 320, "height": 240},
                        )
                        return time.monotonic() - started, result

                    async with anyio.create_task_group() as tg:
                        tg.start_soon(run_guest_command)
                        # let A's leg reach the guest before B's screenshot
                        await anyio.sleep(2.0)
                        screenshot_elapsed, result = await screenshot()
                        is_error = getattr(result, "is_error", None)
                        if is_error is None:
                            is_error = getattr(result, "isError", None)
                        assert not is_error, (
                            f"the screenshot failed while the guest command ran: {result}"
                        )
                        assert screenshot_elapsed < 10.0, (
                            f"the screenshot took {screenshot_elapsed:.1f}s — it queued "
                            "behind the in-flight guest command (FND-01)"
                        )
                        # cancel A's call the way an impatient client would
                        a_scope.cancel()
                    cancelled_settled = time.monotonic()

            # the host PowerShell tree of the cancelled leg must die promptly
            deadline = cancelled_settled + 5.0
            survivors = _descendant_pids(controller.pid, "powershell.exe")
            while survivors and time.monotonic() < deadline:
                time.sleep(0.2)
                survivors = _descendant_pids(controller.pid, "powershell.exe")
            assert survivors == [], (
                f"host powershell.exe descendants of the controller survived the cancelled call: {survivors}"
            )

        anyio.run(scenario)
    finally:
        controller.terminate()
        try:
            controller.wait(timeout=10)
        except subprocess.TimeoutExpired:
            controller.kill()
