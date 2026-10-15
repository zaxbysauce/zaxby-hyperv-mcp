"""Acceptance checks for issue #16: tool calls stop serializing on the event loop.

Part 1 of the c03 check set — the concurrency behaviors themselves:
AC1 (overlap), AC2 (completion order), AC3 (loop responsiveness),
AC4 (cancellation kills the PowerShell child), AC5 (no busy for concurrent
same-VM job polls). Sibling files carry the rest of the ACs:
test_c03_sdk_port.py (AC7-AC9), test_c03_http_entry.py (AC6, AC13),
test_c03_tool_surface.py (AC10-AC12). AC14 (real host, two clients over
streamable-http) is INTEGRATION(hyperv_real) and intentionally has no test
here.

Every check is phrased against the fixed contract and must hold at both ends
of the fix: RED at the pre-fix base, GREEN after the fix. The timing model is
the Phase-2 probe (repro/probe_repro.py): fake `pswindows.run_ps` legs sleep
and record peak in-flight; the discriminating checks here fail at base with
clean assertions. No module of either mcp generation is imported at module
level so a base failure is an assertion, never a collection error.
"""

import asyncio
import importlib
import json
import os
import sys
import threading
import time

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import guestjobs, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.pswindows import PSResult

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

# Inlined recorder for AC4 (self-contained file: only the c03 check files and
# the dispatcher are copied into base worktrees). Written to tmp_path and run
# by the fake host_powershell_path .cmd shim; records {"pid","event","t"}
# jsonl lines to RECORDER_FILE, then sleeps SLEEP_S seconds and exits 0.
_RECORDER_SRC = (
    "import json\n"
    "import os\n"
    "import time\n"
    "\n"
    "with open(os.environ['RECORDER_FILE'], 'a', encoding='utf-8') as fh:\n"
    "    fh.write(json.dumps({'pid': os.getpid(), 'event': 'start',"
    " 't': time.time()}) + '\\n')\n"
    "    fh.flush()\n"
    "time.sleep(float(os.environ.get('SLEEP_S', '5')))\n"
    "with open(os.environ['RECORDER_FILE'], 'a', encoding='utf-8') as fh:\n"
    "    fh.write(json.dumps({'pid': os.getpid(), 'event': 'end',"
    " 't': time.time()}) + '\\n')\n"
    "    fh.flush()\n"
    "raise SystemExit(0)\n"
)


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


class FakeRunPs:
    """In-process run_ps stand-in (probe model).

    Classifies the leg by script content (get_vm_info's info leg carries
    `checkpoint_count`; everything else — the GUID resolver leg, list_vms —
    is a fast leg), sleeps, and records peak in-flight calls. Returns an
    empty successful result, or `guid` on resolution legs when given: the
    checks measure timing and overlap, not payloads.
    """

    def __init__(self, slow_s: float, fast_s: float, guid: str | None = None):
        self.slow_s = slow_s
        self.fast_s = fast_s
        self.guid = guid
        self.live = 0
        self.peak = 0
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, script: str, **kwargs) -> PSResult:
        slow = "checkpoint_count" in script
        with self._lock:
            self.calls += 1
            self.live += 1
            self.peak = max(self.peak, self.live)
        try:
            time.sleep(self.slow_s if slow else self.fast_s)
            if self.guid is not None and _is_resolution_leg(script):
                return PSResult(stdout=self.guid, returncode=0)
            return PSResult(stdout="", returncode=0)
        finally:
            with self._lock:
                self.live -= 1


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        SYNCHRONIZE = 0x00100000
        STILL_ACTIVE = 259
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(SYNCHRONIZE, False, pid)
        if not h:
            return False
        try:
            rc = ctypes.c_ulong(STILL_ACTIVE)
            k32.GetExitCodeProcess(h, ctypes.byref(rc))
            k32.CloseHandle(h)
            return rc.value == STILL_ACTIVE
        finally:
            pass
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_ac1_concurrent_get_vm_info_overlap(fresh_server, monkeypatch):
    """AC1: two hyperv_get_vm_info calls for different VMs issued together
    through call_tool run their PowerShell legs concurrently (peak == 2)."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    fake = FakeRunPs(slow_s=0.6, fast_s=0.6)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    async def main():
        return await asyncio.gather(
            mcp.call_tool("hyperv_get_vm_info", {"vm_name": "c03-vm-a"}),
            mcp.call_tool("hyperv_get_vm_info", {"vm_name": "c03-vm-b"}),
            return_exceptions=True,
        )

    results = asyncio.run(main())
    errors_ = [type(r).__name__ for r in results if isinstance(r, BaseException)]
    assert errors_ == [], f"AC1: unexpected exceptions from the two calls: {errors_}"
    assert fake.peak == 2, (
        f"AC1: peak concurrent run_ps legs was {fake.peak}, expected 2 "
        "(two concurrently issued tool calls must overlap their PowerShell legs)"
    )


def test_ac2_fast_list_vms_completes_first(fresh_server, monkeypatch):
    """AC2: a fast hyperv_list_vms issued 0.2 s after a slow (1.5 s info leg)
    hyperv_get_vm_info completes first (order == ["fast", "slow"])."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    # guid returned so the slow call reaches its 1.5 s info leg
    fake = FakeRunPs(slow_s=1.5, fast_s=0.1, guid=GUID)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    order: list[str] = []
    lock = threading.Lock()

    async def slow_call():
        await mcp.call_tool("hyperv_get_vm_info", {"vm_name": "c03-vm-a"})
        with lock:
            order.append("slow")

    async def fast_call():
        await mcp.call_tool("hyperv_list_vms", {})
        with lock:
            order.append("fast")

    async def main():
        slow_task = asyncio.create_task(slow_call())
        await asyncio.sleep(0.2)
        await asyncio.gather(slow_task, fast_call())

    asyncio.run(main())
    assert order == ["fast", "slow"], (
        f"AC2: completion order was {order}, expected ['fast', 'slow'] "
        "(a later fast call must overtake an in-flight slow one)"
    )


def test_ac3_event_loop_ticker_stays_responsive(fresh_server, monkeypatch):
    """AC3: a 1.0 s sync tool running while an asyncio task ticks every 50 ms
    keeps the event loop responsive (ticks >= 10)."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    fake = FakeRunPs(slow_s=1.0, fast_s=1.0)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    async def main():
        ticks = 0
        ticker_done = False

        async def ticker():
            nonlocal ticks
            while not ticker_done:
                await asyncio.sleep(0.05)
                ticks += 1

        task = asyncio.create_task(ticker())
        await mcp.call_tool("hyperv_list_vms", {})
        ticker_done = True
        await task
        return ticks

    ticks = asyncio.run(main())
    assert ticks >= 10, (
        f"AC3: event loop ticked {ticks} times during a 1.0 s tool call, "
        "expected >= 10 (the loop must stay responsive while a tool runs)"
    )


@pytest.mark.skipif(os.name != "nt", reason="AC4 needs the Windows .cmd shim + ctypes liveness")
def test_ac4_cancelled_call_kills_child_promptly(tmp_path, monkeypatch, fresh_server):
    """AC4: an in-flight hyperv_get_vm_info whose real PowerShell child would
    run 5 s, cancelled through an anyio CancelScope at 0.5 s, settles as
    cancelled within 1.5 s and leaves the child dead."""
    import anyio

    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    saved_run_ps = pswindows.run_ps
    saved_ps_path = pswindows._ps_path
    workdir = tmp_path / "ac4"
    workdir.mkdir()
    recorder_py = workdir / "fake_ps_recorder.py"
    recorder_py.write_text(_RECORDER_SRC, encoding="utf-8")
    shim = workdir / "fake_ps.cmd"
    shim.write_text(f'@echo off\r\n"{sys.executable}" "{recorder_py}"\r\n', encoding="utf-8")
    events = workdir / "events.jsonl"
    monkeypatch.setenv("RECORDER_FILE", str(events))
    monkeypatch.setenv("SLEEP_S", "5")
    # re-init AFTER bootstrap so the REAL run_ps spawns through the shim
    pswindows.init(
        Config(host_powershell_path=str(shim), unrestricted=True),
        redact_fn=lambda s: s,
    )
    mcp = mod.get_mcp()
    outcome: dict = {}
    try:

        async def main():
            started = time.monotonic()
            with anyio.CancelScope() as scope:

                async def canceller():
                    await anyio.sleep(0.5)
                    scope.cancel()

                tg_cancel = asyncio.ensure_future(canceller())
                try:
                    await mcp.call_tool("hyperv_get_vm_info", {"vm_name": "c03-vm-a"})
                finally:
                    tg_cancel.cancel()
            outcome["elapsed"] = time.monotonic() - started
            outcome["cancelled_caught"] = scope.cancelled_caught

        asyncio.run(main())
        time.sleep(0.3)
        pids = []
        if events.exists():
            for line in events.read_text(encoding="utf-8").splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("event") == "start":
                    pids.append(rec["pid"])
        cancelled = bool(outcome.get("cancelled_caught"))
        elapsed = float(outcome.get("elapsed", -1.0))
        assert (cancelled, elapsed < 1.5) == (True, True), (
            f"AC4: cancelled_caught={cancelled}, elapsed={elapsed:.2f}s; a "
            "cancelled tool call must settle as cancelled within 1.5 s"
        )
        alive = [pid for pid in pids if _alive(pid)]
        assert alive == [], f"AC4: recorded child pids {pids} — still alive: {alive}"
    finally:
        pswindows.run_ps = saved_run_ps
        pswindows._ps_path = saved_ps_path


def test_ac5_same_vm_job_status_polls_without_busy(fresh_server, monkeypatch):
    """AC5: two agents polling their own jobs on the same VM concurrently
    (hyperv_guest_job_status x2) are both answered without `busy`."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    # seed a real job entry so the status path runs the per-VM read lock
    guestjobs.clear_registry_for_tests()
    guestjobs._register(
        {
            "job_id": "c03-job",
            "vm_name": "c03-vm",
            "vm_id": GUID,
            "pid": 4242,
            "in_flight": False,
            "owner": None,
            "started_at": "2026-10-14T00:00:00+00:00",
            "cred": CredentialSet("tester", "dummy-password"),
            "stopped": False,
            "exit_path": r"C:\fake\exit.txt",
            "start_time_ticks": None,
        }
    )
    try:
        status_json = '{"status": "running", "process_name": "fake.exe"}'

        def fake_run_ps(script, **kwargs):
            time.sleep(0.6)
            return PSResult(stdout=status_json, returncode=0)

        monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)
        mcp = mod.get_mcp()

        async def main():
            return await asyncio.gather(
                mcp.call_tool("hyperv_guest_job_status", {"job_id": "c03-job"}),
                mcp.call_tool("hyperv_guest_job_status", {"job_id": "c03-job"}),
                return_exceptions=True,
            )

        results = asyncio.run(main())
        errors_ = [type(r).__name__ for r in results if isinstance(r, BaseException)]
        assert errors_ == [], f"AC5: unexpected exceptions from the two polls: {errors_}"
        assert "busy" not in repr(results).lower(), (
            f"AC5: a busy envelope surfaced for same-VM polls: {repr(results)[:300]}"
        )
    finally:
        guestjobs.clear_registry_for_tests()
