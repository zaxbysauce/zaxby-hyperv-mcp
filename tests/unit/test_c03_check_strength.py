"""Strength pins for the frozen c03 acceptance checks (issue #16).

The four frozen c03 files ship byte-identical (they are checkpoint-anchored),
so the gaps the swarm-pr-review found in them cannot be closed by editing
them. This non-frozen companion pins the same scenarios with the missing
preconditions:

- AC4's child-death half: the frozen check asserts no recorded child is
  alive, which is trivially true when the recorder never ran. Here the
  recorded-child precondition is asserted first, and the kill is verified
  against a child that provably existed.
- AC5's busy oracle: the frozen check asserts only "busy" not in the
  results; here the seeded job's status is asserted to actually come back,
  so the read-lock path is proven to have run (an early-return error
  envelope fails here).
- AC9's CallToolResult oracle: the frozen check asserts the result type
  name only; here the module and the success flag are pinned too, so an
  error envelope cannot satisfy it.
"""

import asyncio
import importlib
import json
import os
import sys
import time

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import guestjobs, pswindows
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.pswindows import PSResult

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

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


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        SYNCHRONIZE = 0x00100000
        STILL_ACTIVE = 259
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k32.OpenProcess(SYNCHRONIZE, False, pid)
        if not h:
            return False
        try:
            rc = ctypes.c_ulong(STILL_ACTIVE)
            k32.GetExitCodeProcess(h, ctypes.byref(rc))
            return rc.value == STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


@pytest.mark.skipif(os.name != "nt", reason="AC4 strength pin needs the Windows .cmd shim")
def test_ac4_child_death_is_proven_not_assumed(tmp_path, fresh_server):
    """AC4 strength: the cancelled call's child provably existed before it
    was killed. The frozen check's `alive == []` is trivially true when the
    recorder never spawned; here the recorded-child precondition fails
    loudly when the shim plumbing breaks, and the kill is verified against
    a child that was observed alive mid-flight."""
    import anyio

    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    saved_run_ps = pswindows.run_ps
    saved_ps_path = pswindows._ps_path
    workdir = tmp_path / "ac4p"
    workdir.mkdir()
    recorder_py = workdir / "fake_ps_recorder.py"
    recorder_py.write_text(_RECORDER_SRC, encoding="utf-8")
    shim = workdir / "fake_ps.cmd"
    shim.write_bytes(f'@echo off\r\n"{sys.executable}" "{recorder_py}"\r\n'.encode())
    events = workdir / "events.jsonl"
    os.environ["RECORDER_FILE"] = str(events)
    os.environ["SLEEP_S"] = "5"
    pswindows.init(
        __import__("hyperv_mcp.config", fromlist=["Config"]).Config(
            host_powershell_path=str(shim), unrestricted=True
        ),
        redact_fn=lambda s: s,
    )
    mcp = mod.get_mcp()
    try:
        async def main():
            with anyio.CancelScope() as scope:
                async def canceller():
                    await anyio.sleep(0.5)
                    scope.cancel()

                tg_cancel = asyncio.ensure_future(canceller())
                try:
                    await mcp.call_tool("hyperv_get_vm_info", {"vm_name": "c03-vm-a"})
                finally:
                    tg_cancel.cancel()
            return scope.cancelled_caught

        cancelled = asyncio.run(main())
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
        # The precondition the frozen check lacks: a child must have been
        # recorded, or every assertion below is vacuous.
        assert pids, (
            "the fake-PowerShell child was never recorded — the shim plumbing "
            "is broken, so the frozen AC4 child-death assertion would pass "
            "vacuously"
        )
        assert cancelled, "the cancelled call must settle as cancelled"
        alive = [pid for pid in pids if _alive(pid)]
        assert alive == [], f"the cancelled call left children alive: {alive}"
    finally:
        pswindows.run_ps = saved_run_ps
        pswindows._ps_path = saved_ps_path


def test_ac5_job_status_returns_the_seeded_job(fresh_server, monkeypatch):
    """AC5 strength: two concurrent same-VM job polls return the seeded
    job's status. The frozen check asserts only the absence of "busy"; an
    early-return error envelope (unknown job, skipped lock) would satisfy
    it, so the seeded status is pinned here to prove the read-lock path
    actually ran."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
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
        assert errors_ == [], f"unexpected exceptions from the two polls: {errors_}"
        assert "busy" not in repr(results).lower()
        # The seeded job's status must actually come back from both polls.
        for r in results:
            content = getattr(r, "content", None)
            if content is None and isinstance(r, tuple):
                content = r[0]
            texts = [
                getattr(b, "text", "")
                for b in (content or [])
                if getattr(b, "type", "") == "text"
            ]
            assert texts, f"no text block in a poll result: {r!r}"
            payload = json.loads(texts[0])
            assert payload.get("status") == "running", (
                f"a poll did not return the seeded job's status: {payload!r}"
            )
    finally:
        guestjobs.clear_registry_for_tests()


def test_ac9_calltoolresult_is_mcp_types_and_success(fresh_server, monkeypatch):
    """AC9 strength: call_tool returns an mcp.types.CallToolResult for a
    SUCCEEDING tool. The frozen check asserts the type name only, which an
    error envelope also satisfies; here the module and the success flag are
    pinned."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    monkeypatch.setattr(
        pswindows, "run_ps", lambda script, **kw: PSResult(stdout="", returncode=0)
    )
    mcp = mod.get_mcp()
    result = asyncio.run(mcp.call_tool("hyperv_list_vms", {}))
    assert type(result).__name__ == "CallToolResult"
    assert type(result).__module__.startswith("mcp"), (
        f"the result type is {type(result).__module__}.{type(result).__name__}, "
        "not an mcp.types model"
    )
    is_error = getattr(result, "is_error", None)
    if is_error is None:
        is_error = getattr(result, "isError", None)
    assert not is_error, f"the pinned vehicle must succeed, got {result!r}"


def test_cancelled_while_parked_on_the_vm_lock_settles_promptly(tmp_path, fresh_server, monkeypatch):
    """PRR-005 pin: a call cancelled while QUEUED on the per-VM write lock
    settles within one cancellation-observation slice, not at the lock-wait
    expiry. The frozen checks and the transport test only cancel calls that
    are already inside a PowerShell leg; this pins the parked path the
    vmlocks slice-wait fix added."""
    import anyio

    doc = {"unrestricted": True, "vm_lock_wait_s": 30}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    mcp = mod.get_mcp()

    def fake_run_ps(script, **kwargs):
        # The by-name resolver leg must succeed (a GUID) so the call reaches
        # the write lock; the stop leg then holds the lock for 3 s.
        if script.rstrip().endswith("$vmTarget"):
            time.sleep(0.1)
            return PSResult(stdout=GUID, returncode=0)
        time.sleep(3.0)
        return PSResult(stdout="", returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)

    async def main():
        # A resolves, takes the write lock and holds it across its 3 s leg.
        a = asyncio.create_task(
            mcp.call_tool(
                "hyperv_stop_vm",
                {"vm_name": "c03-vm", "method": "shutdown", "confirm": True},
            )
        )
        await anyio.sleep(0.3)
        # B resolves and parks on the same VM's write lock; cancel it
        # mid-wait (A still holds for ~2.8 s more).
        b_started = time.monotonic()
        with anyio.move_on_after(0.4):
            await mcp.call_tool(
                "hyperv_stop_vm",
                {"vm_name": "c03-vm", "method": "shutdown", "confirm": True},
            )
        b_settled = time.monotonic() - b_started
        await a
        return b_settled

    b_settled = asyncio.run(main())
    assert b_settled < 2.0, (
        f"a call cancelled while parked on the VM lock settled after "
        f"{b_settled:.2f}s; without the slice-wait cancellation poll it "
        "sits out the holder's leg plus its own"
    )
