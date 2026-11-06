"""Issue #68 (wave 59-64-68-70-hardening) — tool-limiter admission + restore.

mcp 2.x runs every sync tool on a worker thread via anyio.to_thread.run_sync
drawing from the DEFAULT thread limiter. The server resizes it to 2 x
max_host_powershell for the server run; the wave pins:

  W3.1  the documented PS-free admission bound under VM-lock saturation: 1
        lock holder + 15 lock-queued calls occupy every 2 x cap token for up
        to vm_lock_wait_s (30 s default), so PS-free admission is delayed up
        to that bound; the delay is measured here against a short configured
        wait and the bound is documented in the README concurrency section
        (the literals `lock-queued` and `vm_lock_wait_s` on one line).
  W3.2  the lifespan restores the captured prior token count on exit (the
        captured-prior value, never a hardcoded constant).
  W3.3  (repro/run_full_unit_suite.sh) the full unit suite stays green.

All legs are deterministic; the RED signature at base is the file itself
(pytest exit 4, NEW-SURFACE); the behavioral tests FAIL on the pre-fix tree
for the named reasons.
"""

import asyncio
import importlib
import json
import threading
import time
from pathlib import Path

import anyio
import pytest

import hyperv_mcp.server as server_module

README_PATH = Path(__file__).resolve().parents[2] / "README.md"

_LOCK_KEY = ("g-limiter-test-0000-0000-0000-000000000001",)


@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def test_limiter_restored_on_lifespan_exit(fresh_server):
    """Exiting the server lifespan restores the CAPTURED PRIOR default-limiter
    token count (W3.2): a mutant that restores a hardcoded value instead of
    the captured prior fails this test (sentinel = 99)."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    async def main():
        limiter = anyio.to_thread.current_default_thread_limiter()
        limiter.total_tokens = 99  # sentinel prior, deliberately not 40
        async with mcp.settings.lifespan(mcp):
            assert limiter.total_tokens == 2 * mod.CFG.max_host_powershell
        assert limiter.total_tokens == 99, (
            "lifespan exit must restore the captured prior token count"
        )

    asyncio.run(main())


def test_psfree_admission_bounded_under_real_lock_saturation(fresh_server, tmp_path):
    """1 lock holder + 15 lock-queued calls occupy every 2 x cap token (real
    vm_lock, short configured wait); a PS-free call queues and is admitted
    within a bounded window once the holder releases (W3.1 measured bound)."""
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(
        json.dumps({"unrestricted": True, "vm_lock_wait_s": 4}), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_path)})
    mcp = mod.get_mcp()
    from hyperv_mcp import vmlocks

    total = 2 * mod.CFG.max_host_powershell  # 16 at defaults
    holder_go = threading.Event()

    def _holder_body():
        with vmlocks.vm_lock(_LOCK_KEY, mode="write"):
            holder_go.wait(timeout=30)

    timeouts = {"n": 0}
    tlock = threading.Lock()

    def _queued_body():
        try:
            with vmlocks.vm_lock(_LOCK_KEY, mode="write"):
                pass  # acquires then releases immediately once drained
        except vmlocks.VMBusy:
            with tlock:
                timeouts["n"] += 1  # the configured-wait timeout IS the bound

    async def main():
        async with mcp.settings.lifespan(mcp):

            async def _worker(fn):
                await anyio.to_thread.run_sync(fn)

            async with anyio.create_task_group() as tg:
                # Token 1: the holder parks INSIDE the write lock. Tokens
                # 2..16: fifteen lock-queued workers. Together they occupy
                # every token the limiter has.
                tg.start_soon(_worker, _holder_body)
                for _ in range(total - 1):
                    tg.start_soon(_worker, _queued_body)

                deadline = time.monotonic() + 10
                while True:
                    lock = vmlocks._locks.get(_LOCK_KEY)
                    held = lock is not None and lock._writer is not None
                    queued = getattr(lock, "_waiting_writers", 0) if lock else 0
                    if held and queued >= total - 1:
                        break
                    if time.monotonic() > deadline:
                        raise AssertionError(
                            f"choreography stalled: held={held} queued={queued}")
                    await asyncio.sleep(0.01)

                psfree_done = asyncio.Event()

                async def _psfree():
                    await anyio.to_thread.run_sync(lambda: None)
                    psfree_done.set()

                tg.start_soon(_psfree)  # token 17: must queue
                enqueue_wall = time.monotonic()
                await asyncio.sleep(0.3)
                assert not psfree_done.is_set(), (
                    "PS-free call was admitted while every token was parked"
                )
                # The holder stays parked THROUGH the queued workers'
                # configured timeout (round-2 challenge 4): the workers time
                # out at vm_lock_wait_s raising VMBusy, tokens free, and the
                # PS-free call is admitted - the measured bound is the
                # documented vm_lock_wait_s worst case plus scheduling slack,
                # measured from PS-free ENQUEUE.
                wait_s = mod.CFG.vm_lock_wait_s
                try:
                    await asyncio.wait_for(psfree_done.wait(), timeout=wait_s + 5)
                    delay = time.monotonic() - enqueue_wall
                    assert delay >= wait_s - 0.5, (
                        f"PS-free admitted at {delay:.2f}s, earlier than the "
                        f"documented vm_lock_wait_s bound ({wait_s}s) allows"
                    )
                    assert delay <= wait_s + 5.0, (
                        f"PS-free admission took {delay:.2f}s; the documented "
                        f"bound is vm_lock_wait_s ({wait_s}s) + slack"
                    )
                    # Deterministic accounting: the holder stays parked until
                    # EVERY queued worker has timed out at the configured
                    # bound (a worker can never drain-success, because the
                    # holder is released only after all timeouts are
                    # counted), then cleanup releases it.
                    deadline = time.monotonic() + wait_s + 5
                    while timeouts["n"] < total - 1:
                        if time.monotonic() > deadline:
                            raise AssertionError(
                                f"only {timeouts['n']}/{total - 1} workers "
                                "timed out at vm_lock_wait_s")
                        await asyncio.sleep(0.05)
                finally:
                    holder_go.set()  # cleanup: release the parked holder
                    await asyncio.sleep(0.05)

    asyncio.run(main())
    assert timeouts["n"] == total - 1, (
        f"expected the {total - 1} queued workers to time out at "
        f"vm_lock_wait_s; counted {timeouts['n']}"
    )


def test_embedder_path_keeps_default_40(fresh_server):
    """Without entering the lifespan, the default limiter keeps anyio's
    40 tokens (the documented embedder-path caveat; pinned so the restore
    change can never silently rebind it)."""
    fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})

    async def main():
        assert anyio.to_thread.current_default_thread_limiter().total_tokens == 40

    asyncio.run(main())


def test_readme_documents_the_admission_bound():
    """The README concurrency section documents the PS-free bound: one line
    carries both `lock-queued` and `vm_lock_wait_s` (W3.1 documented-bound
    branch; RED until the README sentence lands)."""
    lines = README_PATH.read_text(encoding="utf-8").splitlines()
    hits = [ln for ln in lines if "lock-queued" in ln and "vm_lock_wait_s" in ln]
    assert hits, (
        "README must document the PS-free admission bound: a line carrying "
        "both 'lock-queued' and 'vm_lock_wait_s'"
    )
