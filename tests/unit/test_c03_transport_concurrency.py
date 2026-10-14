"""Transport-level concurrency over streamable-http (issue #16).

The frozen c03 checks drive the server object in process; this file drives
the REAL transport: the actual server app served by uvicorn on loopback,
two independent MCP client sessions over HTTP, and in-process faked
PowerShell legs that observe anyio cancellation exactly the way PR #61's
run_ps does. It pins the transport-level half of AC14 without a real VM:

  1. two clients are served CONCURRENTLY — a fast call issued while a slow
     one is in flight completes first (the FND-01 fix over the wire, not
     just in process);
  2. a client-side cancellation crosses the HTTP transport into the
     server's worker thread, settles the call promptly, kills the
     PowerShell leg, and releases the per-VM lock (FND-13 over the wire).
"""

import asyncio
import importlib
import socket
import threading
import time

import anyio
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import hyperv_mcp.http_entry as http_entry
import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows

TOKEN = "c03-transport-token"

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


class _StaticTokenVerifier(http_entry.TokenVerifier):
    def __init__(self, token: str):
        self._token = token

    async def verify_token(self, token: str):
        if token and token == self._token:
            return http_entry.AccessToken(token=token, client_id="test-client", scopes=[])
        return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_listening(port: int, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


class _Server:
    """The real server app served over streamable-http on loopback."""

    def __init__(self):
        self.port = _free_port()
        self.server = None
        self.thread = None

    def start(self):
        importlib.reload(server_module)
        server_module.configure_http_auth(_StaticTokenVerifier(TOKEN))
        server_module.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
        mcp = server_module.get_mcp()
        self.server = uvicorn.Server(
            uvicorn.Config(
                mcp.streamable_http_app(),
                host="127.0.0.1",
                port=self.port,
                log_level="warning",
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        assert _wait_listening(self.port), "server did not listen"
        return self

    def stop(self):
        if self.server is not None:
            self.server.should_exit = True
            self.thread.join(timeout=10)
        importlib.reload(server_module)


class _FakeLegs:
    """run_ps stand-in with cancellation-observing sleeps.

    get_vm_info's info leg (script carries `checkpoint_count`) sleeps
    `slow_s`; every other leg sleeps `fast_s` and, for the by-name resolver
    leg, returns a GUID so the info leg is reached. Each sleep slice calls
    pswindows._check_ps_cancellation() — the exact hook PR #61's run_ps
    uses — so a cancelled server-side worker raises inside the fake and the
    observation is recorded.
    """

    def __init__(self, slow_s: float, fast_s: float):
        self.slow_s = slow_s
        self.fast_s = fast_s
        self.cancellation_observed = False
        self.legs = 0
        self._lock = threading.Lock()

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        slow = "checkpoint_count" in script
        is_resolver = script.rstrip().endswith("$vmTarget")
        budget = self.slow_s if slow else self.fast_s
        with self._lock:
            self.legs += 1
        deadline = time.monotonic() + budget
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.1, remaining))
                pswindows._check_ps_cancellation()
        except asyncio.CancelledError:
            # anyio's from_thread.check_cancelled raises the backend's
            # CancelledError (asyncio's) inside the worker; get_cancelled_exc_class()
            # cannot be called from a worker thread (no event loop there).
            with self._lock:
                self.cancellation_observed = True
            raise
        if is_resolver:
            return pswindows.PSResult(stdout=GUID, returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)


@pytest.fixture()
def served_server(monkeypatch):
    fake = _FakeLegs(slow_s=1.5, fast_s=0.2)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    server = _Server().start()
    try:
        yield server, fake
    finally:
        server.stop()


def _client(url: str):
    import httpx2

    headers = {"Authorization": f"Bearer {TOKEN}"}
    return streamable_http_client(
        url, http_client=httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0))
    )


def test_two_clients_are_served_concurrently(served_server):
    """A fast call issued 0.2 s after a slow one on a DIFFERENT client
    session completes first over the real transport."""
    server, _fake = served_server
    url = f"http://127.0.0.1:{server.port}/mcp"
    order: list[str] = []

    async def main():
        async with _client(url) as (r1, w1), _client(url) as (r2, w2):
            async with ClientSession(r1, w1) as slow_client, ClientSession(r2, w2) as fast_client:
                await slow_client.initialize()
                await fast_client.initialize()

                async def slow_call():
                    await slow_client.call_tool("hyperv_get_vm_info", {"vm_name": "c03-tp-a"})
                    order.append("slow")

                async def fast_call():
                    await asyncio.sleep(0.2)
                    await fast_client.call_tool("hyperv_list_vms", {})
                    order.append("fast")

                await asyncio.gather(slow_call(), fast_call())

    asyncio.run(main())
    assert order == ["fast", "slow"], (
        f"the fast call must overtake the in-flight slow one across sessions; got {order}"
    )


def test_client_cancellation_reaches_the_worker_and_frees_the_lock(served_server):
    """Cancelling a client call settles it promptly, the server-side worker
    observes the cancellation (the PowerShell leg dies), and the per-VM lock
    is not stranded: a follow-up call on the same VM completes."""
    server, fake = served_server
    url = f"http://127.0.0.1:{server.port}/mcp"

    async def main():
        async with _client(url) as (r, w):
            async with ClientSession(r, w) as client:
                await client.initialize()
                started = time.monotonic()
                with anyio.move_on_after(0.5):
                    await client.call_tool("hyperv_get_vm_info", {"vm_name": "c03-tp-a"})
                elapsed = time.monotonic() - started
                # the lock must be free: a same-VM read completes promptly
                follow_up_started = time.monotonic()
                await client.call_tool("hyperv_get_vm_info", {"vm_name": "c03-tp-a"})
                follow_up_elapsed = time.monotonic() - follow_up_started
                return elapsed, follow_up_elapsed

    elapsed, follow_up_elapsed = asyncio.run(main())
    assert elapsed < 1.5, f"the cancelled call must settle promptly; took {elapsed:.2f}s"
    assert fake.cancellation_observed, (
        "the server-side worker must observe the client's cancellation "
        "(the PowerShell leg dies through PR #61's check_cancelled hook)"
    )
    assert follow_up_elapsed < 2.0, (
        f"the per-VM lock must not be stranded by the cancelled call; "
        f"the follow-up took {follow_up_elapsed:.2f}s"
    )
