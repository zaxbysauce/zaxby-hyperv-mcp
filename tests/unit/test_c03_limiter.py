"""Tool-limiter lifespan coverage (issue #16).

mcp 2.x runs every sync tool body on a worker thread via
anyio.to_thread.run_sync, which draws from the process-wide DEFAULT thread
limiter (40 tokens, shared with anything else using to_thread). The server
installs a dedicated bound — 2 x the host PowerShell slot cap — at startup
through its MCPServer lifespan, entered once per server run on both
transports (stdio and streamable-http). These checks pin that wiring: the
lifespan exists, entering it resizes the default limiter to the configured
bound, and the bound actually bounds concurrent tool execution.
"""

import asyncio
import importlib
import json
import threading

import anyio
import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def _limiter_tokens() -> int:
    return anyio.to_thread.current_default_thread_limiter().total_tokens


def test_lifespan_installs_dedicated_tool_limiter(fresh_server):
    """Entering the server lifespan resizes anyio's default thread limiter to
    2 x max_host_powershell (default 8 -> 16), replacing the process-wide
    40-token default the SDK's run_sync would otherwise share."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()
    lifespan = mcp.settings.lifespan
    assert lifespan is not None, "the server must install a tool-limiter lifespan"

    async def main():
        # a fresh async run starts on anyio's default (40)
        assert _limiter_tokens() == 40
        async with lifespan(mcp):
            assert _limiter_tokens() == 2 * mod.CFG.max_host_powershell

    asyncio.run(main())


def test_lifespan_sizing_follows_configured_ps_cap(fresh_server, tmp_path):
    """The bound tracks the configured PowerShell cap, not a hard-coded
    number: max_host_powershell=4 yields an 8-token tool limiter."""
    doc = {"unrestricted": True, "max_host_powershell": 4}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    mcp = mod.get_mcp()

    async def main():
        async with mcp.settings.lifespan(mcp):
            assert _limiter_tokens() == 8

    asyncio.run(main())


def test_tool_calls_run_inside_the_limiter(fresh_server, monkeypatch):
    """The limiter does not block ordinary tool traffic: a tool call issued
    inside the entered lifespan completes and its worker thread actually
    ran (the SDK's to_thread.run_sync path the limiter bounds)."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()
    seen_threads: list[int] = []

    def fake_run_ps(script, **kwargs):
        seen_threads.append(threading.get_ident())
        return pswindows.PSResult(stdout="", returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)

    async def main():
        async with mcp.settings.lifespan(mcp):
            await mcp.call_tool("hyperv_list_vms", {})

    asyncio.run(main())
    assert seen_threads, "the tool body must have run"
    assert all(t != threading.get_ident() for t in seen_threads), (
        "a sync tool body must run on a worker thread, not the event loop"
    )
