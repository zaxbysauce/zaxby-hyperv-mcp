"""Acceptance checks for issue #16, part 2 — the SDK-generation port pins.

AC7 (pyproject declares mcp>=2.3,<3 and version 0.6.0), AC8 (bootstrapping
builds an mcp.server.mcpserver.MCPServer), AC9 (call_tool returns a
CallToolResult). Sibling c03 files: test_c03_tool_concurrency.py (AC1-AC5),
test_c03_http_entry.py (AC6, AC13), test_c03_tool_surface.py (AC10-AC12).

Every check is phrased against the fixed contract and must hold at both ends
of the fix: RED at the pre-fix base, GREEN after the fix. SDK object shapes
are asserted on via `type(x).__module__`/`__name__` only, so a base failure
is a clean assertion, never an import or collection error.
"""

import asyncio
import importlib
import json
import re
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows
from hyperv_mcp.pswindows import PSResult

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


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


def test_ac7_pyproject_declares_mcp2_and_version():
    """AC7: pyproject.toml declares exactly one mcp requirement
    `mcp>=2.3,<3` and version `0.6.0`."""
    try:
        import tomllib
    except ImportError:  # Python 3.10
        import tomli as tomllib

    data = tomllib.loads((Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]

    def req_name(dep: str) -> str:
        match = re.match(r"\s*([A-Za-z0-9_.\-]+)", dep)
        return match.group(1) if match else ""

    mcp_reqs = [d for d in deps if req_name(d) == "mcp"]
    assert mcp_reqs == ["mcp>=2.3,<3"], f"AC7: pyproject mcp requirement(s) {mcp_reqs!r} != ['mcp>=2.3,<3']"
    assert data["project"]["version"] == "0.6.0", (
        f"AC7: pyproject version {data['project']['version']!r} != '0.6.0'"
    )


def test_ac8_bootstrapped_server_is_mcpserver(fresh_server):
    """AC8: bootstrapping builds an mcp.server.mcpserver.MCPServer."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()
    module_name = type(mcp).__module__
    assert module_name.startswith("mcp.server.mcpserver"), (
        f"AC8: bootstrapped server object is "
        f"{module_name}.{type(mcp).__qualname__}; expected an "
        "mcp.server.mcpserver.* server"
    )


def test_ac9_call_tool_returns_calltoolresult(fresh_server, monkeypatch):
    """AC9: a registered tool called through call_tool returns a
    CallToolResult. get_vm_info's success path returns a plain dict from the
    tool body, so the SDK's call_tool return shape is what this pins."""
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    info_row = json.dumps(
        {
            "name": "c03-vm-a",
            "state": "Off",
            "status": "OK",
            "generation": 2,
            "memory_mb": 1024.0,
            "dynamic_memory": False,
            "cpu_count": 1,
            "uptime_seconds": 0.0,
            "checkpoint_count": 0,
            "com_ports": [],
            "network_adapters": [],
            "hard_drives": [],
        }
    )

    def fake_run_ps(script, **kwargs):
        if _is_resolution_leg(script):
            return PSResult(stdout=GUID, returncode=0)
        return PSResult(stdout=info_row, returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)
    result = asyncio.run(mod.get_mcp().call_tool("hyperv_get_vm_info", {"vm_name": "c03-vm-a"}))
    assert type(result).__name__ == "CallToolResult", (
        f"AC9: call_tool returned {type(result).__name__} "
        f"({type(result).__module__}); expected CallToolResult"
    )
