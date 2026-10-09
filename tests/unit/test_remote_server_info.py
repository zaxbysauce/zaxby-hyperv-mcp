"""AC5 acceptance checks: hyperv_server_info names the Hyper-V target.

Contract:
  * payload["hyperv_target"] == {"mode": "remote", "host": "<name>"} when a
    hyperv.host is configured, {"mode": "local", "host": None} by default;
  * the startup banner gains a line containing "Hyper-V target:" naming
    local or the remote hostname.

Pattern: fresh_server importlib.reload + bootstrap with a tmp_path JSON
config via HYPERV_MCP_CONFIG (tests/unit/test_a04_vm_identity.py style).
The PowerShell provenance probe is stubbed offline; no real Hyper-V, no
network, no remote host.
"""

import asyncio
import importlib
import json

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows

HOST = "nuc01"


@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def _offline_ps(script, **kwargs):
    """Any provenance probe fails -> per-field fallbacks (never raises)."""
    return pswindows.PSResult(returncode=1, stderr="offline")


def _server_info_payload(mod) -> dict:
    result = asyncio.run(
        mod.get_mcp()._tool_manager.call_tool("hyperv_server_info", {}, context=None)
    )
    content = result.content if hasattr(result, "content") else result[0]
    texts = [b for b in content if getattr(b, "type", "") == "text"]
    assert texts, "expected a text block from hyperv_server_info"
    return json.loads(texts[0].text)


def test_remote_target_in_banner_and_payload(monkeypatch, tmp_path, fresh_server, capsys):
    doc = {"hyperv": {"host": HOST}}
    p = tmp_path / "remote.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})

    err = capsys.readouterr().err
    assert "Hyper-V target:" in err, "startup banner must name the Hyper-V target"
    assert HOST in err, "the banner must name the configured remote hostname"

    monkeypatch.setattr(pswindows, "run_ps", _offline_ps)
    payload = _server_info_payload(mod)
    assert payload["hyperv_target"] == {"mode": "remote", "host": HOST}


def test_local_target_default(monkeypatch, fresh_server, capsys):
    mod = fresh_server({})

    err = capsys.readouterr().err
    assert "Hyper-V target:" in err, "startup banner must name the Hyper-V target"

    monkeypatch.setattr(pswindows, "run_ps", _offline_ps)
    payload = _server_info_payload(mod)
    assert payload["hyperv_target"] == {"mode": "local", "host": None}
