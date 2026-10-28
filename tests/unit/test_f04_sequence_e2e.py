"""End-to-end server-layer tests for hyperv_console_sequence (review round
pr107-20261027: PRR-002 + NEW-1). The frozen suite pins the module contract;
this file drives the TOOL through mcp.call_tool so the registration plumbing
(policy gate, argument passing, lease scope, ok:false envelope enrichment) is
exercised, and pins the vm_id-only addressing shape (PRR-001) and the console
lease scope (NEW-1) that the schema-only pins could not see.

Transport: folded PowerShell (conftest pins COM_AVAILABLE False); run_ps
stubbed; nothing touches a real host. GREEN at the feedback head; the
vm_id-only test is RED at the pre-fix head by construction (the call raised
ValueError before any transport work)."""

import asyncio
import importlib
import json

from hyperv_mcp import pswindows

E2E_GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


class E2EPS:
    """Serves the by-id resolution leg and a folded success."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Get-VM -Id" in script:
            return pswindows.PSResult(stdout="e2e-vm", returncode=0)
        return pswindows.PSResult(
            stdout="VMID=" + E2E_GUID + "\nEPOCH=55\n", returncode=0)


def _tool_result(mod, arguments: dict):
    mcp = mod.get_mcp()
    result = asyncio.run(mcp.call_tool("hyperv_console_sequence", arguments))
    content = result if isinstance(result, list) else getattr(result, "content", result)
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    text_blocks = [c for c in content or [] if getattr(c, "type", "") == "text"]
    assert text_blocks, f"no text content in result: {content}"
    return json.loads(text_blocks[0].text)


def test_sequence_tool_vm_id_only_end_to_end(tmp_path, monkeypatch):
    """PRR-001/PRR-002: the tool accepts vm_id-only addressing through the
    server layer (the #8 both-forms contract at the MCP boundary). RED at the
    pre-fix head (ValueError -> invalid envelope); GREEN after the fix."""
    import hyperv_mcp.server as server_module

    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({
        "unrestricted": True,
        "audit_log_path": str(tmp_path / "audit.jsonl"),
    }), encoding="utf-8")
    mod = importlib.reload(server_module)
    try:
        mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_file)})
        stub = E2EPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        out = _tool_result(mod, {
            "steps": [{"action": "press_key", "key": "enter"}],
            "vm_id": E2E_GUID,
        })
        assert out.get("ok") is True, out
        assert out.get("vm_name") == "e2e-vm"
        assert out["steps"][0]["ok"] is True
    finally:
        importlib.reload(server_module)


def test_sequence_tool_in_console_lease_scope():
    """NEW-1: hyperv_console_sequence maps to the console lease scope so an
    exclusive console lease conflicts with it (and leases.required gates it
    like every sibling input tool)."""
    from hyperv_mcp.server import TOOL_SCOPES

    assert TOOL_SCOPES.get("hyperv_console_sequence") == "console"


def test_sequence_tool_policy_denial_is_invalid_envelope(tmp_path, monkeypatch):
    """A policy denial through the server layer returns a structured policy
    envelope (not a raised exception) with no PowerShell started. The config
    allows the VM name but leaves console_input disabled, so the category
    gate is the axis that fires."""
    import hyperv_mcp.server as server_module

    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({
        "allowed_vm_patterns": ["*"],
        "audit_log_path": str(tmp_path / "audit.jsonl"),
    }), encoding="utf-8")
    mod = importlib.reload(server_module)
    try:
        mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_file)})
        stub = E2EPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        out = _tool_result(mod, {
            "steps": [{"action": "press_key", "key": "enter"}],
            "vm_name": "any-vm",
        })
        assert out.get("ok") is False
        assert out.get("error_class") == "policy", out
        assert "console_input" in out.get("error", "")
        assert stub.scripts == [], "a denied sequence must spawn nothing"
    finally:
        importlib.reload(server_module)
