"""Issue #9 Phase 4.2 guardrails: the shared error taxonomy and the
CallToolResult delivery preconditions.

Pins the contract that the frozen acceptance checks (test_a05_error_envelope)
exercise end-to-end, at unit level, so a regression is diagnosed here first:

- errors.classify ordering (MediaError -> "invalid" DESPITE RuntimeError —
  the PRR-020 shipped contract and a documented divergence from the issue's
  taxonomy sketch; TimeoutError -> "timeout" DESPITE OSError parenting;
  unknown exceptions -> "transport" so envelope and audit can never
  disagree);
- retry_fields (busy True/2000; everything else False/None);
- the structural output-schema census: every registered tool's func_metadata
  must have NO output model. Bare `-> CallToolResult` annotations guarantee
  that; a future annotation or SDK change that reintroduces a wrapped output
  model would silently reject envelope deliveries on some interpreters
  (plan-critic round-1 finding 1) — this census fails loudly instead.
"""

import importlib
import json

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import errors
from hyperv_mcp.console import ConsoleError
from hyperv_mcp.credentials import CredentialError
from hyperv_mcp.media import MediaError
from hyperv_mcp.policy import PolicyDenied
from hyperv_mcp.vmlocks import VMBusy


class UnknownFault(RuntimeError):
    """An unmapped subclass: must classify as transport, never verbatim."""


def test_classify_most_specific_first():
    assert errors.classify(PolicyDenied("vm", "denied")) == "policy"
    assert errors.classify(CredentialError("no creds")) == "credential"
    assert errors.classify(VMBusy("busy")) == "busy"
    assert errors.classify(ValueError("bad input")) == "invalid"
    assert errors.classify(TimeoutError("timed out")) == "timeout"
    assert errors.classify(ConsoleError("wmi down")) == "transport"
    # MediaError -> "invalid" (PRR-020), a documented divergence from the
    # issue's taxonomy sketch which would have put it under transport.
    assert errors.classify(MediaError("missing iso")) == "invalid"
    # PowerShellTransportError and any other RuntimeError -> transport.
    assert errors.classify(UnknownFault("mystery")) == "transport"
    # Non-RuntimeError escapees (the old ladders let these raise raw).
    assert errors.classify(KeyError("boom")) == "transport"
    assert errors.classify(OSError("disk full")) == "transport"


def test_retry_fields_busy_only():
    retryable, after = errors.retry_fields("busy")
    assert (retryable, after) == (True, errors.BUSY_RETRY_MS)
    assert errors.BUSY_RETRY_MS == 2000  # pinned: the documented ~2s hint
    for cls in ("policy", "credential", "invalid", "timeout", "transport"):
        retryable, after = errors.retry_fields(cls)
        assert (retryable, after) == (False, None), cls


def test_envelope_shape_and_audit_agreement(tmp_path):
    """envelope() uses classify(), and auditlog uses the same function —
    captured here as the unit-level half of the C6 agreement check."""
    audit = tmp_path / "audit.jsonl"
    from hyperv_mcp import auditlog
    from hyperv_mcp.config import Config

    auditlog.init(Config(audit_log_path=str(audit)))
    try:
        op = auditlog.operation(tool="probe", vm_name="v", category="read")
        with pytest.raises(ConsoleError):
            with op:
                op.ok = False
                raise ConsoleError("wmi down")
        env = errors.envelope(ConsoleError("wmi down"))
        assert env["error_class"] == "transport"
        assert env["retryable"] is False and env["retry_after_ms"] is None
        rec = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
        assert rec["error_class"] == env["error_class"], (
            "audit error_class must equal the envelope's for the same fault"
        )
    finally:
        auditlog._config = None


def test_enrich_failure_keeps_module_classes_and_adds_retry():
    out = errors.enrich_failure({"ok": False, "error": "e", "error_class": "timeout"})
    assert out["error_class"] == "timeout"
    assert (out["retryable"], out["retry_after_ms"]) == (False, None)
    out2 = errors.enrich_failure({"ok": False, "error": "e", "timed_out": True})
    assert out2["error_class"] == "transport"  # default when the module omits it
    assert out2["timed_out"] is True  # module diagnostics ride along


def test_unknown_argument_audited_once(monkeypatch, tmp_path):
    """The guard is the only audit for a rejected call (it runs before any
    tool body's audit region), so 'every failure audited once' rests on its
    single log_operation line — deleting it must fail here (implementation
    review round 1, finding 2)."""
    import asyncio
    import json as _json

    audit = tmp_path / "audit.jsonl"
    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True,
           "audit_log_path": str(audit)}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    mcp = mod.get_mcp()

    def fake_list(cfg):
        raise AssertionError("tool body must not run for an unknown argument")

    monkeypatch.setattr("hyperv_mcp.lifecycle.list_vms", fake_list)
    asyncio.run(mcp.call_tool("hyperv_list_vms", {"confirm_everything": True}))

    records = [_json.loads(ln) for ln in
               audit.read_text(encoding="utf-8").splitlines() if ln.strip()]
    guard_records = [r for r in records if r.get("tool") == "hyperv_list_vms"
                     and r.get("error_class") == "invalid"]
    assert len(guard_records) == 1, (
        f"expected exactly one audited rejection, got {len(guard_records)} "
        f"of {len(records)} records"
    )
    rec = guard_records[0]
    assert rec["ok"] is False
    assert rec["category"] == ""


@pytest.fixture()
def registered_tools():
    mod = importlib.reload(server_module)
    mod.bootstrap({})  # deny-all: registration does not depend on policy
    try:
        mcp = mod.get_mcp()
        tm = mcp._tool_manager
        yield {name: tool.fn for name, tool in tm._tools.items()}
    finally:
        importlib.reload(server_module)


def test_every_tool_has_no_output_model(registered_tools):
    """Structural census (plan-critic round-1 finding 1 guardrail): a
    wrapped output model would validate failure CallToolResults against a
    `result:`-keyed model and reject envelope delivery. Only bare
    `-> CallToolResult` annotations (or plain -> dict / -> list) are safe."""
    from mcp.server.fastmcp.utilities.func_metadata import func_metadata

    bad = []
    for name, fn in registered_tools.items():
        md = func_metadata(fn)
        if md.output_schema is not None:
            bad.append(name)
    assert bad == [], f"tools with output models (envelope-hostile): {bad}"


def test_success_result_serializer_matches_convert_to_content():
    """Pin the wire-identity claim (review round 1 mutation M4 survived:
    changing success_result's to_json indent left the suite green). The
    metadata sidecar text must be byte-identical to what
    func_metadata._convert_to_content produces for the same dict."""
    from mcp.server.fastmcp.utilities.func_metadata import _convert_to_content

    meta = {"vm_id": "e953c649", "frame_hash": "abc", "width": 640,
            "unicode": "café", "nested": {"a": 1}}
    block = errors.success_result([meta]).content[0]
    assert block.type == "text"
    assert block.text == _convert_to_content(meta)[0].text, (
        "success_result must serialize dicts exactly as _convert_to_content"
    )


def test_wrong_typed_declared_arg_enveloped_and_audited(monkeypatch, tmp_path):
    """PRR-001/PRR-002 fix: a declared argument with a wrong type used to
    raise raw ToolError out of the guard (no envelope, no audit, message
    embedding the raw input value). The guard now catches it, classifies
    via the ValidationError cause ("invalid"), redacts, and audits once."""
    import asyncio
    import json as _json

    audit = tmp_path / "audit.jsonl"
    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True,
           "audit_log_path": str(audit)}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    mcp = mod.get_mcp()

    result = asyncio.run(mcp.call_tool(
        "hyperv_wait_vm_state", {"vm_name": "test-vm", "states": "Exploded"}
    ))
    assert result.isError is True
    env = result.structuredContent
    assert env["ok"] is False and env["error_class"] == "invalid"
    assert env["retryable"] is False and env["retry_after_ms"] is None
    records = [_json.loads(ln) for ln in
               audit.read_text(encoding="utf-8").splitlines() if ln.strip()]
    rejects = [r for r in records if r.get("tool") == "hyperv_wait_vm_state"
               and r.get("ok") is False]
    assert len(rejects) == 1, f"expected exactly one audited rejection: {records}"
    assert rejects[0]["error_class"] == env["error_class"]


def test_module_dict_without_error_class_audits_envelope_class(monkeypatch, tmp_path):
    """PRR-003 fix: an ok:false module dict lacking error_class used to be
    audited as "" while the envelope said "transport". The wrapper now
    audits from the enriched dict, so audit == envelope by construction."""
    import asyncio
    import json as _json

    audit = tmp_path / "audit.jsonl"
    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True,
           "audit_log_path": str(audit)}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    mcp = mod.get_mcp()

    def classless_failure(*args, **kwargs):
        return {"ok": False, "error": "module said no"}

    monkeypatch.setattr("hyperv_mcp.lifecycle.get_vm_info", classless_failure)
    result = asyncio.run(mcp.call_tool("hyperv_get_vm_info", {"vm_name": "test-vm"}))
    env = result.structuredContent
    assert env["ok"] is False and env["error"] == "module said no"
    assert env["error_class"] == "transport"
    assert env["retryable"] is False and env["retry_after_ms"] is None
    records = [_json.loads(ln) for ln in
               audit.read_text(encoding="utf-8").splitlines() if ln.strip()]
    match = [r for r in records if r.get("tool") == "hyperv_get_vm_info"]
    assert match and match[-1]["error_class"] == env["error_class"], (
        f"audit {match[-1:] if match else 'none'} must equal envelope {env['error_class']!r}"
    )


def test_guard_survives_broken_audit_sink(monkeypatch, tmp_path, capsys):
    """PRR-014 fix: a failed audit write must not turn a rejection into a
    raw exception — the envelope still ships, the failure warns on stderr."""
    import asyncio

    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    mcp = mod.get_mcp()

    def broken_sink(*args, **kwargs):
        raise PermissionError("disk full")

    monkeypatch.setattr(mod.auditlog, "log_operation", broken_sink)
    result = asyncio.run(mcp.call_tool("hyperv_list_vms", {"bogus": True}))
    env = result.structuredContent
    assert env["ok"] is False and env["error_class"] == "invalid"
    assert "bogus" in env["error"]
    captured = capsys.readouterr().err
    assert "audit write failed" in captured


def test_harden_tools_warns_loudly_on_empty_registry(capsys):
    """PRR-015 fix: if the SDK's private tool registry shape changes, the
    hardening pass must say so on stderr instead of failing open silently."""
    from mcp.server.fastmcp import FastMCP

    server_module._harden_tools(FastMCP("probe-empty"))
    captured = capsys.readouterr().err
    assert "found no registered tools" in captured


def test_registered_secret_redacted_in_validation_envelope(monkeypatch, tmp_path):
    """PRR-002 residual pin: a mistyped value that IS a registered secret
    must reach the envelope redacted (the registry scrub runs inside
    errors.envelope). Unregistered values are documented residual — the
    SDK's validation message format embeds them before redaction can see
    a registration."""
    import asyncio

    from hyperv_mcp import credentials

    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True,
           "allow_inline_credentials": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    secret = "S3CR3T-REGISTERED-VALUE"
    credentials._validated_password(secret, "test registration")
    mcp = mod.get_mcp()

    result = asyncio.run(mcp.call_tool(
        "hyperv_guest_run_ps",
        {"vm_name": "test-vm", "script": {"k": secret}},
    ))
    env = result.structuredContent
    assert env["ok"] is False and env["error_class"] == "invalid"
    assert secret not in env["error"], "registered secret leaked into the envelope"
    assert "***REDACTED***" in env["error"]
