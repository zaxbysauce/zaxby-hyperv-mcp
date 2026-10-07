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
    assert retryable is True and isinstance(after, int) and after > 0
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


@pytest.fixture()
def registered_tools():
    mod = importlib.reload(server_module)
    mod.bootstrap({})  # deny-all: registration does not depend on policy
    mcp = mod.get_mcp()
    tm = mcp._tool_manager
    fns = {name: tool.fn for name, tool in tm._tools.items()}
    return fns


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
