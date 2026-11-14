"""Phase-4.2 recurrence-census guardrail for trace 128-129-134-gui-drivability.

The defect class: a contract surface that exists on one side of a seam and
has no counterpart on the other (a host-declared capability with no guest
reporter, a host verb with no guest dispatch arm, a detachable tool with no
destructive preflight gate, a lease-citing tool with no lease scope). The
frozen per-issue checks pin each side in isolation; nothing cross-checks the
seams. Mutation proofs executed during the census (2026-11-13, sandbox copy
of 0deba5a): M1 (BASE_CAPABILITIES += "adapter:edge") survived 131 UIA
tests; M5 (gates -= hyperv_guest_put) survived 94 ops tests; M7 (a new
lease_id-declaring tool with TOOL_NAMES/CONFIRM_TOOLS updated, no scope
entry) survived the inventory pins. The nodes below kill exactly those
mutants; all four are green at 0deba5a.

NOT part of any frozen checkpoint set - additive hardening (the
test_e03_guardrail.py precedent).
"""

import asyncio
import importlib
import json
import re
from pathlib import Path

import hyperv_mcp.server as server_module
from hyperv_mcp import operations, uia

_HELPER = Path(uia.__file__).parent / "guest" / "uia_helper.ps1"

#: lease_id on these tools is the SUBJECT of the call (the lease being
#: renewed/released), not a gate citation - no scope entry is wanted.
_LEASE_SUBJECT_TOOLS = {"hyperv_lease_renew", "hyperv_lease_release"}


def _helper_text() -> str:
    return _HELPER.read_text(encoding="utf-8")


def _ps_function_body(text: str, name: str) -> str:
    """The body of one function in the packaged helper (the next
    top-level 'function ' declaration ends it)."""
    m = re.search(rf"function {re.escape(name)}[^\n]*\{{", text)
    assert m is not None, f"helper ships no function {name}"
    rest = text[m.end():]
    m2 = re.search(r"\nfunction ", rest)
    return rest[:m2.start()] if m2 else rest


def _bootstrapped_schemas(tmp_path):
    p = tmp_path / "census-guardrail-config.json"
    p.write_text(json.dumps(
        {"allowed_vm_patterns": ["test-*"], "unrestricted": True}),
        encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    return mod, {t.name: (getattr(t, "input_schema", None) or {})
                 for t in asyncio.run(mod.get_mcp().list_tools())}


def test_host_capabilities_match_helper_report():
    """Kills census mutant M1: a capability added to the host side
    (uia.BASE_CAPABILITIES / ELECTRON_CAPABILITY) with no counterpart in
    the helper's Get-HelperCapabilities report fails here, and vice versa
    (the RC2/#129 recurrence)."""
    caps = set(re.findall(r"'([a-z:_.]+)'",
                          _ps_function_body(_helper_text(),
                                            "Get-HelperCapabilities")))
    host = uia.BASE_CAPABILITIES | {uia.ELECTRON_CAPABILITY}
    assert caps == host, (
        "one-sided capability seam: the helper's reported capability set "
        f"{sorted(caps)} != the host's declared set {sorted(host)}; every "
        "host-declared capability needs a helper reporter (issue #129)")


def test_host_verbs_match_helper_dispatch_arms():
    """The verb seam: every verb the host may build (uia.VERBS |
    uia._SIDE_CHANNEL_VERBS) needs an Invoke-Request arm in the packaged
    helper, and every helper arm needs a host verb. The host-side half is
    already pinned by test_f05_uia_helper.py::test_request_verbs_are_closed_set
    (which killed census mutant M2); this node adds the cross-file half."""
    arms = set(re.findall(r"\$verb -eq '([a-z_]+)'",
                          _ps_function_body(_helper_text(),
                                            "Invoke-Request")))
    host = uia.VERBS | uia._SIDE_CHANNEL_VERBS
    assert arms == host, (
        "one-sided verb seam: helper dispatch arms "
        f"{sorted(arms)} != host admissible verbs {sorted(host)}")


def test_operations_gates_cover_confirm_requiring_detachable_tools(tmp_path):
    """Kills census mutant M5: every DETACHABLE tool that declares a
    confirm parameter (i.e. whose sync path gates destructively) must have
    a preflight entry in server._OPERATIONS_DESTRUCTIVE_GATES - without it
    a denied detached call mints an op row before failing - and every gate
    entry must name a detachable tool (no dead gate)."""
    gates = set(server_module._OPERATIONS_DESTRUCTIVE_GATES)
    detachable = set(operations.DETACHABLE_TOOLS)
    assert gates <= detachable, (
        f"dead gate entries (tool not detachable): {sorted(gates - detachable)}")
    _, schemas = _bootstrapped_schemas(tmp_path)
    confirming = {
        name for name, sch in schemas.items()
        if name in detachable and "confirm" in sch.get("properties", {})
    }
    assert confirming <= gates, (
        "detachable confirm-requiring tools without a destructive preflight "
        f"gate: {sorted(confirming - gates)}")


def test_lease_citing_tools_have_a_scope_entry(tmp_path):
    """Kills census mutant M7: a tool whose schema declares lease_id
    advertises the lease gate, so it must have a TOOL_SCOPES entry -
    otherwise _lease_gate's TOOL_SCOPES.get(name) returns None and the gate
    is a silent no-op. Stale scope entries (tool never registered) fail
    too."""
    mod, schemas = _bootstrapped_schemas(tmp_path)
    scopes = mod.TOOL_SCOPES
    leased = {name for name, sch in schemas.items()
              if "lease_id" in sch.get("properties", {})}
    missing = sorted(leased - set(scopes) - _LEASE_SUBJECT_TOOLS)
    assert not missing, (
        "lease-citing tools with no TOOL_SCOPES entry (the lease gate is a "
        f"silent no-op for them): {missing}")
    stale = sorted(set(scopes) - set(schemas))
    assert not stale, f"stale TOOL_SCOPES entries: {stale}"
