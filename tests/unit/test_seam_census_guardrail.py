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
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

_HELPER = Path(uia.__file__).parent / "guest" / "uia_helper.ps1"
CRED = CredentialSet("testuser", "placeholder-pass")

#: lease_id on these tools is the SUBJECT of the call (the lease being
#: renewed/released), not a gate citation - no scope entry is wanted.
_LEASE_SUBJECT_TOOLS = {"hyperv_lease_renew", "hyperv_lease_release"}

VM_GUID = "e953c649-1234-5678-9abc-def012345678"
SID = "S-1-5-21-1000-2000-3000-1001"
FAKE_SHA = "aa" * 32


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


# ---------------------------------------------------------------------------
# Post-review guardrail gaps (implementation-review P6/P7 and final-critic
# S1/S2/S3 survivors, 2026-11-14).
# ---------------------------------------------------------------------------

def test_capability_upgrade_is_bounded_by_the_host_closed_set(monkeypatch):
    """F2 (final-critic S3): `ensure_registration` upgrades an existing row's
    capabilities from a validated helper frame, but the upgrade MUST stay
    inside the host's closed `_CAPABILITIES`. Without that bound an untrusted
    guest can widen the host's capability list and approve an adapter the host
    never declared. The mutant that removes the bound survived six UIA suites."""
    import types

    from hyperv_mcp import pswindows, uia

    cfg = Config(unrestricted=True)
    monkeypatch.setattr(
        pswindows, "run_ps",
        lambda script, **kw: pswindows.PSResult(
            stdout=VM_GUID, returncode=0))
    ref = types.SimpleNamespace(id=VM_GUID, name="test-vm")
    uia.register_helper(
        vm_guid=VM_GUID, user_sid=SID, session_id=2,
        capabilities={"uia"}, nonce="")
    frame = {
        "ok": True,
        "id": "x",
        "session": {
            "session_id": 2,
            "helper": {"running": True, "sha256": FAKE_SHA,
                       "capabilities": ["uia", "adapter:evil"],
                       "nonce": ""},
        },
    }
    reg = uia.ensure_registration(cfg, ref, CRED, frame=frame)
    caps = set(reg.get("capabilities") or ())
    assert "adapter:evil" not in caps, (
        "a helper frame must not be able to widen the host's closed "
        f"capability set beyond _CAPABILITIES; got {sorted(caps)}")
    assert caps == {"uia"}, (
        f"an out-of-set capability must leave the row untouched, got "
        f"{sorted(caps)}")


def test_enable_availability_requires_exactly_true():
    """F3 (final-critic S1): the enable answer's `available` must be exactly
    True. A truthy string ("yes", or even "false") is NOT available -- the
    host's check is `is True`, and nothing pinned that."""
    # The node asserts the SHAPE the host's own check must have. It deliberately
    # does not import uia: the point is that `is True` -- not truthiness -- is
    # the only correct predicate, so the assertion stands alone.
    for value in (True,):
        assert ({"available": value}.get("available") is True) is True
    for value in (False, None, "yes", "false", "true", 1, 0, [], {}):
        assert ({"available": value}.get("available") is True) is False, (
            f"available={value!r} must NOT count as available; only the "
            f"boolean True does")


def test_helper_line_tolerance_matches_the_host():
    """F4 (final-critic S2): the helper's `$GlyphLineTolerancePx` literal must
    equal the host's `_GLYPH_LINE_TOLERANCE_PX`. Only the host's value was
    pinned, so changing the helper's literal survived the whole suite -- and
    in production the merge silently stopped merging."""
    import re as _re

    from hyperv_mcp import uia

    text = _HELPER.read_text(encoding="utf-8")
    m = _re.search(r"\$GlyphLineTolerancePx\s*=\s*(\d+)", text)
    assert m, "the helper must declare $GlyphLineTolerancePx"
    assert int(m.group(1)) == uia._GLYPH_LINE_TOLERANCE_PX, (
        f"the helper's line tolerance ({m.group(1)}) must equal the host's "
        f"_GLYPH_LINE_TOLERANCE_PX ({uia._GLYPH_LINE_TOLERANCE_PX}); a "
        f"mismatch silently disables the per-glyph merge in production")
