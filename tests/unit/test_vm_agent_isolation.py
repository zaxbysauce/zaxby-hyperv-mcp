"""Frozen acceptance checks for the #31 supplement (AC14/AC15): the
cleanup-provider seam consulted before owned-clone deletion, and the
synthetic application-fixture ownership harness (trace
55-108-31-32-33-collated, arm's-length authoring, tier L).

Written from the DOCUMENTED IMPORT SURFACE below only — frozen; the
implementation phase makes them green. The module-level import makes every
check in this file an ERROR-at-base (ImportError) until
``hyperv_mcp.agent_isolation`` exists; that is the frozen base signature
(planned-file absence, per the supplement's own expect lines).

Frozen import surface (the contract the implementation must honor):

  from hyperv_mcp import agent_isolation

  agent_isolation.CLEAN / PENDING / UNKNOWN / FAILED   — reconcile verdicts
  agent_isolation.register_cleanup_provider(name, provider)
  agent_isolation.resolve_cleanup_provider(cfg) -> provider | None
  provider.reconcile(vm_guid) -> one of CLEAN/PENDING/UNKNOWN/FAILED
  agent_isolation.reconcile_before_remove(cfg, vm_guid) -> None
      raises agent_isolation.CleanupRefusal when the configured provider
      reports PENDING/UNKNOWN/FAILED **or when the provider call itself
      raises** (fail-closed)
  agent_isolation.CleanupRefusal / agent_isolation.NotOwnerError
  agent_isolation.FixtureOwnership()
      .register(owner, vm_guid, fixture)
      .teardown(owner, fixture) — raises NotOwnerError BEFORE any host
       operation when `owner` does not own `fixture`

Config wiring: ``Config.from_dict({"agent_isolation": {"cleanup_provider":
<name>}})`` selects a registered provider; the default config carries
``agent_isolation.cleanup_provider == "none"`` and an unconfigured registry
resolves to None, so ``reconcile_before_remove`` is a NO-OP success that
must never block ``vm_remove`` when no provider is configured.

Design constraints pinned here:
  * reconcile_before_remove with NO provider configured = no-op success;
  * the provider call happens BEFORE any deletion work — pinned with a
    shared call-log in which the reconcile record strictly precedes the
    delete marker the caller (vm_remove) appends only after the consult
    returns;
  * the synthetic provider proves the seam; the real fault backend ships
    with #102 and is explicitly out of scope for this PR.
"""

import pytest

from hyperv_mcp import agent_isolation
from hyperv_mcp.config import Config

GUID_A = "11111111-1111-1111-1111-111111111111"
GUID_B = "22222222-2222-2222-2222-222222222222"
GUID_UNKNOWN = "33333333-3333-3333-3333-333333333333"
GUID_FAILED = "44444444-4444-4444-4444-444444444444"
GUID_RAISING = "55555555-5555-5555-5555-555555555555"

PROVIDER_NAME = "synthetic-55-108"


class JournalProvider:
    """Synthetic cleanup provider: canned per-guid verdicts, every call
    journaled into the shared timeline the order pin reads."""

    def __init__(self, journal, verdicts):
        self._journal = journal
        self._verdicts = dict(verdicts)
        self.raise_for: set[str] = set()

    def reconcile(self, vm_guid):
        self._journal.append(("reconcile", vm_guid))
        if vm_guid in self.raise_for:
            raise RuntimeError(f"synthetic provider failure for {vm_guid}")
        return self._verdicts.get(vm_guid, agent_isolation.CLEAN)


def test_fault_profile_reconciles_before_owned_clone_delete():
    """#31 AC14 (pure-seam leg): with a cleanup provider configured,
    reconcile_before_remove is refused while the provider reports PENDING
    (and for UNKNOWN / FAILED / a raising provider — fail-closed), returns
    for CLEAN, and the OTHER owned fixture is unaffected. ORDER PROOF
    SCOPE: the journal below MODELS the caller (the delete marker is
    appended by the test after the consult returns) — the REAL
    reconcile-before-Remove-VM order proof against production code is the
    C14 wiring row, test_vm_remove_consults_cleanup_provider_before_removal,
    which journals the provider consult and the actual removal PowerShell
    into one timeline."""
    journal: list = []
    provider = JournalProvider(journal, {
        GUID_A: agent_isolation.PENDING,
        GUID_B: agent_isolation.CLEAN,
        GUID_UNKNOWN: agent_isolation.UNKNOWN,
        GUID_FAILED: agent_isolation.FAILED,
    })
    agent_isolation.register_cleanup_provider(PROVIDER_NAME, provider)
    cfg = Config.from_dict({"agent_isolation": {"cleanup_provider": PROVIDER_NAME}})

    # The configured provider is the one the resolver hands back.
    assert agent_isolation.resolve_cleanup_provider(cfg) is provider

    # The per-agent lifecycle fixture: one owned fault-profile fixture per
    # agent/VM, plus a SECOND owned fixture on B that B's removal flow must
    # leave alone until its own teardown.
    ownership = agent_isolation.FixtureOwnership()
    ownership.register("agent-a", GUID_A, "fault-profile:net-loss")
    ownership.register("agent-b", GUID_B, "fault-profile:net-loss")
    ownership.register("agent-b", GUID_B, "app-fixture:bdd-share")

    # PENDING for VM A -> deletion REFUSED (fail-closed), consulted once.
    with pytest.raises(agent_isolation.CleanupRefusal) as excinfo:
        agent_isolation.reconcile_before_remove(cfg, GUID_A)
    assert GUID_A in str(excinfo.value), (
        "the refusal must name the VM whose reconciliation is pending"
    )
    assert journal.count(("reconcile", GUID_A)) == 1

    # UNKNOWN and FAILED also refuse (AC14: "refuse deletion if it reports
    # UNKNOWN or failed cleanup").
    with pytest.raises(agent_isolation.CleanupRefusal):
        agent_isolation.reconcile_before_remove(cfg, GUID_UNKNOWN)
    with pytest.raises(agent_isolation.CleanupRefusal):
        agent_isolation.reconcile_before_remove(cfg, GUID_FAILED)

    # A provider that itself RAISES refuses too (fail-closed, never a
    # crash-through to deletion).
    provider.raise_for.add(GUID_RAISING)
    with pytest.raises(agent_isolation.CleanupRefusal):
        agent_isolation.reconcile_before_remove(cfg, GUID_RAISING)

    # The refused A flow must never have reached a delete marker.
    assert ("delete", GUID_A) not in journal

    # CLEAN for VM B -> the consult returns None and deletion may proceed.
    # Caller-model order note: the delete marker below is appended by the
    # TEST (modeling vm_remove's proceed-after-consult); the production
    # reconcile-before-Remove-VM order is proven by the C14 wiring row.
    assert agent_isolation.reconcile_before_remove(cfg, GUID_B) is None
    journal.append(("delete", GUID_B))
    assert journal.index(("reconcile", GUID_B)) < journal.index(("delete", GUID_B)), (
        "the cleanup provider must be consulted BEFORE any deletion work"
    )

    # The OTHER owned fixture on B is unaffected by B's flow: both of
    # agent-b's fixtures still tear down cleanly afterwards.
    ownership.teardown("agent-b", "fault-profile:net-loss")
    ownership.teardown("agent-b", "app-fixture:bdd-share")

    # Default config: provider "none", registry lookup None, and the seam
    # is a NO-OP success that never blocks vm_remove unconfigured.
    default_cfg = Config.from_dict({})
    assert default_cfg.agent_isolation.cleanup_provider == "none"
    assert agent_isolation.resolve_cleanup_provider(default_cfg) is None
    assert agent_isolation.reconcile_before_remove(default_cfg, GUID_B) is None


def test_app_fixture_ownership_is_distinct_from_vm_identity():
    """#31 AC15: the synthetic harness keeps application-fixture ownership
    separate from VM identity — non-owner teardown is rejected with
    NotOwnerError BEFORE any host operation (the refusal leaves state
    untouched: the true owner can still tear down), and the same fixture
    NAME under different owners (on different VM guids, and alongside a
    different owner's fixture on the SAME guid) never aliases."""
    ownership = agent_isolation.FixtureOwnership()

    # Shared-VM fixture plus a per-agent fixture on the SAME VM guid: two
    # ownerships, one VM identity.
    ownership.register("shared-actor", GUID_A, "app-fixture:bdd")
    ownership.register("agent-a", GUID_A, "app-fixture:agent-a-db")
    ownership.register("agent-b", GUID_B, "app-fixture:agent-b-db")
    # The same fixture NAME under two different owners on different guids.
    ownership.register("agent-b", GUID_B, "record-namespace:x")
    ownership.register("shared-actor", GUID_A, "record-namespace:x")

    # Non-owner teardown is rejected BEFORE any host operation: the
    # refusal performs no state change, evidenced by the owner's teardown
    # still succeeding afterwards (no host op recorded).
    with pytest.raises(agent_isolation.NotOwnerError):
        ownership.teardown("agent-a", "app-fixture:bdd")
    ownership.teardown("shared-actor", "app-fixture:bdd")

    # Ownership — not VM identity — keys a fixture: agent-b's "record-
    # namespace:x" teardown does not consume shared-actor's same-named
    # fixture on GUID_A.
    ownership.teardown("agent-b", "record-namespace:x")
    ownership.teardown("shared-actor", "record-namespace:x")

    # And the per-agent fixture sharing GUID_A with the (now torn-down)
    # shared fixture was its own ownership all along.
    ownership.teardown("agent-a", "app-fixture:agent-a-db")
    ownership.teardown("agent-b", "app-fixture:agent-b-db")


# ---------------------------------------------------------------------------
# #31-AC14 wiring leg (plan-critic round-1 finding 2; appended by the
# arm's-length check author): media.vm_remove ITSELF must consult the
# configured cleanup provider. The PowerShell leg is monkeypatched
# (pswindows.run_ps — the media._run path), so no real host I/O happens;
# the spy journals every script into the SAME timeline the provider
# journals its reconcile calls into, pinning the before-removal order.
# ---------------------------------------------------------------------------

WIRING_PROVIDER_NAME = "synthetic-55-108-wired"


class _WiringSpyPS:
    """FakePS shape (the test_g02 idiom): canned responses in order, every
    script recorded — and journaled into the shared order timeline."""

    def __init__(self, journal, responses):
        self.journal = journal
        self.scripts = []
        self._responses = list(responses)

    def __call__(self, script, **kwargs):
        from hyperv_mcp import pswindows as _psw

        self.journal.append(("script", script))
        self.scripts.append(script)
        item = (self._responses.pop(0) if self._responses
                else _psw.PSResult(stdout="{}", returncode=0))
        if isinstance(item, Exception):
            raise item
        return item


def _wiring_cfg(provider_name):
    return Config.from_dict({
        "unrestricted": True,
        "agent_isolation": {"cleanup_provider": provider_name},
    })


def test_vm_remove_consults_cleanup_provider_before_removal(monkeypatch):
    """#31-AC14 wiring (plan-critic round-1 finding 2): with a cleanup
    provider configured, media.vm_remove must consult it and proceed only
    on CLEAN (reconcile recorded BEFORE the script that runs Remove-VM);
    PENDING/UNKNOWN/FAILED verdicts, a raising provider, and an unknown
    configured provider name all refuse fail-closed (MediaError, no
    removal PowerShell ever runs); the default 'none' provider proceeds
    normally."""
    import json as _json

    from hyperv_mcp import media, pswindows

    journal: list = []
    provider = JournalProvider(journal, {})
    agent_isolation.register_cleanup_provider(WIRING_PROVIDER_NAME, provider)

    def _removal_responses():
        # vmident by-name resolution leg emits the GUID, then the state
        # gate ("Off"), then the ONE removal leg JSON (delete_disks
        # default False): exactly the test_g02 vm_remove stack.
        return [
            pswindows.PSResult(stdout=GUID_B, returncode=0),
            pswindows.PSResult(stdout="Off", returncode=0),
            pswindows.PSResult(
                stdout=_json.dumps(
                    {"status": "removed", "disks": [], "ancestors": []}),
                returncode=0),
        ]

    def _run_remove(cfg):
        spy = _WiringSpyPS(journal, _removal_responses())
        monkeypatch.setattr(pswindows, "run_ps", spy)
        return media.vm_remove(cfg, vm_name="test-vm-2", confirm=True), spy

    def _first_removal_script_pos():
        for pos, entry in enumerate(journal):
            if entry[0] == "script" and "Remove-VM" in entry[1]:
                return pos
        return -1

    # (a) provider CLEAN -> removal proceeds, reconcile BEFORE the script
    # that carries Remove-VM (the shared journal pins the order).
    provider._verdicts[GUID_B] = agent_isolation.CLEAN
    out, spy = _run_remove(_wiring_cfg(WIRING_PROVIDER_NAME))
    assert out["ok"] is True and out["status"] == "removed", out
    reconcile_pos = journal.index(("reconcile", GUID_B))
    removal_pos = _first_removal_script_pos()
    assert removal_pos != -1, "the removal leg must run for a CLEAN provider"
    assert reconcile_pos < removal_pos, (
        "the cleanup provider must be consulted BEFORE the Remove-VM "
        "removal script runs"
    )
    assert any("Remove-VM -VM $vm" in s for s in spy.scripts)

    # (b) PENDING -> MediaError refusal, NO removal PowerShell ever runs.
    journal.clear()
    provider._verdicts[GUID_B] = agent_isolation.PENDING
    cfg = _wiring_cfg(WIRING_PROVIDER_NAME)
    with pytest.raises(media.MediaError):
        _run_remove(cfg)
    assert _first_removal_script_pos() == -1, (
        "a PENDING provider must refuse before any Remove-VM script"
    )

    # (c) UNKNOWN and FAILED refuse the same way.
    journal.clear()
    provider._verdicts[GUID_B] = agent_isolation.UNKNOWN
    with pytest.raises(media.MediaError):
        _run_remove(_wiring_cfg(WIRING_PROVIDER_NAME))
    assert _first_removal_script_pos() == -1

    journal.clear()
    provider._verdicts[GUID_B] = agent_isolation.FAILED
    with pytest.raises(media.MediaError):
        _run_remove(_wiring_cfg(WIRING_PROVIDER_NAME))
    assert _first_removal_script_pos() == -1

    # (d) a provider that itself raises -> MediaError (fail-closed), with
    # the provider's own failure detail preserved in the message (review
    # round 2: the threading conversion must not swallow it).
    journal.clear()
    provider._verdicts.pop(GUID_B, None)
    provider.raise_for.add(GUID_B)
    with pytest.raises(media.MediaError, match="synthetic provider failure"):
        _run_remove(_wiring_cfg(WIRING_PROVIDER_NAME))
    assert _first_removal_script_pos() == -1
    provider.raise_for.clear()

    # (e) an unknown configured provider name fails closed with MediaError —
    # and the config is built OUTSIDE the raises block so a config-layer
    # rejection cannot satisfy the contract (the refusal must come from the
    # seam's fail-closed resolve) — BEFORE any PowerShell leg at all.
    journal.clear()
    spy = _WiringSpyPS(journal, _removal_responses())
    monkeypatch.setattr(pswindows, "run_ps", spy)
    ghost_cfg = _wiring_cfg("ghost")
    with pytest.raises(media.MediaError):
        media.vm_remove(ghost_cfg, vm_name="test-vm-2", confirm=True)
    assert spy.scripts == [], (
        "an unknown provider name must refuse before ANY PowerShell leg"
    )

    # (f) the default 'none' provider proceeds normally (no consult, no
    # refusal) — the unconfigured seam never blocks vm_remove.
    journal.clear()
    out_none, spy_none = _run_remove(Config.from_dict({"unrestricted": True}))
    assert out_none["ok"] is True, out_none
    assert any("Remove-VM -VM $vm" in s for s in spy_none.scripts)
    assert ("reconcile", GUID_B) not in journal
