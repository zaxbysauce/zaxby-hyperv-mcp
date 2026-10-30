"""Critic-round-2 acceptance checks for issue #30 (per-VM credential
profiles), trace 30-per-vm-credential-profiles, driver repro/check-g01.sh.

Lives in its own file (the established pattern: critic-round checks never
move the frozen bytes of tests/unit/test_g01_credential_profiles.py or
tests/unit/test_g01_pool_edges.py). One test per check id C24..C27, pinning
fix-plan v3's round-2 residuals:

  C24 ([R1-4]/[R2-2], plan section 5): relay restore CONSUMPTION — the
      restored relay's actual credential identity is asserted (not just the
      persisted labels), a changed identity refuses fail-closed at the
      shared binding helper, a legacy relay row restores by ref, and the
      pre-registration placeholder row keeps cred_ref 'inline' semantics
      (never re-resolvable to a live credential).
  C25 ([R1-6] victim arm, plan section 1): victim_password_env validated as
      an env-var NAME without echoing the value; the admin arm stays valid.
  C26 ([R2-1], plan section 3): the GUID-only fail-closed differential —
      with profiles configured an unresolvable canonical name raises a
      credential envelope and NO guest leg runs; with ZERO profiles the
      same call falls back to the global credential byte-identically.
  C27 (plan section 4, adopted non-blocking): victim_run delegates through
      guest_run, and the victim role marker survives the delegation into
      the pooled session key.

Every test is self-contained, deterministic and Hyper-V-free (pooled
workers are recording fakes, per-call PowerShell legs are served by a
recording run_ps stand-in, the store lives in the per-test tmp dir, the
relay binds loopback-only and is stopped before the round-trip).
Placeholder secrets only, always >= 3 characters. RED at the base tree:
the `credential_profiles` config key does not exist yet (the family
signature), except where noted per test.
"""

import importlib
import json
import re
import uuid

import pytest

from hyperv_mcp import (
    credentials,
    guestexec,
    guestjobs,
    psdsessions,
    pswindows,
    relay,
    statestore,
    vmident,
)
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.credentials import CredentialError

LAB_A_PROFILE = {
    "name": "lab-a",
    "vm_patterns": ["lab-a-*"],
    "username": "LabAdminA",
    "password_env": "LAB_A_PW",
}
GUID = "5b1e7a42-9f30-4c8b-8e2f-6c7d91a3b0d5"

_CLOSE_NAMES = ("close", "terminate", "kill", "shutdown", "stop", "dispose")


@pytest.fixture(autouse=True)
def _fresh_state():
    """Isolate the process-global resolver config and registries per test."""
    credentials.init(Config())
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()
    yield
    relay.clear_registry_for_tests()
    guestjobs.clear_registry_for_tests()
    credentials.init(Config())


def _profiles_cfg(profiles, **extra):
    """Build + install a config carrying credential_profiles (the family's
    first base-failure site: the key is unknown at base)."""
    cfg = Config.from_dict({"unrestricted": True,
                            "credential_profiles": profiles, **extra})
    credentials.init(cfg)
    return cfg


# ---------------------------------------------------------------------------
# fakes: pooled workers (tests/unit/test_g01_pool_edges.py pattern)
# ---------------------------------------------------------------------------


class _DuckResult:
    """run_ps-shaped result WITHOUT being a PSResult, so constructing one
    never feeds the timing collector's spawn counter."""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0
        self.timed_out = False
        self.duration_ms = 0

    def ok(self) -> bool:
        return True


def _guest_envelope(stdout: str = "pooled-ok") -> _DuckResult:
    return _DuckResult(stdout=json.dumps(
        {"exit_code": 0, "stdout": stdout, "stderr": ""}))


class _FakeWorker:
    """Protocol-generic pooled-worker double: every attribute access becomes
    a call answering the canned guest envelope; only the close-family names
    are special-cased so closure stays observable."""

    def __init__(self, factory: "_RecordingFactory", key) -> None:
        self._factory = factory
        self.key = key

    def _close(self, *args, **kwargs) -> None:
        pass

    def __getattr__(self, name):
        if name in _CLOSE_NAMES:
            return self._close
        if name.startswith("__"):
            raise AttributeError(name)

        def method(*args, **kwargs):
            return self._factory.canned

        return method


class _RecordingFactory:
    """worker_factory double recording every spawn as (key, script, stdin);
    the key is the composed SessionKey, so its cred_profile component is the
    role-separation oracle."""

    def __init__(self, canned=None) -> None:
        self.canned = canned if canned is not None else _guest_envelope()
        self.spawned: list[tuple] = []

    def __call__(self, *args, **kwargs):
        key = args[0] if args else kwargs.get("key")
        script = args[1] if len(args) > 1 else kwargs.get("script", "")
        stdin_b64 = args[2] if len(args) > 2 else kwargs.get("stdin_b64")
        self.spawned.append((key, script, stdin_b64))
        return _FakeWorker(self, key)


def _stub_vm_identity(monkeypatch, guid: str = GUID, name: str = "lab-a-01"):
    """Stub vmident.resolve: a resolved VMRef with no PowerShell leg."""
    monkeypatch.setattr(
        vmident, "resolve",
        lambda cfg, vm_name="", vm_id="": vmident.VMRef(
            id=guid, name=vm_name or name),
    )


# ---------------------------------------------------------------------------
# fakes: per-call run_ps legs (tests/unit/test_guestjobs.py pattern)
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"ElementName -eq '([^']*)'")


def _is_resolution_leg(script: str) -> bool:
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _resolved_guid(script: str) -> str:
    m = _NAME_RE.search(script)
    return str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1) if m else ""))


class FakePS:
    """Every leg pops one queued response; the by-name resolution leg is
    answered by pattern so distinct names stay distinct GUIDs."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


# ---------------------------------------------------------------------------
# C24 (plan section 5): relay restore consumption + placeholder semantics
# ---------------------------------------------------------------------------


def test_relay_restore_consumes_and_binds_credential_identity(monkeypatch):
    """C24 (plan v3 section 5): through the REAL per-test state store and
    the REAL relay registry — a relay started with a profile credential
    persists cred_profile/cred_username; after clearing the registry and
    reopening the store, the RESTORED relay's actual credential object is
    the profile identity (username + profile, not just the labels); with the
    profile's username changed, the shared binding helper REFUSES naming
    BOTH identities (fail-closed; what relay.py does with the refusal on
    its stop path is the fix's business — the helper-level binding is what
    this pins); a legacy relay row (both fields empty) restores by ref; and
    the pre-registration placeholder row keeps cred_ref 'inline' semantics,
    so it can never re-resolve to a live credential."""
    cfg = _profiles_cfg([LAB_A_PROFILE])
    monkeypatch.setenv("LAB_A_PW", "lab-a-pass-123")
    cred = credentials.resolve_guest(vm_name="lab-a-01")
    assert getattr(cred, "profile", None) == "lab-a", (
        f"premise: the relay credential names the profile; got {cred!r}"
    )

    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    started = relay.relay_start(cfg, "lab-a-01", 9419, cred=cred)
    relay_id = started["relay_id"]
    relay.relay_stop(cfg, relay_id)

    relay.clear_registry_for_tests()
    statestore.clear_store_cache_for_tests()
    restored = relay._restore_relay(cfg, relay_id, None)
    assert restored is not None, "the durable store lost the relay row"
    assert restored.get("cred_profile") == "lab-a", (
        f"the restored relay row must carry the profile label: {restored!r}"
    )
    assert restored.get("cred_username") == "LabAdminA", (
        f"the restored relay row must carry the recorded username: {restored!r}"
    )
    # the CONSUMED credential object, not just the labels
    restored_cred = (restored.get("context") or {}).get("cred")
    assert restored_cred is not None, (
        f"the restored relay must re-resolve a live credential: {restored!r}"
    )
    assert restored_cred.username == "LabAdminA", (
        f"the restored relay's credential must be the profile identity; got "
        f"{restored_cred.username!r}"
    )
    assert getattr(restored_cred, "profile", None) == "lab-a", (
        f"the restored relay's credential must name the profile; got "
        f"{restored_cred!r}"
    )

    # changed profile identity: the shared binding helper refuses, naming
    # both; the global env claims a third identity (no global fallback)
    changed = _profiles_cfg([dict(LAB_A_PROFILE, username="LabAdminZ")])
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "globaladmin")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "global-pass-456")
    with pytest.raises(CredentialError) as excinfo:
        guestjobs._restored_credential(changed, restored)
    message = str(excinfo.value)
    assert "LabAdminA" in message and "LabAdminZ" in message, (
        f"the refusal must name the recorded and re-resolved identities; "
        f"got {message!r}"
    )

    # legacy relay row on the SAME store: no recorded identity, by-ref
    credentials.init(cfg)
    statestore.store_for(cfg).relay_upsert(statestore.RelayRow(
        relay_id="relay-legacy-1", vm_name="lab-a-01", vm_id=GUID,
        guest_port=9420, started_at="2026-01-01T00:00:00Z",
        state=statestore.RELAY_ACTIVE, cred_ref="env", owner=None,
    ))
    relay.clear_registry_for_tests()
    legacy = relay._restore_relay(cfg, "relay-legacy-1", None)
    assert legacy is not None, "the legacy relay row must restore"
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "LegacyAdmin")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "legacy-pass-789")
    legacy_cred = guestjobs._restored_credential(cfg, legacy)
    assert legacy_cred.username == "LegacyAdmin", (
        f"a legacy relay row restores by ref (global re-resolution); got "
        f"{legacy_cred.username!r}"
    )

    # the pre-registration placeholder row: cred_ref 'inline' semantics —
    # a reservation can never re-resolve to a live credential
    guestjobs._reserve_slot("placeholder-job-1", None, cfg=cfg,
                            vm_id=GUID, vm_name="lab-a-01")
    placeholder_row = statestore.store_for(cfg).job_get("placeholder-job-1")
    assert placeholder_row is not None, "the reservation must persist a row"
    assert placeholder_row.cred_ref == "inline", (
        f"a pre-registration placeholder must record cred_ref 'inline' "
        f"(never re-resolvable); got {placeholder_row.cred_ref!r}"
    )
    guestjobs.clear_registry_for_tests()
    placeholder = guestjobs._restore_entry(cfg, "placeholder-job-1", None)
    assert placeholder is not None, "the placeholder row must restore"
    with pytest.raises(CredentialError, match="inline"):
        guestjobs._restored_credential(cfg, placeholder)


# ---------------------------------------------------------------------------
# C25 (plan section 1): victim_password_env validation
# ---------------------------------------------------------------------------


def test_victim_password_env_validation_rejects_without_echo():
    """C25 (plan v3 section 1): victim_password_env must be an
    environment-variable NAME. A pasted secret value and a non-name are each
    refused at config load with a ConfigError naming the FIELD
    (victim_password_env), the value is never echoed (canary asserted
    absent), and the admin password_env arm stays valid in the same config
    (positive control)."""
    canary = "victim-canary-secret-9"
    with pytest.raises(ConfigError, match="victim_password_env") as excinfo:
        Config.from_dict({"credential_profiles": [
            dict(LAB_A_PROFILE, victim_username="LabVictimA",
                 victim_password_env=canary),
        ]})
    assert canary not in str(excinfo.value), (
        f"a pasted secret must never be echoed by the config error; got "
        f"{excinfo.value!r}"
    )
    with pytest.raises(ConfigError, match="victim_password_env") as excinfo:
        Config.from_dict({"credential_profiles": [
            dict(LAB_A_PROFILE, victim_username="LabVictimA",
                 victim_password_env="not a name!"),
        ]})
    assert "not a name!" not in str(excinfo.value), (
        f"the invalid value must never be echoed by the config error; got "
        f"{excinfo.value!r}"
    )
    # positive control: the admin arm stays valid in the same config
    cfg = Config.from_dict({"credential_profiles": [
        dict(LAB_A_PROFILE, victim_username="LabVictimA",
             victim_password_env="LAB_A_VICTIM_PW"),
    ]})
    assert [p.name for p in cfg.credential_profiles] == ["lab-a"]


# ---------------------------------------------------------------------------
# C26 (plan section 3, [R2-1]): GUID-only fail-closed differential
# ---------------------------------------------------------------------------


def test_unresolved_guid_fails_closed_only_when_profiles_exist(monkeypatch):
    """C26 (plan v3 section 3 [R2-1]): the differential —
    (a) WITH profiles configured, a GUID-only call whose canonical-name
    resolution fails must surface a {ok:false, error_class:'credential'}
    envelope AND run NO guest leg (the guest stub fails the test if
    invoked); the global credential is set, so a silent fallback would
    succeed and fail the error_class assert;
    (b) with ZERO profiles, the same failing-resolution call falls back to
    the global credential byte-identically (the guest leg RUNS, ok:true)."""
    import asyncio

    from conftest import content_blocks

    import hyperv_mcp.server as server_module

    cfg_profiles = _profiles_cfg([LAB_A_PROFILE])
    real_resolve = credentials.resolve_guest

    def recorder(*args, **kwargs):
        return credentials.CredentialSet(
            "recorder-admin", "recorder-pass-123", "env")

    def resolve_boom(cfg_arg, vm_name="", vm_id=""):
        raise ValueError("no VM found for GUID (test stub)")

    # (a) profiles configured: fail closed, no guest leg
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "GlobalAdmin")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "global-pass-123")
    guest_legs = []

    def guest_must_not_run(*a, **k):
        guest_legs.append(a)
        raise AssertionError("guest leg must not run")

    monkeypatch.setattr(credentials, "resolve_guest", recorder)
    monkeypatch.setattr(vmident, "resolve", resolve_boom)
    monkeypatch.setattr(guestexec, "guest_run_ps", guest_must_not_run)

    mod = importlib.reload(server_module)
    try:
        mod.bootstrap(config=cfg_profiles)
        result = asyncio.run(mod.get_mcp().call_tool(
            "hyperv_guest_run_ps",
            {"vm_id": GUID, "script": "Write-Output 'probe'"},
        ))
        blocks = content_blocks(result)
        texts = [c for c in blocks if getattr(c, "type", "") == "text"]
        assert texts, "expected a text envelope for the credential failure"
        envelope = json.loads(texts[0].text)
        assert envelope.get("ok") is False, envelope
        assert envelope.get("error_class") == "credential", (
            f"an unresolvable canonical name with profiles configured must "
            f"fail closed as a credential error; got {envelope!r}"
        )
        assert guest_legs == [], (
            "no guest leg may run when the canonical name cannot be resolved"
        )

        # (b) ZERO profiles: byte-identical legacy fallback
        def guest_ran(*a, **k):
            guest_legs.append(a)
            return {"ok": True, "exit_code": 0, "stdout": "stub",
                    "stderr": "", "timed_out": False, "truncated": False}

        monkeypatch.setattr(guestexec, "guest_run_ps", guest_ran)
        monkeypatch.setattr(credentials, "resolve_guest", real_resolve)
        legacy_mod = importlib.reload(server_module)
        legacy_mod.bootstrap(config=Config(unrestricted=True))
        legacy_result = asyncio.run(legacy_mod.get_mcp().call_tool(
            "hyperv_guest_run_ps",
            {"vm_id": GUID, "script": "Write-Output 'probe'"},
        ))
        blocks = content_blocks(legacy_result)
        texts = [c for c in blocks if getattr(c, "type", "") == "text"]
        assert texts, "expected a text result block from the stubbed call"
        legacy_envelope = json.loads(texts[0].text)
        assert legacy_envelope.get("ok") is True, (
            f"with zero profiles the same call must fall back to the global "
            f"credential exactly as at base; got {legacy_envelope!r}"
        )
        assert len(guest_legs) == 1, (
            f"the zero-profile fallback must run exactly one guest leg; "
            f"observed {len(guest_legs)}"
        )
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# C27 (plan section 4): the victim role survives the guest_run delegation
# ---------------------------------------------------------------------------


def test_victim_run_role_survives_guest_run_delegation(monkeypatch):
    """C27 (plan v3 section 4): victim_run delegates through guest_run, so
    the victim role marker must survive the delegation into the pooled
    session key. With a named profile carrying victim fields, an admin
    guest_run_ps call and a victim_run call on the same VM resolve through
    the SAME profile yet compose DIFFERENT session keys: the admin key's
    cred_profile component is the profile name, the victim key's is the
    plan-section-4 victim composition (profile name + '#victim')."""
    combined = dict(LAB_A_PROFILE, victim_username="LabVictimA",
                    victim_password_env="LAB_A_VICTIM_PW")
    _profiles_cfg([combined])
    monkeypatch.setenv("LAB_A_PW", "lab-admin-pass-123")
    monkeypatch.setenv("LAB_A_VICTIM_PW", "lab-victim-pass-456")
    _stub_vm_identity(monkeypatch)

    admin_cred = credentials.resolve_guest(vm_name="lab-a-01")
    victim_cred = credentials.resolve_victim(vm_name="lab-a-01")
    assert getattr(admin_cred, "profile", None) == "lab-a", (
        f"premise: the admin credential names the profile; got {admin_cred!r}"
    )
    assert getattr(victim_cred, "profile", None) == "lab-a", (
        f"premise: the victim credential names the SAME profile; got "
        f"{victim_cred!r}"
    )

    factory = _RecordingFactory()
    monkeypatch.setattr(psdsessions, "DEFAULT", psdsessions.SessionPool(
        worker_factory=factory, max_sessions=8))
    cfg = Config(unrestricted=True)

    admin = guestexec.guest_run_ps(
        cfg, "lab-a-01", "Write-Output admin", cred=admin_cred)
    victim = guestexec.victim_run(
        cfg, "lab-a-01", "cmd.exe", ["/c", "exit", "0"], cred=victim_cred)
    assert admin.get("ok") is True, admin
    assert victim.get("ok") is True, victim

    assert len(factory.spawned) == 2, (
        f"admin and victim roles on one VM/profile opened "
        f"{len(factory.spawned)} pooled session(s); the roles must never "
        f"share a session"
    )
    admin_key = factory.spawned[0][0]
    victim_key = factory.spawned[1][0]
    assert admin_key != victim_key, (
        f"the delegated victim_run must hold a distinct session key: "
        f"{admin_key!r} == {victim_key!r}"
    )
    admin_component = getattr(admin_key, "cred_profile", None)
    victim_component = getattr(victim_key, "cred_profile", None)
    assert admin_component == "lab-a", (
        f"the admin key's cred_profile component must be the profile name; "
        f"got {admin_component!r}"
    )
    assert victim_component == "lab-a#victim", (
        f"the delegated victim key's cred_profile component must be the "
        f"plan-section-4 victim composition (profile name + '#victim'); "
        f"got {victim_component!r}"
    )
