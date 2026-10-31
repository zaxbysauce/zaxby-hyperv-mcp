"""Critic-round-1 acceptance checks for issue #30 (per-VM credential
profiles), trace 30-per-vm-credential-profiles, driver repro/check-g01.sh.

Lives in its own file (the established pattern: critic-round checks never
move the frozen bytes of tests/unit/test_g01_credential_profiles.py). One
test per check id C19..C23, pinning fix-plan v2 sections 3/4/5/1:

  C19 (plan section 4): a NAMED profile's admin and victim credentials get
      DISTINCT pooled sessions through the real entry points.
  C20 (plan section 3): a GUID-only tool call resolves the CANONICAL VM name
      before credential resolution, so a profiled VM is profile-resolved.
  C21 (plan section 5): durable job AND relay rows persist
      cred_profile/cred_username through the real store; restore consumes
      them, a changed identity refuses, and a legacy row restores by ref.
  C22 (plan section 1): invalid password_env values (a pasted secret, a
      non-name) are refused at config load naming the FIELD, never the value.
  C23 (plan section 1): the reserved profile name 'default' (any case-folded
      variant) is refused at config load; a legitimate name still loads.

Every test is self-contained, deterministic and Hyper-V-free: pooled workers
are recording fakes, per-call PowerShell legs are served by a recording
run_ps stand-in, the store lives in the per-test tmp dir. Placeholder
secrets only, always >= 3 characters. RED at the base tree: the
`credential_profiles` config key does not exist yet (the family signature),
except where noted per test.
"""

import base64
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
ADMIN_PW = "lab-admin-pass-123"
VICTIM_PW = "lab-victim-pass-456"
GUID = "3f9d2b71-8c4a-4e11-9d70-2a4c55d0b7e3"

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
# fakes: pooled workers (trace-21 test_d05_psdirect_sessions.py pattern)
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
    a recorded call answering the canned guest envelope; only the
    close-family names are special-cased so closure stays observable."""

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
    """worker_factory double recording every spawn as
    (key, establishment script, stdin_b64) — the credential-separation
    oracle: each spawn's script quotes its own username and its stdin
    carries exactly its own password."""

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
    """Stub vmident.resolve: a resolved VMRef with no PowerShell leg
    (trace-21's _stub_resolve seam)."""
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


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


def _guest_exec_stub(monkeypatch):
    """Replace guestexec.guest_run_ps with a canned ok envelope (the C20
    observable is the vm_name the credential resolver receives, so the guest
    module itself must be inert)."""
    monkeypatch.setattr(
        guestexec, "guest_run_ps",
        lambda *a, **k: {"ok": True, "exit_code": 0, "stdout": "stub",
                         "stderr": "", "timed_out": False, "truncated": False},
    )


# ---------------------------------------------------------------------------
# C19 (plan section 4, [R1-2]): named-profile admin/victim session separation
# ---------------------------------------------------------------------------


def test_named_profile_guest_and_victim_get_distinct_pooled_sessions(monkeypatch):
    """C19 (AC4-role-separation): one profile lab-a (pattern lab-a-*) carries
    BOTH the admin fields and the victim fields; a guest_run_ps call and a
    victim_run_ps call on the same VM resolve through the SAME named profile
    yet must open TWO distinct pooled sessions — and neither worker's
    establishment material may carry the other role's credential (sharing
    would escalate the unprivileged identity into the admin session).

    Driven through the real entry points with the pool installed and a
    recording worker factory (the trace-21 AC16 mechanics)."""
    combined = dict(LAB_A_PROFILE, victim_username="LabVictimA",
                    victim_password_env="LAB_A_VICTIM_PW")
    _profiles_cfg([combined])
    monkeypatch.setenv("LAB_A_PW", ADMIN_PW)
    monkeypatch.setenv("LAB_A_VICTIM_PW", VICTIM_PW)
    _stub_vm_identity(monkeypatch)

    admin_cred = credentials.resolve_guest(vm_name="lab-a-01")
    victim_cred = credentials.resolve_victim(vm_name="lab-a-01")
    assert getattr(admin_cred, "profile", None) == "lab-a", (
        f"premise: the admin credential names the profile; got {admin_cred!r}"
    )
    assert getattr(victim_cred, "profile", None) == "lab-a", (
        f"premise: the victim credential names the SAME profile; got {victim_cred!r}"
    )

    factory = _RecordingFactory()
    monkeypatch.setattr(psdsessions, "DEFAULT", psdsessions.SessionPool(
        worker_factory=factory, max_sessions=8))
    cfg = Config(unrestricted=True)

    admin = guestexec.guest_run_ps(
        cfg, "lab-a-01", "Write-Output admin", cred=admin_cred)
    victim = guestexec.victim_run_ps(
        cfg, "lab-a-01", "Write-Output victim", cred=victim_cred)
    assert admin.get("ok") is True, admin
    assert victim.get("ok") is True, victim

    assert len(factory.spawned) == 2, (
        f"admin and victim credentials of one named profile opened "
        f"{len(factory.spawned)} pooled session(s); sharing would escalate "
        f"the victim identity into the admin session"
    )
    (admin_key, admin_script, admin_stdin), \
        (victim_key, victim_script, victim_stdin) = factory.spawned
    assert admin_key != victim_key, (
        f"the two roles must hold distinct session keys: "
        f"{admin_key!r} == {victim_key!r}"
    )
    # credential separation: each spawn's material carries exactly its own
    # identity (username quoted in the establishment script, password on the
    # worker's stdin channel), never the other role's
    assert "LabAdminA" in admin_script and "LabVictimA" not in admin_script
    assert "LabVictimA" in victim_script and "LabAdminA" not in victim_script
    assert admin_stdin and base64.b64decode(admin_stdin).decode() == ADMIN_PW, (
        "the admin worker's establishment must carry the admin secret only"
    )
    assert victim_stdin and base64.b64decode(victim_stdin).decode() == VICTIM_PW, (
        "the victim worker's establishment must carry the victim secret only"
    )


# ---------------------------------------------------------------------------
# C20 (plan section 3, [R1-1]): GUID-only calls resolve the canonical name
# ---------------------------------------------------------------------------


def test_guid_only_call_resolves_canonical_name_for_profiles(monkeypatch):
    """C20 (AC3-wiring): a GUID-addressed credentialed tool call (vm_name
    absent) resolves the VM's CANONICAL name before credential resolution,
    so a profiled VM is profile-resolved even when the caller only knows the
    GUID. Drives the real registered hyperv_guest_run_ps through
    mcp.call_tool with only vm_id set, vmident.resolve stubbed to a canonical
    name matching profile lab-a, and credentials.resolve_guest replaced by a
    recorder; the recorder must see the canonical name."""
    import asyncio

    from conftest import content_blocks

    import hyperv_mcp.server as server_module

    cfg = _profiles_cfg([LAB_A_PROFILE])

    seen = []

    def recorder(*args, **kwargs):
        seen.append(kwargs.get("vm_name"))
        return credentials.CredentialSet(
            "recorder-admin", "recorder-pass-123", "env")

    def fake_resolve(cfg_arg, vm_name="", vm_id=""):
        # the canonical-name seam: a GUID-addressed call resolves to the
        # display name that the profile patterns match against
        return vmident.VMRef(id=GUID, name="lab-a-01")

    monkeypatch.setattr(credentials, "resolve_guest", recorder)
    monkeypatch.setattr(vmident, "resolve", fake_resolve)
    _guest_exec_stub(monkeypatch)

    mod = importlib.reload(server_module)
    try:
        mod.bootstrap(config=cfg)
        result = asyncio.run(mod.get_mcp().call_tool(
            "hyperv_guest_run_ps",
            {"vm_id": GUID, "script": "Write-Output 'probe'"},
        ))
    finally:
        importlib.reload(server_module)
    blocks = content_blocks(result)
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    assert texts, "expected a text result block from the stubbed guest call"
    envelope = json.loads(texts[0].text)
    assert envelope.get("ok") is True, envelope
    assert seen == ["lab-a-01"], (
        f"resolver saw vm names for GUID-only call: {seen}"
    )


# ---------------------------------------------------------------------------
# C21 (plan section 5, [R1-4]): durable rows persist and bind the identity
# ---------------------------------------------------------------------------


def test_durable_job_and_relay_rows_persist_and_bind_credential_identity(
        monkeypatch):
    """C21 (AC17-durable): through the REAL per-test state store —
    (a) a job started with a profile credential survives a registry reopen
    and the reconstructed entry carries cred_profile/cred_username;
    (b) restoring it after the profile's identity CHANGED refuses with a
    CredentialError naming both the recorded and the re-resolved identities
    (the changed global env is set to a third identity to prove no global
    fallback);
    (c) a legacy row (cred_profile='' / cred_username='') on the SAME store
    restores by ref without error;
    (d) the same round-trip for a relay row."""
    cfg = _profiles_cfg([LAB_A_PROFILE])
    monkeypatch.setenv("LAB_A_PW", "lab-a-pass-123")
    cred = credentials.resolve_guest(vm_name="lab-a-01")
    assert getattr(cred, "profile", None) == "lab-a", (
        f"premise: the job credential names the profile; got {cred!r}"
    )

    # (a) start a job through the registry, then reopen on the same store
    monkeypatch.setattr(pswindows, "run_ps", FakePS([
        _ok({"pid": 4242, "job_dir": "C:\\Temp\\hyperv-mcp-job-g01"}),
    ]))
    started = guestjobs.job_start(cfg, "lab-a-01", "ping.exe", cred=cred)
    job_id = started["job_id"]
    guestjobs.clear_registry_for_tests()
    statestore.clear_store_cache_for_tests()
    restored = guestjobs._restore_entry(cfg, job_id, None)
    assert restored is not None, "the durable store lost the job row"
    assert restored.get("cred_profile") == "lab-a", (
        f"the restored job entry must carry the profile name: {restored!r}"
    )
    assert restored.get("cred_username") == "LabAdminA", (
        f"the restored job entry must carry the recorded username: {restored!r}"
    )

    # (b) the profile's identity changed: restore must refuse, naming both
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

    # (c) legacy row on the SAME store: no recorded identity, restores by ref
    credentials.init(cfg)
    statestore.store_for(cfg).job_upsert(statestore.JobRow(
        job_id="legacy-job-1", vm_name="lab-a-01", vm_id=GUID, pid=4321,
        started_at="2026-01-01T00:00:00Z", state=statestore.JOB_ACTIVE,
        cred_ref="env", owner=None,
    ))
    guestjobs.clear_registry_for_tests()
    legacy = guestjobs._restore_entry(cfg, "legacy-job-1", None)
    assert legacy is not None, "the legacy job row must restore"
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "LegacyAdmin")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "legacy-pass-789")
    legacy_cred = guestjobs._restored_credential(cfg, legacy)
    assert legacy_cred.username == "LegacyAdmin", (
        f"a legacy row restores by ref (global re-resolution); got "
        f"{legacy_cred.username!r}"
    )

    # (d) the same round-trip for a relay row
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    relay_started = relay.relay_start(cfg, "lab-a-01", 9319, cred=cred)
    relay_id = relay_started["relay_id"]
    relay.relay_stop(cfg, relay_id)
    relay.clear_registry_for_tests()
    statestore.clear_store_cache_for_tests()
    restored_relay = relay._restore_relay(cfg, relay_id, None)
    assert restored_relay is not None, "the durable store lost the relay row"
    assert restored_relay.get("cred_profile") == "lab-a", (
        f"the restored relay entry must carry the profile name: "
        f"{restored_relay!r}"
    )
    assert restored_relay.get("cred_username") == "LabAdminA", (
        f"the restored relay entry must carry the recorded username: "
        f"{restored_relay!r}"
    )


# ---------------------------------------------------------------------------
# C22 (plan section 1, [R1-6]): invalid password_env refused without echo
# ---------------------------------------------------------------------------


def test_invalid_password_env_values_rejected_without_echo():
    """C22 (AC2-adjacent): password_env must be an environment-variable
    NAME. A pasted secret value ('hunter2-canary-secret') and a non-name
    ('not a name!') are each refused at config load with a ConfigError
    naming the FIELD (password_env), and the offending VALUE is never
    echoed — the canary must not appear in the message."""
    canary = "hunter2-canary-secret"
    with pytest.raises(ConfigError, match="password_env") as excinfo:
        Config.from_dict({"credential_profiles": [
            dict(LAB_A_PROFILE, password_env=canary),
        ]})
    assert canary not in str(excinfo.value), (
        f"a pasted secret must never be echoed by the config error; got "
        f"{excinfo.value!r}"
    )
    with pytest.raises(ConfigError, match="password_env") as excinfo:
        Config.from_dict({"credential_profiles": [
            dict(LAB_A_PROFILE, password_env="not a name!"),
        ]})
    assert "not a name!" not in str(excinfo.value), (
        f"the invalid value must never be echoed by the config error; got "
        f"{excinfo.value!r}"
    )


# ---------------------------------------------------------------------------
# C23 (plan section 1, [R1-5]): the reserved profile name 'default'
# ---------------------------------------------------------------------------


def test_reserved_default_profile_name_rejected(monkeypatch):
    """C23 (plan section 1, [R1-5]): 'default' is the reserved sentinel for
    the no-profile resolution path (CredentialSet.profile == "default"), so
    a profile NAMED 'default' — or any case-folded variant — must be refused
    at config load with a ConfigError that names the offending profile and
    says it is reserved; a legitimate name still loads (positive control in
    the same test); the error never echoes a secret (the profile's secret
    env var is set to a canary for the leg)."""
    canary = "reserved-default-canary-777"
    monkeypatch.setenv("LAB_A_PW", canary)
    for reserved in ("default", "Default", "DEFAULT"):
        with pytest.raises(ConfigError, match="reserved") as excinfo:
            Config.from_dict({"credential_profiles": [
                dict(LAB_A_PROFILE, name=reserved),
            ]})
        message = str(excinfo.value)
        assert reserved.casefold() in message.casefold(), (
            f"the error must name the offending profile name {reserved!r}; "
            f"got {message!r}"
        )
        assert canary not in message, (
            f"a config-load error must never echo a secret; got {message!r}"
        )
    # positive control: a legitimate name still loads, order preserved
    cfg = Config.from_dict({"credential_profiles": [LAB_A_PROFILE]})
    assert [p.name for p in cfg.credential_profiles] == ["lab-a"]
