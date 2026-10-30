"""Acceptance checks for issue #30 (per-VM credential profiles), trace
30-per-vm-credential-profiles, driver repro/check-g01.sh.

One test per check id C1..C11 and C15..C18 (C12/C13 re-run existing frozen
tests; C14 is the env-gated live test in tests/integration/test_hyperv_real.py).
Every test is self-contained, deterministic and network-free; placeholder
secrets only, always >= 3 characters (the redaction registry's floor).

RED at the base tree by construction: the `credential_profiles` config key,
the vm_name keyword on the resolvers, the CredentialSet.profile field, the
profile-aware job-restore binding and the profile-named session key do not
exist yet. The first failing statement of each test is its base signature.
"""

import ast
import dataclasses
import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from hyperv_mcp import credentials
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.credentials import (
    CredentialError,
    CredentialSet,
    resolve_guest,
    resolve_victim,
)

LAB_A_PROFILE = {
    "name": "lab-a",
    "vm_patterns": ["lab-a-*"],
    "username": "LabAdminA",
    "password_env": "LAB_A_PW",
}
LAB_B_PROFILE = {
    "name": "lab-b",
    "vm_patterns": ["lab-b-*"],
    "username": "LabAdminB",
    "password_env": "LAB_B_PW",
}


@pytest.fixture(autouse=True)
def _fresh_credentials():
    """Isolate the process-global resolver config per test (house pattern)."""
    credentials.init(Config())
    yield
    credentials.init(Config())


def _profiles_cfg(profiles, **extra):
    """Build + install a config carrying credential_profiles (AC1 schema)."""
    cfg = Config.from_dict({"credential_profiles": profiles, **extra})
    credentials.init(cfg)
    return cfg


def _profile_of(cred):
    """Read CredentialSet.profile without erroring at base (clean assert)."""
    return getattr(cred, "profile", "<no profile field>")


# ---------------------------------------------------------------------------
# AC1 / AC2 — config schema
# ---------------------------------------------------------------------------


def test_config_accepts_credential_profiles():
    """AC1 (C1): `credential_profiles` is accepted at schema_version 1; the
    declared order is preserved and the per-profile victim fields load."""
    cfg = Config.from_dict({
        "schema_version": 1,
        "credential_profiles": [
            LAB_A_PROFILE,
            dict(LAB_B_PROFILE, victim_username="LabVictimB",
                 victim_password_env="LAB_B_VICTIM_PW"),
        ],
    })
    assert [p.name for p in cfg.credential_profiles] == ["lab-a", "lab-b"], (
        "declared profile order must be preserved"
    )
    victim_hosting = cfg.credential_profiles[1]
    assert victim_hosting.victim_username == "LabVictimB"
    assert victim_hosting.victim_password_env == "LAB_B_VICTIM_PW"


def test_profile_rejects_inline_password():
    """AC2 (C2): a literal `password` inside a profile object is refused with
    a ConfigError naming the offending key; ANY unknown profile key (e.g.
    app_password_env) is refused the same way."""
    with pytest.raises(ConfigError, match="password"):
        Config.from_dict({"credential_profiles": [
            dict(LAB_A_PROFILE, password="never-in-config-123"),
        ]})
    with pytest.raises(ConfigError, match="app_password_env"):
        Config.from_dict({"credential_profiles": [
            dict(LAB_A_PROFILE, app_password_env="APP_PW"),
        ]})


# ---------------------------------------------------------------------------
# AC3..AC8 — resolver behavior
# ---------------------------------------------------------------------------


def test_profile_selected_by_vm_name(tmp_path):
    """AC3 (C3): resolve_guest(vm_name=...) returns the matching profile's
    triple (username/password/profile); matching is case-insensitive
    fnmatch (policy.vm_allowed semantics); the secret may come from
    password_env or password_file."""
    _profiles_cfg([LAB_A_PROFILE, LAB_B_PROFILE])
    cs = resolve_guest(
        environ={"LAB_A_PW": "lab-a-pass-123", "LAB_B_PW": "lab-b-pass-456"},
        vm_name="lab-a-01",
    )
    assert cs.username == "LabAdminA", (
        f"lab-a-01 must resolve through profile lab-a; got {cs.username!r}"
    )
    assert cs.password == "lab-a-pass-123"
    assert _profile_of(cs) == "lab-a"

    # case-insensitive pattern match, second profile
    cs_b = resolve_guest(
        environ={"LAB_A_PW": "lab-a-pass-123", "LAB_B_PW": "lab-b-pass-456"},
        vm_name="LAB-B-07",
    )
    assert cs_b.username == "LabAdminB"
    assert cs_b.password == "lab-b-pass-456"
    assert _profile_of(cs_b) == "lab-b"

    # password_file flavor: no env var carries the secret at all
    pw_file = tmp_path / "lab-a.pw"
    pw_file.write_text("file-pass-789", encoding="utf-8")
    file_profile = {k: v for k, v in LAB_A_PROFILE.items() if k != "password_env"}
    file_profile["password_file"] = str(pw_file)
    _profiles_cfg([file_profile])
    cs_file = resolve_guest(environ={}, vm_name="lab-a-01")
    assert cs_file.username == "LabAdminA"
    assert cs_file.password == "file-pass-789"
    assert _profile_of(cs_file) == "lab-a"


def test_unmatched_vm_falls_back_to_global_env():
    """AC4 (C4): a VM matching no profile pattern resolves through the global
    environment path exactly as before, with profile reported 'default'."""
    _profiles_cfg([LAB_A_PROFILE, LAB_B_PROFILE])
    cs = resolve_guest(
        environ={
            "HYPERV_GUEST_USERNAME": "GlobalAdmin",
            "HYPERV_GUEST_PASSWORD": "global-pass-123",
        },
        vm_name="build-vm-17",
    )
    assert cs.username == "GlobalAdmin", (
        f"unmatched VM must take the global env credential; got {cs.username!r}"
    )
    assert cs.password == "global-pass-123"
    assert _profile_of(cs) == "default"


def test_ambiguous_profile_match_fails_closed():
    """AC5 (C5): a VM name matching two profiles raises CredentialError
    naming BOTH profile names — never a silent first-match pick."""
    _profiles_cfg([
        LAB_A_PROFILE,
        {"name": "lab-wide", "vm_patterns": ["lab-*"],
         "username": "WideAdmin", "password_env": "WIDE_PW"},
    ])
    with pytest.raises(CredentialError, match="lab-a") as excinfo:
        resolve_guest(
            environ={"LAB_A_PW": "lab-a-pass-123", "WIDE_PW": "wide-pass-456"},
            vm_name="lab-a-01",
        )
    assert "lab-wide" in str(excinfo.value), (
        f"the error must name every matching profile; got {excinfo.value!r}"
    )


def test_matched_profile_missing_secret_does_not_fall_back():
    """AC6 (C6): a matched profile whose secret is missing/unreadable raises
    CredentialError naming the profile — the global credential being set
    must NOT be used as a fallback."""
    _profiles_cfg([LAB_A_PROFILE])
    with pytest.raises(CredentialError, match="lab-a") as excinfo:
        resolve_guest(
            environ={
                "HYPERV_GUEST_USERNAME": "GlobalAdmin",
                "HYPERV_GUEST_PASSWORD": "global-pass-123",
                # LAB_A_PW deliberately absent
            },
            vm_name="lab-a-01",
        )
    assert "GlobalAdmin" not in str(excinfo.value), (
        "no global fallback may be attempted for a matched profile"
    )


def test_profile_password_registered_for_redaction():
    """AC7 (C7): a resolved profile password rides _validated_password, so it
    is registered with the redaction registry and scrubbed from text."""
    _profiles_cfg([LAB_A_PROFILE])
    cs = resolve_guest(environ={"LAB_A_PW": "lab-a-secret-999"},
                       vm_name="lab-a-01")
    poisoned = f"error at line 1: $cred = new('{cs.password}') failed"
    cleaned = credentials.redact(poisoned)
    assert cs.password not in cleaned, (
        "a profile password must be scrubbed by the redaction registry"
    )
    assert "***REDACTED***" in cleaned


def test_credential_set_carries_profile_name():
    """AC8 (C8): CredentialSet gains profile (keyword field, default
    'default'); global and victim resolution report 'default' and the repr
    keeps hiding the password."""
    cs = resolve_guest(environ={
        "HYPERV_GUEST_USERNAME": "Administrator",
        "HYPERV_GUEST_PASSWORD": "global-pass-123",
    })
    assert _profile_of(cs) == "default", (
        f"global resolution must report profile 'default'; got {_profile_of(cs)!r}"
    )
    assert "global-pass-123" not in repr(cs)
    assert "global-pass-123" not in str(cs)
    victim = resolve_victim(environ={
        "HYPERV_GUEST_VICTIM_USERNAME": "victim",
        "HYPERV_GUEST_VICTIM_PASSWORD": "victim-pass-456",
    })
    assert _profile_of(victim) == "default", (
        "victim resolution without profile victim fields reports 'default'"
    )


# ---------------------------------------------------------------------------
# AC9 / AC10 / AC11 — server wiring and check-env
# ---------------------------------------------------------------------------

_RESOLVER_ATTRS = {"resolve_guest", "resolve_victim"}


def _unscoped_resolver_sites(source):
    """Census of credentials.resolve_guest/resolve_victim references in
    server.py that carry no VM context (issue #30 AC9).

    A reference is UNSCOPED when it is (a) a bare attribute used as a value
    (e.g. cred_factory=credentials.resolve_guest) or (b) the func of a call —
    possibly inside a lambda — whose expression has no `vm_name=` keyword
    anywhere in it. Attribute references are inherently non-def sites (the
    resolvers are never defined in server.py). Returns [(lineno, attr, kind)].
    """
    tree = ast.parse(source)
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    sites = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Attribute) and node.attr in _RESOLVER_ATTRS):
            continue
        if not (isinstance(node.value, ast.Name) and node.value.id == "credentials"):
            continue
        scope = None
        cur = node
        while cur is not None:
            cur = parents.get(cur)
            if cur is None:
                break
            if scope is None and isinstance(cur, ast.Lambda):
                scope = cur
            if isinstance(cur, ast.Call) and cur.func is node:
                if scope is None:
                    scope = cur
                break
        if scope is None:
            sites.append((node.lineno, node.attr, "bare reference without VM context"))
            continue
        has_vm_kw = any(
            isinstance(n, ast.Call)
            and any(kw.arg == "vm_name" for kw in n.keywords)
            for n in ast.walk(scope)
        )
        if not has_vm_kw:
            sites.append((node.lineno, node.attr, "call/lambda without vm_name= keyword"))
    return sites


def test_server_guest_credential_sites_pass_vm_name():
    """AC9 (C9): a static AST census of server.py finds ZERO
    resolve_guest/resolve_victim references without VM context — every guest
    tool must resolve credentials for its TARGET VM. At base the census
    counts the current unscoped sites, so the failure prints them."""
    server_path = (
        Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp" / "server.py"
    )
    source = server_path.read_text(encoding="utf-8")
    sites = _unscoped_resolver_sites(source)
    assert sites == [], (
        f"census: {len(sites)} unscoped credential sites in server.py: {sites}"
    )


def test_guest_tool_resolves_credentials_for_target_vm(monkeypatch):
    """AC10 (C10): the registered hyperv_guest_run_ps tool resolves
    credentials for the VM it addresses. Drives the real tool through
    mcp.call_tool with credentials.resolve_guest replaced by a recorder and
    guestexec.guest_run_ps stubbed, so the only observable is the vm_name
    the resolver was called with."""
    import asyncio

    from conftest import content_blocks

    import hyperv_mcp.guestexec as guestexec
    import hyperv_mcp.server as server_module

    seen = []

    def recorder(*args, **kwargs):
        seen.append(kwargs.get("vm_name"))
        return CredentialSet("recorder-admin", "recorder-pass-123", "env")

    monkeypatch.setattr(credentials, "resolve_guest", recorder)
    monkeypatch.setattr(
        guestexec, "guest_run_ps",
        lambda *a, **k: {"ok": True, "exit_code": 0, "stdout": "stub",
                         "stderr": "", "timed_out": False, "truncated": False},
    )

    mod = importlib.reload(server_module)
    try:
        mod.bootstrap(config=Config(
            unrestricted=True,
            allowed_vm_patterns=["lab-a-*"],
            psdirect_session_reuse=False,
        ))
        result = asyncio.run(mod.get_mcp().call_tool(
            "hyperv_guest_run_ps",
            {"vm_name": "lab-a-01", "script": "Write-Output 'probe'"},
        ))
    finally:
        importlib.reload(server_module)
    blocks = content_blocks(result)
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    assert texts, "expected a text result block from the stubbed guest call"
    envelope = json.loads(texts[0].text)
    assert envelope.get("ok") is True, envelope
    assert seen == ["lab-a-01"], f"resolver saw vm names: {seen}"


def test_check_env_lists_profiles_without_secrets(tmp_path):
    """AC11 (C11): --check-env with a profiles config exits 0 and lists each
    profile's name, VM patterns and secret SOURCE name (env var name), plus
    set/not-set status — never the secret VALUE (canary must not print)."""
    import os

    canary = "CANARY-lab-a-pw-value-42"
    cfg_file = tmp_path / "profiles.json"
    cfg_file.write_text(json.dumps({
        "schema_version": 1,
        "credential_profiles": [LAB_A_PROFILE],
    }), encoding="utf-8")
    src = Path(__file__).resolve().parents[2] / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src)
    env["HYPERV_MCP_CONFIG"] = str(cfg_file)
    env["LAB_A_PW"] = canary
    proc = subprocess.run(
        [sys.executable, "-m", "hyperv_mcp.server", "--check-env"],
        env=env, capture_output=True, text=True, timeout=90,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"check-env rc={proc.returncode}; output:\n{out}"
    assert "lab-a" in out, f"profile name missing from --check-env output:\n{out}"
    assert "lab-a-*" in out, f"profile VM patterns missing from output:\n{out}"
    assert "LAB_A_PW" in out, f"secret source name missing from output:\n{out}"
    assert canary not in out, "--check-env printed the profile secret VALUE"


# ---------------------------------------------------------------------------
# AC15 / AC16 — profile scope and application-account separation
# ---------------------------------------------------------------------------


def test_guest_profile_scope_shared_and_independent_vms():
    """AC15 (C15): two independent VMs each resolve their own declared
    profile; a VM named in exactly one profile (a shared box) resolves that
    one profile, not an ambiguity; CredentialSet carries exactly the four
    identity fields — no application-account or test-record fields."""
    profiles = [
        LAB_A_PROFILE,
        LAB_B_PROFILE,
        dict(LAB_B_PROFILE, name="lab-b-shared", vm_patterns=["shared-vm-9"]),
    ]
    _profiles_cfg(profiles)
    field_names = tuple(f.name for f in dataclasses.fields(CredentialSet))
    assert field_names == ("username", "password", "source", "profile"), (
        f"CredentialSet fields must stay identity-only; got {field_names}"
    )
    env = {"LAB_A_PW": "lab-a-pass-123", "LAB_B_PW": "lab-b-pass-456"}
    a = resolve_guest(environ=env, vm_name="lab-a-01")
    b = resolve_guest(environ=env, vm_name="lab-b-04")
    assert (a.username, _profile_of(a)) == ("LabAdminA", "lab-a")
    assert (b.username, _profile_of(b)) == ("LabAdminB", "lab-b")
    # a shared VM named in exactly one profile resolves that one profile
    shared = resolve_guest(environ=env, vm_name="shared-vm-9")
    assert _profile_of(shared) == "lab-b-shared"
    assert shared.username == "LabAdminB"


def test_application_credentials_are_not_guest_profiles():
    """AC16 (C16): application-account-shaped keys inside a profile object
    are rejected with a ConfigError naming the key; and resolver failures
    name keys/profiles, never secret VALUES (redaction never emits a
    configured profile's secret)."""
    with pytest.raises(ConfigError, match="app_username"):
        Config.from_dict({"credential_profiles": [
            {"name": "app", "vm_patterns": ["app-*"], "username": "AppAccount",
             "app_username": "svc-app", "app_password_env": "APP_PW"},
        ]})
    _profiles_cfg([LAB_A_PROFILE, LAB_B_PROFILE])
    canary = "lab-b-canary-secret-777"
    try:
        # lab-a matches but LAB_A_PW is unset; lab-b's secret IS set
        resolve_guest(environ={"LAB_B_PW": canary}, vm_name="lab-a-01")
    except CredentialError as exc:
        message = str(exc)
    else:
        raise AssertionError(
            "a matched profile with a missing secret must fail closed (AC6)"
        )
    assert "lab-a" in message, f"the error must name the profile: {message!r}"
    assert canary not in message, "resolver errors must not echo secret values"
    assert canary not in credentials.redact(message)


# ---------------------------------------------------------------------------
# AC17 / AC18 — job-restore identity binding and pooled session key
# ---------------------------------------------------------------------------


def test_restored_job_binds_credential_identity(monkeypatch):
    """AC17 (C17): a persisted job row records cred_profile/cred_username;
    restoring re-resolves through the NAMED PROFILE for the row's vm_name
    (even when the global env claims a different user), refuses when the
    recorded username would change, refuses inline rows as today, and
    refuses when the profile no longer matches the row's VM."""
    from hyperv_mcp import guestjobs

    cfg = _profiles_cfg([LAB_A_PROFILE])
    monkeypatch.setenv("LAB_A_PW", "lab-a-pass-123")
    # the global env claims a DIFFERENT user; the profile binding must win
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "globaladmin")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "global-pass-456")

    row = {"job_id": "job-1", "cred_ref": "env", "cred_profile": "lab-a",
           "cred_username": "LabAdminA", "vm_name": "lab-a-01"}
    cred = guestjobs._restored_credential(cfg, dict(row))
    assert cred.username == "LabAdminA", (
        f"a restored job must re-resolve through its profile, not the global "
        f"env; got {cred.username!r}"
    )
    assert _profile_of(cred) == "lab-a"

    # no profile recorded, but a username IS: re-resolving under a DIFFERENT
    # username (alice) must refuse — silent account switching is gone
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "alice")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "alice-pass-789")
    with pytest.raises(CredentialError):
        guestjobs._restored_credential(
            cfg, dict(row, cred_profile="", cred_username="LabAdminA"))

    # inline rows keep refusing as today
    with pytest.raises(CredentialError, match="inline"):
        guestjobs._restored_credential(cfg, dict(row, cred_ref="inline"))

    # the profile no longer matches the row's VM: refuse, naming both
    moved = Config.from_dict({"credential_profiles": [
        dict(LAB_A_PROFILE, vm_patterns=["lab-z-*"]),
    ]})
    credentials.init(moved)
    with pytest.raises(CredentialError) as excinfo:
        guestjobs._restored_credential(moved, dict(row))
    assert "lab-a-01" in str(excinfo.value), (
        f"the refusal must name the row's VM: {excinfo.value!r}"
    )
    assert "lab-a" in str(excinfo.value)


def test_pooled_session_key_uses_profile_name():
    """AC18 (C18): psdsessions.credential_profile returns the real profile
    NAME for a named CredentialSet; the 'default' profile keeps today's
    interim HMAC behavior (same credential -> same string, different
    password -> different string); SessionKey.__repr__ still redacts
    cred_profile."""
    from hyperv_mcp import psdsessions

    field_names = tuple(f.name for f in dataclasses.fields(CredentialSet))
    assert "profile" in field_names, (
        f"CredentialSet must gain the profile field for named profiles; "
        f"fields: {field_names}"
    )
    named = CredentialSet("sess-user", "named-pass-123", "env", "lab-a")
    assert psdsessions.credential_profile(named) == "lab-a"

    same_a = psdsessions.credential_profile(
        CredentialSet("u1", "same-pass-123", "env"))
    same_b = psdsessions.credential_profile(
        CredentialSet("u1", "same-pass-123", "env"))
    other = psdsessions.credential_profile(
        CredentialSet("u1", "other-pass-456", "env"))
    assert same_a == same_b, "the interim default profile must be stable"
    assert same_a != other, "a different password must change the profile"

    key = psdsessions.SessionKey("guid-1", "prof-secret-ish", None, None)
    assert "prof-secret-ish" not in repr(key), (
        "SessionKey.__repr__ must redact the cred_profile component"
    )
    assert "cred_profile=<redacted>" in repr(key)
