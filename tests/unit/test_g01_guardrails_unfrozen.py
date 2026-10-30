"""Unfrozen guardrails added by the issue-#30 implementation-review round.

The frozen census (test_g01_credential_profiles.py::C9) counts
``credentials.resolve_guest``/``resolve_victim`` ATTRIBUTE references, which is
the right frozen contract for the issue's AC9 — but it is structurally blind to
helper-mediated ``_cred_args(...)`` call sites, and the implementation review
found exactly such a site (the inline-mode ``hyperv_capture_evidence``
registration) left unmigrated when ``_cred_args`` gained its leading ``vm``
parameter: username landed in the VM slot, the password in the username slot,
and every frozen check stayed green. These guards close that class:

  GUARD1 — every ``_cred_args(`` call site in server.py passes a
  ``_vm_key(...)`` expression as its FIRST argument (AST census over the
  module, worktree-safe like the frozen census).

  GUARD2 — runtime twin: the inline-allowed ``hyperv_capture_evidence``
  registration resolves credentials for the TARGET VM (recorder sees
  vm_name='lab-a-01', username='alice', password NOT scrambled), through the
  real mcp.call_tool path.

This file is deliberately NOT part of the frozen checkpoint (it was authored
after the Phase 2.5 freeze by the fix round; the frozen bytes are untouched).
"""

import ast
import asyncio
import importlib
import json
from pathlib import Path

import pytest

from hyperv_mcp import credentials, vmident
from hyperv_mcp.config import Config

LAB_A_PROFILE = {
    "name": "lab-a",
    "vm_patterns": ["lab-a-*"],
    "username": "LabAdminA",
    "password_env": "LAB_A_PW",
}
GUID = "5b1e7a42-9f30-4c8b-8e2f-6c7d91a3b0d5"


def _server_source() -> str:
    return (Path(__file__).parents[2] / "src" / "hyperv_mcp" / "server.py").read_text(
        encoding="utf-8"
    )


def test_every_cred_args_site_passes_vm_key_first():
    """GUARD1: helper-mediated census. Every ``_cred_args(`` call in server.py
    passes ``_vm_key(...)`` as its first argument — the class of miss the
    implementation review caught (server.py inline capture_evidence resolved
    with username in the VM slot) can never reintroduce silently."""
    tree = ast.parse(_server_source())
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id == "_cred_args"):
            continue
        if not node.args:
            offenders.append(("no-arg call", node.lineno))
            continue
        first = node.args[0]
        ok = (
            isinstance(first, ast.Call)
            and isinstance(first.func, ast.Name)
            and first.func.id == "_vm_key"
        )
        if not ok:
            offenders.append(("first arg is not _vm_key(...)", node.lineno))
    assert offenders == [], (
        f"census: {len(offenders)} _cred_args site(s) not passing _vm_key "
        f"first in server.py: {offenders}"
    )


def test_inline_capture_evidence_resolves_for_target_vm(monkeypatch):
    """GUARD2 (runtime twin of the review probe): with
    allow_inline_credentials true and a profile matching the target VM, the
    inline capture_evidence path resolves the VM-scoped credential — the VM
    key is the VM, the username is the caller's inline username, and the
    password is the caller's inline password (never scrambled into the
    username slot)."""
    import hyperv_mcp.server as server_module

    seen = []
    real_resolve = credentials.resolve_guest

    def recorder(*args, **kwargs):
        seen.append(kwargs)
        return real_resolve(*args, **kwargs)

    monkeypatch.setenv("LAB_A_PW", "lab-a-pass-123")
    monkeypatch.setattr(credentials, "resolve_guest", recorder)
    # PRR-009: stub vmident at the boundary so the unit test never spawns a
    # real host powershell.exe (execution-verified spawn without this).
    monkeypatch.setattr(
        vmident, "resolve",
        lambda cfg_arg, vm_name="", vm_id="": vmident.VMRef(
            id=vm_id or GUID, name=vm_name or "lab-a-01"),
    )

    mod = importlib.reload(server_module)
    try:
        cfg = Config.from_dict({
            "unrestricted": True,
            "allow_inline_credentials": True,
            "credential_profiles": [LAB_A_PROFILE],
        })
        mod.bootstrap(config=cfg)
        result = asyncio.run(mod.get_mcp().call_tool(
            "hyperv_capture_evidence",
            {
                "vm_name": "lab-a-01", "vm_id": GUID,
                "width": 320, "height": 240, "ui_tree": True,
                "username": "alice", "password": "wonderland",
            },
        ))
        blocks = [c for c in result if getattr(c, "type", "") == "text"]
        texts = [c for c in blocks]
        _ = texts  # the envelope shape is not the oracle here
        assert seen, "the resolver was never called by the capture path"
        last = seen[-1]
        assert last.get("vm_name") == "lab-a-01", (
            f"the VM key must reach the resolver as vm_name; got {last!r}"
        )
        assert last.get("username") == "alice", (
            f"the inline username must reach the resolver as username; got "
            f"{last!r}"
        )
        assert last.get("password") == "wonderland", (
            f"the inline password must reach the resolver as password; got "
            f"{last!r}"
        )
    finally:
        importlib.reload(server_module)
        credentials.init(Config())
    _ = json  # keep the import honest for the envelope debugging leg


def test_victim_resolution_fail_closed_arms(monkeypatch):
    """GUARD3/GUARD4 (final-critic round 1, F2): resolve_victim's two
    fail-closed arms — pinned by no frozen check because C3/C4's bodies carry
    no victim assertions — ship pinned here:

    GUARD3 (ambiguity): a VM matching TWO profiles refuses victim resolution
    naming both profiles, exactly like the admin arm — a victim leg can
    never silently pick one of two matching admin profiles.

    GUARD4 (missing victim secret): a matched profile whose victim secret is
    unset refuses NAMING THE PROFILE and never falls back to the global
    victim credential, even with the global victim variables set.
    """
    from hyperv_mcp.credentials import CredentialError

    monkeypatch.setenv("LAB_A_PW", "lab-a-pass-123")
    monkeypatch.setenv("LAB_B_PW", "lab-b-pass-456")
    lab_b = dict(LAB_A_PROFILE, name="lab-b", vm_patterns=["lab-b-*"],
                 username="LabAdminB", password_env="LAB_B_PW")
    # GUARD3: an overlapping wildcard makes BOTH profiles match lab-a-01
    overlapping = Config.from_dict({
        "unrestricted": True,
        "credential_profiles": [
            LAB_A_PROFILE, dict(lab_b, vm_patterns=["*"]),
        ],
    })
    credentials.init(overlapping)
    with pytest.raises(CredentialError) as excinfo:
        credentials.resolve_victim(vm_name="lab-a-01")
    message = str(excinfo.value)
    assert "lab-a" in message and "lab-b" in message, (
        f"the victim ambiguity refusal must name BOTH profiles; got "
        f"{message!r}"
    )

    # GUARD4: matched profile without victim fields -> global victim env;
    # matched profile WITH victim fields but the secret unset -> refuse
    # naming the profile, never the global fallback (global victim vars SET
    # so a silent fallback would succeed and fail the refusal assert).
    monkeypatch.setenv("HYPERV_GUEST_VICTIM_USERNAME", "GlobalVictim")
    monkeypatch.setenv("HYPERV_GUEST_VICTIM_PASSWORD", "global-victim-pass")
    victim_profile = dict(
        LAB_A_PROFILE,
        victim_username="LabVictimA",
        victim_password_env="LAB_A_VICTIM_PW",
    )
    credentials.init(Config.from_dict({
        "unrestricted": True, "credential_profiles": [victim_profile],
    }))
    with pytest.raises(CredentialError) as excinfo:
        credentials.resolve_victim(vm_name="lab-a-01")
    message = str(excinfo.value)
    assert "lab-a" in message, (
        f"the missing-victim-secret refusal must name the profile; got "
        f"{message!r}"
    )
    # positive control: the same profile with the secret set resolves the
    # victim identity
    monkeypatch.setenv("LAB_A_VICTIM_PW", "victim-pass-789")
    cred = credentials.resolve_victim(vm_name="lab-a-01")
    assert cred.username == "LabVictimA" and cred.profile == "lab-a", (
        f"positive control: the victim identity must resolve; got {cred!r}"
    )
