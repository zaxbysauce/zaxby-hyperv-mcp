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

from hyperv_mcp import credentials
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
