"""Issue #23 review-round pins: the three mechanisms the implementation
reviewer probe-confirmed as absent from the first cut. Each test here fails
against the pre-fix tree by construction.

- test_http_controller_defaults_leases_required: the shared controller's own
  entry point turns leases.required ON (the plan's MINOR-12 mechanism; frozen
  AC11 sets the flag by hand and could never see it missing).
- test_env_override_forces_leases_required: HYPERV_MCP_LEASES_REQUIRED=1.
- test_presented_lease_lets_its_own_call_through: an UNATTRIBUTED (stdio)
  caller that acquires a lease and then PRESENTS it on the next call is not
  blocked by its own lease -- adoption is what keeps the documented
  acquire-then-call workflow usable on stdio, where agent_id is always None.
- test_foreign_lease_blocks_unleased_relay_stop: relay_stop resolves its VM
  from the relay store row, so another agent's lease blocks it (the relay
  transport takes no vm_lock; the guard is its only enforcement).
- test_call_row_check_and_insert_are_one_transaction: two threads racing
  begin_call_row on one VM cannot both enter -- the conflict re-check, the
  counter bump and the insert share one BEGIN IMMEDIATE (review finding B).
"""

from __future__ import annotations

import asyncio
import json
import threading

import pytest
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

import hyperv_mcp.server as server_module
from hyperv_mcp import leases, pswindows, relay
from hyperv_mcp.config import Config


class FakePS:
    """Resolve by name to a stable per-name GUID; answer everything else OK."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        import re
        import uuid

        m = re.search(r"ElementName -eq '([^']*)'", script)
        if m and script.rstrip().endswith("$vmTarget"):
            guid = str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1))).upper()
            return pswindows.PSResult(stdout=guid + "\n", returncode=0)
        return pswindows.PSResult(stdout='{"ok": true}', returncode=0)


@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod
    yield make
    importlib.reload(server_module)


import importlib  # noqa: E402  (after the fixture for readability parity)


def _http_cfg(tmp_path):
    doc = {
        "allowed_vm_patterns": ["test-*"],
        "destructive": {"relay": True},
    }
    cfg = tmp_path / "http-cfg.json"
    cfg.write_text(json.dumps(doc), encoding="utf-8")
    return {"HYPERV_MCP_CONFIG": str(cfg),
            "HYPERV_MCP_STATE_DB": str(tmp_path / "state.db")}


def test_http_controller_defaults_leases_required(tmp_path, monkeypatch):
    """End-to-end through the controller's real config path: load -> force
    required on -> bootstrap runs with THAT object. A first cut mutated a
    local cfg that bootstrap then discarded by re-loading from the
    environment; its helper-only pin could not see that, and the
    skip-activation mutant survived it. This pin drives load ->
    controller_leases_cfg -> bootstrap and asserts the bootstrapped CFG."""
    from hyperv_mcp import http_entry

    loaded = Config.load(_http_cfg(tmp_path))
    assert loaded.leases.required is False, "precondition: config default is off"
    assert http_entry.controller_leases_cfg(loaded).leases.required is True
    assert loaded.leases.required is False, "the loaded config must be untouched"

    captured: dict[str, bool] = {}
    real_bootstrap = server_module.bootstrap

    def spy_bootstrap(environ=None, *, config=None):
        cfg = real_bootstrap(environ, config=config)
        captured["required"] = cfg.leases.required
        # Leave the module bootstrapped-state clean for later tests.
        server_module._bootstrapped = False
        server_module.CFG = None
        server_module._mcp = None

        return cfg

    monkeypatch.setattr(http_entry, "bootstrap", spy_bootstrap)
    # The REAL load path, aimed at the tmp config: patching load_controller_config
    # itself would replace the function under test (the skip-activation mutant
    # survived exactly that).
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _http_cfg(tmp_path)["HYPERV_MCP_CONFIG"])
    cfg = http_entry.load_controller_config()
    assert cfg.leases.required is True
    http_entry.bootstrap(config=cfg)
    assert captured.get("required") is True, (
        "the controller's bootstrap must run with leases.required ON"
    )


def test_env_override_forces_leases_required():
    loaded = Config.load({"HYPERV_MCP_LEASES_REQUIRED": "1"})
    assert loaded.leases.required is True
    off = Config.load({})
    assert off.leases.required is False


def test_presented_lease_lets_its_own_call_through(tmp_path, fresh_server, monkeypatch):
    mod = fresh_server(_http_cfg(tmp_path))
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    cfg = mod.CFG

    # UNATTRIBUTED: no auth_context_var -- the stdio shape, agent_id None.
    acquired = leases.acquire(
        cfg, leases_vm(mod, fake, "test-vm"), ["lifecycle"], None, vm_name="test-vm"
    )
    handle = acquired[0].lease_id

    def envelope(tool, args):
        result = asyncio.run(mcp.call_tool(tool, args))
        content = result.content if hasattr(result, "content") else result[0]
        texts = [b.text for b in content if getattr(b, "type", "") == "text"]
        return json.loads(texts[0])

    env = envelope("hyperv_start_vm",
                   {"vm_name": "test-vm", "lease_id": handle,
                    "fencing_token": acquired[0].fencing_token})
    # The two assertions that matter: the agent is NOT blocked by its own
    # lease, and the call actually ran. (The fake answers only identity and
    # Start-VM, so the post-start state wait legitimately reports transport;
    # that is the fake's scope, not the lease mechanism.)
    assert env.get("error_class") != "lease_conflict", (
        "a caller presenting its OWN lease must not be blocked by it: "
        f"{json.dumps(env)[:300]}"
    )
    assert env.get("error_class") != "fenced", json.dumps(env)[:300]
    assert any("Start-VM" in s for s in fake.scripts), (
        "the presented-lease call must actually run"
    )


def leases_vm(mod, fake, name):
    """The resolved GUID exactly as vmident returns it: LOWERCASE (VMRef.id)."""
    import uuid

    _ = mod, fake
    return str(uuid.uuid5(uuid.NAMESPACE_OID, name)).lower()


def test_foreign_lease_blocks_unleased_relay_stop(tmp_path, fresh_server, monkeypatch):
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "placeholder-pass")
    mod = fresh_server(_http_cfg(tmp_path))
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    cfg = mod.CFG
    relay.clear_registry_for_tests()
    try:
        vm_key = leases_vm(mod, fake, "test-vm")
        # agent-a holds lifecycle on the VM and owns a relay on it.
        token_a = auth_context_var.set(
            AuthenticatedUser(AccessToken(token="t", client_id="agent-a", scopes=[]))
        )
        try:
            started = asyncio.run(mcp.call_tool(
                "hyperv_relay_start", {"vm_name": "test-vm", "guest_port": 18080}))
        finally:
            auth_context_var.reset(token_a)
        content = started.content if hasattr(started, "content") else started[0]
        texts = [b.text for b in content if getattr(b, "type", "") == "text"]
        started_env = json.loads(texts[0])
        relay_id = started_env.get("relay_id") or ""
        assert relay_id, f"relay start failed: {json.dumps(started_env)[:300]}"

        # agent-b holds a lifecycle lease on that VM; the relay's OWNER then
        # tries to stop it UNLEASED. The relay transport takes no vm_lock, so
        # the guard is the only enforcement -- it must resolve the VM from the
        # relay store row (owner-filtered peek) and refuse.
        token_b = auth_context_var.set(
            AuthenticatedUser(AccessToken(token="t", client_id="agent-b", scopes=[]))
        )
        try:
            leases.acquire(cfg, vm_key, ["lifecycle"], "agent-b", vm_name="test-vm")
        finally:
            auth_context_var.reset(token_b)
        token_a2 = auth_context_var.set(
            AuthenticatedUser(AccessToken(token="t", client_id="agent-a", scopes=[]))
        )
        try:
            result = asyncio.run(mcp.call_tool(
                "hyperv_relay_stop", {"relay_id": relay_id}))
        finally:
            auth_context_var.reset(token_a2)
        content = result.content if hasattr(result, "content") else result[0]
        texts = [b.text for b in content if getattr(b, "type", "") == "text"]
        env = json.loads(texts[0])
        assert env.get("error_class") == "lease_conflict", (
            "an unleased relay_stop by the owner on a leased VM must be "
            f"refused lease_conflict; got {json.dumps(env)[:300]}"
        )
    finally:
        relay.clear_registry_for_tests()


def test_call_row_check_and_insert_are_one_transaction(tmp_path):
    """Review finding B: the conflict re-check and the insert share one
    BEGIN IMMEDIATE, so two racing begin_call_row calls cannot both enter."""
    from hyperv_mcp import statestore as ss

    db = tmp_path / "race.db"
    cfg = Config(unrestricted=True, state_db_path=str(db))
    ss.clear_store_cache_for_tests()
    entered: list[str] = []
    gate = threading.Event()
    release = threading.Event()
    real_candidates = ss.Store.lease_candidates_by_vm

    def slow_candidates(self, vm_key, now, agent):
        rows = real_candidates(self, vm_key, now, agent)
        if vm_key == "race-vm" and not gate.is_set():
            entered.append(threading.get_ident())
            if len(entered) == 1:
                gate.set()
                release.wait(10)  # hold the first reader inside its txn window
        return rows

    errors: list[str] = []
    results: list[str] = []

    def worker(n: int) -> None:
        try:
            row_key = leases.begin_call_row(
                cfg, "race-vm", "guest_exec", True, None)
            results.append(row_key)
        except Exception as exc:  # VMBusy or LeaseConflict -- either is a refusal
            errors.append(type(exc).__name__)
        finally:
            release.set()

    t1 = threading.Thread(target=worker, args=(1,))
    t1.start()
    gate.wait(10)
    t2 = threading.Thread(target=worker, args=(2,))
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)
    _ = slow_candidates
    assert len(results) == 1, (
        f"exactly one racer may enter; got {len(results)} rows, errors={errors}"
    )
    assert errors, f"the loser must be refused; results={results}"
    ss.clear_store_cache_for_tests()
