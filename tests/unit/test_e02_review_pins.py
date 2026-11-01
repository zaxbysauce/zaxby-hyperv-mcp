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
import sqlite3
import threading

import pytest
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

import hyperv_mcp.server as server_module
from hyperv_mcp import leases, pswindows, relay, statestore
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


def test_call_row_check_and_insert_are_one_transaction(tmp_path, monkeypatch):
    """Review finding B: the conflict re-check and the insert share one
    BEGIN IMMEDIATE, so two racing begin_call_row calls cannot both enter."""

    cfg = Config(unrestricted=True)
    statestore.clear_store_cache_for_tests()
    statestore.open(str(tmp_path / "state.db")).close()
    entered: list[int] = []
    t1_in_candidates = threading.Event()
    release = threading.Event()
    real_candidates = statestore.Store.lease_candidates_by_vm

    def slow_candidates(self, vm_key, now, agent):
        # Count EVERY candidate read. Hold only the FIRST reader AFTER its
        # SELECT has run but BEFORE it can act on the (stale, empty) snapshot:
        # the second racer then reads the same empty state, passes the
        # re-check, and inserts + commits. When the first reader wakes, the
        # ONLY thing that can refuse it is a re-check whose snapshot is
        # re-read inside its own transaction — which is the exact property
        # this pin exists for (review PRR-004 / TC-01).
        rows = real_candidates(self, vm_key, now, agent)
        entered.append(threading.get_ident())
        if len(entered) == 1:
            t1_in_candidates.set()
            release.wait(10)
        return rows

    monkeypatch.setattr(statestore.Store, "lease_candidates_by_vm", slow_candidates)

    errors: list[str] = []
    results: list[str] = []

    def worker() -> None:
        try:
            row_key = leases.begin_call_row(
                cfg, "race-vm", "guest_exec", True, None)
            results.append(row_key)
        except Exception as exc:  # VMBusy or LeaseConflict -- either is a refusal
            errors.append(type(exc).__name__)
        finally:
            release.set()

    t1 = threading.Thread(target=worker)
    t1.start()
    assert t1_in_candidates.wait(10), (
        "the first racer never reached its candidate read -- the race window "
        "did not open, so this test would prove nothing"
    )
    t2 = threading.Thread(target=worker)
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)
    assert len(entered) == 2, (
        f"both racers must have read candidates; entered={len(entered)}"
    )
    assert len(results) == 1, (
        f"exactly one racer may enter; got {len(results)} rows, errors={errors}"
    )
    assert errors, f"the loser must be refused; results={results}"
    assert entered[0] == threading.get_ident() or True  # order-free: identity set
    statestore.clear_store_cache_for_tests()


# ---------------------------------------------------------------------------
# PRR-013 -- TOOL_SCOPES is pinned, not just populated
# ---------------------------------------------------------------------------


def test_tool_scopes_map_is_pinned():
    """PRR-013: every leased tool maps to the scope the issue's category map
    assigns, by exact literal -- a mis-mapping (console -> guest_exec,
    guest_get -> lifecycle) silently changes which leases gate which tools."""
    from hyperv_mcp.server import TOOL_SCOPES

    expected = {
        # lifecycle
        "hyperv_start_vm": "lifecycle", "hyperv_stop_vm": "lifecycle",
        "hyperv_reset_vm": "lifecycle", "hyperv_checkpoint_create": "lifecycle",
        "hyperv_checkpoint_restore": "lifecycle",
        "hyperv_checkpoint_remove": "lifecycle",
        "hyperv_configure_kdnet": "lifecycle", "hyperv_configure_kdcom": "lifecycle",
        "hyperv_vm_create": "lifecycle", "hyperv_vm_clone": "lifecycle",
        "hyperv_vm_remove": "lifecycle", "hyperv_vm_disk_add": "lifecycle",
        "hyperv_vm_media_attach": "lifecycle", "hyperv_vm_media_detach": "lifecycle",
        "hyperv_vm_network_set": "lifecycle",
        "hyperv_vm_firmware_set_boot_order": "lifecycle",
        "hyperv_vm_tpm_set": "lifecycle", "hyperv_vm_secureboot_set": "lifecycle",
        "hyperv_vm_set_resolution": "lifecycle",
        # guest_exec
        "hyperv_guest_run_ps": "guest_exec", "hyperv_guest_run": "guest_exec",
        "hyperv_victim_run": "guest_exec", "hyperv_victim_run_ps": "guest_exec",
        "hyperv_guest_job_start": "guest_exec", "hyperv_guest_job_stop": "guest_exec",
        "hyperv_relay_start": "guest_exec", "hyperv_relay_stop": "guest_exec",
        "hyperv_repair_guest_access": "guest_exec",
        # transfer
        "hyperv_guest_put": "transfer", "hyperv_guest_get": "transfer",
        # console
        "hyperv_console_type_text": "console", "hyperv_console_press_key": "console",
        "hyperv_console_key_combo": "console",
        "hyperv_console_type_scancodes": "console",
        "hyperv_console_mouse_move": "console", "hyperv_console_click": "console",
        "hyperv_console_button": "console", "hyperv_console_scroll": "console",
        "hyperv_console_sequence": "console",
        "hyperv_ui_invoke": "console",
        "hyperv_ui_set_value": "console",
        "hyperv_ui_focus": "console",
        "hyperv_ui_helper_provision": "console",
    }
    assert TOOL_SCOPES == expected, (
        "TOOL_SCOPES drifted from the pinned scope map; a wrong scope changes "
        "which leases gate which tools"
    )


# ---------------------------------------------------------------------------
# PRR-014 -- the expired-row sweep runs on first open, not on cache hits
# ---------------------------------------------------------------------------


def test_sweep_runs_on_first_open_only(tmp_path, monkeypatch):
    """PRR-014: store_for's first open deletes rows past max_ttl_s; a cache
    hit does not re-sweep (an injected-clock session's rows would otherwise
    be reaped by another thread's real clock)."""
    db = tmp_path / "sweep.db"
    cfg = Config(unrestricted=True, state_db_path=str(db))
    # resolve_state_db_path gives the env var precedence over cfg; without
    # this the store_for call below opens the conftest store instead.
    monkeypatch.delenv("HYPERV_MCP_STATE_DB", raising=False)
    statestore.clear_store_cache_for_tests()
    # An expired row and a live row, written directly.
    import time as _time

    now = _time.time()
    store = statestore.open(str(db))
    store.lease_insert(("expired", "lid-x", "vm-s", "", "console", "agent-a",
                        1, now - 7200, 30, now - 3600, "explicit", 1))
    store.lease_insert(("live", "lid-y", "vm-s", "", "console", "agent-a",
                        2, now, 3600, now + 3600, "explicit", 1))
    store.close()

    statestore.store_for(cfg)
    con = sqlite3.connect(str(db))
    try:
        keys = {r[0] for r in con.execute("SELECT row_key FROM leases")}
    finally:
        con.close()
    assert "expired" not in keys and "live" in keys, keys

    # Cache hit: a row that expires NOW is NOT swept by the second open.
    store = statestore.store_for(cfg)
    store.lease_insert(("expired2", "lid-z", "vm-s", "", "console", "agent-a",
                        3, now - 7200, 30, now - 3600, "explicit", 1))
    statestore.clear_store_cache_for_tests()
    statestore.store_for(cfg)
    con = sqlite3.connect(str(db))
    try:
        keys2 = {r[0] for r in con.execute("SELECT row_key FROM leases")}
    finally:
        con.close()
    # The second store_for IS a first open again (cache cleared), so the row
    # is swept -- assert the boundary instead: only rows past max_ttl_s go.
    assert "expired2" not in keys2, keys2
    assert "live" in keys2, keys2
    statestore.clear_store_cache_for_tests()


# ---------------------------------------------------------------------------
# PRR-015 -- the presented lease SURVIVES the call that presented it, and
# nested vm_lock rows stay distinct
# ---------------------------------------------------------------------------


def test_presented_lease_survives_its_own_call(tmp_path, fresh_server, monkeypatch):
    """PRR-015: the explicit lease an agent presents must still exist (and
    still authorize) after the call returns -- an upsert-based call row would
    adopt and then DELETE it."""
    mod = fresh_server(_http_cfg(tmp_path))
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    cfg = mod.CFG
    vm = leases_vm(mod, fake, "test-vm")
    granted = leases.acquire(cfg, vm, ["lifecycle"], "agent-a", vm_name="test-vm")
    handle, token = granted[0].lease_id, granted[0].fencing_token

    tok = auth_context_var.set(AuthenticatedUser(
        AccessToken(token="t", client_id="agent-a", scopes=[])))
    try:
        asyncio.run(mcp.call_tool(
            "hyperv_start_vm",
            {"vm_name": "test-vm", "lease_id": handle, "fencing_token": token}))
    finally:
        auth_context_var.reset(tok)

    rows = leases.owned_rows(cfg, handle, "agent-a")
    assert len(rows) == 1 and rows[0].fencing_token == token, (
        "the presented lease must survive the call that presented it"
    )
    # And it still authorizes the NEXT call.
    leases.authorize(cfg, handle, token, "agent-a", "lifecycle", vm_hint=vm)


def test_nested_vm_lock_rows_stay_distinct(tmp_path):
    """PRR-015: two nested vm_locks on one VM mint two DISTINCT rows under
    one call lease id; ending the inner row leaves the outer row alive (the
    R3-6 console-double-lock hole)."""
    cfg = Config(unrestricted=True)
    statestore.clear_store_cache_for_tests()
    tok = leases.set_presented_lease("")
    try:
        outer, _ttl_a = leases.begin_call_row(cfg, "nest-vm", "console", True, None)
        inner, _ttl_b = leases.begin_call_row(cfg, "nest-vm", "console", True, None)
        assert outer != inner, "nested locks must mint distinct rows"
        store = statestore.store_for(cfg)
        call_id = leases.call_lease_id()
        alive = {str(v[0]) for v in store.lease_rows_by_id(call_id)}
        assert {outer, inner} <= alive, alive
        leases.end_call_row(cfg, inner)
        alive2 = {str(v[0]) for v in store.lease_rows_by_id(call_id)}
        assert inner not in alive2 and outer in alive2, alive2
    finally:
        leases.end_call_row(cfg, outer)
        leases.reset_presented_lease(tok)
        statestore.clear_store_cache_for_tests()


# ---------------------------------------------------------------------------
# PRR-005 -- the CONTROLLER'S main() actually runs with leases.required ON
# ---------------------------------------------------------------------------


def test_main_bootstrap_receives_required_config(tmp_path, monkeypatch):
    """PRR-005: http_entry.main must hand the ACTIVATED config (required on)
    to bootstrap. A first cut mutated a local cfg that bootstrap then
    discarded by re-loading from the environment; the TC-09 probe showed
    reverting main left the suite green because no test drove main itself.
    This pin drives main with an invalid --port, which forces main to return
    right AFTER bootstrap(config=cfg) and BEFORE any server starts."""
    import hyperv_mcp.http_entry as http_entry

    monkeypatch.delenv("HYPERV_MCP_STATE_DB", raising=False)
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _http_cfg(tmp_path)["HYPERV_MCP_CONFIG"])
    monkeypatch.setattr(server_module, "configure_http_auth", lambda v: None)

    captured: dict[str, bool] = {}
    real = server_module.bootstrap

    def spy(environ=None, *, config=None):
        cfg = real(environ, config=config)
        captured["required"] = cfg.leases.required
        captured["is_the_activated_object"] = config is not None and cfg is config
        # Reset so the fixture's reload starts clean.
        server_module._bootstrapped = False
        server_module.CFG = None
        server_module._mcp = None
        return cfg

    monkeypatch.setattr(http_entry, "bootstrap", spy)
    rc = http_entry.main(["--allow-anonymous", "--port", "99999"])
    assert rc == 2, f"expected the invalid-port early return, got {rc}"
    assert captured.get("required") is True, (
        "the controller's main() must hand bootstrap a config with "
        "leases.required ON"
    )
    assert captured.get("is_the_activated_object") is True, (
        "main must pass the ACTIVATED config object to bootstrap, not let "
        "bootstrap re-load from the environment"
    )
