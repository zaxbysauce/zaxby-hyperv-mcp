"""Issue #23 acceptance checks (trace issue-23-leases, class E-02): the
durable lease store — fencing tokens, conflict hygiene, expiry, ownership,
required mode and TTL bounds.

ACs carried (01-issue-summary.md):
  AC4  test_fencing_token_strictly_increases
  AC5  test_fencing_token_monotonic_across_reopen
  AC6  test_conflict_reports_holder_without_secrets
  AC7  test_lifecycle_scope_conflicts_with_every_scope
  AC8  test_expired_lease_taken_over_and_old_token_fenced
  AC9  test_lease_use_requires_owner_agent
  AC10 test_unleased_call_blocked_by_other_agents_lease
  AC11 test_leases_required_on_controller_and_ttl_bounds

RED at base, GREEN after the fix — the RED signature for this whole file is
the module-level import: at base c1da890 there IS no hyperv_mcp.leases, so
collection fails with ImportError: cannot import name 'leases'. That is the
expected new-surface signature, not an authoring bug; after the fix lands,
every check in this file must pass as written.

What is faked: PowerShell (pswindows.run_ps answers by-name VM resolution
legs with a stable per-name GUID and benign start/state JSON — the RECORDING
is the oracle for "no mutation ran"); and TIME — every TTL assertion runs on
an injected clock handed to statestore.Store(path, clock=...) through the
statestore.store_for(cfg) seam. No time.sleep anywhere in this file.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import re
import uuid

import pytest
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

import hyperv_mcp.server as server_module
from hyperv_mcp import leases, pswindows, statestore
from hyperv_mcp.config import Config


class FakeClock:
    """Deterministic wall clock for Store(path, clock=...)."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


def _clock_store(monkeypatch, db: str, clock: FakeClock) -> statestore.Store:
    """Hand the cfg-driven leases API a Store whose clock is `clock`.

    DECLARED GUESS: the production leases API is expected to resolve its
    store through statestore.store_for(cfg) — the repo's established cached
    path — so that is the one seam a test needs to inject
    Store(path, clock=...). The database is opened once through the real
    open() first so the schema exists; the patch (and the same function
    re-bound on the leases module, if it holds its own reference) redirects
    every cfg-driven call to the clock-injected Store. The caller owns
    closing the returned store.
    """
    statestore.open(str(db)).close()
    store = statestore.Store(str(db), clock=clock)

    def _fake_store_for(cfg, environ=None):
        return store

    monkeypatch.setattr(statestore, "store_for", _fake_store_for)
    if hasattr(leases, "store_for"):
        monkeypatch.setattr(leases, "store_for", _fake_store_for, raising=False)
    return store


def _raises(expected: tuple, fn, *args, **kwargs) -> bool:
    """Manual pytest.raises: True when fn(*args) raises one of `expected`.

    Used instead of pytest.raises so the caller's assertion can carry the AC
    label on the DID-NOT-RAISE path (a bare DID-NOT-RAISE reads as ERROR,
    not as the check's RED signature). A wrong exception type propagates raw
    and still fails the test, visibly.
    """
    try:
        fn(*args, **kwargs)
    except expected:
        return True
    return False


def _schema_of(tool) -> dict:
    schema = getattr(tool, "inputSchema", None)
    if schema is None:
        schema = getattr(tool, "input_schema", None)  # mcp 2.x field name
    return schema or {}


def _envelope_from(result, label: str) -> dict:
    """Parse the first text block of a call_tool result into the envelope."""
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {label}"
    return json.loads(texts[0].text)


def _release_quietly(cfg, lease_id: str, agent: str) -> None:
    """Best-effort cleanup release; never masks a check's own failure."""
    try:
        leases.release(cfg, lease_id, agent)
    except leases.LeaseError:
        pass


class FakePS:
    """Record every run_ps script and answer the legs hyperv_start_vm runs:
    by-name resolution -> stable per-name GUID; the start leg and the state
    wait leg -> benign JSON. The recording is the oracle for "no mutation
    ran" (never a Start-VM script under a refused lease)."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(
                stdout=str(uuid.uuid5(uuid.NAMESPACE_OID, "test-vm")), returncode=0
            )
        if "final_state" in script:
            return pswindows.PSResult(stdout='{"final_state": "Running"}', returncode=0)
        if "Start-VM" in script:
            return pswindows.PSResult(stdout='{"initial_state": "Off"}', returncode=0)
        return pswindows.PSResult(stdout="{}", returncode=0)


@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def _boot(tmp_path, fresh_server, doc: dict):
    """Bootstrapped server whose config file is `doc` + the per-test state
    DB, so the tool surface and the API-level checks share one store."""
    cfg_doc = dict(doc)
    p = tmp_path / "e02-store-config.json"
    p.write_text(json.dumps(cfg_doc), encoding="utf-8")
    return fresh_server(
        {
            "HYPERV_MCP_CONFIG": str(p),
            "HYPERV_MCP_STATE_DB": str(tmp_path / "state.db"),
        }
    )


def _as_agent(client_id: str):
    """Set the auth context exactly as AuthContextMiddleware does."""
    return auth_context_var.set(
        AuthenticatedUser(AccessToken(token="t", client_id=client_id, scopes=[]))
    )


# ---------------------------------------------------------------------------
# AC4 — fencing token strictly increases across release/re-acquire
# ---------------------------------------------------------------------------


def test_fencing_token_strictly_increases():
    """AC4: release then re-acquire of the same (vm, scope) must mint a
    strictly higher fencing token."""
    cfg = Config(unrestricted=True)
    vm = "ac-four-vm"
    first = leases.acquire(cfg, vm, ["console"], "agent-a")
    t1 = first[0].fencing_token
    leases.release(cfg, first[0].lease_id, "agent-a")
    second = leases.acquire(cfg, vm, ["console"], "agent-a")
    t2 = second[0].fencing_token
    assert t2 > t1, (
        f"AC4: the fencing token must strictly increase across "
        f"release/re-acquire (t2={t2}, t1={t1})"
    )
    _release_quietly(cfg, second[0].lease_id, "agent-a")


# ---------------------------------------------------------------------------
# AC5 — the fence counter is durable: monotonic across a store reopen
# ---------------------------------------------------------------------------


def test_fencing_token_monotonic_across_reopen():
    """AC5: after the store is closed and reopened (same database), the next
    lease on the same (vm, scope) must carry a strictly higher token, and a
    caller presenting the PRE-reopen token must be fenced.

    DECLARED GUESS: the second acquire by the same holder is the heartbeat
    re-acquire (AC11's "expires ~300s after last heartbeat" semantics): it
    must return the current lease — same or new lease_id — with a strictly
    higher token, not a self-conflict."""
    cfg = Config(unrestricted=True)
    vm = "ac-five-vm"
    db = statestore.resolve_state_db_path(cfg)
    first = leases.acquire(cfg, vm, ["console"], "agent-a")[0]
    t1 = first.fencing_token
    statestore.clear_store_cache_for_tests()  # close every cached store
    probe = statestore.open(str(db))  # explicit reopen: counter must persist
    probe.close()
    second = leases.acquire(cfg, vm, ["console"], "agent-a")[0]
    assert second.fencing_token > t1, (
        f"AC5: the fence counter did not survive a store reopen "
        f"(second token {second.fencing_token} <= {t1})"
    )
    assert _raises(
        (leases.LeaseFenced,),
        leases.authorize, cfg, second.lease_id, t1, "agent-a", "console",
    ), "AC5: authorize with the pre-reopen fencing token must raise LeaseFenced"
    _release_quietly(cfg, second.lease_id, "agent-a")
    if first.lease_id != second.lease_id:
        _release_quietly(cfg, first.lease_id, "agent-a")


# ---------------------------------------------------------------------------
# AC6 — a conflict reports the holder but never the lease secrets
# ---------------------------------------------------------------------------


def test_conflict_reports_holder_without_secrets():
    """AC6: agent-b's conflicting acquire raises LeaseConflict carrying
    holder_agent/scopes/expires_at — and never the holder's lease_id or
    fencing token (not as attributes, not in the rendered message)."""
    cfg = Config(unrestricted=True)
    vm = "conflict-vm-alpha"  # digit-free: nothing numeric can alias the token
    held = leases.acquire(cfg, vm, ["console"], "agent-a")[0]
    lease_id, t1 = held.lease_id, held.fencing_token
    with pytest.raises(leases.LeaseConflict) as raised:
        leases.acquire(cfg, vm, ["console"], "agent-b")
    exc = raised.value
    assert exc.holder_agent == "agent-a", (
        f"AC6: the conflict must name the holder; got {exc.holder_agent!r}"
    )
    assert list(exc.scopes) and exc.expires_at > 0, (
        "AC6: the conflict must carry non-empty scopes and a positive expires_at"
    )
    rendered = str(exc)
    attributes = vars(exc)
    assert lease_id not in rendered and lease_id not in repr(attributes), (
        "AC6: the conflict leaked the holder's lease_id"
    )
    assert "fencing_token" not in attributes and "lease_id" not in attributes, (
        f"AC6: the conflict carries secret attributes: {sorted(attributes)}"
    )
    assert t1 not in [v for v in attributes.values() if isinstance(v, int)], (
        "AC6: the fencing token value is exposed as an attribute"
    )
    # The token must not be STATED in the message as a standalone number (a
    # timestamp digit-run is not a token disclosure; the regex keeps the
    # check precise where a substring check would false-fail on epochs).
    assert re.search(rf"(?<!\d){t1}(?!\d)", rendered) is None, (
        f"AC6: the conflict message states the holder's fencing token {t1}"
    )
    _release_quietly(cfg, lease_id, "agent-a")


# ---------------------------------------------------------------------------
# AC7 — lifecycle conflicts with every scope; other scopes coexist
# ---------------------------------------------------------------------------


def test_lifecycle_scope_conflicts_with_every_scope():
    """AC7: while agent-a holds `lifecycle`, EVERY scope agent-b asks for
    conflicts; after the release, two different non-lifecycle scopes held by
    two different agents coexist."""
    cfg = Config(unrestricted=True)
    vm = "matrix-vm"

    def conflicts(scope: str, agent: str) -> bool:
        """True when agent's acquire of scope raises LeaseConflict. A grant
        on the mutant path is released immediately so it cannot pollute the
        later legs of this check."""
        try:
            got = leases.acquire(cfg, vm, [scope], agent)
        except leases.LeaseConflict:
            return True
        for row in got:
            _release_quietly(cfg, row.lease_id, agent)
        return False

    held = leases.acquire(cfg, vm, ["lifecycle"], "agent-a")[0]
    try:
        granted = [scope for scope in leases.SCOPES if not conflicts(scope, "agent-b")]
        assert not granted, (
            f"AC7: agent-b was granted {granted} while agent-a held "
            f"'lifecycle' — lifecycle must conflict with every scope"
        )
    finally:
        _release_quietly(cfg, held.lease_id, "agent-a")

    got_x = leases.acquire(cfg, vm, ["guest_exec"], "agent-x")
    got_y = leases.acquire(cfg, vm, ["transfer"], "agent-y")
    assert [row.scope for row in got_x] == ["guest_exec"], (
        "AC7: agent-x's guest_exec acquire must grant after the release"
    )
    assert [row.scope for row in got_y] == ["transfer"], (
        "AC7: agent-y's transfer acquire must grant alongside agent-x's "
        "guest_exec lease (different non-lifecycle scopes coexist)"
    )
    assert got_x[0].holder_agent == "agent-x" and got_y[0].holder_agent == "agent-y", (
        "AC7: granted leases must record their own holder"
    )
    for row in got_x + got_y:
        _release_quietly(cfg, row.lease_id, row.holder_agent)


# ---------------------------------------------------------------------------
# AC8 — expiry: takeover, dead renew, fenced old token, dead call rows
# ---------------------------------------------------------------------------


def test_expired_lease_taken_over_and_old_token_fenced(monkeypatch):
    """AC8 (injected clock, no sleeps): 31s past a 30s TTL, agent-b takes
    the scope over with a HIGHER token; agent-a's renew raises LeaseExpired;
    authorize with a's old token raises LeaseFenced or LeaseExpired (exactly
    that set). A per-call (kind="call") row whose owner died stops blocking
    after its TTL."""
    cfg = Config(unrestricted=True)
    vm = "expiry-vm"
    db = statestore.resolve_state_db_path(cfg)
    clock = FakeClock(1_000_000.0)
    store = _clock_store(monkeypatch, db, clock)
    try:
        a = leases.acquire(cfg, vm, ["console"], "agent-a", ttl_s=30)[0]
        clock.advance(31)

        try:
            b = leases.acquire(cfg, vm, ["console"], "agent-b")[0]
        except leases.LeaseError as exc:
            raise AssertionError(
                f"AC8: agent-a's expired lease still blocks takeover: {exc}"
            ) from exc
        assert b.fencing_token > a.fencing_token, (
            f"AC8: the takeover must mint a higher fencing token "
            f"(b={b.fencing_token}, a={a.fencing_token})"
        )

        assert _raises(
            (leases.LeaseExpired,), leases.renew, cfg, a.lease_id, "agent-a"
        ), "AC8: renew of an expired lease must raise LeaseExpired"

        assert _raises(
            (leases.LeaseFenced, leases.LeaseExpired),
            leases.authorize, cfg, a.lease_id, a.fencing_token, "agent-a", "console",
        ), (
            "AC8: authorize with the pre-expiry fencing token must raise "
            "LeaseFenced (or LeaseExpired), never succeed"
        )

        # A per-call row whose owner "died": after its TTL it stops blocking.
        call = leases.acquire(
            cfg, vm, ["guest_exec"], "agent-c", ttl_s=30, kind="call"
        )[0]
        clock.advance(31)
        try:
            leases.assert_unleased(cfg, "agent-e", "guest_exec", vm)
        except leases.LeaseError as exc:
            raise AssertionError(
                f"AC8: the dead owner's per-call lease still blocks after its "
                f"TTL: {exc}"
            ) from exc
        try:
            d = leases.acquire(cfg, vm, ["guest_exec"], "agent-d")[0]
        except leases.LeaseError as exc:
            raise AssertionError(
                f"AC8: the expired per-call lease still blocks a new holder: {exc}"
            ) from exc
        assert d.fencing_token > call.fencing_token, (
            "AC8: taking over an expired per-call lease must mint a higher token"
        )
    finally:
        store.close()


# ---------------------------------------------------------------------------
# AC9 — a lease is usable only by its owner
# ---------------------------------------------------------------------------


def test_lease_use_requires_owner_agent():
    """AC9: agent-b's renew/release/authorize against agent-a's lease_id all
    raise LeaseNotOwned, and a's row is byte-for-byte unchanged afterwards."""
    cfg = Config(unrestricted=True)
    vm = "ownership-vm"
    lease = leases.acquire(cfg, vm, ["transfer"], "agent-a")[0]
    before = leases.list_leases(cfg, vm_id=vm)
    try:
        assert _raises(
            (leases.LeaseNotOwned,), leases.renew, cfg, lease.lease_id, "agent-b"
        ), "AC9: agent-b's renew of agent-a's lease must raise LeaseNotOwned"
        assert _raises(
            (leases.LeaseNotOwned,), leases.release, cfg, lease.lease_id, "agent-b"
        ), "AC9: agent-b's release of agent-a's lease must raise LeaseNotOwned"
        assert _raises(
            (leases.LeaseNotOwned,),
            leases.authorize, cfg, lease.lease_id, lease.fencing_token, "agent-b", "transfer",
        ), "AC9: agent-b's authorize against agent-a's lease must raise LeaseNotOwned"
        after = leases.list_leases(cfg, vm_id=vm)
        assert after == before, (
            "AC9: the failed foreign calls changed the lease row "
            f"(before={before}, after={after})"
        )
    finally:
        _release_quietly(cfg, lease.lease_id, "agent-a")


# ---------------------------------------------------------------------------
# AC10 — an unleased mutating call is blocked by another agent's lease
# ---------------------------------------------------------------------------


def test_unleased_call_blocked_by_other_agents_lease(tmp_path, fresh_server, monkeypatch):
    """AC10: agent-a (auth_context_var) acquires `lifecycle` on a VM the
    faked PowerShell resolves; agent-b's hyperv_start_vm with NO lease
    arguments is refused with error_class "lease_conflict", the message
    names holder agent-a, and no Start-VM script ever runs."""
    mod = _boot(tmp_path, fresh_server, {"allowed_vm_patterns": ["test-*"]})
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    token = _as_agent("agent-a")
    try:
        result = asyncio.run(
            mcp.call_tool(
                "hyperv_lease_acquire", {"vm_name": "test-vm", "scopes": ["lifecycle"]}
            )
        )
    finally:
        auth_context_var.reset(token)
    acq = _envelope_from(result, "hyperv_lease_acquire")
    assert acq.get("ok") is not False and not acq.get("error_class"), (
        f"AC10: agent-a's lease acquire failed: {json.dumps(acq)[:300]}"
    )
    assert "lease_id" in json.dumps(acq), (
        f"AC10: the acquire response must expose the lease_id: {json.dumps(acq)[:300]}"
    )

    token = _as_agent("agent-b")
    try:
        result = asyncio.run(mcp.call_tool("hyperv_start_vm", {"vm_name": "test-vm"}))
    finally:
        auth_context_var.reset(token)
    env = _envelope_from(result, "hyperv_start_vm")
    assert env.get("error_class") == "lease_conflict", (
        "AC10: agent-b's unleased mutating call must be refused with "
        f"error_class 'lease_conflict'; got {env.get('error_class')!r} "
        f"(envelope: {json.dumps(env)[:400]})"
    )
    assert "agent-a" in str(env.get("error", "")), (
        f"AC10: the refusal must name the holder 'agent-a'; error was "
        f"{env.get('error')!r}"
    )
    assert not any("Start-VM" in s for s in fake.scripts), (
        f"AC10: a mutation ran under agent-a's lease: {[s[:80] for s in fake.scripts]}"
    )

    # Cleanup: give the lease back through the API as its owner.
    lease_id = acq.get("lease_id") if isinstance(acq.get("lease_id"), str) else ""
    if not lease_id:
        for row in acq.get("leases") or []:
            if isinstance(row, dict) and isinstance(row.get("lease_id"), str):
                lease_id = row["lease_id"]
                break
    if lease_id:
        _release_quietly(mod.CFG, lease_id, "agent-a")


# ---------------------------------------------------------------------------
# AC11 — leases.required on the shared controller + TTL bounds
# ---------------------------------------------------------------------------


def test_leases_required_on_controller_and_ttl_bounds(tmp_path, fresh_server, monkeypatch):
    """AC11: with cfg.leases.required = True (shared-controller default) a
    mutating call with no lease arguments is refused "lease_required" with
    no PowerShell run; with required = False (standalone) the same call
    proceeds to the mutation. Default TTL is ~300s; ttl_s above the 3600 cap
    is rejected as invalid at the tool layer; renew pushes expires_at to
    now + ttl (injected clock)."""
    mod = _boot(tmp_path, fresh_server, {"allowed_vm_patterns": ["test-*"]})
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    # Controller mode: no lease presented, no lease held -> lease_required.
    mod.CFG.leases.required = True
    env = _envelope_from(
        asyncio.run(mcp.call_tool("hyperv_start_vm", {"vm_name": "test-vm"})),
        "hyperv_start_vm (required)",
    )
    assert env.get("error_class") == "lease_required", (
        "AC11: under leases.required a mutating call with no lease arguments "
        f"must be refused 'lease_required'; got {env.get('error_class')!r} "
        f"(envelope: {json.dumps(env)[:400]})"
    )
    assert not fake.scripts, (
        f"AC11: the lease_required refusal must run no PowerShell: "
        f"{[s[:80] for s in fake.scripts]}"
    )

    # Standalone mode: the same call proceeds to the mutation.
    mod.CFG.leases.required = False
    env = _envelope_from(
        asyncio.run(mcp.call_tool("hyperv_start_vm", {"vm_name": "test-vm"})),
        "hyperv_start_vm (not required)",
    )
    assert env.get("error_class") != "lease_required" and env.get("status") == "started", (
        f"AC11: with leases.required off the call must proceed; got {json.dumps(env)[:300]}"
    )
    assert any("Start-VM" in s for s in fake.scripts), (
        "AC11: with leases.required off the mutation must actually run"
    )

    # Default TTL: omitted ttl_s lands ~300s after the acquire heartbeat.
    cfg = Config(unrestricted=True)
    vm = "ttl-vm"
    lease = leases.acquire(cfg, vm, ["console"], "agent-a")[0]
    ttl = lease.expires_at - lease.acquired_at
    assert 295 <= ttl <= 305, (
        f"AC11: an omitted ttl_s must yield the ~300s default TTL; got {ttl}"
    )
    _release_quietly(cfg, lease.lease_id, "agent-a")

    # Tool-layer TTL bound: 3601s is above max_ttl_s and must be invalid.
    bad = _envelope_from(
        asyncio.run(
            mcp.call_tool(
                "hyperv_lease_acquire",
                {"vm_name": "test-vm", "scopes": ["console"], "ttl_s": 3601},
            )
        ),
        "hyperv_lease_acquire (ttl_s=3601)",
    )
    assert bad.get("error_class") == "invalid", (
        "AC11: ttl_s above max_ttl_s (3601 > 3600) must be rejected as "
        f"'invalid'; got {bad.get('error_class')!r} (envelope: {json.dumps(bad)[:300]})"
    )

    # Renew pushes expires_at to now + ttl on the injected clock.
    clock = FakeClock(2_000_000.0)
    db = statestore.resolve_state_db_path(cfg)
    store = _clock_store(monkeypatch, db, clock)
    try:
        held = leases.acquire(cfg, vm, ["guest_exec"], "agent-a", ttl_s=120)[0]
        assert held.expires_at == pytest.approx(clock() + 120, abs=1), (
            f"AC11: acquire(ttl_s=120) must expire at now+120; got {held.expires_at}"
        )
        clock.advance(60)
        renewed = leases.renew(cfg, held.lease_id, "agent-a")
        assert renewed.expires_at == pytest.approx(clock() + 120, abs=1), (
            "AC11: renew must push expires_at to now+ttl "
            f"(want ~{clock() + 120}, got {renewed.expires_at})"
        )
    finally:
        store.close()
