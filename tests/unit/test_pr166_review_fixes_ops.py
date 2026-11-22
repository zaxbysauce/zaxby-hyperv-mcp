"""PR #166 review fixes: RED-first pins for FB-005 and FB-003.

FB-005 (HIGH) — startup pruning erased a completed identity INSIDE the
replay window. store_for()'s first-open sweep called ops_prune() with NO
replay_cutoff, so the replay cutoff defaulted to the retention cutoff: the
FIRST startup tombstoned a completed keyed row (result_json=NULL) and the
SECOND startup DELETED that same row while it was still inside the
configured replay window (idempotency_ttl_s), so a same-key retry executed
the body a SECOND time. The identity-deletion cutoff must be the REPLAY
window, and startup deletion must carry the consult's legacy/unresolved
protections (a generation-0 legacy row and an interrupted/unknown/
possibly_sent row are never deleted by the sweep).

  test_fb005_second_startup_keeps_tombstoned_identity   — RED at base
  test_fb005_startup_pruning_protects_legacy_gen0_row   — RED at base
  test_fb005_row_past_replay_window_is_forgotten        — acceptance (b)
  test_fb005_unresolved_rows_survive_startup_pruning    — acceptance (d)

FB-003 (MEDIUM) — a late heartbeat refreshed a TERMINAL row. The inline
beat helper and the detached twin wrote the beat BEFORE checking the stop
flag and cancelled only the FIRST timer (an already-scheduled replacement
fired once after the body exited); op_heartbeat's UPDATE had no status
predicate, so it refreshed heartbeat_at on a terminal row; and both
consults used heartbeat freshness in the TTL-expiry decision regardless of
the row's status, replaying an expired resolved identity instead of
allowing a fresh dispatch.

  test_fb003_op_heartbeat_refuses_terminal_row          — RED at base
  test_fb003_inline_heartbeat_stops_with_the_body       — RED at base
  test_fb003_detached_heartbeat_stops_after_body        — RED at base
  test_fb003_expired_resolved_row_not_kept_alive        — RED at base
  test_fb003_unresolved_row_not_expired_by_ttl          — acceptance (c)
  test_fb003_live_working_row_past_ttl_still_attaches   — protection kept

Wave 4 (PR #166 verification transcript): two sub-parts the shipped pins
above do not discriminate are now pinned in their own right —

  test_fb005_startup_pruning_protects_blank_fingerprint_row: the legacy
      deletion guard filters on BOTH legacy shapes; the shipped legacy
      pin's row is generation 0 with a NON-blank fingerprint, so only the
      generation half was pinned.
  test_fb003_tasks_route_ignores_a_late_heartbeat_on_a_resolved_row: the
      tasks route carries its OWN copy of the heartbeat_fresh predicate;
      the shipped FB-003 (b) pin drives guard_consult only.

What is faked: nothing beyond the module's own seams — the store is a real
temp SQLite database; the "two startups" are two clear_store_cache_for_
tests() + store_for() first-open sweeps against the same file; the
clock-sensitive consult schedules use statestore.Store(clock=) (the
t157-158 schedules pattern). Bounded waits only (poll loops with
monotonic deadlines); every store is closed in teardown (Windows
file-lock hazard) and every detached runner is drained by the conftest's
drain_for_tests.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from types import SimpleNamespace

import pytest

from hyperv_mcp import operations, statestore
from hyperv_mcp.config import Config

OP_TOOL = "hyperv_checkpoint_create"
TASKS_ID = "io.modelcontextprotocol/tasks"


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


class _NoDispatchTool:
    """tool_fn stand-in that FAILS the test if a consult-only retry ever
    reaches the body (at most one dispatch per protected attempt)."""

    def __call__(self, **kwargs):
        raise AssertionError("the protected retry re-dispatched the body")


class _GatedBody:
    """Detached tool_fn stand-in that parks on a gate Event so the runner
    stays provably mid-flight (a beat must fire while the row is working)."""

    def __init__(self) -> None:
        self.gate = threading.Event()
        self._mu = threading.Lock()
        self.calls = 0

    def __call__(self, **kwargs):
        with self._mu:
            self.calls += 1
        self.gate.wait(timeout=10.0)
        return {"ok": True, "status": "created"}


class FakeClock:
    """Deterministic wall clock for Store(path, clock=...)."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


class _OneSemaphore(threading.BoundedSemaphore):
    pass


def _ops_cfg(**overrides) -> Config:
    """An unrestricted Config with direct operations-knob overrides (the
    direct-setattr route the config validator's own _set_ops_int_on uses)."""
    cfg = Config(unrestricted=True)
    for key, value in overrides.items():
        setattr(cfg.operations, key, value)
    return cfg


def _wait_until(predicate, timeout_s: float, message: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(message)


@pytest.fixture()
def fb_store(tmp_path, monkeypatch):
    """A real per-test Store behind the operations.store_for seam, closed on
    teardown (the Windows file-lock teardown hazard)."""
    store = statestore.open(str(tmp_path / "fb-pr166.db"))
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)
    yield store
    store.close()


@pytest.fixture()
def startup_db(tmp_path, monkeypatch):
    """A dedicated state DB for store_for() first-open sweep tests. Each
    statestore.clear_store_cache_for_tests() + store_for() call below is ONE
    process startup: the cache miss re-opens the file and runs the first-open
    sweeps (lease sweep, events prune, ops_prune)."""
    db = str(tmp_path / "fb005-startup.db")
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", db)
    statestore.clear_store_cache_for_tests()
    yield db
    statestore.clear_store_cache_for_tests()


@pytest.fixture()
def admission_budget():
    """Size the classed-admission budget the detached runner admits through
    (the schedules-file admission_env pattern: bootstrap sizes it in the
    server; a direct-drive test must size it the same way)."""
    from hyperv_mcp import admission

    admission.reset()
    admission.configure(total_tokens=8, light_reserve=2, wait_s=0.5, light_wait_s=0.5)
    yield
    admission.reset()


def _startup(cfg: Config) -> statestore.Store:
    """One simulated process startup against the mounted state DB."""
    statestore.clear_store_cache_for_tests()
    return statestore.store_for(cfg)


# ---------------------------------------------------------------------------
# FB-005 — startup pruning vs the replay window
# ---------------------------------------------------------------------------


def test_fb005_second_startup_keeps_tombstoned_identity(startup_db):
    """FB-005 acceptance (a): with retention_s < idempotency_ttl_s, TWO
    startups keep the completed row's identity as a payload tombstone, and a
    same-key retry ATTACHES to the original handle instead of executing the
    body a second time. RED at base: the second startup (single-cutoff
    prune) deletes the tombstoned row inside the replay window."""
    cfg = _ops_cfg(retention_s=60, idempotency_ttl_s=3600)
    args = {"vm_name": "test-vm", "checkpoint_name": "fb005",
            "idempotency_key": "fb005"}

    boot = statestore.open(startup_db)
    now = boot.now()
    # A generation-stamped, fingerprinted, COMPLETED keyed row: 120s old —
    # past the 60s payload retention, well inside the 3600s replay window.
    boot.op_insert(statestore.OpRow(
        op_id="fb005-op", tool=OP_TOOL, agent="", vm_name="test-vm",
        status=statestore.OP_COMPLETED,
        created_at=now - 120.0, updated_at=now - 120.0,
        runner="fb005-runner", heartbeat_at=now - 120.0,
        params_hmac=operations.arguments_fingerprint(cfg, boot, args),
        idem_key="fb005",
        result_json='{"ok": true, "status": "created"}',
        result_size=34, generation=4,
    ))
    boot.close()

    # Startup 1: the payload is tombstoned at the retention cutoff, the
    # identity survives (the README replay-window promise).
    s1 = _startup(cfg)
    row1 = s1.op_find_idem("", OP_TOOL, "fb005")
    assert row1 is not None and row1.op_id == "fb005-op", (
        "startup 1 must tombstone, not delete, a row inside the replay window"
    )
    assert row1.result_json is None, (
        f"startup 1 must prune the payload: {row1.as_dict()}"
    )

    # Startup 2: the tombstoned identity must STILL be here.
    s2 = _startup(cfg)
    row2 = s2.op_find_idem("", OP_TOOL, "fb005")
    assert row2 is not None and row2.op_id == "fb005-op", (
        "FB-005: the SECOND startup deleted a completed identity that is "
        "still inside the replay window (idempotency_ttl_s) — a same-key "
        "retry would execute the body a second time"
    )

    # The same-key retry attaches to the ORIGINAL tombstoned identity with
    # the explicit result-expired disclosure; the body never re-runs.
    retry = _NoDispatchTool()
    resp, ctx = operations.guard_consult(
        cfg, OP_TOOL, args, retry, lambda: _OneSemaphore(1))
    assert ctx is None and isinstance(resp, dict), (
        f"the replay-window retry must answer from the row, not re-dispatch; "
        f"got resp={resp!r} ctx={ctx!r}"
    )
    assert resp.get("op_id") == "fb005-op", f"got {resp!r}"
    assert "expired" in json.dumps(resp).lower(), (
        f"the tombstone attach must carry the result-expired disclosure: {resp!r}"
    )


def test_fb005_startup_pruning_protects_legacy_gen0_row(startup_db):
    """FB-005 acceptance (c): a migrated v5 keyed row (generation 0) past
    BOTH windows survives startup pruning — identity deletion obeys the
    consult's AC8 legacy guard, so the sweep can never consume a protected
    legacy identity to authorize a duplicate dispatch. RED at base: the
    deletion phase has no generation protection, so the row is deleted."""
    cfg = _ops_cfg(retention_s=60, idempotency_ttl_s=3600)
    boot = statestore.open(startup_db)
    now = boot.now()
    boot.op_insert(statestore.OpRow(
        op_id="fb005-legacy", tool=OP_TOOL, agent="", vm_name="test-vm",
        status=statestore.OP_COMPLETED,
        created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="v5-migrated", heartbeat_at=now - 7200.0,
        params_hmac="legacy-v5-fingerprint", idem_key="fb005-legacy",
        result_json=None, generation=0,
    ))
    boot.close()

    _startup(cfg)
    s2 = _startup(cfg)
    survivor = s2.op_get("fb005-legacy")
    assert survivor is not None, (
        "FB-005: startup pruning deleted a generation-0 legacy identity — "
        "it must reach the reconciliation refusal, never be silently "
        "forgotten by the sweep"
    )
    assert survivor.idem_key == "fb005-legacy"


def test_fb005_row_past_replay_window_is_forgotten(startup_db):
    """FB-005 acceptance (b): a resolved, fingerprinted, generation-stamped
    row past the REPLAY window (not just past retention) is still forgotten,
    and the same-key retry dispatches fresh. (Non-RED: pins that the fix does
    not make retention permanent.)"""
    cfg = _ops_cfg(retention_s=60, idempotency_ttl_s=3600)
    args = {"vm_name": "test-vm", "checkpoint_name": "fb005gone",
            "idempotency_key": "fb005gone"}
    boot = statestore.open(startup_db)
    now = boot.now()
    boot.op_insert(statestore.OpRow(
        op_id="fb005-gone", tool=OP_TOOL, agent="", vm_name="test-vm",
        status=statestore.OP_COMPLETED,
        created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="fb005-runner", heartbeat_at=now - 7200.0,
        params_hmac=operations.arguments_fingerprint(cfg, boot, args),
        idem_key="fb005gone",
        result_json='{"ok": true, "status": "created"}',
        result_size=34, generation=5,
    ))
    boot.close()

    _startup(cfg)  # tombstones (payload pruned, identity kept)
    s2 = _startup(cfg)  # past the replay window: the identity is forgotten
    assert s2.op_find_idem("", OP_TOOL, "fb005gone") is None, (
        "a row past the replay window must be forgotten by startup pruning"
    )
    resp, ctx = operations.guard_consult(
        cfg, OP_TOOL, args, _NoDispatchTool(), lambda: _OneSemaphore(1))
    assert ctx is not None and ctx.get("op_id") != "fb005-gone", (
        f"the past-window retry must dispatch fresh; got resp={resp!r} ctx={ctx!r}"
    )


def test_fb005_unresolved_rows_survive_startup_pruning(startup_db):
    """FB-005 acceptance (d): unresolved identities (failed/interrupted,
    failed/unknown, cancelled+possibly_sent) past BOTH windows survive
    startup pruning. (Non-RED: the deletion phase already excluded them;
    pins that the FB-005 correction keeps those protections.)"""
    cfg = _ops_cfg(retention_s=60, idempotency_ttl_s=3600)
    boot = statestore.open(startup_db)
    now = boot.now()
    seeds = [
        statestore.OpRow(
            op_id="fb005-int", tool=OP_TOOL, agent="", vm_name="test-vm",
            status=statestore.OP_FAILED, error_class=statestore.OP_INTERRUPTED,
            created_at=now - 7200.0, updated_at=now - 7200.0,
            runner="r1", heartbeat_at=now - 7200.0,
            params_hmac="h1", idem_key="fb005-int",
            result_json=None, generation=5,
        ),
        statestore.OpRow(
            op_id="fb005-unk", tool=OP_TOOL, agent="", vm_name="test-vm",
            status=statestore.OP_FAILED, error_class=statestore.OP_UNKNOWN,
            created_at=now - 7200.0, updated_at=now - 7200.0,
            runner="r2", heartbeat_at=now - 7200.0,
            params_hmac="h2", idem_key="fb005-unk",
            result_json=None, generation=5,
        ),
        statestore.OpRow(
            op_id="fb005-ps", tool=OP_TOOL, agent="", vm_name="test-vm",
            status=statestore.OP_CANCELLED,
            created_at=now - 7200.0, updated_at=now - 7200.0,
            runner="r3", heartbeat_at=now - 7200.0,
            params_hmac="h3", idem_key="fb005-ps",
            result_json=None, generation=5, send_state="possibly_sent",
        ),
    ]
    for row in seeds:
        boot.op_insert(row)
    boot.close()

    _startup(cfg)
    s2 = _startup(cfg)
    for row in seeds:
        survivor = s2.op_get(row.op_id)
        assert survivor is not None, (
            f"FB-005: startup pruning deleted the unresolved identity "
            f"{row.op_id!r} — it stays protected until trusted reconciliation"
        )


# ---------------------------------------------------------------------------
# FB-003 — late heartbeats on terminal rows
# ---------------------------------------------------------------------------


def test_fb003_op_heartbeat_refuses_terminal_row(fb_store):
    """FB-003 acceptance (a), store level: op_heartbeat may only freshen a
    WORKING row — after the body's terminal write no heartbeat write moves a
    terminal row's heartbeat_at. RED at base: the UPDATE has no status
    predicate."""
    store = fb_store
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="hb-term", tool=OP_TOOL, agent="", status=statestore.OP_WORKING,
        created_at=now, updated_at=now, runner="sync-aa",
        heartbeat_at=now, generation=2,
    ))
    store.op_heartbeat("hb-term", now + 100.0, generation=2)
    assert store.op_get("hb-term").heartbeat_at == now + 100.0, (
        "a WORKING row's heartbeat must still freshen"
    )
    assert store.op_transition(
        "hb-term", (statestore.OP_WORKING,), statestore.OP_COMPLETED,
        updated_at=store.now(), generation=2,
    ) is True
    store.op_heartbeat("hb-term", now + 500.0, generation=2)
    row = store.op_get("hb-term")
    assert row.status == statestore.OP_COMPLETED and \
        row.heartbeat_at == now + 100.0, (
            f"FB-003: a late heartbeat refreshed a TERMINAL row: "
            f"{row.as_dict()}"
        )


def _beat_spy(store):
    """FB-003 (PR #166 review, wave 3): observe the heartbeat WRITE ATTEMPT,
    not the stored row. statestore.op_heartbeat independently refuses to
    freshen a non-working row, so a stored-value assertion is MASKED by the
    store-level guard — reverting only the active-timer teardown left the
    row's heartbeat_at unchanged and the old pins GREEN. The spy records the
    ATTEMPT before the store guard can swallow it, so an orphan replacement
    timer that fires after the body exited is caught by its CALL, never by
    the (guard-protected) row."""
    beats: list[float] = []
    real_op_heartbeat = store.op_heartbeat

    def _spy(op_id, at, generation=None):
        beats.append(time.monotonic())
        return real_op_heartbeat(op_id, at, generation=generation)

    store.op_heartbeat = _spy
    return beats


def test_fb003_inline_heartbeat_stops_with_the_body(fb_store):
    """FB-003 acceptance (a)+(d), inline path: a beat fires mid-body (and
    schedules its replacement timer); the body then completes and the
    dispatch's finally stops the chain — NO further heartbeat write may be
    ATTEMPTED after the body has exited. RED at base: the beat wrote before
    any stop check and _stop cancelled only the FIRST timer, so the parked
    replacement fired once after the body exited and attempted a write on
    the terminal row (the store guard masked that write's stored value; the
    spy's discriminating signal is the ATTEMPT itself)."""
    store = fb_store
    cfg = _ops_cfg(heartbeat_ttl_s=3)  # beat interval = max(1.0, 3/3) = 1.0s
    beats = _beat_spy(store)
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="hb-inline", tool=OP_TOOL, agent="", status=statestore.OP_WORKING,
        created_at=now, updated_at=now, runner="sync-bb",
        heartbeat_at=now, generation=7,
    ))
    op_ctx = {"cfg": cfg, "op_id": "hb-inline", "agent": "", "generation": 7}
    stop = operations.start_inline_heartbeat(op_ctx)
    try:
        _wait_until(
            lambda: beats,
            timeout_s=5.0,
            message="the inline heartbeat never ATTEMPTED a beat mid-body",
        )
        # The mid-body beat's call-through freshened the WORKING row.
        _wait_until(
            lambda: store.op_get("hb-inline").heartbeat_at > now,
            timeout_s=5.0,
            message="the mid-body beat never freshened the working row",
        )
        # Let the beat thread finish scheduling its replacement timer.
        time.sleep(0.3)
        # The body exits: the terminal write, then the dispatch's finally.
        assert store.op_transition(
            "hb-inline", (statestore.OP_WORKING,), statestore.OP_COMPLETED,
            updated_at=store.now(), generation=7,
        ) is True
    finally:
        stop()
    settled = store.op_get("hb-inline").heartbeat_at
    # Grace for a beat that was already past the stop check when stop() ran
    # (it lands within microseconds); base's orphan replacement fires ~1s
    # after the last beat — well outside this grace.
    time.sleep(0.2)
    exit_index = len(beats)
    # An unstopped replacement (1s interval) would attempt 2 writes in 2.5s.
    time.sleep(2.5)
    assert len(beats) == exit_index, (
        f"FB-003: the inline beat ATTEMPTED a heartbeat write after the "
        f"body exited ({len(beats) - exit_index} post-exit attempt(s)); the "
        f"store guard masks the stored value, so the ATTEMPT is the defect"
    )
    # Additional (masked-safe, non-discriminating) row check.
    row = store.op_get("hb-inline")
    assert row.status == statestore.OP_COMPLETED and \
        row.heartbeat_at == settled, (
            f"FB-003: an inline heartbeat fired after the body exited: "
            f"{row.as_dict()}"
        )


def test_fb003_detached_heartbeat_stops_after_body(fb_store, admission_budget):
    """FB-003 acceptance (a)+(d), detached path: a beat fires while the
    runner body is parked; the body then completes and the runner's finally
    stops the beat chain — NO further heartbeat write may be ATTEMPTED after
    the body has exited. RED at base: the beat wrote before any stop check
    and the finally cancelled only the FIRST timer, so the parked beat's
    replacement fired once after the body exited and attempted a write on
    the terminal row (masked in the stored value by the store guard; caught
    here by the spy on the write ATTEMPT)."""
    store = fb_store
    cfg = _ops_cfg(heartbeat_ttl_s=3)
    beats = _beat_spy(store)
    body = _GatedBody()
    handle, ctx = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "test-vm", "checkpoint_name": "fb003",
         "idempotency_key": "fb003-det", "detach": True},
        body, lambda: _OneSemaphore(1))
    assert ctx is None and isinstance(handle, dict) and handle.get("op_id"), (
        f"expected a detached handle; got {handle!r} {ctx!r}"
    )
    op_id = handle["op_id"]

    # A beat must fire while the body is parked mid-flight.
    _wait_until(
        lambda: beats,
        timeout_s=5.0,
        message="the detached runner's heartbeat never ATTEMPTED a beat "
                "mid-body",
    )
    time.sleep(0.3)  # let the beat thread schedule its replacement timer

    body.gate.set()
    _wait_until(
        lambda: store.op_get(op_id).status == statestore.OP_COMPLETED,
        timeout_s=5.0,
        message="the detached runner never completed its body",
    )
    # The runner's finally (stop.set + active-timer cancel) runs BEFORE the
    # _runners deregistration — wait for that deregistration so the exit
    # point below is provably AFTER the teardown.
    _wait_until(
        lambda: op_id not in operations._runners,
        timeout_s=5.0,
        message="the detached runner never tore down its beat chain",
    )
    settled = store.op_get(op_id).heartbeat_at
    # Grace for a beat already past the stop check when the finally ran;
    # base's orphan replacement fires ~1s after the parked beat.
    time.sleep(0.2)
    exit_index = len(beats)
    # An unstopped replacement (1s interval) would attempt a write in 2.5s.
    time.sleep(2.5)
    assert len(beats) == exit_index, (
        f"FB-003: the detached runner's beat ATTEMPTED a heartbeat write "
        f"after the body exited ({len(beats) - exit_index} post-exit "
        f"attempt(s)); the store guard masks the stored value, so the "
        f"ATTEMPT is the defect"
    )
    # Additional (masked-safe, non-discriminating) row check.
    row = store.op_get(op_id)
    assert row.status == statestore.OP_COMPLETED and \
        row.heartbeat_at == settled, (
            f"FB-003: the detached runner's beat fired after the body "
            f"exited: {row.as_dict()}"
        )
    assert body.calls == 1


def test_fb003_expired_resolved_row_not_kept_alive_by_late_heartbeat(
        tmp_path, monkeypatch):
    """FB-003 acceptance (b): the TTL consult ignores heartbeat freshness
    for a RESOLVED row — an expired completed identity whose heartbeat_at was
    refreshed by a late beat is forgotten, and the same-key retry dispatches
    FRESH (a new handle). RED at base: heartbeat_fresh has no status
    predicate, so the expired resolved row replays instead."""
    clock = FakeClock(start=1000.0)
    db = str(tmp_path / "fb003-clock.db")
    statestore.open(db).close()
    store = statestore.Store(db, clock=clock)
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)
    try:
        cfg = _ops_cfg(idempotency_ttl_s=100, heartbeat_ttl_s=60)
        args = {"vm_name": "test-vm", "checkpoint_name": "fb003c",
                "idempotency_key": "fb003c"}
        clock.now = 2000.0
        store.op_insert(statestore.OpRow(
            op_id="fb003c-op", tool=OP_TOOL, agent="", vm_name="test-vm",
            status=statestore.OP_COMPLETED,
            created_at=1000.0, updated_at=1990.0, runner="sync-cc",
            # A late beat refreshed a TERMINAL row (the FB-003 write).
            heartbeat_at=1995.0,
            params_hmac=operations.arguments_fingerprint(cfg, store, args),
            idem_key="fb003c",
            result_json='{"ok": true, "status": "created"}',
            result_size=34, generation=3,
        ))
        resp, ctx = operations.guard_consult(
            cfg, OP_TOOL, args, _NoDispatchTool(), lambda: _OneSemaphore(1))
        assert ctx is not None and ctx.get("op_id") != "fb003c-op", (
            f"FB-003: an expired RESOLVED row was kept live by its (late) "
            f"fresh heartbeat and replayed instead of allowing a fresh "
            f"dispatch; got resp={resp!r} ctx={ctx!r}"
        )
        assert store.op_get("fb003c-op") is None, (
            "the expired resolved identity must be forgotten (op.expired)"
        )
    finally:
        store.close()


def test_fb003_unresolved_row_not_expired_by_ttl(tmp_path, monkeypatch):
    """FB-003 acceptance (c): an unresolved identity (failed/unknown,
    possibly_sent) past the TTL stays protected — it attaches with the
    unknown disclosure, never a fresh dispatch. (Non-RED: pins that the
    FB-003 correction leaves the unresolved protections in place.)"""
    clock = FakeClock(start=1000.0)
    db = str(tmp_path / "fb003-unk.db")
    statestore.open(db).close()
    store = statestore.Store(db, clock=clock)
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)
    try:
        cfg = _ops_cfg(idempotency_ttl_s=100, heartbeat_ttl_s=60)
        args = {"vm_name": "test-vm", "checkpoint_name": "fb003u",
                "idempotency_key": "fb003u"}
        clock.now = 2000.0
        store.op_insert(statestore.OpRow(
            op_id="fb003u-op", tool=OP_TOOL, agent="", vm_name="test-vm",
            status=statestore.OP_FAILED, error_class=statestore.OP_UNKNOWN,
            created_at=1000.0, updated_at=1990.0, runner="runner-u",
            heartbeat_at=1995.0, send_state="possibly_sent",
            params_hmac=operations.arguments_fingerprint(cfg, store, args),
            idem_key="fb003u",
            result_json='{"ok": false}', result_size=13, generation=3,
        ))
        resp, ctx = operations.guard_consult(
            cfg, OP_TOOL, args, _NoDispatchTool(), lambda: _OneSemaphore(1))
        assert ctx is None and isinstance(resp, dict) and \
            resp.get("op_id") == "fb003u-op" and \
            resp.get("vm_outcome") == "unknown", (
                f"the unresolved identity must stay protected and attach "
                f"with the unknown disclosure; got resp={resp!r} ctx={ctx!r}"
            )
    finally:
        store.close()


def test_fb003_live_working_row_past_ttl_still_attaches(tmp_path, monkeypatch):
    """FB-003 protection kept: a LIVE (working) row past the idempotency TTL
    with a fresh heartbeat still attaches live — heartbeat freshness keeps
    its meaning for unresolved rows. (Non-RED: pins the kept behavior.)"""
    clock = FakeClock(start=1000.0)
    db = str(tmp_path / "fb003-live.db")
    statestore.open(db).close()
    store = statestore.Store(db, clock=clock)
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)
    try:
        cfg = _ops_cfg(idempotency_ttl_s=100, heartbeat_ttl_s=60)
        args = {"vm_name": "test-vm", "checkpoint_name": "fb003l",
                "idempotency_key": "fb003l"}
        clock.now = 2000.0
        store.op_insert(statestore.OpRow(
            op_id="fb003l-op", tool=OP_TOOL, agent="", vm_name="test-vm",
            status=statestore.OP_WORKING,
            created_at=1000.0, updated_at=1990.0, runner="runner-l",
            heartbeat_at=1995.0,
            params_hmac=operations.arguments_fingerprint(cfg, store, args),
            idem_key="fb003l", generation=3,
        ))
        resp, ctx = operations.guard_consult(
            cfg, OP_TOOL, args, _NoDispatchTool(), lambda: _OneSemaphore(1))
        assert ctx is None and isinstance(resp, dict) and \
            resp.get("op_id") == "fb003l-op" and \
            resp.get("status") == statestore.OP_WORKING, (
                f"a live row past the TTL must attach with its handle; "
                f"got resp={resp!r} ctx={ctx!r}"
            )
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Wave 4 — the sub-parts the shipped pins above did not discriminate
# ---------------------------------------------------------------------------


def test_fb005_startup_pruning_protects_blank_fingerprint_row(startup_db):
    """FB-005 wave 4: the startup sweep's legacy deletion guard filters on
    BOTH legacy shapes (a BLANK fingerprint protects exactly like
    generation 0). The shipped legacy pin's row is generation 0 with a
    NON-blank fingerprint, so it exercises only the generation half — this
    pin isolates the blank-fingerprint half: a generation-5 completed row
    whose params_hmac is the pre-fingerprinting empty string must survive
    startup pruning past both windows. RED under the blank-fingerprint-half
    mutation (the row is deleted); GREEN at head."""
    cfg = _ops_cfg(retention_s=60, idempotency_ttl_s=3600)
    boot = statestore.open(startup_db)
    now = boot.now()
    boot.op_insert(statestore.OpRow(
        op_id="fb005-blank", tool=OP_TOOL, agent="", vm_name="test-vm",
        status=statestore.OP_COMPLETED,
        created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="v5-migrated", heartbeat_at=now - 7200.0,
        params_hmac="",  # the pre-fingerprinting legacy shape
        result_json=None, generation=5, idem_key="fb005-blank",
    ))
    boot.close()
    _startup(cfg)
    s2 = _startup(cfg)
    survivor = s2.op_get("fb005-blank")
    assert survivor is not None, (
        "FB-005 (wave 4): startup pruning deleted a BLANK-FINGERPRINT "
        "legacy identity — like a generation-0 row it must reach the "
        "reconciliation refusal, never be silently forgotten by the sweep"
    )
    assert survivor.idem_key == "fb005-blank"


def _tasks_runner(cfg: Config, tool, sem):
    """The shipped tasks extension driven directly (the schedules-file
    _tasks_driver pattern): gate_fn passes, tool_fn_resolver serves the
    stand-in, runner_slots is the caller's semaphore."""
    ext = operations.tasks_extension(
        cfg,
        lambda name, arguments: (None, None),
        lambda name: tool,
        lambda: sem,
    )
    caps = SimpleNamespace(extensions={TASKS_ID: {}})
    ctx = SimpleNamespace(session=SimpleNamespace(client_capabilities=caps))

    def run(name, arguments):
        params = SimpleNamespace(name=name, arguments=dict(arguments))
        return asyncio.run(ext.intercept_tool_call(params, ctx, None))

    return run


def test_fb003_tasks_route_ignores_a_late_heartbeat_on_a_resolved_row(
        tmp_path, monkeypatch):
    """FB-003 wave 4 (b), tasks route: the TTL consult's heartbeat-freshness
    predicate has its OWN copy in tasks_extension; the shipped FB-003 (b)
    pin drives guard_consult only. An expired RESOLVED identity whose
    heartbeat_at was refreshed by a late beat must be forgotten by the TASKS
    route too (a fresh dispatch, a new task id), never replayed. RED under
    the tasks-route-only predicate mutation; GREEN at head."""
    clock = FakeClock(start=1000.0)
    db = str(tmp_path / "fb003-tasks-route.db")
    statestore.open(db).close()
    store = statestore.Store(db, clock=clock)
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)
    try:
        cfg = _ops_cfg(idempotency_ttl_s=100, heartbeat_ttl_s=60)
        args = {"vm_name": "test-vm", "checkpoint_name": "fb003t",
                "idempotency_key": "fb003t", "detach": True}
        clock.now = 2000.0
        store.op_insert(statestore.OpRow(
            op_id="fb003t-op", tool=OP_TOOL, agent="", vm_name="test-vm",
            status=statestore.OP_COMPLETED,
            created_at=1000.0, updated_at=1990.0, runner="sync-cc",
            heartbeat_at=1995.0,  # a late beat refreshed a TERMINAL row
            params_hmac=operations.arguments_fingerprint(cfg, store, args),
            idem_key="fb003t",
            result_json='{"ok": true, "status": "created"}',
            result_size=34, generation=3,
        ))
        run = _tasks_runner(cfg, _NoDispatchTool(),
                            threading.BoundedSemaphore(2))
        result = run(OP_TOOL, args)
        try:
            assert getattr(result, "task_id", None) != "fb003t-op", (
                f"FB-003 (wave 4): the tasks route replayed an expired "
                f"RESOLVED identity kept live by its late heartbeat instead "
                f"of dispatching fresh; got {result!r}"
            )
            assert store.op_get("fb003t-op") is None, (
                "FB-003 (wave 4): the expired resolved identity must be "
                "forgotten by the tasks route (op.expired)"
            )
        finally:
            operations.drain_for_tests(timeout_s=10.0)
    finally:
        store.close()
