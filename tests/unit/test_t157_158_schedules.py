"""Supplemental (non-frozen) schedule coverage for trace
157-158-durable-identity-repair-outcomes (approved plan, Change 7).

NOT in the checkpoint manifest: this file stays rewritable through feedback
rounds. Every family the plan's Change 7 names maps to a test here:

  S1  test_cross_route_saturation_matrix      — concurrent guard_consult +
      tasks-route calls across (inline / detached / tasks) x (identical key /
      conflicting fingerprint / different owner): at most one dispatch per
      protected attempt, reattach/conflict answered BEFORE capacity on every
      route, independent permit/handle counters balance.
  S2  test_send_gate_boundary_schedules       — the three boundary schedules
      (crash BEFORE the send-gate commit / crash AFTER authority validation
      before provider submission / crash AFTER the provider commit before the
      local acknowledgment), injected at the commit_send_intent / tool_fn /
      terminal-acknowledgment seams; per-boundary unknown-vs-attach semantics.
      The gate covers the pre-send COMMIT window only (the disclosed
      deviation from the plan's whole-body hold): the commit seam is
      operations.commit_send_intent, the crash-after-commit arm is a tool_fn
      (or BaseException) raising after the mark landed.
  S3  test_authority_transfer_fencing         — store.op_fence transfers
      authority: the old generation's heartbeat, send mark, terminal write
      AND idempotency release are refused; the new executor completes.
  S4  test_pool_dirty_epoch_fresh_bind_dance  — SessionPool restart borrow
      with a dirty epoch: a failed spawn (and a failing clear) leave the
      epoch dirty + raise SessionEpochDirty, the refusal is transient, the
      successful dance clears and proceeds, a mid-use dirty release closes
      instead of pooling, and concurrent recovery serializes (one dance).
  S4b test_default_pool_epoch_wiring          — install_default_pool wires
      epoch_reader/epoch_clear through operations.store_for (the ABA-guarded
      clear against the real vm_epochs table).
  S4c test_pool_clean_release_with_epoch_reader_pools — the CLEAN-epoch
      release companion (an xfail canary): documents the SRC DEFECT this
      file found in psdsessions.SessionPool.release — with an epoch_reader
      installed and a clean epoch, `victims` is never bound and the release
      raises UnboundLocalError (see the xfail reason; reported, not fixed
      here — supplemental tests may not modify src/).
  S5  test_run_pooled_raw_re_raises_epoch_dirty — SessionEpochDirty
      passthrough on BOTH acquire sites and the outer wrapper in
      guestexec._run_pooled_raw (never a silent per-call fallback).
  S6  test_acknowledgment_provenance_arms     — a completed restore's op row
      CLEARS send_state and is tombstone-prunable (never permanently
      retained); a post-send cancellation stays cancelled WITH send_state
      retained and the unknown disclosure in the view; the fail_inline
      post-send arm keeps send_state + OP_UNKNOWN with non-null result_json,
      replay attachment and prune protection (the detached BaseException
      twin of that arm is S2's mid-boundary schedule).
  S7  test_send_gate_identity_schedules       — the gate key canonicalizer
      (first-present of vm_name/name/vm_id, casefolded): GUID-only VMs get
      their own key, concurrent vm_create names serialize per name, the
      same-VM name-vs-GUID alias gap is the DOCUMENTED boundary (the epoch
      anchors the GUID), and an uncontended VM progresses while another
      VM's gate is held.
  S8  test_keyed_inline_generation_validation — a keyed-inline body's
      CAPTURED generation passes/fails the pre-send mark exactly per the
      fence; a live inline row past the idempotency TTL attaches with NO
      unknown classification (fresh heartbeat); a crashed inline row
      classifies unknown.
  S9  test_repair_intent_edit_and_directives  — #158: a non-default IPv4
      intent drives the emitted edit (intended value in the map, unrelated
      directives preserved), mixed valid+stale and IPv4/IPv6 planner arms.
  S10 test_repair_tripartite_observation_arms — #158: negative observation
      (finding still present), failed apply + healthy readback, the
      three-action scenario WITH intent asserting every action applied and
      the exact PowerShell leg order, and the ambiguous/invalid intent
      diagnostics.

What is faked: PowerShell only (the test_repair.py FakePS canned-leg pattern
and content-dispatched recorder tools), the pool's worker factory, and — for
the clock-sensitive schedules — the store's clock (statestore.Store(clock=)
through the operations.store_for seam). No sleeps beyond bounded event waits;
every store is closed in teardown (Windows file-lock teardown hazard) and
every detached runner is drained via operations.drain_for_tests.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import re
import threading
from types import SimpleNamespace

import pytest
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

from hyperv_mcp import (
    diagnostics,
    guestexec,
    lifecycle,
    operations,
    psdsessions,
    pswindows,
    repair,
    statestore,
    vmident,
    vmlocks,
)
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.statestore import StateStoreError

CRED = CredentialSet("Administrator", "placeholder-pass")
VM_GUID = "e953c649-1234-5678-9abc-def012345678"
OP_TOOL = "hyperv_checkpoint_create"
TASKS_ID = "io.modelcontextprotocol/tasks"


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


class FakeClock:
    """Deterministic wall clock for Store(path, clock=...)."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


class CountingSemaphore(threading.BoundedSemaphore):
    """BoundedSemaphore that counts successful acquire/release calls — the
    independent permit accounting the saturation schedules assert against."""

    def __init__(self, value=1):
        super().__init__(value)
        self.acquired = 0
        self.released = 0
        self._mu = threading.Lock()

    def acquire(self, blocking=True, timeout=None):
        ok = super().acquire(blocking, timeout)
        if ok:
            with self._mu:
                self.acquired += 1
        return ok

    def release(self):
        super().release()
        with self._mu:
            self.released += 1


class _GatedRecorder:
    """tool_fn stand-in that counts dispatches and blocks on a gate Event so
    a detached runner stays provably mid-flight (deterministic: the row is
    inserted before the handle returns; only the body is parked)."""

    def __init__(self) -> None:
        self.gate = threading.Event()
        self._mu = threading.Lock()
        self.calls = 0

    def __call__(self, **kwargs):
        with self._mu:
            self.calls += 1
        self.gate.wait(timeout=10.0)
        return {"ok": True, "status": "created"}


class _CountingTool:
    """tool_fn stand-in that counts dispatches and returns immediately."""

    def __init__(self) -> None:
        self._mu = threading.Lock()
        self.calls = 0

    def __call__(self, **kwargs):
        with self._mu:
            self.calls += 1
        return {"ok": True, "status": "created"}


class _NoDispatchTool:
    """tool_fn stand-in that FAILS the test if a consult-only retry ever
    reaches the body (at most one dispatch per protected attempt)."""

    def __call__(self, **kwargs):
        raise AssertionError("the protected retry re-dispatched the body")


class _PostSendBoom(BaseException):
    """A BaseException raised by the body AFTER the pre-send mark landed —
    the post-send ambiguity arm the runner must classify OP_UNKNOWN."""


@pytest.fixture()
def ops_store(tmp_path, monkeypatch):
    """A real temp Store injected through the operations.store_for seam.
    ALWAYS closed on teardown (Windows file-lock teardown hazard)."""
    store = statestore.open(str(tmp_path / "t157-sched-store.db"))
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)
    yield store
    store.close()


@pytest.fixture()
def admission_env():
    """Size the classed-admission budget the detached runners admit through
    (bootstrap sizes it in the server; a direct-drive test must size it the
    same way or every runner body dies at admit_sync). Cleared on teardown
    so no budget state leaks into other tests."""
    from hyperv_mcp import admission

    admission.reset()
    admission.configure(total_tokens=8, light_reserve=2, wait_s=0.5, light_wait_s=0.5)
    yield
    admission.reset()


@pytest.fixture()
def clock_store(tmp_path, monkeypatch):
    """A fake-clock Store behind the same seam, plus its clock — the
    heartbeat/idempotency TTL schedules advance time explicitly."""
    clock = FakeClock()
    db = str(tmp_path / "t157-sched-clock.db")
    statestore.open(db).close()
    store = statestore.Store(db, clock=clock)
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)

    def _close():
        store.close()

    yield store, clock
    _close()


@contextlib.contextmanager
def _agent(client_id: str):
    """Run the block as one authenticated caller (the tasks-bridge pattern):
    agent scoping of the ops rows is the different-owner axis of S1."""
    token = auth_context_var.set(
        AuthenticatedUser(AccessToken(token="t", client_id=client_id, scopes=[]))
    )
    try:
        yield
    finally:
        auth_context_var.reset(token)


def _tasks_driver(cfg, tool, sem):
    """The shipped tasks extension driven directly (the
    test_e03_guardrail.py interceptor pattern, without the server reload):
    gate_fn passes, tool_fn_resolver serves the recorder, runner_slots is the
    counting semaphore."""
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


def _failure_payload(result) -> dict:
    return json.loads(result.content[0].text)


def _bind_op_context(op_id: str, cfg: Config, generation: int | None):
    """Bind the op ContextVars the route layer owns (id + cfg + the CAPTURED
    generation) and return the reset tokens."""
    tokens = (
        operations._current_op_id.set(op_id),
        operations._current_ops_cfg.set(cfg),
    )
    if generation is not None:
        tokens += (operations._current_op_generation.set(int(generation)),)
    return tokens


def _reset_op_context(tokens) -> None:
    for token in reversed(tokens):
        try:
            token.var.reset(token)
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# S1 — cross-route saturation matrix
# ---------------------------------------------------------------------------


def test_cross_route_saturation_matrix(ops_store, admission_env):
    """S1: concurrent guard_consult + tasks-route calls across
    (inline/detached/tasks) x (identical key / conflicting fingerprint /
    different owner). One dispatch per protected attempt; reattach and
    conflict are answered BEFORE runner-slot acquisition on every route; a
    different owner gets its own row only once capacity exists."""
    cfg = Config(unrestricted=True)
    store = ops_store
    sem = CountingSemaphore(1)
    tool = _GatedRecorder()
    run_tasks = _tasks_driver(cfg, tool, sem)

    base = {"vm_name": "sat-vm", "checkpoint_name": "one",
            "idempotency_key": "sat-1", "detach": True}

    # (guard/detached, fresh): acquires the only permit, row inserted before
    # the handle returns; the body is parked on the tool's gate.
    resp_a, ctx_a = operations.guard_consult(cfg, OP_TOOL, base, tool, lambda: sem)
    assert ctx_a is None and resp_a.get("op_id") and resp_a["status"] == statestore.OP_WORKING
    op_a = resp_a["op_id"]
    assert sem.acquired == 1, "S1: the fresh detach acquires exactly one permit"

    # (tasks, identical key): reattach to the LIVE row, same handle, no extra
    # permit, no dispatch — answered before capacity.
    b = run_tasks(OP_TOOL, base)
    assert getattr(b, "task_id", "") == op_a, (
        f"S1 tasks-reattach: expected the original handle {op_a}; got {b!r}"
    )
    assert sem.acquired == 1, "S1: a tasks reattach must consume no runner slot"
    assert tool.calls <= 1

    # (guard/inline, identical key): attach to the same live row.
    resp_c, ctx_c = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "sat-vm", "checkpoint_name": "one", "idempotency_key": "sat-1"},
        _NoDispatchTool(), lambda: sem,
    )
    assert ctx_c is None and resp_c.get("op_id") == op_a and resp_c.get("replayed") is True, (
        f"S1 inline-reattach: expected the live handle with replayed; got {resp_c!r}"
    )
    assert tool.calls <= 1

    # (tasks, conflicting fingerprint): disclosed conflict, no capacity, no
    # dispatch.
    d = run_tasks(OP_TOOL, {**base, "checkpoint_name": "DIFFERENT"})
    payload_d = _failure_payload(d)
    assert payload_d.get("error_class") == "idempotency_conflict", payload_d
    assert sem.acquired == 1, "S1: a conflict refusal must consume no runner slot"
    assert tool.calls <= 1

    # (guard/detached, conflicting fingerprint): the same conflict envelope.
    resp_e, _ = operations.guard_consult(
        cfg, OP_TOOL, {**base, "checkpoint_name": "OTHER"},
        _NoDispatchTool(), lambda: sem,
    )
    assert resp_e.get("error_class") == "idempotency_conflict", resp_e
    assert tool.calls <= 1

    # (tasks, different owner): agent-scoped rows are independent, so this is
    # a FRESH dispatch attempt — refused busy at capacity with NO row minted.
    with _agent("sat-agent-b"):
        f1 = run_tasks(OP_TOOL, {"vm_name": "sat-vm", "checkpoint_name": "b",
                                 "idempotency_key": "sat-2", "detach": True})
        payload_f1 = _failure_payload(f1)
        assert payload_f1.get("error_class") == "busy", payload_f1
        assert store.op_rows_by_agent("sat-agent-b", include_terminal=True) == [], (
            "S1: a capacity-refused fresh dispatch must mint no op row"
        )
        assert sem.acquired == 1

        # Release the parked body: the original completes and frees capacity.
        tool.gate.set()
        assert operations.drain_for_tests(timeout_s=5.0) == 0, (
            "S1: a detached runner outlived its drain (cross-test interference)"
        )
        row_a = store.op_get(op_a)
        assert row_a is not None and row_a.status == statestore.OP_COMPLETED, (
            f"S1: the parked dispatch must complete; got {row_a.as_dict() if row_a else None}"
        )
        assert sem.released == 1

        # The different owner's retry now dispatches its OWN row.
        f2 = run_tasks(OP_TOOL, {"vm_name": "sat-vm", "checkpoint_name": "b",
                                 "idempotency_key": "sat-2", "detach": True})
        op_f = getattr(f2, "task_id", "")
        assert op_f and op_f != op_a
        assert sem.acquired == 2
        assert operations.drain_for_tests(timeout_s=5.0) == 0, (
            "S1: a detached runner outlived its drain (cross-test interference)"
        )
        assert tool.calls == 2, (
            f"S1: exactly one dispatch per protected attempt; tool ran {tool.calls} times"
        )

        # (guard/inline, different owner, identical key): attaches to the
        # tasks-created row — the tasks-to-guard cross-route arm. A terminal
        # row's replay embeds the STORED result; the attach (not a fresh
        # dispatch) is proven by the no-dispatch tool and the stable count.
        resp_g, ctx_g = operations.guard_consult(
            cfg, OP_TOOL,
            {"vm_name": "sat-vm", "checkpoint_name": "b", "idempotency_key": "sat-2"},
            _NoDispatchTool(), lambda: sem,
        )
        assert ctx_g is None and resp_g.get("replayed") is True and \
            resp_g.get("status") == "created", (
                f"S1 tasks-to-guard attach: expected the stored result with "
                f"replayed; got {resp_g!r}"
            )
        assert tool.calls == 2

    assert sem.released == sem.acquired == 2, (
        f"S1: permit accounting must balance; acquired={sem.acquired} released={sem.released}"
    )


# ---------------------------------------------------------------------------
# S2 — the three boundary schedules at the send-gate seam
# ---------------------------------------------------------------------------


def test_send_gate_boundary_schedules(clock_store, monkeypatch, admission_env):
    """S2: crash before the send-gate commit (no mark, ordinary classified
    failure, the retry replays the stored envelope); crash after authority
    validation before provider submission (the mark landed, a BaseException
    body yields the protected OP_UNKNOWN identity with replay attachment and
    prune protection); crash after the provider commit before the local
    acknowledgment (the tool ran, the completed write is lost — the row
    stays possibly_sent and read-time classifies unknown)."""
    cfg = Config(unrestricted=True)
    store, clock = clock_store
    sem = CountingSemaphore(1)

    # -- boundary 1: the crash precedes the commit (nothing marked) ---------
    def _raise_before_commit(cfg_arg, vm_key=""):
        raise RuntimeError("injected: crash before the send commit")

    tool1 = _CountingTool()
    mp1 = pytest.MonkeyPatch()
    try:
        mp1.setattr(operations, "commit_send_intent", _raise_before_commit)
        resp1, _ = operations.guard_consult(
            cfg, OP_TOOL,
            {"vm_name": "b1-vm", "checkpoint_name": "cp", "detach": True,
             "idempotency_key": "bnd-1"},
            tool1, lambda: sem,
        )
        op1 = resp1["op_id"]
        operations.drain_for_tests(timeout_s=5.0)
    finally:
        mp1.undo()
    row1 = store.op_get(op1)
    assert row1 is not None and row1.status == statestore.OP_FAILED, (
        f"S2 b1: the pre-commit crash must close the row failed; got "
        f"{row1.as_dict() if row1 else None}"
    )
    assert row1.send_state == "", (
        "S2 b1: a crash before the send-gate commit must leave the row unmarked"
    )
    assert row1.error_class == "transport"
    assert tool1.calls == 0, (
        "S2 b1: a crash before the send commit must never submit the provider leg"
    )
    resp1b, ctx1b = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "b1-vm", "checkpoint_name": "cp", "idempotency_key": "bnd-1"},
        _NoDispatchTool(), lambda: sem,
    )
    assert ctx1b is None and resp1b.get("replayed") is True and \
        "crash before the send commit" in resp1b.get("error", ""), (
            f"S2 b1: the retry replays the stored ordinary-failure envelope "
            f"(same row, no re-dispatch); got {resp1b!r}"
        )
    assert "vm_outcome" not in resp1b, (
        f"S2 b1: an unmarked crash is no unknown-outcome identity; got {resp1b!r}"
    )

    # -- boundary 2: the mark landed, the body dies before submitting -------
    def _boom_body(**kwargs):
        raise _PostSendBoom("crash after authority validation, before submission")

    resp2, _ = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "b2-vm", "checkpoint_name": "cp", "detach": True,
         "idempotency_key": "bnd-2"},
        _boom_body, lambda: sem,
    )
    op2 = resp2["op_id"]
    operations.drain_for_tests(timeout_s=5.0)
    row2 = store.op_get(op2)
    assert row2 is not None and row2.status == statestore.OP_FAILED
    assert row2.error_class == statestore.OP_UNKNOWN, (
        f"S2 b2: a post-mark body crash must classify unknown; got {row2.as_dict()}"
    )
    assert row2.send_state == "possibly_sent", (
        "S2 b2: the send mark must be retained on the unknown identity"
    )
    assert row2.result_json, "S2 b2: the unknown row must keep a non-null result payload"
    resp2b, ctx2b = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "b2-vm", "checkpoint_name": "cp", "idempotency_key": "bnd-2"},
        _NoDispatchTool(), lambda: sem,
    )
    assert ctx2b is None and resp2b.get("op_id") == op2, (
        f"S2 b2: the retry must attach to the unknown identity; got {resp2b!r}"
    )
    assert resp2b.get("vm_outcome") == "unknown", resp2b
    store.ops_prune(clock() + 10.0 ** 6)
    survivor2 = store.op_get(op2)
    assert survivor2 is not None and survivor2.result_json, (
        "S2 b2: an unknown identity is pruned neither in row nor in payload"
    )

    # -- boundary 3: the provider committed, the local acknowledgment lost --
    tool3 = _CountingTool()

    def _failing_transition(*args, **kwargs):
        raise StateStoreError("injected: acknowledgment write lost")

    mp3 = pytest.MonkeyPatch()
    try:
        mp3.setattr(store, "op_transition", _failing_transition)
        resp3, _ = operations.guard_consult(
            cfg, OP_TOOL,
            {"vm_name": "b3-vm", "checkpoint_name": "cp", "detach": True,
             "idempotency_key": "bnd-3"},
            tool3, lambda: sem,
        )
        op3 = resp3["op_id"]
        operations.drain_for_tests(timeout_s=5.0)
    finally:
        mp3.undo()
    assert tool3.calls == 1, "S2 b3: the provider effect (the body) must have run"
    row3 = store.op_get(op3)
    assert row3 is not None and row3.status == statestore.OP_WORKING, (
        f"S2 b3: the lost acknowledgment must leave the row working; got "
        f"{row3.as_dict() if row3 else None}"
    )
    assert row3.send_state == "possibly_sent"
    clock.advance(7200.0)
    status3 = operations.op_status(cfg, op3, "")
    assert status3.get("status") == statestore.OP_FAILED and \
        status3.get("error_class") == statestore.OP_UNKNOWN, (
            f"S2 b3: the post-commit lost reply must classify unknown; got {status3!r}"
        )
    assert status3.get("vm_outcome") == "unknown"
    resp3b, ctx3b = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "b3-vm", "checkpoint_name": "cp", "idempotency_key": "bnd-3"},
        _NoDispatchTool(), lambda: sem,
    )
    assert ctx3b is None and resp3b.get("op_id") == op3 and \
        resp3b.get("vm_outcome") == "unknown", (
            f"S2 b3: the retry attaches to the unknown identity, no re-dispatch; "
            f"got {resp3b!r}"
        )
    assert sem.released == sem.acquired


# ---------------------------------------------------------------------------
# S3 — authority transfer (op_fence)
# ---------------------------------------------------------------------------


def test_authority_transfer_fencing(ops_store):
    """S3: fencing a live row moves authority to a new generation — the old
    executor's heartbeat, send mark, terminal write and idempotency release
    are all refused; the new executor marks, releases and completes."""
    store = ops_store
    gen = store.op_next_generation()
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="fence-op", tool=OP_TOOL, agent="", vm_name="fence-vm",
        status=statestore.OP_WORKING, created_at=now, updated_at=now,
        runner="old-executor", heartbeat_at=now, params_hmac="fp",
        idem_key="fence-key", generation=gen,
    ))
    new_gen = store.op_fence("fence-op")
    assert new_gen == gen + 1, (
        f"S3: the fence must bump the generation; {gen} -> {new_gen}"
    )

    # The OLD generation cannot keep the row alive.
    hb_before = store.op_get("fence-op").heartbeat_at
    store.op_heartbeat("fence-op", now + 500.0, generation=gen)
    assert store.op_get("fence-op").heartbeat_at == hb_before, (
        "S3: a fenced executor's heartbeat must be refused"
    )
    # The NEW generation can.
    store.op_heartbeat("fence-op", now + 500.0, generation=new_gen)
    assert store.op_get("fence-op").heartbeat_at == now + 500.0

    # The OLD generation cannot mark the send.
    assert store.op_mark_send("fence-op", gen) is False, (
        "S3: a fenced executor's send mark must fail closed"
    )
    assert store.op_get("fence-op").send_state == ""
    # The NEW generation can.
    assert store.op_mark_send("fence-op", new_gen) is True
    assert store.op_get("fence-op").send_state == "possibly_sent"

    # The OLD generation cannot terminal-write over the replacement.
    assert store.op_transition(
        "fence-op", (statestore.OP_WORKING,), statestore.OP_FAILED,
        generation=gen, updated_at=store.now(),
    ) is False, "S3: a fenced executor's terminal write must be refused"
    assert store.op_get("fence-op").status == statestore.OP_WORKING

    # The OLD generation's busy/cancellation epilogue cannot clear the
    # replacement's idempotency slot (round-4 blocker 4).
    store.op_release_idem("fence-op", generation=gen)
    assert store.op_get("fence-op").idem_key == "fence-key", (
        "S3: a fenced executor's idempotency release must be refused"
    )
    store.op_release_idem("fence-op", generation=new_gen)
    assert store.op_get("fence-op").idem_key == "", (
        "S3: the replacement generation frees its own idempotency slot"
    )

    # The NEW executor completes (and the completion clears the send mark).
    assert store.op_transition(
        "fence-op", (statestore.OP_WORKING,), statestore.OP_COMPLETED,
        generation=new_gen, updated_at=store.now(),
    ) is True
    fresh = store.op_get("fence-op")
    assert fresh.status == statestore.OP_COMPLETED and fresh.send_state == ""


# ---------------------------------------------------------------------------
# S4 — restart pool borrow with a dirty epoch (the fresh-bind dance)
# ---------------------------------------------------------------------------

POOL_GUID = "11111111-2222-3333-4444-555555555555"
POOL_KEY = (POOL_GUID, "guest:Administrator", "agent-a", None)


class _StubWorker:
    def __init__(self, factory) -> None:
        self._factory = factory
        self.closed = False

    def is_alive(self) -> bool:
        return not self.closed

    def close(self) -> None:
        self.closed = True
        self._factory.closed_count += 1


class _StubFactory:
    """Worker factory that can fail its first `fail_first` spawns and records
    every spawn + close (the test_c02/d05 pool-test pattern)."""

    def __init__(self, fail_first: int = 0) -> None:
        self.calls = 0
        self.closed_count = 0
        self.fail_first = fail_first
        self.spawned = threading.Event()

    def __call__(self, key, script, stdin_b64):
        self.calls += 1
        index = self.calls
        self.spawned.set()
        if index <= self.fail_first:
            raise RuntimeError("injected spawn failure")
        return _StubWorker(self)


def test_pool_dirty_epoch_fresh_bind_dance(ops_store):
    """S4: a dirty durable epoch makes the pool borrow run the serialized
    fresh-bind dance. A failed spawn leaves the epoch dirty and raises
    SessionEpochDirty — transiently (the next borrow retries); a failing
    expected-epoch clear discards the fresh worker and keeps the epoch dirty;
    the successful dance clears and proceeds; a session released while its
    VM's epoch turned dirty mid-use is CLOSED, not pooled; and two
    concurrent dirty borrows run ONE dance (the per-VM recovery lock)."""
    store = ops_store

    def _reader(vm_key):
        return store.epoch_snapshot(vm_key)

    def _clear(vm_key, expected_epoch):
        return store.epoch_clear_dirty(vm_key, expected_epoch)

    # (a) failed spawn: dirty stays, SessionEpochDirty, refusal transient.
    # NOTE: this arm never calls release() on a CLEAN epoch — see
    # test_pool_clean_release_with_epoch_reader_pools (the xfail canary for
    # the psdsessions.release UnboundLocalError found by this schedule file).
    store.epoch_bump(POOL_GUID)
    factory_a = _StubFactory(fail_first=1)
    pool_a = psdsessions.SessionPool(
        factory_a, epoch_reader=_reader, epoch_clear=_clear,
    )
    with pytest.raises(psdsessions.SessionEpochDirty):
        pool_a.acquire(POOL_KEY)
    assert store.epoch_snapshot(POOL_GUID) == (1, "dirty"), (
        "S4a: a failed fresh-bind dance must leave the epoch dirty"
    )
    assert factory_a.closed_count == 0
    worker_a = pool_a.acquire(POOL_KEY)
    assert factory_a.calls == 2, (
        "S4a: the dirty-epoch refusal must be transient (the next borrow "
        "retries the dance)"
    )
    assert store.epoch_snapshot(POOL_GUID) == (1, "clean"), (
        "S4a: the successful dance clears the dirty epoch"
    )
    assert isinstance(worker_a, _StubWorker) and not worker_a.closed
    pool_a.close_all()

    # (b) the expected-epoch clear fails: the fresh worker is discarded+closed
    # and the epoch STAYS dirty.
    store.epoch_bump(POOL_GUID)
    factory_b = _StubFactory()
    pool_b = psdsessions.SessionPool(
        factory_b, epoch_reader=_reader, epoch_clear=lambda g, e: False,
    )
    with pytest.raises(psdsessions.SessionEpochDirty):
        pool_b.acquire(POOL_KEY)
    assert store.epoch_snapshot(POOL_GUID) == (2, "dirty"), (
        "S4b: an unproven fresh bind must never clear the epoch"
    )
    assert factory_b.closed_count >= 1, (
        "S4b: the post-spawn dance failure must close the fresh worker"
    )
    pool_b.close_all()

    # (c) mid-use dirty release: CLOSED instead of pooled.
    assert store.epoch_clear_dirty(POOL_GUID, 2) is True
    factory_c = _StubFactory()
    pool_c = psdsessions.SessionPool(
        factory_c, epoch_reader=_reader, epoch_clear=_clear,
    )
    w1 = pool_c.acquire(POOL_KEY)
    store.epoch_bump(POOL_GUID)
    pool_c.release(w1)
    assert w1.closed, (
        "S4c: a session returning while its epoch is dirty must be closed"
    )
    w2 = pool_c.acquire(POOL_KEY)
    assert w2 is not w1, "S4c: the dirty-released session must never be reused"
    assert store.epoch_snapshot(POOL_GUID)[1] == "clean"
    pool_c.close_all()

    # (d) concurrent dirty borrows serialize: ONE dance, the second caller
    # waits for the recovery lock and then finds the entry checked out.
    store.epoch_bump(POOL_GUID)
    factory_d = _StubFactory()
    clear_gate = threading.Event()

    def _gated_clear(vm_key, expected_epoch):
        clear_gate.wait(timeout=5.0)
        return store.epoch_clear_dirty(vm_key, expected_epoch)

    pool_d = psdsessions.SessionPool(
        factory_d, epoch_reader=_reader, epoch_clear=_gated_clear,
    )
    results: dict[str, object] = {}

    def _borrow(tag):
        try:
            results[tag] = pool_d.acquire(POOL_KEY)
        except BaseException as exc:  # noqa: BLE001 — recorded, asserted below
            results[tag] = exc

    t1 = threading.Thread(target=_borrow, args=("t1",), daemon=True)
    t1.start()
    assert factory_d.spawned.wait(timeout=5.0), "S4d: the first dance never spawned"
    t2 = threading.Thread(target=_borrow, args=("t2",), daemon=True)
    t2.start()
    clear_gate.set()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)
    assert not t1.is_alive() and not t2.is_alive()
    assert isinstance(results["t1"], _StubWorker), (
        f"S4d: the first caller must get the dance's fresh worker; got {results['t1']!r}"
    )
    assert isinstance(results["t2"], psdsessions.SessionBusy), (
        f"S4d: the serialized second caller must wait, not re-dance; got {results['t2']!r}"
    )
    assert factory_d.calls == 1, (
        f"S4d: concurrent recovery must run ONE fresh-bind dance; the factory "
        f"ran {factory_d.calls} times"
    )
    pool_d.close_all()


def test_pool_clean_release_with_epoch_reader_pools(ops_store):
    """S4 pin (the src fix landed in this PR): with the epoch consults
    wired, returning a session while its VM's epoch is CLEAN must POOL it —
    the next borrow reuses the same worker identity (the release-path consult
    never strands a normal pooled return; the UnboundLocalError this test
    documented as an xfail canary was fixed before publication)."""
    factory = _StubFactory()
    pool = psdsessions.SessionPool(
        factory,
        epoch_reader=ops_store.epoch_snapshot,
        epoch_clear=ops_store.epoch_clear_dirty,
    )
    try:
        w1 = pool.acquire(POOL_KEY)
        assert ops_store.epoch_snapshot(POOL_GUID) == (0, "clean")
        pool.release(w1)
        w2 = pool.acquire(POOL_KEY)
        assert w2 is w1, (
            "a clean-epoch release must pool the session for identity reuse"
        )
        assert factory.calls == 1
        pool.release(w2)
    finally:
        pool.close_all()


def test_default_pool_epoch_wiring(ops_store):
    """S4b: install_default_pool wires epoch_reader/epoch_clear through
    operations.store_for — the borrow/return consults read and clear the
    REAL vm_epochs table, ABA-guarded on the expected epoch."""
    cfg = Config(unrestricted=True)
    pool = psdsessions.install_default_pool(cfg)
    try:
        assert pool is not None, "S4b: the default pool must install at the default cap"
        assert callable(pool.epoch_reader) and callable(pool.epoch_clear)
        assert pool.epoch_reader(POOL_GUID) == (0, "clean")
        bumped = ops_store.epoch_bump(POOL_GUID)
        assert pool.epoch_reader(POOL_GUID) == (bumped, "dirty")
        assert pool.epoch_clear(POOL_GUID, bumped) is True
        assert pool.epoch_reader(POOL_GUID) == (bumped, "clean")
        assert pool.epoch_clear(POOL_GUID, bumped) is False, (
            "S4b: the clear is expected-epoch guarded (an already-clean epoch "
            "does not clear again)"
        )
    finally:
        psdsessions.close_default_pool()


# ---------------------------------------------------------------------------
# S5 — SessionEpochDirty passthrough in guestexec._run_pooled_raw
# ---------------------------------------------------------------------------


class _SessionPhaseResult:
    def __init__(self) -> None:
        self.stdout = json.dumps({"phase": "session", "exit_code": 0})
        self.stderr = ""
        self.timed_out = False
        self.duration_ms = 0


class _SessionPhaseWorker:
    def run(self, script, elevated=False, timeout_ms=0):
        return _SessionPhaseResult()


class _FirstAcquireDirtyPool:
    def acquire(self, key, wait_s, cred=None):
        raise psdsessions.SessionEpochDirty("dirty on the first acquire")


class _BusyPool:
    def acquire(self, key, wait_s, cred=None):
        raise psdsessions.SessionBusy("every session in use")


class _SecondAcquireDirtyPool:
    def __init__(self) -> None:
        self.calls = 0
        self.discarded: list = []

    def acquire(self, key, wait_s, cred=None):
        self.calls += 1
        if self.calls == 1:
            return _SessionPhaseWorker()
        raise psdsessions.SessionEpochDirty("dirty on the re-acquire")

    def take_open_cost(self, session):
        return None

    def discard(self, worker):
        self.discarded.append(worker)

    def release(self, worker):
        pass


def test_run_pooled_raw_re_raises_epoch_dirty():
    """S5: the dirty-epoch refusal is DISCLOSED at the tool boundary — both
    acquire sites and the outer wrapper in _run_pooled_raw re-raise
    SessionEpochDirty instead of returning None (the per-call fallback); any
    other acquire failure keeps the documented None fallback."""
    cfg = Config(unrestricted=True)

    with pytest.raises(psdsessions.SessionEpochDirty):
        guestexec._run_pooled_raw(cfg, _FirstAcquireDirtyPool(), VM_GUID,
                                  "Write-Output one", CRED, 60000)

    pool = _SecondAcquireDirtyPool()
    with pytest.raises(psdsessions.SessionEpochDirty):
        guestexec._run_pooled_raw(cfg, pool, VM_GUID, "Write-Output two", CRED, 60000)
    assert pool.calls == 2, "S5: the second acquire site must have been reached"
    assert len(pool.discarded) == 1, "S5: the session-phase worker was discarded first"

    assert guestexec._run_pooled_raw(cfg, _BusyPool(), VM_GUID,
                                     "Write-Output three", CRED, 60000) is None, (
        "S5: a non-epoch acquire failure keeps the per-call fallback (None)"
    )


# ---------------------------------------------------------------------------
# S6 — acknowledgment / provenance arms
# ---------------------------------------------------------------------------


def _lifecycle_run_ok(cfg, script, **kwargs):
    if "final_state" in script:
        return pswindows.PSResult(stdout=json.dumps({"final_state": "Off"}), returncode=0)
    return pswindows.PSResult(stdout="", returncode=0)


def test_acknowledgment_provenance_arms(tmp_path, monkeypatch, ops_store):
    """S6: (a) a completed restore's op row CLEARS its send_state and is
    tombstone-prunable — retention is never permanent (M13's home: the
    boundary commit marks + dirties the epoch atomically, the completion
    acknowledges); (b) a post-send cancellation stays cancelled WITH the
    send_state retained and the view discloses the unknown outcome; (c) the
    fail_inline post-send arm keeps send_state + OP_UNKNOWN with a non-null
    result payload, replay attachment and prune protection."""
    cfg = Config(unrestricted=True)
    store = ops_store

    # -- (a) completed restore: mark at the boundary, clear at the ack -------
    monkeypatch.setattr(
        vmident, "resolve",
        lambda cfg, vm_name="", vm_id="": vmident.VMRef(VM_GUID, vm_name or "ack-vm"),
    )
    monkeypatch.setattr(vmlocks, "vm_lock", lambda key, mode="write": contextlib.nullcontext())
    monkeypatch.setattr(pswindows, "check_result", lambda result, ctx="": None)
    invalidated: list[str] = []
    monkeypatch.setattr(
        psdsessions, "invalidate_vm",
        lambda vm_guid, reason=None: (invalidated.append(vm_guid), 0)[1],
    )
    monkeypatch.setattr(lifecycle, "_run", _lifecycle_run_ok)

    _, ctx_a = operations.guard_consult(
        cfg, "hyperv_checkpoint_restore",
        {"vm_name": "ack-vm", "checkpoint_name": "cp", "confirm": True,
         "idempotency_key": "ack-restore"},
        _NoDispatchTool(), lambda: CountingSemaphore(1),
    )
    assert ctx_a is not None, "S6a: expected the inline op context"
    tokens = _bind_op_context(ctx_a["op_id"], cfg, ctx_a["generation"])
    try:
        out = lifecycle.checkpoint_restore(
            cfg, vm_name="ack-vm", checkpoint_name="cp", confirm=True,
        )
    finally:
        _reset_op_context(tokens)
    assert out.get("status") == "restored", f"S6a: restore stub failed: {out!r}"
    row_a = store.op_get(ctx_a["op_id"])
    assert row_a is not None and row_a.send_state == "possibly_sent", (
        "S6a: the restore boundary commit must mark the keyed row"
    )
    assert store.epoch_snapshot(VM_GUID) == (1, "dirty"), (
        "S6a: the boundary commit dirties the epoch in the same transaction"
    )
    assert invalidated, "S6a: the acknowledged restore invalidates pooled sessions"
    operations.complete_inline(ctx_a, out)
    row_a = store.op_get(ctx_a["op_id"])
    assert row_a.status == statestore.OP_COMPLETED and row_a.send_state == "", (
        f"S6a (M13): a completed restore clears its send mark; got {row_a.as_dict()}"
    )
    store.ops_prune(store.now() + 10.0 ** 6)
    tomb = store.op_get(ctx_a["op_id"])
    assert tomb is not None and tomb.result_json is None, (
        "S6a: a completed restore tombstones (payload pruned, identity kept)"
    )
    store.ops_prune(store.now() + 10.0 ** 6, replay_cutoff=store.now() + 2 * 10.0 ** 6)
    assert store.op_get(ctx_a["op_id"]) is None, (
        "S6a: the resolved tombstone is deleted past the replay window — "
        "retention is never permanent"
    )

    # -- (b) post-send cancellation: mark retained + unknown disclosure ------
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="ack-cancel", tool=OP_TOOL, agent="", vm_name="ack-vm",
        status=statestore.OP_WORKING, created_at=now, updated_at=now,
        runner="ack-runner", heartbeat_at=now, generation=5,
    ))
    assert store.op_mark_send("ack-cancel", 5) is True
    assert store.op_transition(
        "ack-cancel", (statestore.OP_WORKING,), statestore.OP_CANCELLED,
        updated_at=store.now(),
    ) is True
    row_b = store.op_get("ack-cancel")
    assert row_b.status == statestore.OP_CANCELLED and \
        row_b.send_state == "possibly_sent", (
            f"S6b: a post-send cancellation retains the send mark; got {row_b.as_dict()}"
        )
    view_b = operations.op_status(cfg, "ack-cancel", "")
    assert view_b.get("vm_outcome") == "unknown" and \
        "cancel honored after the send commit" in view_b.get("note", ""), (
            f"S6b: the view must disclose the uncertain VM-side outcome; got {view_b!r}"
        )
    store.ops_prune(store.now() + 10.0 ** 6)
    assert store.op_get("ack-cancel") is not None, (
        "S6b: a possibly_sent cancelled row is pruned never"
    )

    # -- (c) fail_inline AFTER the mark: OP_UNKNOWN + replay + prune shield --
    _, ctx_c = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "ack-vm", "checkpoint_name": "cp", "idempotency_key": "ack-fi"},
        _NoDispatchTool(), lambda: CountingSemaphore(1),
    )
    assert ctx_c is not None
    tokens_c = _bind_op_context(ctx_c["op_id"], cfg, ctx_c["generation"])
    try:
        operations.commit_send_intent(cfg)
    finally:
        _reset_op_context(tokens_c)
    operations.fail_inline(ctx_c, RuntimeError("post-send inline failure"))
    row_c = store.op_get(ctx_c["op_id"])
    assert row_c.status == statestore.OP_FAILED and \
        row_c.error_class == statestore.OP_UNKNOWN, (
            f"S6c: a post-send inline failure classifies unknown; got {row_c.as_dict()}"
        )
    assert row_c.send_state == "possibly_sent" and row_c.result_json
    resp_c2, ctx_c2 = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "ack-vm", "checkpoint_name": "cp", "idempotency_key": "ack-fi"},
        _NoDispatchTool(), lambda: CountingSemaphore(1),
    )
    assert ctx_c2 is None and resp_c2.get("op_id") == ctx_c["op_id"] and \
        resp_c2.get("vm_outcome") == "unknown", (
            f"S6c: the retry attaches to the protected identity; got {resp_c2!r}"
        )
    store.ops_prune(store.now() + 10.0 ** 6)
    survivor_c = store.op_get(ctx_c["op_id"])
    assert survivor_c is not None and survivor_c.result_json, (
        "S6c: the unknown identity keeps its payload through retention"
    )


# ---------------------------------------------------------------------------
# S7 — gate-identity schedules
# ---------------------------------------------------------------------------

S7_GUID = "aaaa7777-8888-9999-0000-111122223333"


def test_send_gate_identity_schedules(ops_store, admission_env):
    """S7: the send-gate key is the casefolded FIRST PRESENT of
    (vm_name, name, vm_id). GUID-only VMs get their own key; vm_create names
    serialize per name; the same VM addressed once by name and once by GUID
    gets TWO keys (the documented alias boundary — durability stays anchored
    to the GUID the body resolves, where the epoch lives); and a dispatch
    for an uncontended VM completes while another VM's gate is held (the
    held VM's own runner takes the disclosed busy refusal instead)."""
    key = operations._send_gate_key
    assert key({"vm_name": "S7-Held-VM"}) == key({"vm_name": "s7-held-vm"}) == "s7-held-vm"
    assert key({"name": "New-VM"}) == "new-vm"
    assert key({"vm_id": S7_GUID}) == S7_GUID.lower()
    assert key({"vm_name": "", "name": "n", "vm_id": "g"}) == "n"
    assert key({}) == ""
    # The documented same-VM alias boundary: name-key vs GUID-key differ.
    assert key({"vm_name": "s7-held-vm"}) != key({"vm_id": S7_GUID})

    held = operations._send_gate_acquire({"vm_name": "S7-Held-VM"})
    assert held
    try:
        # Casefolded contention on the same name.
        assert operations._send_gate_acquire({"vm_name": "s7-HELD-vm"}) is False
        # A GUID-only VM is a different key: independently acquirable.
        assert operations._send_gate_acquire({"vm_id": S7_GUID}) is True
        operations._send_gate_release({"vm_id": S7_GUID})
        # Concurrent vm_create: per-name keys, same name contended.
        assert operations._send_gate_acquire({"name": "s7-created-a"}) is True
        assert operations._send_gate_acquire({"name": "S7-CREATED-A"}) is False
        assert operations._send_gate_acquire({"name": "s7-created-b"}) is True
        operations._send_gate_release({"name": "s7-created-a"})
        operations._send_gate_release({"name": "s7-created-b"})
    finally:
        operations._send_gate_release({"vm_name": "S7-Held-VM"})
    assert operations._send_gate_acquire({"vm_name": "s7-held-vm"}) is True
    operations._send_gate_release({"vm_name": "s7-held-vm"})

    # Independent progress through a REAL dispatch while the gate is held:
    # the free VM's runner commits and completes; the held VM's runner takes
    # the disclosed busy refusal (its gate acquire is non-blocking).
    cfg = Config(unrestricted=True)
    sem = CountingSemaphore(2)
    operations._send_gate_acquire({"vm_name": "S7-Held-VM"})
    try:
        tool_free = _CountingTool()
        resp_free, _ = operations.guard_consult(
            cfg, OP_TOOL,
            {"vm_name": "s7-free-vm", "checkpoint_name": "cp", "detach": True,
             "idempotency_key": "s7-free"},
            tool_free, lambda: sem,
        )
        operations.drain_for_tests(timeout_s=5.0)
        row_free = ops_store.op_get(resp_free["op_id"])
        assert row_free is not None and \
            row_free.status == statestore.OP_COMPLETED, (
                f"S7: an uncontended VM must progress while another VM's gate "
                f"is held; got {row_free.as_dict() if row_free else None}"
            )
        assert tool_free.calls == 1

        tool_held = _CountingTool()
        resp_held, _ = operations.guard_consult(
            cfg, OP_TOOL,
            {"vm_name": "S7-Held-VM", "checkpoint_name": "cp", "detach": True,
             "idempotency_key": "s7-held"},
            tool_held, lambda: sem,
        )
        operations.drain_for_tests(timeout_s=5.0)
        row_held = ops_store.op_get(resp_held["op_id"])
        # Issue #157 (final critic F2): a detached RUNNER acquires the gate
        # BLOCKING - it waits its turn on the held VM (a queued wait beats
        # a wedged idempotency key). Free the gate, then the runner proceeds.
        operations._send_gate_release({"vm_name": "S7-Held-VM"})
        operations.drain_for_tests(timeout_s=5.0)
        row_held = ops_store.op_get(resp_held["op_id"])
        assert row_held is not None and row_held.status == statestore.OP_COMPLETED, (
            f"S7: the contended VM's runner must WAIT on the gate and proceed "
            f"once it frees; got {row_held.as_dict() if row_held else None}"
        )
        assert tool_held.calls == 1, (
            "S7: the held runner must submit after the gate frees"
        )
    finally:
        operations._send_gate_release({"vm_name": "S7-Held-VM"})
    assert sem.released == sem.acquired


# ---------------------------------------------------------------------------
# S8 — keyed-inline nonzero-generation validation (M14's home)
# ---------------------------------------------------------------------------


def test_keyed_inline_generation_validation(clock_store):
    """S8: the keyed-inline dispatch validates its CAPTURED generation at the
    pre-send mark — the pass arm marks, the fenced arm fails closed without
    marking, and the legacy shape (generation 0, no bound ContextVar
    generation) validates against its generation-0 row. A live inline row
    past the idempotency TTL attaches with NO unknown classification (its
    heartbeat is fresh); a crashed inline row (lapsed, marked) classifies
    unknown."""
    cfg = Config(unrestricted=True)
    store, clock = clock_store

    # -- pass arm: the captured generation marks -----------------------------
    _, ctx_p = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "m14-vm", "checkpoint_name": "cp", "idempotency_key": "m14-pass"},
        _NoDispatchTool(), lambda: CountingSemaphore(1),
    )
    assert ctx_p is not None and ctx_p["generation"] >= 1
    tokens = _bind_op_context(ctx_p["op_id"], cfg, ctx_p["generation"])
    try:
        operations.commit_send_intent(cfg)
    finally:
        _reset_op_context(tokens)
    assert store.op_get(ctx_p["op_id"]).send_state == "possibly_sent"
    operations.complete_inline(ctx_p, {"ok": True, "status": "created"})
    done_p = store.op_get(ctx_p["op_id"])
    assert done_p.status == statestore.OP_COMPLETED and done_p.send_state == ""

    # -- fail arm: the fence moves, the captured generation fails closed -----
    _, ctx_f = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "m14-vm", "checkpoint_name": "cp", "idempotency_key": "m14-fail"},
        _NoDispatchTool(), lambda: CountingSemaphore(1),
    )
    assert ctx_f is not None
    fenced = store.op_fence(ctx_f["op_id"])
    assert fenced == ctx_f["generation"] + 1
    tokens_f = _bind_op_context(ctx_f["op_id"], cfg, ctx_f["generation"])
    try:
        with pytest.raises(RuntimeError, match="send authority"):
            operations.commit_send_intent(cfg)
    finally:
        _reset_op_context(tokens_f)
    assert store.op_get(ctx_f["op_id"]).send_state == "", (
        "S8: a fenced inline executor must not mark the send (fail-closed)"
    )

    # -- legacy arm: generation 0 (no bound generation) validates ------------
    t0 = clock.now
    store.op_insert(statestore.OpRow(
        op_id="m14-legacy", tool=OP_TOOL, agent="", vm_name="m14-vm",
        status=statestore.OP_WORKING, created_at=t0, updated_at=t0,
        runner="", heartbeat_at=t0, generation=0,
    ))
    tokens_0 = _bind_op_context("m14-legacy", cfg, None)
    try:
        operations.commit_send_intent(cfg)
    finally:
        _reset_op_context(tokens_0)
    assert store.op_get("m14-legacy").send_state == "possibly_sent", (
        "S8: the legacy/direct shape validates generation 0 against its "
        "generation-0 row"
    )

    # -- live inline past the TTL: attaches, no unknown classification -------
    live_args = {"vm_name": "m14-vm", "checkpoint_name": "live",
                 "idempotency_key": "m14-live"}
    live_fp = operations.arguments_fingerprint(cfg, store, live_args)
    store.op_insert(statestore.OpRow(
        op_id="m14-live-op", tool=OP_TOOL, agent="", vm_name="m14-vm",
        status=statestore.OP_WORKING,
        created_at=t0 - 90_000.0, updated_at=t0,   # past the 86400 s idem TTL
        runner="sync-live",
        heartbeat_at=t0 - 5.0,                     # fresh (inside 60 s)
        params_hmac=live_fp, idem_key="m14-live",
        generation=1, send_state="possibly_sent",
    ))
    resp_l, ctx_l = operations.guard_consult(
        cfg, OP_TOOL, live_args, _NoDispatchTool(), lambda: CountingSemaphore(1),
    )
    assert ctx_l is None and resp_l.get("op_id") == "m14-live-op" and \
        resp_l.get("status") == statestore.OP_WORKING and \
        resp_l.get("replayed") is True, (
            f"S8: a live inline row past the TTL must attach as the live "
            f"handle; got {resp_l!r}"
        )
    assert "vm_outcome" not in resp_l, (
        f"S8: no unknown classification for a live inline handle; got {resp_l!r}"
    )

    # -- crashed inline (marked, lapsed): classifies unknown -----------------
    dead_args = {"vm_name": "m14-vm", "checkpoint_name": "dead",
                 "idempotency_key": "m14-dead"}
    dead_fp = operations.arguments_fingerprint(cfg, store, dead_args)
    store.op_insert(statestore.OpRow(
        op_id="m14-dead-op", tool=OP_TOOL, agent="", vm_name="m14-vm",
        status=statestore.OP_WORKING,
        created_at=t0 - 7_200.0, updated_at=t0 - 7_200.0,
        runner="sync-dead",
        heartbeat_at=t0 - 7_200.0,                 # lapsed past 60 s
        params_hmac=dead_fp, idem_key="m14-dead",
        generation=1, send_state="possibly_sent",
    ))
    status_d = operations.op_status(cfg, "m14-dead-op", "")
    assert status_d.get("status") == statestore.OP_FAILED and \
        status_d.get("error_class") == statestore.OP_UNKNOWN and \
        status_d.get("vm_outcome") == "unknown", (
            f"S8: a crashed (lapsed, marked) inline row classifies unknown; "
            f"got {status_d!r}"
        )
    resp_d, ctx_d = operations.guard_consult(
        cfg, OP_TOOL, dead_args, _NoDispatchTool(), lambda: CountingSemaphore(1),
    )
    assert ctx_d is None and resp_d.get("op_id") == "m14-dead-op" and \
        resp_d.get("vm_outcome") == "unknown", (
            f"S8: the crashed-inline retry attaches to the unknown identity; "
            f"got {resp_d!r}"
        )


# ---------------------------------------------------------------------------
# S9/S10 — #158 supplemental repair scenarios
# ---------------------------------------------------------------------------


class FakePS:
    """Canned-leg run_ps fake (the test_repair.py pattern). A response item
    that is an Exception is raised instead of returned."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


def _guid_result():
    return pswindows.PSResult(stdout=VM_GUID, returncode=0)


def _host():
    return {"state": "Running", "vm_id": VM_GUID, "uptime_s": 1,
            "memory_mb": 1, "cpu_usage": 1}


def _guest(status="Running", listen="0.0.0.0", fw=True):
    return {
        "identity": {"hostname": "W"},
        "ip_addresses": {"ipv4": [{"interface": "E", "address": "10.0.0.5",
                                   "prefix": 24}], "ipv6": []},
        "ssh": {
            "service": {"present": True, "status": status, "start_type": "Automatic"},
            "agent_service": {"present": False},
            "config_present": True, "effective_ports": [22],
            "config_listen": [listen],
            "listeners": [{"address": listen, "port": 22}],
        },
        "winrm": {"service": {"present": True, "status": "Running",
                              "start_type": "Automatic"},
                  "listeners": [], "tcp_listeners": []},
        "firewall": {"ssh22_allowed": fw, "winrm5985_allowed": True},
    }


def _decode_inner(script: str) -> str:
    m = re.search(r"\$enc = '([A-Za-z0-9+/=]+)'", script)
    assert m, "the apply leg must carry the base64-encoded inner script"
    return base64.b64decode(m.group(1)).decode("utf-8")


def test_repair_intent_edit_and_directives(monkeypatch):
    """S9: a non-default IPv4 intent drives the EMITTED edit — the rewrite
    map carries exactly the stale line -> the intended value (never a guessed
    0.0.0.0) and unrelated ListenAddress directives fall through untouched;
    a mixed valid+stale config rewrites only the stale line; the planner
    classifies assigned IPv4/IPv6, unassigned families and unobserved
    families exactly (mixed valid+stale, IPv6 arms)."""
    cfg = Config(unrestricted=True)

    # Mixed config: one ASSIGNED (valid) binding + one stale binding.
    mixed = _guest(listen="192.168.50.20")
    mixed["ssh"]["config_listen"] = ["10.0.0.5", "192.168.50.20"]
    mixed["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    healthy = _guest(listen="10.0.0.5")
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(mixed),
        _ok({"backup": "C:/ProgramData/ssh/sshd_config.bak-20261120", "replaced": 1}),
        _ok(_host()), _ok(healthy),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    rewrite = [c for c in out["changes"] if c["action"] == "rewrite_stale_ssh_bindings"]
    assert len(rewrite) == 1, f"S9: expected the single rewrite change; got {out['changes']}"
    change = rewrite[0]
    assert change["before"]["stale_bindings"] == ["192.168.50.20"], (
        f"S9: only the stale binding is planned for rewrite; got {change['before']}"
    )
    assert change["apply_outcome"] == "applied" and change["verified"] is True, change
    # The emitted edit (leg index 3: resolve, host, guest, REWRITE):
    inner = _decode_inner(fake.scripts[3])
    entries = re.findall(r"'([0-9a-fA-F.:]+)' = '([0-9a-fA-F.:]+)'", inner)
    assert entries == [("192.168.50.20", "10.0.0.5")], (
        f"S9: the rewrite map must carry exactly the stale line -> the "
        f"intended value; got {entries}"
    )
    assert "0.0.0.0" not in inner, (
        "S9: the hardcoded 0.0.0.0 default must be retired from the edit"
    )
    assert "$out.Add($ln)" in inner, (
        "S9: unmatched (unrelated) directives must fall through untouched"
    )
    # The plan item records the intended replacement per line.
    plan_rewrite = [p for p in out["plan"]
                    if p["action"] == "rewrite_stale_ssh_bindings"][0]
    assert plan_rewrite.get("intended_bindings") == ["10.0.0.5"]

    # Planner arms: assigned IPv4/IPv6, stale, unobserved family, loopback,
    # hostname — the shared observation-aware classification.
    section = {"ipv4": [{"address": "10.0.0.5"}],
               "ipv6": [{"address": "fe80::1"}]}
    planner = diagnostics.classify_bind_address
    assert planner("10.0.0.5", section) == "not_stale"
    assert planner("10.0.0.9", section) == "stale"
    assert planner("fe80::1", section) == "unknown"
    # Issue #157 (final critic F3 + delta review R7-2): link-local fe80::/10
    # is NEVER in the production probe's enumeration, so its assignment can
    # never be confirmed - it classifies UNKNOWN (never rewritten, never
    # positively certified; the approved plan's observation rule).
    assert planner("fe80::5", section) == "unknown"
    assert planner("fe80::5", {"ipv4": [], "ipv6": None}) == "unknown"
    assert planner("10.0.0.9", {"ipv4": None, "ipv6": []}) == "unknown"
    assert planner("::1", section) == "not_stale"
    assert planner("host.example", section) == "not_stale"

    # An assigned-IPv6 (global, not link-local) stale binding plans the
    # rewrite for the IPv6 line (dry run). fe80* link-local is never stale
    # (final critic F3), so this scenario uses a global unassigned v6.
    stale6 = _guest(listen="2001:db8::5")
    stale6["ip_addresses"]["ipv6"] = [{"interface": "E", "address": "2001:db8::1",
                                       "prefix": 64}]
    fake6 = FakePS([_guid_result(), _ok(_host()), _ok(stale6)])
    monkeypatch.setattr(pswindows, "run_ps", fake6)
    out6 = repair.repair_guest_access(cfg, "test-vm", cred=CRED)
    rewrite6 = [p for p in out6["plan"]
                if p["action"] == "rewrite_stale_ssh_bindings"]
    assert rewrite6 and rewrite6[0]["before"]["stale_bindings"] == ["2001:db8::5"], (
        f"S9: an unassigned global IPv6 binding must plan its rewrite; got "
        f"{out6['plan']}"
    )


def test_repair_tripartite_observation_arms(monkeypatch):
    """S10: negative observation (the finding remains after a claimed apply —
    postcondition unsatisfied on a POSITIVE observation), failed apply +
    healthy readback (the failure and the observed state stay separate), the
    three-action scenario WITH intent (every action applied, verified, and
    the exact PowerShell leg consumption order), and the ambiguous/invalid
    intent diagnostics (decision_required, never a guessed rewrite)."""
    cfg = Config(unrestricted=True)

    # -- negative observation: applied, observed, still broken ---------------
    broken = _guest(status="Stopped")
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken),
        _ok({"service": "sshd", "status": "Running"}),
        _ok(_host()), _ok(_guest(status="Stopped")),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True, cred=CRED)
    change = out["changes"][0]
    assert change["action"] == "start_service"
    assert change["apply_outcome"] == "applied" and change["applied"] is True
    assert change["observation"] == "positive", (
        f"S10 negative observation: the verify pass WAS observed; got {change}"
    )
    assert change["postcondition"] == "unsatisfied" and change["verified"] is False
    assert "still present" in change["verify_detail"]

    # -- failed apply + healthy readback: separate channels ------------------
    stale = _guest(listen="192.168.50.20")
    stale["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    fake2 = FakePS([
        _guid_result(),
        _ok(_host()), _ok(stale),
        pswindows.PSResult(stdout="", returncode=1, stderr="rewrite apply failed"),
        _ok(_host()), _ok(_guest(listen="10.0.0.5")),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake2)
    out2 = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    change2 = [c for c in out2["changes"]
               if c["action"] == "rewrite_stale_ssh_bindings"][0]
    assert change2["apply_outcome"] == "failed" and change2["applied"] is False
    assert "rewrite apply failed" in change2["error"]
    assert change2["observation"] == "positive"
    assert change2["postcondition"] == "satisfied", (
        "S10: the observed-state channel may independently report satisfied"
    )
    assert change2["verified"] is False, (
        "S10: a failed apply is never verified off a healthy readback"
    )

    # -- three actions WITH intent: every action applied + the leg order -----
    broken3 = _guest(status="Stopped", listen="192.168.50.20", fw=False)
    broken3["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    healthy3 = _guest(status="Running", listen="10.0.0.5", fw=True)
    fake3 = FakePS([
        _guid_result(),                            # 0: resolve
        _ok(_host()), _ok(broken3),                # 1-2: diagnose
        _ok({"service": "sshd", "status": "Running"}),          # 3: start sshd
        _ok({"backup": "C:/b.bak-20261120", "replaced": 1}),    # 4: rewrite
        _ok({"port": "22", "enabled_rules": ["OpenSSH-Server-In-TCP"]}),  # 5: firewall
        _ok(_host()), _ok(healthy3),               # 6-7: verify
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake3)
    out3 = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    assert out3["applied"] is True and len(out3["changes"]) == 3
    by_action = {c["action"]: c for c in out3["changes"]}
    assert sorted(by_action) == [
        "enable_existing_firewall_rules", "rewrite_stale_ssh_bindings", "start_service",
    ]
    for action, change3 in by_action.items():
        assert change3["apply_outcome"] == "applied", f"S10 {action}: {change3}"
        assert change3["verified"] is True, f"S10 {action}: {change3}"
    detail = by_action["rewrite_stale_ssh_bindings"]["postcondition_detail"]
    assert detail.get("stale_bindings_remaining") == [] and \
        detail.get("config_listen") == ["10.0.0.5"], detail
    # The exact PowerShell leg consumption order (advisory 2).
    assert len(fake3.scripts) == 8, (
        f"S10: resolve + diagnose(2) + 3 applies + verify(2) legs; got "
        f"{len(fake3.scripts)}"
    )
    assert "Start-Service" in _decode_inner(fake3.scripts[3])
    assert "Copy-Item" in _decode_inner(fake3.scripts[4])
    assert "Set-NetFirewallRule" in _decode_inner(fake3.scripts[5])

    # -- ambiguous / invalid intent diagnostics ------------------------------
    stale4 = _guest(listen="192.168.50.20")
    stale4["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    fake4 = FakePS([_guid_result(), _ok(_host()), _ok(stale4)])
    monkeypatch.setattr(pswindows, "run_ps", fake4)
    out_amb = repair.repair_guest_access(
        cfg, "test-vm", cred=CRED, intended_bindings=["10.0.0.5", "10.0.0.6"],
    )
    item_amb = [p for p in out_amb["plan"]
                if p["action"] == "rewrite_stale_ssh_bindings"][0]
    assert item_amb.get("decision_required") is True
    assert "ambiguous" in item_amb["change"].lower(), item_amb["change"]
    assert "apply_script" not in item_amb

    fake5 = FakePS([
        _guid_result(), _ok(_host()), _ok(stale4),
        _ok(_host()), _ok(_guest(listen="10.0.0.5")),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake5)
    out_inv = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["not-an-ip"],
    )
    change_inv = [c for c in out_inv["changes"]
                  if c["action"] == "rewrite_stale_ssh_bindings"][0]
    assert change_inv["apply_outcome"] == "not_attempted" and \
        change_inv["applied"] is False and \
        change_inv.get("decision_required") is True and \
        change_inv["verified"] is False, change_inv
    assert sum("Copy-Item" in s for s in fake5.scripts) == 0, (
        "S10: an invalid intent must run no rewrite mutation script"
    )



# ---------------------------------------------------------------------------
# S11 (final critic F1): the KEYED-INLINE route driven through the REAL
# mcp.call_tool dispatch - no hand-bound context. At the provider submission
# the row must carry possibly_sent with the dispatch-bound op context; a
# crash after the effect must lapse to the unknown reconciliation identity.
# ---------------------------------------------------------------------------


def _boot_server(tmp_path):
    import importlib
    import json as _json

    import hyperv_mcp.server as server_module

    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True,
           "state_db_path": str(tmp_path / "s11-state.db")}
    cfg_path = tmp_path / "s11-boot.json"
    cfg_path.write_text(_json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_path)})
    return mod


def test_inline_route_marks_possibly_sent_at_submission(tmp_path):
    """S11a: a keyed-inline checkpoint_restore observed AT the
    Restore-VMSnapshot submission carries send_state='possibly_sent' and the
    dispatch-bound op context - proving the route wiring itself, never a
    hand-bound context (final critic F1/PA)."""
    import asyncio
    import json as _json
    import threading as _th

    import hyperv_mcp.operations as _ops
    from hyperv_mcp import pswindows

    mod = _boot_server(tmp_path)
    mcp = mod.get_mcp()
    reached = {"payload": None}
    release = _th.Event()
    saved = pswindows.run_ps

    def dispatcher(script, **kwargs):
        # Leg shapes mirror the e03 _FakePS: resolve -> bare GUID,
        # restore -> empty stdout, state wait -> final_state JSON.
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=VM_GUID, returncode=0)
        if "Restore-VMSnapshot" in script:
            cfg = mod.CFG
            store = _ops.store_for(cfg)
            row = store.op_get(_ops._current_op_id.get(""))
            reached["payload"] = {
                "ctx_op_id": _ops._current_op_id.get(""),
                "ctx_gen": _ops._current_op_generation.get(0),
                "row_send": row.send_state if row else None,
                "row_status": row.status if row else None,
            }
            release.set()
            return pswindows.PSResult(stdout="", returncode=0)
        if "final_state" in script:
            return pswindows.PSResult(
                stdout=_json.dumps({"final_state": "Off"}), returncode=0)
        return pswindows.PSResult(stdout="{}", returncode=0)

    pswindows.run_ps = dispatcher
    try:
        handle = asyncio.run(mcp.call_tool(
            "hyperv_checkpoint_restore",
            {"vm_name": "test-vm", "checkpoint_name": "s11a", "confirm": True,
             "idempotency_key": "s11-inline-a"},
        ))
        release.wait(timeout=30.0)
        payload = reached["payload"]
        assert payload is not None and payload["row_send"] == "possibly_sent", (
            f"S11a: the keyed-inline restore must carry possibly_sent AT the "
            f"provider submission (route wiring); got {payload!r}"
        )
        handle_id = handle.get("op_id") if isinstance(handle, dict) else getattr(
            handle, "op_id", None)
        if handle_id:
            assert payload["ctx_op_id"] == handle_id, (
                f"S11a: the dispatch-bound op context must name the attempt; "
                f"got {payload!r}"
            )
        assert payload["row_status"] == "working", (
            f"S11a: the attempt is live mid-body; got {payload!r}"
        )
    finally:
        release.set()
        pswindows.run_ps = saved
        _ops.drain_for_tests(timeout_s=5.0)


def test_inline_route_crash_after_effect_lapses_to_unknown(tmp_path):
    """S11b: an inline body that crashes AFTER the effect committed (the
    restore leg succeeded, then the body raises) keeps the mark; once the
    heartbeat lapsed the row reads failed/unknown at read time (final critic
    F1/PB) - never a fresh dispatch."""
    import asyncio

    import hyperv_mcp.operations as _ops
    from hyperv_mcp import pswindows

    mod = _boot_server(tmp_path)
    mcp = mod.get_mcp()
    saved = pswindows.run_ps
    calls = {"restore": 0}

    def crash_after_restore(script, **kwargs):
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=VM_GUID, returncode=0)
        if "Restore-VMSnapshot" in script:
            calls["restore"] += 1
            return pswindows.PSResult(stdout="", returncode=0)
        # The state-wait leg runs AFTER the restore committed: raising here
        # is the crash-after-effect schedule exactly.
        raise RuntimeError("post-effect crash (simulated)")

    pswindows.run_ps = crash_after_restore
    try:
        try:
            asyncio.run(mcp.call_tool(
                "hyperv_checkpoint_restore",
                {"vm_name": "test-vm", "checkpoint_name": "s11b", "confirm": True,
                 "idempotency_key": "s11-inline-b"},
                ))
        except Exception:
            pass  # the post-effect crash surfaces as an audited rejection
        cfg = mod.CFG
        store = _ops.store_for(cfg)
        rows = [r for r in store.op_rows_by_agent("", include_terminal=True)
                if r.tool == "hyperv_checkpoint_restore"
                and r.send_state == "possibly_sent"]
        assert rows, (
            "S11b: the crash-after-effect attempt must persist with the mark"
        )
        row = rows[-1]
        assert calls["restore"] == 1, (
            f"S11b: exactly one provider submission; got {calls['restore']}"
        )
        # R7-3 hardening: the request-time provenance is terminal BEFORE any
        # heartbeat aging - whichever route arm completes the row (the fail
        # arm writes error_class unknown; the ok:false arm records the
        # envelope's own class), the CONTRACT is identical: terminal failed,
        # the possibly_sent mark RETAINED, and the stored envelope carries
        # the vm_outcome unknown disclosure. The aging step below proves the
        # terminal identity is STABLE across a lapsed read (idempotent).
        stored = json.loads(row.result_json) if row.result_json else {}
        terminal_unknown = (
            row.status == "failed"
            and (row.error_class == statestore.OP_UNKNOWN
                 or stored.get("vm_outcome") == "unknown")
        )
        assert terminal_unknown, (
            f"S11b: the post-send crash must terminal-fail at request time "
            f"with the unknown identity (error_class unknown, or the "
            f"envelope disclosing vm_outcome unknown); got status="
            f"{row.status!r} error_class={row.error_class!r} "
            f"stored={stored!r}"
        )
        # Age the heartbeat deterministically (the beat timer stopped at
        # dispatch exit) so the read-time classification runs its lapsed arm.
        store._begin()
        try:
            store._connect().execute(
                "UPDATE ops SET heartbeat_at = ? WHERE op_id = ?",
                (1.0, row.op_id),
            )
            store._commit()
        except BaseException:
            store._rollback()
            raise
        status = _ops.op_status(cfg, row.op_id, "")
        # Issue #157 (final critic F1/PB): the body-originated envelope
        # retains the mark; the status view carries the vm_outcome unknown
        # disclosure (the restore committed before the crash).
        blob = json.dumps(status).lower()
        assert status.get("status") == "failed", (
            f"S11b: the crashed inline row reads failed; got {status!r}"
        )
        assert "unknown" in blob, (
            f"S11b: the retained-mark row must disclose the unknown VM-side "
            f"outcome in its status view; got {blob[:240]}"
        )
        # A same-key retry ATTACHES to the unknown identity (never fresh).
        resp, ctx = _ops.guard_consult(
            cfg, "hyperv_checkpoint_restore",
            {"vm_name": "test-vm", "checkpoint_name": "s11b", "confirm": True,
             "idempotency_key": "s11-inline-b"},
            lambda **kw: (_ for _ in ()).throw(AssertionError("re-dispatch")),
            lambda: __import__("threading").BoundedSemaphore(2),
        )
        # The retry REPLAYS the stored crash envelope (marked replayed, the
        # unknown disclosure carried) and NEVER re-dispatches.
        assert ctx is None and isinstance(resp, dict) and resp.get(
            "replayed") is True and resp.get("vm_outcome") == "unknown", (
            f"S11b: the same-key retry must replay the stored unknown envelope "
            f"without re-dispatch; got resp={resp!r} ctx={ctx!r}"
        )
    finally:
        pswindows.run_ps = saved
        _ops.drain_for_tests(timeout_s=5.0)


# ---------------------------------------------------------------------------
# S12 (delta impl-review R7-1): a BaseException inside the route-level
# pre-send commit must NOT wedge the VM's send gate - the finally-owned
# release runs, the admission ticket stays balanced, the bound op context is
# unbound, and the lost attempt's identity stays a protected
# working/possibly_sent unknown until trusted reconciliation.
# ---------------------------------------------------------------------------


class _CommitBoom(BaseException):
    """A non-Exception BaseException (neither KeyboardInterrupt nor
    SystemExit, so the runner survives) simulating a host interruption
    landing inside the pre-send commit window."""


def test_inline_route_baseexception_at_commit_releases_gate(tmp_path):
    """S12: dispatch a keyed-inline restore whose commit_send_intent raises
    a BaseException; the gate must be FREE afterward (a same-VM acquire
    succeeds), the admission ticket balanced, the context unbound, and the
    row must persist working/possibly_sent (the durable unknown identity)."""
    import asyncio

    import hyperv_mcp.operations as _ops
    from hyperv_mcp import pswindows, statestore

    mod = _boot_server(tmp_path)
    mcp = mod.get_mcp()
    saved = pswindows.run_ps
    saved_commit = _ops.commit_send_intent
    fired = {"commit": 0}

    def boom_commit(cfg):
        fired["commit"] += 1
        raise _CommitBoom("simulated host interruption at commit")

    def host_ok(script, **kwargs):
        return pswindows.PSResult(stdout="", returncode=0)

    pswindows.run_ps = host_ok
    _ops.commit_send_intent = boom_commit
    try:
        raised = None
        try:
            asyncio.run(mcp.call_tool(
                "hyperv_checkpoint_restore",
                {"vm_name": "test-vm", "checkpoint_name": "s12", "confirm": True,
                 "idempotency_key": "s12-boom"},
            ))
        except BaseException as exc:
            raised = exc
        assert fired["commit"] == 1, (
            f"S12: the route-level commit must fire exactly once; got "
            f"{fired['commit']}"
        )
        assert isinstance(raised, _CommitBoom), (
            f"S12: the BaseException must propagate out of the dispatch "
            f"uncaught; got {raised!r}"
        )
        # The gate is free: a same-VM acquire succeeds immediately.
        assert operations._send_gate_acquire({"vm_name": "test-vm"}) is True, (
            "S12: the send gate must be released after a BaseException "
            "inside the commit window (no wedged gate)"
        )
        operations._send_gate_release({"vm_name": "test-vm"})
        # The admission ticket is balanced (no leaked in-flight admission).
        admission = __import__("hyperv_mcp.admission", fromlist=["x"])
        inflight = admission.snapshot()["in_flight_general"]
        assert inflight == 0, (
            f"S12: the admission ticket must be released on the "
            f"BaseException path; in_flight={inflight!r}"
        )
        # The bound op context is unbound.
        assert _ops._current_op_id.get("") == "", (
            "S12: the dispatch-bound op context must be unbound after the "
            "BaseException path"
        )
        # R8-1 reconciliation: the boom fired at the commit's entry, so the
        # possibly_sent mark never landed - nothing was dispatched, the
        # definitive pre-send refusal. The row is terminal failed/interrupted
        # (a same-key retry replays the envelope; no working ghost).
        store = _ops.store_for(mod.CFG)
        rows = [r for r in store.op_rows_by_agent("", include_terminal=True)
                if r.tool == "hyperv_checkpoint_restore"
                and r.idem_key == "s12-boom"]
        assert rows and rows[-1].status == "failed" and rows[-1].send_state == "", (
            f"S12: the pre-mark interruption must terminal-fail the row "
            f"(definitive pre-send refusal; no working ghost); "
            f"got {rows[-1].as_dict() if rows else None}"
        )
        assert rows[-1].error_class == statestore.OP_INTERRUPTED, (
            f"S12: the reconciled row must carry the interrupted class; "
            f"got {rows[-1].error_class!r}"
        )
        # The same-key retry replays the interrupted envelope (no ghost
        # attach, no re-dispatch).
        resp, ctx = _ops.guard_consult(
            mod.CFG, "hyperv_checkpoint_restore",
            {"vm_name": "test-vm", "checkpoint_name": "s12", "confirm": True,
             "idempotency_key": "s12-boom"},
            lambda **kw: (_ for _ in ()).throw(AssertionError("re-dispatch")),
            lambda: threading.BoundedSemaphore(2),
        )
        assert ctx is None and isinstance(resp, dict) and resp.get(
            "replayed") is True, (
            f"S12: the same-key retry must replay the interrupted envelope "
            f"without re-dispatch; got resp={resp!r} ctx={ctx!r}"
        )
    finally:
        pswindows.run_ps = saved
        _ops.commit_send_intent = saved_commit
        _ops.drain_for_tests(timeout_s=5.0)


# ---------------------------------------------------------------------------
# S13 (delta review R8-1, post-mark arm): a BaseException AFTER the send
# commit landed keeps the protected unknown identity - the row stays
# working/possibly_sent, the aged read reconciles it to failed/unknown, and
# the same-key retry attaches to that identity without re-dispatch.
# ---------------------------------------------------------------------------


def test_inline_route_post_mark_interruption_keeps_unknown_identity(tmp_path):
    """S13: dispatch a keyed-inline restore whose commit completes (the mark
    lands) and THEN raises a BaseException; the row keeps
    working/possibly_sent, a heartbeat-lapsed read reconciles it to
    failed/unknown, and the same-key retry attaches to the unknown identity."""
    import asyncio

    import hyperv_mcp.operations as _ops
    from hyperv_mcp import pswindows, statestore

    mod = _boot_server(tmp_path)
    mcp = mod.get_mcp()
    saved = pswindows.run_ps
    saved_commit = _ops.commit_send_intent

    def host_ok(script, **kwargs):
        return pswindows.PSResult(stdout="", returncode=0)

    real_commit = _ops.commit_send_intent

    def commit_then_boom(cfg):
        real_commit(cfg)
        raise _CommitBoom("simulated host interruption after the commit")

    pswindows.run_ps = host_ok
    _ops.commit_send_intent = commit_then_boom
    try:
        raised = None
        try:
            asyncio.run(mcp.call_tool(
                "hyperv_checkpoint_restore",
                {"vm_name": "test-vm", "checkpoint_name": "s13", "confirm": True,
                 "idempotency_key": "s13-boom"},
            ))
        except BaseException as exc:
            raised = exc
        assert isinstance(raised, _CommitBoom), (
            f"S13: the BaseException must propagate; got {raised!r}"
        )
        store = _ops.store_for(mod.CFG)
        rows = [r for r in store.op_rows_by_agent("", include_terminal=True)
                if r.tool == "hyperv_checkpoint_restore"
                and r.idem_key == "s13-boom"]
        assert rows and rows[-1].status == "working" and rows[
            -1].send_state == "possibly_sent", (
            f"S13: the post-mark interruption must keep the protected "
            f"unknown identity (working/possibly_sent); "
            f"got {rows[-1].as_dict() if rows else None}"
        )
        # The aged read reconciles the identity at read time.
        store._begin()
        try:
            store._connect().execute(
                "UPDATE ops SET heartbeat_at = ? WHERE op_id = ?",
                (1.0, rows[-1].op_id),
            )
            store._commit()
        except BaseException:
            store._rollback()
            raise
        status = _ops.op_status(mod.CFG, rows[-1].op_id, "")
        assert status.get("status") == "failed" and (
            status.get("error_class") == statestore.OP_UNKNOWN
        ), f"S13: the lapsed read must reconcile to failed/unknown; got {status!r}"
        # The same-key retry attaches to the unknown identity (never fresh).
        resp, ctx = _ops.guard_consult(
            mod.CFG, "hyperv_checkpoint_restore",
            {"vm_name": "test-vm", "checkpoint_name": "s13", "confirm": True,
             "idempotency_key": "s13-boom"},
            lambda **kw: (_ for _ in ()).throw(AssertionError("re-dispatch")),
            lambda: threading.BoundedSemaphore(2),
        )
        assert ctx is None and isinstance(resp, dict) and resp.get(
            "op_id") == rows[-1].op_id, (
            f"S13: the same-key retry must attach to the original unknown "
            f"identity; got resp={resp!r} ctx={ctx!r}"
        )
    finally:
        pswindows.run_ps = saved
        _ops.commit_send_intent = saved_commit
        _ops.drain_for_tests(timeout_s=5.0)


# ---------------------------------------------------------------------------
# S14 (delta review R9-1 + final-critic freshness): the rewrite-verification
# seam preserves the classifier's three states - an unknown (fe80*) binding
# remaining in the readback prevents positive certification entirely.
# ---------------------------------------------------------------------------


def test_rewrite_verification_unknown_binding_blocks_certification(monkeypatch):
    """S14: a fully observed report, an applied rewrite of a stale IPv4
    binding, and a remaining fe80::1 listener in the readback must yield
    postcondition unknown + verified False (the mixed-binding falsifier),
    while the same flow without the fe80 listener certifies satisfied."""
    cfg = Config(unrestricted=True)

    # Mixed readback: the diagnostic found the stale IPv4 binding (the
    # plan proposes rewriting it), the apply cleared it, but the readback
    # carries a remaining fe80::1 link-local listener - uncertifiable.
    stale_diag = _guest(listen="192.168.50.20")
    mixed = _guest(listen="10.0.0.5")
    mixed["ip_addresses"]["ipv6"] = [{"interface": "E", "address": "fe80::1",
                                      "prefix": 64}]
    mixed["ssh"]["listeners"] = [{"address": "10.0.0.5", "port": 22},
                                 {"address": "fe80::1", "port": 22}]

    def fake_apply_verify(diag_guest, readback_guest):
        fake = FakePS([
            _guid_result(),
            _ok(_host()), _ok(diag_guest),
            pswindows.PSResult(stdout="", returncode=0),
            _ok(_host()), _ok(readback_guest),
        ])
        monkeypatch.setattr(pswindows, "run_ps", fake)
        return repair.repair_guest_access(
            cfg, "test-vm", apply=True, confirm=True, cred=CRED,
            intended_bindings=["10.0.0.5"],
        )

    out = fake_apply_verify(stale_diag, mixed)
    change = [c for c in out["changes"]
              if c["action"] == "rewrite_stale_ssh_bindings"][0]
    assert change["apply_outcome"] == "applied" and change["applied"] is True
    assert change["observation"] == "positive"
    assert change["postcondition"] == "unknown", (
        f"S14: an unknown (fe80*) binding in the readback must prevent "
        f"positive certification; got {change}"
    )
    assert change["verified"] is False
    assert change["postcondition_detail"]["stale_bindings_remaining"] == []
    assert "fe80::1" in change["postcondition_detail"]["unverified_bindings"]
    # The planner proposed the rewrite for the stale IPv4 binding only
    # (final-critic F3: no rewrite is ever proposed for fe80).
    plan_rewrites = [p for p in out["plan"]
                     if p["action"] == "rewrite_stale_ssh_bindings"]
    assert plan_rewrites and plan_rewrites[0]["before"][
        "stale_bindings"] == ["192.168.50.20"], (
        f"S14: the planner must propose the rewrite for the stale IPv4 "
        f"binding only; got {plan_rewrites}"
    )

    # Control: the same flow with a clean readback certifies.
    clean = _guest(listen="10.0.0.5")
    out2 = fake_apply_verify(stale_diag, clean)
    change2 = [c for c in out2["changes"]
               if c["action"] == "rewrite_stale_ssh_bindings"][0]
    assert change2["postcondition"] == "satisfied" and change2[
        "verified"] is True, (
        f"S14 control: without the fe80 listener the rewrite certifies; "
        f"got {change2}"
    )
