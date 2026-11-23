"""Issue #157 + #158 acceptance checks (trace
157-158-durable-identity-repair-outcomes): durable identity/repair-outcome
contracts, one executable check per AC.

AC -> check map (01-issue-summary.md / 02-reproduction.md):

  #157 (operations / statestore / lifecycle):
    C1  test_c1_permit_exact_once          — runner-slot permit is released and
        the op row never strands as `working` when the detach path fails at
        op-insert OR thread-start; the failure surfaces as the guard's
        classified refusal envelope, never a raw escape.
    C2  test_c2_inline_owner_identity      — a keyed INLINE call persists an
        execution owner + `generation` on its row (base: runner == "" and no
        generation field).
    C3  test_c3_executor_generation_fencing — Store.op_transition is
        generation-guarded: a stale-generation terminal write is refused, a
        current-generation write moves (base: no generation predicate).
    C4  test_c4_presend_unknown_outcome    — a durable send-state exists; a
        possibly-sent row with a lapsed heartbeat persists an UNKNOWN outcome
        and a matching retry ATTACHES (same op_id, no re-dispatch) (base: no
        send_state field at all).
    C5  test_c5_durable_vm_epoch           — a durable per-VM epoch record
        exists, checkpoint_restore dirties it before the restore leg, and the
        session-pool borrow surface names an epoch consult (base: no epoch
        surface anywhere).
    C6  test_c6_failure_cancel_arms_mark_uncertain — checkpoint_restore's
        failure arm AND cancel arm invalidate sessions or leave the durable
        epoch dirty (base P6: invalidate skipped, no epoch).
    C7  test_c7_replay_window_retention    — ops_prune keeps completed rows'
        identity through the replay window so a same-key retry returns the
        ORIGINAL handle with an explicit result-expired disclosure (base: the
        row is deleted outright).
    C8  test_c8_protected_reconciliation   — (a) unknown-outcome (interrupted)
        rows survive retention pruning; (b) a legacy row with an EMPTY
        params_hmac is treated as protected reconciliation on a fingerprint
        mismatch, not a silent reattach (base: pruned silently; empty hmac
        skips the conflict check at operations.py:305).
    C9  test_c9_migration_seeds_v6         — SCHEMA_VERSION becomes 6; a v5
        store upgrades forward with live+terminal rows' identity intact,
        repeated reopen and a subsequent write behave, and the #151 relay-kind
        read-back stays 'http' (PRESERVING arm, runs at base too).
    C10 test_c10_saturation_accounting     — after a failed detach start, a
        follow-up dispatch is not starved by a leaked permit, and the
        permit accounting balances (base: busy forever).

  #158 (repair.py):
    C11 test_c11_tripartite_change_shape   — every change carries apply-outcome,
        observation-quality and postcondition as SEPARATE keys.
    C12 test_c12_failed_apply_preserved    — a failed apply + healthy readback
        keeps verified=False with the failure AND verification facts separate.
    C13 test_c13_unknown_on_incomplete_observation — verify-timeout or a
        raising observation leg yields postcondition=unknown, verified=False,
        and never raises the changes away.
    C14 test_c14_service_vs_listener_facts — a start_service postcondition
        records service status and listener binding as separate named facts.
    C15 test_c15_operator_intent           — repair_guest_access takes an
        explicit intent argument; absent intent yields a decision-requiring
        item, never a guessed 0.0.0.0 rewrite.
    C16 test_c16_wire_compat_verified      — `verified` truth table: True only
        for applied + satisfied postcondition + positive observation.
    C17 test_c17_guest_floor_disclosure    — README + tool docstring disclose
        the RUNNING-guest PowerShell Direct floor vs host-console/firmware
        (structural pin).
    C18 test_c18_stale_address_loopback    — _is_stale_address('::1') is False,
        '::1' is classed non-stale (loopback), and no rewrite is proposed for
        a config_listen=['::1'] guest.

Contract names these checks DEFINE for the head (the head must satisfy them):
  - OpRow gains a `generation` int field; Store.op_transition gains a
    `generation` keyword predicate (C3); keyed inline rows persist a non-empty
    runner owner and generation >= 1 (C2).
  - OpRow gains a `send_state` field whose lost-submission sentinel is
    'possibly_sent' (C4).
  - The durable epoch surface is any SQLite table named *epoch* whose row for
    the VM GUID carries one of the dirty/uncertain markers (dirty, uncertain,
    invalidat*, revalidat*, pending), or a public Store method naming epoch
    (C5/C6 probe helper _epoch_dirty below).
  - Change dicts gain `apply_outcome` in {applied, failed, not_attempted},
    `observation` in {positive, negative, partial, unavailable}, and
    `postcondition` in {satisfied, unsatisfied, unknown}; start_service
    changes additionally carry a dict `postcondition_detail` with separate
    service/listener facts (C11/C14).
  - repair_guest_access gains a `bind_address` (or `intended_bindings`)
    parameter (C15).
  - The docs disclosure literals (C17): both the README repair section and the
    hyperv_repair_guest_access docstring must mention PowerShell Direct, a
    running guest, and the host-console/firmware distinction.

What is faked: PowerShell only (pswindows.run_ps canned legs, the
test_repair.py FakePS pattern) and, for the lifecycle arms, vmident.resolve /
vmlocks.vm_lock / lifecycle._run / pswindows.check_result. No sleeps beyond
bounded thread joins; every store is closed in teardown (Windows file-lock
teardown hazard).
"""

import contextlib
import dataclasses
import inspect
import json
import re
import sqlite3
import threading
import types
from pathlib import Path

import pytest

from hyperv_mcp import (
    diagnostics,
    lifecycle,
    operations,
    psdsessions,
    pswindows,
    repair,
    statestore,
    vmlocks,
)
from hyperv_mcp import server as server_module
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.statestore import StateStoreError

CRED = CredentialSet("Administrator", "placeholder-pass")
VM_GUID = "e953c649-1234-5678-9abc-def012345678"
OP_TOOL = "hyperv_checkpoint_create"


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


class FakePS:
    """Canned-leg run_ps fake (test_repair.py pattern). A response item that
    is an Exception is raised instead of returned, which is how the
    verify-timeout arm simulates a lost observation leg."""

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
    return {"state": "Running", "vm_id": VM_GUID, "uptime_s": 1, "memory_mb": 1, "cpu_usage": 1}


def _guest(status="Running", listen="0.0.0.0", fw=True):
    return {
        "identity": {"hostname": "W"},
        "ip_addresses": {"ipv4": [{"interface": "E", "address": "10.0.0.5", "prefix": 24}], "ipv6": []},
        "ssh": {
            "service": {"present": True, "status": status, "start_type": "Automatic"},
            "agent_service": {"present": False},
            "config_present": True, "effective_ports": [22],
            "config_listen": [listen],
            "listeners": [{"address": listen, "port": 22}],
        },
        "winrm": {"service": {"present": True, "status": "Running", "start_type": "Automatic"},
                  "listeners": [], "tcp_listeners": []},
        "firewall": {"ssh22_allowed": fw, "winrm5985_allowed": True},
    }


class CountingSemaphore(threading.BoundedSemaphore):
    """BoundedSemaphore that counts successful acquire/release calls — the
    independent permit accounting C1/C10 assert against."""

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


class _Recorder:
    """tool_fn stand-in that records dispatches instead of doing work."""

    def __init__(self):
        self.calls = 0

    def __call__(self, **kwargs):
        self.calls += 1
        return {"ok": True, "status": "created"}


@pytest.fixture()
def ops_store(tmp_path, monkeypatch):
    """A real temp Store injected through the operations.store_for seam
    (module-attribute patch — the same seam the frozen e03 checks use).
    ALWAYS closed on teardown (Windows file-lock teardown hazard)."""
    store = statestore.open(str(tmp_path / "t157-store.db"))
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)
    yield store
    store.close()


def _oprow_field_names() -> set[str]:
    return {f.name for f in dataclasses.fields(statestore.OpRow)}


def _epoch_dirty(store: statestore.Store, vm_guid: str) -> bool:
    """Probe for a DURABLE dirty per-VM epoch record, whatever surface the
    head ships: any table named *epoch* holding a row that references the VM
    GUID and carries a dirty/uncertain marker. A cleared epoch must not
    match (the markers are the contract, documented in the module
    docstring)."""
    con = sqlite3.connect(store.path)
    try:
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%epoch%'"
        )]
        for table in tables:
            try:
                rows = con.execute(f'SELECT * FROM "{table}"').fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                blob = " ".join(str(v).lower() for v in row)
                if vm_guid.lower() not in blob:
                    continue
                if any(m in blob for m in (
                    "dirty", "uncertain", "invalidat", "revalidat", "pending",
                )):
                    return True
    finally:
        con.close()
    return False


def _has_durable_epoch_surface(store: statestore.Store) -> bool:
    if any("epoch" in n.lower() and not n.startswith("_") for n in dir(store)):
        return True
    con = sqlite3.connect(store.path)
    try:
        row = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name LIKE '%epoch%'"
        ).fetchone()
    finally:
        con.close()
    return row is not None


# ---------------------------------------------------------------------------
# #157 — C1: permit exact-once on insert/start failure
# ---------------------------------------------------------------------------


def test_c1_permit_exact_once(tmp_path, monkeypatch, ops_store):
    """C1: guard_consult detach calls whose op_insert raises StateStoreError
    (arm A) or whose runner thread fails to start (arm B) must release the
    runner-slot permit, leave no stranded `working` row, and surface the
    failure as the guard's classified refusal envelope. RED at base: the
    permit leaks (acquired=1, released=0) and the exception escapes raw."""
    cfg = Config(unrestricted=True)
    store = ops_store
    sem = CountingSemaphore(1)
    tool = _Recorder()

    # -- arm A: op_insert raises inside the guard's transaction -------------
    def _boom(row):
        raise StateStoreError("injected insert failure")

    store.op_insert = _boom  # instance attribute shadows the class method
    escaped = None
    resp_a = None
    try:
        resp_a, _ctx = operations.guard_consult(
            cfg, OP_TOOL,
            {"vm_name": "test-vm", "checkpoint_name": "c1a",
             "detach": True, "idempotency_key": "c1-arm-a"},
            tool, lambda: sem,
        )
    except Exception as exc:  # noqa: BLE001 — the raw escape IS the defect
        escaped = exc
    finally:
        del store.op_insert  # restore the class method for arm B

    assert sem.released == sem.acquired, (
        f"C1 arm A: the runner-slot permit must be released when the detach "
        f"path fails at op-insert; acquired={sem.acquired} released={sem.released} "
        f"(escaped={escaped!r})"
    )
    assert escaped is None, (
        f"C1 arm A: the insert failure must be classified into the guard's "
        f"refusal envelope, not escape raw: {escaped!r}"
    )
    assert isinstance(resp_a, dict) and resp_a.get("ok") is False and resp_a.get("error_class"), (
        f"C1 arm A: expected a classified refusal envelope; got {resp_a!r}"
    )
    stranded = [
        row for row in store.op_rows_by_agent("", include_terminal=True)
        if row.idem_key == "c1-arm-a" and row.status == statestore.OP_WORKING
    ]
    assert not stranded, (
        f"C1 arm A: a failed detach must not strand a working row: "
        f"{[r.as_dict() for r in stranded]}"
    )

    # -- arm B: the runner thread fails to start -----------------------------
    shim = types.ModuleType("threading_shim")
    shim.__dict__.update(threading.__dict__)

    class _StartFailsThread:
        daemon = True
        name = ""

        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("injected thread start failure")

        def join(self, timeout=None):
            return None

        def is_alive(self):
            return False

    shim.Thread = _StartFailsThread
    monkeypatch.setattr(operations, "threading", shim)
    sem2 = CountingSemaphore(1)
    escaped_b = None
    resp_b = None
    try:
        resp_b, _ctx = operations.guard_consult(
            cfg, OP_TOOL,
            {"vm_name": "test-vm", "checkpoint_name": "c1b",
             "detach": True, "idempotency_key": "c1-arm-b"},
            tool, lambda: sem2,
        )
    except Exception as exc:  # noqa: BLE001
        escaped_b = exc
    monkeypatch.undo()

    assert sem2.released == sem2.acquired, (
        f"C1 arm B: the runner-slot permit must be released when the runner "
        f"thread fails to start; acquired={sem2.acquired} released={sem2.released} "
        f"(escaped={escaped_b!r})"
    )
    assert escaped_b is None, (
        f"C1 arm B: the start failure must be classified into the guard's "
        f"refusal envelope, not escape raw: {escaped_b!r}"
    )
    assert isinstance(resp_b, dict) and resp_b.get("ok") is False and resp_b.get("error_class"), (
        f"C1 arm B: expected a classified refusal envelope; got {resp_b!r}"
    )
    stranded_b = [
        row for row in store.op_rows_by_agent("", include_terminal=True)
        if row.idem_key == "c1-arm-b" and row.status == statestore.OP_WORKING
    ]
    assert not stranded_b, (
        f"C1 arm B: a failed start must leave the row durably terminal (or "
        f"absent), never working: {[r.as_dict() for r in stranded_b]}"
    )
    assert tool.calls == 0, "C1: the body must never run on a failed start"


# ---------------------------------------------------------------------------
# #157 — C2: inline owner identity
# ---------------------------------------------------------------------------


def test_c2_inline_owner_identity(ops_store):
    """C2: a keyed INLINE call (idempotency_key, no detach) must persist an
    execution owner and generation on its row. RED at base: the inline row is
    created with runner='' and OpRow has no generation field at all."""
    cfg = Config(unrestricted=True)
    store = ops_store
    sem = CountingSemaphore(1)

    resp, ctx = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "test-vm", "checkpoint_name": "c2", "idempotency_key": "c2-inline"},
        _Recorder(), lambda: sem,
    )
    assert ctx is not None, (
        f"C2: a keyed inline call must record its op row and return the "
        f"completion context; got resp={resp!r}"
    )
    # The guard's caller (server.py) runs the body then completes the row.
    operations.complete_inline(ctx, {"ok": True, "status": "created"})
    row = store.op_get(ctx["op_id"])
    assert row is not None, "C2: the inline op row must persist"
    assert row.idem_key == "c2-inline" and row.status == statestore.OP_COMPLETED, (
        f"C2: identity/completion broken: {row.as_dict()}"
    )
    assert row.runner, (
        f"C2: a keyed inline row must persist a non-empty execution owner "
        f"(runner); got {row.runner!r}"
    )
    generation = getattr(row, "generation", 0)
    assert isinstance(generation, int) and generation >= 1, (
        f"C2: a keyed inline row must persist an execution generation >= 1; "
        f"got {generation!r}"
    )


# ---------------------------------------------------------------------------
# #157 — C3: executor generation fencing
# ---------------------------------------------------------------------------


def test_c3_executor_generation_fencing(ops_store):
    """C3: Store.op_transition must be generation-guarded — a stale-generation
    terminal write is REFUSED (row unchanged) and a current-generation write
    moves. RED at base: op_transition has no generation predicate."""
    store = ops_store
    params = inspect.signature(store.op_transition).parameters
    assert "generation" in params, (
        "C3: Store.op_transition must carry a generation predicate so a "
        "stale-generation executor cannot terminal-write over a new "
        f"generation; parameters found: {sorted(params)}"
    )
    kwargs = {}
    if "generation" in _oprow_field_names():
        kwargs["generation"] = 2
    row = statestore.OpRow(
        op_id="c3-op", tool=OP_TOOL, agent="", vm_name="test-vm",
        status=statestore.OP_WORKING, created_at=store.now(), updated_at=store.now(),
        runner="c3-owner", heartbeat_at=store.now(), idem_key="c3",
        **kwargs,
    )
    store.op_insert(row)
    # A stale generation (one behind the row's current 2) must be refused.
    moved = store.op_transition(
        "c3-op", (statestore.OP_WORKING,), statestore.OP_COMPLETED,
        generation=1, updated_at=store.now(),
    )
    assert moved is False, "C3: a stale-generation terminal write must be refused"
    fresh = store.op_get("c3-op")
    assert fresh is not None and fresh.status == statestore.OP_WORKING, (
        f"C3: the row must be unchanged after a refused stale write: "
        f"{fresh.as_dict() if fresh else None}"
    )
    # The current generation moves.
    moved = store.op_transition(
        "c3-op", (statestore.OP_WORKING,), statestore.OP_COMPLETED,
        generation=2, updated_at=store.now(),
    )
    assert moved is True, "C3: a current-generation write must move the row"


# ---------------------------------------------------------------------------
# #157 — C4: pre-send commit + unknown outcome
# ---------------------------------------------------------------------------


def test_c4_presend_unknown_outcome(ops_store):
    """C4: a durable pre-send state exists ('possibly_sent'); a lost
    submission (heartbeat lapse on a possibly_sent row) persists an UNKNOWN
    outcome, and a matching retry ATTACHES to the same op_id without
    re-dispatching. RED at base: OpRow carries no send-state field."""
    fields = _oprow_field_names()
    send_names = sorted(n for n in fields if "send" in n.lower())
    assert send_names, (
        "C4: the ops row must carry a durable send-state field (the "
        "pre-send 'possibly_sent' commit before an unacknowledged provider "
        f"submission); OpRow fields: {sorted(fields)}"
    )
    cfg = Config(unrestricted=True)
    store = ops_store
    sem = CountingSemaphore(1)
    send_state = send_names[0]
    now = store.now()
    kwargs = {send_state: "possibly_sent"}
    # CHECK_WRONG amendment (plan-critic round 1, blocker B1): the seeded row
    # must carry the REAL fingerprint of the exact retry arguments below, so
    # the attach arm exercises honest fingerprint equality (the original
    # placeholder could only pass by bypassing the conflict contract).
    retry_args = {"vm_name": "test-vm", "checkpoint_name": "c4",
                  "idempotency_key": "c4", "detach": True}
    seeded = statestore.OpRow(
        op_id="c4-op", tool=OP_TOOL, agent="", vm_name="test-vm",
        status=statestore.OP_WORKING, created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="c4-runner",
        heartbeat_at=now - 7200.0,  # lapsed long past heartbeat_ttl_s
        params_hmac=operations.arguments_fingerprint(cfg, store, retry_args),
        idem_key="c4", **kwargs,
    )
    store.op_insert(seeded)
    # Read-time loss classification must persist an UNKNOWN outcome.
    payload = operations.op_status(cfg, "c4-op", "")
    blob = json.dumps(payload).lower()
    assert payload.get("status") == statestore.OP_FAILED, (
        f"C4: a lost possibly_sent op must persist a terminal outcome; got {payload!r}"
    )
    assert "unknown" in blob or "interrupted" in blob, (
        f"C4: the persisted outcome must disclose the UNKNOWN VM-side result; "
        f"got {payload!r}"
    )
    # A matching retry ATTACHES: same op_id, no re-dispatch.
    tool = _Recorder()
    resp, ctx = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "test-vm", "checkpoint_name": "c4", "idempotency_key": "c4",
         "detach": True},
        tool, lambda: sem,
    )
    assert ctx is None and isinstance(resp, dict), (
        f"C4: a matching retry must attach to the unknown-outcome row, not "
        f"re-dispatch; got resp={resp!r} ctx={ctx!r}"
    )
    assert resp.get("op_id") == "c4-op", (
        f"C4: the retry must return the ORIGINAL handle; got {resp!r}"
    )
    assert tool.calls == 0, "C4: an attached retry must not re-dispatch the body"
    retry_blob = json.dumps(resp).lower()
    assert "unknown" in retry_blob or "interrupted" in retry_blob, (
        f"C4: the attach must carry the unknown outcome; got {resp!r}"
    )


# ---------------------------------------------------------------------------
# #157 — C5: durable VM epoch + restore barrier
# ---------------------------------------------------------------------------


@pytest.fixture()
def lifecycle_fakes(monkeypatch):
    """Stub the PowerShell surface lifecycle.checkpoint_restore rides: name
    resolution, the VM lock, the host legs, check_result and the session
    invalidation spy. Returns the spy-call list."""
    from hyperv_mcp import vmident

    calls: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        vmident, "resolve",
        lambda cfg, vm_name="", vm_id="": vmident.VMRef(VM_GUID, vm_name or "test-vm"),
    )
    monkeypatch.setattr(vmlocks, "vm_lock", lambda key, mode="write": contextlib.nullcontext())
    monkeypatch.setattr(
        pswindows, "check_result", lambda result, ctx="": None,
    )
    monkeypatch.setattr(
        psdsessions, "invalidate_vm",
        lambda vm_guid, reason=None: (calls.append((vm_guid, reason)), 0)[1],
    )
    return calls


def _lifecycle_run_ok(cfg, script, **kwargs):
    if "final_state" in script:
        return _ok({"final_state": "Off"})
    return pswindows.PSResult(stdout="", returncode=0)


def test_c5_durable_vm_epoch(tmp_path, monkeypatch, ops_store, lifecycle_fakes):
    """C5: a durable per-VM epoch record exists; checkpoint_restore dirties it
    in its pre-send transaction; the session-pool borrow surface names an
    epoch consult. RED at base: no epoch surface exists anywhere (the pool
    borrow consults nothing store-backed)."""
    cfg = Config(unrestricted=True)
    store = ops_store
    monkeypatch.setattr(lifecycle, "_run", _lifecycle_run_ok)
    out = lifecycle.checkpoint_restore(
        cfg, vm_name="test-vm", checkpoint_name="cp5", confirm=True,
    )
    assert out.get("status") == "restored", f"C5: restore stub failed: {out!r}"
    assert _has_durable_epoch_surface(store), (
        "C5: no durable per-VM epoch surface exists on the store (no public "
        "epoch-named member, no *epoch* table) — the restore barrier has "
        "nothing to consult"
    )
    assert _epoch_dirty(store, VM_GUID), (
        "C5: checkpoint_restore must record a dirty epoch for the VM in its "
        "pre-send transaction (a restored guest must block stale session "
        "reuse until confirmed invalidation clears the epoch)"
    )
    pool_surface = [
        n for n in vars(psdsessions.SessionPool)
        if "epoch" in n.lower() and not n.startswith("_")
    ] or [
        p for p in inspect.signature(psdsessions.SessionPool.__init__).parameters
        if p not in ("self", "worker_factory") and "epoch" in p.lower()
    ]
    assert pool_surface, (
        "C5: the SessionPool borrow path exposes no epoch consult surface "
        "(no public epoch-named member, no epoch-related constructor "
        "parameter) — session acquisition cannot consult the durable epoch"
    )


# ---------------------------------------------------------------------------
# #157 — C6: failure/cancel arms invalidate or mark uncertain
# ---------------------------------------------------------------------------


def test_c6_failure_cancel_arms_mark_uncertain(monkeypatch, ops_store, lifecycle_fakes):
    """C6: checkpoint_restore's failure arm (restore leg raises) AND cancel
    arm (OperationCancelled after the restore leg commits) must both
    invalidate sessions or leave the durable epoch dirty — no stale reusable
    sessions. RED at base (P6): the cancel arm skips invalidate_vm entirely
    and no epoch exists."""
    cfg = Config(unrestricted=True)
    store = ops_store
    calls = lifecycle_fakes

    # -- failure arm: the restore leg raises --------------------------------
    def _leg_raises(cfg, script, **kwargs):
        raise RuntimeError("restore leg failed")

    monkeypatch.setattr(lifecycle, "_run", _leg_raises)
    with pytest.raises(RuntimeError):
        lifecycle.checkpoint_restore(
            cfg, vm_name="test-vm", checkpoint_name="cp6f", confirm=True,
        )
    assert calls or _epoch_dirty(store, VM_GUID), (
        "C6 failure arm: a failed restore leg must invalidate the VM's "
        "sessions or mark its durable epoch dirty/uncertain (a partially "
        "applied restore must block session reuse)"
    )

    # -- cancel arm: OperationCancelled after the restore leg commits -------
    monkeypatch.setattr(lifecycle, "_run", _lifecycle_run_ok)
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="c6-cancel-op", tool="hyperv_checkpoint_restore", agent="",
        vm_name="test-vm", status=statestore.OP_WORKING,
        created_at=now, updated_at=now, runner="c6runner", heartbeat_at=now,
        cancel_requested=1,
    ))
    tok_op = operations._current_op_id.set("c6-cancel-op")
    tok_cfg = operations._current_ops_cfg.set(cfg)
    try:
        with pytest.raises(operations.OperationCancelled):
            lifecycle.checkpoint_restore(
                cfg, vm_name="test-vm", checkpoint_name="cp6c", confirm=True,
            )
    finally:
        operations._current_op_id.reset(tok_op)
        operations._current_ops_cfg.reset(tok_cfg)
    assert calls or _epoch_dirty(store, VM_GUID), (
        f"C6 cancel arm: a cancel after the restore leg commits must "
        f"invalidate the VM's sessions or mark its durable epoch dirty "
        f"(invalidate_vm spy calls: {calls})"
    )


# ---------------------------------------------------------------------------
# #157 — C7: replay-window retention
# ---------------------------------------------------------------------------


def test_c7_replay_window_retention(ops_store):
    """C7: a completed op's identity+fingerprint survives ops_prune within
    the replay window, and a same-key retry returns the ORIGINAL handle with
    an explicit result-expired disclosure. RED at base: ops_prune deletes
    the row entirely, so the retry mints a fresh dispatch."""
    cfg = Config(unrestricted=True)
    store = ops_store
    sem = CountingSemaphore(1)
    tool = _Recorder()

    resp, ctx = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "test-vm", "checkpoint_name": "c7", "idempotency_key": "c7"},
        tool, lambda: sem,
    )
    assert ctx is not None, f"C7: expected an inline op context; got {resp!r}"
    operations.complete_inline(ctx, {"ok": True, "status": "created"})
    op_id = ctx["op_id"]
    row = store.op_get(op_id)
    assert row is not None and row.status == statestore.OP_COMPLETED

    # Retention pass with a cutoff far in the future prunes every terminal
    # row it can; the replay-window identity must survive it.
    store.ops_prune(store.now() + 10.0 ** 6)
    survivor = store.op_find_idem("", OP_TOOL, "c7")
    assert survivor is not None and survivor.op_id == op_id, (
        "C7: ops_prune must keep the completed row's identity (or a "
        "tombstone) through the replay window — the retry below would "
        "otherwise be an unknown-id refusal or a fresh re-dispatch"
    )
    assert survivor.params_hmac == row.params_hmac and survivor.idem_key == "c7", (
        f"C7: the surviving identity must keep its fingerprint: "
        f"{survivor.as_dict()}"
    )
    retry = _Recorder()
    resp2, ctx2 = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "test-vm", "checkpoint_name": "c7", "idempotency_key": "c7"},
        retry, lambda: sem,
    )
    assert ctx2 is None and isinstance(resp2, dict), (
        f"C7: the post-prune retry must answer from the row, not re-dispatch; "
        f"got resp={resp2!r} ctx={ctx2!r}"
    )
    assert resp2.get("op_id") == op_id, (
        f"C7: the retry must return the ORIGINAL handle; got {resp2!r}"
    )
    assert retry.calls == 0, "C7: a replay-window retry must not re-dispatch"
    blob = json.dumps(resp2).lower()
    assert "expired" in blob, (
        f"C7: the retained-handle answer must carry an explicit "
        f"result-expired disclosure; got {resp2!r}"
    )


# ---------------------------------------------------------------------------
# #157 — C8: protected reconciliation + legacy blank fingerprint
# ---------------------------------------------------------------------------


def test_c8_protected_reconciliation(ops_store):
    """C8: (a) unknown-outcome rows are not silently pruned at ordinary
    retention; (b) a legacy row with an EMPTY params_hmac is protected
    reconciliation on a fingerprint mismatch — a disclosed refusal, never a
    silent reattach. RED at base: the interrupted row is pruned, and the
    empty fingerprint skips the conflict check (operations.py:305)."""
    cfg = Config(unrestricted=True)
    store = ops_store
    now = store.now()

    # (a) an unknown-outcome (failed/interrupted) row survives retention.
    store.op_insert(statestore.OpRow(
        op_id="c8a-op", tool=OP_TOOL, agent="", vm_name="test-vm",
        status=statestore.OP_FAILED, error_class=statestore.OP_INTERRUPTED,
        created_at=now - 10.0 ** 6, updated_at=now - 10.0 ** 6,
        runner="c8a", heartbeat_at=now - 10.0 ** 6, idem_key="c8a",
    ))
    store.ops_prune(store.now() + 10.0 ** 6)
    survivor = store.op_get("c8a-op")
    assert survivor is not None, (
        "C8a: unknown-outcome rows must NOT be silently pruned at ordinary "
        "retention — they are flagged for reconciliation, not forgotten"
    )

    # (b) legacy row with an empty fingerprint + a DIFFERENT retry.
    store.op_insert(statestore.OpRow(
        op_id="c8b-op", tool=OP_TOOL, agent="", vm_name="test-vm",
        status=statestore.OP_COMPLETED,
        created_at=now, updated_at=now, runner="",
        idem_key="c8b", params_hmac="",
        result_json='{"status":"created"}',
    ))
    tool = _Recorder()
    resp, ctx = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "test-vm-OTHER", "checkpoint_name": "c8b",
         "idempotency_key": "c8b", "detach": True},
        tool, lambda: CountingSemaphore(1),
    )
    assert ctx is None and isinstance(resp, dict), (
        f"C8b: expected a consult answer, not an inline dispatch: {resp!r}"
    )
    assert tool.calls == 0, "C8b: the conflict path must not dispatch the body"
    assert resp.get("ok") is False, (
        f"C8b: an empty-fingerprint row with different arguments is protected "
        f"reconciliation — a disclosed refusal, never a silent reattach of "
        f"the stored result; got {resp!r}"
    )
    blob = json.dumps(resp).lower()
    assert any(w in blob for w in ("reconcil", "conflict", "fingerprint")), (
        f"C8b: the refusal must name the reconciliation/conflict; got {resp!r}"
    )


# ---------------------------------------------------------------------------
# #157 — C9: migration seeds (schema v6) + #151-preserving relay kind
# ---------------------------------------------------------------------------

# The v5 schema exactly as base ships it (statestore._SCHEMA_STATEMENTS at
# 60f98c9). Frozen here so the check can build a genuine v5 database at any
# head revision and demand the forward migration.
_V5_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        vm_name TEXT NOT NULL DEFAULT '',
        vm_id TEXT NOT NULL DEFAULT '',
        pid INTEGER NOT NULL DEFAULT 0,
        start_time_ticks INTEGER,
        job_dir TEXT NOT NULL DEFAULT '',
        out_path TEXT NOT NULL DEFAULT '',
        err_path TEXT NOT NULL DEFAULT '',
        exit_path TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'starting'
            CHECK (state IN ('starting','active','stopped','orphaned')),
        cred_ref TEXT NOT NULL DEFAULT 'inline',
        cred_profile TEXT NOT NULL DEFAULT '',
        cred_username TEXT NOT NULL DEFAULT '',
        owner TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS relays (
        relay_id TEXT PRIMARY KEY,
        vm_name TEXT NOT NULL DEFAULT '',
        vm_id TEXT NOT NULL DEFAULT '',
        guest_port INTEGER NOT NULL DEFAULT 0,
        bind TEXT NOT NULL DEFAULT '127.0.0.1',
        host_port INTEGER NOT NULL DEFAULT 0,
        started_at TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'active'
            CHECK (state IN ('active','stopped','interrupted')),
        cred_ref TEXT NOT NULL DEFAULT 'inline',
        cred_profile TEXT NOT NULL DEFAULT '',
        cred_username TEXT NOT NULL DEFAULT '',
        owner TEXT,
        kind TEXT NOT NULL DEFAULT 'http'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS leases (
        row_key      TEXT PRIMARY KEY,
        lease_id     TEXT NOT NULL,
        vm_key       TEXT NOT NULL,
        vm_name      TEXT NOT NULL DEFAULT '',
        scope        TEXT NOT NULL,
        holder_agent TEXT,
        fencing_seq  INTEGER NOT NULL DEFAULT 0,
        acquired_at  REAL NOT NULL DEFAULT 0,
        ttl_s        INTEGER NOT NULL DEFAULT 0,
        expires_at   REAL NOT NULL DEFAULT 0,
        kind         TEXT NOT NULL DEFAULT 'explicit'
            CHECK (kind IN ('explicit','call')),
        write_lock   INTEGER NOT NULL DEFAULT 1
    )
    """,
    "CREATE INDEX IF NOT EXISTS leases_active ON leases(vm_key, expires_at)",
    "CREATE INDEX IF NOT EXISTS leases_by_id ON leases(lease_id)",
    "CREATE INDEX IF NOT EXISTS leases_by_name ON leases(vm_name COLLATE NOCASE)",
    """
    CREATE TABLE IF NOT EXISTS fence_counters (
        vm_key   TEXT NOT NULL,
        scope    TEXT NOT NULL,
        last_seq INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (vm_key, scope)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ops (
        op_id TEXT PRIMARY KEY,
        agent TEXT NOT NULL DEFAULT '',
        tool TEXT NOT NULL,
        vm_id TEXT NOT NULL DEFAULT '',
        vm_name TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'working'
            CHECK (status IN ('working','input_required','completed','failed','cancelled')),
        error_class TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        runner TEXT NOT NULL DEFAULT '',
        heartbeat_at REAL NOT NULL DEFAULT 0,
        cancel_requested INTEGER NOT NULL DEFAULT 0,
        params_hmac TEXT NOT NULL DEFAULT '',
        idem_key TEXT NOT NULL DEFAULT '',
        result_json TEXT,
        result_size INTEGER NOT NULL DEFAULT 0,
        poll_interval_ms INTEGER NOT NULL DEFAULT 2000
    )
    """,
    "CREATE INDEX IF NOT EXISTS ops_by_agent ON ops(agent, status)",
    """
    CREATE UNIQUE INDEX IF NOT EXISTS ops_idem
        ON ops(agent, tool, idem_key) WHERE idem_key <> ''
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        agent TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL,
        ref_id TEXT NOT NULL DEFAULT '',
        vm_id TEXT NOT NULL DEFAULT '',
        data_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS events_by_agent ON events(agent, seq)",
    """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
)


def _build_v5_db(path: Path) -> None:
    con = sqlite3.connect(str(path))
    try:
        con.execute("BEGIN IMMEDIATE")
        for statement in _V5_SCHEMA_STATEMENTS:
            con.execute(statement)
        now = 1770000000.0
        con.execute(
            "INSERT INTO ops (op_id, agent, tool, vm_id, vm_name, status, "
            "error_class, created_at, updated_at, runner, heartbeat_at, "
            "cancel_requested, params_hmac, idem_key, result_json, "
            "result_size, poll_interval_ms) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("c9-terminal", "", OP_TOOL, "", "test-vm", "completed", "",
             now, now, "", 0.0, 0, "feedface", "c9-terminal",
             '{"status":"created"}', 22, 2000),
        )
        con.execute(
            "INSERT INTO ops (op_id, agent, tool, vm_id, vm_name, status, "
            "error_class, created_at, updated_at, runner, heartbeat_at, "
            "cancel_requested, params_hmac, idem_key, result_json, "
            "result_size, poll_interval_ms) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("c9-working", "", OP_TOOL, "", "test-vm", "working", "",
             now, now, "c9runner", now, 0, "feedface", "c9-working",
             None, 0, 2000),
        )
        con.execute("PRAGMA user_version=5")
        con.execute("COMMIT")
    finally:
        con.close()


def test_c9_migration_seeds_v6(tmp_path):
    """C9: SCHEMA_VERSION becomes 6; a v5 store upgrades forward with its
    live+terminal rows' identity intact (params_hmac/idem_key preserved, new
    columns defaulted safely), repeated reopen and a subsequent write
    behave. The relay-kind read-back stays the #151-disclosed 'http'
    (PRESERVING arm — deliberately executed BEFORE the version assert so it
    also runs at base; do not re-litigate #151 here). RED at base:
    SCHEMA_VERSION == 5."""
    path = tmp_path / "t157-v5.db"
    _build_v5_db(path)
    store = statestore.open(str(path))
    try:
        # PRESERVING arm: an untyped (kind defaulted) relay row reads back
        # 'http' exactly as #151 shipped.
        store.relay_upsert(statestore.RelayRow(
            relay_id="c9-relay", vm_name="test-vm", vm_id=VM_GUID,
            guest_port=22, host_port=0, state=statestore.RELAY_ACTIVE,
        ))
        relay = store.relay_get("c9-relay")
        assert relay is not None and relay.kind == "http", (
            f"C9 preserving arm: an untyped relay row must keep the #151 "
            f"disclosed 'http' read-back; got {relay.as_dict() if relay else None}"
        )

        assert statestore.SCHEMA_VERSION == 6, (
            f"C9: SCHEMA_VERSION must advance to 6 (identity/epoch/send-state "
            f"seeds); got {statestore.SCHEMA_VERSION}"
        )
        # The open above must have migrated the v5 stamp forward.
        con = sqlite3.connect(str(path))
        try:
            found = int(con.execute("PRAGMA user_version").fetchone()[0])
        finally:
            con.close()
        assert found == 6, (
            f"C9: a v5 store must upgrade forward on open; user_version={found}"
        )
        # Identity survives: terminal + working rows, fingerprints intact.
        terminal = store.op_find_idem("", OP_TOOL, "c9-terminal")
        assert terminal is not None and terminal.params_hmac == "feedface", (
            f"C9: the terminal row's identity must survive the migration: "
            f"{terminal.as_dict() if terminal else None}"
        )
        assert terminal.status == "completed" and terminal.idem_key == "c9-terminal"
        working = store.op_find_idem("", OP_TOOL, "c9-working")
        assert working is not None and working.status == "working", (
            f"C9: the live row must survive the migration: "
            f"{working.as_dict() if working else None}"
        )
        # A subsequent write behaves against the migrated schema.
        store.op_insert(statestore.OpRow(
            op_id="c9-fresh", tool=OP_TOOL, agent="", vm_name="test-vm",
            status=statestore.OP_WORKING, created_at=store.now(),
            updated_at=store.now(), runner="c9fresh",
        ))
        assert store.op_get("c9-fresh") is not None
    finally:
        store.close()
    # Repeated reopen against the now-current database is clean.
    store2 = statestore.open(str(path))
    try:
        again = store2.op_find_idem("", OP_TOOL, "c9-terminal")
        assert again is not None and again.params_hmac == "feedface", (
            "C9: repeated reopen must keep the migrated rows addressable"
        )
    finally:
        store2.close()


# ---------------------------------------------------------------------------
# #157 — C10: no duplicated dispatch authority at saturation
# ---------------------------------------------------------------------------


def test_c10_saturation_accounting(monkeypatch, ops_store):
    """C10: at capacity exhaustion caused by a prior failed start, the leaked
    permit must not starve later legitimate dispatches — a follow-up detach
    dispatch succeeds after a failed-insert+retry cycle, and the permit
    accounting balances once the runner drains. RED at base: the insert
    failure leaks the only permit, so the follow-up is refused busy
    forever."""
    cfg = Config(unrestricted=True)
    store = ops_store
    sem = CountingSemaphore(1)
    tool = _Recorder()

    def _boom(row):
        raise StateStoreError("injected insert failure")

    store.op_insert = _boom
    escaped = None
    try:
        operations.guard_consult(
            cfg, OP_TOOL,
            {"vm_name": "test-vm", "checkpoint_name": "c10",
             "detach": True, "idempotency_key": "c10-fail"},
            tool, lambda: sem,
        )
    except Exception as exc:  # noqa: BLE001
        escaped = exc
    finally:
        del store.op_insert

    resp, ctx = operations.guard_consult(
        cfg, OP_TOOL,
        {"vm_name": "test-vm", "checkpoint_name": "c10",
         "detach": True, "idempotency_key": "c10-legit"},
        tool, lambda: sem,
    )
    assert ctx is None and isinstance(resp, dict) and resp.get("op_id") and \
        resp.get("status") == statestore.OP_WORKING, (
        f"C10: a follow-up dispatch must succeed after a failed-start cycle "
        f"(a leaked permit starves the pool at capacity 1); got {resp!r} "
        f"(earlier escaped={escaped!r})"
    )
    operations.drain_for_tests(timeout_s=5.0)
    assert sem.released == sem.acquired, (
        f"C10: permit accounting must balance after the runner drains; "
        f"acquired={sem.acquired} released={sem.released}"
    )
    assert tool.calls <= 1, (
        f"C10: at most one dispatch may run for the identical-retry race; "
        f"tool ran {tool.calls} times"
    )


# ---------------------------------------------------------------------------
# #158 — C11: tripartite change shape
# ---------------------------------------------------------------------------


def _run_apply(fake):
    cfg = Config(unrestricted=True)
    import hyperv_mcp.repair as repair_mod
    from hyperv_mcp import pswindows as _pw

    saved = _pw.run_ps
    _pw.run_ps = fake
    try:
        return repair_mod.repair_guest_access(
            cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        )
    finally:
        _pw.run_ps = saved


def test_c11_tripartite_change_shape():
    """C11: every applied change carries the apply-outcome, the observation
    quality, and the action-specific postcondition as SEPARATE keys with the
    documented vocabularies. RED at base: none of the three keys exist."""
    broken = _guest(status="Stopped", listen="192.168.50.20", fw=False)
    broken["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    healthy = _guest(status="Running", listen="0.0.0.0", fw=True)
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken),
        _ok({"service": "sshd", "status": "Running"}),
        _ok({"backup": "C:/ProgramData/ssh/sshd_config.bak-20260929", "replaced": 1}),
        _ok({"port": "22", "enabled_rules": ["OpenSSH-Server-In-TCP"]}),
        _ok(_host()), _ok(healthy),
    ])
    out = _run_apply(fake)
    assert out["applied"] is True and len(out["changes"]) == 3, (
        f"C11: the three-action scenario must apply cleanly first; got "
        f"{json.dumps(out)[:300]}"
    )
    for change in out["changes"]:
        assert change.get("apply_outcome") in ("applied", "failed", "not_attempted"), (
            f"C11: change must carry a separate apply_outcome key from the "
            f"documented vocabulary; got {change!r}"
        )
        assert change.get("observation") in ("positive", "negative", "partial", "unavailable"), (
            f"C11: change must carry a separate observation-quality key from "
            f"the documented vocabulary; got {change!r}"
        )
        assert change.get("postcondition") in ("satisfied", "unsatisfied", "unknown"), (
            f"C11: change must carry a separate action-specific postcondition "
            f"key from the documented vocabulary; got {change!r}"
        )


# ---------------------------------------------------------------------------
# #158 — C12: failed apply preserved (P4)
# ---------------------------------------------------------------------------


def test_c12_failed_apply_preserved():
    """C12: when the apply leg fails but the verify readback is healthy, the
    change keeps the failure AND verification facts separate, verified stays
    False, and the postcondition may independently report satisfied. RED at
    base (P4): verified flips True off a healthy readback while applied is
    False."""
    broken = _guest(status="Stopped")
    healthy = _guest(status="Running")
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken),
        pswindows.PSResult(stdout="", returncode=1, stderr="apply failed"),
        _ok(_host()), _ok(healthy),
    ])
    out = _run_apply(fake)
    assert len(out["changes"]) == 1, (
        f"C12: expected the single start_service change; got {out['changes']!r}"
    )
    change = out["changes"][0]
    assert change.get("applied") is False, "C12: the failed apply must stay applied=False"
    assert "error" in change and change.get("error"), (
        f"C12: the apply failure facts must be preserved on the change; got {change!r}"
    )
    assert change.get("verified") is False, (
        f"C12 (P4): verified must stay False when the apply failed, even with "
        f"a healthy readback — a readback cannot attest an apply that never "
        f"ran; got {change!r}"
    )
    # The separate postcondition channel MAY report the observed state.
    assert change.get("postcondition") in (None, "satisfied", "unknown"), (
        f"C12: the postcondition channel is separate from verified; got {change!r}"
    )


# ---------------------------------------------------------------------------
# #158 — C13: unknown on incomplete observation (P3 + P3b)
# ---------------------------------------------------------------------------


def test_c13_unknown_on_incomplete_observation(monkeypatch):
    """C13: verify legs unavailable/timeout yield postcondition=unknown and
    verified=False (arm 1), and a RAISING observation leg still returns the
    changes instead of losing them (arm 2). RED at base (P3): the timeout
    readback clears the finding, flipping verified True; (P3b) a raising
    verify leg propagates the exception away and drops the changes."""
    cfg = Config(unrestricted=True)

    # -- arm 1: the verify guest probe times out (the observation never ran) -
    broken = _guest(status="Stopped")
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken),
        _ok({"service": "sshd", "status": "Running"}),  # apply ok
        _ok(_host()),                                    # verify host ok
        TimeoutError("guest probe timed out"),           # verify guest lost
    ])
    out = _run_apply(fake)
    assert len(out["changes"]) == 1, (
        f"C13 arm 1: expected the single change; got {out['changes']!r}"
    )
    change = out["changes"][0]
    assert change.get("applied") is True
    assert change.get("verified") is False, (
        f"C13 (P3): an unobserved verify pass must not count as verified; "
        f"got {change!r}"
    )
    assert change.get("postcondition") == "unknown", (
        f"C13 (P3): an unavailable observation must yield postcondition "
        f"unknown, not a clearance; got {change!r}"
    )

    # -- arm 2: the verify observation leg raises (busy VM lock) ------------
    class _LimitLocks:
        """diagnostics.vm_lock stand-in that permits `limit` acquisitions and
        raises on the next one, simulating a busy VM during the verify pass
        (the lock acquire sits OUTSIDE diagnose_report's try, so a busy lock
        raises straight out of the observation leg)."""

        def __init__(self, limit):
            self.n = 0
            self.limit = limit

        def __call__(self, key, mode="read"):
            self.n += 1
            if self.n > self.limit:
                raise RuntimeError("vm lock busy: injected")
            return contextlib.nullcontext()

    broken2 = _guest(status="Stopped")
    fake2 = FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken2),
        _ok({"service": "sshd", "status": "Running"}),  # apply ok
    ])
    # Legs before the verify pass: diagnose(2 locks) + apply(1 lock) = 3.
    monkeypatch.setattr(diagnostics, "vm_lock", _LimitLocks(3))
    saved_run = pswindows.run_ps
    pswindows.run_ps = fake2
    try:
        out2 = repair.repair_guest_access(
            cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        )
    except Exception as exc:  # noqa: BLE001 — losing the changes IS the defect
        pytest.fail(
            f"C13 (P3b): a raising observation leg must still return the "
            f"changes with unknown postconditions, not raise away the "
            f"result: {type(exc).__name__}: {exc}"
        )
    finally:
        pswindows.run_ps = saved_run
    assert len(out2["changes"]) == 1, (
        f"C13 arm 2: the changes must survive the raising observation leg; "
        f"got {out2['changes']!r}"
    )
    change2 = out2["changes"][0]
    assert change2.get("applied") is True
    assert change2.get("verified") is False
    assert change2.get("postcondition") == "unknown", (
        f"C13 (P3b): the surviving change must carry an unknown "
        f"postcondition; got {change2!r}"
    )


# ---------------------------------------------------------------------------
# #158 — C14: service vs listener facts
# ---------------------------------------------------------------------------


def test_c14_service_vs_listener_facts():
    """C14: a start_service postcondition records the service-status
    observation AND the listener-binding observation as separate named facts
    (service running does not imply listener satisfied). RED at base: no
    postcondition detail exists at all."""
    broken = _guest(status="Stopped")
    healthy = _guest(status="Running")
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken),
        _ok({"service": "sshd", "status": "Running"}),
        _ok(_host()), _ok(healthy),
    ])
    out = _run_apply(fake)
    assert len(out["changes"]) == 1
    change = out["changes"][0]
    assert change.get("action") == "start_service", (
        f"C14: expected the sshd start_service change; got {change!r}"
    )
    detail = change.get("postcondition_detail")
    assert isinstance(detail, dict) and detail, (
        f"C14: start_service must carry a structured postcondition detail; "
        f"got {change!r}"
    )
    keys = {str(k).lower() for k in detail}
    service_facts = [k for k in keys if "service" in k]
    listener_facts = [k for k in keys if "listener" in k or "binding" in k]
    assert service_facts, (
        f"C14: the postcondition detail must name the service-status "
        f"observation separately; got {detail!r}"
    )
    assert listener_facts, (
        f"C14: the postcondition detail must name the listener-binding "
        f"observation separately — service running does not imply the "
        f"listener is satisfied; got {detail!r}"
    )


# ---------------------------------------------------------------------------
# #158 — C15: operator intent
# ---------------------------------------------------------------------------


def test_c15_operator_intent():
    """C15: repair_guest_access accepts an explicit intent argument
    (bind_address / intended_bindings); the rewrite plan records the intended
    replacement per line; an absent intent on a stale-binding item yields a
    diagnostic-requiring-decision change, never a guessed 0.0.0.0 rewrite.
    RED at base: the signature carries no intent parameter (the with-intent
    call is a TypeError)."""
    params = inspect.signature(repair.repair_guest_access).parameters
    intent_params = [p for p in ("bind_address", "intended_bindings") if p in params]
    assert intent_params, (
        f"C15: repair_guest_access must accept an explicit operator intent "
        f"(bind_address or intended_bindings); parameters: {sorted(params)}"
    )
    intent_name = intent_params[0]

    cfg = Config(unrestricted=True)
    stale = _guest(listen="192.168.50.20")
    stale["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]

    # Absent intent: a diagnostic-requiring-decision item, not a guessed
    # rewrite of the stale line.
    fake = FakePS([_guid_result(), _ok(_host()), _ok(stale)])
    saved = pswindows.run_ps
    pswindows.run_ps = fake
    try:
        out = repair.repair_guest_access(cfg, "test-vm", cred=CRED)
    finally:
        pswindows.run_ps = saved
    rewrite = [p for p in out["plan"] if p.get("action") == "rewrite_stale_ssh_bindings"]
    assert rewrite, "C15: the stale-binding scenario must plan a rewrite item"
    blob = json.dumps(rewrite[0]).lower()
    assert any(w in blob for w in ("decision", "ambiguous", "intent")), (
        f"C15: an absent operator intent must yield a "
        f"diagnostic-requiring-decision item, not a guessed replacement; "
        f"got {rewrite[0]!r}"
    )

    # Explicit intent: the plan records the intended replacement per line.
    fake2 = FakePS([_guid_result(), _ok(_host()), _ok(stale)])
    pswindows.run_ps = fake2
    try:
        out2 = repair.repair_guest_access(
            cfg, "test-vm", cred=CRED, **{intent_name: ["0.0.0.0"]},
        )
    finally:
        pswindows.run_ps = saved
    rewrite2 = [p for p in out2["plan"] if p.get("action") == "rewrite_stale_ssh_bindings"]
    assert rewrite2, "C15: with explicit intent the rewrite item must remain"
    blob2 = json.dumps(rewrite2[0])
    assert "0.0.0.0" in blob2, (
        f"C15: the plan must record the intended replacement per line; got "
        f"{rewrite2[0]!r}"
    )


# ---------------------------------------------------------------------------
# #158 — C16: wire-compat `verified`
# ---------------------------------------------------------------------------


def test_c16_wire_compat_verified():
    """C16: the `verified` truth table — True only for applied + satisfied
    postcondition + positive observation (scenario 1, PRESERVING at base);
    False on an unobserved verify pass (scenario 2) and on a failed apply
    with a healthy readback (scenario 3), where a separate observed-state
    fact may still show the current state. RED at base via scenarios 2/3."""
    # Scenario 1: healthy end to end (wire compatibility — stays True).
    broken = _guest(status="Stopped")
    healthy = _guest(status="Running")
    out1 = _run_apply(FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken),
        _ok({"service": "sshd", "status": "Running"}),
        _ok(_host()), _ok(healthy),
    ]))
    assert out1["changes"][0].get("applied") is True
    assert out1["changes"][0].get("verified") is True, (
        f"C16 scenario 1 (wire compat): a fully applied, positively observed, "
        f"satisfied repair must stay verified=True; got {out1['changes'][0]!r}"
    )

    # Scenario 2: verify pass unobserved (timeout) — verified False.
    out2 = _run_apply(FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken),
        _ok({"service": "sshd", "status": "Running"}),
        _ok(_host()),
        TimeoutError("guest probe timed out"),
    ]))
    change2 = out2["changes"][0]
    assert change2.get("verified") is False, (
        f"C16 scenario 2: verified must be False when the postcondition is "
        f"unknown; got {change2!r}"
    )

    # Scenario 3: failed apply + positive readback — verified False.
    out3 = _run_apply(FakePS([
        _guid_result(),
        _ok(_host()), _ok(broken),
        pswindows.PSResult(stdout="", returncode=1, stderr="apply failed"),
        _ok(_host()), _ok(healthy),
    ]))
    change3 = out3["changes"][0]
    assert change3.get("applied") is False
    assert change3.get("verified") is False, (
        f"C16 scenario 3: verified must be False while applied is False — "
        f"an observed-state fact may exist separately, but a failed apply "
        f"cannot be verified; got {change3!r}"
    )


# ---------------------------------------------------------------------------
# #158 — C17: guest-floor disclosure (structural docs pin)
# ---------------------------------------------------------------------------


def _repair_docstrings() -> list[str]:
    src = Path(server_module.__file__).read_text(encoding="utf-8")
    docs = []
    for m in re.finditer(r"def hyperv_repair_guest_access\(", src):
        dm = re.search(r'"""(.*?)"""', src[m.end():], re.S)
        if dm:
            docs.append(dm.group(1))
    return docs


def _readme_repair_section() -> str:
    root = Path(server_module.__file__).resolve().parents[2]
    text = (root / "README.md").read_text(encoding="utf-8")
    start = text.find("### Guest Access Diagnostics & Repair")
    assert start >= 0, "C17: README.md must keep the Guest Access Diagnostics & Repair section"
    nxt = text.find("\n### ", start + 1)
    return text[start:nxt if nxt > 0 else len(text)]


def test_c17_guest_floor_disclosure():
    """C17: the tool docstring AND the README repair section must disclose the
    guest floor — repair/diagnostics need a RUNNING guest reachable over
    PowerShell Direct, distinct from the host-console/firmware prerequisites
    of the console family. Structural pin on literals. RED at base: neither
    surface carries the disclosure."""
    docs = _repair_docstrings()
    assert docs, "C17: hyperv_repair_guest_access docstring not found in server.py"
    doc = max(docs, key=len).lower()
    assert "powershell direct" in doc, (
        "C17: the repair tool docstring must name the PowerShell Direct "
        "guest floor"
    )
    assert "running guest" in doc or ("running" in doc and "guest" in doc), (
        "C17: the repair tool docstring must state the RUNNING-guest "
        "prerequisite"
    )
    assert any(w in doc for w in ("host console", "console", "firmware", "pre-boot")), (
        "C17: the repair tool docstring must distinguish the guest floor "
        "from the host-console/firmware prerequisites of the console family"
    )
    section = _readme_repair_section().lower()
    assert "powershell direct" in section, (
        "C17: the README repair section must name the PowerShell Direct "
        "guest floor"
    )
    assert "running guest" in section or ("running" in section and "guest" in section), (
        "C17: the README repair section must state the RUNNING-guest "
        "prerequisite"
    )
    assert any(w in section for w in ("host console", "console", "firmware", "pre-boot")), (
        "C17: the README repair section must distinguish the guest floor "
        "from the host-console/firmware prerequisites of the console family"
    )


# ---------------------------------------------------------------------------
# #158 — C18: stale-address planning — '::1' is loopback, not stale (P5)
# ---------------------------------------------------------------------------


def test_c18_stale_address_loopback():
    """C18: _is_stale_address('::1') is False; '::1' is classed non-stale
    (loopback); a config_listen=['::1'] guest gets NO rewrite proposal. RED
    at base (P5): '::1' has no alpha characters so it classifies stale and
    the plan proposes rewriting the loopback binding."""
    report = {"guest": {"ip_addresses": {
        "ipv4": [{"interface": "E", "address": "10.0.0.5", "prefix": 24}],
    }}}
    assert repair._is_stale_address("::1", report) is False, (
        "C18 (P5): '::1' is the IPv6 loopback — a non-stale class — and must "
        "never classify as a stale binding"
    )
    # Loopback classed explicitly non-stale (either in the universal set or
    # functionally excluded).
    assert "::1" in diagnostics._UNIVERSAL_ADDRESSES or \
        repair._is_stale_address("::1", {"guest": {}}) is False, (
        "C18: '::1' must be listed in a non-stale (loopback) class"
    )
    loopback_guest = _guest(listen="::1")
    cfg = Config(unrestricted=True)
    fake = FakePS([_guid_result(), _ok(_host()), _ok(loopback_guest)])
    saved = pswindows.run_ps
    pswindows.run_ps = fake
    try:
        out = repair.repair_guest_access(cfg, "test-vm", cred=CRED)
    finally:
        pswindows.run_ps = saved
    actions = [p.get("action") for p in out["plan"]]
    assert "rewrite_stale_ssh_bindings" not in actions, (
        f"C18: a loopback-only ListenAddress must not be proposed for "
        f"rewrite; plan actions: {actions}"
    )
