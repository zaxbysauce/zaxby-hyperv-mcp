"""PR #166 review fixes, wave 2: RED-first pins for FB-010/FB-011/FB-012/FB-014.

FB-010 (HIGH, probe-confirmed) — the tasks-route INSERT-RACE RE-CONSULT omitted
every guard the ordinary consult applies: it only checked a fingerprint
mismatch and a blank fingerprint, so it (a) attached a LIVE task handle to a
legacy generation-0 identity the ordinary consult refuses with the AC8
reconciliation refusal, (b) attached to a stranded terminal failed/interrupted
key-holder instead of freeing its key, and (c) attached to a dead working
sync- residue the ordinary consult reconciles. The re-consult must run the
SAME shared guards (the _legacy_protection_reason, _inline_residue_recovery
and _stranded_presend_key_recovery helpers) the ordinary consult runs.

  test_fb010_reconsult_refuses_legacy_gen0_winner      — RED at base
  test_fb010_reconsult_frees_stranded_presend_key      — RED at base
  test_fb010_reconsult_reconciles_qualified_residue    — RED at base
  test_fb010_reconsult_answers_residue_fence_failure   — RED at base

FB-011 (MEDIUM, probe-confirmed) — the AdmissionStopped cancelled transitions
passed no `generation`, so a FENCED executor's pre-body cancel terminalized a
row whose generation was superseded (probe: fenced gen 1 -> 2, the arm's
unguarded write landed status=cancelled on the gen-2 row).

  test_fb011_admission_stopped_cancel_obeys_fence      — RED at base
  test_fb011_grant_window_stop_cancel_obeys_fence      — RED at base

FB-011 wave 4 (PR #166 verification transcript, completeness) — two MORE
pre-body arms of the same function carried NO generation: the send-gate busy
arm ("op.busy") and the commit_send_intent failure arm ("op.failed"). The
commit-failure arm is the one a fenced executor actually takes (the commit
fails precisely because op_mark_send is generation-validated), and its
unguarded pre_body_terminal write cleared the NEWER executor's send mark.
Every pre-body write now carries the captured generation in the fail-closed
form (int(generation or 0) — a real 0, never `or None`). The pins identify
the attempt by its IDEMPOTENCY KEY (op_find_idem), never by the op context.

  test_fb011_commit_failure_arm_obeys_fence            — RED before the wave-4 fix
  test_fb011_send_gate_busy_arm_obeys_fence            — RED before the wave-4 fix

FB-011 wave 5 (verification transcript, the honest gap) — the wave-4 pins all
drive executors with captured generation=1, where the fail-open FORM
(`generation or None` / `int(generation or 0) or None`) still guards (1 stays
1). The form only opens at captured generation 0/None — a LEGACY generation-0
executor (the v6 migration shape) on a row fenced 0 -> 1 — which no shipped
pin drove. Each wave-5 pin drives exactly that legacy path through every
pre-body arm (both AdmissionStopped cancels, the send-gate busy terminal AND
its op_release_idem, the pre-send commit-failure terminal, and the previously
un-pinned _admission_refusal transition AND its op_release_idem), identifying
the attempt by its IDEMPOTENCY KEY. RED under the single-site form mutation
at each named site; GREEN at head.

  test_fb011_legacy_gen0_admission_stopped_cancel_obeys_fence
  test_fb011_legacy_gen0_grant_window_stop_cancel_obeys_fence
  test_fb011_legacy_gen0_send_gate_busy_arm_obeys_fence
  test_fb011_legacy_gen0_commit_failure_arm_obeys_fence
  test_fb011_legacy_gen0_admission_refusal_obeys_fence

FB-012 (HIGH, probe-confirmed) — _classify_stale's read-time terminal write
had NO generation predicate, so a read path terminalized a row a newer
executor held (probe: a classifiable WORKING row fenced gen 1 -> 2 was written
failed/unknown at generation 2). The write must carry the row's CAPTURED
generation while still classifying a row whose generation matches (the
ordinary lapsed path, including a legacy generation-0 row whose stored value
IS 0).

  test_fb012_classify_stale_write_obeys_fence          — RED at base
  test_fb012_classify_stale_matching_generation_still_classifies — regression pin

FB-014 (MEDIUM, probe-confirmed) — the tasks-route fence/reconcile refusals
left ZERO durable trace (no event row, no audit line; the guard-route
equivalents are audited through server.py's _audited_rejection). Every
tasks-route consult refusal must record one audit row in the same shape the
guard route's rejections write and one ops event naming the ORIGINAL handle
in ref_id, so an operator can correlate the refusal to the identity.

  test_fb014_reconciliation_refusal_is_traced          — RED at base
  test_fb014_residue_fence_failure_refusal_is_traced   — RED at base

What is faked: nothing beyond the module's own seams — a real temp SQLite
store behind operations.store_for, the shipped tasks_extension driven
directly (the schedules file's _tasks_driver pattern), a one-shot
first-consult-blind store wrapper that deterministically lands a tasks call
in the insert-race RE-CONSULT, and the global auditlog pointed at a temp
JSONL file (the test_b01 save/restore pattern). No sleeps beyond bounded
drains; every store is closed on teardown (Windows file-lock hazard).
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import threading
from types import SimpleNamespace

import pytest

from hyperv_mcp import admission, auditlog, operations, statestore
from hyperv_mcp.config import Config

OP_TOOL = "hyperv_checkpoint_create"
TASKS_ID = "io.modelcontextprotocol/tasks"


# ---------------------------------------------------------------------------
# shared helpers (the wave-1 / schedules-file patterns)
# ---------------------------------------------------------------------------


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


@pytest.fixture()
def ops_store(tmp_path, monkeypatch):
    """A real per-test Store behind the operations.store_for seam, closed on
    teardown (the Windows file-lock teardown hazard)."""
    store = statestore.open(str(tmp_path / "fb-pr166-consult.db"))
    monkeypatch.setattr(operations, "store_for", lambda cfg, environ=None: store)
    yield store
    store.close()


@pytest.fixture()
def admission_env():
    """Size the classed-admission budget the detached runners admit through
    (the schedules-file admission_env pattern: bootstrap sizes it in the
    server; a direct-drive test must size it the same way)."""
    admission.reset()
    admission.configure(total_tokens=8, light_reserve=2, wait_s=0.5, light_wait_s=0.5)
    yield
    admission.reset()


@pytest.fixture()
def audit_sink(tmp_path):
    """Point the global auditlog at a temp JSONL file so refusal audit rows
    are assertable (the test_b01 save/restore pattern — the module _config is
    restored so nothing leaks into other tests)."""
    log = tmp_path / "fb-pr166-audit.jsonl"
    saved = auditlog._config
    auditlog.init(Config(unrestricted=True, audit_log_path=str(log)))
    try:
        yield log
    finally:
        auditlog._config = saved


def _audit_rows(log) -> list[dict]:
    return [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _tasks_runner(cfg: Config, tool, sem):
    """The shipped tasks extension driven directly (the schedules file's
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


def _payload(result) -> dict | None:
    """The refusal envelope when the route refused, else None (a task handle
    carries task_id, not content)."""
    texts = getattr(result, "content", None)
    if not texts:
        return None
    return json.loads(texts[0].text)


class _BlindFirstConsultStore:
    """Deterministically land a tasks call in the INSERT-RACE RE-CONSULT: the
    FIRST op_find_idem answers None (the consult passes and the fresh-dispatch
    arm runs), the insert then loses the (agent, tool, idem_key) UNIQUE race
    to the pre-seeded key-holder, and the SECOND op_find_idem (the re-consult)
    sees the real winner."""

    def __init__(self, inner: statestore.Store) -> None:
        self._inner = inner
        self.finds = 0

    def op_find_idem(self, agent, tool, idem_key):
        self.finds += 1
        if self.finds == 1:
            return None
        return self._inner.op_find_idem(agent, tool, idem_key)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _seed(store, cfg: Config, *, op_id: str, args: dict, **kw) -> statestore.OpRow:
    """Insert a key-holder row whose fingerprint MATCHES the retry arguments
    by default (honest fingerprint equality, the CHECK_WRONG amendment
    pattern); every overridable field is a kw."""
    now = store.now()
    row = statestore.OpRow(
        op_id=op_id, tool=OP_TOOL, agent="",
        vm_name=str(args.get("vm_name") or ""),
        status=kw.pop("status", statestore.OP_WORKING),
        error_class=kw.pop("error_class", ""),
        created_at=kw.pop("created_at", now), updated_at=kw.pop("updated_at", now),
        runner=kw.pop("runner", "seeded-runner"),
        heartbeat_at=kw.pop("heartbeat_at", now),
        params_hmac=kw.pop(
            "params_hmac", operations.arguments_fingerprint(cfg, store, args)),
        idem_key=str(args["idempotency_key"]),
        **kw,
    )
    store.op_insert(row)
    return row


# ---------------------------------------------------------------------------
# FB-011 — the AdmissionStopped cancelled transitions omit the generation
# ---------------------------------------------------------------------------


def _run_body_isolated(*args, **kwargs) -> None:
    """Drive _execute_body inside a throwaway context (the op ContextVars it
    sets stay in the copied context, never the test's)."""
    contextvars.copy_context().run(
        lambda: operations._execute_body(*args, **kwargs))


def test_fb011_admission_stopped_cancel_obeys_fence(ops_store, admission_env):
    """FB-011: a runner whose row was fenced mid-flight (captured generation 1,
    the row now at generation 2 under a replacement executor) hits the
    AdmissionStopped pre-body arm — its cancelled transition must be refused
    by the generation predicate. RED at base: the write has no generation
    predicate and terminalizes the gen-2 row (status=cancelled)."""
    store = ops_store
    cfg = Config(unrestricted=True)
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="fb011-op", tool=OP_TOOL, agent="", vm_name="fb011-vm",
        status=statestore.OP_WORKING, created_at=now, updated_at=now,
        runner="fb011-r", heartbeat_at=now, generation=1,
    ))
    store.op_fence("fb011-op")  # authority moved: 1 -> 2

    stop = threading.Event()
    stop.set()  # admit_sync observes the stop on its first tick -> AdmissionStopped
    _run_body_isolated(
        cfg, "fb011-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, stop, generation=1,
    )
    row = store.op_get("fb011-op")
    assert row.status == statestore.OP_WORKING and row.generation == 2, (
        f"FB-011: a FENCED executor's AdmissionStopped cancel terminalized a "
        f"row whose generation was superseded: {row.as_dict()}"
    )


def test_fb011_grant_window_stop_cancel_obeys_fence(
        ops_store, admission_env, monkeypatch):
    """FB-011 (the grant-to-pop twin of the same AdmissionStopped arm): the
    ticket was granted, the stop signalled inside the grant-to-pop window, and
    the was_stopped arm closes the op cancelled — that transition must carry
    the captured generation too. RED at base: same unguarded write."""
    store = ops_store
    cfg = Config(unrestricted=True)
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="fb011b-op", tool=OP_TOOL, agent="", vm_name="fb011-vm",
        status=statestore.OP_WORKING, created_at=now, updated_at=now,
        runner="fb011b-r", heartbeat_at=now, generation=1,
    ))
    store.op_fence("fb011b-op")  # authority moved: 1 -> 2

    stop = threading.Event()
    ticket = SimpleNamespace(_waiter=None, _ctx_token=None)

    def _fake_admit_sync(*args, **kwargs):
        # Grant, then the cancel lands before the park-window pop observes it.
        stop.set()
        return ticket

    monkeypatch.setattr(admission, "admit_sync", _fake_admit_sync)
    _run_body_isolated(
        cfg, "fb011b-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, stop, generation=1,
    )
    row = store.op_get("fb011b-op")
    assert row.status == statestore.OP_WORKING and row.generation == 2, (
        f"FB-011: the grant-to-pop-window stop cancel terminalized a fenced "
        f"row: {row.as_dict()}"
    )


def _fenced_marked_row(store, op_id: str) -> None:
    """FB-011 wave 4 fixture: a row the captured executor (generation 1) has
    LOST — fenced to generation 2 — whose NEWER executor has committed its
    send (send_state='possibly_sent' at generation 2). The row carries
    idem_key=op_id so the pins can identify the attempt INDEPENDENTLY of the
    op context (op_find_idem, the same identification a retry's consult
    uses)."""
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id=op_id, tool=OP_TOOL, agent="", vm_name="fb011-vm",
        status=statestore.OP_WORKING, created_at=now, updated_at=now,
        runner="fb011-r", heartbeat_at=now, idem_key=op_id, generation=1,
    ))
    assert store.op_fence(op_id) == 2  # authority moved: 1 -> 2
    assert store.op_mark_send(op_id, 2) is True  # the newer executor sent
    row = store.op_get(op_id)
    assert row.generation == 2 and row.send_state == "possibly_sent", (
        f"FB-011 fixture premise: {row.as_dict()}"
    )


def _row_by_idem(store, op_id: str) -> statestore.OpRow:
    """Identify the attempt by its IDEMPOTENCY KEY — never by the op context —
    so a pin cannot be fooled by a row the context happens to name."""
    found = store.op_find_idem("", OP_TOOL, op_id)
    assert found is not None, "FB-011: the attempt row must be findable by key"
    assert found.op_id == op_id, (found.op_id, op_id)
    return found


def test_fb011_commit_failure_arm_obeys_fence(ops_store, admission_env):
    """FB-011 wave 4 (b): the arm a FENCED executor actually takes — the
    pre-send commit fails precisely because op_mark_send is
    generation-validated — so its pre-body failure terminal MUST be refused
    by the same captured-generation predicate: it must NOT land on the newer
    executor's row and must NOT clear the newer row's send mark
    (pre_body_terminal would wipe it). RED before the wave-4 fix: the
    unguarded write flipped the gen-2 row to failed/busy-envelope with
    send_state=''. The attempt is identified by its idempotency key."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_marked_row(store, "fb011c-op")
    _run_body_isolated(
        cfg, "fb011c-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, threading.Event(), generation=1,
    )
    row = _row_by_idem(store, "fb011c-op")
    assert row.status == statestore.OP_WORKING and row.generation == 2 \
        and row.send_state == "possibly_sent", (
            f"FB-011 (wave 4): a FENCED executor's commit-failure pre-body "
            f"write landed on the newer executor's row and cleared its send "
            f"mark: {row.as_dict()}"
        )


def test_fb011_send_gate_busy_arm_obeys_fence(
        ops_store, admission_env, monkeypatch):
    """FB-011 wave 4 (a): the send-gate busy refusal is provably pre-body
    (the gate is acquired BEFORE the pre-send commit and the body), so its
    pre_body_terminal write carries the same hazard — a fenced executor's
    busy terminal must not land on the newer executor's row nor clear its
    send mark, and its idem release must not free the newer row's key. RED
    before the wave-4 fix: the unguarded write flipped the gen-2 row to
    failed with the busy envelope. Identified by idempotency key."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_marked_row(store, "fb011d-op")
    monkeypatch.setattr(operations, "_send_gate_acquire",
                        lambda arguments, blocking=True: False)
    _run_body_isolated(
        cfg, "fb011d-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, threading.Event(), generation=1,
    )
    row = _row_by_idem(store, "fb011d-op")
    assert row.status == statestore.OP_WORKING and row.generation == 2 \
        and row.send_state == "possibly_sent", (
            f"FB-011 (wave 4): a FENCED executor's send-gate busy pre-body "
            f"write landed on the newer executor's row: {row.as_dict()}"
        )
    assert row.idem_key == "fb011d-op", (
        f"FB-011 (wave 4): the fenced executor's busy arm freed the newer "
        f"executor's idempotency slot: {row.as_dict()}"
    )


# ---------------------------------------------------------------------------
# FB-012 — _classify_stale's terminal write has no generation predicate
# ---------------------------------------------------------------------------


def test_fb012_classify_stale_write_obeys_fence(ops_store):
    """FB-012: a classifiable WORKING possibly_sent row read at generation 1
    and fenced to generation 2 before the classification write — the read-time
    write must be refused (the row belongs to the newer executor). RED at
    base: the write lands (status=failed, error_class=unknown, generation 2),
    the exact authority inversion the fence exists to prevent."""
    store = ops_store
    cfg = Config(unrestricted=True)
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="fb012-op", tool=OP_TOOL, agent="", vm_name="fb012-vm",
        status=statestore.OP_WORKING,
        created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="fb012-r", heartbeat_at=now - 7200.0,
        send_state="possibly_sent", generation=1, idem_key="fb012",
    ))
    captured = store.op_get("fb012-op")  # the read-time path's row (gen 1)
    assert captured is not None
    store.op_fence("fb012-op")  # a replacement executor takes authority (gen 2)

    operations._classify_stale(store, captured, cfg)
    row = store.op_get("fb012-op")
    assert row.status == statestore.OP_WORKING, (
        f"FB-012: the read-time staleness classification terminalized a row "
        f"whose generation a newer executor holds: {row.as_dict()}"
    )
    refused_events = [
        e for e in store.events_after("", 0)
        if e["kind"] == "op.failed" and e["ref_id"] == "fb012-op"
    ]
    assert not refused_events, (
        f"FB-012: a refused classification still emitted its op.failed event: "
        f"{refused_events}"
    )


def test_fb012_classify_stale_matching_generation_still_classifies(ops_store):
    """FB-012 regression pin (the 'Careful' clause): the generation predicate
    must not break the ordinary lapsed paths — a possibly_sent row whose
    generation still matches classifies failed/unknown, and a LEGACY
    generation-0 row (the v6 migration default, whose stored value IS 0)
    classifies too."""
    store = ops_store
    cfg = Config(unrestricted=True)
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="fb012-match", tool=OP_TOOL, agent="", vm_name="fb012-vm",
        status=statestore.OP_WORKING,
        created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="fb012-m", heartbeat_at=now - 7200.0,
        send_state="possibly_sent", generation=4, idem_key="fb012m",
    ))
    store.op_insert(statestore.OpRow(
        op_id="fb012-legacy", tool=OP_TOOL, agent="", vm_name="fb012-vm",
        status=statestore.OP_WORKING,
        created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="fb012-l", heartbeat_at=now - 7200.0,
        send_state="possibly_sent", generation=0, idem_key="fb012l",
    ))
    for op_id in ("fb012-match", "fb012-legacy"):
        row = store.op_get(op_id)
        operations._classify_stale(store, row, cfg)
        fresh = store.op_get(op_id)
        assert fresh.status == statestore.OP_FAILED and \
            fresh.error_class == statestore.OP_UNKNOWN, (
                f"FB-012 regression: a matching-generation row no longer "
                f"classifies: {fresh.as_dict()}"
            )


# ---------------------------------------------------------------------------
# FB-012's cousin on the shipped read paths — op_status must still classify
# (the frozen C4 shape, driven through the public tool path)
# ---------------------------------------------------------------------------


def test_fb012_op_status_still_classifies_lapsed_row(ops_store):
    """FB-012 regression pin through the public read path: op_status's
    _classify_stale call still terminalizes a lapsed detached row whose
    generation matches (nothing was fenced)."""
    store = ops_store
    cfg = Config(unrestricted=True)
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="fb012-status", tool=OP_TOOL, agent="", vm_name="fb012-vm",
        status=statestore.OP_WORKING,
        created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="fb012-s", heartbeat_at=now - 7200.0,
        send_state="possibly_sent", generation=2, idem_key="fb012s",
    ))
    payload = operations.op_status(cfg, "fb012-status", "")
    assert payload.get("status") == statestore.OP_FAILED and \
        payload.get("error_class") == statestore.OP_UNKNOWN, (
            f"FB-012 regression: op_status no longer classifies a lapsed "
            f"row: {payload!r}"
        )


# ---------------------------------------------------------------------------
# FB-014 — the tasks-route consult refusals leave no durable trace
# ---------------------------------------------------------------------------


def test_fb014_reconciliation_refusal_is_traced(ops_store, audit_sink):
    """FB-014: driving the tasks-route consult to its legacy blank-fingerprint
    reconciliation refusal must leave a durable trace an operator can
    correlate to the original handle — one ops event row naming the handle in
    ref_id and one audit row in the same shape the guard route's audited
    rejections write (ok=false with the envelope's error_class). RED at base:
    the refusal envelope is answered with NO new event rows and 0 audit
    lines."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb014-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb014a", "detach": True}
    _seed(store, cfg, op_id="fb014-legacy", args=args,
          params_hmac="", generation=5, runner="v5-migrated",
          status=statestore.OP_FAILED)

    run = _tasks_runner(cfg, _NoDispatchTool(), threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)
    payload = _payload(result)
    assert payload is not None and \
        payload.get("error_class") == "idempotency_conflict" and \
        payload.get("op_id") == "fb014-legacy", (
            f"FB-014 setup: expected the reconciliation refusal; got {result!r}"
        )

    events = [
        e for e in store.events_after("", 0)
        if e["ref_id"] == "fb014-legacy" and e["kind"] == "op.refused"
    ]
    assert events, (
        "FB-014: the reconciliation refusal left NO durable event row naming "
        "the original handle"
    )
    assert "idempotency_conflict" in events[-1]["data_json"], (
        f"FB-014: the refusal event must carry the envelope's error_class; "
        f"got {events[-1]}"
    )
    rows = [
        r for r in _audit_rows(audit_sink)
        if r.get("tool") == OP_TOOL and r.get("ok") is False
        and r.get("error_class") == "idempotency_conflict"
    ]
    assert rows, (
        "FB-014: the reconciliation refusal wrote no audit row (the guard "
        "route's equivalent is audited through _audited_rejection)"
    )


def test_fb014_residue_fence_failure_refusal_is_traced(
        ops_store, audit_sink, monkeypatch):
    """FB-014: the tasks-route consult's residue-recovery FENCE failure (the
    fail-closed retryable refusal) must leave the same durable trace — event
    row naming the handle, audit row with the refusal's error_class. RED at
    base: zero event rows, zero audit lines."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb014-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb014b", "detach": True}
    now = store.now()
    _seed(store, cfg, op_id="fb014-residue", args=args,
          runner="sync-deadbeef", generation=1,
          created_at=now - 400.0, updated_at=now - 400.0,
          heartbeat_at=now - 400.0)  # lapsed sync- residue, unmarked, gen>0

    def _fence_down(op_id):
        raise RuntimeError("fence transport down")

    monkeypatch.setattr(store, "op_fence", _fence_down)
    run = _tasks_runner(cfg, _NoDispatchTool(), threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)
    payload = _payload(result)
    assert payload is not None and \
        payload.get("op_id") == "fb014-residue" and \
        "fenced" in str(payload.get("error", "")), (
            f"FB-014 setup: expected the residue fence-failure refusal; "
            f"got {result!r}"
        )
    # Fail-closed: the identity is kept exactly as it was.
    kept = store.op_get("fb014-residue")
    assert kept.status == statestore.OP_WORKING and kept.idem_key == "fb014b"

    events = [
        e for e in store.events_after("", 0)
        if e["ref_id"] == "fb014-residue" and e["kind"] == "op.refused"
    ]
    assert events, (
        "FB-014: the residue fence-failure refusal left NO durable event row "
        "naming the original handle"
    )
    rows = [
        r for r in _audit_rows(audit_sink)
        if r.get("tool") == OP_TOOL and r.get("ok") is False
        and r.get("error_class") == "transport"
    ]
    assert rows, (
        "FB-014: the residue fence-failure refusal wrote no audit row"
    )


# ---------------------------------------------------------------------------
# FB-010 — the insert-race re-consult omits the ordinary consult's guards
# ---------------------------------------------------------------------------


def test_fb010_reconsult_refuses_legacy_gen0_winner(
        ops_store, monkeypatch, audit_sink):
    """FB-010 (a): the insert-race winner is a legacy generation-0 identity
    with a MATCHING fingerprint — the re-consult must answer the same AC8
    reconciliation refusal the ordinary consult answers, never attach a live
    task handle to it. RED at base: the re-consult returns a WORKING
    TaskHandleResult for the legacy identity."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb010-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb010a", "detach": True}
    _seed(store, cfg, op_id="fb010-legacy", args=args,
          runner="v6-migrated", generation=0)  # matching fp, gen 0, unmarked

    blind = _BlindFirstConsultStore(store)
    monkeypatch.setattr(operations, "store_for",
                        lambda cfg_, environ=None: blind)
    run = _tasks_runner(cfg, _NoDispatchTool(), threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)

    assert blind.finds >= 2, (
        "FB-010 setup: the call never reached the insert-race re-consult"
    )
    payload = _payload(result)
    assert payload is not None and \
        payload.get("error_class") == "idempotency_conflict" and \
        payload.get("reconciliation") is True and \
        payload.get("op_id") == "fb010-legacy", (
            f"FB-010: the re-consult attached a live handle to a legacy "
            f"generation-0 identity instead of the reconciliation refusal; "
            f"got {result!r}"
        )
    assert store.op_get("fb010-legacy").status == statestore.OP_WORKING, (
        "FB-010: the refusal must not touch the protected legacy identity"
    )


def test_fb010_reconsult_frees_stranded_presend_key(
        ops_store, admission_env, monkeypatch):
    """FB-010 (b): the insert-race winner is a terminal failed/interrupted
    UNMARKED key-holder (the definitive pre-send refusal whose key is excluded
    from TTL expiry and pruning) — the re-consult must free its key through
    the shared stranded-key recovery and proceed fresh, never attach to the
    stranded identity. RED at base: the re-consult answers status=failed with
    the key still held."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb010-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb010b", "detach": True}
    _seed(store, cfg, op_id="fb010-stranded", args=args,
          status=statestore.OP_FAILED, error_class=statestore.OP_INTERRUPTED,
          runner="fb010-r", generation=3)

    blind = _BlindFirstConsultStore(store)
    monkeypatch.setattr(operations, "store_for",
                        lambda cfg_, environ=None: blind)
    tool = _CountingTool()
    run = _tasks_runner(cfg, tool, threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)

    assert blind.finds >= 2, (
        "FB-010 setup: the call never reached the insert-race re-consult"
    )
    stranded = store.op_get("fb010-stranded")
    assert stranded.idem_key == "", (
        f"FB-010: the re-consult left the stranded pre-send refusal's key "
        f"held: {stranded.as_dict()}"
    )
    assert stranded.status == statestore.OP_FAILED and \
        stranded.error_class == statestore.OP_INTERRUPTED, (
            "FB-010: the stranded identity's replay answer must be kept"
        )
    handle_id = getattr(result, "task_id", "")
    assert handle_id and handle_id != "fb010-stranded", (
        f"FB-010: the re-consult attached to the stranded identity instead "
        f"of proceeding fresh; got {result!r}"
    )
    operations.drain_for_tests(timeout_s=10.0)
    assert tool.calls == 1, (
        f"FB-010: the freed key must let the fresh dispatch execute; got "
        f"{tool.calls} dispatches"
    )


def test_fb010_reconsult_reconciles_qualified_residue(
        ops_store, admission_env, monkeypatch):
    """FB-010 (c): the insert-race winner is a dead WORKING sync- unmarked
    lapsed-heartbeat residue (the shape the ordinary consult reconciles
    through the shared residue recovery) — the re-consult must run the same
    recovery: fence, terminalize as the definitive pre-send refusal, free the
    key, proceed fresh. RED at base: the re-consult attaches a live handle to
    the dead residue."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb010-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb010c", "detach": True}
    now = store.now()
    _seed(store, cfg, op_id="fb010-residue", args=args,
          runner="sync-deadbeef", generation=1,
          created_at=now - 400.0, updated_at=now - 400.0,
          heartbeat_at=now - 400.0)

    blind = _BlindFirstConsultStore(store)
    monkeypatch.setattr(operations, "store_for",
                        lambda cfg_, environ=None: blind)
    tool = _CountingTool()
    run = _tasks_runner(cfg, tool, threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)

    assert blind.finds >= 2, (
        "FB-010 setup: the call never reached the insert-race re-consult"
    )
    residue = store.op_get("fb010-residue")
    assert residue.status == statestore.OP_FAILED and \
        residue.error_class == statestore.OP_INTERRUPTED and \
        residue.send_state == "" and residue.idem_key == "", (
            f"FB-010: the re-consult left the dead residue unreconciled: "
            f"{residue.as_dict()}"
        )
    handle_id = getattr(result, "task_id", "")
    assert handle_id and handle_id != "fb010-residue", (
        f"FB-010: the re-consult attached to the dead residue instead of "
        f"proceeding fresh; got {result!r}"
    )
    operations.drain_for_tests(timeout_s=10.0)
    assert tool.calls == 1


def test_fb010_reconsult_answers_residue_fence_failure(
        ops_store, monkeypatch):
    """FB-010 (d): the qualified residue whose fence FAILS — the re-consult
    must answer the shared recovery's fail-closed refusal naming the original
    handle (identity kept), never a live handle. RED at base: the re-consult
    attaches a working handle to the residue."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb010-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb010d", "detach": True}
    now = store.now()
    _seed(store, cfg, op_id="fb010-resfail", args=args,
          runner="sync-deadbeef", generation=1,
          created_at=now - 400.0, updated_at=now - 400.0,
          heartbeat_at=now - 400.0)

    def _fence_down(op_id):
        raise RuntimeError("fence transport down")

    monkeypatch.setattr(store, "op_fence", _fence_down)
    blind = _BlindFirstConsultStore(store)
    monkeypatch.setattr(operations, "store_for",
                        lambda cfg_, environ=None: blind)
    run = _tasks_runner(cfg, _NoDispatchTool(), threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)

    assert blind.finds >= 2, (
        "FB-010 setup: the call never reached the insert-race re-consult"
    )
    payload = _payload(result)
    assert payload is not None and \
        payload.get("op_id") == "fb010-resfail" and \
        "could not be fenced" in str(payload.get("error", "")), (
            f"FB-010: the re-consult answered a live handle instead of the "
            f"fail-closed residue refusal; got {result!r}"
        )
    kept = store.op_get("fb010-resfail")
    assert kept.status == statestore.OP_WORKING and kept.idem_key == "fb010d", (
        f"FB-010: the refusal must keep the identity exactly as it was: "
        f"{kept.as_dict()}"
    )


# ---------------------------------------------------------------------------
# Wave 4 — FB-012's legacy generation-0 fence (the 'Careful' clause's twin)
# ---------------------------------------------------------------------------


def test_fb012_legacy_generation0_write_is_fence_guarded(ops_store):
    """FB-012 wave 4: the classification write's generation predicate is the
    FAIL-CLOSED form (a real 0, never `or None`), so even a LEGACY
    generation-0 row is fenced: a classifiable WORKING possibly_sent row
    whose stored generation IS 0, fenced to generation 1 before the
    classification write, must NOT be terminalized by the read-time path.
    RED under the legacy-generation-0-unguarded mutation (`... or None`);
    GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id="fb012-gen0", tool=OP_TOOL, agent="", vm_name="fb012-vm",
        status=statestore.OP_WORKING,
        created_at=now - 7200.0, updated_at=now - 7200.0,
        runner="fb012-g0", heartbeat_at=now - 7200.0,
        send_state="possibly_sent", generation=0, idem_key="fb012g0",
    ))
    captured = store.op_get("fb012-gen0")  # the read-time path's row (gen 0)
    assert captured is not None
    store.op_fence("fb012-gen0")  # a replacement executor takes authority (0 -> 1)

    operations._classify_stale(store, captured, cfg)
    row = store.op_get("fb012-gen0")
    assert row.status == statestore.OP_WORKING and row.generation == 1, (
        f"FB-012 (wave 4): the read-time classification terminalized a "
        f"FENCED legacy generation-0 row: {row.as_dict()}"
    )


# ---------------------------------------------------------------------------
# Wave 4 — FB-014's four un-pinned call sites (1, 4, 5, 6)
# ---------------------------------------------------------------------------


def _fb014_trace(store, audit_sink, handle: str, error_class: str) -> None:
    """Assert the durable trace FB-014 promises: one op.refused event naming
    the ORIGINAL handle in ref_id (carrying the envelope's error_class) and
    one audit row in the guard route's rejection shape."""
    events = [
        e for e in store.events_after("", 0)
        if e["ref_id"] == handle and e["kind"] == "op.refused"
    ]
    assert events, (
        f"FB-014 (wave 4): the refusal left NO durable op.refused event "
        f"naming the original handle {handle!r}"
    )
    assert error_class in events[-1]["data_json"], events[-1]
    rows = [
        r for r in _audit_rows(audit_sink)
        if r.get("tool") == OP_TOOL and r.get("ok") is False
        and r.get("error_class") == error_class
    ]
    assert rows, (
        f"FB-014 (wave 4): the refusal wrote no audit row (error_class "
        f"{error_class!r})"
    )


def test_fb014_consult_fingerprint_conflict_is_traced(ops_store, audit_sink):
    """FB-014 wave 4, site 1: the ORDINARY tasks consult's fingerprint-
    conflict refusal (idempotency_fingerprint_conflict) must leave the same
    durable trace as sites 2/3 (which the shipped pins cover). RED under the
    site-1-disabled mutation; GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb014-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb014s1", "detach": True}
    _seed(store, cfg, op_id="fb014-s1", args=args,
          params_hmac="a-different-fingerprint")
    run = _tasks_runner(cfg, _NoDispatchTool(), threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)
    payload = _payload(result)
    assert payload is not None and \
        payload.get("error_class") == "idempotency_conflict", (
            f"FB-014 site-1 setup: expected the fingerprint-conflict "
            f"refusal; got {result!r}"
        )
    _fb014_trace(store, audit_sink, "fb014-s1", "idempotency_conflict")


def test_fb014_reconsult_fingerprint_conflict_is_traced(
        ops_store, audit_sink, monkeypatch):
    """FB-014 wave 4, site 4: the INSERT-RACE RE-CONSULT's fingerprint-
    conflict refusal must leave the durable trace. RED under the site-4-
    disabled mutation; GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb014-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb014s4", "detach": True}
    _seed(store, cfg, op_id="fb014-s4", args=args,
          params_hmac="a-different-fingerprint")
    blind = _BlindFirstConsultStore(store)
    monkeypatch.setattr(operations, "store_for",
                        lambda cfg_, environ=None: blind)
    run = _tasks_runner(cfg, _NoDispatchTool(), threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)
    assert blind.finds >= 2, (
        "FB-014 site-4 setup: the call never reached the insert-race "
        "re-consult"
    )
    payload = _payload(result)
    assert payload is not None and \
        payload.get("error_class") == "idempotency_conflict", (
            f"FB-014 site-4 setup: expected the re-consult conflict refusal; "
            f"got {result!r}"
        )
    _fb014_trace(store, audit_sink, "fb014-s4", "idempotency_conflict")


def test_fb014_reconsult_legacy_reconciliation_is_traced(
        ops_store, audit_sink, monkeypatch):
    """FB-014 wave 4, site 5: the INSERT-RACE RE-CONSULT's legacy
    reconciliation refusal must leave the durable trace. RED under the
    site-5-disabled mutation; GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb014-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb014s5", "detach": True}
    _seed(store, cfg, op_id="fb014-s5", args=args,
          runner="v6-migrated", generation=0)
    blind = _BlindFirstConsultStore(store)
    monkeypatch.setattr(operations, "store_for",
                        lambda cfg_, environ=None: blind)
    run = _tasks_runner(cfg, _NoDispatchTool(), threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)
    assert blind.finds >= 2, (
        "FB-014 site-5 setup: the call never reached the insert-race "
        "re-consult"
    )
    payload = _payload(result)
    assert payload is not None and \
        payload.get("reconciliation") is True and \
        payload.get("op_id") == "fb014-s5", (
            f"FB-014 site-5 setup: expected the re-consult reconciliation "
            f"refusal; got {result!r}"
        )
    _fb014_trace(store, audit_sink, "fb014-s5", "idempotency_conflict")


def test_fb014_reconsult_residue_fence_failure_is_traced(
        ops_store, audit_sink, monkeypatch):
    """FB-014 wave 4, site 6: the INSERT-RACE RE-CONSULT's residue-recovery
    FENCE failure (the fail-closed retryable refusal) must leave the durable
    trace. RED under the site-6-disabled mutation; GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    args = {"vm_name": "fb014-vm", "checkpoint_name": "cp",
            "idempotency_key": "fb014s6", "detach": True}
    now = store.now()
    _seed(store, cfg, op_id="fb014-s6", args=args,
          runner="sync-deadbeef", generation=1,
          created_at=now - 400.0, updated_at=now - 400.0,
          heartbeat_at=now - 400.0)  # lapsed sync- residue, unmarked, gen>0

    def _fence_down(op_id):
        raise RuntimeError("fence transport down")

    monkeypatch.setattr(store, "op_fence", _fence_down)
    blind = _BlindFirstConsultStore(store)
    monkeypatch.setattr(operations, "store_for",
                        lambda cfg_, environ=None: blind)
    run = _tasks_runner(cfg, _NoDispatchTool(), threading.BoundedSemaphore(2))
    result = run(OP_TOOL, args)
    assert blind.finds >= 2, (
        "FB-014 site-6 setup: the call never reached the insert-race "
        "re-consult"
    )
    payload = _payload(result)
    assert payload is not None and \
        payload.get("op_id") == "fb014-s6" and \
        "fenced" in str(payload.get("error", "")), (
            f"FB-014 site-6 setup: expected the re-consult residue "
            f"fence-failure refusal; got {result!r}"
        )
    _fb014_trace(store, audit_sink, "fb014-s6", "transport")


# ---------------------------------------------------------------------------
# Wave 5 — FB-011's fail-open FORM: the LEGACY generation-0 executor
# (verification transcript: every shipped pin drives generation=1, where
# `generation or None` still guards; the form only opens at 0/None)
# ---------------------------------------------------------------------------


def _fenced_legacy_row(store, op_id: str) -> None:
    """FB-011 wave 5 fixture — the LEGACY twin of _fenced_marked_row: a row in
    the v6 migration's shape (stored generation IS 0, blank pre-fingerprint
    params_hmac) whose authority a replacement executor has TAKEN (fence
    0 -> 1) and whose NEWER executor committed its send (send_state
    'possibly_sent' at generation 1). The captured executor still holds
    generation 0 — the ONLY value at which the fail-open FORM
    (`generation or None` / `int(generation or 0) or None`) degrades to a
    MISSING predicate (0 -> None = no generation guard) instead of the real
    0 the fail-closed form writes. The row carries idem_key=op_id so every
    pin identifies the attempt by its IDEMPOTENCY KEY (op_find_idem), never
    by the op context."""
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id=op_id, tool=OP_TOOL, agent="", vm_name="fb011-vm",
        status=statestore.OP_WORKING, created_at=now, updated_at=now,
        runner="fb011-legacy", heartbeat_at=now, idem_key=op_id,
        params_hmac="", generation=0,
    ))
    assert store.op_fence(op_id) == 1  # authority moved: 0 -> 1 (legacy row)
    assert store.op_mark_send(op_id, 1) is True  # the newer executor sent
    row = store.op_get(op_id)
    assert row.generation == 1 and row.send_state == "possibly_sent", (
        f"FB-011 fixture premise: {row.as_dict()}"
    )


def test_fb011_legacy_gen0_admission_stopped_cancel_obeys_fence(
        ops_store, admission_env):
    """FB-011 wave 5 (mid-park AdmissionStopped arm, fail-open FORM): a LEGACY
    generation-0 executor whose row was fenced 0 -> 1 (the newer executor
    already committed its send) hits the mid-park AdmissionStopped arm — the
    captured generation must ride the cancelled transition as the REAL 0, so
    the write is refused. RED under the transcript's form mutation at the
    mid-park site (`generation=int(generation or 0)` -> `generation or None`:
    0 or None = None = no predicate — the cancel lands on the newer
    executor's row and clears its send mark); GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_row(store, "fb011e-op")

    stop = threading.Event()
    stop.set()  # admit_sync observes the stop on its first tick -> AdmissionStopped
    _run_body_isolated(
        cfg, "fb011e-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, stop, generation=0,
    )
    row = _row_by_idem(store, "fb011e-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1 \
        and row.send_state == "possibly_sent", (
            f"FB-011 (wave 5): a LEGACY generation-0 executor's mid-park "
            f"AdmissionStopped cancel landed on the newer executor's row "
            f"(the fail-open form): {row.as_dict()}"
        )


def test_fb011_legacy_gen0_grant_window_stop_cancel_obeys_fence(
        ops_store, admission_env, monkeypatch):
    """FB-011 wave 5 (the grant-to-pop-window twin of the AdmissionStopped
    arm, fail-open FORM): the ticket was granted, the stop signalled inside
    the grant-to-pop window, and the legacy generation-0 executor's row was
    fenced 0 -> 1 with the newer executor's send committed — the was_stopped
    cancelled transition must carry the REAL captured 0 and be refused. RED
    under the single-site form mutation at the grant-window site
    (`generation or None`); GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_row(store, "fb011f-op")

    stop = threading.Event()
    ticket = SimpleNamespace(_waiter=None, _ctx_token=None)

    def _fake_admit_sync(*args, **kwargs):
        # Grant, then the cancel lands before the park-window pop observes it.
        stop.set()
        return ticket

    monkeypatch.setattr(admission, "admit_sync", _fake_admit_sync)
    _run_body_isolated(
        cfg, "fb011f-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, stop, generation=0,
    )
    row = _row_by_idem(store, "fb011f-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1 \
        and row.send_state == "possibly_sent", (
            f"FB-011 (wave 5): the grant-to-pop-window stop cancel of a "
            f"LEGACY generation-0 executor landed on the newer executor's "
            f"row (the fail-open form): {row.as_dict()}"
        )


def test_fb011_legacy_gen0_send_gate_busy_arm_obeys_fence(
        ops_store, admission_env, monkeypatch):
    """FB-011 wave 5 (send-gate busy arm, fail-open FORM — the transition AND
    its op_release_idem): a LEGACY generation-0 executor on a row fenced
    0 -> 1 whose newer executor committed its send fails the send-gate
    acquisition — its busy terminal and its idem release must both carry the
    REAL captured 0 and be refused: the write must not land on (nor clear the
    send mark of) the newer executor's row, and the release must not free the
    newer row's idempotency slot. RED under the single-site form mutation at
    EITHER the busy-transition site or the op_release_idem site of this arm
    (`generation or None` — the transition mutation flips the row to the busy
    envelope, the release mutation frees the key while the row stays
    working); GREEN at head. Identified by idempotency key."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_row(store, "fb011g-op")
    monkeypatch.setattr(operations, "_send_gate_acquire",
                        lambda arguments, blocking=True: False)
    _run_body_isolated(
        cfg, "fb011g-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, threading.Event(), generation=0,
    )
    refound = store.op_find_idem("", OP_TOOL, "fb011g-op")
    assert refound is not None and refound.op_id == "fb011g-op", (
        "FB-011 (wave 5): the LEGACY executor's busy-arm idem release freed "
        "the newer executor's idempotency slot (the fail-open form) — the "
        "attempt is no longer identifiable by its idempotency key"
    )
    row = _row_by_idem(store, "fb011g-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1 \
        and row.send_state == "possibly_sent", (
            f"FB-011 (wave 5): a LEGACY generation-0 executor's send-gate "
            f"busy pre-body write landed on the newer executor's row (the "
            f"fail-open form): {row.as_dict()}"
        )


def test_fb011_legacy_gen0_commit_failure_arm_obeys_fence(
        ops_store, admission_env):
    """FB-011 wave 5 (pre-send commit-failure arm, fail-open FORM): the arm a
    fenced executor actually takes — commit_send_intent fails precisely
    because op_mark_send is generation-validated — driven by a LEGACY
    generation-0 executor on a row fenced 0 -> 1 whose newer executor
    committed its send: the failure terminal must carry the REAL captured 0
    and be refused (it must not land on the newer executor's row nor clear
    its send mark). RED under the transcript's form mutation at the
    commit-failure site (`generation or None`); GREEN at head. This is the
    in-repo form of the verification transcript's out-of-repo probe
    (fb011-failopen-ornone-commit-failure), identified by idempotency key."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_row(store, "fb011h-op")
    _run_body_isolated(
        cfg, "fb011h-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, threading.Event(), generation=0,
    )
    row = _row_by_idem(store, "fb011h-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1 \
        and row.send_state == "possibly_sent", (
            f"FB-011 (wave 5): a LEGACY generation-0 executor's "
            f"commit-failure pre-body write landed on the newer executor's "
            f"row and cleared its send mark (the fail-open form): "
            f"{row.as_dict()}"
        )


def test_fb011_legacy_gen0_admission_refusal_obeys_fence(
        ops_store, admission_env, monkeypatch):
    """FB-011 wave 5 (the _admission_refusal arm — previously covered by NO
    pin — its busy transition AND its op_release_idem, fail-open FORM): a
    LEGACY generation-0 executor on a row fenced 0 -> 1 whose newer executor
    committed its send is refused by the admission park — the runner-side
    _admission_refusal terminal and its idem release must both carry the REAL
    captured 0 and be refused: the busy terminal must not land on the newer
    executor's row, and the release must not free its idempotency slot. RED
    under the transcript's form mutation at EITHER _admission_refusal site
    (`int(generation or 0)` -> `int(generation or 0) or None` — the transition
    mutation flips the row to the busy envelope, the op_release_idem
    mutation frees the key while the row stays working); GREEN at head. This
    is the in-repo form of the transcript's out-of-repo probe
    (fb011-m5-admission-refusal-failopen-legacy0), identified by idempotency
    key."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_row(store, "fb011i-op")

    def _busy_park(*args, **kwargs):
        raise admission.AdmissionBusy(250.0)

    monkeypatch.setattr(admission, "admit_sync", _busy_park)
    _run_body_isolated(
        cfg, "fb011i-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, threading.Event(), generation=0,
    )
    refound = store.op_find_idem("", OP_TOOL, "fb011i-op")
    assert refound is not None and refound.op_id == "fb011i-op", (
        "FB-011 (wave 5): the LEGACY executor's _admission_refusal idem "
        "release freed the newer executor's idempotency slot (the fail-open "
        "form) — the attempt is no longer identifiable by its idempotency key"
    )
    row = _row_by_idem(store, "fb011i-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1 \
        and row.send_state == "possibly_sent", (
            f"FB-011 (wave 5): a LEGACY generation-0 executor's "
            f"_admission_refusal busy terminal landed on the newer "
            f"executor's row (the fail-open form): {row.as_dict()}"
        )


class _Wave5BaseException(BaseException):
    """FB-011 wave 5: a BaseException that is NOT an Exception, so the commit
    window's `except Exception` arm does not take it and the BaseException
    reconcile arm does."""


def _fenced_legacy_unmarked_row(store, op_id: str) -> None:
    """FB-011 wave 5 fixture: the UNMARKED twin of _fenced_legacy_row — a
    legacy generation-0 row whose authority a replacement executor has taken
    (fence 0 -> 1) but whose send mark is EMPTY (nothing was dispatched).
    The BaseException reconcile arm reconciles UNMARKED rows only (a marked
    row keeps its protected unknown identity and is left alone), so this is
    the only shape that reaches its transition."""
    now = store.now()
    store.op_insert(statestore.OpRow(
        op_id=op_id, tool=OP_TOOL, agent="", vm_name="fb011-vm",
        status=statestore.OP_WORKING, created_at=now, updated_at=now,
        runner="fb011-legacy-u", heartbeat_at=now, idem_key=op_id,
        params_hmac="", generation=0,
    ))
    assert store.op_fence(op_id) == 1  # authority moved: 0 -> 1 (legacy row)
    row = store.op_get(op_id)
    assert row.generation == 1 and row.send_state == "", (
        f"FB-011 wave 5 fixture premise: {row.as_dict()}"
    )


def test_fb011_legacy_gen0_baseexception_reconcile_arm_obeys_fence(
        ops_store, admission_env, monkeypatch):
    """FB-011 wave 5 (the BaseException reconcile arm, fail-open FORM): a
    BaseException escaping the pre-send commit window reaches the reconcile
    arm, which terminalizes the UNMARKED row as a definitive pre-send
    refusal. A LEGACY generation-0 executor whose row was fenced 0 -> 1 must
    NOT be able to terminalize the newer executor's row: the reconcile core
    must receive the captured generation as the REAL 0 (the fail-closed
    form), so its generation-validated transition is refused. RED under the
    single-site form mutation at the reconcile call site
    (`int(generation or 0)` -> `generation or None`: 0 or None = None = no
    predicate, and the reconcile lands on the newer executor's row); GREEN
    at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_unmarked_row(store, "fb011j-op")

    def _boom(_cfg):
        raise _Wave5BaseException(
            "interrupted inside the pre-send commit window")

    monkeypatch.setattr(operations, "commit_send_intent", _boom)
    # The outer BaseException handler CLASSIFIES the interruption (it does
    # not re-raise it), so the observable is the ROW, not the escape.
    _run_body_isolated(
        cfg, "fb011j-op", OP_TOOL, _NoDispatchTool(),
        {"vm_name": "fb011-vm"}, "", store, threading.Event(),
        generation=0,
    )
    row = _row_by_idem(store, "fb011j-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1, (
        f"FB-011 (wave 5): a LEGACY generation-0 executor's BaseException "
        f"reconcile terminalized the newer executor's row (the fail-open "
        f"form): {row.as_dict()}"
    )


# ---------------------------------------------------------------------------
# Wave 6 — the INLINE route's pre-body writes (the head-bound mutation
# transcript reported them still carrying the pre-PR fail-open form; they are
# the inline twins of the runner sites waves 4/5 already converted)
# ---------------------------------------------------------------------------


def _inline_ctx(cfg, op_id: str, generation: int = 0) -> dict:
    """The inline route's op-context shape, carrying the CAPTURED generation
    of the executor that owns the attempt (0 = the legacy shape)."""
    return {"cfg": cfg, "op_id": op_id, "agent": "", "generation": generation}


def test_fb011_legacy_gen0_inline_fail_inline_obeys_fence(ops_store):
    """FB-011 wave 6 (the inline failure arm, fail-open FORM): the inline
    route's failure arm is a PRE-BODY write whenever the row is unmarked
    (pre_body_terminal = not post_send), so a LEGACY generation-0 executor
    whose row was fenced 0 -> 1 must NOT be able to terminalize the newer
    executor's row. RED under the single-site form mutation at the inline
    site (`int(op_ctx.get("generation") or 0) or None` -> the fail-open
    `or None` dropped: the write lands); GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_unmarked_row(store, "fb011k-op")
    operations.fail_inline(_inline_ctx(cfg, "fb011k-op"),
                           RuntimeError("interrupted before the send commit"))
    row = _row_by_idem(store, "fb011k-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1, (
        f"FB-011 (wave 6): the INLINE failure arm of a LEGACY generation-0 "
        f"executor terminalized the newer executor's row (the fail-open "
        f"form): {row.as_dict()}"
    )


def test_fb011_legacy_gen0_inline_reconcile_obeys_fence(ops_store):
    """FB-011 wave 6 (the inline reconcile wrapper, fail-open FORM): the
    inline twin of the runner's BaseException reconcile arm — the inline
    reconcile terminalizes an UNMARKED row as a definitive pre-send
    refusal, so it must carry the captured generation as the REAL 0 and be
    refused. RED under the single-site form mutation at the inline site;
    GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_unmarked_row(store, "fb011l-op")
    operations.reconcile_interrupted_commit(
        _inline_ctx(cfg, "fb011l-op"),
        _Wave5BaseException("interrupted inside the pre-send commit window"),
    )
    row = _row_by_idem(store, "fb011l-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1, (
        f"FB-011 (wave 6): the INLINE reconcile of a LEGACY generation-0 "
        f"executor terminalized the newer executor's row (the fail-open "
        f"form): {row.as_dict()}"
    )


def test_fb011_legacy_gen0_inline_busy_idem_release_obeys_fence(ops_store):
    """FB-011 wave 6 (the inline busy idempotency release, fail-open FORM):
    the inline twin of the runner's send-gate busy idem release — a LEGACY
    generation-0 executor must NOT free the newer executor's idempotency
    slot (a same-key retry would then dispatch a second time). RED under the
    single-site form mutation at the inline site; GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_unmarked_row(store, "fb011m-op")
    operations.release_busy_idem(_inline_ctx(cfg, "fb011m-op"))
    refound = store.op_find_idem("", OP_TOOL, "fb011m-op")
    assert refound is not None and refound.op_id == "fb011m-op", (
        f"FB-011 (wave 6): the INLINE busy idempotency release of a LEGACY "
        f"generation-0 executor freed the newer executor's idempotency slot "
        f"(the fail-open form) — the attempt is no longer identifiable by "
        f"its idempotency key: {refound!r}"
    )


def test_fb011_legacy_gen0_inline_busy_terminal_obeys_fence(ops_store):
    """FB-011 wave 6 (the inline busy terminal, fail-open FORM): the inline
    twin of the runner's send-gate busy transition — a provably pre-body
    terminal that CLEARS the send mark, so a LEGACY generation-0 executor
    must not land it on the newer executor's row. RED under the single-site
    form mutation at the inline site; GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_unmarked_row(store, "fb011n-op")
    operations.busy_inline(_inline_ctx(cfg, "fb011n-op"), OP_TOOL)
    row = _row_by_idem(store, "fb011n-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1, (
        f"FB-011 (wave 6): the INLINE busy terminal of a LEGACY "
        f"generation-0 executor landed on the newer executor's row and "
        f"cleared its send mark (the fail-open form): {row.as_dict()}"
    )


# ---------------------------------------------------------------------------
# Wave 7 — a REFUSED transition must not emit a terminal event (the
# verification reviewer's finding against the wave-6 head)
# ---------------------------------------------------------------------------


def _failed_events(store, op_id: str) -> list:
    return [e for e in store.events_after("", 0)
            if e["ref_id"] == op_id and e["kind"] == "op.failed"]


def test_fb011_fenced_inline_reconcile_emits_no_terminal_event(ops_store):
    """FB-011 wave 7 (the shared reconciliation core): a LEGACY
    generation-0 executor's inline reconcile is REFUSED by the generation
    fence (the wave-6 change) — and a refused transition must NOT publish a
    terminal event: the event would otherwise report a failure against the
    newer executor's still-working handle. RED under the single-site
    mutation (the unconditional emit); GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_unmarked_row(store, "fb011o-op")
    operations.reconcile_interrupted_commit(
        _inline_ctx(cfg, "fb011o-op"),
        _Wave5BaseException("interrupted inside the pre-send commit window"),
    )
    row = _row_by_idem(store, "fb011o-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1, (
        f"FB-011 (wave 7): the inline reconcile terminalized the newer "
        f"executor's row: {row.as_dict()}"
    )
    assert not _failed_events(store, "fb011o-op"), (
        f"FB-011 (wave 7): the REFUSED inline reconcile still published a "
        f"terminal event against the newer executor's working handle: "
        f"{_failed_events(store, 'fb011o-op')!r}"
    )


def test_fb011_fenced_inline_fail_inline_emits_no_terminal_event(ops_store):
    """FB-011 wave 7 (the inline failure arm): a LEGACY generation-0
    executor's inline failure arm is REFUSED by the generation fence, and
    must not publish a terminal event against the newer executor's
    still-working handle. RED under the single-site mutation (the
    unconditional emit); GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_unmarked_row(store, "fb011p-op")
    operations.fail_inline(_inline_ctx(cfg, "fb011p-op"),
                           RuntimeError("interrupted before the send commit"))
    row = _row_by_idem(store, "fb011p-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1, (
        f"FB-011 (wave 7): the inline failure arm terminalized the newer "
        f"executor's row: {row.as_dict()}"
    )
    assert not _failed_events(store, "fb011p-op"), (
        f"FB-011 (wave 7): the REFUSED inline failure arm still published a "
        f"terminal event against the newer executor's working handle: "
        f"{_failed_events(store, 'fb011p-op')!r}"
    )


def test_fb011_fenced_inline_busy_emits_no_terminal_event(ops_store):
    """FB-011 wave 7 (the inline busy terminal): a LEGACY generation-0
    executor's inline busy terminal is REFUSED by the generation fence, and
    must not publish a terminal event against the newer executor's
    still-working handle. RED under the single-site mutation (the
    unconditional emit); GREEN at head."""
    store = ops_store
    cfg = Config(unrestricted=True)
    _fenced_legacy_unmarked_row(store, "fb011q-op")
    operations.busy_inline(_inline_ctx(cfg, "fb011q-op"), OP_TOOL)
    row = _row_by_idem(store, "fb011q-op")
    assert row.status == statestore.OP_WORKING and row.generation == 1, (
        f"FB-011 (wave 7): the inline busy terminal terminalized the newer "
        f"executor's row: {row.as_dict()}"
    )
    assert not _failed_events(store, "fb011q-op"), (
        f"FB-011 (wave 7): the REFUSED inline busy terminal still published "
        f"a terminal event against the newer executor's working handle: "
        f"{_failed_events(store, 'fb011q-op')!r}"
    )
