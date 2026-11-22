"""PR #166 review-fix pin for the unbounded per-VM recovery-lock wait
(FB-013, trace 157-158-durable-identity-repair-outcomes).

``SessionPool._epoch_fresh_bind`` took the per-VM recovery lock with a
plain unbounded ``with lock:`` BEFORE ``acquire()``'s bounded wait loop, so
a dance holder stuck inside its critical section (a spawn that never
returns, an epoch clear that never answers) hung every LATER same-VM
borrower indefinitely — the caller's ``wait_s`` budget was never consulted
(the probe's reproduction: a 0.5s-budget borrower still running 3s in).
The fix bounds the recovery-lock acquisition by the caller's own wait
budget and answers with the pool's normal busy refusal (SessionBusy), so a
stuck holder refuses later borrows within their budget instead of wedging
the key; after the refusal the next borrow may rebind.

Pins (each FAILED against the unfixed code — RED — and passes after it):
  test_fb013_stuck_holder_refuses_same_vm_borrow_within_budget (acceptance a
    + the "next borrow may rebind" tail)
  test_fb013_different_vm_borrow_unaffected_by_stuck_holder (acceptance b —
    a guard: the probe already showed a foreign GUID returning in bounds)
  test_fb013_ordinary_dirty_dance_still_works (acceptance c)

What is faked: only the pool's worker factory (the _StubFactory pattern
from test_t157_158_schedules.py / test_pr166_review_fixes_sessions.py) and
the store-backed epoch consults. Every store is closed in teardown
(Windows file-lock teardown hazard) and every pool via close_all.
"""

from __future__ import annotations

import threading
import time

import pytest

from hyperv_mcp import psdsessions, statestore

VM_A = "aaaaaaaa-1111-2222-3333-444444444444"
VM_B = "bbbbbbbb-1111-2222-3333-444444444444"
AGENT = "agent-fb013"

KEY_A = (VM_A, "guest:Administrator", AGENT, None)
KEY_B = (VM_B, "guest:Administrator", AGENT, None)


@pytest.fixture()
def store(tmp_path):
    """A real temp Store backing the epoch consults (the sessions-file
    pattern); ALWAYS closed on teardown (Windows file-lock teardown hazard)."""
    s = statestore.open(str(tmp_path / "pr166-fb013-store.db"))
    yield s
    s.close()


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
    """Worker factory that records every spawn and every close."""

    def __init__(self) -> None:
        self.calls = 0
        self.closed_count = 0

    def __call__(self, key, script, stdin_b64):
        self.calls += 1
        return _StubWorker(self)


class _GatedFactory:
    """Worker factory whose FIRST spawn is the stuck dance holder: it
    signals ``entered``, parks on ``unblock`` — holding the per-VM recovery
    lock the whole while — and, once released, fails the spawn so the
    holder's dance ends in the ordinary SessionEpochDirty failure. Every
    later spawn is a plain stub."""

    def __init__(self) -> None:
        self.calls = 0
        self.closed_count = 0
        self.entered = threading.Event()
        self.unblock = threading.Event()

    def __call__(self, key, script, stdin_b64):
        self.calls += 1
        if self.calls == 1:
            self.entered.set()
            if not self.unblock.wait(timeout=10.0):
                raise RuntimeError("the stuck holder was never unblocked")
            raise RuntimeError("injected stuck-dance spawn failure")
        return _StubWorker(self)


def _pool(store, factory, **kw):
    return psdsessions.SessionPool(
        factory,
        epoch_reader=store.epoch_snapshot,
        epoch_clear=store.epoch_clear_dirty,
        **kw,
    )


def _borrow(pool, tag, results, key, wait_s=0.0):
    try:
        results[tag] = pool.acquire(key, wait_s)
    except BaseException as exc:  # noqa: BLE001 — recorded, asserted below
        results[tag] = exc


# ---------------------------------------------------------------------------
# FB-013 — a stuck dance holder must refuse later same-VM borrows in budget
# ---------------------------------------------------------------------------


def test_fb013_stuck_holder_refuses_same_vm_borrow_within_budget(store):
    """FB-013 acceptance (a): with a dance holder stuck inside the per-VM
    recovery lock's critical section, a later SAME-VM borrower is refused
    within its own wait_s with the pool's normal busy shape (SessionBusy,
    NOT the dirty-epoch disclosure) — never wedged past its budget on the
    lock acquisition. The refusal is transient: once the holder's dance
    ends, the next borrow re-runs the dance and rebinds."""
    store.epoch_bump(VM_A)
    factory = _GatedFactory()
    pool = _pool(store, factory)
    results: dict[str, object] = {}
    t1 = threading.Thread(
        target=_borrow, args=(pool, "t1", results, KEY_A), daemon=True
    )
    t1.start()
    t2: threading.Thread | None = None
    try:
        assert factory.entered.wait(timeout=5.0), (
            "FB-013 premise: the stuck holder never entered its spawn"
        )
        t2 = threading.Thread(
            target=_borrow, args=(pool, "t2", results, KEY_A, 0.5),
            daemon=True,
        )
        started = time.monotonic()
        t2.start()
        t2.join(timeout=3.0)
        elapsed = time.monotonic() - started
        assert not t2.is_alive(), (
            f"FB-013a: the same-VM borrower was still blocked {elapsed:.2f}s "
            f"in on a 0.5s wait budget — the recovery-lock acquisition is "
            f"unbounded"
        )
        refusal = results.get("t2")
        assert isinstance(refusal, psdsessions.SessionBusy), (
            f"FB-013a: the refusal must be the pool's busy/timeout shape; "
            f"got {refusal!r}"
        )
        assert not isinstance(refusal, psdsessions.SessionEpochDirty), (
            "FB-013a: the stuck-lock refusal is a retry-later busy "
            "condition, not the dirty-epoch disclosure"
        )
        assert elapsed < 2.5, (
            f"FB-013a: the refusal must land within the caller's budget "
            f"plus scheduling slack; took {elapsed:.2f}s"
        )
        # The stuck holder must not wedge the key: release it, its dance
        # ends in the injected failure (the epoch stays dirty), and the
        # NEXT borrow re-runs the dance and rebinds.
        factory.unblock.set()
        t1.join(timeout=5.0)
        assert not t1.is_alive(), "FB-013a: the holder thread never ended"
        assert isinstance(results.get("t1"), psdsessions.SessionEpochDirty), (
            "FB-013 premise: the holder's own dance ended in the injected "
            "spawn failure"
        )
        assert store.epoch_snapshot(VM_A) == (1, "dirty"), (
            "FB-013 premise: the failed dance left the epoch dirty"
        )
        rebound = pool.acquire(KEY_A)
        assert isinstance(rebound, _StubWorker) and not rebound.closed, (
            "FB-013a tail: the next borrow must re-run the dance and rebind"
        )
        assert store.epoch_snapshot(VM_A) == (1, "clean"), (
            "FB-013a tail: the rebound dance cleared the dirty epoch"
        )
        assert factory.calls == 2, (
            f"FB-013a tail: exactly one rebound spawn; got {factory.calls}"
        )
        pool.release(rebound)
    finally:
        factory.unblock.set()
        t1.join(timeout=5.0)
        if t2 is not None:
            t2.join(timeout=5.0)
        pool.close_all()


def test_fb013_different_vm_borrow_unaffected_by_stuck_holder(store):
    """FB-013 acceptance (b): the recovery lock is PER VM GUID — while VM A's
    dance holder is stuck, a caller-thread borrower for VM B (its own dirty
    epoch, its own dance on its own lock) returns within its budget. The
    bound must not turn a foreign VM's stuck dance into this caller's
    refusal."""
    store.epoch_bump(VM_A)
    store.epoch_bump(VM_B)
    factory = _GatedFactory()
    pool = _pool(store, factory)
    results: dict[str, object] = {}
    t1 = threading.Thread(
        target=_borrow, args=(pool, "t1", results, KEY_A), daemon=True
    )
    t1.start()
    try:
        assert factory.entered.wait(timeout=5.0), (
            "FB-013 premise: the stuck holder never entered its spawn"
        )
        started = time.monotonic()
        other = pool.acquire(KEY_B, 0.5)
        elapsed = time.monotonic() - started
        assert isinstance(other, _StubWorker), (
            f"FB-013b: VM B's borrow must succeed; got {other!r}"
        )
        assert elapsed < 2.5, (
            f"FB-013b: VM B's borrow queued on VM A's stuck recovery lock "
            f"({elapsed:.2f}s on a 0.5s budget)"
        )
        assert store.epoch_snapshot(VM_B) == (1, "clean"), (
            "FB-013b: VM B's own dance ran to completion"
        )
        pool.release(other)
    finally:
        factory.unblock.set()
        t1.join(timeout=5.0)
        pool.close_all()


def test_fb013_ordinary_dirty_dance_still_works(store):
    """FB-013 acceptance (c): the ordinary dirty-epoch dance (no stuck
    holder) is unchanged — the dirty borrow invalidates, fresh-binds, clears
    the epoch and hands out the fresh worker, and the clean reuse after the
    dance returns the SAME worker."""
    bumped = store.epoch_bump(VM_A)
    factory = _StubFactory()
    pool = _pool(store, factory)
    try:
        danced = pool.acquire(KEY_A)
        assert isinstance(danced, _StubWorker) and not danced.closed, (
            "FB-013c: the ordinary dance must hand out its fresh worker"
        )
        assert store.epoch_snapshot(VM_A) == (bumped, "clean"), (
            "FB-013c: the ordinary dance must clear the dirty epoch"
        )
        pool.release(danced)
        reused = pool.acquire(KEY_A)
        assert reused is danced, (
            "FB-013c: the clean reuse after the dance must return the same "
            "worker"
        )
        assert factory.calls == 1, (
            f"FB-013c: the dance is one spawn; got {factory.calls}"
        )
        pool.release(reused)
    finally:
        pool.close_all()
