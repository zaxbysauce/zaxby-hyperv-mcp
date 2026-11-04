"""cubic-13 regression pin: the pending-writer record is promoted past a
departed queue head (PR #116 feedback round).

The pre-fix `_RWLock` kept ONE pending-writer record, stamped when the FIRST
writer queued, and only cleared it when the whole queue drained — so once
the queue head was admitted (and especially after it finished), a timed-out
reader could still be told the departed writer's tool and its long-stale
queue-entry timestamp. The fix carries a (tid, record) FIFO: every queued
writer owns its entry, the reported holder is the CURRENT head, and each
waiter's entry is dropped at admission / timeout / cancellation.

Deterministic: drives `_RWLock` directly. Helper threads queue behind
events and HOLD the lock until individually released, so the post-admission
assertion observes a stable state (the admitted writer holds, the other is
still queued with exactly one entry). The whole choreography runs inside
try/finally so an assertion failure releases the lock and joins the helper
threads instead of parking them for their 30 s waits.

RED/GREEN lifecycle: RED against the pre-fix single-record field (the
admission assertion fails — the departed head's entry survived or the
remaining count is wrong), GREEN with the FIFO promotion.
"""

from __future__ import annotations

import threading

from hyperv_mcp import vmlocks


def test_pending_records_promote_past_departed_queue_head():
    """When the queue-head writer is admitted, its entry must be dropped and
    the remaining writer's own entry must survive (cubic-13)."""
    lock = vmlocks._RWLock()
    b_done = threading.Event()
    c_done = threading.Event()
    b_queued = threading.Event()
    c_queued = threading.Event()
    release_b = threading.Event()
    release_c = threading.Event()
    tids: dict[str, int] = {}

    def writer_b():
        tids["b"] = threading.get_ident()
        b_queued.set()
        lock.acquire("vm", "write", wait_s=30, tid=tids["b"])
        b_done.set()
        release_b.wait(timeout=30)
        lock.release(tids["b"])

    def writer_c():
        tids["c"] = threading.get_ident()
        c_queued.set()
        lock.acquire("vm", "write", wait_s=30, tid=tids["c"])
        c_done.set()
        release_c.wait(timeout=30)
        lock.release(tids["c"])

    # The main thread holds the write lock so B and C must queue.
    main_tid = threading.get_ident()
    lock.acquire("vm", "write", wait_s=0, tid=main_tid)
    released_main = False
    tb = threading.Thread(target=writer_b)
    tc = threading.Thread(target=writer_c)
    try:
        tb.start()
        assert b_queued.wait(timeout=10)
        tc.start()
        assert c_queued.wait(timeout=10)
        # Small settle window so both pending entries are registered.
        for _ in range(20):
            if len(lock._pending_writer_records) == 2:
                break
            threading.Event().wait(0.05)
        pending_after_queue = [entry[0] for entry in lock._pending_writer_records]
        assert len(pending_after_queue) == 2, (
            f"both queued writers must carry entries; got {pending_after_queue}"
        )

        # Release the main holder. Either B or C is admitted first (notify_all
        # makes no order guarantee); the admitted one drops ITS OWN entry and
        # HOLDS the lock (its done-event fires), the other stays queued.
        lock.release(main_tid)
        released_main = True
        assert b_done.wait(timeout=10) or c_done.wait(timeout=10), (
            "at least one queued writer must be admitted after the release"
        )
        pending_after_admission = [e[0] for e in lock._pending_writer_records]
        assert len(pending_after_admission) == 1, (
            "exactly one queued writer's entry must survive (the other was "
            f"admitted and dropped its own); got {pending_after_admission}"
        )
        # The surviving entry belongs to the writer still queued (not done).
        if b_done.is_set():
            assert pending_after_admission[0] == tids["c"], (
                "the surviving entry must be C's (B was admitted and departed)"
            )
        else:
            assert pending_after_admission[0] == tids["b"], (
                "the surviving entry must be B's (C was admitted and departed)"
            )
    finally:
        # Failure safety: free everything so no thread parks for 30 s.
        release_b.set()
        release_c.set()
        if released_main:
            try:
                lock.release(main_tid)
            except Exception:
                pass  # already released on the success path
    release_b.set()
    release_c.set()
    tb.join(timeout=10)
    tc.join(timeout=10)
    assert b_done.is_set() and c_done.is_set()
    assert not lock._pending_writer_records, (
        "an empty queue must leave no pending records"
    )
