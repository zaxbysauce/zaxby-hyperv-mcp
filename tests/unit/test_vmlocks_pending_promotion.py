"""cubic-13 regression pin: the pending-writer record is promoted past a
departed queue head (PR #116 feedback round).

The pre-fix `_RWLock` kept ONE pending-writer record, stamped when the FIRST
writer queued, and only cleared it when the whole queue drained — so once
the queue head was admitted (and especially after it finished), a timed-out
reader could still be told the departed writer's tool and its long-stale
queue-entry timestamp. The fix carries a (tid, record) FIFO: every queued
writer owns its entry, the reported holder is the CURRENT head, and each
waiter's entry is dropped at admission / timeout / cancellation.

Deterministic: drives `_RWLock` directly (helper threads only queue behind
events; the main thread holds and releases the lock). The whole choreography
runs inside try/finally so an assertion failure releases the lock and joins
the helper threads instead of parking them for their 30 s waits.

RED/GREEN lifecycle: RED against the pre-fix single-record field (the
admission assertion fails — the departed head's entry survived), GREEN with
the FIFO promotion.
"""

from __future__ import annotations

import threading

from hyperv_mcp import vmlocks


def test_pending_records_promote_past_departed_queue_head():
    """After the queue-head writer is admitted, its entry must be dropped:
    the pending records must name only CURRENTLY queued writers (cubic-13)."""
    lock = vmlocks._RWLock()
    admitted = threading.Event()
    release = threading.Event()
    b_queued = threading.Event()
    c_queued = threading.Event()

    results: dict[str, object] = {}

    def writer_b():
        b_queued.set()
        lock.acquire("vm", "write", wait_s=30, tid=threading.get_ident())
        admitted.set()
        release.wait(timeout=30)
        lock.release(threading.get_ident())

    def writer_c():
        c_queued.set()
        lock.acquire("vm", "write", wait_s=30, tid=threading.get_ident())
        results["c_acquired"] = True
        lock.release(threading.get_ident())

    # The main thread holds the write lock so B and C must queue.
    lock.acquire("vm", "write", wait_s=0, tid=threading.get_ident())
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

        # Release the main holder: B (queue head) is admitted.
        lock.release(threading.get_ident())
        assert admitted.wait(timeout=10)
        pending_after_admission = [e[0] for e in lock._pending_writer_records]
        assert len(pending_after_admission) == 1, (
            "the admitted queue head's entry must be dropped at admission "
            f"(pre-fix behavior kept the departed record); got "
            f"{pending_after_admission}"
        )
        assert results.get("c_acquired") is None, "C must still be queued"
    finally:
        # Failure safety: free the helpers so no thread parks for 30 s.
        release.set()
        try:
            lock.release(threading.get_ident())
        except Exception:
            pass  # already released on the success path
    # B finishes; C is admitted and then releases itself.
    release.set()
    tb.join(timeout=10)
    tc.join(timeout=10)
    assert results.get("c_acquired") is True
    assert not lock._pending_writer_records, (
        "an empty queue must leave no pending records"
    )
