"""Per-VM mutual exclusion so conflicting operations never overlap.

FastMCP dispatches tool calls concurrently; a checkpoint restore racing a
guest execution on the same VM is exactly the kind of interference this
prevents. Locks are keyed by case-folded VM name (Hyper-V names are
case-insensitive) and acquired non-blocking: a second conflicting call fails
fast with VMBusy instead of queueing behind an unknown-duration operation.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager


class VMBusy(RuntimeError):
    """Raised when a conflicting operation holds the VM lock."""


_locks: dict[str, threading.Lock] = {}
_registry_lock = threading.Lock()
_MAX_LOCKS = 4096  # SOFT bound: held locks are never evicted, so a fully-held
# registry can exceed it — mutual exclusion is never weakened for the bound.


def _acquire(vm_name: str) -> threading.Lock:
    """Fetch-or-create the lock and acquire it, atomically under the registry
    lock. Doing BOTH under _registry_lock closes the eviction race: a lock
    can never be fetched and then evicted before its acquire (round-2 review
    finding), and eviction can never remove a lock a waiter is about to
    acquire, because waiters cannot exist outside the registry lock."""
    key = vm_name.casefold()
    with _registry_lock:
        lock = _locks.get(key)
        if lock is None:
            if len(_locks) >= _MAX_LOCKS:
                # Bound against unbounded growth from client-supplied names:
                # evict entries that are not currently held. Held locks are
                # never evicted, so mutual exclusion is never weakened.
                for stale in [k for k, v in _locks.items() if not v.locked()]:
                    del _locks[stale]
            lock = threading.Lock()
            _locks[key] = lock
        if not lock.acquire(blocking=False):
            raise VMBusy(
                f"another operation is already running on VM '{vm_name}'; "
                "wait for it to finish before starting a conflicting one"
            )
        return lock


@contextmanager
def vm_lock(vm_name: str) -> Iterator[None]:
    lock = _acquire(vm_name)
    try:
        yield
    finally:
        lock.release()
