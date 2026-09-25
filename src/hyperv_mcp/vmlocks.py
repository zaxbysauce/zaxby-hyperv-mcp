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


def _lock_for(vm_name: str) -> threading.Lock:
    key = vm_name.casefold()
    with _registry_lock:
        lock = _locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _locks[key] = lock
        return lock


@contextmanager
def vm_lock(vm_name: str) -> Iterator[None]:
    lock = _lock_for(vm_name)
    if not lock.acquire(blocking=False):
        raise VMBusy(
            f"another operation is already running on VM '{vm_name}'; "
            "wait for it to finish before starting a conflicting one"
        )
    try:
        yield
    finally:
        lock.release()
