"""Per-VM scoped read/write locks with bounded waits and holder metadata.

When the server dispatches tool calls concurrently WITHIN one process (an
SDK- or config-dependent property — current sync tools mostly run inline on
the event loop), a checkpoint restore racing a guest execution on the same
VM is exactly the kind of interference this prevents; the lock is the
arbitration point for that in-process concurrency whenever it occurs. The
lock covers ONE process only: it is a module-dict entry, so two separately
spawned `hyperv-mcp` servers never exclude each other — which is why the
default deployment proxies every client to the ONE shared controller (see
stdio_proxy / README "Shared controller"), putting every agent's calls into
this lock's process. Within that process the path applies across agents;
observable cross-agent VMBusy lands once the controller stops serializing
sync tool calls (FND-01, Workstream C PR 3 / issue #16) — until then a
second agent's call queues behind the first instead of fast-failing.

Each VM key maps to a writer-preferring read/write lock (issue #14,
FND-02/ENH-02): read-scope legs (guest probes, job status/output, file
reads) run concurrently with each other; write-scope legs (VM power,
checkpoints, media, firmware) exclude everything; a waiting writer is
preferred over newly arriving readers so polling readers can never starve
`stop_vm`/`checkpoint_restore` out indefinitely. A conflicting acquire
waits up to a bounded window (`wait_s`, defaulting to
`Config.vm_lock_wait_s`, 0 = fail fast) and then raises `VMBusy` carrying
holder metadata (tool, mode, since, held_ms) so an agent can tell a 2 s
screenshot input from a 15 min restore. Re-entry from the holding thread
fails fast (deadlock guard) and never waits.

Locks are keyed by the case-folded VM GUID (the identity resolved by
vmident.resolve, stable across renames). The key is an opaque string;
vm_create locks on the not-yet-existing VM's name, which the
duplicate-name guard keeps unique. Console input uses a second key
`(vm_id, "console")` so two agents cannot interleave keystrokes while
guest work on the VM key proceeds. Known residual: between `New-VM`
committing inside vm_create's script and that script finishing, the new
VM is GUID-resolvable while the create still holds only the name key, so
a concurrent GUID-keyed operation can overlap the (sub-second,
functionally complete) creation tail. Closing that window requires the
creation script to hand back the GUID mid-lock, which a single script
cannot do.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

#: Tool name of the enclosing `auditlog.operation`, set/reset by its
#: __enter__/__exit__ so a VMBusy raised anywhere inside a tool call can
#: name the holding tool without threading it through every signature.
_current_tool: ContextVar[str | None] = ContextVar("hyperv_mcp_current_tool", default=None)


def current_tool() -> str | None:
    """The audit-log tool name of the running operation, if any."""
    return _current_tool.get()


class VMBusy(RuntimeError):
    """Raised when a conflicting operation holds the VM lock.

    `holder` (when attached) is a dict {"tool", "mode", "since", "held_ms"}
    describing the operation that held the lock at failure time; it never
    contains command text, file content, or credentials.
    """

    def __init__(self, message: str, holder: dict | None = None):
        super().__init__(message)
        self.holder = holder


#: Server default bounded wait; 0 restores the pre-#14 fail-fast. Re-set
#: from Config.vm_lock_wait_s at server startup (set_default_wait_s); the
#: import-time value keeps embedders and unit tests bounded with no wiring.
_DEFAULT_WAIT_S = 30.0
_MAX_WAIT_S = 600.0


def set_default_wait_s(seconds: float) -> None:
    """Set the process-wide default bounded-wait window (0..600 seconds)."""
    global _DEFAULT_WAIT_S
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool):
        raise ValueError("vm_lock wait default must be a number in 0..600")
    if not 0 <= float(seconds) <= _MAX_WAIT_S:
        raise ValueError(f"vm_lock wait default must be in 0..{_MAX_WAIT_S:g}")
    _DEFAULT_WAIT_S = float(seconds)


def _holder_dict(mode: str, since: float) -> dict:
    return {
        "tool": current_tool() or "unknown",
        "mode": mode,
        "since": since,
        "held_ms": int((time.time() - since) * 1000),
    }


def _busy(key: str, holder: dict) -> VMBusy:
    return VMBusy(
        f"another operation is already running on VM '{key}': "
        f"tool={holder['tool']} mode={holder['mode']} held_ms={holder['held_ms']}; "
        "wait for it to finish before starting a conflicting one",
        holder=holder,
    )


class _RWLock:
    """Writer-preferring read/write lock with bounded waits.

    Readers register per thread id with their holder info; one writer holds
    at a time; `_waiting_writers` gives arriving readers no-admission while
    a writer queues (writer preference, AC4). All state transitions happen
    inside the Condition's critical section; release and waiter-timeout both
    notify_all so queued parties re-evaluate (a timing-out writer decrements
    its counter and notifies in the same section, so a reader queued behind
    it is admitted rather than falsely rejected).
    """

    def __init__(self) -> None:
        self._cv = threading.Condition()
        self._readers: dict[int, dict] = {}  # tid -> holder dict
        self._writer: tuple[int, dict] | None = None  # (tid, holder dict)
        self._waiting_writers = 0

    def _current_holder(self) -> dict | None:
        """The holder record to report on failure: the writer, else the
        longest-held reader."""
        if self._writer is not None:
            return self._writer[1]
        if self._readers:
            return min(self._readers.values(), key=lambda h: h["since"])
        return None

    def acquire(self, key: str, mode: str, wait_s: float | None, tid: int) -> None:
        # Re-entry from the holding thread fails fast: this lock is not
        # reentrant, and waiting would deadlock (AC8 keeps the phrase).
        with self._cv:
            if (self._writer is not None and self._writer[0] == tid) or tid in self._readers:
                holder = self._current_holder()
                raise _busy(key, holder or _holder_dict(mode, time.time()))

            deadline = None if wait_s is None else time.monotonic() + max(0.0, wait_s)
            if mode == "write":
                self._waiting_writers += 1
                try:
                    while self._writer is not None or self._readers:
                        if not self._wait_tick(deadline):
                            holder = self._current_holder()
                            raise _busy(key, holder or _holder_dict(mode, time.time()))
                    self._writer = (tid, _holder_dict(mode, time.time()))
                finally:
                    self._waiting_writers -= 1
                    # A timeout (or error) here must wake readers queued
                    # behind this writer; on success the new writer blocks
                    # them anyway, so an extra notify is harmless.
                    self._cv.notify_all()
            else:
                while self._writer is not None or self._waiting_writers > 0:
                    if not self._wait_tick(deadline):
                        holder = self._current_holder()
                        raise _busy(key, holder or _holder_dict(mode, time.time()))
                self._readers[tid] = _holder_dict(mode, time.time())

    def _wait_tick(self, deadline: float | None) -> bool:
        """Wait for the CV until the predicate may have changed; return
        False when the bounded window has expired. Caller holds the CV."""
        if deadline is None:
            self._cv.wait()
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self._cv.wait(remaining)
        return True

    def release(self, tid: int) -> None:
        with self._cv:
            if self._writer is not None and self._writer[0] == tid:
                self._writer = None
            else:
                self._readers.pop(tid, None)
            self._cv.notify_all()

    def idle(self) -> bool:
        """No holders and no waiters — safe to evict from the registry."""
        with self._cv:
            return (
                self._writer is None
                and not self._readers
                and self._waiting_writers == 0
            )


_locks: dict[str, _RWLock] = {}
_pins: dict[str, int] = {}  # in-flight fetches; never evict a pinned key
_registry_lock = threading.Lock()
_MAX_LOCKS = 4096  # SOFT bound: held locks are never evicted, so a fully-held
# registry can exceed it — mutual exclusion is never weakened for the bound.


def _normalize_key(key: object) -> str:
    """Case-folded lock key; tuple keys (console dual-key) join with '|'."""
    if isinstance(key, tuple):
        return "|".join(str(part).casefold() for part in key)
    return str(key).casefold()


def _acquire(key: object, mode: str, wait_s: float | None) -> _RWLock:
    """Fetch-or-create the key's RW lock and acquire it.

    The registry mutation happens atomically under _registry_lock WITH an
    in-flight pin, so eviction (which also runs under _registry_lock) can
    never remove a lock between this fetch and its acquire — the exact race
    the pre-#14 code closed for the plain Lock (round-2 review finding,
    issue #14 plan BLOCKER-1). The (possibly waiting) acquire itself runs
    OUTSIDE the registry lock: holding it across a bounded wait would
    serialize every VM in the server. Pins are dropped once the acquire
    resolves (held locks are then protected by idle(); failures simply
    release the fetch).
    """
    key = _normalize_key(key)
    with _registry_lock:
        lock = _locks.get(key)
        if lock is None:
            if len(_locks) >= _MAX_LOCKS:
                # Bound against unbounded growth from client-supplied names:
                # evict entries that are idle AND not being fetched. Held or
                # waited-on locks are never evicted, so mutual exclusion is
                # never weakened.
                for stale in [
                    k for k, v in _locks.items() if v.idle() and _pins.get(k, 0) == 0
                ]:
                    del _locks[stale]
            lock = _RWLock()
            _locks[key] = lock
        _pins[key] = _pins.get(key, 0) + 1
    try:
        lock.acquire(key, mode, wait_s, threading.get_ident())
    finally:
        with _registry_lock:
            remaining = _pins.get(key, 0) - 1
            if remaining <= 0:
                _pins.pop(key, None)
            else:
                _pins[key] = remaining
    return lock


@contextmanager
def vm_lock(key: object, mode: str = "write", wait_s: float | None = None) -> Iterator[None]:
    """Hold the VM `key` in `mode` ("read" or "write") for the block.

    `wait_s=None` uses the process default (Config.vm_lock_wait_s, 30);
    `wait_s=0` fails fast; expiry raises VMBusy with holder metadata.
    """
    if mode not in ("read", "write"):
        raise ValueError(f"vm_lock mode must be 'read' or 'write', not {mode!r}")
    if wait_s is None:
        wait_s = _DEFAULT_WAIT_S
    lock = _acquire(key, mode, wait_s)
    try:
        yield
    finally:
        lock.release(threading.get_ident())
