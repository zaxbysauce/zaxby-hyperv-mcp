"""Per-VM scoped read/write locks with bounded waits and holder metadata.

The server dispatches tool calls concurrently WITHIN one process: mcp 2.x
runs every sync tool body on a worker thread, so a checkpoint restore racing
a guest execution on the same VM is exactly the kind of interference this
lock prevents; the lock is the arbitration point for that concurrency. The
lock covers ONE process only: it is a module-dict entry, so two separately
spawned `hyperv-mcp` servers never exclude each other — which is why the
default deployment proxies every client to the ONE shared controller (see
stdio_proxy / README "Shared controller"), putting every agent's calls into
this lock's process. Within that process the path applies across agents;
cross-agent VMBusy is observable and fast-fails (with holder metadata)
instead of queueing — the serialization that used to hide it ended with
FND-01's fix (Workstream C PR 3 / issue #16).

Each VM key maps to a writer-preferring read/write lock (issue #14,
FND-02/ENH-02): read-scope legs — guest probes, job start/status/output/
stop, guest script execution, guest file transfers (incl. put/get),
evidence capture — run concurrently with each other; write-scope legs
(VM power, checkpoints, media, firmware, repair apply) exclude
everything; a waiting writer is preferred over newly arriving readers so
polling readers can never starve `stop_vm`/`checkpoint_restore` out
indefinitely. A conflicting acquire
waits up to a bounded window (`wait_s`, defaulting to
`Config.vm_lock_wait_s`, 0 = fail fast) and then raises `VMBusy` carrying
holder metadata (tool, mode, since, held_ms) so an agent can tell a 2 s
screenshot input from a 15 min restore. Re-entry from the holding thread
fails fast (deadlock guard) and never waits.

Locks are keyed by the case-folded VM GUID (the identity resolved by
vmident.resolve, stable across renames). A key is an opaque string, or a
tuple for dual-key scopes; the two types live in disjoint registry
namespaces, so no client-supplied name can alias a tuple key. vm_create
locks on the not-yet-existing VM's name, which the duplicate-name guard
keeps unique. Console input takes READ on the VM key plus a WRITE on the
second key `(vm_id, "console")` so two agents cannot interleave
keystrokes while guest work on the VM key proceeds — with one residual on
the by-name PowerShell transport, where issue #18's fold resolves the VM
inside the op script and the console key is therefore the caller-supplied
name: exclusion holds between calls that address the VM the same way, but
not across name-vs-GUID addressing, nor against a write-scope op (which
always resolves first and keys on the GUID). That residual is disclosed in
vmident and tracked in issue #77. Known residual: between `New-VM`
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

import anyio

from . import timing

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

    `waited_ms` is how long the failing waiter was parked on the lock. It rides
    the exception because a return value cannot escape a raise, and a busy
    failure's audit row must report the wait that actually elapsed rather than
    a fabricated zero.
    """

    def __init__(self, message: str, holder: dict | None = None, waited_ms: int = 0):
        super().__init__(message)
        self.holder = holder
        self.waited_ms = waited_ms


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


def _live_holder(holder: dict) -> dict:
    """Copy of a stored holder record with held_ms recomputed at READ time.

    The stored record's held_ms is a birth-time snapshot (~0); the busy
    payload and message must report how long the holder has held the VM
    NOW (issue #14 Verification: "a growing held_ms"). max(0, ...) guards
    against a backward wall-clock step between acquire and failure.
    """
    return {
        **holder,
        "held_ms": max(0, int((time.time() - holder["since"]) * 1000)),
    }


def _display_key(key: object) -> str:
    """Human form of a lock key for error messages: tuples join for
    readability, but they never share a registry namespace with strings."""
    if isinstance(key, tuple):
        return "|".join(str(part) for part in key)
    return str(key)


def _busy(key: object, holder: dict | None, waited_ms: int = 0) -> VMBusy:
    """Build the contention failure, carrying how long the waiter was parked.

    `waited_ms` defaults to 0 and is passed only by callers that actually
    waited. The pre-loop re-entry fast-fail raises before any wait, so it
    genuinely reports 0; both in-loop raises pass the accumulated wait,
    including the `holder is None` branch, which is reached after the bounded
    window expired — that waiter really did sit out the full wait.
    """
    if holder is None:
        # Contention drained between the waiter's wakeup and its expiry:
        # no holder exists, so claim none. Message keeps no tool clause and
        # the envelope carries no holder key (honest absence over a
        # fabricated self-blaming record).
        return VMBusy(
            f"another operation is already running on VM '{_display_key(key)}'; "
            "wait for it to finish before starting a conflicting one",
            holder=None,
            waited_ms=waited_ms,
        )
    return VMBusy(
        f"another operation is already running on VM '{_display_key(key)}': "
        f"tool={holder['tool']} mode={holder['mode']} held_ms={holder['held_ms']}; "
        "wait for it to finish before starting a conflicting one",
        holder=holder,
        waited_ms=waited_ms,
    )


_POLL_SLICE_S = 0.2  # cancellation observation window while parked on the lock


def _check_lock_cancellation() -> None:
    """Observe anyio host-task cancellation from inside a worker thread
    parked on the lock (same contract as pswindows._check_ps_cancellation:
    the cancellation exception is raised only in the worker-thread dispatch
    shape mcp 2.x uses; everywhere else it is a swallowed RuntimeError)."""
    try:
        anyio.from_thread.check_cancelled()
    except RuntimeError:
        pass


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
        # Oldest queued writer's record, so a reader that times out while
        # ONLY a queued writer blocks it can name that writer instead of
        # fabricating a record about itself (feedback PRR-008).
        self._pending_writer: dict | None = None

    def _current_holder(self) -> dict | None:
        """The holder record to report on failure: the writer, else the
        longest-held reader, else the oldest queued writer (a real blocker
        even though not yet admitted), else None (contention drained)."""
        if self._writer is not None:
            return _live_holder(self._writer[1])
        if self._readers:
            return _live_holder(min(self._readers.values(), key=lambda h: h["since"]))
        if self._pending_writer is not None:
            return _live_holder(self._pending_writer)
        return None

    def acquire(self, key: object, mode: str, wait_s: float | None, tid: int) -> int:
        """Acquire in `mode` and return the milliseconds spent parked.

        The wait is accumulated only inside the `while` loops, so an
        uncontended acquire returns exactly 0 rather than the sub-millisecond
        cost of taking the Condition. On the busy path the accumulated value
        rides the `VMBusy` (see `_busy`).
        """
        # Re-entry from the holding thread fails fast: this lock is not
        # reentrant, and waiting would deadlock (AC8 keeps the phrase).
        with self._cv:
            if (self._writer is not None and self._writer[0] == tid) or tid in self._readers:
                raise _busy(key, self._current_holder())

            waited_ms = 0
            deadline = None if wait_s is None else time.monotonic() + max(0.0, wait_s)
            if mode == "write":
                self._waiting_writers += 1
                if self._pending_writer is None:
                    self._pending_writer = _holder_dict(mode, time.time())
                try:
                    while self._writer is not None or self._readers:
                        slice_start = time.monotonic()
                        if not self._wait_tick(deadline):
                            raise _busy(
                                key, self._current_holder(), waited_ms=waited_ms
                            )
                        waited_ms += int((time.monotonic() - slice_start) * 1000)
                    self._writer = (tid, _holder_dict(mode, time.time()))
                finally:
                    self._waiting_writers -= 1
                    if self._waiting_writers == 0:
                        self._pending_writer = None
                    # A timeout (or error) here must wake readers queued
                    # behind this writer; on success the new writer blocks
                    # them anyway, so an extra notify is harmless.
                    self._cv.notify_all()
            else:
                while self._writer is not None or self._waiting_writers > 0:
                    slice_start = time.monotonic()
                    if not self._wait_tick(deadline):
                        raise _busy(key, self._current_holder(), waited_ms=waited_ms)
                    waited_ms += int((time.monotonic() - slice_start) * 1000)
                self._readers[tid] = _holder_dict(mode, time.time())
            return waited_ms

    def _wait_tick(self, deadline: float | None) -> bool:
        """Wait for the CV until the predicate may have changed; return
        False when the bounded window has expired. Caller holds the CV.

        The wait runs in cancellation-observation slices: mcp 2.x dispatches
        tool bodies on anyio worker threads and shields the host task for the
        thread's lifetime, so a call cancelled while parked here would
        otherwise sit out the whole bounded window (default 30 s, up to
        600 s) holding its tool thread and the tool-limiter token. Anywhere
        that is not an anyio worker thread (plain threads, the event-loop
        thread, CLI callers) the check raises RuntimeError, which is
        swallowed, so non-worker callers keep the pre-poll behavior."""
        _check_lock_cancellation()
        if deadline is None:
            self._cv.wait(_POLL_SLICE_S)
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self._cv.wait(min(remaining, _POLL_SLICE_S))
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


_locks: dict[object, _RWLock] = {}  # str keys (VM ids/names) and tuple keys (dual-key scopes) are disjoint namespaces
_pins: dict[object, int] = {}  # in-flight fetches; never evict a pinned key
_registry_lock = threading.Lock()
_MAX_LOCKS = 4096  # SOFT bound: held locks are never evicted, so a fully-held
# registry can exceed it — mutual exclusion is never weakened for the bound.


def _normalize_key(key: object) -> object:
    """Case-folded lock key. Tuples normalize to TUPLES of case-folded
    strings — a separate dict-key type that can never alias a plain-string
    key, so a client-supplied VM name containing '|' (feedback PRR-009)
    cannot collide with a console dual-key. Display only happens through
    `_display_key`, which joins tuples for readability."""
    if isinstance(key, tuple):
        return tuple(str(part).casefold() for part in key)
    return str(key).casefold()


def _acquire(key: object, mode: str, wait_s: float | None) -> tuple[_RWLock, int]:
    """Fetch-or-create the key's RW lock and acquire it.

    Returns `(lock, waited_ms)`. The registry mutation happens atomically
    under _registry_lock WITH an in-flight pin, so eviction (which also runs
    under _registry_lock) can never remove a lock between this fetch and its
    acquire — the exact race the pre-#14 code closed for the plain Lock
    (round-2 review finding, issue #14 plan BLOCKER-1). The (possibly waiting)
    acquire itself runs OUTSIDE the registry lock: holding it across a bounded
    wait would serialize every VM in the server. Pins are dropped once the
    acquire resolves (held locks are then protected by idle(); failures simply
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
        waited_ms = lock.acquire(key, mode, wait_s, threading.get_ident())
    finally:
        with _registry_lock:
            remaining = _pins.get(key, 0) - 1
            if remaining <= 0:
                _pins.pop(key, None)
            else:
                _pins[key] = remaining
    return lock, waited_ms


def _feed_lock_wait(ms: int) -> None:
    """Hand a measured lock wait to the active call's collector, if any."""
    collector = timing.current()
    if collector is not None:
        collector.add_lock_wait(ms)


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
    # Validate BEFORE taking the pin (feedback PRR-014): a bad value used
    # to reach max() inside the acquire and surface as TypeError/transport.
    if not isinstance(wait_s, (int, float)) or isinstance(wait_s, bool):
        raise ValueError(f"vm_lock wait_s must be a number in 0..{_MAX_WAIT_S:g}, not {wait_s!r}")
    if not 0 <= float(wait_s) <= _MAX_WAIT_S:
        raise ValueError(f"vm_lock wait_s must be a number in 0..{_MAX_WAIT_S:g}, not {wait_s!r}")
    wait_s = float(wait_s)
    # Capture the OWNING thread id at entry: if the context manager is
    # finalized on another thread (ExitStack hand-off / GeneratorExit during
    # GC — feedback PRR-015), the finally must still release THIS thread's
    # records instead of silently wedging a phantom holder forever.
    tid = threading.get_ident()
    # The wait is fed immediately after _acquire resolves, on the acquiring
    # thread and in the acquiring context — never in the generator's exit
    # finally, which can run on another thread (feedback PRR-015) and would
    # then attribute this wait to an unrelated call's collector. A VMBusy
    # carries the wait on the exception, so a failed acquire is measured too.
    try:
        lock, waited_ms = _acquire(key, mode, wait_s)
    except VMBusy as exc:
        _feed_lock_wait(exc.waited_ms)
        raise
    _feed_lock_wait(waited_ms)
    try:
        yield
    finally:
        lock.release(tid)
