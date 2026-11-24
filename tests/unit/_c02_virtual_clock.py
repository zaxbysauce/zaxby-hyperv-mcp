"""Virtual clock for the c02 pool-schedule checks (issue #167 AC2).

RED at base / GREEN after the fix: this helper is used by the converted
checks to run the PRODUCTION backoff loop against virtual time, so the
schedule the code asks for is observable exactly and no real sleeping or
wall-clock harness wait is involved.

The fake replaces the `time` module reference INSIDE
`hyperv_mcp.pswindows` (and only there), so:

* `sleep(seconds)` records the REQUESTED duration and advances the clock by
  exactly that amount;
* `monotonic()` and `perf_counter()` return the virtual now.

Because the clock advances only when the production code asks to sleep, the
interval the pool probe measures between two events equals the requested
sleep duration - the jitter that made the old ratio-bound assertions flaky
on a loaded CI runner cannot enter the measurement at all.

The clock is thread-safe: the pool acquire loop runs in a worker thread
while the test thread observes it.

Gated mode (opt-in, issue #167 AC2 follow-up): `enable_gating()` turns the
worker's sleeps into a hand-held relay. A gated `sleep(seconds)` still
records the request and advances virtual time FIRST, and then PARKS the
caller until the test hands out a permit - `permit_one_sleep()` releases
exactly one parked sleeper (or pre-authorizes the next request when nobody
is parked yet), `permit_all_sleeps()` opens the gate for every remaining
sleep. `wait_for_sleeps(n)` is condition-driven: it returns the instant the
n-th request is recorded, so the test can assert the requested schedule one
sleep at a time with no race and no real waiting, then permit exactly one
further sleep. `disable_gating()` reverts to the free-running clock and
releases every parked sleeper (safe teardown for a failed assertion).

This module also hosts `no_real_sleep()`: a spy over the STANDARD LIBRARY
`time.sleep` (the `time` module attribute - NOT `pswindows.time.sleep`,
which the virtual clock replaces) that fails the test the moment anything
really sleeps inside the block. The production pool loop reaches the clock
through `pswindows.time`, so a genuine real sleep can only reach the spy by
bypassing the virtual clock - exactly the regression the spy exists to
catch, asserted directly instead of through a duration proxy.
"""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

# Deadlock protection only (harness side): a sleeper parked on the gate is
# released after this much REAL time even without a permit, so a broken test
# fails its joins/assertions instead of hanging the run. It is never a
# measurement and never advances the virtual clock.
_GATE_SAFETY_TIMEOUT_S = 60.0


class VirtualClock:
    """A monotonic clock that only moves when someone sleeps on it.

    Free-running by default (the sleeping caller returns immediately);
    `enable_gating()` parks each sleeper after its request is recorded.
    """

    def __init__(self, start: float = 0.0) -> None:
        # One condition guards the now/sleeps state AND the gate: sleep()
        # notifies wait_for_sleeps() observers on every recorded request and
        # parks on the same condition until a permit arrives, so no
        # notification can be lost between the two sides.
        self._cond = threading.Condition()
        self._now = float(start)
        self._sleeps: list[float] = []
        self._gated = False
        self._gate_open = False
        self._permits = 0

    # ---- the surface `pswindows` uses from `time` ----

    def sleep(self, seconds: float) -> None:
        duration = float(seconds)
        with self._cond:
            self._sleeps.append(duration)
            self._now += duration
            self._cond.notify_all()  # a request was recorded (wait_for_sleeps)
            if self._gated:
                self._await_permit_locked()

    def _await_permit_locked(self) -> None:
        """Park the caller until the test permits this sleeper (lock held)."""
        deadline = time.monotonic() + _GATE_SAFETY_TIMEOUT_S
        while self._gated and not self._gate_open and self._permits <= 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return  # safety release; the test's joins turn this into a failure
            self._cond.wait(remaining)
        if self._gated and not self._gate_open and self._permits > 0:
            self._permits -= 1  # consume exactly one single-use permit

    def monotonic(self) -> float:
        with self._cond:
            return self._now

    def perf_counter(self) -> float:
        return self.monotonic()

    def time(self) -> float:
        return self.monotonic()

    # ---- observation helpers for the assertions ----

    @property
    def sleeps(self) -> list[float]:
        """Every duration the code asked to sleep, in order."""
        with self._cond:
            return list(self._sleeps)

    @property
    def now(self) -> float:
        return self.monotonic()

    def wait_for_sleeps(self, count: int, timeout: float = 5.0) -> bool:
        """Block until at least `count` sleeps have been REQUESTED.

        This is EVENT-driven coordination, not a fixed wall-clock wait: the
        condition is notified the instant a request is recorded, so this
        returns as soon as the count is reached. The timeout is only ever
        deadlock protection for a worker that is expected to make progress.
        """
        with self._cond:
            deadline = time.monotonic() + float(timeout)
            while len(self._sleeps) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(remaining)
            return len(self._sleeps) >= count

    # ---- gated-mode controls (test side; gating is strictly opt-in) ----

    def enable_gating(self) -> None:
        """Park every sleeper right after its request is recorded."""
        with self._cond:
            self._gated = True

    def permit_one_sleep(self) -> None:
        """Permit exactly one further sleep: wake one parked sleeper, or
        pre-authorize the next request when nobody is parked yet."""
        with self._cond:
            self._permits += 1
            self._cond.notify_all()

    def permit_all_sleeps(self) -> None:
        """Permit every remaining sleep unconditionally (cleanup path)."""
        with self._cond:
            self._gate_open = True
            self._permits = 0
            self._cond.notify_all()

    def disable_gating(self) -> None:
        """Return to the free-running clock, releasing every parked sleeper."""
        with self._cond:
            self._gated = False
            self._gate_open = False
            self._permits = 0
            self._cond.notify_all()


@contextmanager
def no_real_sleep() -> Iterator[list[float]]:
    """Prohibit the STANDARD LIBRARY `time.sleep` for the duration of the
    block (issue #167 AC2: a direct prohibition, not a duration proxy).

    The c02 backoff tests replace `pswindows.time` with a VirtualClock, so
    the production pool loop cannot reach the real `time.sleep`; anything
    that still calls it inside this block has bypassed the virtual clock and
    is REALLY sleeping. The spy swaps the `sleep` attribute on the real
    `time` module (restored on exit, so pytest and unrelated machinery are
    untouched outside the test body) and raises immediately with the
    requested duration, keeping the failure at the offending call site. The
    recorded-call list is yielded for tests that want to inspect it.
    """
    calls: list[float] = []
    real_sleep = time.sleep

    def _forbidden_sleep(seconds) -> None:
        calls.append(float(seconds))
        raise AssertionError(
            f"real time.sleep({seconds}) called inside no_real_sleep() - the "
            f"c02 backoff tests must run entirely on the virtual clock "
            f"(recorded calls: {calls})"
        )

    time.sleep = _forbidden_sleep
    try:
        yield calls
    finally:
        time.sleep = real_sleep
