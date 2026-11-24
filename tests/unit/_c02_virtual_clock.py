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
"""

import threading


class VirtualClock:
    """A monotonic clock that only moves when someone sleeps on it."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)
        self._lock = threading.Lock()
        self._sleeps: list[float] = []
        self._sleep_event = threading.Event()

    # ---- the surface `pswindows` uses from `time` ----

    def sleep(self, seconds: float) -> None:
        duration = float(seconds)
        with self._lock:
            self._sleeps.append(duration)
            self._now += duration
        self._sleep_event.set()

    def monotonic(self) -> float:
        with self._lock:
            return self._now

    def perf_counter(self) -> float:
        return self.monotonic()

    def time(self) -> float:
        return self.monotonic()

    # ---- observation helpers for the assertions ----

    @property
    def sleeps(self) -> list[float]:
        """Every duration the code asked to sleep, in order."""
        with self._lock:
            return list(self._sleeps)

    @property
    def now(self) -> float:
        return self.monotonic()

    def wait_for_sleeps(self, count: int, timeout: float = 5.0) -> bool:
        """Block until at least `count` sleeps have been requested.

        This is EVENT-driven coordination, not a fixed wall-clock wait: it
        returns as soon as the count is reached. It is only ever used as
        deadlock protection for a worker that is expected to make progress.
        """
        deadline = threading.Event()
        waited = 0.0
        step = 0.01
        while waited < timeout:
            if len(self.sleeps) >= count:
                return True
            deadline.wait(step)
            waited += step
        return len(self.sleeps) >= count
