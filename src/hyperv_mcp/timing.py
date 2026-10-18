"""Per-call timing collection for audit records and console metadata.

One collector per audited operation, held in a ContextVar so it survives the
`anyio.to_thread.run_sync` hop mcp 2.x uses to dispatch every sync tool body
(that hop copies the caller's context into the worker thread). The collector is
therefore created and read inside one worker's context, which is what makes
concurrent and sequential calls each report their own costs.

Instrumentation points:
  - `auditlog.operation.__enter__` / `__exit__` create and serialize it;
  - `PSResult.__post_init__` contributes each spawn's duration and count, plus
    any parsed timing markers, so a stubbed or directly-invoked `run_ps` is
    counted exactly like a real spawn;
  - `vmlocks.vm_lock` contributes the time a waiter spent parked;
  - `server._audited_rejection` creates a short-lived one so a pre-body
    rejection still reports an honest (zeroed) breakdown.

Every value is numeric or null. Nothing here carries script text, arguments or
credentials: `parse_marker` accepts only three known keys and only `int` values
(bool excluded), so a marker cannot become a channel for anything else.
"""

from __future__ import annotations

import threading
import time
from contextvars import ContextVar, Token

#: Keys present on every record, whatever the tool.
BASE_KEYS = ("lock_wait_ms", "ps_ms", "ps_spawns", "total_ms")
#: Keys present only when a PowerShell script emitted a timing marker.
MARKER_KEYS = ("ps_startup_ms", "psdirect_session_ms", "guest_ms")
#: The line prefix a guest host script appends as its last stdout line.
MARKER_PREFIX = "__MCP_TIMING="

_collector: ContextVar[Collector | None] = ContextVar("hyperv_mcp_timing", default=None)


class Collector:
    """Accumulates one audited operation's costs.

    All mutation happens under a lock so two threads that somehow share a
    collector cannot corrupt the counters. `_markers` is replaced wholesale by
    a marker-bearing spawn and left untouched by a marker-less one — see
    `add_spawn`.
    """

    __slots__ = ("_start", "_mu", "lock_wait_ms", "ps_ms", "ps_spawns", "_markers")

    def __init__(self) -> None:
        self._start = time.monotonic()
        self._mu = threading.Lock()
        self.lock_wait_ms = 0
        self.ps_ms = 0
        self.ps_spawns = 0
        self._markers: dict[str, int] = {}

    def add_spawn(self, duration_ms: int, markers: dict | None) -> None:
        """Record one PowerShell process's duration and any timing markers.

        `markers is None` means "this stdout carried no marker line at all" and
        leaves the trio unchanged. A dict — even an empty one, which is what a
        present-but-unparseable marker yields — means "a marker was present"
        and REPLACES the trio. Overwrite rather than first-wins, so a later,
        more specific measurement is never masked by an earlier vaguer one.
        """
        with self._mu:
            self.ps_spawns += 1
            self.ps_ms += int(duration_ms)
            if markers is not None:
                self._markers = dict(markers)

    def add_lock_wait(self, ms: int) -> None:
        with self._mu:
            self.lock_wait_ms += int(ms)

    def snapshot(self) -> dict:
        with self._mu:
            out: dict[str, int | None] = {
                "lock_wait_ms": self.lock_wait_ms,
                "ps_ms": self.ps_ms,
                "ps_spawns": self.ps_spawns,
                "total_ms": int((time.monotonic() - self._start) * 1000),
            }
            for key in MARKER_KEYS:
                out[key] = self._markers.get(key)
            return out


def start() -> Token:
    """Install a FRESH collector, replacing any prior one, and return the
    reset token. Replacing (rather than nesting) means a leaked collector from
    an earlier operation can never corrupt a later call's numbers."""
    return _collector.set(Collector())


def finish(token: Token) -> dict:
    """Reset the ContextVar and return the snapshot of the collector that was
    installed. The reset happens before anything that can raise, so a sink
    failure cannot leak a collector into the next operation on this thread.

    Same-thread invariant: the token is reset on the thread that set it. Both
    call sites (`operation.__exit__` and `_audited_rejection`) run on the
    thread that entered.
    """
    try:
        collector = _collector.get()
    finally:
        _collector.reset(token)
    return collector.snapshot() if collector is not None else zeroed()


def current() -> Collector | None:
    return _collector.get()


def zeroed() -> dict:
    """The honest breakdown for a call that made no lock acquisition and no
    spawn. Used by callers with no collector of their own."""
    return {
        "lock_wait_ms": 0,
        "ps_ms": 0,
        "ps_spawns": 0,
        "total_ms": 0,
        "ps_startup_ms": None,
        "psdirect_session_ms": None,
        "guest_ms": None,
    }


def parse_marker(text: str) -> tuple[str, dict | None]:
    """Split a trailing `__MCP_TIMING=` line off `text`.

    Returns `(cleaned_text, markers)` where `markers` is `None` when no marker
    line was present at all, and otherwise a dict of the accepted keys. The
    distinction is the contract: `None` means "leave the caller's trio alone",
    a dict means "a marker was here, replace the trio".

    Removal is unconditional on the prefix: a line whose stripped form starts
    with `__MCP_TIMING=` is dropped whether or not its payload parses and
    whether or not its values are numeric, so an unparseable or hostile marker
    can never survive into a tool's stdout.

    Accepted values are the three known keys with `int` values only — `bool`
    is excluded explicitly, because `isinstance(True, int)` is true in Python
    and a boolean is not a measurement. Any other key or type is dropped, so
    the corresponding field reads `None`.

    Splitting uses `splitlines()` rather than `split("\\n")` because real
    PowerShell emits CRLF while the checks inject LF. The rejoin uses the
    caller's own terminator, so stdout that arrived CRLF leaves CRLF: the only
    bytes removed are the marker line itself, and nothing else about the
    caller's stdout changes.
    """
    separator = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    for index in range(len(lines) - 1, -1, -1):
        if lines[index].strip().startswith(MARKER_PREFIX):
            payload = lines[index].strip()[len(MARKER_PREFIX):]
            del lines[index]
            return separator.join(lines), _accept(payload)
    return text, None


def _accept(payload: str) -> dict:
    """The marker's numeric values, or an empty dict when nothing qualifies."""
    import json

    try:
        data = json.loads(payload)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, int] = {}
    for key in MARKER_KEYS:
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        out[key] = value
    return out
