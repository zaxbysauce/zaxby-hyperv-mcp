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
(bool excluded), bounds the payload's length and each value's magnitude, and
never splits on a Unicode line boundary — so a marker cannot become a channel
for anything else, and cannot be used to smuggle a secret past redaction.
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
#: A marker payload longer than this is refused rather than parsed. The three
#: values it can carry are six-or-seven-digit millisecond counts, so 4 KiB is
#: already two orders of magnitude of slack.
_MAX_MARKER_BYTES = 4096
#: An integer wider than this many bits is dropped: 64 bits already covers a
#: millisecond count for every duration this process can observe, and the
#: timing dict is the one record field inserted without the redaction wrapper.
_MAX_MARKER_INT_BITS = 64

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
    can never survive into a tool's stdout. Every marker line is dropped, not
    just the last one, so the guarantee really is absolute.

    Accepted values are the three known keys with `int` values only — `bool`
    is excluded explicitly, because `isinstance(True, int)` is true in Python
    and a boolean is not a measurement. Any other key or type is dropped, so
    the corresponding field reads `None`.

    Splitting is on CRLF and LF ONLY, never on the Unicode line boundaries
    `str.splitlines()` also honours (U+2028, U+2029, U+0085, \x0b, \x0c,
    \x1c-\x1e). `run_ps` parses this marker BEFORE `credentials.redact` runs,
    and redaction matches on exact substrings, so splitting on a Unicode
    separator would break a guest secret containing one into two fragments
    that no longer match the registry — leaking the secret to the MCP client
    in mangled form. `credentials._validated_password` rejects only `\r` and
    `\n`, so such a password is accepted and registered. Splitting narrowly
    keeps the caller's bytes intact for the redactor to see.

    The rejoin uses the caller's own terminator, so stdout that arrived CRLF
    leaves CRLF: the only bytes removed are the marker lines themselves, and
    nothing else about the caller's stdout changes.
    """
    separator = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(separator)
    # A trailing terminator leaves a final empty element that splitlines()
    # would not have produced. It is the marker line's own terminator when the
    # marker is last, so dropping it here means removing the marker line also
    # removes its terminator — and nothing else about the caller's stdout
    # changes.
    if lines and lines[-1] == "":
        lines.pop()
    found = False
    markers: dict | None = None
    for index in range(len(lines) - 1, -1, -1):
        if lines[index].strip().startswith(MARKER_PREFIX):
            payload = lines[index].strip()[len(MARKER_PREFIX):]
            del lines[index]
            if not found:
                # The first one found scanning backwards — i.e. the last in the
                # file — supplies the values; any EARLIER marker line is still
                # removed, so the guarantee is absolute rather than last-only.
                found = True
                markers = _accept(payload)
    if not found:
        return text, None
    return separator.join(lines), markers


def _accept(payload: str) -> dict:
    """The marker's numeric values, or an empty dict when nothing qualifies.

    Bounded on three axes, because the marker line arrives on a channel this
    module describes as nominally untrusted:

    - LENGTH — a payload over `_MAX_MARKER_BYTES` is refused rather than
      parsed, so a hostile emitter cannot make the host spend unbounded work
      on it;
    - NESTING — `json.loads` on a deeply nested array raises `RecursionError`,
      which is NOT a `ValueError`, so the `except ValueError` below would let
      it escape into `run_ps`. The depth guard refuses before parsing;
    - MAGNITUDE — an integer wider than `_MAX_MARKER_INT_BITS` is dropped, so
      a marker carrying a 4000-digit value cannot inflate the audit row (the
      timing dict is the one record field inserted without the redaction
      wrapper, and three such values made a row ~12 KB).
    """
    import json

    if len(payload) > _MAX_MARKER_BYTES:
        return {}
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
        if value.bit_length() > _MAX_MARKER_INT_BITS:
            continue
        out[key] = value
    return out
