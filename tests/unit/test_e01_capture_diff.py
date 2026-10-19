"""Acceptance check C5 for issue #72 in the #74/#72/#88 bundle:
`capture_sequence`'s `changed_bytes_vs_previous` must not run a per-byte Python
loop.

C5 (AC5, DISCRIMINATING) — the computation executes fewer than 100 Python line
events per payload byte. RED at base (3.000 per byte), GREEN after the fix.

The counter is `sys.settrace`, which is machine-speed independent, so the check
replaces a wall-clock budget that would drift between a loaded CI runner and an
idle workstation. The issue names this instrument explicitly.

The probe drives the REAL production function on both transports' shared helper,
and asserts the exact count of the two bytes it flipped, so a diff that returns
a wrong number cannot pass by being fast.
"""
from __future__ import annotations

import sys

from hyperv_mcp import console as console_mod

_PREFIX_LEN = console_mod._PREFIX_LEN

#: The issue's AC2 states the criterion as "fewer than 100 Python line events
#: per payload byte". MEASURED AT BASE, the per-byte loop executes 3.000 line
#: events per byte — comfortably inside that bound — so the literal threshold
#: is satisfied by the defective implementation and cannot discriminate. It is
#: kept below as a continuity assertion only.
#:
#: The DISCRIMINATING assertions are the two the issue's own "Suggested
#: approach" actually asks for, and both are deterministic by construction:
#:
#: 1. THE IDLE CASE. "Compare the two payloads' sha256 frame_hash values first:
#:    when they are equal the changed-byte count is 0 and no diff is needed at
#:    all (the common case for an idle console)." An idle console is the common
#:    case, and the base spends 4.7 M line events on it.
#: 2. THE SPARSE-CHANGE CASE. When the payloads differ, the diff is taken over
#:    fixed-size chunks, so a change confined to one chunk costs one chunk
#:    rather than the whole payload.
#:
#: What is NOT claimed, because it is not achieved: a change in every chunk
#: still costs O(payload). There is no stdlib C-level primitive that counts
#: differing bytes between two byte strings, and numpy is not a dependency.
#: That residual is disclosed in the trace and in the PR body rather than
#: papered over with a threshold that happens to pass.
_MAX_LINE_EVENTS_PER_BYTE = 100
_MAX_IDLE_EVENTS = 100
_MAX_SPARSE_EVENTS = 1_000_000
#: A 1024x768 payload is 1,572,864 pixel bytes = 24 chunks of 64 KiB.
_LARGE = (1024, 768)
_CHUNK = 65536


def _payload(w: int, h: int) -> bytes:
    px = bytearray()
    for y in range(h):
        for x in range(w):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            px += bytes([v & 0xFF, (v >> 8) & 0xFF])
    return bytes([0, 0, 0x96, 4]) + bytes(px)


def _flipped(payload: bytes, *indexes: int) -> bytes:
    out = bytearray(payload)
    for i in indexes:
        out[_PREFIX_LEN + i] ^= 0xFF
    return bytes(out)


def _count_events(a: bytes, b: bytes) -> int:
    events = [0]

    def _tracer(frame, event, arg):
        if event == "line":
            events[0] += 1
        return _tracer

    sys.settrace(_tracer)
    try:
        console_mod._changed_pixel_bytes(a, b)
    finally:
        sys.settrace(None)
    return events[0]


def test_diff_cost_does_not_scale_with_the_payload():
    """C5 / AC5: the changed-byte diff must not run a per-byte Python loop.

    The discriminator is the IDLE case, not an absolute per-byte threshold (see
    the module docstring for why the issue's literal threshold cannot
    discriminate). Counted with `sys.settrace`, so the number is machine-speed
    independent and needs no wall-clock budget.
    """
    large = _payload(*_LARGE)
    large_bytes = len(large) - console_mod._PREFIX_LEN

    # --- the exact count must survive, or a fast-but-wrong diff passes -------
    sparse = _flipped(large, 5000, 60000)
    assert console_mod._changed_pixel_bytes(large, sparse) == 2, (
        "C5 sanity: the two flipped bytes must be counted exactly"
    )

    # --- 1. the idle case costs O(1) -------------------------------------
    idle_events = _count_events(large, large)
    print(f"idle_events={idle_events} payload_bytes={large_bytes}")
    assert idle_events < _MAX_IDLE_EVENTS, (
        f"AC5: an idle console (identical payloads) costs {idle_events} line "
        f"events; expected fewer than {_MAX_IDLE_EVENTS}. Comparing two "
        f"identical {large_bytes}-byte payloads must not walk them byte by "
        f"byte — that is the common case, and it is the one the issue's "
        f"suggested approach short-circuits."
    )

    # --- 2. a sparse change costs one chunk, not the payload ---------------
    sparse_events = _count_events(large, sparse)
    print(f"sparse_events={sparse_events}")
    assert sparse_events < _MAX_SPARSE_EVENTS, (
        f"AC5: a change confined to one {_CHUNK}-byte chunk costs "
        f"{sparse_events} line events; expected fewer than {_MAX_SPARSE_EVENTS}. "
        f"The diff must skip the chunks that did not change."
    )

    # --- the issue's literal threshold, kept for continuity ---------------
    assert idle_events / large_bytes < _MAX_LINE_EVENTS_PER_BYTE, (
        f"AC5: {idle_events / large_bytes:.3f} line events per byte, expected "
        f"fewer than {_MAX_LINE_EVENTS_PER_BYTE}"
    )


def test_diff_reports_zero_when_only_the_prefix_drifted():
    """C5's companion: the pixel-only domain is preserved, not just made fast.

    A cheaper diff that accidentally counted the 4-byte prefix would still pass
    the line-event check above while reintroducing the contradiction issue #19
    closed. This pins the domain.
    """
    a = _payload(64, 48)
    drifted = bytes([0xDE, 0xAD, 0xBE, 0xEF]) + a[_PREFIX_LEN:]
    assert console_mod._changed_pixel_bytes(a, drifted) == 0, (
        "AC5 companion: identical pixels with a drifted prefix must report zero "
        "changed bytes"
    )
    assert console_mod._changed_pixel_bytes(None, a) == 0, (
        "AC5 companion: the first frame has no predecessor, so it reports zero"
    )


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
