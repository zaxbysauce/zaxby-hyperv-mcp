"""Issue #76 AC4/AC5: the d01 AC1 check leaves interpreter tracing state as found.

The frozen file tests/unit/test_d01_screenshot_decode.py installs a trace
function in ``test_decode_runs_no_per_pixel_python_loop`` (its AC1
line-event count) and at base tears it down with ``sys.settrace(None)``,
permanently discarding any tracer that was already installed — coverage,
pdb or debugpy instrumentation silently vanishes, with no failure. Two
invariants:

* AC4 — a tracer installed BEFORE the check runs is still installed AFTER
  it. RED at base b1ed4f7 (the frozen teardown clears the tracer instead of
  restoring what was captured), GREEN after the #76 amendment makes the
  check restore the trace function it displaced.
* AC5 — with NO tracer installed beforehand, none is installed afterwards.
  GREEN at base (``settrace(None)`` leaves None) and GREEN after the fix
  (restoring the captured ``None`` is a no-op).

Both tests capture the true pre-state (``prev = sys.gettrace()``) before
touching anything and restore it in a ``finally`` that runs after the
assertion, so even a failing assertion returns the interpreter to exactly
the state it started from.
"""

import sys
from pathlib import Path

_UNIT_DIR = Path(__file__).resolve().parent


def _d01():
    """Import the frozen d01 module from this test directory.

    pytest's prepend import mode already puts tests/unit on sys.path (the
    directory has no __init__.py); the explicit insert keeps the helper
    correct under any import mode.
    """
    if str(_UNIT_DIR) not in sys.path:
        sys.path.insert(0, str(_UNIT_DIR))
    import test_d01_screenshot_decode as d01

    return d01


def test_preexisting_tracer_survives_frozen_ac1_check():
    """AC4: a pre-installed trace function survives the d01 AC1 check run."""
    d01 = _d01()
    prev = sys.gettrace()
    calls = {"n": 0}

    def sentinel(frame, event, arg):
        calls["n"] += 1
        return sentinel

    sys.settrace(sentinel)
    try:
        d01.test_decode_runs_no_per_pixel_python_loop()
        assert sys.gettrace() is sentinel, (
            "AC4: the d01 AC1 check discarded the pre-existing trace function "
            f"(sys.gettrace()={sys.gettrace()!r} after the check ran; the "
            f"sentinel had received {calls['n']} events before being displaced)"
        )
    finally:
        sys.settrace(prev)


def test_no_tracer_leaves_none():
    """AC5: no tracer beforehand means none installed afterwards."""
    d01 = _d01()
    prev = sys.gettrace()
    # Guarantee the precondition even under an outer coverage/pdb tracer:
    # tracing is disabled for the duration of this one check and the true
    # pre-state is restored in the finally below.
    sys.settrace(None)
    try:
        d01.test_decode_runs_no_per_pixel_python_loop()
        assert sys.gettrace() is None, (
            "AC5: the d01 AC1 check left a trace function installed "
            f"(sys.gettrace()={sys.gettrace()!r}) when none was installed "
            "before it ran"
        )
    finally:
        sys.settrace(prev)
