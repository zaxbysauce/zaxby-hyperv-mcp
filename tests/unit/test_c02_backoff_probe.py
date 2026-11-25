"""Issue #64 AC3 (amendment) — binding backoff-attempt schedule probe.

The PR #61/#64 bounded-wait acquire backs off exponentially between sweeps:
5 ms doubling to a 200 ms ceiling, each sleep capped to the remaining
deadline. This probe BINDS the amended AC3 figures against the real shipped
schedule: it saturates a recorded cap-2 pool (both slot files held by the
main thread), runs one waiter with host_powershell_wait_s = 3.0 in a worker
thread, counts every sweep through a counting wrapper around
pswindows._try_lock_slot, brackets each sleep between the cancellation
tick's return and the next sweep's first attempt (the seam's one-time
~30 ms initialization and the sweep's file-lock work are not the backoff
schedule), and asserts against the REQUESTED schedule EXACTLY.

Why the schedule is asserted exactly (issue #167 AC2): the probe used to
measure the schedule from wall-clock timestamps and compare JITTER-ROBUST
RATIO BOUNDS, because CI-runner scheduler jitter (~5-10 ms per sleep)
inflates each measured sleep and every absolute band the probe originally
used. Those bounds were the flake source: the 1.2x ratio floor could be
violated by a perfectly correct schedule. The probe now runs the
production loop against a VIRTUAL clock (tests/unit/_c02_virtual_clock.py)
installed on `pswindows.time`, so the interval between two events equals
the duration the code REQUESTED. The assertions are therefore exact - the
schedule, the sweep count and the attempt-reduction ratio are all
deterministic - and no real sleeping or wall-clock harness wait is
involved. The tolerant real-clock path stays covered separately by
tests/unit/test_c02_backoff_schedule_smoke.py.

  P1  the requested sleep sequence IS the schedule: 5 ms doubling to the
      200 ms ceiling, with the final sleep capped to the remaining
      deadline (and a 1 ms floor when the remainder is smaller);
  P2  the sweep count in the 3.0 s window follows from that schedule (the
      fixed 50 ms cadence would do ~61 sweeps);
  P3  the amendment's arithmetic recomputed from the MEASURED ceiling keeps
      the attempt-reduction ratio >= 3 (315 ms ramp + 200 ms ceiling over a
      600 s window -> 3005 vs 12000 = 3.99x);
  P4  the busy contract survives inside the same probe run: the waiter
      raises PowerShellBusy naming 'saturated', and its permit accounting
      closes cleanly - the failed waiter stranded no slot lock (a fresh
      acquire succeeds immediately once the holders release);
  P5  the 1 ms sleep floor of `min(backoff, max(deadline - now, 0.001))` is
      REALLY engaged: a 315.5 ms budget leaves a 0.5 ms remainder after the
      ramp, and the production loop's next request is exactly the 1 ms floor
      (not the 0.5 ms remainder a floor-less mutant would ask for).

Both legs run under the DIRECT real-sleep prohibition `no_real_sleep()`: a
spy over the STDLIB `time.sleep` (the module attribute - the production
loop reaches its clock through `pswindows.time`, which the virtual clock
replaces), so any code path that bypasses the virtual clock and really
sleeps fails the test at the offending call site.

Hermetic: no PowerShell spawn, no host, no network (the pool-identity
fixture pattern from test_c02_pool_identity.py: temp slot dir, config
seam, captured log lines). The file's whole runtime is now well under a
second.
"""

import json
import math
import threading
from types import SimpleNamespace

import pytest
from _c02_virtual_clock import (
    VirtualClock,
    assert_no_cached_sleep_references,
    no_real_sleep,
)

from hyperv_mcp import pswindows

_META_NAME = "pool.meta"
_CAP = 2
_WAIT_S = 3.0
_FIRST_SLEEP = 0.005
_CEILING = 0.2
_SLEEP_FLOOR = 0.001
# The sub-1 ms floor case: the plain ramp (5+10+20+40+80+160 ms) sums to
# 0.315 s, so a 0.3155 s budget leaves 0.5 ms of remaining deadline - BELOW
# the 1 ms sleep floor - at the next sleep request.
_FLOOR_WAIT_S = 0.3155


def _pool_cfg(slot_dir, wait_s: float) -> SimpleNamespace:
    return SimpleNamespace(
        max_host_powershell=_CAP,
        host_powershell_wait_s=wait_s,
        ps_slot_dir=str(slot_dir),
    )


def _expected_schedule(
    wait_s: float,
    first: float = _FIRST_SLEEP,
    ceiling: float = _CEILING,
    floor: float = _SLEEP_FLOOR,
) -> list[float]:
    """The sleep sequence the SHIPPED loop requests.

    Mirrors `pswindows._acquire_ps_slot`: the backoff starts at 5 ms,
    doubles up to a 200 ms ceiling, and each sleep is capped to the
    remaining deadline with a 1 ms floor.
    """
    schedule: list[float] = []
    now = 0.0
    backoff = first
    while True:
        sleep = min(backoff, max(wait_s - now, floor))
        schedule.append(sleep)
        now += sleep
        if now >= wait_s:
            break
        backoff = min(backoff * 2, ceiling)
    return schedule


@pytest.fixture()
def pool_env(tmp_path, monkeypatch):
    """Isolated slot dir + config seam + log capture (pool-identity style)."""
    slot_dir = tmp_path / "slots"
    slot_dir.mkdir()
    logs: list[str] = []

    def _capture(*parts, **kwargs):
        logs.append(" ".join(str(p) for p in parts))

    monkeypatch.setattr(pswindows.logemit, "log_line", _capture)
    monkeypatch.setattr(pswindows, "_config", _pool_cfg(slot_dir, 5.0))
    monkeypatch.setattr(pswindows, "_PS_POOL_STATE",
                        SimpleNamespace(warned=set(), marker_written=False),
                        raising=False)
    return SimpleNamespace(dir=slot_dir, logs=logs)


def test_no_cached_sleep_reference_on_the_guarded_path():
    """The `no_real_sleep()` spy's boundary, checked at the seam it covers.

    The spy intercepts sleeps resolved through the `time` module at CALL
    time. A reference bound to the builtin BEFORE the swap would evade it,
    because `time.sleep` is a C builtin with nothing underneath to wrap.

    This is a TARGETED regression guard over the guarded path - the
    production pool module and the two c02 backoff test files - for the two
    binding FORMS that would produce such a reference:
    `from time import sleep` and `name = time.sleep`. It is not a proof
    that no cached reference can exist (an aliased import, `getattr`, or a
    star import would not be caught), so it is recorded as a bounded check,
    not as the closure of the gap on its own.
    """
    assert_no_cached_sleep_references()


def test_backoff_attempt_schedule_matches_ceiling_model(pool_env, monkeypatch):
    """P1..P4 (module docstring), under the DIRECT real-sleep prohibition:
    the whole probe runs inside `no_real_sleep()`, a spy over the STDLIB
    `time.sleep` (not `pswindows.time.sleep`, which the virtual clock
    replaces), so a code path that bypasses the virtual clock and really
    sleeps fails the test at the offending call site."""
    with no_real_sleep():
        _run_backoff_attempt_schedule_probe(pool_env, monkeypatch)


def _run_backoff_attempt_schedule_probe(pool_env, monkeypatch):
    """P1..P4 (module docstring): the REQUESTED sweep schedule of a
    saturated cap-2 pool is 5 ms doubling to a 200 ms ceiling with the final
    sleep capped to the deadline, the sweep count follows from that
    schedule, the amendment's ratio holds from the measured ceiling, and
    the busy/no-leak contracts hold inside the same run."""
    # The virtual clock replaces `pswindows.time` only: the production loop
    # asks to sleep, the clock records the REQUESTED duration and advances
    # virtual time, and the probe's own stamps read the same clock - so
    # the measured interval IS the requested sleep.
    clock = VirtualClock()
    monkeypatch.setattr(pswindows, "time", clock)

    # Publish the pool marker (cap 2) and hold BOTH slots from this thread:
    # the worker below runs against a genuinely saturated pool.
    holders = [pswindows._acquire_ps_slot() for _ in range(_CAP)]
    assert all(fd is not None for fd in holders), "harness must hold every slot"
    payload = json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert payload.get("cap") == _CAP, f"pool.meta must record cap {_CAP}: {payload}"

    # Bounded wait 3.0 s; count only the WORKER thread's slot attempts (the
    # harness holds/releases below and any stray loop from another test
    # cannot pollute the measurement).
    monkeypatch.setattr(pswindows, "_config", _pool_cfg(pool_env.dir, _WAIT_S))
    main_tid = threading.get_ident()
    real_try_lock = pswindows._try_lock_slot
    stamps: list[float] = []  # one virtual stamp per worker attempt

    def _counting_try_lock(path):
        if threading.get_ident() != main_tid:
            stamps.append(clock.perf_counter())
        return real_try_lock(path)

    monkeypatch.setattr(pswindows, "_try_lock_slot", _counting_try_lock)

    # Stamp the return of each cancellation tick too: a failed sweep runs
    # _check_ps_cancellation() BETWEEN its attempts and its sleep. The seam's
    # FIRST call in a fresh process pays a one-time ~30 ms anyio / sniffio
    # thread-detection initialization that is not part of the backoff
    # schedule (its per-tick observance is pinned separately by
    # test_c02_pool_identity.py's cancellation test).
    real_check = pswindows._check_ps_cancellation
    check_ends: list[float] = []

    def _stamping_check():
        real_check()
        if threading.get_ident() != main_tid:
            check_ends.append(clock.perf_counter())

    monkeypatch.setattr(pswindows, "_check_ps_cancellation", _stamping_check)

    outcome: dict = {}

    def _waiter():
        try:
            outcome["fd"] = pswindows._acquire_ps_slot()
        except BaseException as exc:  # noqa: BLE001 - recorded, asserted below
            outcome["error"] = exc

    waiter = threading.Thread(target=_waiter, daemon=True)
    waiter.start()
    waiter.join(timeout=30)
    assert not waiter.is_alive(), "the bounded wait must terminate on its own"

    # P4a — the busy contract: PowerShellBusy naming saturation, no fd.
    assert "fd" not in outcome, "the waiter must never acquire a held slot"
    error = outcome.get("error")
    assert isinstance(error, pswindows.PowerShellBusy), (
        f"the saturated waiter must raise PowerShellBusy; got {outcome!r}"
    )
    assert "saturated" in str(error)

    # The measured schedule. One stamp per attempt, cap attempts per sweep;
    # each sleep is BRACKETED as (first attempt of sweep i+1) minus (return
    # of the cancellation tick after sweep i), so the measured interval is
    # the sleep itself plus the loop-around and the next first file-open
    # attempt - the sweep's own file-lock work and the cancellation seam's
    # one-time initialization must not inflate the schedule. The FINAL sweep
    # may be truncated by the in-sweep deadline check; sweeps counts it, the
    # schedule below is built only over full sweeps.
    assert stamps, "the waiter never attempted a slot lock"
    n_full = len(stamps) // _CAP
    sweep_starts = [stamps[i * _CAP] for i in range(n_full)]
    sweeps = math.ceil(len(stamps) / _CAP)
    assert len(check_ends) >= n_full - 1, (
        f"cancellation ticks not observed per failed sweep: {len(check_ends)}"
    )
    measured_sleeps = [
        sweep_starts[i + 1] - check_ends[i] for i in range(n_full - 1)
    ]
    print("SLEEPS-MS:", [round(s * 1000, 1) for s in measured_sleeps])

    # P1 — the REQUESTED schedule, exactly. Two views of the same clock:
    # `requested` is every duration the production loop asked for, and
    # `measured_sleeps` is the interval the probe brackets between the
    # cancellation tick and the next sweep's first attempt. The FINAL
    # request (the one capped to the remaining deadline) has no following
    # sweep - that sweep raises instead - so it is bracketed nowhere and
    # appears only in `requested`.
    requested = clock.sleeps
    expected = _expected_schedule(_WAIT_S)
    assert requested == pytest.approx(expected), (
        f"the requested backoff schedule must be 5 ms doubling to a 200 ms "
        f"ceiling with the final sleep capped to the deadline; "
        f"expected {expected}, requested {requested}"
    )
    assert measured_sleeps == pytest.approx(expected[:-1]), (
        f"each bracketed interval must equal the requested sleep; "
        f"expected {expected[:-1]}, measured {measured_sleeps}"
    )
    assert len(measured_sleeps) == len(requested) - 1, (
        f"every requested sleep but the last must be bracketed; "
        f"requested {len(requested)}, measured {len(measured_sleeps)}")
    assert len(measured_sleeps) >= 7, (
        f"backoff sequence too short to show ramp+ceiling: {measured_sleeps}")
    first_ms = measured_sleeps[0] * 1000
    assert first_ms == pytest.approx(5.0), (
        f"the first sleep must be exactly the model's 5 ms; got {first_ms:.1f} ms")
    ramp = measured_sleeps[:6]
    assert ramp == pytest.approx([0.005, 0.01, 0.02, 0.04, 0.08, 0.16]), (
        f"the ramp must double exactly from 5 ms; got {ramp}")
    peak = next((i for i, sl in enumerate(measured_sleeps) if sl >= 0.185),
                None)
    assert peak is not None and peak >= 3, (
        f"no ceiling sleep (>= 150 ms) reached by the ramp; sleeps: "
        f"{[round(s * 1000, 1) for s in measured_sleeps]}")
    for i in range(peak + 1, len(measured_sleeps)):
        plateau = measured_sleeps[i] * 1000
        assert plateau == pytest.approx(200.0), (
            f"post-peak sleep {i} must hold the 200 ms ceiling plateau; "
            f"got {plateau:.1f} ms")
    max_ms = max(measured_sleeps) * 1000
    assert max_ms == pytest.approx(200.0), (
        f"the ceiling sleep must be exactly 200 ms; got {max_ms:.1f} ms from "
        f"{[round(s * 1000, 1) for s in measured_sleeps]}")
    # The final request is capped to the deadline remainder (and the floor
    # applies when that remainder is under 1 ms).
    capped = requested[-1]
    assert capped < _CEILING, (
        f"the final sleep must be capped to the remaining deadline, not the "
        f"200 ms ceiling; got {capped}")
    assert capped == pytest.approx(_WAIT_S - sum(requested[:-1])), (
        f"the final sleep must equal the remaining deadline budget; "
        f"expected {_WAIT_S - sum(requested[:-1])}, got {capped}")

    # P2 — the sweep COUNT follows from the schedule: the loop sleeps once
    # per sweep and the final sweep raises instead of sleeping, and the
    # cumulative sleep total reaches the 3.0 s window exactly at the last
    # request.
    cumulative = 0.0
    for duration in requested:
        cumulative += duration
    assert cumulative >= _WAIT_S, (
        f"the sleeps must cover the {_WAIT_S} s window; they sum to "
        f"{cumulative:.4f} s")
    assert cumulative - requested[-1] < _WAIT_S, (
        f"the last sleep is the one that crosses the window; the previous "
        f"total was {cumulative - requested[-1]:.4f} s")
    # Every sweep that reached the attempt loop slept exactly once, and the
    # sweep that finally raises does so on the in-sweep deadline check
    # BEFORE any attempt, so the counted sweeps equal the requests.
    assert sweeps == len(requested), (
        f"expected {len(requested)} backoff sweeps in {_WAIT_S} s "
        f"(the fixed 50 ms cadence would do 61); got {sweeps} sweeps "
        f"({len(stamps)} attempts), sleeps "
        f"{[round(s * 1000, 1) for s in requested]}"
    )
    # The contract the sweep count exists for: the backoff performs far
    # fewer lock attempts over the window than the fixed 50 ms cadence.
    fixed_cadence_attempts = int(_WAIT_S / 0.05)
    assert len(stamps) < fixed_cadence_attempts, (
        f"the backoff must make fewer attempts than the fixed 50 ms cadence "
        f"would over {_WAIT_S} s (fixed would make about "
        f"{fixed_cadence_attempts}); got {len(stamps)}")

    # P3 — the amendment's arithmetic, recomputed from the MEASURED ceiling
    # and reported; the RATIO assertion is the binding part: a measured
    # ceiling >= 150 ms is >= 3x the fixed cadence, so the 600 s attempt
    # reduction is >= ~3x (315 ms ramp + 200 ms ceiling -> 3005 vs 12000 =
    # 3.99x).
    ceiling_ms = max_ms
    ramp_ms = sum(measured_sleeps[:6]) * 1000
    window_ms = 600_000.0
    backoff_attempts = 1 + 6 + max(0.0, (window_ms - ramp_ms) / ceiling_ms - 1)
    fixed_attempts = window_ms / 50.0
    ratio = fixed_attempts / backoff_attempts
    print(f"MEASURED ramp={ramp_ms:.1f} ms ceiling={ceiling_ms:.1f} ms -> "
          f"600 s window: attempts={backoff_attempts:.0f} "
          f"fixed-cadence={fixed_attempts:.0f} ratio={ratio:.3f}")
    assert ratio >= 3.0, (
        f"the amended AC3 target (~4x, floor 3x) requires ratio >= 3; "
        f"measured {ratio:.3f} from ceiling {ceiling_ms:.1f} ms"
    )

    # P4b — snapshot-clean: the failed waiter stranded no slot lock. Release
    # both holders; a fresh acquire must succeed immediately. The fresh
    # acquisition is a slot too, so it is released on every path.
    for fd in holders:
        pswindows._release_ps_slot(fd)
    fresh = pswindows._acquire_ps_slot()
    try:
        assert fresh is not None, (
            "a fresh acquire must succeed once the holders release (the failed "
            "waiter leaked a slot lock)"
        )
    finally:
        if fresh is not None:
            pswindows._release_ps_slot(fresh)


def test_sub_ms_deadline_remaining_hits_the_1ms_floor(pool_env, monkeypatch):
    """The `max(deadline - time.monotonic(), 0.001)` floor is REALLY engaged.

    The shipped backoff expression floors every sleep at 1 ms, but the floor
    only bites when the remaining deadline drops BELOW 1 ms - no executed
    case in the schedule probe above drives that (its 3.0 s window ends on a
    deadline-CAPPED final sleep, not a floored one). This leg drives the
    PRODUCTION loop itself - not a re-implementation of the formula - with a
    budget of 0.3155 s: the plain ramp (5+10+20+40+80+160 ms) consumes
    0.315 s, so the next sleep faces a 0.5 ms remainder and must REQUEST
    exactly the 1 ms floor. A mutant that dropped the floor requests the
    0.5 ms remainder instead; a mutant that dropped the cap requests the raw
    backoff earlier in the ramp and dies on the prefix assertion.
    """
    clock = VirtualClock()
    monkeypatch.setattr(pswindows, "time", clock)
    monkeypatch.setattr(pswindows, "_config", _pool_cfg(pool_env.dir, _FLOOR_WAIT_S))
    with no_real_sleep():
        holders = [pswindows._acquire_ps_slot() for _ in range(_CAP)]
        assert all(fd is not None for fd in holders), "harness must hold every slot"
        # The main thread drives the production acquire loop against the
        # saturated pool: sweep, fail, sleep - until the budget is spent.
        with pytest.raises(pswindows.PowerShellBusy):
            pswindows._acquire_ps_slot()
        for fd in holders:
            pswindows._release_ps_slot(fd)
        fresh = pswindows._acquire_ps_slot()
        assert fresh is not None, "the failed waiter leaked a slot lock"
        pswindows._release_ps_slot(fresh)
    requested = clock.sleeps
    ramp = [_FIRST_SLEEP, 0.01, 0.02, 0.04, 0.08, 0.16]
    assert requested[:-1] == pytest.approx(ramp), (
        f"the ramp before the floor case must be the plain doubling ladder; "
        f"got {requested}"
    )
    remainder = _FLOOR_WAIT_S - sum(ramp)
    assert 0.0 < remainder < _SLEEP_FLOOR, (
        f"the harness must leave a sub-floor positive remainder; got {remainder}"
    )
    assert requested[-1] == pytest.approx(_SLEEP_FLOOR), (
        f"a remaining deadline of {remainder * 1000:.2f} ms must request the "
        f"1 ms floor exactly; got {requested[-1]} (requests: {requested})"
    )
    assert requested[-1] > remainder, (
        f"the final request must EXCEED the remaining deadline - the floor "
        f"engaged rather than the deadline cap; request {requested[-1]}, "
        f"remainder {remainder}"
    )
