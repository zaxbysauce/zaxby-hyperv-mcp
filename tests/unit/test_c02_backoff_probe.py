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
schedule), and asserts:

  P1  the first 7 inter-sweep sleeps are 5, 10, 20, 40, 80, 160, 200 ms and
      every subsequent sleep sits at the 200 ms ceiling (the final one or
      two sleeps may be capped to the remaining deadline), with the
      per-sweep timestamps within ±25 ms of the model's cumulative
      schedule [0, 5, 15, 35, 75, 155, 315, 515, ...] ms;
  P2  a 3.0 s bounded wait performs 20 (±1) sweeps — a fixed 50 ms cadence
      would perform ~60, so any fixed-cadence or sub-ceiling mutant is
      caught here (the mutant-kill run is Phase 4; this file is the
      arm's-length green leg at base);
  P3  the amendment's published 600 s-window figures extrapolate from the
      MEASURED ramp and ceiling period: backoff attempts ≈ 3005 (assert
      3004..3007), fixed-cadence counterfactual 12000, ratio ≈ 3.99
      (assert 3.90 <= ratio <= 4.05);
  P4  the busy contract survives inside the same probe run: the waiter
      raises PowerShellBusy naming 'saturated', and its permit accounting
      closes cleanly — the failed waiter stranded no slot lock (a fresh
      acquire succeeds immediately once the holders release).

Hermetic: no PowerShell spawn, no host, no network (the pool-identity
fixture pattern from test_c02_pool_identity.py: temp slot dir, config
seam, captured log lines). The file's whole runtime is ~3.3 s — the one
bounded wait plus pool teardown.
"""

import json
import math
import statistics
import threading
import time
from types import SimpleNamespace

import pytest

from hyperv_mcp import pswindows

_META_NAME = "pool.meta"
_CAP = 2
_WAIT_S = 3.0

# The amended-AC3 ceiling model: inter-sweep sleeps (seconds) and the
# cumulative sweep-start schedule they imply (anchored at sweep 0).
_MODEL_SLEEPS = [0.005, 0.010, 0.020, 0.040, 0.080, 0.160, 0.200]
_MODEL_CUM = [0.0]
for _sleep_s in _MODEL_SLEEPS:
    _MODEL_CUM.append(_MODEL_CUM[-1] + _sleep_s)
# ±25 ms: the probe's timestamp tolerance (the amendment's own band). The
# stamps use perf_counter, so the measured schedule tracks the model to
# ~1 ms on a healthy host; the band also absorbs scheduler jitter.
_TOL_S = 0.025


def _pool_cfg(slot_dir, wait_s: float) -> SimpleNamespace:
    return SimpleNamespace(
        max_host_powershell=_CAP,
        host_powershell_wait_s=wait_s,
        ps_slot_dir=str(slot_dir),
    )


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


def test_backoff_attempt_schedule_matches_ceiling_model(pool_env, monkeypatch):
    """P1..P4 (module docstring): the measured sweep schedule of a saturated
    cap-2 pool equals the 5 ms-doubling/200 ms-ceiling model, the 3.0 s
    window performs 20 (±1) sweeps, the amendment's 600 s figures
    extrapolate from the measured period, and the busy/no-leak contracts
    hold inside the same run."""
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
    # The stamps use perf_counter (QPC, sub-microsecond): on Windows
    # time.monotonic can be GetTickCount64-quantized to the 15.625 ms
    # scheduler tick, which would blur the 5/10/20 ms ramp legs into one
    # reading. This is the probe's own instrumentation; pswindows keeps its
    # own (monotonic) deadline math untouched.
    stamps: list[float] = []  # one perf_counter() per worker attempt

    def _counting_try_lock(path):
        if threading.get_ident() != main_tid:
            stamps.append(time.perf_counter())
        return real_try_lock(path)

    monkeypatch.setattr(pswindows, "_try_lock_slot", _counting_try_lock)

    # Stamp the return of each cancellation tick too: a failed sweep runs
    # _check_ps_cancellation() BETWEEN its attempts and its sleep, and the
    # seam's FIRST call in a fresh process pays a one-time ~30 ms anyio /
    # sniffio thread-detection initialization that is not part of the
    # backoff schedule (its per-tick observance is pinned separately by
    # test_c02_pool_identity.py's cancellation test).
    real_check = pswindows._check_ps_cancellation
    check_ends: list[float] = []

    def _stamping_check():
        real_check()
        if threading.get_ident() != main_tid:
            check_ends.append(time.perf_counter())

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

    # The measured schedule. One timestamp per attempt, cap attempts per
    # sweep; each sleep is BRACKETED as (first attempt of sweep i+1) minus
    # (return of the cancellation tick after sweep i), so the measured
    # interval is the sleep itself plus the loop-around and the next first
    # file-open attempt — the sweep's own file-lock work and the
    # cancellation seam's one-time initialization must not inflate the
    # schedule. The FINAL sweep may be truncated by the in-sweep deadline
    # check; sweeps counts it, the schedule below is built only over full
    # sweeps.
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
    print("SWEEP-TS-MS:", [round((t - sweep_starts[0]) * 1000, 1) for t in sweep_starts])
    print("SLEEPS-MS:", [round(s * 1000, 1) for s in measured_sleeps])

    # P2 — 20 (±1) sweeps inside the 3.0 s bounded wait.
    assert 19 <= sweeps <= 21, (
        f"a 3.0 s bounded wait must sweep ~20 times under the ceiling model; "
        f"measured {sweeps} sweeps ({len(stamps)} attempts), "
        f"sleeps {[round(s * 1000) for s in measured_sleeps]}"
    )

    # P1 — the ramp plus the first ceiling sleep, then the steady ceiling.
    assert len(measured_sleeps) >= 8, (
        f"schedule too short to show ramp + ceiling: {measured_sleeps}"
    )
    for i, model_s in enumerate(_MODEL_SLEEPS):
        assert abs(measured_sleeps[i] - model_s) <= _TOL_S, (
            f"sleep {i} must be {model_s * 1000:.0f} ms (±25 ms); got "
            f"{measured_sleeps[i] * 1000:.1f} ms in "
            f"{[round(s * 1000, 1) for s in measured_sleeps]}"
        )
    # Cumulative sleep schedule vs the model: the cumulative sum of the
    # bracketed sleeps (the per-sweep schedule anchored at sweep 0) tracks
    # [0, 5, 15, 35, 75, 155, 315, 515, ...] ms within ±25 ms; the repeating
    # tail beyond 515 ms is bound by the ceiling checks and the sweep count.
    cumulative = 0.0
    for k in range(len(_MODEL_CUM)):
        assert k < len(measured_sleeps) + 1, "schedule shorter than the ramp anchors"
        assert abs(cumulative - _MODEL_CUM[k]) <= _TOL_S, (
            f"the cumulative sleep schedule must be within ±25 ms of the model "
            f"at sweep {k} (model {_MODEL_CUM[k] * 1000:.0f} ms); got "
            f"{cumulative * 1000:.1f} ms from {[round(s * 1000, 1) for s in measured_sleeps]}"
        )
        if k < len(measured_sleeps):
            cumulative += measured_sleeps[k]
    tail = measured_sleeps[len(_MODEL_SLEEPS):]
    strict_tail = tail[:-2]  # the last sleep(s) may be deadline-capped
    assert strict_tail, "schedule must include steady-state ceiling sleeps"
    for s in strict_tail:
        assert abs(s - 0.2) <= _TOL_S, (
            f"steady-state sleeps must sit at the 200 ms ceiling; got "
            f"{[round(s * 1000, 1) for s in measured_sleeps]}"
        )
    for s in tail[-2:]:
        assert s <= 0.2 + _TOL_S, (
            f"a sleep exceeded the ceiling (only deadline caps may shorten): "
            f"{[round(s * 1000, 1) for s in measured_sleeps]}"
        )

    # P3 — extrapolate the amendment's 600 s figures from the MEASURED
    # ramp (6 sleeps; model 315 ms) and ceiling period. The ceiling is
    # quantized to the model's 10 ms scheduling quantum after the band
    # check: sub-quantum timer wobble must not move a 600 s extrapolation
    # by ±60 attempts (1 ms of ceiling ≈ 15 attempts).
    ramp_ms = sum(measured_sleeps[:6]) * 1000.0
    full_ceiling = [s for s in tail if s >= 0.15]  # drops deadline-capped tail
    assert len(full_ceiling) >= 8, (
        f"not enough steady-ceiling sleeps to measure the period: {measured_sleeps}"
    )
    ceiling_ms_raw = statistics.mean(full_ceiling) * 1000.0
    assert 190.0 <= ceiling_ms_raw <= 210.0, (
        f"the measured ceiling period must sit at the 200 ms model; got "
        f"{ceiling_ms_raw:.1f} ms"
    )
    ceiling_ms = round(ceiling_ms_raw / 10.0) * 10.0
    attempts_600s = round(1 + 6 + (600_000.0 - ramp_ms) / ceiling_ms)
    fixed_600s = round(600_000.0 / 50.0)  # the fixed 50 ms cadence counterfactual
    ratio = fixed_600s / attempts_600s
    print(f"MEASURED ramp={ramp_ms:.1f} ms ceiling={ceiling_ms_raw:.1f} ms -> "
          f"600 s window: attempts={attempts_600s} fixed-cadence={fixed_600s} "
          f"ratio={ratio:.3f}")
    assert 3004 <= attempts_600s <= 3007, (
        f"the 600 s extrapolation must reproduce the amendment's ~3005 "
        f"attempts (measured ramp {ramp_ms:.1f} ms, ceiling {ceiling_ms:.0f} ms "
        f"-> {attempts_600s})"
    )
    assert fixed_600s == 12000, (
        f"the fixed-cadence counterfactual for 600 s is 12000; got {fixed_600s}"
    )
    assert 3.90 <= ratio <= 4.05, (
        f"the attempt-reduction ratio must reproduce the amendment's ~3.99; "
        f"got {ratio:.3f}"
    )

    # P4b — snapshot-clean: the failed waiter stranded no slot lock. Release
    # both holders; a fresh acquire must succeed immediately.
    for fd in holders:
        pswindows._release_ps_slot(fd)
    fresh = pswindows._acquire_ps_slot()
    assert fresh is not None, (
        "a fresh acquire must succeed once the holders release (the failed "
        "waiter leaked a slot lock)"
    )
    pswindows._release_ps_slot(fresh)
