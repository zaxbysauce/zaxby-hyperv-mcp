"""REAL-clock HYGIENE smoke for the c02 backoff path (issue #167 AC2).

WHAT THIS FILE PROVES: the real-clock path still terminates on its own,
still raises the documented busy refusal, and still releases every pool
slot it took. That is a HYGIENE property, not a schedule property.

THE SCHEDULE CLAIM IS EXPLICITLY WAIVED HERE. The requested schedule
(5 ms doubling to the 200 ms ceiling) is asserted EXACTLY, against a
virtual clock, in test_c02_backoff_probe.py: there the production loop
asks to sleep, the clock records the REQUESTED duration and advances
virtual time, and the requested schedule is compared byte for byte. That
is the deterministic contract, and it is the only place the schedule is
asserted.

A real-clock schedule assertion is what AC2 removes: on a loaded CI
runner a CORRECT schedule can produce an adjacent-sleep ratio below 1
(the issue records 0.69x, because the earlier sleep was delayed more
than the next), a first sleep far past the model's 5 ms, and a ramp that
never reaches the ceiling before its wall-clock deadline expires. Any of
those would be a false red. So this file OBSERVES the measured
intervals, reports them, and asserts NOTHING about their values, their
number, or their ratios. The intervals are printed for a human reader.

This file used to be named `test_c02_backoff_schedule_smoke.py` and to
call itself a "realized-schedule smoke", which claimed a coverage its
assertions did not provide. It is now named and documented for what it
actually asserts - the hygiene properties above - and the realized-
schedule coverage is WAIVED, which is the disposition AC2's own scope
allows ("a tolerant realized-schedule smoke kept separately or explicitly
waived").

It lives in its own file on purpose: the frozen check C2 measures the
summed pytest CALL duration of the two c02 files, and a real-clock smoke
inside them would put wall-clock time back into that budget.
"""

import json
import math
import threading
import time
from types import SimpleNamespace

import pytest

from hyperv_mcp import pswindows

_META_NAME = "pool.meta"
_CAP = 2
_WAIT_S = 0.6


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


def test_the_real_clock_path_terminates_and_releases_its_slots(pool_env, monkeypatch):
    """The REAL clock path terminates, refuses, and leaks no slot.

    Nothing about the measured intervals is asserted: the exact schedule
    is pinned by the virtual-clock probe, and every bound that could be
    written against real measurements is scheduler-sensitive (the issue
    records a 0.69x adjacent-sleep ratio on a loaded runner for a
    CORRECT schedule). The intervals are observed and printed. What IS
    asserted is the hygiene the real path must keep: the waiter
    terminates on its own, it raises the documented busy refusal, and
    every slot this test took is released on every path.
    """
    holders: list[int] = []
    try:
        for _ in range(_CAP):
            holders.append(pswindows._acquire_ps_slot())
        assert all(fd is not None for fd in holders), "harness must hold every slot"
        payload = json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
        assert payload.get("cap") == _CAP, f"pool.meta must record cap {_CAP}: {payload}"

        monkeypatch.setattr(pswindows, "_config", _pool_cfg(pool_env.dir, _WAIT_S))
        main_tid = threading.get_ident()
        real_try_lock = pswindows._try_lock_slot
        stamps: list[float] = []

        def _counting_try_lock(path):
            if threading.get_ident() != main_tid:
                stamps.append(time.perf_counter())
            return real_try_lock(path)

        monkeypatch.setattr(pswindows, "_try_lock_slot", _counting_try_lock)

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
        # DEADLOCK PROTECTION, not a scheduler-independent claim: the waiter
        # must terminate on its own inside a generous real-time budget. A
        # worker starved for the whole budget would fail this even with a
        # correct implementation, so the bound is deliberately wide - the
        # exact schedule is asserted by the virtual-clock test, which has no
        # scheduler in its loop.
        waiter.join(timeout=30)
        assert not waiter.is_alive(), "the bounded wait must terminate on its own"
        assert isinstance(outcome.get("error"), pswindows.PowerShellBusy), (
            f"the saturated waiter must raise PowerShellBusy; got {outcome!r}"
        )

        assert stamps, "the waiter never attempted a slot lock"
        n_full = len(stamps) // _CAP
        sweep_starts = [stamps[i * _CAP] for i in range(n_full)]
        assert len(check_ends) >= n_full - 1, (
            f"cancellation ticks not observed per failed sweep: {len(check_ends)}"
        )
        measured = [sweep_starts[i + 1] - check_ends[i] for i in range(n_full - 1)]
        # OBSERVED, not asserted: the values are reported so a human can see
        # what the runner did, and no bound is derived from them.
        print("REAL-CLOCK SLEEPS-MS:", [round(s * 1000, 1) for s in measured])
        # NOTHING is asserted about the measured intervals. Every bound that
        # could be written against real measurements is scheduler-sensitive: a
        # waiter can observe one short early interval and then be delayed
        # (the issue records a 0.69x adjacent-sleep ratio on a loaded runner
        # for a CORRECT schedule), and reaching the ceiling before the
        # wall-clock deadline depends on how much time the runner leaves. The
        # intervals are OBSERVED and REPORTED; the exact schedule is asserted
        # by the virtual-clock test, which has no scheduler in its loop.
        # The OBSERVATION is what is waived when the ramp was not observed -
        # NOT the hygiene check below, which runs on every path.

    finally:
        for fd in holders:
            pswindows._release_ps_slot(fd)
    # The SLOT-RELEASE check runs whatever the scheduler did: the fresh
    # acquisition must succeed once the holders release, which is exactly
    # the property that a failed waiter leaked a slot lock would break.
    # It must not sit behind the timing observation's waiver (the round-15
    # implementation reviewer's finding: the old `pytest.skip` on the
    # no-ramp path skipped this check too).
    fresh = pswindows._acquire_ps_slot()
    assert fresh is not None, (
        "a fresh acquire must succeed once the holders release (the failed "
        "waiter leaked a slot lock)"
    )
    # The fresh acquisition is a slot too: it is released here, on every
    # path this test can take.
    try:
        if measured:
            assert math.isfinite(measured[0]), "the measured sleep must be finite"
    finally:
        pswindows._release_ps_slot(fresh)
    if not measured:
        # The timing OBSERVATION is unavailable on this host; the hygiene
        # properties above were asserted and passed. The test reports the
        # waiver rather than skipping, so a skip never hides a failed
        # slot-release check.
        print("REAL-CLOCK OBSERVATION WAIVED: the ramp was not observed on "
              "this host (scheduler delay); the schedule is asserted by the "
              "virtual-clock test")
