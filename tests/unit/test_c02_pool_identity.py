"""Issue #64 (wave 59-64-68-70-hardening) — slot-pool identity + polite waiting.

The PR #61 slot pool is correct for the documented single-configuration
deployment. These checks pin the wave's new robustness behavior:

  W2.1  the slot directory records the pool's cap once (a discoverable
        pool.meta marker); a process whose configured cap or slot dir
        diverges from the recorded/host-visible default logs a warning
        naming both values; the effective host-wide bound is the recorded
        pool cap (a cap-64 process cannot exceed a recorded cap-8 pool).
        Publication is atomic (tmp + rename): a reader never observes a
        partial marker, and a corrupt/unreadable marker never silently
        authorizes the local cap — it logs a loud warning naming the
        marker and re-publishes.
  W2.2  the bounded-wait acquire loop backs off exponentially (5 ms doubling
        to a 200 ms ceiling), caps each sleep to the remaining deadline,
        and still observes cancellation each tick.
  W2.3  (frozen test_c02_ps_cap.py, unchanged) the busy-envelope contract
        is preserved — this file carries only the companions this module
        can observe directly.

All legs are hermetic: no real PowerShell, host, network, or secret. The
W2.2 backoff legs run the production acquire loop against the virtual clock
(tests/unit/_c02_virtual_clock.py) under the no_real_sleep() prohibition -
the slot file locking stays REAL, the waiting is event-driven virtual time,
and a real time.sleep anywhere in the block fails the test outright. The
RED signature at base is the file itself (pytest exit 4, NEW-SURFACE);
each behavioral test below FAILS on the pre-fix tree for the named reason.
"""

import json
import re
import threading
from types import SimpleNamespace

import pytest
from _c02_virtual_clock import (
    VirtualClock,
    assert_no_cached_sleep_references,
    no_real_sleep,
)

from hyperv_mcp import errors, pswindows

_META_NAME = "pool.meta"


def _pool_cfg(cap: int, slot_dir, wait_s: float = 5.0):
    return SimpleNamespace(
        max_host_powershell=cap,
        host_powershell_wait_s=wait_s,
        ps_slot_dir=str(slot_dir),
    )


@pytest.fixture()
def pool_env(tmp_path, monkeypatch):
    """Isolated slot dir + config seam + log capture."""
    slot_dir = tmp_path / "slots"
    slot_dir.mkdir()
    logs: list[str] = []

    def _capture(*parts, **kwargs):
        logs.append(" ".join(str(p) for p in parts))

    monkeypatch.setattr(pswindows.logemit, "log_line", _capture)
    monkeypatch.setattr(pswindows, "_config", _pool_cfg(4, slot_dir))
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


def test_pool_cap_marker_written_once(pool_env):
    """First pool use writes pool.meta with the configured cap, exactly once
    (W2.1); the marker is never rewritten with a divergent cap."""
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    meta = pool_env.dir / _META_NAME
    assert meta.exists(), "the slot directory must record the pool cap"
    payload = json.loads(meta.read_text(encoding="utf-8"))
    assert payload.get("cap") == 4
    pswindows._config = _pool_cfg(4, pool_env.dir)
    fd2 = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd2)
    payload2 = json.loads(meta.read_text(encoding="utf-8"))
    assert payload2.get("cap") == 4, "marker cap must never be rewritten"


def test_cap_divergence_warns_and_honors_recorded_cap(pool_env, monkeypatch):
    """A cap-64 process meeting a recorded cap-4 pool warns naming both caps
    and sweeps only the recorded cap's slot files (W2.1 effective bound)."""
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    assert (pool_env.dir / _META_NAME).exists()

    pswindows._config = _pool_cfg(64, pool_env.dir)
    attempted: list[str] = []
    real_try_lock = pswindows._try_lock_slot

    def _recording_try_lock(path):
        attempted.append(path.name)
        return real_try_lock(path)

    monkeypatch.setattr(pswindows, "_try_lock_slot", _recording_try_lock)
    fd2 = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd2)
    assert attempted, "the divergent process must still acquire"
    assert all(
        name in {"slot-00.lock", "slot-01.lock", "slot-02.lock", "slot-03.lock"}
        for name in attempted
    ), f"cap-64 swept outside the recorded cap-4 pool: {sorted(set(attempted))}"
    caps_named = [ln for ln in pool_env.logs
                  if re.search(r"\b64\b", ln) and re.search(r"\b4\b", ln)
                  and "cap" in ln.lower()]
    assert caps_named, f"cap-divergence warning naming both values missing: {pool_env.logs}"


def test_dir_divergence_warns_once(pool_env):
    """A caller-named slot dir differing from the platform default warns
    once, naming both directories (W2.1)."""
    default_dir = pswindows._default_ps_slot_dir()
    assert str(pool_env.dir) != str(default_dir)
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    named = [ln for ln in pool_env.logs
             if str(pool_env.dir) in ln and str(default_dir) in ln]
    assert named, f"dir-divergence warning naming both dirs missing: {pool_env.logs}"
    fd2 = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd2)
    assert len([ln for ln in pool_env.logs
                if str(pool_env.dir) in ln and str(default_dir) in ln]) == 1


def test_corrupt_marker_warns_and_repairs(pool_env):
    """A corrupt/unreadable pool.meta never silently authorizes the local
    cap (W2.1): the reader logs a loud warning naming the marker and
    republishes it (a partial-write legacy from a non-atomic creator is
    repaired on first read)."""
    (pool_env.dir / _META_NAME).write_text('{"cap": ', encoding="utf-8")
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    named = [ln for ln in pool_env.logs if _META_NAME in ln
             and ("unreadable" in ln or "corrupt" in ln)]
    assert named, f"corrupt-marker warning missing: {pool_env.logs}"
    payload = json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert payload.get("cap") == 4, "the corrupt marker must be republished"


def test_acquire_backoff_and_release_latency(pool_env, monkeypatch):
    """The bounded-wait acquire backs off exponentially (5 ms doubling to a
    200 ms ceiling) and BOTH real waiters acquire within one backoff interval
    (250 ms) of their release (W2.2) - on EVENT-DRIVEN VIRTUAL time, with a
    direct real-sleep prohibition, and no wall-clock MEASUREMENT of the
    schedule anywhere (the harness's own condition waits use the real clock
    purely as deadlock protection, never as a measurement).

    The production acquire loop runs against a GATED VirtualClock: each
    backoff request is recorded and virtual time advances by exactly that
    amount, then the waiter PARKS until the test permits one further sleep,
    so the requested schedule is observed one sleep at a time with no race.
    The two waiters still contend for a REAL slot file lock (the production
    locking is real and stays real); only the WAITING is virtual. The
    release-to-acquire property is asserted on the virtual clock: only a
    sleep request can move virtual time, so the virtual gap counts exactly
    the post-release backoff the waiter needed (zero for a correct release;
    a mutant that makes the waiter wait several intervals accumulates those
    durations - and its extra requests - and fails).
    """
    clock = VirtualClock()
    clock.enable_gating()
    monkeypatch.setattr(pswindows, "time", clock)
    monkeypatch.setattr(pswindows, "_config",
                        _pool_cfg(1, pool_env.dir, wait_s=10.0))

    results: dict = {}
    acquires: dict = {}
    failures: dict = {}
    waiters: list[threading.Thread] = []

    def _waiter(tag):
        try:
            fd = pswindows._acquire_ps_slot()
        except BaseException as exc:  # noqa: BLE001 - recorded, asserted below
            failures[tag] = exc
        else:
            results[tag] = fd
            acquires[tag] = clock.monotonic()

    with no_real_sleep():
        try:
            holder_fd = pswindows._acquire_ps_slot()  # take the only slot
            assert holder_fd is not None

            waiter_a = threading.Thread(target=_waiter, args=("a",), daemon=True)
            waiters.append(waiter_a)
            waiter_a.start()

            # Drive the backoff one request at a time: after each permit the
            # waiter really sweeps, really fails (the slot is really held),
            # and requests its next backoff sleep, parking again. Exact
            # exponential shape: 5 ms doubling through the ramp, then the
            # 200 ms ceiling constant (a mutant that sleeps 5 ms once and
            # then a constant 200 ms fails the ramp equality).
            expected = [0.005, 0.01, 0.02, 0.04, 0.08, 0.16, 0.2, 0.2]
            for count in range(1, len(expected) + 1):
                assert clock.wait_for_sleeps(count), (
                    f"waiter A never requested backoff sleep {count}"
                )
                seen = clock.sleeps
                assert len(seen) == count, (
                    f"the gated waiter must be parked on sleep {count}; "
                    f"observed {seen}"
                )
                assert seen == pytest.approx(expected[:count]), (
                    f"backoff ramp must be 5 ms doubling to the 200 ms "
                    f"ceiling; expected {expected[:count]}, requested {seen}"
                )
                # The LAST request of the ramp is deliberately NOT permitted
                # here: the waiter stays parked INSIDE it until the slot is
                # released below. Permitting it before the release would
                # let the worker sweep the STILL-HELD slot and ask for a
                # ninth backoff - a spurious extra request caused by the
                # harness ordering, not by a production defect.
                if count < len(expected):
                    clock.permit_one_sleep()

            # Release, THEN permit: the waiter wakes from its final parked
            # backoff, sweeps, and finds the slot free, so it acquires on
            # the FIRST sweep after the release, requesting no further sleep.
            release_virtual = clock.now
            pswindows._release_ps_slot(holder_fd)
            clock.permit_one_sleep()
            waiter_a.join(timeout=5)
            assert not waiter_a.is_alive(), "waiter A never acquired after release"
            assert "a" not in failures, f"waiter A raised: {failures['a']!r}"
            assert results.get("a") is not None
            assert len(clock.sleeps) == len(expected), (
                f"waiter A needed further backoff sleeps after its release: "
                f"{clock.sleeps[len(expected):]}"
            )
            a_gap = acquires["a"] - release_virtual
            assert a_gap <= 0.25, (
                f"release-to-acquire must sit within one backoff interval "
                f"(250 ms) of VIRTUAL time; got {a_gap:.3f}s"
            )

            # Second waiter: still parked while A held the slot (following
            # the same ramp), then acquires within one interval of A's
            # release.
            base = len(clock.sleeps)
            waiter_b = threading.Thread(target=_waiter, args=("b",), daemon=True)
            waiters.append(waiter_b)
            waiter_b.start()
            b_ramp = [0.005, 0.01, 0.02]
            for count in range(1, len(b_ramp) + 1):
                assert clock.wait_for_sleeps(base + count), (
                    f"waiter B never requested backoff sleep {count}"
                )
                assert clock.sleeps[base:] == pytest.approx(b_ramp[:count]), (
                    f"waiter B must follow the same ramp; expected "
                    f"{b_ramp[:count]}, requested {clock.sleeps[base:]}"
                )
                # As with waiter A: the final request stays parked until
                # the holder is released below, so the worker never sweeps a
                # still-held slot and asks for an extra backoff.
                if count < len(b_ramp):
                    clock.permit_one_sleep()
            release_virtual_b = clock.now
            pswindows._release_ps_slot(results["a"])
            clock.permit_one_sleep()
            waiter_b.join(timeout=5)
            assert not waiter_b.is_alive(), "waiter B never acquired after release"
            assert "b" not in failures, f"waiter B raised: {failures['b']!r}"
            assert results.get("b") is not None
            assert len(clock.sleeps) == base + len(b_ramp), (
                f"waiter B needed further backoff sleeps after its release: "
                f"{clock.sleeps[base + len(b_ramp):]}"
            )
            b_gap = acquires["b"] - release_virtual_b
            assert b_gap <= 0.25, (
                f"second release-to-acquire must sit within one backoff "
                f"interval (250 ms) of VIRTUAL time; got {b_gap:.3f}s"
            )
            pswindows._release_ps_slot(results["b"])
        finally:
            # Never leave a worker parked on the gate (a failed assertion
            # above would otherwise leak a blocked daemon into later tests).
            clock.permit_all_sleeps()
            clock.disable_gating()
            for w in waiters:
                w.join(timeout=5)
                assert not w.is_alive(), f"{w.name} never finished"


def test_short_deadline_overshoot_is_bounded(pool_env, monkeypatch):
    """Each backoff sleep is capped to the remaining deadline: a wait budget
    far below the 200 ms ceiling still raises PowerShellBusy promptly
    (W2.2 deadline cap; no 200 ms overshoot) - on the VIRTUAL clock, so the
    deadline-cap arithmetic is asserted EXACTLY and no real sleeping is
    involved: 5 ms + 10 ms + the 15 ms remainder, never a full-ceiling
    request against a 30 ms budget."""
    clock = VirtualClock()
    monkeypatch.setattr(pswindows, "time", clock)
    monkeypatch.setattr(pswindows, "_config",
                        _pool_cfg(1, pool_env.dir, wait_s=0.03))
    with no_real_sleep():
        holder_fd = pswindows._acquire_ps_slot()
        started = clock.monotonic()
        with pytest.raises(pswindows.PowerShellBusy):
            pswindows._acquire_ps_slot()
        elapsed = clock.monotonic() - started
        pswindows._release_ps_slot(holder_fd)
    requested = clock.sleeps
    # The deadline-cap arithmetic, exactly: the third sleep is capped to the
    # 15 ms REMAINDER of the 30 ms budget instead of the 20 ms backoff (a
    # full-ceiling request with a 30 ms budget is the defect this pins).
    assert requested == pytest.approx([0.005, 0.01, 0.015]), (
        f"requested sleeps must be the ramp capped to the remaining "
        f"deadline; got {requested}"
    )
    assert max(requested) <= 0.03 + 1e-9, (
        f"requested sleeps must be capped to the remaining deadline; got {requested}"
    )
    assert elapsed == pytest.approx(0.03), (
        f"a short-deadline wait must cover exactly its budget on the virtual "
        f"clock; got {elapsed:.4f}s"
    )
    assert elapsed <= 0.03 + 0.1, (
        f"a short-deadline wait must not overshoot by a full ceiling; got {elapsed:.3f}s"
    )


def test_attempt_count_reduced_under_saturation(pool_env, monkeypatch):
    """Bounded attempt-count probe (issue #64 AC3): over a saturated window
    the exponential backoff performs far fewer lock attempts per waiter than
    the fixed 50 ms cadence would (measured; the fixed-cadence count for
    the same window is recorded alongside).

    The window is measured on a VIRTUAL clock (issue #167 AC2): the pool
    loop asks to sleep, the clock records the requested duration and
    advances virtual time, so the attempt count and the window are exact
    rather than a wall-clock measurement that CI jitter could inflate.
    """
    clock = VirtualClock()
    monkeypatch.setattr(pswindows, "time", clock)
    pswindows._config = _pool_cfg(1, pool_env.dir, wait_s=1.5)
    holder_fd = pswindows._acquire_ps_slot()
    attempts = {"n": 0}
    my_tid = threading.get_ident()
    real_try_lock = pswindows._try_lock_slot

    def _counting_try_lock(path):
        # Count ONLY this test's thread: a leaked acquire loop from an
        # earlier failed test must not pollute the measurement.
        if threading.get_ident() == my_tid:
            attempts["n"] += 1
        return real_try_lock(path)

    pswindows._try_lock_slot = _counting_try_lock
    sleeps_seen: list[float] = []
    try:
        with no_real_sleep():
            started = clock.monotonic()
            # The bound method is captured BEFORE the attribute is replaced:
            # `pswindows.time` IS the clock here, so replacing `sleep` on it
            # and then calling `clock.sleep` would recurse into the
            # replacement.
            clock_sleep = clock.sleep

            def _spy_sleep(d):
                sleeps_seen.append(float(d))
                clock_sleep(d)

            pswindows.time.sleep = _spy_sleep
            try:
                with pytest.raises(pswindows.PowerShellBusy):
                    pswindows._acquire_ps_slot()
            finally:
                pswindows.time.sleep = clock_sleep
            window = clock.monotonic() - started
    finally:
        pswindows._try_lock_slot = real_try_lock
    print("SLEEPS:", sleeps_seen[:16], "total", len(sleeps_seen))
    pswindows._release_ps_slot(holder_fd)
    fixed_cadence_floor = int(window / 0.05)  # what the 50 ms loop would do
    assert attempts["n"] < fixed_cadence_floor, (
        f"backoff must reduce attempts vs fixed 50 ms cadence "
        f"(did {attempts['n']}, fixed would do ~{fixed_cadence_floor}, "
        f"window {window:.3f}s)"
    )
    # The measured reduction is recorded for the trace (target ~10x per the
    # issue; the 200 ms ceiling arithmetic yields ~4x steady state — the
    # deviation is disclosed in the PR body, not silently claimed).
    ratio = fixed_cadence_floor / max(attempts["n"], 1)
    print(f"ATTEMPT-REDUCTION-RATIO ~{ratio:.1f}x over {window:.2f}s")
    # The ratio is load-sensitive (deadline-capped end-of-window sleeps
    # inflate the attempt count under load), so the deterministic contract
    # is strictly-fewer-than-fixed; the measured ratio rides the trace for
    # the AC3 disclosure instead of a flaky floor.
    assert attempts["n"] * 2 < fixed_cadence_floor, (
        f"backoff must at least halve attempts vs the fixed cadence "
        f"(did {attempts['n']}, fixed ~{fixed_cadence_floor})"
    )


def test_cancellation_tick_and_busy_envelope_preserved(pool_env, monkeypatch):
    """The acquire loop still observes cancellation each retry tick and the
    saturation contract still raises PowerShellBusy naming the cap (the
    PR-61 contracts; frozen test_c02_ps_cap.py pins the rest) - run on the
    VIRTUAL clock so the 0.3 s bounded wait costs no real sleeping."""
    clock = VirtualClock()
    monkeypatch.setattr(pswindows, "time", clock)
    calls = {"n": 0}
    real_check = pswindows._check_ps_cancellation

    def _counting_check():
        calls["n"] += 1
        real_check()

    pswindows._check_ps_cancellation = _counting_check
    # cap=1 is set BEFORE the holder so the holder occupies slot 0 and the
    # second acquire genuinely saturates (a holder taken at cap 4 occupies
    # slots 1-3 and leaves slot 0 free).
    pswindows._config = _pool_cfg(1, pool_env.dir, wait_s=0.3)
    holder_fd = pswindows._acquire_ps_slot()
    try:
        # wait_s=0.3 of VIRTUAL time: several retry ticks (backoff after the
        # fix) so the cancellation-seam pin bites, at no real-clock cost.
        with no_real_sleep():
            with pytest.raises(pswindows.PowerShellBusy) as excinfo:
                pswindows._acquire_ps_slot()
        assert "saturated" in str(excinfo.value)
        assert "1" in str(excinfo.value)
        assert errors.classify(excinfo.value) == "busy"
    finally:
        pswindows._check_ps_cancellation = real_check
        pswindows._release_ps_slot(holder_fd)
    assert calls["n"] >= 1, "cancellation must still be observed per tick"


def test_marker_publication_arbitration(pool_env, monkeypatch):
    """Concurrent first-use publication is arbitrated (round-2 challenge 5):
    two divergent-cap publishers racing to publish pool.meta produce exactly
    one parseable marker (never partial JSON), and the loser's divergence is
    handled by the normal warning path, not a silent overwrite."""
    import threading as _th

    publish = getattr(pswindows, "_publish_pool_marker", None)
    if publish is None:
        pytest.fail("pswindows._publish_pool_marker missing (marker not implemented)")

    observed: list = []
    errors: list[str] = []
    stop = _th.Event()
    observed_once = _th.Event()

    def _reader():
        while not stop.is_set():
            try:
                raw = (pool_env.dir / _META_NAME).read_text(encoding="utf-8")
            except FileNotFoundError:
                continue
            except (PermissionError, OSError):
                # Transient reader/rename contention on Windows is retryable,
                # not partial JSON (round-3 challenge 3).
                continue
            try:
                observed.append(json.loads(raw).get("cap"))
            except json.JSONDecodeError as exc:
                errors.append(f"partial json: {exc}")
            else:
                observed_once.set()

    reader = _th.Thread(target=_reader, daemon=True)
    reader.start()

    def _publisher(cap):
        publish(pool_env.dir, cap)

    pub_errors: list[str] = []

    def _publisher(cap):
        try:
            publish(pool_env.dir, cap)
        except Exception as exc:
            pub_errors.append(f"{type(exc).__name__}: {exc}")

    a = _th.Thread(target=_publisher, args=(4,))
    b = _th.Thread(target=_publisher, args=(64,))
    a.start()
    b.start()
    a.join(timeout=5)
    b.join(timeout=5)
    assert not pub_errors, f"publisher threads failed: {pub_errors}"
    # Event-driven drain: the reader signals the instant it has parsed the
    # published marker (both publishers have joined by now, so the whole
    # publication race has already been observed). No fixed wall-clock nap;
    # the timeout is deadlock protection only.
    assert observed_once.wait(timeout=2.0), (
        "the concurrent reader never observed the published marker"
    )
    stop.set()
    reader.join(timeout=2)

    assert not errors, f"readers observed partial JSON: {errors[:3]}"
    marker = json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert marker.get("cap") in (4, 64), (
        f"final marker must be one publisher's cap, got {marker}"
    )


def test_corrupt_shapes_all_repaired(pool_env):
    """Every corrupt/unreadable marker shape triggers the loud warn +
    republish contract (implementation review F3): valid-JSON non-object
    (null/list), out-of-range cap, and post-publication deletion."""
    import json as _json

    # Shape A: valid JSON, wrong shape (null).
    (pool_env.dir / _META_NAME).write_text("null", encoding="utf-8")
    pswindows._PS_POOL_STATE.marker_written = True  # prior publication
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    payload = _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert payload == {"cap": 4}, f"null marker not repaired: {payload}"
    assert any("unreadable or corrupt" in ln for ln in pool_env.logs)

    # Shape B: valid JSON object, out-of-range cap.
    pool_env.logs.clear()
    (pool_env.dir / _META_NAME).write_text('{"cap": 100}', encoding="utf-8")
    fd2 = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd2)
    payload2 = _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert payload2 == {"cap": 4}, f"out-of-range marker not repaired: {payload2}"

    # Shape C: deleted after a prior publication (not "first use").
    pool_env.logs.clear()
    (pool_env.dir / _META_NAME).unlink()
    fd3 = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd3)
    payload3 = _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert payload3 == {"cap": 4}, f"deleted marker not republished: {payload3}"
    assert any("missing from slot directory" in ln for ln in pool_env.logs)


def test_publisher_never_publishes_without_the_lock(pool_env, monkeypatch):
    """The publication lock is not best-effort (implementation review F2):
    a publisher that cannot acquire it must NOT publish - the recorded cap
    stays authoritative (first-writer-wins deterministically)."""
    import json as _json

    # First publication records cap 4.
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    assert _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8")) == {"cap": 4}

    # Hold the publication lock and simulate a divergent publisher.
    lock_path = pool_env.dir / "pool.meta.lock"
    held_fd = pswindows._try_lock_slot(lock_path)
    assert held_fd is not None
    try:
        pswindows._config = _pool_cfg(64, pool_env.dir)
        result = pswindows._publish_pool_marker(pool_env.dir, 64)
        assert result is False, "publish must report skip under lock contention"
        payload = _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
        assert payload == {"cap": 4}, (
            f"lock-contended publisher overwrote the recorded cap: {payload}"
        )
    finally:
        pswindows._release_ps_slot(held_fd)

    # Deterministic first-writer-wins: divergent first publishers racing
    # under the arbitration resolve to ONE winner (the first to publish).
    import threading as _th2
    pswindows._PS_POOL_STATE.marker_written = False
    pswindows._config = _pool_cfg(4, pool_env.dir)
    (pool_env.dir / _META_NAME).unlink()
    outcomes: list = []

    def _publisher(cap):
        outcomes.append(pswindows._publish_pool_marker(pool_env.dir, cap))

    a = _th2.Thread(target=_publisher, args=(4,))
    b = _th2.Thread(target=_publisher, args=(64,))
    a.start()
    b.start()
    a.join(timeout=5)
    b.join(timeout=5)
    payload = _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert payload["cap"] in (4, 64)
    # Exactly one TRUE publish; the loser deferred-to-valid or skipped.
    assert outcomes.count(True) >= 1 and outcomes.count(False) <= 1


def test_defer_to_valid_marker_is_pinned(pool_env):
    """Direct no-rewrite pin (round-2 review P1 falsifier): a valid recorded
    marker + free lock -> _publish_pool_marker defers (True) and the marker
    is byte-identical afterwards. The P1 mutant (defer disabled) overwrites
    and fails this test."""
    import json as _json

    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    before = (pool_env.dir / _META_NAME).read_bytes()
    assert _json.loads(before) == {"cap": 4}
    result = pswindows._publish_pool_marker(pool_env.dir, 64)
    assert result is True, "defer to a valid marker must report True"
    after = (pool_env.dir / _META_NAME).read_bytes()
    assert after == before, (
        f"a valid recorded marker was rewritten: {before!r} -> {after!r}"
    )


def test_corrupt_shapes_repaired_on_the_fresh_process_path(pool_env):
    """Round-2 review F3 falsifier: corrupt valid-JSON shapes must be
    warned + repaired, never silently overwritten. The first shape drives
    the NORMAL fresh-process path (marker_written False, publisher runs
    first); subsequent shapes exercise the reader repair path (marker
    already published this process) - both paths carry the same contract."""
    import json as _json

    for shape in ("null", "[]", '{"cap": 100}'):
        pool_env.logs.clear()
        (pool_env.dir / _META_NAME).write_text(shape, encoding="utf-8")
        fd = pswindows._acquire_ps_slot()
        pswindows._release_ps_slot(fd)
        payload = _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
        assert payload == {"cap": 4}, (
            f"shape {shape}: fresh-process path did not repair to the local "
            f"cap: {payload}"
        )
        assert any(
            "unreadable or corrupt" in ln for ln in pool_env.logs
        ), f"shape {shape}: the loud warning is missing: {pool_env.logs}"
        # Subsequent acquisitions see a valid marker again.
        fd2 = pswindows._acquire_ps_slot()
        pswindows._release_ps_slot(fd2)
        assert _json.loads(
            (pool_env.dir / _META_NAME).read_text(encoding="utf-8")) == {"cap": 4}


def test_bool_cap_rejected_on_every_path(pool_env, monkeypatch):
    """Round-4 review falsifier: a JSON boolean is NOT a cap on ANY path -
    publisher defer, reader range checks, and both repair re-reads. With
    {"cap": true} on disk and the publication lock held, _read_pool_cap
    must return the LOCAL cap (never True) and the marker stays corrupt
    until a repair can run."""
    import json as _json

    (pool_env.dir / _META_NAME).write_text('{"cap": true}', encoding="utf-8")
    # Hold the publication lock: the publisher must skip (repair blocked),
    # so the reader cannot see a freshly-written valid marker.
    lock_fd = pswindows._try_lock_slot(pool_env.dir / "pool.meta.lock")
    assert lock_fd is not None
    try:
        cap = pswindows._read_pool_cap(pool_env.dir, 4)
        assert isinstance(cap, int) and not isinstance(cap, bool) and cap == 4, (
            f"a JSON boolean leaked through a repair re-read as the cap: {cap!r}"
        )
    finally:
        pswindows._release_ps_slot(lock_fd)
    # Once the lock frees, the next acquire repairs the corrupt marker.
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    payload = _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert payload == {"cap": 4}, f"corrupt bool marker never repaired: {payload}"


def test_missing_branch_repair_honors_foreign_cap(pool_env, monkeypatch):
    """Round-3 Q1 pin: the missing-after-publication repair defers to a
    foreign valid marker and the re-read honors ITS cap, not the local
    one."""
    import json as _json

    # Publish once (marker_written True), then delete the marker.
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    (pool_env.dir / _META_NAME).unlink()

    # A foreign publisher's valid marker lands during the repair window.
    def _foreign_publish(directory, cap):
        (pool_env.dir / _META_NAME).write_text('{"cap": 8}', encoding="utf-8")
        return True  # the real publish would then defer to this valid marker

    monkeypatch.setattr(pswindows, "_publish_pool_marker", _foreign_publish)
    cap = pswindows._read_pool_cap(pool_env.dir, 4)
    assert cap == 8, (
        f"the deferred foreign cap was not honored by the re-read: {cap!r}"
    )
    assert _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8")) == {"cap": 8}


def test_both_divergences_warn_in_one_acquire(pool_env):
    """Final-critic blocker 2: when recorded cap AND slot dir diverge in the
    SAME acquire, BOTH warnings fire (cap naming both values, dir naming
    both directories). The shared-key mutant (dir key collapsed to the cap
    key) suppresses the dir warning and fails this test."""
    import re as _re

    # A foreign pool recorded cap 4 in the caller-named slot directory (the
    # marker is pre-seeded; marker_written True as if this process had read
    # it). The local config is cap 64 in that same named dir: ONE acquire
    # carries BOTH divergences (recorded-vs-local cap, named-vs-default dir).
    (pool_env.dir / _META_NAME).write_text('{"cap": 4}', encoding="utf-8")
    pswindows._PS_POOL_STATE.marker_written = True
    pool_env.logs.clear()
    pswindows._config = _pool_cfg(64, pool_env.dir)
    fd2 = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd2)
    cap_warns = [ln for ln in pool_env.logs
                 if _re.search(r"\b64\b", ln) and _re.search(r"\b4\b", ln)
                 and "cap" in ln.lower()]
    dir_warns = [ln for ln in pool_env.logs
                 if str(pool_env.dir) in ln
                 and str(pswindows._default_ps_slot_dir()) in ln]
    assert cap_warns, f"cap divergence warning missing: {pool_env.logs}"
    assert dir_warns, (
        f"dir divergence warning suppressed when both diverge in one "
        f"acquire (shared-key mutant): {pool_env.logs}"
    )
    # The effective bound still honors the recorded cap-4 pool.
    attempted: list[str] = []
    real_try_lock = pswindows._try_lock_slot

    def _recording(path):
        attempted.append(path.name)
        return real_try_lock(path)

    pswindows._try_lock_slot = _recording
    try:
        fd3 = pswindows._acquire_ps_slot()
        pswindows._release_ps_slot(fd3)
    finally:
        pswindows._try_lock_slot = real_try_lock
    assert all(name.startswith("slot-0") and int(name[5]) < 4 for name in attempted
               if name.startswith("slot-")), (
        f"cap-64 process swept outside the recorded cap-4 pool: {attempted}"
    )


def test_recursion_error_repaired(pool_env):
    """PRR-009 regression: deep-nested hostile JSON in pool.meta raises
    RecursionError (a RuntimeError, not ValueError) from json.loads - the
    repair contract must still run, and the corrupt marker must be
    republished to the local cap."""
    import json as _json

    deep = '{"cap": ' + "[" * 1200 + "]" * 1200 + "}"
    (pool_env.dir / _META_NAME).write_text(deep, encoding="utf-8")
    pswindows._PS_POOL_STATE.marker_written = True  # prior publication
    fd = pswindows._acquire_ps_slot()
    pswindows._release_ps_slot(fd)
    payload = _json.loads((pool_env.dir / _META_NAME).read_text(encoding="utf-8"))
    assert payload == {"cap": 4}, (
        f"RecursionError marker not repaired to the local cap: {payload}"
    )
    assert any("unreadable or corrupt" in ln for ln in pool_env.logs)


def test_unrepairable_marker_degrades_to_local_cap(pool_env, monkeypatch):
    """PRR-006 regression: a repair that cannot publish (persistent replace
    contention) DEGRADES to the local cap per the documented contract -
    the acquire succeeds, the failure is logged (redacted), and the raw
    OSError never escapes to run_ps callers (at base-revision-equivalent
    behavior the leg worked with the local cap)."""
    (pool_env.dir / _META_NAME).write_text("not json", encoding="utf-8")

    def _failing_publish(directory, cap):
        raise PermissionError(
            f"[WinError 5] Access is denied: {directory}" + chr(92) + "pool.meta")

    monkeypatch.setattr(pswindows, "_publish_pool_marker", _failing_publish)
    fd = pswindows._acquire_ps_slot()  # must NOT raise raw OSError
    pswindows._release_ps_slot(fd)
    logs = " ".join(pool_env.logs)
    assert "repair publication failed" in logs or "publication failed" in logs, (
        f"the publish failure must be logged: {pool_env.logs}"
    )
    assert str(pool_env.dir) in logs or pool_env.dir.name in logs, (
        "the log names the slot directory (operator debugging)"
    )
