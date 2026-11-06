"""Issue #70 AC5 (wave 59-64-68-70-hardening) — registry lookups return
snapshots, not live dicts.

PRR-046: guestjobs._lookup and the relay read boundary copied the entry
reference under the registry lock but returned the LIVE dict, so a
concurrent stop mutating the entry mid-read handed the caller a torn view
(stopped=False with cred=None). The wave fixes the read boundaries to
return point-in-time snapshots; these checks pin the isolation:

  guestjobs leg   — mutating the dict returned by _lookup must never reach
                    the registry; a fresh lookup sees pre-mutation values.
  relay leg       — a mutation landing between the read boundary's copy and
                    the row construction must not appear in the built rows
                    (deterministic interleaving via the _latency_summary
                    seam).

Both legs FAIL on the pre-fix tree for the named reasons.
"""

import threading

from hyperv_mcp import guestjobs, relay

_MINIMAL_ENTRY = {
    "job_id": "j-snap", "vm_id": "00000000-0000-0000-0000-000000000002",
    "vm_name": "real-vm", "pid": 1234, "stopped": False,
    "row_state": "running", "owner": None, "in_flight": False,
    "job_dir": "C:/tmp/j-snap", "start_time_ticks": 1,
}


def test_guestjobs_lookup_returns_snapshot():
    """Mutating the dict returned by _lookup never reaches the registry: a
    second lookup sees the pre-mutation values (W4.5)."""
    with guestjobs._jobs_lock:
        guestjobs._jobs["j-snap"] = dict(_MINIMAL_ENTRY)
    try:
        e1 = guestjobs._lookup("j-snap")
        e1["stopped"] = True
        e2 = guestjobs._lookup("j-snap")
        assert e2["stopped"] is False, (
            "the registry entry must not see the caller's mutation "
            "(torn view: the caller got a live dict)"
        )
        assert e2 is not e1, "each lookup must return a distinct snapshot object"
    finally:
        with guestjobs._jobs_lock:
            guestjobs._jobs.pop("j-snap", None)


class _Thread:
    def is_alive(self):
        return True


def _relay_entry():
    return {
        "relay_id": "r-snap", "vm_name": "real-vm", "guest_port": 8730,
        "bind": "127.0.0.1", "host_port": 18730, "started_at": "t",
        "stopped": False, "owner": None, "row_state": None,
        "thread": _Thread(),
        "context": {
            "counter_lock": threading.Lock(),
            "counters": {"requests": 0},
            "latency": {"samples": [], "cap": 500},
        },
    }


def test_relay_status_row_is_isolated_from_concurrent_mutation(monkeypatch):
    """A mutation landing between the read boundary's copy and the row
    construction must not appear in the built rows (W4.5 relay leg,
    deterministic via the _latency_summary seam)."""
    entry = _relay_entry()
    with relay._relays_lock:
        relay._relays["r-snap"] = entry
    try:
        calls = {"n": 0}

        def _mutating_latency(samples, cap):
            calls["n"] += 1
            # simulate the concurrent stop landing mid row-build
            entry["stopped"] = True
            entry["cred"] = None
            return {"cap": cap, "samples": 0, "p50_ms": None,
                    "p95_ms": None, "p99_ms": None}

        monkeypatch.setattr(relay, "_latency_summary", _mutating_latency)
        monkeypatch.setattr(relay, "_restored_rows", lambda cfg, owner: [])
        out = relay.relay_status({})
        row = out["relays"][0]
        assert calls["n"] == 1
        assert row["stopped"] is False, (
            "a concurrent stop landing mid row-build must not tear the row "
            "(snapshot at the read boundary)"
        )
    finally:
        with relay._relays_lock:
            relay._relays.pop("r-snap", None)


def test_relay_status_smoke_row_shape_preserved(monkeypatch):
    """Preserving companion: the status row keeps its documented key set
    (the snapshot change must not drop keys)."""
    entry = _relay_entry()
    with relay._relays_lock:
        relay._relays["r-snap"] = entry
    try:
        monkeypatch.setattr(relay, "_restored_rows", lambda cfg, owner: [])
        out = relay.relay_status({})
        row = out["relays"][0]
        for key in ("relay_id", "vm_name", "guest_port", "bind", "host_port",
                    "url", "started_at", "stopped", "thread_alive",
                    "counters", "latency", "state"):
            assert key in row, f"status row lost key {key}"
        assert row["state"] == "active"
    finally:
        with relay._relays_lock:
            relay._relays.pop("r-snap", None)


def test_restored_entry_is_isolated(monkeypatch):
    """The store-restore path is isolated too (round-2 challenge 3): the
    caller receives a DISTINCT object from the cached one, and mutating the
    returned dict never reaches the registry's cached entry (setdefault
    path)."""
    from hyperv_mcp.config import Config as _Cfg

    cfg = _Cfg()

    def _fake_restore(c, job_id, owner):
        restored = dict(_MINIMAL_ENTRY)
        restored["job_id"] = job_id
        return restored

    monkeypatch.setattr(guestjobs, "_restore_entry", _fake_restore)
    e1 = guestjobs._lookup("j-restored", None, cfg)
    e1["stopped"] = True
    e2 = guestjobs._lookup("j-restored", None, cfg)
    assert e2["stopped"] is False, (
        "the restored-then-cached entry must not see the caller's mutation"
    )
    with guestjobs._jobs_lock:
        cached = guestjobs._jobs.get("j-restored")
    assert cached is not None and cached is not e1, (
        "the cached object and the returned object must be distinct snapshots"
    )
    assert cached["stopped"] is False


class _MutatingOnExitLock:
    """Wrapper lock that mutates the registry entry at lock RELEASE -
    a deterministic interleaving distinguishing copy-under-lock from
    copy-after-release (round-2 challenge 3)."""

    def __init__(self, real, entry):
        self._real = real
        self._entry = entry

    def __enter__(self):
        return self._real.__enter__()

    def __exit__(self, *exc):
        self._entry["stopped"] = True  # concurrent stop lands at release
        return self._real.__exit__(*exc)


def test_guestjobs_copy_happens_under_the_lock(monkeypatch):
    """The snapshot copy must happen INSIDE _jobs_lock: a copy performed
    after lock release observes the simulated concurrent stop that lands at
    lock release and fails this test."""
    entry = dict(_MINIMAL_ENTRY)
    with guestjobs._jobs_lock:
        guestjobs._jobs["j-lockscope"] = entry
    try:
        monkeypatch.setattr(
            guestjobs, "_jobs_lock", _MutatingOnExitLock(guestjobs._jobs_lock, entry))
        got = guestjobs._lookup("j-lockscope")
        assert got["stopped"] is False, (
            "the returned snapshot must be taken under the registry lock "
            "(copy-after-release saw the simulated concurrent stop)"
        )
    finally:
        with guestjobs._jobs_lock:
            guestjobs._jobs.pop("j-lockscope", None)
