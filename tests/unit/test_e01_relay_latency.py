"""Acceptance checks C6, C7 and C9 for issue #88 in the #74/#72/#88 bundle: the
relay must record per-request latency.

C6 (AC6, DISCRIMINATING) — a completed relay request records its latency, keyed
by relay id. RED at base (`_bump` captures no duration).
C7 (AC7, DISCRIMINATING) — `relay_status` returns a latency summary with at
least p50 and p95. RED at base (the row has no `latency` key).
C9 (AC9, DISCRIMINATING) — the latency store is bounded, so a long-lived relay
cannot grow it without bound. RED at base (there is no store to bound).

All three drive the REAL `relay_start` / `_RelayHandler` / `relay_status` path
over loopback, with only `vmident.resolve` and `pswindows.run_ps` stubbed — so
neither Hyper-V nor a guest is touched, and the code under test is the shipped
code rather than a reimplementation of it. The stub returns a fixed guest
duration, which is exactly the number the relay currently discards.

C8 (AC8, PRESERVING) is the existing `tests/unit/test_relay.py` suite: the
latency summary must be additive, with `counters` keeping its meaning. It is
replayed as its own acceptance row rather than duplicated here.
"""
from __future__ import annotations

import http.client
import json
import sys

import pytest

from hyperv_mcp import credentials as creds
from hyperv_mcp import pswindows, vmident
from hyperv_mcp import relay as relay_mod
from hyperv_mcp.config import Config

_PROBE_GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
_GUEST_MS = 37


class _Stub:
    """Patches `vmident.resolve` and `pswindows.run_ps` for the probe's life.

    `vmident.resolve` is patched so no host PowerShell runs to resolve the VM;
    `pswindows.run_ps` is patched so the guest leg never reaches a guest. Both
    are restored on exit, so a failure inside the block cannot leak the patch
    into the next test.
    """

    def __init__(self, guest_ms: int = _GUEST_MS):
        self.guest_ms = guest_ms
        self._saved_resolve = None
        self._saved_run_ps = None

    def __enter__(self):
        self._saved_resolve = relay_mod.vmident.resolve
        self._saved_run_ps = relay_mod.pswindows.run_ps

        def _fake_resolve(cfg, vm_name="", vm_id=""):
            return vmident.VMRef(id=_PROBE_GUID, name=vm_name or "probe-vm")

        def _fake_run_ps(script, **kwargs):
            return pswindows.PSResult(
                stdout=json.dumps({
                    "status": 200,
                    "content_type": "application/json",
                    "body_b64": "eyJvayI6dHJ1ZX0=",
                }),
                returncode=0,
                duration_ms=self.guest_ms,
            )

        relay_mod.vmident.resolve = _fake_resolve
        relay_mod.pswindows.run_ps = _fake_run_ps
        return self

    def __exit__(self, *exc):
        relay_mod.vmident.resolve = self._saved_resolve
        relay_mod.pswindows.run_ps = self._saved_run_ps
        return False


def _drive(requests: int, guest_ms: int = _GUEST_MS) -> dict:
    """Start a relay, push `requests` through it, return its status row."""
    cfg = Config(unrestricted=True)
    cred = creds.CredentialSet(username="probe", password="probe-pass")
    with _Stub(guest_ms):
        started = relay_mod.relay_start(
            cfg, vm_name="probe-vm", guest_port=9999, cred=cred,
        )
        relay_id = started["relay_id"]
        try:
            return _status_after(cfg, relay_id, requests, started["url"],
                                 started["host_port"])
        finally:
            try:
                relay_mod.relay_stop(cfg, relay_id)
            except Exception:
                pass


def _status_after(cfg, relay_id: str, requests: int, url: str, port: int) -> dict:
    """Push `requests` through a started relay, then read its status row."""
    target = url + "/json/version"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        for _ in range(requests):
            conn.request("GET", target.split(str(port), 1)[1])
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 200, (
                f"probe request failed: {resp.status}"
            )
    finally:
        conn.close()
    return relay_mod.relay_status(cfg, relay_id)["relays"][0]


def _fresh_relay():
    """Start a relay with NO request pushed through it yet."""
    cfg = Config(unrestricted=True)
    cred = creds.CredentialSet(username="probe", password="probe-pass")
    with _Stub():
        started = relay_mod.relay_start(
            cfg, vm_name="probe-vm", guest_port=9999, cred=cred,
        )
    return cfg, started["relay_id"], started["url"], started["host_port"]


def _sample_count(latency: dict) -> int:
    """How many request latencies the store is holding.

    The summary reports a COUNT, not the samples themselves: shipping every
    sample in the status payload would grow the response without bound, which
    is the thing AC9 exists to prevent.
    """
    for key in ("samples", "count", "n"):
        value = latency.get(key)
        if isinstance(value, int):
            return value
    raise AssertionError(
        f"the latency summary must report how many samples it holds; got "
        f"{json.dumps(latency, sort_keys=True)}"
    )


def test_relay_records_request_latency():
    """C6 / AC6: a completed request's latency is recorded per relay id."""
    row = _drive(3)
    latency = row.get("latency")
    assert latency is not None, (
        "no latency recorded for the relay request: `_bump` captures no "
        "duration and `relay_status` returns no latency companion"
    )
    count = _sample_count(latency)
    assert count >= 3, (
        f"C6: the latency store must carry the request samples; got "
        f"{json.dumps(latency, sort_keys=True)}"
    )
    # The stub's guest duration is _GUEST_MS; the recorded latencies must be in
    # that neighbourhood, so a store that records a constant zero is caught.
    assert latency.get("p50_ms"), (
        f"C6: at least one recorded latency must be non-zero; got "
        f"{json.dumps(latency, sort_keys=True)}"
    )


def test_relay_status_reports_latency():
    """C7 / AC7: the status row carries p50 and p95 alongside the counters."""
    row = _drive(5)
    latency = row["latency"]
    assert "p50_ms" in latency, (
        f"KeyError: 'p50_ms' — the latency summary must carry at least p50 and "
        f"p95; got {sorted(latency)}"
    )
    assert "p95_ms" in latency, (
        f"KeyError: 'p95_ms' — the latency summary must carry at least p50 and "
        f"p95; got {sorted(latency)}"
    )
    # The existing counters contract is unchanged (AC8's shape, asserted here
    # too so a regression in the additive field fails the DISCRIMINATING row).
    assert row["counters"].get("requests") == 5, (
        f"counters must keep their meaning; got {row['counters']}"
    )
    # A relay that has served NOTHING reports null percentiles, not zeros, so
    # "no requests yet" is distinguishable from "requests were instantaneous".
    # Every other check in this file drives requests first, so without this
    # assertion the empty branch is unpinned: a probe that replaced the nulls
    # with 0 left the whole suite green.
    cfg, fresh_id, _url, _port = _fresh_relay()
    try:
        empty = relay_mod.relay_status(cfg, fresh_id)["relays"][0]["latency"]
        for key in ("p50_ms", "p95_ms", "p99_ms"):
            assert key in empty, (
                f"an un-driven relay must still report {key}; got "
                f"{sorted(empty)}"
            )
            assert empty[key] is None, (
                f"an un-driven relay must report null {key}, not "
                f"{empty[key]!r}; got {json.dumps(empty, sort_keys=True)}"
            )
        assert _sample_count(empty) == 0, (
            f"an un-driven relay must hold no samples; got "
            f"{json.dumps(empty, sort_keys=True)}"
        )
    finally:
        try:
            relay_mod.relay_stop(cfg, fresh_id)
        except Exception:
            pass


def test_relay_latency_store_is_bounded():
    """C9 / AC9: the store cannot grow without bound."""
    row = _drive(3)
    latency = row["latency"]
    cap = latency.get("cap")
    assert cap is not None, (
        f"the latency store must publish its bound; got {sorted(latency)}"
    )
    cap = int(cap)

    # Push far past the bound through a fresh relay and re-read.
    over = _drive(cap + 50)
    count = _sample_count(over["latency"])
    assert count <= cap, (
        f"the latency store grew past its bound: {count} samples against a cap "
        f"of {cap}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
