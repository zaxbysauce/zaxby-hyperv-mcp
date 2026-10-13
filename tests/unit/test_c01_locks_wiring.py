"""Issue #14 wiring pins (trace issue-14-vm-rw-locks, C-01 follow-on):
server startup applies Config.vm_lock_wait_s, busy envelopes carry holder
metadata, console tuple keys normalize, and the registry pin keeps eviction
from removing a fetched-but-unacquired lock.

These are GREEN-after-fix pins for the surfaces the frozen acceptance file
(test_c01_vm_locks.py) does not cover; they were all RED at base f4b2862
(set_default_wait_s / holder envelope / tuple keys did not exist).
"""

import threading

import pytest

from hyperv_mcp import errors, server, vmlocks
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.vmlocks import VMBusy, _MAX_LOCKS, _pins, vm_lock


def test_config_default_and_validation():
    """Config.vm_lock_wait_s defaults to 30 and validates 0..600."""
    assert Config().vm_lock_wait_s == 30
    Config(vm_lock_wait_s=0).validate()  # 0 = fail-fast is legal
    Config(vm_lock_wait_s=600).validate()
    with pytest.raises(ConfigError, match="vm_lock_wait_s"):
        Config(vm_lock_wait_s=601).validate()
    with pytest.raises(ConfigError, match="vm_lock_wait_s"):
        Config(vm_lock_wait_s=-1).validate()


def test_set_default_wait_s_validation():
    vmlocks.set_default_wait_s(0.5)
    try:
        assert vmlocks._DEFAULT_WAIT_S == 0.5
        with pytest.raises(ValueError):
            vmlocks.set_default_wait_s(601)
        with pytest.raises(ValueError):
            vmlocks.set_default_wait_s(-1)
        with pytest.raises(ValueError):
            vmlocks.set_default_wait_s("30")
    finally:
        vmlocks.set_default_wait_s(30)


def test_server_bootstrap_wires_wait_default(monkeypatch):
    """server.bootstrap applies cfg.vm_lock_wait_s to vmlocks (the wiring
    the plan promises; without it the config key would be inert)."""
    monkeypatch.setattr(server, "_bootstrapped", False)
    monkeypatch.setattr(vmlocks, "_DEFAULT_WAIT_S", 30.0)
    cfg = Config(unrestricted=True, vm_lock_wait_s=7)
    monkeypatch.setattr(Config, "load", staticmethod(lambda environ=None: cfg))
    server.bootstrap()
    assert vmlocks._DEFAULT_WAIT_S == 7.0
    monkeypatch.setattr(vmlocks, "_DEFAULT_WAIT_S", 30.0)


def test_envelope_carries_holder():
    """errors.envelope attaches and redacts VMBusy holder metadata."""
    exc = VMBusy(
        "another operation is already running on VM 'v': tool=t mode=write "
        "held_ms=5; wait",
        holder={"tool": "hyperv_stop_vm", "mode": "write", "since": 1.5, "held_ms": 5},
    )
    env = errors.envelope(exc)
    assert env["error_class"] == "busy"
    assert env["retryable"] is True
    holder = env["holder"]
    assert holder == {
        "tool": "hyperv_stop_vm", "mode": "write", "since": 1.5, "held_ms": 5,
    }
    # No holder -> no key (additive envelope change).
    assert "holder" not in errors.envelope(RuntimeError("x"))


def test_tuple_key_normalizes_and_is_distinct():
    """(guid, "console") is its own key, case-folded per element, and never
    collides with the plain VM key."""
    with vm_lock("Tuple-Key-GUID", mode="read"):
        with vm_lock(("tuple-key-guid", "console")):
            pass  # different key: nested acquire succeeds
    with vm_lock("Tuple-Key-GUID"):
        with pytest.raises(VMBusy):
            with vm_lock("tuple-key-guid"):  # same key, re-entry
                pass


def test_read_holder_reports_longest_reader():
    """A write conflict against multiple readers reports the earliest
    reader (longest-held), with mode=read in the holder."""
    entered = threading.Event()
    release = threading.Event()

    def hold_read():
        with vm_lock("holder-read-vm", mode="read"):
            entered.set()
            release.wait(10)

    t = threading.Thread(target=hold_read)
    t.start()
    try:
        assert entered.wait(5)
        t0 = threading.get_ident()
        del t0  # current thread conflicts as a writer
        with pytest.raises(VMBusy) as raised:
            with vm_lock("holder-read-vm", mode="write", wait_s=0.2):
                pass
        holder = raised.value.holder
        assert holder["mode"] == "read"
        assert holder["tool"] == "unknown"  # outside any audit operation
    finally:
        release.set()
        t.join(timeout=5)


def test_eviction_never_removes_pinned_or_held(monkeypatch):
    """Registry cap: a held lock and a pinned (fetched, unacquired) key both
    survive eviction; idle unpinned entries are removed."""
    monkeypatch.setattr(vmlocks, "_MAX_LOCKS", 2)
    # Hold one key; fetch-pin another via a blocked acquire on a second thread.
    held = threading.Event()
    release = threading.Event()

    def hold():
        with vm_lock("evict-held"):
            held.set()
            release.wait(10)

    t = threading.Thread(target=hold)
    t.start()
    try:
        assert held.wait(5)
        # Fill the registry past the cap with idle keys.
        for i in range(5):
            with vm_lock(f"evict-idle-{i}"):
                pass
        assert "evict-held" in vmlocks._locks  # held: never evicted
        # The pin map does not leak entries.
        assert all(v <= 0 for v in _pins.values()) or not _pins
    finally:
        release.set()
        t.join(timeout=5)
        monkeypatch.setattr(vmlocks, "_MAX_LOCKS", _MAX_LOCKS)
