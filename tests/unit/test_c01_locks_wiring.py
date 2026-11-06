"""Issue #14 wiring pins (trace issue-14-vm-rw-locks, C-01 follow-on):
server startup applies Config.vm_lock_wait_s, busy envelopes carry live
holder metadata, console dual-keys reach the registry, the registry pin
actually protects a fetched-but-unacquired lock, and vm_lock validates
its arguments.

GREEN-after-fix pins for surfaces the frozen acceptance file
(test_c01_vm_locks.py) does not cover; they were all RED at base f4b2862
(set_default_wait_s / holder envelope / tuple keys did not exist).
The PRR-* names are PR #58 swarm-pr-feedback finding ids.
"""

import contextlib
import threading
import time
from types import SimpleNamespace

import pytest

from hyperv_mcp import auditlog, console, errors, server, vmlocks
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.vmlocks import _MAX_LOCKS, VMBusy, _pins, vm_lock


def test_config_default_and_validation():
    """Config.vm_lock_wait_s defaults to 30 and validates 0..600."""
    assert Config().vm_lock_wait_s == 30
    Config(vm_lock_wait_s=0).validate()  # 0 = fail-fast is legal
    Config(vm_lock_wait_s=600).validate()
    with pytest.raises(ConfigError, match="vm_lock_wait_s"):
        Config(vm_lock_wait_s=601).validate()
    with pytest.raises(ConfigError, match="vm_lock_wait_s"):
        Config(vm_lock_wait_s=-1).validate()


def test_vm_lock_wait_s_load_path():
    """The JSON/_FIELD_MAP load path registers the key and rejects a
    non-integer (feedback PRR-013: constructor-only coverage let a dropped
    _FIELD_MAP entry pass silently)."""
    cfg = Config.from_dict({"vm_lock_wait_s": 9})
    assert cfg.vm_lock_wait_s == 9
    with pytest.raises(ConfigError, match="vm_lock_wait_s must be an integer"):
        Config.from_dict({"vm_lock_wait_s": "9"})


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
        assert vmlocks._DEFAULT_WAIT_S == 0.5  # rejected calls change nothing
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


def test_vm_lock_rejects_bad_args():
    """vm_lock validates mode AND wait_s up front (feedback PRR-014: a
    non-numeric wait_s used to reach max() inside the acquire and surface
    as TypeError/transport after the pin was taken)."""
    with pytest.raises(ValueError, match="mode"):
        with vm_lock("bad-args-vm", mode="rw"):
            pass
    with pytest.raises(ValueError, match="wait_s"):
        with vm_lock("bad-args-vm", wait_s="30"):
            pass
    with pytest.raises(ValueError, match="wait_s"):
        with vm_lock("bad-args-vm", wait_s=-1):
            pass
    with pytest.raises(ValueError, match="wait_s"):
        with vm_lock("bad-args-vm", wait_s=601):
            pass
    with vm_lock("bad-args-vm", wait_s=0):  # 0 = fail-fast, still legal
        pass


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


def test_enrich_failure_preserves_holder():
    """enrich_failure keeps (and re-redacts) a module-supplied holder and
    ignores a non-dict one (feedback PRR-013: this branch was untested)."""
    env = errors.enrich_failure({
        "ok": False, "error": "x", "error_class": "busy",
        "holder": {"tool": "t", "mode": "read", "since": 1.0, "held_ms": 2},
    })
    assert env["holder"] == {"tool": "t", "mode": "read", "since": 1.0, "held_ms": 2}
    assert env["retryable"] is True and env["retry_after_ms"] == 2000
    weird = errors.enrich_failure({"ok": False, "error_class": "busy", "holder": "nope"})
    assert weird["holder"] == "nope"  # non-dict passes through untouched
    assert "holder" not in errors.enrich_failure({"ok": False, "error_class": "busy"})


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


def test_tuple_key_casefolds_per_element():
    """Tuple keys case-fold each element (feedback PRR-013: a mutant
    dropping .casefold() from the tuple branch previously survived)."""
    with vm_lock(("Case-GUID", "Console")):
        with pytest.raises(VMBusy):
            with vm_lock(("case-guid", "console")):  # same tuple after fold
                pass


def test_plain_name_cannot_alias_tuple_key():
    """String and tuple keys are disjoint namespaces (feedback PRR-009):
    a client VM name shaped like a dual key cannot collide with one."""
    with vm_lock("alias-guid|console"):  # hostile/colliding client name
        with vm_lock(("alias-guid", "console")):  # separate namespace
            pass


def test_console_input_takes_dual_keys(monkeypatch):
    """console._input_lock takes READ on the VM key + WRITE (default) on
    the (vm, "console") key (feedback PRR-013: deleting the tuple lock
    from _input_lock used to leave the whole suite green)."""
    recorded: list = []
    real = vmlocks.vm_lock

    @contextlib.contextmanager
    def spy(key, *args, **kwargs):
        recorded.append((key, kwargs))
        with real(key, *args, **kwargs):
            yield

    monkeypatch.setattr(vmlocks, "vm_lock", spy)
    ref = SimpleNamespace(id="AAAA-BBBB-CCCC", name="vm-x")
    with console._input_lock(ref):
        pass
    assert recorded == [
        ("AAAA-BBBB-CCCC", {"mode": "read"}),
        (("AAAA-BBBB-CCCC", "console"), {}),  # write is the default mode
    ]


def test_holder_held_ms_grows():
    """Feedback PRR-001: held_ms must reflect the LIVE hold at failure
    time (issue #14 Verification: "a growing held_ms"), and the message
    must carry that live value — a birth-time snapshot (~0) fails this."""
    entered = threading.Event()
    release = threading.Event()

    def hold():
        with auditlog.operation(
            tool="hyperv_checkpoint_restore", vm_name="v", category="destructive"
        ):
            with vm_lock("growth-vm", mode="write"):
                entered.set()
                release.wait(10)

    t = threading.Thread(target=hold)
    t.start()
    try:
        assert entered.wait(5)
        time.sleep(0.5)
        with pytest.raises(VMBusy) as raised:
            with vm_lock("growth-vm", mode="write", wait_s=0.2):
                pass
        holder = raised.value.holder
        assert holder["tool"] == "hyperv_checkpoint_restore"
        assert holder["mode"] == "write"
        assert holder["since"] <= time.time()
        assert holder["held_ms"] >= 400, (
            f"held_ms must reflect the ~0.5s live hold, got {holder['held_ms']}"
        )
        # The operator-facing message carries the same live value.
        assert f"held_ms={holder['held_ms']}" in str(raised.value)
    finally:
        release.set()
        t.join(timeout=5)


def test_read_holder_reports_longest_reader():
    """A write conflict against MULTIPLE readers reports the earliest
    reader (longest-held) — feedback PRR-013: the single-reader version
    could not distinguish min(since) from max/next."""
    r1_in = threading.Event()
    r2_in = threading.Event()
    release = threading.Event()
    r1_time: dict = {}

    def hold_read(label, started, stamp):
        with vm_lock("longest-reader-vm", mode="read"):
            stamp["t"] = time.time()
            started.set()
            release.wait(10)

    t1 = threading.Thread(target=hold_read, args=("r1", r1_in, r1_time))
    t1.start()
    assert r1_in.wait(5)
    time.sleep(0.4)  # strictly separate the two acquire epochs
    t2 = threading.Thread(target=hold_read, args=("r2", r2_in, {}))
    t2.start()
    assert r2_in.wait(5)
    try:
        with pytest.raises(VMBusy) as raised:
            with vm_lock("longest-reader-vm", mode="write", wait_s=0.2):
                pass
        holder = raised.value.holder
        assert holder["mode"] == "read"
        assert holder["tool"] == "unknown"  # outside any audit operation
        # The reported record is the OLDEST reader's: a max()/next() mutant
        # would report r2's epoch, which is strictly later than r1's stamp.
        assert holder["since"] <= r1_time["t"], (
            "holder must be the longest-held (earliest-since) reader"
        )
    finally:
        release.set()
        t1.join(timeout=5)
        t2.join(timeout=5)


def test_reader_expiry_names_queued_writer():
    """Feedback PRR-008: a reader timing out while ONLY a queued writer
    blocks it must name that writer — not fabricate a record blaming the
    requester. (State constructed directly to hit the transient window
    deterministically.)"""
    lock = vmlocks._RWLock()
    writer_rec = {
        "tool": "hyperv_checkpoint_restore", "mode": "write",
        "since": time.time() - 2.0, "held_ms": 0,
    }
    with lock._cv:
        lock._waiting_writers = 1
        lock._pending_writer_records = [(threading.get_ident(), writer_rec)]
    with pytest.raises(VMBusy) as raised:
        lock.acquire("queued-writer-vm", "read", 0.1, threading.get_ident())
    holder = raised.value.holder
    assert holder is not None
    assert holder["tool"] == "hyperv_checkpoint_restore"
    assert holder["mode"] == "write"
    assert holder["held_ms"] >= 2000  # queued-writer wait reported live


def test_reader_expiry_without_holder_is_honest():
    """If contention drained before expiry, there is no holder: the
    envelope must omit `holder` and the message must not name a tool
    instead of blaming the requester."""
    lock = vmlocks._RWLock()
    with lock._cv:
        lock._waiting_writers = 1  # predicate true, nobody recorded
        lock._pending_writer_records = []
    with pytest.raises(VMBusy) as raised:
        lock.acquire("drained-vm", "read", 0.1, threading.get_ident())
    assert raised.value.holder is None
    assert "tool=" not in str(raised.value)
    assert "holder" not in errors.envelope(raised.value)


def test_context_manager_exit_on_another_thread_releases():
    """Feedback PRR-015: the CM must release the OWNING thread's records
    even when finalized elsewhere (ExitStack / GC finalization), instead
    of wedging a phantom holder for the process lifetime."""
    cm = vm_lock("cross-thread-vm")
    entered = threading.Event()

    def owner():
        cm.__enter__()
        entered.set()

    t = threading.Thread(target=owner)
    t.start()
    assert entered.wait(5)
    t.join(timeout=5)  # owner thread is now gone
    cm.__exit__(None, None, None)  # finalize on THIS thread
    with vm_lock("cross-thread-vm", wait_s=0):  # fail-fast proves no wedge
        pass


def test_eviction_never_removes_pinned_or_held(monkeypatch):
    """Registry cap with a GENUINELY pinned (fetched, not yet acquired)
    key (feedback PRR-011: the previous version never created one, so the
    pin machinery — the plan's BLOCKER-1 fix — had zero coverage)."""
    monkeypatch.setattr(vmlocks, "_MAX_LOCKS", 3)
    held = threading.Event()
    release = threading.Event()

    def hold():
        with vm_lock("evict-held"):
            held.set()
            release.wait(10)

    holder_thread = threading.Thread(target=hold)
    holder_thread.start()

    pinned_fetched = threading.Event()
    unblock = threading.Event()
    original_acquire = vmlocks._RWLock.acquire

    def slow_acquire(self, key, mode, wait_s, tid):
        # Freeze the pinned key's acquire AFTER the fetch+pin, BEFORE the
        # lock state changes — the exact window the pin exists to protect.
        if key == "evict-pinned":
            pinned_fetched.set()
            assert unblock.wait(10)
        return original_acquire(self, key, mode, wait_s, tid)

    monkeypatch.setattr(vmlocks._RWLock, "acquire", slow_acquire)

    def pin_blocker():
        with vm_lock("evict-pinned"):
            pass

    pin_thread = threading.Thread(target=pin_blocker)
    pin_thread.start()
    try:
        assert held.wait(5)
        assert pinned_fetched.wait(5)  # pin taken, acquire not yet run
        assert _pins.get("evict-pinned", 0) >= 1  # genuinely pinned NOW
        # Blow past the cap with idle keys; each insert triggers eviction.
        created = [f"evict-idle-{i}" for i in range(6)]
        for k in created:
            with vm_lock(k):
                pass
        assert "evict-pinned" in vmlocks._locks, "pinned key was evicted"
        assert "evict-held" in vmlocks._locks, "held key was evicted"
        surviving_idle = [k for k in created if k in vmlocks._locks]
        assert len(vmlocks._locks) < 2 + len(created), (
            "eviction never ran; registry grew past the cap"
        )
        assert surviving_idle != created, "idle keys should have been evicted"
    finally:
        unblock.set()
        pin_thread.join(timeout=10)
        release.set()
        holder_thread.join(timeout=10)
        monkeypatch.setattr(vmlocks, "_MAX_LOCKS", _MAX_LOCKS)
    # Pins never leak once the acquires resolve.
    assert _pins.get("evict-pinned", 0) == 0

# ---------------------------------------------------------------------------
# W1.2 / W1.3 — issue #59 (wave 59-64-68-70-hardening): pins for PR #58
# review fixes that had no asserting test at base. These test nodes are
# absent at base (pytest exit 4 RED signature) and GREEN after the fix.
# The defaulted-parameter guardrail pattern for this file is
# PRR0[0-9]+[a-z]*=None (two-digit ids were invisible to the old pattern).


def test_job_stop_vmbusy_propagates_as_busy(monkeypatch):
    """A VMBusy raised by job_stop's guest stop leg propagates (the tool
    wrapper envelopes it as error_class=busy with holder) instead of being
    rewritten into a transport result (feedback PRR-002)."""
    from hyperv_mcp import guestjobs
    from hyperv_mcp.config import Config as _Cfg

    cfg = _Cfg()
    entry = {
        "job_id": "j-busy", "vm_id": "00000000-0000-0000-0000-000000000001",
        "vm_name": "vm", "pid": 4321, "stopped": False,
        "row_state": "running", "owner": None, "in_flight": False,
        "job_dir": "C:/tmp/j-busy", "start_time_ticks": 1,
    }
    with guestjobs._jobs_lock:
        guestjobs._jobs["j-busy"] = entry

    def _raise_busy(*_a, **_k):
        raise vmlocks.VMBusy(
            "write lock held", holder={"tool": "other", "mode": "write"},
            waited_ms=7,
        )

    monkeypatch.setattr(guestjobs, "run_guest_inner", _raise_busy)
    monkeypatch.setattr(
        guestjobs, "_entry_credential",
        lambda cfg, entry: SimpleNamespace(username="u", password="p"),
    )
    with pytest.raises(vmlocks.VMBusy) as excinfo:
        guestjobs.job_stop(cfg, "j-busy")
    assert getattr(excinfo.value, "holder", None) == {
        "tool": "other", "mode": "write",
    }
    # and the envelope machinery classifies it busy (holder rides the error)
    cls = errors.classify(vmlocks.VMBusy("held", holder={"tool": "x"}))
    assert cls == "busy"


def test_swallowed_lock_failure_keeps_busy_class(monkeypatch):
    """Swallowed lock failures keep error_class=busy: the evidence UIA walk
    records it in the ui_tree field and a repair apply records it in the
    change dict (feedback PRR-004 classification)."""
    from types import SimpleNamespace as _NS

    from hyperv_mcp import evidence
    from hyperv_mcp import repair as repair_module
    from hyperv_mcp.config import Config as _Cfg
    from hyperv_mcp.credentials import CredentialSet

    def _raise_busy(*_a, **_k):
        raise vmlocks.VMBusy("read lock held", holder={"tool": "writer"})

    # evidence leg: the ps_direct walk swallow site (evidence.py PRR-004).
    cfg = _Cfg()
    monkeypatch.setattr(evidence.vmident, "resolve",
                        lambda *a, **k: _NS(id="g-1", name="vm"))
    monkeypatch.setattr(evidence.console, "screenshot",
                        lambda *a, **k: (object(), {"ok": True}))
    monkeypatch.setattr(evidence, "_uia_via_helper", lambda *a, **k: None)
    monkeypatch.setattr(evidence, "run_guest_inner", _raise_busy)
    result = evidence.capture_evidence(
        cfg, "vm", ui_tree=True, cred=CredentialSet("Administrator", "pw"))
    ui_tree = result["meta"]["ui_tree"]
    assert ui_tree["ok"] is False and ui_tree["error_class"] == "busy"

    # repair leg: the apply-loop swallow site (repair.py PRR-004).
    cfg.destructive.guest_repair = True  # require_destructive gate
    monkeypatch.setattr(repair_module.vmident, "resolve",
                        lambda *a, **k: _NS(id="g-1", name="vm"))
    monkeypatch.setattr(repair_module, "_plan_items", lambda report: [{
        "action": "start_sshd", "target": "sshd", "before": "stopped",
        "apply_script": "Start-Service sshd", "verify_finding": "f-sshd",
    }])
    monkeypatch.setattr(repair_module.diagnostics, "diagnose_report",
                        lambda *a, **k: {"findings": []})
    monkeypatch.setattr(repair_module, "run_guest_inner", _raise_busy)
    out = repair_module.repair_guest_access(
        cfg, "vm", apply=True, confirm=True,
        cred=CredentialSet("Administrator", "pw"))
    change = out["changes"][0]
    assert change["applied"] is False
    assert change["error_class"] == "busy"


def test_job_stop_busy_envelope_through_the_tool_wrapper(monkeypatch):
    """issue #59 AC2 wrapper leg: a VMBusy raised by job_stop's guest leg
    reaches the MCP envelope as error_class=busy with the holder dict
    intact (the direct re-raise is pinned separately; this drives the
    registered tool the way an MCP client does)."""
    import asyncio as _aio
    import importlib as _il
    import json as _json

    from hyperv_mcp import guestjobs as _gj

    mod = _il.reload(server)
    mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})

    entry = {
        "job_id": "j-wrap", "vm_id": "00000000-0000-0000-0000-000000000003",
        "vm_name": "vm", "pid": 4321, "stopped": False,
        "row_state": "running", "owner": None, "in_flight": False,
        "job_dir": "C:/tmp/j-wrap", "start_time_ticks": 1,
    }
    with _gj._jobs_lock:
        _gj._jobs["j-wrap"] = entry
    try:

        def _raise_busy(*_a, **_k):
            raise vmlocks.VMBusy(
                "write lock held", holder={"tool": "other", "mode": "write"},
                waited_ms=7,
            )

        monkeypatch.setattr(_gj, "run_guest_inner", _raise_busy)
        monkeypatch.setattr(
            _gj, "_entry_credential",
            lambda cfg, entry: SimpleNamespace(username="u", password="p"),
        )
        result = _aio.run(mod.get_mcp().call_tool(
            "hyperv_guest_job_stop", {"job_id": "j-wrap"}))
        assert getattr(result, "is_error", False), (
            f"the busy envelope must be an error result; got {result!r}"
        )
        text = result.content[0].text
        payload = _json.loads(text)
        assert payload.get("error_class") == "busy", (
            f"envelope must carry error_class=busy; got {payload!r}"
        )
        holder = (payload.get("error") or {}).get("holder") if isinstance(
            payload.get("error"), dict) else payload.get("holder")
        assert holder == {"tool": "other", "mode": "write"}, (
            f"envelope must carry the holder dict intact; got {payload!r}"
        )
    finally:
        with _gj._jobs_lock:
            _gj._jobs.pop("j-wrap", None)
        _il.reload(server)
