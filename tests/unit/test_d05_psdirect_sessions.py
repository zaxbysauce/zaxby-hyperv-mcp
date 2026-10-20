"""Frozen acceptance checks for issue #21: PS Direct session reuse.

The contract under check (from the issue's own suggested approach, so nothing
here leaks implementer detail): a new ``hyperv_mcp.psdsessions`` module owns a
long-lived host-PowerShell worker pool keyed by
``(vm_guid, cred_profile, agent_id, boot_epoch)``, with ``SessionPool`` /
``acquire`` / ``release`` / ``invalidate_vm`` / ``reap`` / ``SessionBusy``, a
module-level DEFAULT pool, a ``psdirect_session_reuse`` config switch (default
True), lifecycle invalidation hooks, lifespan teardown, remote-host exclusion,
per-profile isolation, honest pooled timing, and stdin-only secret delivery.

RED (or deterministic absence) at base 9434636cb035ebdb91415c5e4809ba6db20b05c5,
GREEN after the fix. No real PowerShell child, Hyper-V host, network or
credential is touched: every pooled worker is a recording fake and every
per-call PowerShell leg is served by a recording ``run_ps`` stand-in.

Assumed surface, spelled out because the internals are NOT known at freeze
time (each assumption is also marked where it is used):

  * ``SessionPool(worker_factory=..., idle_ttl_s=..., max_sessions=..., clock=...)``.
  * ``worker_factory`` is called with the session key (a single 4-tuple, or
    the four components, or keyword components) and returns a worker object
    with a ``close()``-family method; the tests accept all three spellings.
  * ``pool.acquire(key, wait_s=...)`` returns a session handle whose IDENTITY
    is the reuse oracle; ``pool.release(session)`` returns it to the pool.
  * The module-level DEFAULT pool is the module attribute ``psdsessions.DEFAULT``.
  * ``worker.run(script, ...)`-shaped calls are answered by a protocol-generic
    recording double (``__getattr__``), so the exact worker method name does
    not matter to the checks.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import auditlog, guestexec, lifecycle, pswindows, vmident
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "d05-pool-pass")
VICTIM = CredentialSet("victim", "d05-victim-pass")

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
GUID_B = "a17b3d92-4e50-4c71-9b0d-8f2a51c0664e"

# Every vm-taking lifecycle op resolves name -> GUID in one extra run_ps leg
# before the action script (vmident.resolve); queue fakes prepend this
# response — the tests/unit/test_lifecycle.py protocol.
RESOLUTION = pswindows.PSResult(stdout=GUID, returncode=0)


def _psdsessions():
    """Import the new module lazily so the AC1 config check fails with the
    CONFIG gap (ConfigError) rather than the module gap; every other check
    fails with the module-absence signature, which is its frozen expect.
    importlib.import_module raises ModuleNotFoundError (the deterministic
    absence signature) where `from hyperv_mcp import psdsessions` would raise
    a generic ImportError instead."""
    import importlib

    return importlib.import_module("hyperv_mcp.psdsessions")


def _import_soak_bench():
    """Insert the repo's scripts/ dir on sys.path and import soak_bench (the
    tests/unit/test_d04_timing.py helper, copied verbatim in spirit)."""
    scripts_dir = str(Path(__file__).resolve().parents[2] / "scripts")
    sys.path.insert(0, scripts_dir)
    try:
        import soak_bench
    finally:
        sys.path.remove(scripts_dir)
    return soak_bench


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class SteppyClock:
    """Injected clock: every read advances a fixed 0.01 s (deterministic —
    never time.sleep, never a statistical pin), and a test can age time
    explicitly with ``jump()`` so an idle-TTL boundary is unambiguous no
    matter how many reads the pool makes internally."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        self.now += 0.01
        return self.now

    def jump(self, seconds: float) -> None:
        self.now += seconds


class _DuckResult:
    """A run_ps-shaped result WITHOUT being a pswindows.PSResult.

    PSResult.__post_init__ feeds the active timing collector's spawn counter
    (pswindows.py:103-112), so constructing one in a fake worker would make a
    REUSED session claim a spawn that never happened — the exact dishonesty
    AC21 forbids. The duck type carries only the fields _run_inner reads.
    """

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0
        self.timed_out = False
        self.duration_ms = 0

    def ok(self) -> bool:
        return True


def _guest_envelope(stdout: str = "pooled-ok") -> _DuckResult:
    return _DuckResult(stdout=json.dumps(
        {"exit_code": 0, "stdout": stdout, "stderr": ""}
    ))


_CLOSE_NAMES = ("close", "terminate", "kill", "shutdown", "stop", "dispose", "exit")


class FakeWorker:
    """Protocol-generic pooled-worker double.

    Every attribute access becomes a recorded method call answering the canned
    result, so the checks do not depend on the worker method names the fix
    chooses; only the close-family names are special-cased so closure is
    observable whichever spelling the pool uses.
    """

    def __init__(self, factory: RecordingFactory, key, canned) -> None:
        self._factory = factory
        self._key = key
        self._canned = canned
        self.calls: list[tuple] = []
        self.closed = False

    def _close(self, *args, **kwargs) -> None:
        self.closed = True
        self._factory.note_close(self._key)

    def __getattr__(self, name):
        if name in _CLOSE_NAMES:
            return self._close
        if name.startswith("__"):
            raise AttributeError(name)

        def method(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            self._factory.note_strings(args, kwargs)
            return self._canned

        return method


def _key_of(args, kwargs):
    """Normalize the arguments the worker factory was called with into the
    session key, accepting the three obvious spellings (assumption: the pool
    passes the key — as one 4-tuple, as four positionals, or as keyword
    components named after the issue's key tuple)."""
    kw = dict(kwargs)
    for a in args:
        if isinstance(a, (tuple, list)) and len(a) == 4:
            return tuple(a)
    if len(args) == 4:
        return tuple(args)
    by_name = [kw.get(name) for name in ("vm_guid", "cred_profile", "agent_id", "boot_epoch")]
    if all(v is not None for v in by_name):
        return tuple(by_name)
    return ("opaque",) + tuple(sorted(repr(k) for k in args))


class RecordingFactory:
    """worker_factory double: records the key each worker is created for,
    every string argument it or its workers ever receive, and every close."""

    def __init__(self, canned=None) -> None:
        self.canned = canned if canned is not None else _guest_envelope()
        self.workers: list[FakeWorker] = []
        self.keys: list[tuple] = []
        self.closed_keys: list[tuple] = []
        self.strings: list[str] = []
        self._mark = 0

    def __call__(self, *args, **kwargs):
        key = _key_of(args, kwargs)
        self.keys.append(key)
        self.note_strings(args, kwargs)
        worker = FakeWorker(self, key, self.canned)
        self.workers.append(worker)
        return worker

    def note_strings(self, args, kwargs) -> None:
        for value in list(args) + list(kwargs.values()):
            if isinstance(value, str):
                self.strings.append(value)

    def note_close(self, key) -> None:
        self.closed_keys.append(key)

    def mark(self) -> None:
        """Freeze the record length, so strings recorded after the mark are
        attributable to the calls made after it."""
        self._mark = len(self.strings)

    def strings_since_mark(self) -> list[str]:
        return self.strings[self._mark:]


class FakePS:
    """Recording run_ps stand-in on tests/unit/test_lifecycle.py's protocol:
    EVERY leg pops exactly one queued response, the by-name resolution leg
    included.

    The pattern-discriminator form (answer the resolver by inspecting the
    script and leave the queue untouched) is deliberately NOT used. It
    desynchronises the queue from the leg count by one for any operation that
    both resolves and acts, which made the lifecycle checks unpassable against
    a correct implementation: the resolver was served without popping, so the
    action leg consumed the prepended resolution response and the state-wait
    leg consumed the action response. Callers that do not resolve (the pool
    checks stub vmident.resolve) simply queue no resolution response.
    """

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []
        self.kwargs = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _stub_resolve(monkeypatch, guid: str = GUID, name: str = "vm1") -> None:
    """Stub vmident.resolve (the seam the trace's own count_sessions.py
    repro uses): a resolved VMRef with no PowerShell leg. Stubbing here —
    rather than serving the resolve leg through a fake run_ps — keeps the
    resolution PSResult (whose __post_init__ feeds the spawn counter) out of
    the timing assertions in AC21."""
    monkeypatch.setattr(
        vmident, "resolve",
        lambda cfg, vm_name="", vm_id="": vmident.VMRef(id=guid, name=vm_name or name),
    )


# ---------------------------------------------------------------------------
# AC1: the config switch
# ---------------------------------------------------------------------------


def test_session_reuse_on_by_default_and_can_be_disabled(tmp_path):
    """AC1: Config() defaults psdirect_session_reuse to True; a config dict /
    file setting it to False loads and turns it off
    ((default, loaded) == (True, False)); a non-bool value is rejected as
    ConfigError (the test_config.py::test_wrong_type_rejected shape)."""
    loaded = Config.from_dict({"schema_version": 1, "psdirect_session_reuse": False})
    assert (Config().psdirect_session_reuse, loaded.psdirect_session_reuse) == (True, False)
    # The file-load route too (Config.load with a written temp file).
    p = tmp_path / "d05-reuse.json"
    p.write_text(
        json.dumps({"schema_version": 1, "psdirect_session_reuse": False}),
        encoding="utf-8",
    )
    assert Config.load(environ={"HYPERV_MCP_CONFIG": str(p)}).psdirect_session_reuse is False
    with pytest.raises(ConfigError):
        Config.from_dict({"psdirect_session_reuse": "yes"})


# ---------------------------------------------------------------------------
# AC2..AC9: the pool itself
# ---------------------------------------------------------------------------


def test_same_key_reuses_one_session():
    """AC2: acquire/release/acquire on one (vm_guid, cred_profile, agent_id,
    boot_epoch) key returns the SAME session object and creates exactly one
    worker."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(worker_factory=factory, clock=SteppyClock())
    key = (GUID, "guest:Administrator", "agent-a", 1)
    first = pool.acquire(key)
    pool.release(first)
    second = pool.acquire(key)
    assert first is second, "a released session must be handed out again by identity"
    assert len(factory.workers) == 1, (
        f"the worker factory ran {len(factory.workers)} times for one key"
    )


def test_sessions_never_shared_across_agents():
    """AC3: two agent ids on the same VM and credential profile get two
    DISTINCT sessions (two workers) — an agent's session state can never be
    observed by another agent."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(
        worker_factory=factory, max_sessions=8, clock=SteppyClock()
    )
    s_a = pool.acquire((GUID, "guest:Administrator", "agent-a", 1))
    s_b = pool.acquire((GUID, "guest:Administrator", "agent-b", 1))
    assert s_a is not s_b, "two agents were handed the same session"
    assert len(factory.workers) == 2, (
        f"two agents shared {len(factory.workers)} worker(s)"
    )


def test_sessions_never_shared_across_credential_profiles():
    """AC4: one agent on the same VM under two credential profiles gets two
    DISTINCT sessions (two workers)."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(
        worker_factory=factory, max_sessions=8, clock=SteppyClock()
    )
    s_guest = pool.acquire((GUID, "guest:Administrator", "agent-a", 1))
    s_victim = pool.acquire((GUID, "victim:victim", "agent-a", 1))
    assert s_guest is not s_victim, "two credential profiles shared one session"
    assert len(factory.workers) == 2, (
        f"two credential profiles shared {len(factory.workers)} worker(s)"
    )


def test_boot_epoch_change_invalidates_session():
    """AC5: acquiring the same vm/profile/agent key with a different
    boot_epoch closes the old worker and creates a new session:
    (new_is_different, closed_keys) == (True, [old_key]). closed_keys is
    observed via the worker factory's close recording — the pool's public
    surface reports closed keys nowhere else (assumption marked in the
    module docstring)."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(
        worker_factory=factory, max_sessions=8, clock=SteppyClock()
    )
    old_key = (GUID, "guest:Administrator", "agent-a", 1)
    new_key = (GUID, "guest:Administrator", "agent-a", 2)
    first = pool.acquire(old_key)
    pool.release(first)
    second = pool.acquire(new_key)
    assert (second is not first, factory.closed_keys) == (True, [old_key]), (
        f"boot-epoch change: new_is_different={second is not first} "
        f"closed_keys={factory.closed_keys}"
    )


def test_invalidate_vm_closes_every_session_for_that_vm_only():
    """AC6: invalidate_vm(guid, reason=...) closes EVERY session for that VM
    GUID (all agents and profiles) and leaves other VMs' sessions alive and
    reusable by identity."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(
        worker_factory=factory, max_sessions=8, clock=SteppyClock()
    )
    keys_vm_a = [
        (GUID, "guest:Administrator", "agent-a", 1),
        (GUID, "guest:Administrator", "agent-b", 1),
        (GUID, "victim:victim", "agent-a", 1),
    ]
    key_vm_b = (GUID_B, "guest:Administrator", "agent-a", 1)
    for key in keys_vm_a:
        pool.release(pool.acquire(key))
    b_session = pool.acquire(key_vm_b)
    pool.release(b_session)
    # Opening the third session RETIRES the first: same VM and agent, different
    # credential profile, so the worker still holding the retired credential
    # must not survive the rotation (PRR-044). Nothing else is closed by merely
    # opening these sessions.
    assert factory.closed_keys == [keys_vm_a[0]], (
        f"opening a rotated-credential session closed {factory.closed_keys}; "
        f"expected exactly the retired {keys_vm_a[0]}"
    )

    pool.invalidate_vm(GUID, reason="test")

    assert set(factory.closed_keys) == set(keys_vm_a), (
        f"invalidate_vm closed {factory.closed_keys}, expected exactly VM A's "
        f"{keys_vm_a}"
    )
    # VM B's session survived and is still reusable without a new worker.
    again = pool.acquire(key_vm_b)
    assert again is b_session, "another VM's session was invalidated"
    assert len(factory.workers) == 4, (
        f"{len(factory.workers)} workers after re-acquiring the surviving "
        f"VM's session (expected the original 4)"
    )


def test_session_in_use_is_not_handed_to_a_second_caller():
    """AC7: acquiring a key that is currently checked out, with wait_s=0,
    raises psdsessions.SessionBusy; the in-use session stays alive and a
    later acquire after release returns that same session."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(worker_factory=factory, clock=SteppyClock())
    key = (GUID, "guest:Administrator", "agent-a", 1)
    held = pool.acquire(key)
    with pytest.raises(psdsessions.SessionBusy):
        pool.acquire(key, wait_s=0)
    assert not factory.workers[0].closed, "the in-use session was closed by the busy refusal"
    pool.release(held)
    again = pool.acquire(key)
    assert again is held
    assert len(factory.workers) == 1


def test_idle_ttl_and_cap_evict_and_close():
    """AC8: a released session idle longer than idle_ttl_s is closed by
    reap(); a released session idle less than the TTL survives reap() and is
    returned by identity on the next acquire. The clock is INJECTED and
    deterministic (fixed step per read plus an explicit jump) — never
    time.sleep, never a statistical pin.

    The over-TTL session is released BEFORE the jump and the under-TTL one
    AFTER it, so the two idle ages differ by the whole jump rather than by the
    clock's own step: a boundary this narrow is what makes the TTL assertion
    mean something instead of passing on any implementation that closes
    everything or nothing."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    clock = SteppyClock()
    pool = psdsessions.SessionPool(
        worker_factory=factory, idle_ttl_s=30, max_sessions=8, clock=clock
    )
    stale_key = (GUID, "guest:Administrator", "agent-a", 1)
    fresh_key = (GUID, "guest:Administrator", "agent-b", 1)
    pool.release(pool.acquire(stale_key))

    clock.jump(31)  # stale has now been idle longer than idle_ttl_s=30
    fresh = pool.acquire(fresh_key)
    pool.release(fresh)

    pool.reap()

    assert factory.closed_keys == [stale_key], (
        f"reap() closed {factory.closed_keys}, expected only the over-TTL "
        f"{stale_key}"
    )
    assert pool.acquire(fresh_key) is fresh, (
        "a session idle less than the TTL was evicted by reap()"
    )
    assert len(factory.workers) == 2


def test_max_sessions_evicts_least_recently_used_idle_session():
    """AC9: with max_sessions=2 and two idle sessions, acquiring a third key
    closes the LEAST RECENTLY USED idle session and creates a third worker:
    (closed, created) == ([lru_key], 3). The LRU victim is made observable by
    TOUCHING the older-inserted session after the newer one, so eviction
    cannot pass on dict insertion order alone."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(
        worker_factory=factory, max_sessions=2, clock=SteppyClock()
    )
    first_inserted = (GUID, "guest:Administrator", "agent-a", 1)
    second_inserted = (GUID, "guest:Administrator", "agent-b", 1)
    third_key = (GUID, "guest:Administrator", "agent-c", 1)

    pool.release(pool.acquire(first_inserted))
    pool.release(pool.acquire(second_inserted))
    # Deliberate LRU touch: re-acquire the FIRST-inserted key so the SECOND
    # one becomes the least recently used.
    touched = pool.acquire(first_inserted)
    pool.release(touched)

    pool.acquire(third_key)  # over the cap: must evict the LRU idle session

    assert (factory.closed_keys, len(factory.workers)) == ([second_inserted], 3), (
        f"cap eviction closed {factory.closed_keys} after "
        f"{len(factory.workers)} workers; expected the LRU "
        f"{second_inserted} and 3 workers"
    )
    # The touched session survived the eviction and is still reusable.
    assert pool.acquire(first_inserted) is touched


# ---------------------------------------------------------------------------
# AC10: lifecycle invalidation hooks
# ---------------------------------------------------------------------------


def test_restore_path_invalidates_sessions(monkeypatch):
    """AC10: checkpoint_restore (confirm=True, PowerShell stubbed the
    tests/unit/test_lifecycle.py way) calls psdsessions.invalidate_vm exactly
    once with reason 'checkpoint_restore'; stop/reset/start do the same with
    their own reason strings."""
    psdsessions = _psdsessions()
    cfg = Config(allowed_vm_patterns=["test-*"], unrestricted=False)
    cfg.destructive.checkpoint_restore = True
    cfg.destructive.stop = True
    cfg.destructive.reset = True
    calls: list[tuple] = []
    monkeypatch.setattr(
        psdsessions,
        "invalidate_vm",
        lambda guid, reason=None: calls.append((guid, reason)),
    )

    # checkpoint_restore: resolution leg, restore leg, state-wait leg.
    monkeypatch.setattr(pswindows, "run_ps", FakePS([
        RESOLUTION,
        pswindows.PSResult(stdout="", returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Off"}), returncode=0),
    ]))
    out = lifecycle.checkpoint_restore(cfg, "test-vm", "pre-d05", confirm=True)
    assert out["state"] == "Off" and "note" in out
    assert calls == [(GUID, "checkpoint_restore")], (
        f"checkpoint_restore recorded {calls}"
    )

    # stop_vm with its own reason.
    calls.clear()
    monkeypatch.setattr(pswindows, "run_ps", FakePS([
        RESOLUTION,
        pswindows.PSResult(stdout=json.dumps({"initial_state": "Running"}), returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Off"}), returncode=0),
    ]))
    lifecycle.stop_vm(cfg, "test-vm", "turnoff", confirm=True)
    assert calls == [(GUID, "stop")], f"stop_vm recorded {calls}"

    # reset_vm with its own reason.
    calls.clear()
    monkeypatch.setattr(pswindows, "run_ps", FakePS([
        RESOLUTION,
        pswindows.PSResult(stdout="", returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Running"}), returncode=0),
    ]))
    lifecycle.reset_vm(cfg, "test-vm", confirm=True)
    assert calls == [(GUID, "reset")], f"reset_vm recorded {calls}"

    # start_vm with its own reason.
    calls.clear()
    monkeypatch.setattr(pswindows, "run_ps", FakePS([
        RESOLUTION,
        pswindows.PSResult(stdout=json.dumps({"initial_state": "Off"}), returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Running"}), returncode=0),
    ]))
    lifecycle.start_vm(cfg, "test-vm")
    assert calls == [(GUID, "start")], f"start_vm recorded {calls}"


# ---------------------------------------------------------------------------
# AC17: remote-host mode never pools
# ---------------------------------------------------------------------------


def test_remote_host_mode_never_uses_pooled_worker(monkeypatch):
    """AC17: with cfg.hyperv.host set (issue #43 remote mode), guest_run_ps
    takes the per-call path unchanged — the remote-hop envelope goes through
    pswindows.run_ps — and NEVER acquires a pooled worker. The installed
    pool's acquire raises, so any pooled acquisition fails the check."""
    psdsessions = _psdsessions()
    for var in (
        "HYPERV_HOST_USERNAME", "HYPERV_HOST_PASSWORD", "HYPERV_HOST_PASSWORD_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    cfg = Config.from_dict({
        "hyperv": {"host": "nuc01"},
        "allowed_vm_patterns": ["test-*"],
    })

    attempts: list[tuple] = []

    class _NoAcquirePool(psdsessions.SessionPool):
        def acquire(self, *args, **kwargs):
            # Record FIRST, then raise. The pooled path's documented contract is
            # to fall back to the per-call path when the pool cannot serve a
            # call, which swallows this exception — so the attempt, not the
            # exception, is what the check must observe.
            attempts.append((args, kwargs))
            raise AssertionError(
                "remote mode acquired a pooled worker "
                f"({args!r} {kwargs!r})"
            )

    # Assumption: the module-level DEFAULT pool is the attribute the guest
    # path consults; installing a hostile subclass makes any use fatal.
    monkeypatch.setattr(
        psdsessions, "DEFAULT",
        _NoAcquirePool(worker_factory=RecordingFactory(), clock=SteppyClock()),
    )

    fake = FakePS([
        RESOLUTION,  # the by-name resolution leg
        pswindows.PSResult(
            stdout=json.dumps({"exit_code": 0, "stdout": "remote-ok", "stderr": ""}),
            returncode=0,
        ),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(cfg, "test-vm", "Get-Date", cred=CRED)
    assert out.get("ok") is True, out
    # The per-call path was taken: the by-name resolution leg plus the
    # remote-hop envelope leg (tests/unit/test_remote_psdirect_hop.py shape).
    assert len(fake.scripts) == 2, (
        f"remote mode made {len(fake.scripts)} run_ps legs: {fake.scripts}"
    )
    assert "Invoke-Command -ComputerName 'nuc01'" in fake.scripts[1]
    assert "Invoke-Command -VMId" in fake.scripts[1]
    assert attempts == [], (
        f"remote mode attempted {len(attempts)} pooled acquisition(s); the "
        f"per-call path must be taken whenever hyperv.host is set"
    )


# ---------------------------------------------------------------------------
# AC18: lifespan teardown closes pooled workers
# ---------------------------------------------------------------------------


def test_lifespan_teardown_closes_pooled_workers(monkeypatch):
    """AC18: exiting the lifespan built by server._make_tool_limiter_lifespan
    closes EVERY pooled worker (driven as an async context manager), so no
    idle-TTL wait is needed for the host powershell count to return to zero."""
    psdsessions = _psdsessions()
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(
        worker_factory=factory, max_sessions=8, clock=SteppyClock()
    )
    keys = [
        (GUID, "guest:Administrator", "agent-a", 1),
        (GUID, "guest:Administrator", "agent-b", 1),
        (GUID_B, "guest:Administrator", "agent-a", 1),
    ]
    for key in keys:
        pool.release(pool.acquire(key))
    assert len(factory.workers) == 3 and not any(w.closed for w in factory.workers)

    monkeypatch.setattr(psdsessions, "DEFAULT", pool)
    lifespan = server_module._make_tool_limiter_lifespan(8)

    async def drive() -> None:
        async with lifespan(None):
            return None

    asyncio.run(drive())

    assert all(w.closed for w in factory.workers), (
        f"{sum(1 for w in factory.workers if w.closed)}/3 pooled workers were "
        f"closed at lifespan exit"
    )


# ---------------------------------------------------------------------------
# AC19: guest vs victim credentials never share a session
# ---------------------------------------------------------------------------


def test_guest_and_victim_creds_get_distinct_sessions(monkeypatch):
    """AC19: one agent calling guest_run_ps then victim_run_ps on the same VM
    gets two DISTINCT sessions (the victim credential set is a distinct
    credential profile; sharing would escalate the unprivileged identity into
    the admin session). Driven through the real entry points with the pool
    installed and a recording worker factory."""
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True)
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(
        worker_factory=factory, max_sessions=8, clock=SteppyClock()
    )
    monkeypatch.setattr(psdsessions, "DEFAULT", pool)
    _stub_resolve(monkeypatch)

    admin = guestexec.guest_run_ps(cfg, "vm1", "Write-Output admin", cred=CRED)
    victim = guestexec.victim_run_ps(cfg, "vm1", "Write-Output victim", cred=VICTIM)
    assert admin.get("ok") is True, admin
    assert victim.get("ok") is True, victim
    assert len(factory.workers) == 2, (
        f"guest and victim credentials shared {len(factory.workers)} session(s)"
    )
    assert factory.workers[0] is not factory.workers[1]


# ---------------------------------------------------------------------------
# AC21: one session establishment, honest second-call timing
# ---------------------------------------------------------------------------


def test_second_call_reuses_session_and_reports_zero_spawns(monkeypatch, tmp_path):
    """AC21: with the pool installed and an agent identity present, two
    guest_run_ps calls on the same VM and credential establish exactly ONE
    PowerShell Direct session in total (counted over the scripts the worker
    factory and its workers receive: a script containing
    'Invoke-Command -VMId' or 'New-PSSession -VMId' is an establishment), and
    the second call's audit timing reports ps_spawns == 0 with
    psdirect_session_ms absent (None)."""
    from mcp.server.auth.middleware.auth_context import (
        AuthenticatedUser,
        auth_context_var,
    )
    from mcp.server.auth.provider import AccessToken

    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True)
    log = tmp_path / "audit-d05-reuse.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(worker_factory=factory, clock=SteppyClock())
    monkeypatch.setattr(psdsessions, "DEFAULT", pool)
    _stub_resolve(monkeypatch)

    user = AuthenticatedUser(AccessToken(token="t", client_id="agent-a", scopes=[]))
    ctx_token = auth_context_var.set(user)
    try:

        def one_call(marker: str) -> dict:
            with auditlog.operation(
                tool="d05-guest-reuse", vm_name="vm1", category="guest"
            ) as op:
                result = guestexec.guest_run_ps(
                    cfg, "vm1", f"Write-Output {marker}", cred=CRED
                )
                op.exit_code = result.get("exit_code")
                op.ok = bool(result.get("ok", True))
                return result

        first = one_call("one")
        second = one_call("two")
    finally:
        auth_context_var.reset(ctx_token)
    assert first.get("ok") is True and second.get("ok") is True, (first, second)

    establishments = {
        s for s in factory.strings
        if "Invoke-Command -VMId" in s or "New-PSSession -VMId" in s
    }
    assert len(establishments) == 1, (
        f"{len(establishments)} distinct PS Direct session-establishing "
        f"scripts reached the pooled workers: {sorted(establishments)[:1]}"
    )
    # The set above DEDUPES: an implementation that opens a fresh worker per
    # call with a byte-identical establishment script would still report one
    # distinct script. The worker count is the occurrence oracle, so the pair
    # is what actually proves reuse.
    assert len(factory.workers) == 1, (
        f"{len(factory.workers)} pooled workers were created for two same-key "
        f"calls; the second call did not reuse the session"
    )
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2, f"expected two audit rows, got {len(rows)}"
    timing = rows[-1].get("timing") or {}
    assert timing.get("ps_spawns") == 0, (
        f"the reused call reported ps_spawns={timing.get('ps_spawns')!r}"
    )
    assert timing.get("psdirect_session_ms") is None, (
        f"the reused call reported psdirect_session_ms="
        f"{timing.get('psdirect_session_ms')!r}"
    )


# ---------------------------------------------------------------------------
# AC22: the pooled path delivers the password on stdin only
# ---------------------------------------------------------------------------


def test_pooled_password_via_stdin_only(monkeypatch):
    """AC22: on the pooled path the password reaches the worker ONLY as
    discrete data (the stdin channel): it is never embedded in any script
    text, never inside a per-call request frame, and — because the
    establishment script is the only variable content a worker spawn carries
    — never in any argv the spawn layer could build. Mirror of
    tests/unit/test_guestexec.py::test_password_via_stdin_not_script for the
    pooled path; with a fake worker there is no process argv to inspect, so
    the recorded strings (factory arguments plus every worker call) are the
    complete secret-bearing surface at this layer."""
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True)
    factory = RecordingFactory()
    pool = psdsessions.SessionPool(worker_factory=factory, clock=SteppyClock())
    monkeypatch.setattr(psdsessions, "DEFAULT", pool)
    _stub_resolve(monkeypatch)

    assert guestexec.guest_run_ps(
        cfg, "vm1", "Write-Output one", cred=CRED
    ).get("ok") is True
    factory.mark()
    assert guestexec.guest_run_ps(
        cfg, "vm1", "Write-Output two", cred=CRED
    ).get("ok") is True

    secret = CRED.password
    secret_b64 = pswindows.utf8_b64(CRED.password)
    # The session really was reused, so the pooled path is the one under test.
    assert len(factory.workers) == 1, (
        f"{len(factory.workers)} workers for two same-key calls"
    )
    # (a) the password DID reach the worker as discrete data — the stdin
    # delivery (assumption: it appears as a standalone argument, exactly the
    # per-call path's stdin_b64 discipline, not embedded in a larger string).
    deliveries = [s for s in factory.strings if s in (secret, secret_b64)]
    assert deliveries, "the password never reached the pooled worker"
    # (b) it never rides inside any script or frame the layer built.
    for recorded in factory.strings:
        if recorded in (secret, secret_b64):
            continue
        assert secret not in recorded and secret_b64 not in recorded, (
            "the password (or its base64 form) was embedded in a pooled-path "
            f"string: {recorded[:120]!r}"
        )
    # (c) the per-call request frames (everything after the first call)
    # never carry it either.
    for frame in factory.strings_since_mark():
        assert secret not in frame and secret_b64 not in frame, (
            f"a request frame leaked the password: {frame[:120]!r}"
        )


# ---------------------------------------------------------------------------
# AC20: the soak harness runs each reuse state
# ---------------------------------------------------------------------------


def test_soak_bench_session_reuse_flag_runs_each_state():
    """AC20: soak_bench --session-reuse off,on accepts the flag, runs the
    harness once per reuse state per agent count, and records the reuse state
    in each emitted row (assumption: the row key is 'session_reuse', the most
    obvious spelling of the flag's name). Driven in-process via
    soak_bench.main (the test_d04_soak_live_gate.py pattern), never shelled
    out."""
    soak_bench = _import_soak_bench()

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = soak_bench.main([
            "--fake", "--agents", "1", "--iterations", "1",
            "--session-reuse", "off,on", "--json",
        ])
    assert rc == 0, f"soak_bench --session-reuse exited {rc}"
    rows = [
        json.loads(line)
        for line in buffer.getvalue().splitlines()
        if line.strip().startswith("{")
    ]
    assert len(rows) == 2, (
        f"expected one row per reuse state, got {len(rows)}: {buffer.getvalue()!r}"
    )
    assert sorted(str(row.get("session_reuse")) for row in rows) == ["False", "True"], (
        f"the rows did not record one run with reuse off and one with it on: {rows}"
    )
    assert all(row.get("agents") == 1 for row in rows), rows
