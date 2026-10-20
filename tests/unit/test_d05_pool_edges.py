"""Frozen acceptance checks for issue #21, AC24-AC27.

These are the checks the plan critic (Round 1, `06-critic-review.md`) required
after finding that the original 21-check set left four plan-named contracts
unpinned. They live in their own file so the frozen blob of
`tests/unit/test_d05_psdirect_sessions.py` is never disturbed by an edit here.

  * AC24 - the credential-profile key component is discriminating for
    same-username/different-password, stable within a process, keyed by a
    process-local secret (so it is not an offline password verifier), and never
    carries the password or any digest of it.
  * AC25 - the pooled path is actually wired into the filetransfer and
    diagnostics chokes, not only into guestexec.
  * AC26 - the pool's failure paths: a broken session is discarded and retried
    exactly once on a fresh session, a timeout kills and evicts its worker and
    reports the base envelope, and a guest-side failure is never retried.
  * AC27 - the installed pool's session cap is derived from the host PowerShell
    cap with reserved headroom.

RED (or deterministic absence) at base 9434636cb035ebdb91415c5e4809ba6db20b05c5;
GREEN after the fix.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import hyperv_mcp.diagnostics as diagnostics
import hyperv_mcp.filetransfer as filetransfer
from hyperv_mcp import guestexec, pswindows, vmident
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.pswindows import PowerShellTransportError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
GUID_B = "a17b3d92-4e50-4c71-9b0d-8f2a51c0664e"

CRED = CredentialSet("Administrator", "d05-pool-pass")
# Same username, different password: the discriminator the original check set
# never exercised (plan-critic probe P2).
CRED_SAME_USER = CredentialSet("Administrator", "d05-other-pass")
CRED_OTHER_USER = CredentialSet("victim", "d05-victim-pass")


def _psdsessions():
    import importlib

    return importlib.import_module("hyperv_mcp.psdsessions")


def _stub_resolve(monkeypatch, guid: str = GUID, name: str = "vm1") -> None:
    monkeypatch.setattr(
        vmident, "resolve",
        lambda cfg, vm_name="", vm_id="": vmident.VMRef(id=guid, name=vm_name or name),
    )


class SteppyClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        self.now += 0.01
        return self.now

    def jump(self, seconds: float) -> None:
        self.now += seconds


class _DuckResult:
    """A run_ps-shaped result that is deliberately NOT a pswindows.PSResult:
    PSResult.__post_init__ feeds the timing collector's spawn counter, so
    constructing one in a fake worker would make a REUSED session claim a host
    spawn that never happened."""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0
        self.timed_out = False
        self.duration_ms = 0


def _envelope(stdout: str = "pooled-ok") -> _DuckResult:
    return _DuckResult(stdout=json.dumps({"exit_code": 0, "stdout": stdout, "stderr": ""}))


_CLOSE_NAMES = ("close", "terminate", "kill", "shutdown", "stop", "dispose", "exit")


class FakeWorker:
    """Protocol-generic pooled-worker double. Any attribute access becomes a
    recorded method call answering the canned result, so the checks do not
    depend on the worker method names the fix chooses; only the close-family
    names are special-cased so closure is observable."""

    def __init__(self, factory: RecordingFactory, key, canned, behaviour=None) -> None:
        self._factory = factory
        self._key = key
        self._canned = canned
        self._behaviour = behaviour
        self.calls: list[tuple] = []
        self.closed = False
        self.run_count = 0
        #: Whether the underlying PROCESS is alive, independent of whether the
        #: pool has closed it. A test models a worker that died by setting this
        #: False, exactly as `PooledWorker._dead` does in production.
        self.process_alive = True

    def is_alive(self) -> bool:
        """Answered TRUTHFULLY, not through `__getattr__`.

        `SessionPool.release` probes this on every release and drops a worker
        that reports dead. A `__getattr__` answer would hand back the canned
        result — truthy — so no test could ever observe a dead worker being
        dropped, and the probe itself would be recorded as a call, inflating
        `run_count` and contaminating any retry oracle built on it.
        """
        return self.process_alive and not self.closed

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
            self.run_count += 1
            if self._behaviour is not None:
                outcome = self._behaviour(self.run_count)
                if isinstance(outcome, Exception):
                    raise outcome
                if outcome is not None:
                    return outcome
            return self._canned

        return method


class RecordingFactory:
    """worker_factory double: records the key each worker is created for, every
    string argument it or its workers ever receive, and every close."""

    def __init__(self, canned=None, behaviour=None) -> None:
        # The canned response models the REAL worker: `stdout` is the per-call
        # wrapper, and the wrapper's own `stdout` is the guest payload.
        self.canned = canned if canned is not None else _DuckResult(stdout=json.dumps({
            "exit_code": 0,
            "stdout": json.dumps({"probe": "pooled-ok"}),
            "stderr": "",
        }))
        self.behaviour = behaviour
        self.workers: list[FakeWorker] = []
        self.keys: list[tuple] = []
        self.closed_keys: list[tuple] = []
        self.strings: list[str] = []

    def __call__(self, *args, **kwargs):
        for value in list(args) + list(kwargs.values()):
            if isinstance(value, (tuple, list)) and len(value) == 4:
                key = tuple(value)
                break
        else:
            key = tuple(args) if len(args) == 4 else ("opaque",) + tuple(sorted(repr(a) for a in args))
        self.keys.append(key)
        self.note_strings(args, kwargs)
        worker = FakeWorker(self, key, self.canned, self.behaviour)
        self.workers.append(worker)
        return worker

    def note_strings(self, args, kwargs) -> None:
        for value in list(args) + list(kwargs.values()):
            if isinstance(value, str):
                self.strings.append(value)

    def note_close(self, key) -> None:
        self.closed_keys.append(key)


def _pool(factory, **kwargs):
    psdsessions = _psdsessions()
    params = {"max_sessions": 8, "clock": SteppyClock()}
    params.update(kwargs)
    return psdsessions.SessionPool(worker_factory=factory, **params)


# ---------------------------------------------------------------------------
# AC24: the credential-profile key component
# ---------------------------------------------------------------------------


def test_credential_profile_discriminates_and_is_not_a_password_verifier():
    """AC24: `psdsessions.credential_profile` returns one stable string per
    credential identity and DIFFERENT strings for different identities —
    including two credentials that share a username and differ only by
    password, which is the discrimination the original check set never
    exercised (plan-critic probe P2 collapsed the derivation to `username` and
    every frozen check still passed).

    It must also not be an offline password verifier: the derivation is keyed
    by a process-local secret, so the same credential yields a different string
    in a different process. A truncated SHA-256 of the password would be stable
    across processes and would let anyone with log access verify candidate
    passwords against the recorded value."""
    psdsessions = _psdsessions()
    profile = psdsessions.credential_profile

    same_user = profile(CRED_SAME_USER)
    assert profile(CRED) != same_user, (
        "two credentials differing only by password shared a credential profile"
    )
    assert profile(CRED) != profile(CRED_OTHER_USER)
    # Stable within a process: the same credential always maps to one profile,
    # so a caller re-using its credential reuses its session.
    assert profile(CRED) == profile(CRED)
    for value in (profile(CRED), same_user):
        assert isinstance(value, str) and value, value

    # No password-derived material in the key component.
    for secret in (CRED.password, CRED_SAME_USER.password, pswindows.utf8_b64(CRED.password)):
        for value in (profile(CRED), same_user):
            assert secret not in value, f"the credential profile embedded {secret!r}"
    raw = hashlib.sha256(CRED.password.encode("utf-8")).hexdigest()
    for value in (profile(CRED), same_user):
        assert raw not in value and raw[:16] not in value, (
            "the credential profile is a truncated password digest, i.e. an "
            "offline verifier"
        )

    # Cross-process instability: a different process derives a different string
    # for the same credential, which is what makes it a non-verifier.
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        "from hyperv_mcp.psdsessions import credential_profile as p;"
        "from hyperv_mcp.credentials import CredentialSet as C;"
        f"print(p(C({CRED.username!r}, {CRED.password!r})))"
    )
    root = str(Path(__file__).resolve().parents[2])
    out = subprocess.run(
        [sys.executable, "-c", code, root], capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, f"the child process failed: {out.stderr[-400:]}"
    assert out.stdout.strip() != profile(CRED), (
        "the credential profile is stable across processes, so it is derived "
        "from the password alone and functions as an offline verifier"
    )


# ---------------------------------------------------------------------------
# AC25: the pooled path is wired into the other two chokes
# ---------------------------------------------------------------------------


def test_filetransfer_and_diagnostics_chokes_reuse_one_session(monkeypatch):
    """AC25: the pooled path is wired into `filetransfer` and `diagnostics`, not
    only into `guestexec`.

    The oracle is wiring, NOT key shape: the issue fixes the session key as
    (VM GUID, credential profile, agent id, boot epoch), and all four calls here
    share that key — same VM, same credential, no agent identity — so a
    contract-conforming pool creates exactly ONE worker for all four. An earlier
    revision of this check asserted a second worker after the diagnostics calls,
    which no conforming implementation could pass; the corrected oracle is that
    the single worker served all four calls and that NO per-call `run_ps` leg
    happened, so an un-wired choke cannot pass silently (its per-call leg would
    reach the transport instead of the pool)."""
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True)
    factory = RecordingFactory()
    pool = _pool(factory)
    monkeypatch.setattr(psdsessions, "DEFAULT", pool)
    _stub_resolve(monkeypatch)
    legs = _LegRecorder()
    monkeypatch.setattr(pswindows, "run_ps", legs)

    first = filetransfer.guest_list_dir(cfg, "vm1", "C:\\Windows\\Temp", cred=CRED)
    second = filetransfer.guest_list_dir(cfg, "vm1", "C:\\Windows\\Temp", cred=CRED)
    assert first.get("ok") is True, first
    assert second.get("ok") is True, second

    d1 = diagnostics.run_guest_inner(cfg, GUID, "Write-Output a", CRED)
    d2 = diagnostics.run_guest_inner(cfg, GUID, "Write-Output b", CRED)
    # The worker reports the SAME wrapper the per-call host script reports, so
    # `run_guest_inner` must take one more step than the per-call path and read
    # the wrapper's `stdout`. An earlier revision of this check asserted the
    # WRAPPER was the payload, which is exactly the bug the implementation
    # reviewer caught: the guest payload would have been silently dropped.
    assert d1 == {"probe": "pooled-ok"}, d1
    assert d2 == d1, d2

    assert len(factory.workers) == 1, (
        f"{len(factory.workers)} pooled workers for four same-key calls across "
        f"filetransfer and diagnostics; the key is (VM GUID, credential "
        f"profile, agent id, boot epoch) and all four share it"
    )
    assert len(legs.scripts) == 0, (
        f"{len(legs.scripts)} per-call run_ps leg(s) happened, so a choke was "
        f"left on the per-call path: {legs.scripts[:1]}"
    )
    assert len(factory.workers[0].calls) >= 4, (
        f"the one pooled worker served {len(factory.workers[0].calls)} call(s); "
        f"four were expected"
    )


class _LegRecorder:
    """run_ps stand-in that records scripts and answers plausibly. Present so an
    un-wired choke is VISIBLE (a leg appears) rather than silently spawning a
    real host PowerShell process."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and "$vmTarget" in script:
            return pswindows.PSResult(stdout=GUID, returncode=0)
        return pswindows.PSResult(
            stdout=json.dumps({"exit_code": 0, "stdout": "per-call", "stderr": ""}),
            returncode=0,
        )


# ---------------------------------------------------------------------------
# AC26: the pool's failure paths
# ---------------------------------------------------------------------------


def test_broken_session_is_discarded_and_retried_exactly_once(monkeypatch):
    """AC26a: a pooled call whose session breaks BEFORE any guest-side effect is
    retried exactly once on a fresh session. The worker reports the failure on
    the `session` phase; a failure on the `guest` phase is a guest result and is
    never retried."""
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True)

    # Session-phase failure once, then success: exactly two workers, and the
    # second call's result is the successful one.
    calls = {"n": 0}

    def behaviour(n):
        calls["n"] += 1
        if calls["n"] == 1:
            return _DuckResult(stdout=json.dumps({
                "ok": False, "error": "PSSessionStateBroken", "phase": "session",
            }))
        return None  # fall through to the canned success

    factory = RecordingFactory(behaviour=behaviour)
    pool = _pool(factory)
    monkeypatch.setattr(psdsessions, "DEFAULT", pool)
    _stub_resolve(monkeypatch)

    out = guestexec.guest_run_ps(cfg, "vm1", "Write-Output after-retry", cred=CRED)
    assert out.get("ok") is True, out
    # `guest_run_ps` unwraps the per-call wrapper, so the guest payload is the
    # wrapper's own `stdout`.
    assert out.get("stdout") == json.dumps({"probe": "pooled-ok"}), out
    assert len(factory.workers) == 2, (
        f"{len(factory.workers)} workers for one session-break retry"
    )
    assert factory.closed_keys, "the broken session was not closed"

    # A guest-phase failure is never retried: exactly one worker.
    calls2 = {"n": 0}

    def guest_failure(n):
        calls2["n"] += 1
        return _DuckResult(stdout=json.dumps({
            "ok": False, "error": "guest said no", "phase": "guest", "exit_code": 3,
        }))

    factory2 = RecordingFactory(behaviour=guest_failure)
    pool2 = _pool(factory2)
    monkeypatch.setattr(psdsessions, "DEFAULT", pool2)
    out2 = guestexec.guest_run_ps(cfg, "vm1", "exit 3", cred=CRED)
    assert out2.get("ok") is False, out2
    assert len(factory2.workers) == 1, (
        f"a guest-phase failure was retried ({len(factory2.workers)} workers)"
    )


class _TimedOutResult(_DuckResult):
    """A run_ps-shaped result carrying timed_out, the shape pswindows.run_ps
    produces when its own deadline fires."""

    def __init__(self) -> None:
        super().__init__(stdout="")
        self.timed_out = True


def test_pooled_timeout_kills_the_worker_and_reports_the_base_envelope(monkeypatch):
    """AC26b: a per-call timeout on a pooled worker kills and evicts that worker
    and reports exactly the envelope the per-call path reports at base
    (`timed_out` true, error naming the timeout and "guest execution may still
    be running"). A subsequent call for the same key gets a fresh worker rather
    than the dead one."""
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True)
    factory = RecordingFactory(canned=_TimedOutResult())
    pool = _pool(factory)
    monkeypatch.setattr(psdsessions, "DEFAULT", pool)
    _stub_resolve(monkeypatch)

    out = guestexec.guest_run_ps(
        cfg, "vm1", "Start-Sleep -Seconds 60", timeout_ms=2000, cred=CRED,
    )
    assert out.get("timed_out") is True, out
    assert "may still be running" in (out.get("error") or ""), out
    assert factory.closed_keys, "the timed-out worker was not closed"
    # The eviction is observable through the pool: the next acquire for the same
    # key creates a new worker instead of handing out the dead one.
    again = pool.acquire((GUID, psdsessions.credential_profile(CRED), None, None))
    assert len(factory.workers) == 2, (
        f"{len(factory.workers)} workers after a timeout; the dead worker was "
        f"still in the pool"
    )
    pool.release(again)


# ---------------------------------------------------------------------------
# AC27: the installed pool's session cap
# ---------------------------------------------------------------------------


def test_session_key_repr_masks_the_credential_profile():
    """A pool key must never reach a traceback or a log line with its credential
    profile in it. `SessionBusy(key)` and `raise KeyError(key)` both interpolate
    the key, and the profile is derived from the password — so `__repr__` shows
    the VM GUID and the agent id and replaces the profile with a marker.

    Pinned because the final critic's probe (adding the profile back to `__repr__`)
    survived the whole frozen suite: nothing else asserts the redaction, and a
    future edit to the NamedTuple could quietly undo it.
    """
    psdsessions = _psdsessions()
    key = psdsessions.SessionKey(
        vm_guid=GUID,
        cred_profile=psdsessions.credential_profile(CRED),
        agent_id="agent-a",
        boot_epoch="2026-10-20T00:00:00.0000000Z",
    )
    text = repr(key)
    assert "<redacted>" in text, text
    assert key.cred_profile not in text, text
    assert CRED.password not in text, text
    # The components that are safe to show still are, so a key stays diagnosable.
    assert GUID in text and "agent-a" in text, text


def test_install_default_pool_starts_the_idle_ttl_reaper():
    """The reaper is what makes the idle TTL real.

    `reap()` on its own has no production caller, so without a trigger an idle
    worker holds a decrypted credential and a host PowerShell slot until
    invalidation, cap eviction or server exit. `install_default_pool` therefore
    starts one, and `close_all` stops it.

    Pinned because the final critic's probe (dropping the `start_reaper()` call)
    survived the whole frozen suite: C8 proves `reap()` works when called, and
    nothing proved it gets called.
    """
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True)
    pool = psdsessions.install_default_pool(cfg)
    try:
        assert pool is not None
        assert pool._reaper is not None, (
            "install_default_pool did not start the idle-TTL reaper, so idle "
            "workers are never closed and the README's 300 s claim is false"
        )
        assert pool._reaper._thread.is_alive(), "the reaper thread is not running"
        # close_all must stop it, or a stopped server leaks a live thread.
        pool.close_all()
        assert not pool._reaper._thread.is_alive(), (
            "close_all did not stop the reaper thread"
        )
    finally:
        pool.close_all()
        psdsessions.DEFAULT = None


@pytest.mark.parametrize("cap,expected", [(8, 6), (3, 1), (64, 62), (2, None), (1, None)])
def test_installed_pool_reserves_host_powershell_headroom(cap, expected):
    """AC27: the pool `server.bootstrap` installs derives its session cap from
    the host PowerShell cap with reserved headroom, so pooled workers — each of
    which holds one host-wide slot for its whole lifetime — can never consume
    every slot and starve the per-call legs (resolver legs, lifecycle actions,
    `wait_guest_recovery`).

    At a cap of 1 or 2 there is no headroom to reserve at all: `max(1, cap-2)`
    would install a one-session pool whose single worker can hold the host's
    last slot for the whole idle TTL, so no pool is installed and every guest
    call takes the per-call path (PRR-018)."""
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True, max_host_powershell=cap)
    pool = psdsessions.install_default_pool(cfg)
    try:
        if expected is None:
            assert pool is None, (
                f"max_host_powershell={cap} installed a pool with "
                f"{pool.max_sessions} sessions; at this cap no headroom can be "
                f"reserved, so one idle worker could hold the host's last slot "
                f"for the whole idle TTL and every per-call leg would busy-fail"
            )
            return
        assert pool is not None, "no pool was installed"
        assert pool.max_sessions == expected, (
            f"max_host_powershell={cap} installed max_sessions={pool.max_sessions}; "
            f"expected {expected} (cap - 2, floor 1)"
        )
        assert pool.max_sessions < cap
    finally:
        if pool is not None:
            pool.close_all()
        psdsessions.DEFAULT = None


# ---------------------------------------------------------------------------
# AC29: a FAILED lifecycle action must not invalidate sessions
# ---------------------------------------------------------------------------


def test_failed_lifecycle_action_does_not_invalidate_sessions(monkeypatch):
    """AC29: the invalidation hook fires only after the action SUCCEEDED. A
    `checkpoint_restore` whose restore leg fails must not invalidate any
    session, because a failed restore leaves the guest exactly as it was and
    killing live sessions on a failed action is a self-inflicted outage.

    The hook's placement (after `check_result`, inside the `vm_lock`) is what
    this pins; a hook placed before the action would pass every other check in
    the frozen set (plan-critic probe P3b)."""
    psdsessions = _psdsessions()
    from hyperv_mcp import lifecycle

    cfg = Config(allowed_vm_patterns=["test-*"], unrestricted=False)
    cfg.destructive.checkpoint_restore = True
    calls: list[tuple] = []
    monkeypatch.setattr(
        psdsessions, "invalidate_vm",
        lambda guid, reason=None: calls.append((guid, reason)),
    )
    monkeypatch.setattr(pswindows, "run_ps", _FailingRestorePS())
    with pytest.raises(PowerShellTransportError):
        lifecycle.checkpoint_restore(cfg, "test-vm", "pre-d05", confirm=True)
    assert calls == [], (
        f"a FAILED checkpoint_restore invalidated {calls}; the hook must fire "
        f"only after the action succeeded"
    )


class _FailingRestorePS:
    """Serves the resolution leg, then fails the restore leg."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, script, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return pswindows.PSResult(stdout=GUID, returncode=0)
        return pswindows.PSResult(stdout="", stderr="Restore-VMSnapshot failed", returncode=1)


# ---------------------------------------------------------------------------
# PRR follow-up: the pool's close paths must RETURN, not self-deadlock
# ---------------------------------------------------------------------------


class _CloseSpy:
    """A pooled worker whose close is observable, and whose liveness is fine."""

    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class _MutableClock:
    """A clock the test advances by hand, so an idle-TTL boundary is exact
    rather than a bet on `time.monotonic`'s resolution."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def jump(self, seconds: float) -> None:
        self.now += seconds


def _bounded(label: str, fn, limit_s: float = 5.0):
    """Run ``fn`` on a thread and FAIL if it does not return.

    Every `_close_entries` caller used to hold ``_mu`` while `_close_entries`
    took it again, which self-deadlocks on a plain ``threading.Lock``. Under
    pytest that is a HANG — it reads as a slow suite, not a failure — so these
    pins assert the call RETURNS, on a daemon thread the test can abandon.
    """
    box: dict = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # re-raised on the asserting thread
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(limit_s)
    assert not thread.is_alive(), (
        f"{label} did not return within {limit_s}s: the session pool "
        f"deadlocked. A close helper called with _mu held must not take _mu "
        f"itself."
    )
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _key(guid: str, profile: str = "p", agent: str = "a", epoch=None):
    return _psdsessions().SessionKey(
        vm_guid=guid, cred_profile=profile, agent_id=agent, boot_epoch=epoch
    )


def test_every_close_path_returns_instead_of_self_deadlocking():
    """Each way a session leaves the pool must complete.

    `invalidate_vm` (every lifecycle hook), `discard` (every failed pooled
    call), `release` of a doomed entry, `reap` past the idle TTL and cap
    eviction all remove entries and then close the workers. When the removal
    and the close share one non-reentrant lock hold, every one of those paths
    hangs the tool call that triggered it — and a hang is invisible to a test
    that only checks the return value.
    """
    psdsessions = _psdsessions()
    made: list[_CloseSpy] = []

    def factory(key, script, stdin_b64=None):
        worker = _CloseSpy()
        made.append(worker)
        return worker

    guid, other = GUID, GUID_B

    # 1. invalidate_vm — the lifecycle-hook path.
    pool = psdsessions.SessionPool(factory, idle_ttl_s=1e9, max_sessions=8)
    pool.release(pool.acquire(_key(guid)))
    assert _bounded("invalidate_vm", lambda: pool.invalidate_vm(guid)) == 1
    assert made[-1].closed == 1, "invalidate_vm did not close the session"

    # 2. discard — the failed-pooled-call path.
    pool = psdsessions.SessionPool(factory, idle_ttl_s=1e9, max_sessions=8)
    held = pool.acquire(_key(guid))
    _bounded("discard", lambda: pool.discard(held))
    assert made[-1].closed == 1, "discard did not close the session"

    # 3. release of a session doomed while it was checked out.
    pool = psdsessions.SessionPool(factory, idle_ttl_s=1e9, max_sessions=8)
    held = pool.acquire(_key(guid))
    _bounded("invalidate while held", lambda: pool.invalidate_vm(guid))
    _bounded("release of doomed", lambda: pool.release(held))
    assert made[-1].closed == 1, "release did not close the doomed session"

    # 4. reap past the idle TTL.
    clock = _MutableClock()
    pool = psdsessions.SessionPool(
        factory, idle_ttl_s=1.0, max_sessions=8, clock=clock
    )
    pool.release(pool.acquire(_key(guid)))
    clock.jump(10.0)
    assert _bounded("reap", lambda: pool.reap()) == 1
    assert made[-1].closed == 1, "reap did not close the idle session"

    # 5. cap eviction.
    pool = psdsessions.SessionPool(factory, idle_ttl_s=1e9, max_sessions=1)
    pool.release(pool.acquire(_key(guid)))
    _bounded("acquire past the cap", lambda: pool.acquire(_key(other)))
    assert made[0].closed == 1, "cap eviction did not close the LRU session"

    # 6. close_all — the server-shutdown path.
    pool = psdsessions.SessionPool(factory, idle_ttl_s=1e9, max_sessions=8)
    pool.release(pool.acquire(_key(guid)))
    assert _bounded("close_all", lambda: pool.close_all()) == 1
    assert made[-1].closed == 1, "close_all did not close the session"


def test_a_missing_session_is_created_not_waited_for():
    """`acquire` CREATES a session when there is none.

    The gate used to be conditioned on a close batch being in flight, so with
    none in flight — the normal case — a missing entry was never created and
    every pooled call burned its whole bounded wait before falling back. The
    pool therefore never reused anything.
    """
    psdsessions = _psdsessions()
    made: list[_CloseSpy] = []

    def factory(key, script, stdin_b64=None):
        worker = _CloseSpy()
        made.append(worker)
        return worker

    pool = psdsessions.SessionPool(factory, idle_ttl_s=1e9, max_sessions=8)
    worker = _bounded("acquire of a missing session", lambda: pool.acquire(_key(GUID)))
    assert worker is made[0], "acquire did not create the missing session"
    assert pool.stats()["sessions"] == 1

    # And the SAME key hands back the same worker: that is the whole feature.
    pool.release(worker)
    again = _bounded("re-acquire", lambda: pool.acquire(_key(GUID)))
    assert again is worker, "a released session was not reused"
    assert len(made) == 1, "a second worker was spawned for a reusable session"


def test_a_spawn_failure_propagates_instead_of_burning_the_wait():
    """A factory that cannot spawn fails the call at once.

    Retrying a spawn that cannot succeed would only consume the bounded wait,
    and the caller's per-call fallback is the correct response — so the error
    must surface, not be waited out.
    """
    psdsessions = _psdsessions()

    def exploding_factory(key, script, stdin_b64=None):
        raise PowerShellTransportError("no host PowerShell available")

    pool = psdsessions.SessionPool(exploding_factory, idle_ttl_s=1e9, max_sessions=8)

    started = time.monotonic()
    with pytest.raises(PowerShellTransportError):
        _bounded("acquire with a failing factory", lambda: pool.acquire(_key(GUID), 30.0))
    elapsed = time.monotonic() - started
    assert elapsed < 5.0, (
        f"a spawn that cannot succeed was retried for {elapsed:.1f}s instead "
        f"of failing the call"
    )
    assert pool.stats()["sessions"] == 0, "a failed spawn left an entry behind"


class _EofResult(_DuckResult):
    """The shape `PooledWorker.run` returns when the worker exits WITHOUT
    answering: no wrapper, no return code, and `phase="session"` because the
    transport — not the guest scriptblock — gave up."""

    def __init__(self) -> None:
        super().__init__(stdout="")
        self.returncode = None
        self.phase = "session"


def test_a_worker_that_died_mid_script_is_not_retried(monkeypatch):
    """PRR-062: a worker that dies or answers unreadably says NOTHING about
    whether the guest scriptblock ran, so the call is neither retried nor
    silently re-run through the per-call fallback — both would repeat a script
    that may already have had its effect (a checkpoint, a file write, a guest
    reboot).

    The positive control is `test_broken_session_is_discarded_and_retried_
    exactly_once` above: a worker that REPORTS `phase: "session"` in its own
    wrapper is retried, because that is the guest scriptblock stating it never
    entered the inner script. This pin is the negative half — the same
    `phase="session"` string arriving WITHOUT a wrapper must not move.
    """
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True)

    def always_eof(n):
        # The process is gone: that is what an EOF answer means, and it is why
        # the worker must be dropped rather than handed to the next caller.
        factory.workers[-1].process_alive = False
        return _EofResult()

    factory = RecordingFactory(behaviour=always_eof)
    pool = _pool(factory)
    monkeypatch.setattr(psdsessions, "DEFAULT", pool)
    _stub_resolve(monkeypatch)

    out = guestexec.guest_run_ps(cfg, "vm1", "New-Checkpoint", cred=CRED)
    assert out.get("ok") is False, out
    assert out.get("error_class") == "transport", (
        f"a worker that died mid-script was reported as {out.get('error_class')!r}, "
        f"not a transport failure"
    )
    assert len(factory.workers) == 1, (
        f"a worker that died mid-script was retried ({len(factory.workers)} "
        f"workers); the script may already have run in the guest"
    )
    assert factory.closed_keys, "the dead worker was not closed"


def test_a_failed_create_does_not_strand_doomed_entries(monkeypatch):
    """A create that fails AFTER the retire/stale-epoch collectors have marked
    their entries must not leak them.

    Those collectors set `doomed = True` before the spawn. Nothing else ever
    closes a doomed entry — `reap` and `acquire` both skip them, and `release`
    closes only the entry for the worker being returned — so leaving one
    marked-but-open holds a host-wide slot and a live session with a decrypted
    credential for the life of the process.

    There are TWO reachable triggers, and the guard covers both:

      1. `establishment_script` raising between the collectors and the spawn;
      2. `_capacity_victims` raising `SessionBusy`.

    Trigger 2 is the subtle one. `_retire_victims` marks its entries doomed but
    LEAVES them in `_entries`, and `_capacity_victims`'s candidate filter is
    `not e.doomed` — so the retired entries are invisible to it. Its loop
    condition counts its OWN local victim list, which starts empty, so the
    condition `len(self._entries) - 0 >= max_sessions` holds on a full pool and
    the generator finds nothing evictable. It raises with the caller's victim
    list non-empty. Verified by execution across caps 1, 2, 3, 4 and 8: the
    retired entry is doomed, `_capacity_victims` raises, and without the guard
    nothing ever closes it.
    """
    psdsessions = _psdsessions()
    closed: list = []
    made: list = []

    class Spy:
        def __init__(self, tag):
            self.tag = tag

        def close(self):
            closed.append(self.tag)

    def factory(key, script, stdin_b64=None):
        worker = Spy(f"{key.cred_profile}:{len(made)}")
        made.append(worker)
        return worker

    real_script = psdsessions.establishment_script
    armed = {"fail": False}

    def exploding_script(key, cred):
        if armed["fail"]:
            raise PowerShellTransportError(
                "could not build the establishment script"
            )
        return real_script(key, cred)

    monkeypatch.setattr(psdsessions, "establishment_script", exploding_script)

    pool = psdsessions.SessionPool(factory, idle_ttl_s=1e9, max_sessions=8)
    # An idle session under profile p1: a rotated password retires it.
    pool.release(pool.acquire(_key(GUID, "p1"), 1.0))
    assert pool.stats()["sessions"] == 1
    armed["fail"] = True

    with pytest.raises(PowerShellTransportError):
        pool.acquire(_key(GUID, "p2"), 1.0)

    assert closed, (
        "the retired entry was doomed but never closed; it holds a host-wide "
        "slot and a live session with a decrypted credential"
    )
    assert pool.stats()["sessions"] == 0, (
        f"the pool still holds {pool.stats()['sessions']} doomed entries, so "
        f"they occupy capacity nothing can reclaim"
    )
    # The pool is still usable afterwards: a later create succeeds.
    armed["fail"] = False
    pool.release(pool.acquire(_key(GUID, "p3"), 1.0))
    assert pool.stats()["sessions"] == 1


def test_a_capacity_busy_does_not_strand_the_retired_entry():
    """The second reachable trigger for the same leak: the pool is full.

    `_retire_victims` marks the retired entry doomed but leaves it in
    `_entries`; `_capacity_victims` filters on `not e.doomed`, so it cannot see
    it, and its loop condition counts its own (empty) local list. It therefore
    raises `SessionBusy` while the caller's victim list is non-empty. Without the
    guard the retired entry stays doomed-but-open forever: `reap` and `acquire`
    skip doomed, and `release` closes only the entry for the worker returned.
    """
    psdsessions = _psdsessions()
    closed: list = []

    class Spy:
        def __init__(self, tag):
            self.tag = tag

        def close(self):
            closed.append(self.tag)

    made: list = []

    def factory(key, script, stdin_b64=None):
        worker = Spy(f"{key.cred_profile}:{len(made)}")
        made.append(worker)
        return worker

    pool = psdsessions.SessionPool(factory, idle_ttl_s=1e9, max_sessions=2)
    # An idle session under p1 (the one a rotation retires), plus one checked
    # out for another VM so the pool is at its cap.
    pool.release(pool.acquire(_key(GUID, "p1"), 1.0))
    held = pool.acquire(_key(GUID_B, "p1"), 1.0)
    assert pool.stats()["sessions"] == 2

    with pytest.raises(psdsessions.SessionBusy):
        pool.acquire(_key(GUID, "p2"), 1.0)

    assert closed, (
        "the retired entry was doomed by the rotation but never closed; it "
        "holds a host-wide slot and a live session with a decrypted credential"
    )
    assert pool.stats()["doomed"] == 0, (
        f"{pool.stats()['doomed']} doomed entries survived the failed create"
    )
    # The other VM's session is untouched and still checked out to its caller.
    pool.release(held)
    assert pool.stats()["sessions"] == 1
