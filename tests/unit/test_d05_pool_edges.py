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
        self.canned = canned if canned is not None else _envelope()
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
    assert d1 == {"exit_code": 0, "stdout": "pooled-ok", "stderr": ""}, d1
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
    assert out.get("stdout") == "pooled-ok", out
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


@pytest.mark.parametrize("cap,expected", [(8, 6), (3, 1), (1, 1), (64, 62)])
def test_installed_pool_reserves_host_powershell_headroom(cap, expected):
    """AC27: the pool `server.bootstrap` installs derives its session cap from
    the host PowerShell cap with reserved headroom, so pooled workers — each of
    which holds one host-wide slot for its whole lifetime — can never consume
    every slot and starve the per-call legs (resolver legs, lifecycle actions,
    `wait_guest_recovery`)."""
    psdsessions = _psdsessions()
    cfg = Config(unrestricted=True, max_host_powershell=cap)
    pool = psdsessions.install_default_pool(cfg)
    try:
        assert pool is not None, "no pool was installed"
        assert pool.max_sessions == expected, (
            f"max_host_powershell={cap} installed max_sessions={pool.max_sessions}; "
            f"expected {expected} (cap - 2, floor 1)"
        )
        assert pool.max_sessions < cap or cap == 1
    finally:
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
