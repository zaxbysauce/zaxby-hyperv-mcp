"""Reusable PowerShell Direct sessions — one long-lived host worker per key.

The problem this closes (issue #21 / ENH-05): every guest-facing call used to
start a fresh host ``powershell.exe`` and open a fresh PowerShell Direct session
inside it, because :func:`pswindows.run_ps` ties each child to a kill-on-close
Job Object and returns only after the process exits. No session could outlive
the call that created it, so the session-establishment cost was paid on every
call and nothing could be invalidated when the guest changed underneath.

This module owns the session side of the fix: a pool of long-lived host
PowerShell workers, each hosting ONE PSSession, keyed by

    (vm_guid, cred_profile, agent_id, boot_epoch)

Microsoft documents that persistent PowerShell Direct sessions retain state
(variables, imported modules, location), which is exactly why the key carries
the agent id and the credential profile: a session is never handed to a caller
that is not the one it was opened for. A session is also never handed out after
the guest it points at has been rolled back or rebooted — the boot epoch is part
of the key, and the lifecycle operations that change the guest call
:func:`invalidate_vm`.

Layering. This module owns the SESSION semantics (keying, isolation,
invalidation, cap, idle TTL, one pipeline at a time). It does not own the
transport: the caller supplies a ``worker_factory`` that turns
``(key, establishment_script, stdin_b64)`` into a worker object exposing
``run(inner_script, ...)`` and ``close()``. :mod:`hyperv_mcp.pswindows` supplies
the default factory, which spawns the host ``powershell.exe`` with the same Job
Object, suspended-start and slot plumbing every other spawn uses. That split is
what lets the whole contract be tested with a recording fake and no Hyper-V.

What this module deliberately does NOT do:
  * it never resolves a VM name — the caller has already resolved the identity
    (``vmident.resolve``) and the key carries the GUID;
  * it never touches the remote-Hyper-V-host hop (issue #43) — a pooled worker
    would have to be spawned on the remote host through a second transport,
    which is out of scope, so the pooled branches are local-mode only;
  * it keeps no durable state; every session dies with the process.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from collections.abc import Callable
from typing import Any, NamedTuple

from .credentials import CredentialSet

#: The default idle lifetime of a released session. Each live worker is a host
#: process holding a decrypted credential in memory, so an unused one must not
#: linger indefinitely.
DEFAULT_IDLE_TTL_S = 300.0

#: The default session cap when a pool is installed without an explicit one.
#: ``install_default_pool`` derives the real value from the host PowerShell cap
#: (see there); this is the floor for a pool constructed directly.
DEFAULT_MAX_SESSIONS = 4

#: How long ``acquire`` waits for a checked-out key before giving up, when the
#: caller passes ``wait_s=0`` — i.e. immediately.
POLL_INTERVAL_S = 0.02

#: Process-local secret keying the credential-profile fingerprint. Generated
#: once per process with ``os.urandom`` and never persisted, so the same
#: credential yields a different string in a different process. That is the
#: property that makes the fingerprint a non-verifier: without the key, an
#: observed value cannot be checked against candidate passwords offline.
_PROFILE_KEY = os.urandom(32)


class SessionBusy(RuntimeError):
    """Every session for this key is checked out, or the cap is saturated with
    in-use sessions and nothing can be evicted.

    Retryable by contract: the caller either waits (``wait_s > 0``) or reports
    the same busy envelope a saturated host PowerShell pool reports.
    """


class SessionKey(NamedTuple):
    """The pool key: (VM GUID, credential profile, agent id, boot epoch).

    ``agent_id`` is the authenticated bearer-token ``client_id``
    (``auditlog.current_agent_id``) and is ``None`` on the paths that carry no
    identity — plain stdio, ``--standalone`` and ``--allow-anonymous``.
    README.md:1078-1080 documents that in those modes all callers form one
    local principal, so ``None`` is one legitimate bucket rather than a
    blocker.

    ``boot_epoch`` is whatever the caller can say about the guest's current
    boot; ``None`` means "not tracked", and live detection then falls to the
    lifecycle hooks plus the broken-session retry.
    """

    vm_guid: str
    cred_profile: str
    agent_id: str | None
    boot_epoch: str | None

    def __repr__(self) -> str:
        # The credential profile is derived from the password, so a key must
        # never be interpolated into an exception message, a log line or a
        # traceback. Everything except that one component is safe to show.
        return (
            f"SessionKey(vm_guid={self.vm_guid!r}, cred_profile=<redacted>, "
            f"agent_id={self.agent_id!r}, boot_epoch={self.boot_epoch!r})"
        )


def credential_profile(cred: CredentialSet) -> str:
    """The credential-profile component of a session key.

    Workstream G PR 1 (issue #30) owns real per-VM credential profiles and is
    still open, so no profile name exists in the tree yet. Until it lands there
    is exactly one global credential set per process, and the profile is
    derived from the credential IDENTITY: the username, for debuggability, plus
    16 hex characters of an HMAC-SHA-256 over the username and password under
    the process-local :data:`_PROFILE_KEY`.

    Why not a plain digest of the password: a truncated SHA-256 of the password
    is an offline dictionary verifier — anyone who reads a pool key out of a
    log line goes from "nothing" to "verify candidate passwords against
    ``Administrator:6b1f…``". Keying the HMAC with a per-process random secret
    removes that: the same credential produces a different string in a
    different process, so an observed value verifies nothing anywhere else.

    Discriminating today: two credentials that share a username and differ only
    by password get different profiles, so a rotated password can never inherit
    a session opened under the old one. Stable within a process, so a caller
    that re-resolves the same credential reuses its session.

    When Workstream G lands, this function is the one place that changes.
    """
    digest = hmac.new(
        _PROFILE_KEY,
        f"{cred.username}\0{cred.password}".encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"{cred.username}:{digest}"


class _Entry:
    """One pooled session: its worker, its checkout state and its idle clock."""

    __slots__ = ("key", "worker", "in_use", "last_used", "doomed", "open_ms")

    def __init__(self, key: SessionKey, worker: Any, open_ms: int | None = None) -> None:
        self.key = key
        self.worker = worker
        self.in_use = False
        self.last_used = 0.0
        self.doomed = False
        #: Milliseconds spent spawning this worker and establishing its session.
        #: Reported once, on the call that opened it, and never again.
        self.open_ms = open_ms


class SessionPool:
    """A bounded pool of long-lived pooled workers, one session per key.

    Thread safety. ``_mu`` guards the entry table and every field mutation.
    Creation happens OUTSIDE ``_mu`` under a per-key gate, so opening a session
    for one VM never blocks a caller opening one for another; the gate makes two
    concurrent acquires of the same missing key create exactly one worker.
    Closing also happens outside ``_mu`` (snapshot under the lock, release
    outside it — the pattern ``relay.py`` uses), so a slow kill never stalls
    unrelated keys.
    """

    def __init__(
        self,
        worker_factory: Callable[..., Any],
        *,
        idle_ttl_s: float = DEFAULT_IDLE_TTL_S,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not callable(worker_factory):
            raise TypeError("worker_factory must be callable")
        self._factory = worker_factory
        self._idle_ttl_s = float(idle_ttl_s)
        self.max_sessions = max(1, int(max_sessions))
        self._clock = clock if clock is not None else time.monotonic
        self._mu = threading.Lock()
        self._entries: dict[SessionKey, _Entry] = {}
        self._gates: dict[SessionKey, threading.Lock] = {}
        self._closed = False
        self._reaper: _Reaper | None = None
        self.invalidated = 0
        self.evicted = 0
        self.reaped = 0

    def start_reaper(self) -> None:
        """Start the idle-TTL reaper. Idempotent; the server-shutdown path stops
        it through `close_all`."""
        if self._reaper is None and not self._closed:
            self._reaper = _Reaper(self, self._idle_ttl_s / 4.0)
            self._reaper.start()

    # -- acquisition -------------------------------------------------------

    def acquire(
        self,
        key: SessionKey,
        wait_s: float = 0.0,
        *,
        cred: CredentialSet | None = None,
    ) -> Any:
        """Check out the session for ``key``, creating it if needed.

        ``cred`` is consulted ONLY when a worker must be created: it supplies
        the username for the establishment script and the base64 password that
        crosses to the worker on stdin. It is ignored on reuse, because the key
        already determines the session.

        Returns the worker. The caller MUST pass it to :meth:`release` (or
        :meth:`discard`) in a ``finally``.
        """
        key = _as_key(key)
        deadline = self._clock() + max(0.0, float(wait_s))
        while True:
            with self._mu:
                if self._closed:
                    raise SessionBusy("the session pool is closed")
                entry = self._entries.get(key)
                if entry is not None and not entry.doomed and not entry.in_use:
                    entry.in_use = True
                    entry.last_used = self._clock()
                    return entry.worker
                gate = self._gates.setdefault(key, threading.Lock()) if entry is None else None
            if gate is not None:
                with gate:
                    worker = self._create_locked(key, cred)
                    if worker is not None:
                        return worker
                    # Another thread created it while we held the gate and it
                    # is checked out; fall through to the bounded wait.
            if self._clock() >= deadline:
                raise SessionBusy(
                    f"every session for {key!r} is in use; waited "
                    f"{max(0.0, float(wait_s)):g}s"
                )
            time.sleep(POLL_INTERVAL_S)

    def _create_locked(self, key: SessionKey, cred: CredentialSet | None) -> Any:
        """Create the worker for ``key``, or return None if it now exists and is
        checked out. Runs with the per-key gate held and ``_mu`` released for
        the spawn itself."""
        with self._mu:
            entry = self._entries.get(key)
            if entry is not None and not entry.doomed:
                if entry.in_use:
                    return None
                entry.in_use = True
                entry.last_used = self._clock()
                return entry.worker
            self._close_stale_epochs(key)
            self._evict_for_capacity()
            script, stdin_b64 = establishment_script(key, cred)
            opened_at = self._clock()
        worker = self._factory(key, script, stdin_b64)
        open_ms = int((self._clock() - opened_at) * 1000)
        with self._mu:
            self._gates.pop(key, None)
            if self._closed:
                # Closed while we were spawning: do not strand the child.
                _close_quietly(worker)
                raise SessionBusy("the session pool is closed")
            fresh = _Entry(key, worker, open_ms)
            fresh.in_use = True
            fresh.last_used = self._clock()
            self._entries[key] = fresh
        return worker

    def _close_stale_epochs(self, key: SessionKey) -> None:
        """Close sessions for the same VM, credential profile and agent whose
        boot epoch no longer matches ``key``.

        A guest reboot breaks the underlying VMBus session, so a session opened
        under an older epoch must never be handed out again. Caller holds
        ``_mu``; the closes happen outside it.
        """
        stale = [
            e for e in self._entries.values()
            if (e.key.vm_guid, e.key.cred_profile, e.key.agent_id)
            == (key.vm_guid, key.cred_profile, key.agent_id)
            and e.key.boot_epoch != key.boot_epoch
            and not e.in_use
            and not e.doomed
        ]
        self._close_entries(stale)

    def _evict_for_capacity(self) -> None:
        """Make room for one more session by closing the least recently used
        IDLE entries. In-use entries are never evicted; when every entry is in
        use the caller gets SessionBusy. Caller holds ``_mu``; the closes happen
        outside it."""
        while len(self._entries) >= self.max_sessions:
            victim = min(
                (e for e in self._entries.values() if not e.in_use and not e.doomed),
                key=lambda e: e.last_used,
                default=None,
            )
            if victim is None:
                raise SessionBusy(
                    f"the session pool is at its cap of {self.max_sessions} and "
                    f"every session is in use"
                )
            self._close_entries([victim])
            self.evicted += 1

    # -- release -----------------------------------------------------------

    def release(self, session: Any) -> None:
        """Return a checked-out session to the pool.

        A session whose worker died underneath it (closed by something other
        than the pool) is dropped rather than handed out again.
        """
        worker = session
        with self._mu:
            entry = next((e for e in self._entries.values() if e.worker is worker), None)
            if entry is None:
                return
            entry.in_use = False
            entry.last_used = self._clock()
            if entry.doomed or _worker_is_dead(worker):
                self._close_entries([entry])

    def discard(self, session: Any) -> None:
        """Drop a checked-out session without returning it: the worker failed,
        timed out, or its guest session broke. Closes the worker now."""
        worker = session
        with self._mu:
            entry = next((e for e in self._entries.values() if e.worker is worker), None)
            if entry is None:
                _close_quietly(worker)
                return
            self._close_entries([entry])

    # -- invalidation ------------------------------------------------------

    def invalidate_vm(self, vm_guid: str, reason: str | None = None) -> int:
        """Close every session for ``vm_guid`` — all agents, all credential
        profiles — and leave other VMs' sessions alone.

        A session that is checked out at invalidation time is marked doomed
        rather than killed mid-pipeline: killing a worker while a caller is
        inside its script would corrupt that caller's result. The lifecycle
        operations that call this hold the VM's write lock, and guest legs hold
        the read lock, so in practice nothing for that GUID is checked out.
        """
        guid = (vm_guid or "").strip().lower()
        with self._mu:
            victims = [e for e in self._entries.values() if e.key.vm_guid == guid]
            for entry in self._entries.values():
                if entry.key.vm_guid == guid:
                    entry.doomed = True
            self._close_entries(victims)
            self.invalidated += len(victims)
            return len(victims)

    def reap(self) -> int:
        """Close sessions idle longer than ``idle_ttl_s``. In-use sessions are
        never reaped — an idle clock is only meaningful for a released one."""
        now = self._clock()
        with self._mu:
            victims = [
                e for e in self._entries.values()
                if not e.in_use and not e.doomed and (now - e.last_used) > self._idle_ttl_s
            ]
            self._close_entries(victims)
            self.reaped += len(victims)
            return len(victims)

    def close_all(self) -> int:
        """Close every session, in use or not. The server-shutdown path."""
        reaper = getattr(self, "_reaper", None)
        if reaper is not None:
            reaper.stop()
        with self._mu:
            self._closed = True
            victims = list(self._entries.values())
            self._close_entries(victims)
            self._gates.clear()
            return len(victims)

    def _close_entries(self, victims: list[_Entry]) -> None:
        """Remove ``victims`` from the table and close their workers. The caller
        holds ``_mu``; closing happens after it is released so a slow kill never
        stalls an unrelated key."""
        if not victims:
            return
        for entry in victims:
            self._entries.pop(entry.key, None)
        workers = [e.worker for e in victims]
        self._mu.release()
        try:
            for worker in workers:
                _close_quietly(worker)
        finally:
            self._mu.acquire()

    # -- introspection -----------------------------------------------------

    def take_open_cost(self, session: Any) -> int | None:
        """The cost of opening `session`, ONCE — consumed so a later reuse of the
        same session reports nothing.

        This is what lets a caller report `psdirect_session_ms` on the call that
        actually paid it and nothing on the calls that did not. The worker is
        checked out by the caller while it holds it, so the consume is race-free.
        """
        worker = session
        with self._mu:
            entry = next((e for e in self._entries.values() if e.worker is worker), None)
            if entry is None:
                return None
            cost, entry.open_ms = entry.open_ms, None
            return cost

    def stats(self) -> dict:
        with self._mu:
            return {
                "sessions": len(self._entries),
                "in_use": sum(1 for e in self._entries.values() if e.in_use),
                "doomed": sum(1 for e in self._entries.values() if e.doomed),
                "max_sessions": self.max_sessions,
                "idle_ttl_s": self._idle_ttl_s,
                "invalidated": self.invalidated,
                "evicted": self.evicted,
                "reaped": self.reaped,
                "closed": self._closed,
            }


# ---------------------------------------------------------------------------
# module-level default pool
# ---------------------------------------------------------------------------

#: The pool the guest modules consult. ``None`` means "no pool installed", which
#: is the state every unit test and every flag-off deployment runs in. Read by
#: attribute lookup at call time, so a monkeypatch or a ``bootstrap`` install is
#: observed by every caller.
DEFAULT: SessionPool | None = None


class _Reaper:
    """Wakes periodically and closes sessions idle past the TTL.

    Without a trigger, `reap()` has no caller and an idle worker holds a
    decrypted credential and a host-wide PowerShell slot until invalidation, cap
    eviction or server exit — which is exactly what the idle TTL exists to
    prevent. A daemon thread is the only thing that can notice a pool nobody is
    calling.
    """

    def __init__(self, pool: SessionPool, every_s: float) -> None:
        self._pool = pool
        self._every_s = max(1.0, float(every_s))
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="psdsessions-reaper", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self._every_s):
            try:
                self._pool.reap()
            except Exception:
                pass  # a reaper must never take the server down


def default_pool() -> SessionPool | None:
    return DEFAULT


def _default_worker_factory(key: Any, script: str, stdin_b64: str | None) -> Any:
    """The pool's worker_factory over :func:`pswindows.spawn_worker`.

    The pool calls the factory with the key FIRST so a factory can record what
    it opened a worker for (the frozen checks rely on that); the transport itself
    needs only the script and the credential line.
    """
    from . import pswindows

    return pswindows.spawn_worker(script, stdin_b64)


def install_default_pool(cfg: Any) -> SessionPool | None:
    """Install the default pool from ``cfg``, or leave ``DEFAULT`` unset when
    reuse is off.

    The session cap is derived from the host PowerShell cap with reserved
    headroom: every pooled worker holds one host-wide slot
    (``pswindows._acquire_ps_slot``, issue #15) for its ENTIRE lifetime, so
    ``max_sessions == max_host_powershell`` would let a saturated idle pool
    consume every slot and leave the per-call legs — the ``vmident.resolve``
    leg on every guest call, every lifecycle action, ``wait_guest_recovery`` —
    with nothing to run on. Two slots of headroom is enough for those legs to
    fail fast with the retryable busy envelope instead of blocking for
    ``host_powershell_wait_s``.
    """
    global DEFAULT
    if not getattr(cfg, "psdirect_session_reuse", False):
        return None
    cap = int(getattr(cfg, "max_host_powershell", 8) or 8)
    pool = SessionPool(
        _default_worker_factory,
        idle_ttl_s=DEFAULT_IDLE_TTL_S,
        max_sessions=max(1, cap - 2),
    )
    pool.start_reaper()
    DEFAULT = pool
    return pool


def invalidate_vm(vm_guid: str, reason: str | None = None) -> int:
    """Invalidate ``vm_guid`` on the default pool. A no-op when no pool is
    installed, which is the state unit tests and flag-off deployments run in."""
    pool = DEFAULT
    if pool is None:
        return 0
    return pool.invalidate_vm(vm_guid, reason)


def close_default_pool() -> int:
    """Close the default pool and uninstall it. The server-shutdown path."""
    global DEFAULT
    pool = DEFAULT
    if pool is None:
        return 0
    try:
        return pool.close_all()
    finally:
        DEFAULT = None


# ---------------------------------------------------------------------------
# the establishment script
# ---------------------------------------------------------------------------


def guest_scriptblock(elevated: bool) -> str:
    """The guest-side scriptblock text the worker runs for an ordinary call.

    This is the SAME capture wrapper the per-call host script uses
    (`guestexec._normal_body` / `_elevated_body`): the inner .ps1 runs as a
    child powershell with redirected streams, so the result object carries a
    real exit code and the real stdout/stderr. Reusing it rather than
    re-implementing it is what keeps the two transports from drifting — and
    what stops the pooled path from fabricating `exit_code: 0` with empty
    streams, which is what a bare `& $tmp` does (verified on a real host: the
    child's output never reaches the parent pipeline).

    Imported lazily: `guestexec` imports this module, so a module-level import
    here would be a cycle.
    """
    from . import guestexec

    body = (guestexec._elevated_body() if elevated else guestexec._normal_body()).strip()
    lines = [
        "param($enc)",
        "$__mcpGuest = [Diagnostics.Stopwatch]::StartNew()",
        "$text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc))",
        "$tmp  = Join-Path ([System.IO.Path]::GetTempPath())"
        " ([System.IO.Path]::GetRandomFileName() + '.ps1')",
        "[System.IO.File]::WriteAllText($tmp, $text,"
        " [System.Text.UTF8Encoding]::new($false))",
        body,
        "[PSCustomObject]@{ exit_code=$ec; stdout=$so; stderr=$se;"
        " duration_ms=$__mcpGuest.ElapsedMilliseconds }",
    ]
    return "\n".join(lines) + "\n"


def establishment_script(
    key: SessionKey, cred: CredentialSet | None
) -> tuple[str, str | None]:
    """Build the host script a new worker runs, and the stdin credential line.

    The script opens ONE PSSession against the already-resolved GUID and then
    loops: read a length-delimited base64 JSON frame from stdin, run its inner
    script over the session, write a base64 JSON frame to stdout. The password
    is the worker's FIRST stdin line and appears nowhere else — not in argv,
    not in the script text, not in the worker command line, and not in any
    request frame.

    ``cred is None`` produces a placeholder script with no credential and no
    session. That is the shape unit tests use; production always passes one.
    """
    if cred is None:
        return _placeholder_loop(), None
    return _worker_loop(key, cred), _b64(cred.password)


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _ps_quote(value: str) -> str:
    from . import pswindows

    return pswindows.ps_quote(value)


def _worker_loop(key: SessionKey, cred: CredentialSet) -> str:
    """The PowerShell read-eval loop, as one -EncodedCommand payload.

    PowerShell 5.1 compatible throughout: no ternary, no null-coalescing, no
    ``??=``. Every response is a single base64 line on stdout, so the host can
    frame it unambiguously whatever the guest script itself printed.

    Three guards run BEFORE the guest scriptblock, so a retry can never re-run a
    script that already had a side effect:

      1. the session must still be ``Opened`` — a Broken/Closed/Disconnected
         session means the scriptblock was never entered;
      2. the guest's boot epoch must match the one read at open — a reboot
         under a live session breaks the VMBus channel;
      3. the request must decode.

    The guest scriptblock itself comes from :func:`guest_scriptblock`, which is
    the SAME capture wrapper the per-call host script uses, so a pooled call
    reports a real exit code and real stdout/stderr.
    """
    normal_b64 = _b64(guest_scriptblock(False))
    elevated_b64 = _b64(guest_scriptblock(True))
    q = chr(39)
    lines = [
        "[Console]::InputEncoding  = [System.Text.UTF8Encoding]::new($false)",
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)",
        "$ErrorActionPreference = " + q + "Stop" + q,
        "$__mcpBorn = [Diagnostics.Process]::GetCurrentProcess().StartTime",
        "$secRaw = [Console]::In.ReadLine()",
        "$secText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($secRaw))",
        "$sec = $secText | ConvertTo-SecureString -AsPlainText -Force",
        "$cred = [System.Management.Automation.PSCredential]::new("
        + _ps_quote(cred.username) + ", $sec)",
        "$secRaw = $null; $secText = $null; $sec = $null",
        "$vmTarget = " + _ps_quote(key.vm_guid),
        "$s = $null",
        "$bootEpoch = $null",
        "$openMs = 0",
        "try {",
        "    $s = New-PSSession -VMId $vmTarget -Credential $cred -ErrorAction Stop",
        "    $openMs = [int]((Get-Date) - $__mcpBorn).TotalMilliseconds",
        "    $bootEpoch = Invoke-Command -Session $s -ErrorAction SilentlyContinue -ScriptBlock {",
        "        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue",
        "        if ($null -ne $os) { $os.LastBootUpTime.ToString(" + q + "o" + q + ") } else { " + q + q + " }",
        "    }",
        "} catch {",
        "    $err = @{ ok = $false; phase = " + q + "open" + q + "; error = $_.Exception.Message } | ConvertTo-Json -Compress",
        "    [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($err)))",
        "    exit 1",
        "}",
        "$global:__mcpSession = $s",
        "$global:__mcpBootEpoch = $bootEpoch",
        "$global:__mcpSbNormal = " + q + normal_b64 + q,
        "$global:__mcpSbElevated = " + q + elevated_b64 + q,
        "# The open handshake. spawn_worker reads exactly one line after starting",
        "# the process and expects THIS frame.",
        "$open = @{ ok = $true; phase = " + q + "open" + q + "; boot_epoch = $bootEpoch;"
        " session_ms = $openMs } | ConvertTo-Json -Compress",
        "[Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($open)))",
        "while ($true) {",
        "    $line = [Console]::In.ReadLine()",
        "    if ($null -eq $line) { break }",
        "    if ($line -eq " + q + "__MCP_WORKER_EXIT__" + q + ") { break }",
        "    $req = $null",
        "    try { $req = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line)) | ConvertFrom-Json } catch { $req = $null }",
        "    if ($null -eq $req) {",
        "        $bad = @{ ok = $false; phase = " + q + "frame" + q + "; error = " + q + "unreadable request frame" + q + " } | ConvertTo-Json -Compress",
        "        [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bad)))",
        "        continue",
        "    }",
        "    $resp = $null",
        "    try {",
        "        $enc = [string]$req.script",
        "        $wantEpoch = [string]$req.expect_epoch",
        "        $elevated = [bool]$req.elevated",
        "        # Guard 2 reads the guest's boot time afresh on every request, so a",
        "        # reboot under a live session is detected rather than assumed away.",
        "        $nowEpoch = Invoke-Command -Session $s -ErrorAction SilentlyContinue -ScriptBlock {",
        "            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue",
        "            if ($null -ne $os) { $os.LastBootUpTime.ToString(" + q + "o" + q + ") } else { " + q + q + " }",
        "        }",
        "        if ($null -eq $nowEpoch) { $nowEpoch = $global:__mcpBootEpoch }",
        "        # Guard 1: the session must still be open. A session that is not",
        "        # Opened was never entered by this request, so reporting a",
        "        # session-phase failure here is what makes the caller's retry safe.",
        "        if ($s.State -ne " + q + "Opened" + q + ") {",
        "            $resp = @{ ok = $false; phase = " + q + "session" + q + ";"
        " error = (" + q + "session state is " + q + " + $s.State) } | ConvertTo-Json -Compress",
        "        } elseif (($wantEpoch -ne " + q + q + ") -and ($wantEpoch -ne $nowEpoch)) {",
        "            # Guard 2: the guest rebooted under this session.",
        "            $resp = @{ ok = $false; phase = " + q + "session" + q + ";"
        " error = " + q + "boot epoch changed" + q + "; boot_epoch = $nowEpoch } | ConvertTo-Json -Compress",
        "        } else {",
        "            $sbText = if ($elevated) { $global:__mcpSbElevated } else { $global:__mcpSbNormal }",
        "            $sw = [Diagnostics.Stopwatch]::StartNew()",
        "            $out = Invoke-Command -Session $s -ErrorAction Stop -ScriptBlock"
        " ([ScriptBlock]::Create($sbText)) -ArgumentList $enc",
        "            $guestMs = $sw.ElapsedMilliseconds",
        "            $resp = @{ ok = $true; phase = " + q + "guest" + q + ";"
        " exit_code = [int]$out.exit_code; stdout = [string]$out.stdout;"
        " stderr = [string]$out.stderr; guest_ms = [int]$guestMs;"
        " boot_epoch = $nowEpoch } | ConvertTo-Json -Compress -Depth 3",
        "        }",
        "    } catch {",
        "        # The scriptblock may or may not have started. Re-read the session",
        "        # state: only a session that is no longer Opened proves the guest",
        "        # was never entered, so only that is reported as retryable.",
        "        $st = $null",
        "        try { $st = [string]$s.State } catch { $st = $null }",
        "        if (($null -ne $st) -and ($st -ne " + q + "Opened" + q + ")) {",
        "            $resp = @{ ok = $false; phase = " + q + "session" + q + ";"
        " error = $_.Exception.Message; boot_epoch = $global:__mcpBootEpoch } | ConvertTo-Json -Compress",
        "        } else {",
        "            $resp = @{ ok = $false; phase = " + q + "guest" + q + ";"
        " error = $_.Exception.Message; boot_epoch = $global:__mcpBootEpoch } | ConvertTo-Json -Compress",
        "        }",
        "    }",
        "    [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($resp)))",
        "}",
    ]
    return "\n".join(lines) + "\n"



def _placeholder_loop() -> str:
    """The loop used when no credential is supplied — the unit-test shape.

    It reads no credential line, because `establishment_script` passes no stdin
    payload in that case, and answers every request with an empty successful
    guest result. Kept as a function so the shipped ReadLine census attributes
    its one read to this name rather than to `_worker_loop`.
    """
    return "\n".join([
        "[Console]::InputEncoding  = [System.Text.UTF8Encoding]::new($false)",
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)",
        "$ErrorActionPreference = 'Stop'",
        "$open = @{ ok = $true; phase = 'open'; boot_epoch = ''; session_ms = 0 } | ConvertTo-Json -Compress",
        "[Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($open)))",
        "while ($true) {",
        "    $line = [Console]::In.ReadLine()",
        "    if ($null -eq $line) { break }",
        "    if ($line -eq '__MCP_WORKER_EXIT__') { break }",
        "    $resp = @{ ok = $true; phase = 'guest'; exit_code = 0; stdout = '';"
        " stderr = ''; guest_ms = 0 } | ConvertTo-Json -Compress",
        "    [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($resp)))",
        "}",
    ])


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _as_key(key: Any) -> SessionKey:
    if isinstance(key, SessionKey):
        return key
    if isinstance(key, tuple) and len(key) == 4:
        return SessionKey(*key)
    raise TypeError(
        "a session key is (vm_guid, cred_profile, agent_id, boot_epoch); "
        f"got {key!r}"
    )


def _worker_is_dead(worker: Any) -> bool:
    """Best-effort liveness probe. A worker the pool did not close is assumed
    dead only when it says so; anything else is left for the failure path."""
    probe = getattr(worker, "is_alive", None)
    if callable(probe):
        try:
            return not bool(probe())
        except Exception:
            return False
    return False


def _close_quietly(worker: Any) -> None:
    for name in ("close", "terminate", "kill", "shutdown", "stop", "dispose"):
        closer = getattr(worker, name, None)
        if callable(closer):
            try:
                closer()
            except Exception:
                pass
            return
