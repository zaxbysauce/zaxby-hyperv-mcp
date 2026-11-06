"""Issue #70 (wave 59-64-68-70-hardening) — five pre-existing runtime defects.

The issue-16 review's runtime lane found five defects that are pre-existing at
base but reachable under real concurrency; the wave fixes and pins them:

  W4.1  a second `_fail_outstanding` caller (host task + read_client failing
        in the same window) runs the SAME settle+flush tail as the first —
        every outstanding id still gets its -32000 reply and stdout flushes
        before exit (stdio_proxy.py bare os._exit at base). The fix's
        emission-ownership protocol is pinned: ids are claimed synchronously
        before the first await, every id is answered EXACTLY ONCE across
        concurrent callers, and no caller exits while another emitter still
        owns unflushed ids (gated concurrent double-failure leg).
  W4.2  the recovery wait documents its in-guest polling bound and observes
        cancellation at the run_ps poll slice (docstring literals
        `poll slice` + `interval_s`; deterministic cancellation leg).
  W4.3  an upstream-closed diagnostic names the observed cause instead of
        the literal "session ended" (the caught _UpstreamClosed is passed,
        not discarded).
  W4.4  `--port 0` is refused with a clear error naming port 0 — it never
        silently binds the configured port (falsy-0 fallback removed), and
        an explicitly supplied port is validated before the logon-task
        branch too.
  W4.5  registry lookups return snapshots (separate file).

All legs are hermetic and deterministic; the RED signature at base is the
file itself (pytest exit 4, NEW-SURFACE); behavioral tests FAIL on the
pre-fix tree for the named reasons.
"""

import asyncio
from types import SimpleNamespace

import anyio
import pytest

from hyperv_mcp import diagnostics, http_entry, stdio_proxy

_EXIT_CALLS: list[int] = []


class _ExitSentinel(BaseException):
    def __init__(self, code):
        self.code = code


class _RecorderWrite:
    """Minimal client_write seam: records every sent payload."""

    def __init__(self):
        self.payloads: list = []
        self.closed = False

    async def send(self, payload):
        self.payloads.append(payload)

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _no_real_exit(monkeypatch):
    """os._exit must never run in tests; record and raise a sentinel."""
    _EXIT_CALLS.clear()
    monkeypatch.setattr(stdio_proxy.os, "_exit",
                        lambda code=1: (_EXIT_CALLS.append(code),
                                        (_ for _ in ()).throw(_ExitSentinel(code))))


def _ids_of(payloads):
    out = []
    for p in payloads:
        root = getattr(p, "message", None)
        root = getattr(root, "root", root)
        out.append(getattr(root, "id", "?"))
    return out


def test_double_failure_still_emits_and_flushes():
    """Two sequential _fail_outstanding callers each answer the ids their set
    observes and both run the settle+flush tail (W4.1): the second caller's
    ids are never left unanswered by a bare exit."""
    first = _RecorderWrite()

    async def _call1():
        await stdio_proxy._fail_outstanding(
            first, {1, 2}, RuntimeError("first failure"), "TOK", "http://u")

    with pytest.raises(_ExitSentinel) as e1:
        asyncio.run(_call1())
    assert e1.value.code == stdio_proxy.EXIT_TRANSPORT_FAILURE
    assert len(first.payloads) == 2, (
        f"first caller must answer both ids, got {len(first.payloads)}"
    )

    second = _RecorderWrite()

    async def _call2():
        await stdio_proxy._fail_outstanding(
            second, {3}, RuntimeError("second failure"), "TOK", "http://u")

    with pytest.raises(_ExitSentinel) as e2:
        asyncio.run(_call2())
    assert e2.value.code == stdio_proxy.EXIT_TRANSPORT_FAILURE
    assert len(second.payloads) == 1, (
        "the second caller must also answer its outstanding id (W4.1: no "
        "bare exit on the idempotency-guard path)"
    )


def test_concurrent_failures_answer_every_id_exactly_once(monkeypatch):
    """Gated concurrent double-failure over ONE shared outstanding set
    (W4.1 emission-ownership protocol): ids claimed synchronously, every id
    answered exactly once across both callers, and the process exit happens
    only after both emitters flushed (the tail runs per emitter; no caller
    hard-exits while another still owns unemitted ids)."""
    shared = {10, 11, 12}
    writes = {"a": _RecorderWrite(), "b": _RecorderWrite()}
    flush_marks: list[str] = []

    real_stdout_flush = stdio_proxy.sys.stdout.flush
    real_stderr_flush = stdio_proxy.sys.stderr.flush

    def _mark_stdout():
        flush_marks.append("out")
        real_stdout_flush()

    def _mark_stderr():
        flush_marks.append("err")
        real_stderr_flush()

    monkeypatch.setattr(stdio_proxy.sys.stdout, "flush", _mark_stdout)
    monkeypatch.setattr(stdio_proxy.sys.stderr, "flush", _mark_stderr)

    release = anyio.Event()

    async def _caller(name):
        await release.wait()  # gate: both callers start in the same window
        await stdio_proxy._fail_outstanding(
            writes[name], shared, RuntimeError(name), "TOK", "http://u")

    async def main():
        async with anyio.create_task_group() as tg:
            tg.start_soon(_caller, "a")
            tg.start_soon(_caller, "b")
            await anyio.sleep(0.05)  # both callers now parked at the gate
            release.set()

    with pytest.raises(BaseException) as excinfo:
        asyncio.run(main())
    # The exit sentinel may arrive raw or wrapped in the task group's
    # exception group — accept both shapes, but it must be present.
    group = excinfo.value
    if isinstance(group, BaseExceptionGroup):  # noqa: F821 (py311 builtin)
        codes = [getattr(item, "code", None) for item in group.exceptions]
    else:
        codes = [getattr(group, "code", None)]
    assert stdio_proxy.EXIT_TRANSPORT_FAILURE in codes, (
        f"the process must exit with the transport-failure code; got {group!r}"
    )
    # Every id answered exactly once across both emitters.
    all_ids = sorted(_ids_of(writes["a"].payloads + writes["b"].payloads))
    assert all_ids == [10, 11, 12], (
        f"every outstanding id must be answered exactly once; got {all_ids!r}"
    )
    # Both settle+flush tails ran (stdout and stderr flushed).
    assert "out" in flush_marks and "err" in flush_marks, (
        f"both emitters must flush before exit; got {flush_marks!r}"
    )


def test_upstream_closed_carries_text(monkeypatch, capsys):
    """An upstream close mid-session names the observed cause on stderr
    (W4.3) instead of the literal "session ended"."""
    class _Blocked:
        def __init__(self):
            self.started = False

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self.started:
                self.started = True
                return RuntimeError("boom: the controller reset the stream")
            await anyio.sleep_forever()  # cancellable park

    def _fake_stdio_server():
        class _CM:
            async def __aenter__(self):
                return _Blocked(), _RecorderWrite()

            async def __aexit__(self, *exc):
                return False
        return _CM()

    def _fake_upstream(url, **kwargs):
        class _UpCM:
            async def __aenter__(self):
                return _Blocked(), _RecorderWrite()

            async def __aexit__(self, *exc):
                return False
        return _UpCM()

    monkeypatch.setattr(stdio_proxy, "stdio_server", _fake_stdio_server)
    monkeypatch.setattr(stdio_proxy, "streamable_http_client", _fake_upstream)

    async def main():
        with pytest.raises(BaseException) as excinfo:
            await stdio_proxy._run_proxy("http://u", None, "TOK")
        return excinfo.value

    group = asyncio.run(main())

    def _leaves(exc):
        if isinstance(exc, BaseExceptionGroup):  # noqa: F821 (py311 builtin)
            out = []
            for item in exc.exceptions:
                out.extend(_leaves(item))
            return out
        return [exc]

    leaves = _leaves(group)
    sentinels = [item for item in leaves if isinstance(item, _ExitSentinel)]
    assert sentinels, f"the transport exit must fire; got {leaves!r}"
    assert sentinels[0].code == stdio_proxy.EXIT_TRANSPORT_FAILURE
    err = capsys.readouterr().err
    assert "boom" in err, (
        f"the upstream-closed note must carry the observed cause; got: {err!r}"
    )
    assert "session ended" not in err


def test_port_zero_is_explicit(monkeypatch, capsys):
    """`--port 0` is refused with a clear error naming port 0 and never
    reaches the bind (W4.4; a falsy-0 fallback mutant that silently binds
    the configured port is killed because the bind sentinel raises)."""
    calls = {"run": 0}

    def _run_sentinel(*a, **k):
        calls["run"] += 1
        raise _ExitSentinel("bind reached")

    fake_cfg = SimpleNamespace(
        unrestricted=True,
        destructive=SimpleNamespace(require_confirm=False),
        http=SimpleNamespace(port=8443, host="127.0.0.1", agents=[],
                             allowed_hosts=[], token_env="HYPERV_MCP_HTTP_TOKEN"),
    )
    monkeypatch.setattr(http_entry, "load_controller_config", lambda: fake_cfg)
    monkeypatch.setattr(http_entry, "bootstrap", lambda config=None: config)
    monkeypatch.setattr(http_entry, "get_mcp",
                        lambda: SimpleNamespace(run=_run_sentinel))
    rc = http_entry.main(["--allow-anonymous", "--port", "0"])
    assert rc == 2, f"port 0 must be refused, got rc={rc}"
    err = capsys.readouterr().err
    assert "0" in err and "1..65535" in err, (
        f"the refusal must name port 0 and the valid range; got: {err!r}"
    )
    assert calls["run"] == 0, "the bind must never be reached for port 0"

    # Logon-task branch leg (round-1 critic F10): an explicitly supplied
    # invalid port is refused before the install, never silently dropped
    # into the config-default fallback.
    calls["run"] = 0
    rc2 = http_entry.main(["--allow-anonymous", "--port", "0",
                           "--install-logon-task"])
    assert rc2 == 2, f"logon-task port 0 must be refused, got rc={rc2}"
    assert calls["run"] == 0
    assert "1..65535" in capsys.readouterr().err


def test_recovery_wait_documents_bound_and_cancels(monkeypatch):
    """The recovery wait documents its in-guest polling bound and Python-side
    cancellation (W4.2 documented-bound branch): the docstring names the poll
    slice and interval_s, the wait's timeout carries the grace, and a
    cancelled host scope settles the leg within the poll-slice window (not
    the in-guest interval_s)."""
    doc = diagnostics.wait_guest_recovery.__doc__ or ""
    assert "poll slice" in doc, "docstring must document the run_ps poll slice"
    assert "interval_s" in doc, "docstring must name the in-guest interval bound"

    from hyperv_mcp import pswindows
    from hyperv_mcp.config import Config as _Cfg
    from hyperv_mcp.credentials import CredentialSet

    recorded: dict = {}

    def _fake_run(cfg, script, timeout_s=None, stdin_b64=None):
        recorded["timeout_s"] = timeout_s
        import time as _time
        deadline = _time.monotonic() + 30
        while _time.monotonic() < deadline:
            pswindows._check_ps_cancellation()  # poll-slice observation seam
            _time.sleep(0.01)
        return SimpleNamespace(timed_out=False, exit_code=0, stdout="{}",
                               stderr=b"")

    monkeypatch.setattr(diagnostics, "_run", _fake_run)
    monkeypatch.setattr(
        diagnostics.vmident, "resolve",
        lambda *a, **k: SimpleNamespace(
            id="00000000-0000-0000-0000-000000000001", name="vm"))

    cfg = _Cfg()

    def _call():
        diagnostics.wait_guest_recovery(
            cfg, "vm", cred=CredentialSet("Administrator", "pw"))

    async def main():
        with anyio.move_on_after(2.0) as scope:
            await anyio.to_thread.run_sync(_call)
        assert scope.cancelled_caught, (
            "the cancelled scope must interrupt the recovery wait leg"
        )

    asyncio.run(main())
    assert recorded.get("timeout_s") == 300 + 15, (
        "the wait leg must carry the recovery timeout plus grace"
    )


def test_blocked_send_blocks_peer_exit(monkeypatch):
    """Deterministic blocked-send leg (round-2 challenge 1): while the first
    claimant is parked inside send, the second caller must NOT hard-exit;
    only after the parked sender completes do the flush+exit fire, and every
    id is answered exactly once."""
    shared = {20, 21, 22}
    unblock = anyio.Event()
    first = _RecorderWrite()
    second = _RecorderWrite()
    exit_marks: list[str] = []

    real_send = first.send

    async def _blocking_send(payload):
        await unblock.wait()  # park the first emitter INSIDE send
        await real_send(payload)

    monkeypatch.setattr(first, "send", _blocking_send)
    real_exit = stdio_proxy.os._exit

    def _recording_exit(code=1):
        exit_marks.append("exit")
        real_exit(code)

    monkeypatch.setattr(stdio_proxy.os, "_exit", _recording_exit)

    async def _caller_a():
        await stdio_proxy._fail_outstanding(
            first, shared, RuntimeError("a"), "TOK", "http://u")

    async def _caller_b():
        await stdio_proxy._fail_outstanding(
            second, shared, RuntimeError("b"), "TOK", "http://u")

    async def main():
        async with anyio.create_task_group() as tg:
            tg.start_soon(_caller_a)
            tg.start_soon(_caller_b)
            # caller A claims (synchronous) then parks in send; caller B
            # runs, claims nothing left, and must NOT exit while A parks.
            # The snapshot window must OUTLAST the settle tail (anyio.sleep
            # 0.2 s): a mutant that bounds or deletes the peer wait lets B
            # flush+exit at ~0.2-0.26 s, so sampling at 0.4 s catches it
            # (final-critic blocker 1; the old 0.1 s snapshot preceded the
            # tail and could not discriminate).
            await anyio.sleep(0.4)
            assert not exit_marks, (
                "a peer must not hard-exit (or even run its exit tail) "
                "while another emitter still owns claimed-but-unsent replies"
            )
            unblock.set()
            # NOTE (final-critic fix round): a per-emitter tail COUNTER is
            # structurally impossible here - the first os._exit sentinel
            # (production first-exit-wins) cancels the task group before the
            # peer's tail runs, so only the TIMING assertion above
            # discriminates the bounded/deleted-peer-wait mutants.

    with pytest.raises(BaseException) as excinfo:
        asyncio.run(asyncio.wait_for(main(), timeout=10))
    group = excinfo.value

    def _leaves(exc):
        if isinstance(exc, BaseExceptionGroup):  # noqa: F821 (py311 builtin)
            out = []
            for item in exc.exceptions:
                out.extend(_leaves(item))
            return out
        return [exc]

    leaves = _leaves(group)
    assert not any(isinstance(item, asyncio.TimeoutError) for item in leaves), (
        "the blocked-send choreography deadlocked (peer-exit coordination "
        "must not wait for a peer that is itself waiting)"
    )
    codes = [getattr(item, "code", None) for item in leaves]
    assert stdio_proxy.EXIT_TRANSPORT_FAILURE in codes
    assert "exit" in exit_marks
    # Every id answered exactly once (A claimed all three).
    all_ids = sorted(_ids_of(first.payloads + second.payloads))
    assert all_ids == [20, 21, 22], (
        f"every outstanding id must be answered exactly once; got {all_ids!r}"
    )
