"""Shared unit-test fixtures. No real Hyper-V is touched."""

import time

import pytest

from hyperv_mcp.config import Config


@pytest.fixture(autouse=True)
def _ps_transport_default(monkeypatch):
    """Unit tests default to the PowerShell console transport: no real
    Hyper-V through EITHER transport (the suite stubs run_ps; the
    in-process WMI backend is likewise never real here — on boxes with
    pywin32 AND a live namespace it would otherwise serve silently).
    Tests that exercise the WMI path install their own fake backend
    explicitly and re-enable it via wmiconsole.COM_AVAILABLE (issue #45).
    The backend/negative-cache state is reset per test so no test inherits
    another test's fake service (review F3-C/P24)."""
    from hyperv_mcp import wmiconsole

    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", False)
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})


@pytest.fixture(autouse=True)
def _console_caches_isolated(monkeypatch):
    """Reset the console module's process-local caches per test (issue #77's
    hint map and issue #28's UNKNOWN record map): without this, a check that
    seeds a hint for a name (or records an uncertain outcome) leaks into
    every later by-name call in the same process and silently changes its
    lock keys and guard behavior."""
    from hyperv_mcp import console

    monkeypatch.setattr(console, "_NAME_GUID_HINTS", {})
    monkeypatch.setattr(console, "_UNKNOWN_RESULTS", {})


@pytest.fixture(autouse=True)
def _uia_caches_isolated(monkeypatch):
    """Reset the uia module's process-local caches per test (issue #29,
    PR-#109 F11/F18): the broker registrations (_REGISTRATIONS, keyed by
    (vm_guid, session_id)), the SID cache, the recorded-install cache
    (_INSTALLS) and the thread-local leg slot. Without this, one test's
    seeded registration (or its resolved SID / install facts) routes a later
    test's bootstrap request through a stale row, and a pooled worker thread
    keeps the leg slot's credential past the call that used it. The dicts
    are replaced monkeypatch-style (auto-restored, so a test's writes are
    discarded with it); the thread-local slot is nulled directly —
    monkeypatch.setattr on a threading.local raises AttributeError when the
    attribute has never been set on this thread."""
    from hyperv_mcp import uia

    monkeypatch.setattr(uia, "_REGISTRATIONS", {})
    monkeypatch.setattr(uia, "_SID_CACHE", {})
    monkeypatch.setattr(uia, "_INSTALLS", {})
    uia._LEG.guid = None
    uia._LEG.cred = None
    uia._CALL.cfg = None
    uia._CALL.ref = None
    uia._CALL.cred = None


@pytest.fixture(autouse=True)
def _state_store_in_tmp(monkeypatch, tmp_path):
    """Point the durable state store at a per-test temp directory (issue #22).

    The store is always on, so without this every unit test that reaches
    job_start or relay_start would open a SQLite database under the real
    profile. Redirecting HYPERV_MCP_STATE_DB covers configs built through
    Config.load(); redirecting LOCALAPPDATA covers the derived default, so
    stdio_proxy._controller_log_path (the repo's other LOCALAPPDATA reader)
    also lands in tmp rather than the live profile.

    Teardown closes every cached Store: a long suite would otherwise
    accumulate open SQLite connections and, on Windows, open -wal/-shm files
    that pytest's tmp cleanup cannot delete.
    """
    from hyperv_mcp import statestore

    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    # Issue #24: pin the PowerShell slot-pool directory into the per-test tmp
    # too. The derived default reads %ProgramData% at call time, so without
    # this every test shares ONE real pool under C:\ProgramData — a real-PS
    # test's straggler child (the c02 kill tests, the b03 controller
    # subprocess) holds its slot past the test's end and a later detached
    # runner's guest leg waits out host_powershell_wait_s on it.
    monkeypatch.setenv("ProgramData", str(tmp_path))
    yield
    statestore.clear_store_cache_for_tests()


@pytest.fixture()
def png_encode_counter(monkeypatch):
    """Count PNG encodes (issue #17, PRR-016).

    The single oracle the "one PNG encode per returned image" invariant rests
    on. It lives here rather than being copied into each test file so there is
    one implementation to maintain. `Image.init()` runs first: without it the
    SAVE registry does not exist yet and a patch made earlier is overwritten by
    plugin registration, which would make the counter read zero and every
    encode-count assertion vacuous.

    `tests/unit/test_d01_screenshot_decode.py` keeps its own byte-locked copy
    because that file is frozen by the issue-tracer red checkpoint.
    """
    from PIL import Image

    Image.init()
    original = Image.SAVE["PNG"]
    box = {"encodes": 0}

    def counting_encode(fp, *args, **kwargs):
        box["encodes"] += 1
        return original(fp, *args, **kwargs)

    monkeypatch.setitem(Image.SAVE, "PNG", counting_encode)
    return box


@pytest.fixture()
def deny_all_cfg() -> Config:
    return Config()


@pytest.fixture()
def unrestricted_cfg() -> Config:
    return Config(unrestricted=True)


@pytest.fixture()
def lab_cfg(tmp_path) -> Config:
    """A realistic restrictive lab config: one VM pattern, tmp roots."""
    return Config(
        allowed_vm_patterns=["test-vm-*"],
        host_read_roots=[str(tmp_path / "host-read")],
        host_write_roots=[str(tmp_path / "host-write")],
        guest_read_roots=["C:\\guest-read"],
        guest_write_roots=["C:\\guest-write"],
    )


def content_blocks(result):
    """Content blocks from any mcp call_tool return shape.

    Handles the historical tuple form, the converted list form, and the
    CallToolResult object that in-process call_tool returns when a tool
    returns one (issue #9 envelope delivery)."""
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    return content if isinstance(content, list) else [content]


def envelope_from_result(result, label: str) -> dict:
    """Parse the first text block of a failure result into the envelope."""
    import json

    blocks = content_blocks(result)
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {label}"
    return json.loads(texts[0].text)

@pytest.fixture(scope="session", autouse=True)
def _reap_stray_controllers():
    """Session-end safety net (PRR-012): any controller that outlived its
    test — e.g. AC8's failure path, whose frozen-file reap sits after its
    assertion (the test file is checkpoint-anchored and cannot be edited) —
    is terminated here. Controllers created before the session started (an
    operator's own hyperv-mcp-http) are never touched."""
    started = time.time()
    yield
    try:
        import psutil
    except ImportError:  # dev extra absent: warn, never mask test results
        return

    victims = []
    for proc in psutil.process_iter(["pid", "cmdline", "create_time"]):
        try:
            cmd = " ".join(proc.info.get("cmdline") or [])
            created = proc.info.get("create_time") or 0
        except psutil.Error:
            continue
        if "hyperv_mcp.http_entry" in cmd or "hyperv-mcp-http" in cmd:
            if created >= started:
                victims.append(proc)
    for proc in victims:
        try:
            proc.terminate()
        except psutil.Error:
            pass
    if victims:
        psutil.wait_procs(victims, timeout=5.0)
        for proc in victims:
            try:
                proc.kill()
            except psutil.Error:
                pass


@pytest.fixture(autouse=True)
def _restore_bootstrap_module_globals():
    """Per-test isolation (PRR-014): bootstrap() writes _config into
    credentials/pswindows/auditlog AND server._bootstrapped/CFG — a server
    reload alone cannot undo it (the b01 guard's scope, generalized).
    AC5 in test_b03_stdio_proxy reaches bootstrap() through the launcher
    with no teardown of its own, so this fixture is the boundary that keeps
    one test's config out of the next test."""
    from hyperv_mcp import auditlog as _a
    from hyperv_mcp import credentials as _c
    from hyperv_mcp import psdsessions as _ps
    from hyperv_mcp import pswindows as _pw
    from hyperv_mcp import server as _srv
    from hyperv_mcp import vmlocks as _vl

    def _no_spawn(script, stdin_b64=None):
        """Refuse to spawn a host powershell.exe from a unit test.

        `server.bootstrap` installs the default session pool (issue #21), so a
        test that stubs `pswindows.run_ps` but still reaches `bootstrap` would
        otherwise spawn a REAL worker on its next guest call and block on
        `New-PSSession` against a VM that does not exist. Raising here makes the
        pooled path fail fast and fall back to the per-call path the test
        actually stubbed.
        """
        raise _pw.PowerShellTransportError(
            "psdsessions: unit tests must not spawn a pooled worker"
        )

    saved = {
        ("auditlog", "_config"): getattr(_a, "_config", None),
        ("credentials", "_config"): getattr(_c, "_config", None),
        ("pswindows", "_config"): getattr(_pw, "_config", None),
        ("pswindows", "_redact"): getattr(_pw, "_redact", None),
        # PRR-074: pswindows.init() also sets _ps_path, and nothing restored it,
        # so whichever test initialised first decided whether every later test
        # could spawn PowerShell at all — an ordering dependency that reads as a
        # random failure when the file order changes.
        ("pswindows", "_ps_path"): getattr(_pw, "_ps_path", None),
        ("server", "_bootstrapped"): getattr(_srv, "_bootstrapped", False),
        ("server", "CFG"): getattr(_srv, "CFG", None),
        # bootstrap() also wires vmlocks' default bounded wait; without this
        # a test reaching bootstrap leaks its vm_lock_wait_s into the rest of
        # the session (review CLEAN-note on PR #58).
        ("vmlocks", "_DEFAULT_WAIT_S"): getattr(_vl, "_DEFAULT_WAIT_S", 30.0),
        # issue #23: bootstrap() wires the lease-row provider/resolvers into
        # vmlocks. Without restoring them, a test that bootstraps leaves the
        # provider pointing at its CFG in every later test -- masked today
        # because CFG restores to None and vm_lock skips row work then, but
        # any future test that leaves CFG set would silently route lockless
        # tests through a real store.
        ("vmlocks", "_store_provider"): getattr(_vl, "_store_provider", None),
        ("vmlocks", "_scope_for_tool"): getattr(_vl, "_scope_for_tool", None),
        ("vmlocks", "_agent_resolver"): getattr(_vl, "_agent_resolver", None),
        # issue #21: bootstrap() installs the reusable PS Direct session pool
        # when psdirect_session_reuse is on, which the default Config is. Without
        # restoring DEFAULT, every later guest-tool test in the session routes
        # pooled into the real spawn path instead of the per-call path it was
        # written against.
        ("psdsessions", "DEFAULT"): getattr(_ps, "DEFAULT", None),
        ("psdsessions", "_spawn_worker"): getattr(_ps, "_spawn_worker", None),
        # issue #24: bootstrap() sizes the detached-runner semaphore and the
        # tasks extension caches the config; operations also caches fingerprint
        # keys per store path. Without this, one test's key/bound serves the
        # next test's store.
        ("server", "_RUNNER_SLOTS"): getattr(_srv, "_RUNNER_SLOTS", None),
    }
    import hyperv_mcp.operations as _ops

    _ops.reset_for_tests()
    _ps.set_worker_spawn(_no_spawn)
    yield
    # Issue #24 (implementation-review R9): wait (bounded) for live detached
    # runners BEFORE the monkeypatches undo - a runner that outlives its test
    # otherwise calls the REAL run_ps and its late writes bleed into the next
    # test's mounted store.
    _ops.drain_for_tests(timeout_s=5.0)
    _a._config = saved[("auditlog", "_config")]
    _c._config = saved[("credentials", "_config")]
    _pw._config = saved[("pswindows", "_config")]
    _pw._redact = saved[("pswindows", "_redact")]
    _pw._ps_path = saved[("pswindows", "_ps_path")]
    _srv._bootstrapped = saved[("server", "_bootstrapped")]
    _srv.CFG = saved[("server", "CFG")]
    _vl._DEFAULT_WAIT_S = saved[("vmlocks", "_DEFAULT_WAIT_S")]
    _vl._store_provider = saved[("vmlocks", "_store_provider")]
    _vl._scope_for_tool = saved[("vmlocks", "_scope_for_tool")]
    _vl._agent_resolver = saved[("vmlocks", "_agent_resolver")]
    _ps.DEFAULT = saved[("psdsessions", "DEFAULT")]
    _ps.set_worker_spawn(saved[("psdsessions", "_spawn_worker")])
    _srv._RUNNER_SLOTS = saved[("server", "_RUNNER_SLOTS")]
    _ops.reset_for_tests()

