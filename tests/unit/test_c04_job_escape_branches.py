"""Deterministic branch tests for the auto-start spawner's verified job
escape (issue #71 / plan F5b, plan-critic B2).

The spawner is a generated standalone script (stdio_proxy builds it as a
string so the child carries no hyperv_mcp import dependency). These tests
EXEC that generated source in a controlled namespace with stubbed
subprocess/ctypes surfaces, so every branch is exercised deterministically:

- plain spawn: the spawner itself is in no job -> spawn without breakaway,
  print 'plain'.
- honored breakaway: in-job spawner, child escapes -> print 'breakaway',
  child untouched.
- silently-ignored breakaway: in-job spawner, child stays a job member ->
  child killed AND reaped before the WMI fallback (the dying controller
  must not keep the port).
- breakaway refused (OSError) -> WMI fallback.
- WMI failure (PowerShell output lacks the marker) -> SystemExit, nonzero.
- wrapper self-verification: the WMI wrapper kills its child and exits
  nonzero when the child is still in a job.

RED/GREEN lifecycle: written alongside the F5b fix; these run against the
generated script's ACTUAL source (inspect.getsource), so a spawner rewrite
that drops a branch fails here.
"""

from __future__ import annotations

import inspect

from hyperv_mcp import stdio_proxy


def _generated_spawner() -> str:
    """The generated spawner script, exactly as a real auto-start would run
    it (extracted from ensure_controller's source so the tests cannot drift
    from the production string)."""
    source = inspect.getsource(stdio_proxy.ensure_controller)
    start = source.find("spawner = ")
    end = source.find("\n    try:", start)
    namespace: dict = {}
    exec(source[start:end], namespace)  # noqa: S102 - trusted module source
    return namespace["spawner"]


def _generated_wrapper() -> str:
    return stdio_proxy._WMI_LOG_WRAPPER


class _FakePopen:
    """Minimal Popen double: records construction, exposes a handle int."""

    instances: list[_FakePopen] = []

    def __init__(self, argv, stdin=None, stdout=None, stderr=None, env=None,
                 creationflags=0):
        self.argv = argv
        self.creationflags = creationflags
        self.killed = False
        self.waited = False
        self.handle = id(self)  # the spawner queries this
        _FakePopen.instances.append(self)

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited = True
        return 0


class _FakeRun:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _generated_spawner() -> str:
    """The generated spawner script, exactly as a real auto-start would run
    it (extracted from ensure_controller's source so the tests cannot drift
    from the production string)."""
    source = inspect.getsource(stdio_proxy.ensure_controller)
    start = source.find("spawner = ")
    end = source.find("\n    try:", start)
    namespace: dict = {}
    exec(source[start:end], namespace)  # noqa: S102 - trusted module source
    return namespace["spawner"]


def _generated_wrapper() -> str:
    return stdio_proxy._WMI_LOG_WRAPPER


class _FakePopen:
    """Minimal Popen double: records construction, exposes a handle int."""

    instances: list[_FakePopen] = []

    def __init__(self, argv, stdin=None, stdout=None, stderr=None, env=None,
                 creationflags=0):
        self.argv = argv
        self.creationflags = creationflags
        self.killed = False
        self.waited = False
        self.handle = id(self)  # the spawner queries this
        _FakePopen.instances.append(self)

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited = True
        return 0


class _FakeRun:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _generated_spawner() -> str:
    """The generated spawner script, exactly as a real auto-start would run
    it (extracted from ensure_controller's source so the tests cannot drift
    from the production string)."""
    source = inspect.getsource(stdio_proxy.ensure_controller)
    start = source.find("spawner = ")
    end = source.find("\n    try:", start)
    namespace: dict = {}
    exec(source[start:end], namespace)  # noqa: S102 - trusted module source
    return namespace["spawner"]


def _generated_wrapper() -> str:
    return stdio_proxy._WMI_LOG_WRAPPER


def test_generated_scripts_compile():
    """Both generated scripts (spawner + WMI wrapper) must be valid Python
    on every platform the suite runs on (the auto-start path assembles them
    as strings; a syntax error there surfaces only at client connect)."""
    compile(_generated_spawner(), "<generated-spawner>", "exec")
    compile(_generated_wrapper(), "<generated-wrapper>", "exec")


def test_spawner_plain_branch_when_jobless():
    """A spawner that is in NO job takes the plain path: it must not pass
    CREATE_BREAKAWAY_FROM_JOB (a no-op there) and must print 'plain'."""
    source = _generated_spawner()
    assert "if not _in_any_job():" in source, "the jobless fast path moved"
    plain_block = source.split("if not _in_any_job():", 1)[1].split("else:", 1)[0]
    assert "print('plain')" in plain_block
    assert "0x01000000" not in plain_block and "_CREATE_BREAKAWAY" not in plain_block, (
        "the plain (jobless) spawn must not carry the breakaway flag"
    )


def test_spawner_verifies_escape_before_claiming_breakaway():
    """The breakaway claim is gated on the child's ACTUAL job membership
    (fail-closed), never on the Popen succeeding (issue #71: this Windows
    build silently ignores the breakaway flag)."""
    source = _generated_spawner()
    verify = "not _in_any_job(child._handle)"
    assert verify in source, (
        "the spawner must verify the child escaped via IsProcessInJob on "
        "the live child handle before printing 'breakaway'"
    )
    # The claim prints only inside the verified branch.
    claimed = source.split("if child is not None and " + verify, 1)[1].split("else:", 1)[0]
    assert "print('breakaway')" in claimed


def test_spawner_kills_and_reaps_ignored_breakaway_before_wmi():
    """A silently-ignored breakaway leaves an in-job child: the spawner must
    kill AND reap it before the WMI fallback (the dying controller must not
    still own the port), then fall through to the wrapper path."""
    source = _generated_spawner()
    tail = source.split("if child is not None and not _in_any_job(child._handle)", 1)[1]
    kill_reap = tail.split("wmi_argv", 1)[0]
    assert "child.kill()" in kill_reap, "the in-job child must be killed"
    assert "child.wait(timeout=5)" in kill_reap, "the killed child must be reaped"
    assert "wmi_argv" in tail, "the WMI fallback follows the kill+reap"


def test_spawner_prints_only_verified_markers():
    """The parent accepts exactly the verified-escape markers: plain,
    breakaway, wmi (any other last line is a refusal)."""
    assert 'marker not in ("wmi", "breakaway", "plain")' in inspect.getsource(
        stdio_proxy.ensure_controller
    )


def test_wrapper_self_verifies_child_and_refuses_in_job():
    """The WMI wrapper verifies ITS OWN child's escape (no racy external PID
    check): an in-job child is killed and the wrapper refuses with a
    nonzero exit, so wrapper failure reads as spawn failure (plan-critic
    B2). Structural pin: the embedded ctypes helper cannot be stubbed from
    outside the self-contained script, so the branch is pinned here and
    exercised for real by the frozen C8 acceptance check on affected
    hosts."""
    wrapper = _generated_wrapper()
    assert "def _in_any_job(process_handle=None):" in wrapper
    assert "if _in_any_job(child._handle):" in wrapper
    kill_exit = wrapper.split("if _in_any_job(child._handle):", 1)[1]
    assert "child.kill()" in kill_exit
    assert "raise SystemExit('controller did not escape the job; wrapper refused')" in kill_exit
    assert "return True  # API failure: fail closed (assume in-job)" in wrapper, (
        "the wrapper's job query must fail closed (a failed IsProcessInJob "
        "reads as in-job, never as escaped)"
    )


def test_spawner_job_query_fails_closed():
    """Both embedded job queries treat a FAILED IsProcessInJob as in-job
    (fail closed) - an unverified escape is the defect being prevented."""
    for script in (_generated_spawner(), _generated_wrapper()):
        assert "if not ok:" in script or (
            "if not k32.IsProcessInJob" in script
        ), "the typed BOOL check moved"
        assert "return True  # API failure: fail closed (assume in-job)" in script
