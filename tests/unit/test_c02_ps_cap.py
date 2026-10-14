"""Acceptance checks for issue 15 (FND-13): host PowerShell admission control.

Checks the run_ps transport contract along five axes:

  AC1  at most max_host_powershell (default 8) host PowerShell children are
       live at once, no matter how many threads call run_ps concurrently
  AC2  a non-TimeoutExpired exception unwinding run_ps through communicate()
       still kills the spawned child tree
  AC3  cancelling the async scope around an anyio worker-thread run_ps leg
       stops the leg promptly instead of running the child to completion
  AC4  a call that cannot get a slot within host_powershell_wait_s raises
       PowerShellBusy (errors.classify -> "busy") instead of queueing forever
  AC5  the cap is host-wide: two separate worker processes sharing one
       ps_slot_dir never exceed it combined

Every check is RED at the pre-fix base and must pass unchanged once the fix
lands. No real PowerShell, Hyper-V, VM, network or secret is used: the
"PowerShell" is a generated shim that runs a recording Python child, driven
through the real run_ps spawn path (Config.host_powershell_path).
"""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from hyperv_mcp import errors, pswindows
from hyperv_mcp.config import Config

_UNIT_FILE = Path(__file__).resolve()
_STILL_ACTIVE = 259  # Windows NT STILL_ACTIVE exit code

_RECORDER_SOURCE = '''\
"""Recording fake-PowerShell child. Writes events/<pid>.json - ONE FILE PER
CHILD, so concurrent recorders never lose a line pair the way a shared
append file can - holding start/end wall-clock timestamps with a SLEEP_S
nap between them. RECORDER_FILE names the events DIRECTORY; both variables
ride pswindows.child_env() like any non-secret environment variable."""
import json
import os
import time

events = os.path.join(os.environ["RECORDER_FILE"], "events")
os.makedirs(events, exist_ok=True)
pid = os.getpid()
start = time.time()
path = os.path.join(events, "%d.json" % pid)
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"pid": pid, "start": start}, fh)
time.sleep(float(os.environ.get("SLEEP_S", "1")))
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"pid": pid, "start": start, "end": time.time()}, fh)
'''


def _write_recorder_shim(tmp_path: Path) -> Path:
    """Generate the fake PowerShell into tmp_path and return its path.

    Windows: a .cmd shim invoking this interpreter on the recorder module
    (run_ps spawns the shim; the interpreter is the recorded LEAF child the
    fix must kill). POSIX: a shebang script runpy-executing the recorder in
    the child itself, so the event-file pid IS the direct run_ps child.
    """
    recorder = tmp_path / "recorder.py"
    recorder.write_text(_RECORDER_SOURCE, encoding="utf-8")
    if os.name == "nt":
        shim = tmp_path / "fake-powershell.cmd"
        shim.write_bytes(
            f'@echo off\r\n"{sys.executable}" "{recorder}"\r\n'.encode()
        )
    else:
        shim = tmp_path / "fake-powershell.sh"
        shim.write_text(
            "#!/usr/bin/env python3\n"
            "import runpy\n"
            f"runpy.run_path({str(recorder)!r}, run_name='__main__')\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
    return shim


def _alive(pid: int) -> bool:
    """True while process `pid` is still running (pure ctypes/os, no psutil)."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == _STILL_ACTIVE
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _load_intervals(events_dir: Path) -> list[tuple[float, float]]:
    """(start, end) wall-clock interval per completed recording child."""
    intervals: list[tuple[float, float]] = []
    for path in sorted((events_dir / "events").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        intervals.append((data["start"], data["end"]))
    return intervals


def _peak_concurrency(intervals: list[tuple[float, float]]) -> int:
    """Peak number of simultaneously-live children across the intervals."""
    points: list[tuple[float, int]] = []
    for start, end in intervals:
        points.append((start, 1))
        points.append((end, -1))
    points.sort()  # ties: an end at t frees the slot before a start at t
    live = peak = 0
    for _, delta in points:
        live += delta
        peak = max(peak, live)
    return peak


def _first_event_pid(events_dir: Path, timeout_s: float) -> int | None:
    """Pid of the first recording child to publish an event, or None."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        published = sorted((events_dir / "events").glob("*.json"))
        if published:
            return int(json.loads(published[0].read_text(encoding="utf-8"))["pid"])
        time.sleep(0.05)
    return None


# ---------------------------------------------------------------------------
# AC1 - admission control (cap on live host PowerShell children)
# ---------------------------------------------------------------------------

def test_host_powershell_children_are_capped(tmp_path, monkeypatch):
    """AC1: 12 threads calling run_ps at once against a 0.8 s fake
    PowerShell never leave more than 8 simultaneously-live children (the
    default max_host_powershell cap), and every one of the 12 calls still
    completes. RED at the pre-fix base (no admission control: peak 12),
    GREEN after the fix."""
    events_dir = tmp_path / "rec"
    events_dir.mkdir()
    shim = _write_recorder_shim(tmp_path)
    monkeypatch.setenv("RECORDER_FILE", str(events_dir))
    monkeypatch.setenv("SLEEP_S", "0.8")
    pswindows.init(Config(host_powershell_path=str(shim)))

    results: list = [None] * 12
    failures: list = []
    barrier = threading.Barrier(12)

    def call(index):
        try:
            barrier.wait(timeout=30)
            results[index] = pswindows.run_ps("Write-Output 'cap-probe'", timeout_s=60)
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=call, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=90)

    assert not failures, f"run_ps calls raised: {failures!r}"
    completed = [result for result in results if result is not None]
    assert len(completed) == 12, (
        f"only {len(completed)}/12 run_ps calls completed; the cap must "
        "queue callers, not drop them"
    )
    for result in completed:
        assert result.ok(), f"capped child did not complete cleanly: {result.stderr!r}"

    intervals = _load_intervals(events_dir)
    assert len(intervals) == 12, (
        f"expected 12 recorded children, found {len(intervals)} "
        "(recording loss?)"
    )
    peak = _peak_concurrency(intervals)
    assert peak <= 8, (
        f"{peak} host PowerShell children were live at once; the default "
        "max_host_powershell cap of 8 was not enforced"
    )


# ---------------------------------------------------------------------------
# AC2 - abnormal unwind still kills the child tree
# ---------------------------------------------------------------------------

def test_child_killed_when_run_ps_unwinds_by_exception(tmp_path, monkeypatch):
    """AC2: when run_ps unwinds through communicate() with an exception that
    is NOT subprocess.TimeoutExpired, the spawned child tree is killed
    anyway. The real child keeps running while the unwind happens; it must
    be dead shortly after. RED at the pre-fix base (the kill only runs on
    the TimeoutExpired/normal paths), GREEN after the fix."""
    events_dir = tmp_path / "rec"
    events_dir.mkdir()
    shim = _write_recorder_shim(tmp_path)
    monkeypatch.setenv("RECORDER_FILE", str(events_dir))
    monkeypatch.setenv("SLEEP_S", "5")
    pswindows.init(Config(host_powershell_path=str(shim)))

    direct_child_pid: list[int] = []

    if os.name == "nt":
        # Windows branch (CI is windows-only; this is the load-bearing one):
        # wrap only Popen.communicate so the FIRST call raises a
        # non-TimeoutExpired exception while the REAL child - already
        # spawned, job-assigned and resumed by run_ps - keeps running.
        real_popen = subprocess.Popen

        class _UnwindingPopen:
            """Delegates every attribute to the real child but raises from
            the first communicate(); later calls (post-kill reaping)
            delegate normally."""

            def __init__(self, proc):
                self._proc = proc
                self._raised = False

            def communicate(self, input=None, timeout=None):
                if not self._raised:
                    self._raised = True
                    raise RuntimeError("probe: non-timeout unwind during communicate")
                return self._proc.communicate(input=input, timeout=timeout)

            def kill(self):
                return self._proc.kill()

            def __getattr__(self, name):
                return getattr(self._proc, name)

        def unwinding_popen(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            direct_child_pid.append(proc.pid)
            return _UnwindingPopen(proc)

        monkeypatch.setattr(pswindows.subprocess, "Popen", unwinding_popen)
        with pytest.raises(RuntimeError, match="probe: non-timeout unwind"):
            pswindows.run_ps("Write-Output 'unwind-probe'", timeout_s=30)
    else:
        # POSIX branch: SIGALRM raises the same non-TimeoutExpired exception
        # out of the blocking communicate() call (the classic alarm idiom).
        # The shebang shim IS the recorder, so its event-file pid is the
        # direct run_ps child.
        import signal

        def _probe_raise(signum, frame):
            raise RuntimeError("probe: non-timeout unwind during communicate")

        previous = signal.signal(signal.SIGALRM, _probe_raise)
        signal.setitimer(signal.ITIMER_REAL, 1.0)
        try:
            with pytest.raises(RuntimeError, match="probe: non-timeout unwind"):
                pswindows.run_ps("Write-Output 'unwind-probe'", timeout_s=30)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous)

    # Watch every known pid: the Windows wrapper captured the direct (shim)
    # child, the recording leaf publishes its own pid once running.
    leaf_pid = _first_event_pid(events_dir, timeout_s=2.0)
    watched = [pid for pid in (direct_child_pid[:1] + [leaf_pid]) if pid]
    assert watched, "no child pid could be observed to check the abnormal-exit kill"

    deadline = time.monotonic() + 1.0
    for pid in watched:
        while time.monotonic() < deadline and _alive(pid):
            time.sleep(0.05)
    for pid in watched:
        assert _alive(pid) is False, (
            f"child pid {pid} is still alive shortly after run_ps unwound "
            "by a non-timeout exception; the abnormal-exit path leaked it"
        )


# ---------------------------------------------------------------------------
# AC3 - cancellation observed from an anyio worker thread
# ---------------------------------------------------------------------------

def test_cancelled_worker_thread_kills_child_promptly(tmp_path, monkeypatch):
    """AC3: cancelling the async scope around an anyio worker-thread run_ps
    leg (the shape every MCP tool call uses) must kill the leg's child and
    free the worker thread promptly, not run the 5 s child to completion.
    RED at the pre-fix base (communicate() never observes cancellation),
    GREEN after the fix."""
    import anyio

    events_dir = tmp_path / "rec"
    events_dir.mkdir()
    shim = _write_recorder_shim(tmp_path)
    monkeypatch.setenv("RECORDER_FILE", str(events_dir))
    monkeypatch.setenv("SLEEP_S", "5")
    pswindows.init(Config(host_powershell_path=str(shim)))

    def leg():
        return pswindows.run_ps("Write-Output 'cancel-probe'", timeout_s=60)

    start = time.monotonic()

    async def scenario():
        with anyio.move_on_after(0.5):
            await anyio.to_thread.run_sync(leg)

    anyio.run(scenario)
    elapsed = time.monotonic() - start
    assert round(elapsed) <= 1, (
        f"the cancelled worker thread kept the leg alive for {elapsed:.2f}s; "
        "cancellation must kill the child and free the thread promptly"
    )

    pid = _first_event_pid(events_dir, timeout_s=1.0)
    assert pid is not None, "no child was ever started for the cancelled leg"
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and _alive(pid):
        time.sleep(0.05)
    assert _alive(pid) is False, (
        f"child pid {pid} from the cancelled leg is still alive"
    )


# ---------------------------------------------------------------------------
# AC4 - bounded slot wait fails loudly as PowerShellBusy
# ---------------------------------------------------------------------------

def test_cap_wait_is_bounded_and_reports_busy(tmp_path, monkeypatch):
    """AC4: with max_host_powershell=1 and host_powershell_wait_s=0.3, a
    second run_ps call while the only slot is held must raise
    pswindows.PowerShellBusy, classified "busy" by errors.classify, instead
    of queueing forever. RED at the pre-fix base (the config keys do not
    exist yet, so this cannot even be configured), GREEN after the fix."""
    events_dir = tmp_path / "rec"
    events_dir.mkdir()
    slot_dir = tmp_path / "slots"
    slot_dir.mkdir()
    shim = _write_recorder_shim(tmp_path)
    monkeypatch.setenv("RECORDER_FILE", str(events_dir))
    monkeypatch.setenv("SLEEP_S", "2")

    cfg = Config(
        host_powershell_path=str(shim),
        max_host_powershell=1,
        host_powershell_wait_s=0.3,
        ps_slot_dir=str(slot_dir),
    )
    pswindows.init(cfg)

    def slot_holding_leg():
        pswindows.run_ps("Write-Output 'busy-holder'", timeout_s=30)

    first = threading.Thread(target=slot_holding_leg)
    first.start()
    try:
        holder_pid = _first_event_pid(events_dir, timeout_s=10.0)
        assert holder_pid is not None, "the slot-holding child never started"

        raised: list = []
        try:
            pswindows.run_ps("Write-Output 'busy-second'", timeout_s=30)
        except Exception as exc:
            raised.append(exc)

        assert raised, (
            "the second run_ps call neither completed nor raised while the "
            "only slot was held; the bounded wait must fail loudly"
        )
        busy = raised[0]
        assert isinstance(busy, pswindows.PowerShellBusy), (
            f"expected pswindows.PowerShellBusy, got "
            f"{type(busy).__name__}: {busy}"
        )
        assert errors.classify(busy) == "busy", (
            f"errors.classify(PowerShellBusy) returned "
            f"{errors.classify(busy)!r}, not 'busy'"
        )
    finally:
        first.join(timeout=30)


# ---------------------------------------------------------------------------
# AC5 - the cap is host-wide across separate processes
# ---------------------------------------------------------------------------

# Worker run via `sys.executable -c`: inserts <repo-root>/src derived from the
# TEST FILE's location (never cwd or an installed binding, so base-leg runs in
# a disposable worktree import the base src), builds the capped config through
# the real from_dict loader, then drives 6 concurrent run_ps calls.
_WORKER_TEMPLATE = """\
import sys

sys.path.insert(0, {src!r})

import threading

from hyperv_mcp import pswindows
from hyperv_mcp.config import Config


def main():
    cfg = Config.from_dict(dict(
        host_powershell_path={shim!r},
        max_host_powershell=4,
        host_powershell_wait_s=30,
        ps_slot_dir={slot_dir!r},
    ))
    pswindows.init(cfg)
    results = [None] * 6
    failures = []
    barrier = threading.Barrier(6)

    def call(index):
        try:
            barrier.wait(timeout=30)
            results[index] = pswindows.run_ps(
                "Write-Output 'cross-process-cap'", timeout_s=120)
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=call, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    if failures:
        raise failures[0]
    if any(result is None or not result.ok() for result in results):
        raise SystemExit(3)


main()
"""


def test_cap_is_host_wide_across_processes(tmp_path):
    """AC5: two separate worker PROCESSES sharing one ps_slot_dir with
    max_host_powershell=4 (6 concurrent run_ps calls each, 12 total) never
    leave more than 4 live children COMBINED, and both workers exit 0. RED
    at the pre-fix base (both workers die on the unknown config keys), GREEN
    after the fix."""
    src_root = str(_UNIT_FILE.parents[2] / "src")
    shim = _write_recorder_shim(tmp_path)
    slot_dir = tmp_path / "slots"
    slot_dir.mkdir()
    worker_source = _WORKER_TEMPLATE.format(
        src=src_root, shim=str(shim), slot_dir=str(slot_dir)
    )

    events_dirs = []
    for index in range(2):
        worker_events = tmp_path / f"rec-w{index}"
        worker_events.mkdir()
        events_dirs.append(worker_events)

    popens = []
    for worker_events in events_dirs:
        env = dict(os.environ, RECORDER_FILE=str(worker_events), SLEEP_S="1.5")
        popens.append(subprocess.Popen(
            [sys.executable, "-c", worker_source],
            cwd=str(tmp_path),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ))
    outputs = [popen.communicate(timeout=120) for popen in popens]
    codes = [popen.returncode for popen in popens]

    assert codes == [0, 0], (
        f"cap workers exited {codes} (expected both 0); worker stderr tails: "
        f"{[out[1].decode('utf-8', 'replace')[-400:] for out in outputs]}"
    )

    intervals: list[tuple[float, float]] = []
    for worker_events in events_dirs:
        intervals.extend(_load_intervals(worker_events))
    assert len(intervals) == 12, (
        f"expected 12 recorded children across both workers, found "
        f"{len(intervals)}"
    )
    peak = _peak_concurrency(intervals)
    assert peak <= 4, (
        f"{peak} host PowerShell children were live at once across two "
        "separate processes; the cap is not host-wide"
    )
