"""Issue #7 checks (Workstream A PR 3): truthful managed-guest-job reporting.

These tests pin the REQUIRED post-fix behavior of acceptance criteria
AC1-AC7 from .agents/issue-traces/7-guest-jobs-truthful-reporting
(01-issue-summary.md). They deliberately FAIL against the current tree:
each asserts a shape the unfixed guest scripts / host plumbing do not yet
produce (no tree kill, optimistic stop result, null->0 exit defaults, no
PID start-time pin). Pure unit tests: pswindows.run_ps is faked; no
Hyper-V host, no guest, no network.
"""

import base64
import json
import re

import pytest

from hyperv_mcp import guestexec, guestjobs, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")
VICTIM = CredentialSet("victim", "placeholder-pass-2")

# .NET-style UTC ticks a fixed start leg reports as start_time_ticks.
START_TICKS = 638765432100000000

# Well-formed GUID served for the by-name identity-resolution leg vmident
# resolve runs before job_start/guestexec calls (issue #8; test_a04 pattern).
VM_GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


class FakePS:
    """Records every host script; auto-serves the identity-resolution leg
    (issue #8) and pops one canned response per action leg."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=VM_GUID, returncode=0)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


def _start_ok():
    return _ok(
        {
            "pid": 4242,
            "job_dir": "C:\\Users\\x\\AppData\\Local\\Temp\\hyperv-mcp-job-abc",
            "start_time_ticks": START_TICKS,
        }
    )


@pytest.fixture(autouse=True)
def _clean_registry():
    guestjobs.clear_registry_for_tests()
    yield
    guestjobs.clear_registry_for_tests()


def _inner(script: str) -> str:
    m = re.search(r"\$enc = '([A-Za-z0-9+/=]+)'", script)
    assert m, "script must embed a b64 payload"
    return base64.b64decode(m.group(1)).decode("utf-8")


def _kills_process_tree(inner: str) -> bool:
    """AC1 shape: terminate the recorded PID AND all descendants — a
    taskkill carrying /PID with /T (tree) and /F, or a Win32_Process
    ParentProcessId walk. A bare Stop-Process on one PID is not a tree kill."""
    lower = inner.lower()
    if "taskkill" in lower and all(re.search(rf"{flag}\b", lower) for flag in ("/pid", "/t", "/f")):
        return True
    return "win32_process" in lower and "parentprocessid" in lower


def test_stop_script_kills_process_tree(monkeypatch):
    """AC1: the guest stop script must kill the whole process tree."""
    cfg = Config(unrestricted=True)
    fake = FakePS(
        [
            _start_ok(),
            _ok({"stopped": True, "alive_pids": [], "job_dir_removed": True}),
        ]
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    guestjobs.job_stop(cfg, start["job_id"])
    stop_inner = _inner(fake.scripts[2])
    assert _kills_process_tree(stop_inner) is True


def test_stop_reports_guest_observed_failure(monkeypatch):
    """AC2: a guest stop leg RETURNING stopped:false must be reported as
    such, and the entry stays stoppable with its credential retained."""
    cfg = Config(unrestricted=True)
    fake = FakePS(
        [
            _start_ok(),
            _ok({"stopped": False, "alive_pids": [4242], "job_dir_removed": True}),
        ]
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    out = guestjobs.job_stop(cfg, start["job_id"])
    assert out["stopped"] is False
    assert out["ok"] is False
    entry = guestjobs._jobs[start["job_id"]]
    assert entry["stopped"] is False
    assert entry["cred"] is CRED


def test_stop_surfaces_job_dir_removed(monkeypatch):
    """AC3: the tool result must carry the guest-observed job_dir_removed."""
    cfg = Config(unrestricted=True)
    fake = FakePS(
        [
            _start_ok(),
            _ok({"stopped": True, "alive_pids": [], "job_dir_removed": False}),
        ]
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    out = guestjobs.job_stop(cfg, start["job_id"])
    assert out.get("job_dir_removed") is False


def test_wrapper_never_defaults_exit_code_to_zero(monkeypatch):
    """AC4: a null $LASTEXITCODE must not be recorded as exit code 0."""
    cfg = Config(unrestricted=True)
    fake = FakePS([_start_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    # The wrapper .ps1 rides the start script's own b64 payload: decode twice.
    # scripts[0] is the identity-resolution leg; scripts[1] the start action.
    wrapper = _inner(_inner(fake.scripts[1]))
    assert "else { 0 | Set-Content -LiteralPath $exitf }" not in wrapper


def test_start_records_process_start_time(monkeypatch):
    """AC5: the start leg must record the launched process's StartTime."""
    cfg = Config(unrestricted=True)
    fake = FakePS([_start_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    start_inner = _inner(fake.scripts[1])
    assert "StartTime" in start_inner


def test_status_and_stop_pin_process_start_time(monkeypatch):
    """AC6: status and stop legs must embed the recorded start_time_ticks so
    a reused PID is neither reported running nor killed."""
    cfg = Config(unrestricted=True)
    fake = FakePS(
        [
            _start_ok(),
            _ok({"status": "running", "process_name": "x"}),
            _ok({"stopped": True, "alive_pids": [], "job_dir_removed": True}),
        ]
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    guestjobs.job_status(cfg, start["job_id"])
    guestjobs.job_stop(cfg, start["job_id"])
    recorded = str(START_TICKS)
    legs = [
        ("status", _inner(fake.scripts[2])),
        ("stop", _inner(fake.scripts[3])),
    ]
    missing = [name for name, script in legs if recorded not in script]
    assert missing == []


def test_exec_inner_scripts_never_default_exit_to_zero(monkeypatch):
    """AC7: no synchronous exec entry point may tail with `else { exit 0 }`."""
    cfg = Config(unrestricted=True)
    payload = {"exit_code": 0, "stdout": "", "stderr": ""}
    fake = FakePS([_ok(payload) for _ in range(4)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run_ps(cfg, "test-vm", "Write-Output hi", cred=CRED)
    guestexec.guest_run(cfg, "test-vm", "cmd.exe", ["/c", "exit 0"], cred=CRED)
    guestexec.victim_run_ps(cfg, "test-vm", "whoami", cred=VICTIM)
    guestexec.victim_run(cfg, "test-vm", "cmd.exe", ["/c", "exit 0"], cred=VICTIM)
    names = ("guest_run_ps", "guest_run", "victim_run_ps", "victim_run")
    # Each call resolves the VM identity first (issue #8): action legs are
    # the odd indexes after each interleaved resolution leg.
    defaulting = [
        name for name, script in zip(names, fake.scripts[1::2], strict=True) if "else { exit 0 }" in _inner(script)
    ]
    assert defaulting == []
