"""PR #38 review-feedback pins (issue #7 round 2, PRR-010 supplemental tests).

The frozen acceptance file tests/unit/test_a03_guest_jobs.py is
mutation-permeable by construction (its matcher accepts a kill-free walk;
its ticks checks are presence-only; no negative-path tests exist anywhere).
These are the supplemental NON-FROZEN pins the review required, one per
escaped mutation class:

  (a) survivor-wins guard  — `stopped: true` with a survivor must NOT win
  (b) tree-kill target pin — taskkill carries /T /F AND the recorded pid
  (c) wrapper-gone walk    — no `$null -eq $p` short-circuit; the
                             Win32_Process BFS + per-member kill loop are
                             unconditional (orphans of a dead wrapper keep
                             the dead PID as ParentProcessId, so the walk
                             must still find and kill them)
  (d) pid_reused plumbing  — a guest payload's pid_reused reaches the result
  (e) pinned-ticks path    — a recorded start_time_ticks is embedded by the
                             status AND stop legs and returned by job_start
  (f) FIX-3 error contract — the transport-error stop returns the full
                             documented key set plus the error pair
  (g) FIX-5 OverflowError  — an overflowing (inf) start_time_ticks degrades
                             to None instead of stranding the slot
  (h) FIX-6 malformed survivors — a non-numeric alive_pids member returns
                             the full-key error envelope, entry stoppable
  (i) FIX-2 LE reset       — wrapper and all sync builders reset
                             $LASTEXITCODE immediately before the invoke
"""

import base64
import json
import re

import pytest

from hyperv_mcp import guestexec, guestjobs, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")
TICKS = 12345


class FakePS:
    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


def _start_ok():
    return _ok({"pid": 4242, "job_dir": "C:\\t\\hyperv-mcp-job-x",
                "start_time_ticks": TICKS})


@pytest.fixture(autouse=True)
def _clean_registry():
    guestjobs.clear_registry_for_tests()
    yield
    guestjobs.clear_registry_for_tests()


def _inner(script: str) -> str:
    m = re.search(r"\$enc = '([A-Za-z0-9+/=]+)'", script)
    assert m, "script must embed a b64 payload"
    return base64.b64decode(m.group(1)).decode("utf-8")


def _start_job(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_start_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    return cfg, fake, start


# (a) survivor-wins guard ----------------------------------------------------


def test_survivor_wins_over_contradictory_stopped_true(monkeypatch):
    """PRR-010/T7: a guest payload claiming stopped:true WITH a survivor
    must be reported as not stopped, and the entry must stay retryable."""
    cfg, fake, start = _start_job(monkeypatch)
    fake.responses.append(_ok({"stopped": True, "alive_pids": [7],
                               "job_dir_removed": True, "pid_reused": False}))
    out = guestjobs.job_stop(cfg, start["job_id"])
    assert out["ok"] is False
    assert out["stopped"] is False
    assert out["alive_pids"] == [7]
    entry = guestjobs._jobs[start["job_id"]]
    assert entry["stopped"] is False
    assert entry["cred"] is CRED  # retained for the retry


# (b)+(c) emitted stop-script shape -------------------------------------------


def test_stop_script_pins_tree_kill_target_and_wrapper_gone_walk(monkeypatch):
    """(b) The kill must carry /T /F on the RECORDED pid (target-proof, not
    a kill-free walk); (c) the wrapper-gone short-circuit must be gone and
    the Win32_Process walk + per-member kill loop unconditional."""
    cfg, fake, start = _start_job(monkeypatch)
    fake.responses.append(_ok({"stopped": True, "alive_pids": [],
                               "job_dir_removed": True, "pid_reused": False}))
    guestjobs.job_stop(cfg, start["job_id"])
    script = _inner(fake.scripts[1])
    # (b) target-proof: the literal recorded pid rides a taskkill /T /F.
    assert "taskkill" in script.lower()
    for flag in ("/pid", "/t", "/f"):
        assert re.search(rf"{flag}\b", script.lower()), f"missing {flag}"
    assert re.search(r"taskkill /PID 4242 /T /F", script), (
        "the tree kill must be rooted at the recorded pid"
    )
    # (c) no wrapper-gone short-circuit: the walk/kill/observe must run
    # even when the recorded pid is absent (orphaned descendants keep the
    # dead pid as ParentProcessId, so the BFS from the recorded pid is the
    # only thing that still finds them).
    assert "$null -eq $p" not in script, (
        "a missing wrapper pid must not short-circuit to stopped"
    )
    assert "Get-CimInstance -ClassName Win32_Process" in script
    assert "ParentProcessId" in script
    assert "$frontier" in script  # BFS frontier walk
    # Per-member kill: every walked member (not just the root) is killed,
    # so an orphaned descendant dies even with the wrapper already gone.
    assert "foreach ($t in $tree)" in script
    assert re.search(r"taskkill /PID \$t /T /F", script)
    assert "Stop-Process -Id $t -Force" in script
    # Survivors are OBSERVED after the kill, from the walked tree.
    assert re.search(r"if \(\$null -ne \(Get-Process -Id \$t", script)
    assert "if ($alive.Count -eq 0) { $stopped = $true }" in script


def test_stop_script_identity_catch_does_not_claim_reuse():
    """FIX-4/PRR-002 shape pin: only a CONFIRMED tick mismatch may set
    pid_reused — the StartTime-read catch must not (the emitted script
    tracks the read failure separately from the mismatch)."""
    script = guestjobs._stop_script(4242, "C:\\t", TICKS)
    assert "catch { $ours = $false; $readFailed = $true }" in script
    assert "if (-not $readFailed) { $reused = $true }" in script


# (d) pid_reused plumbing ------------------------------------------------------


def test_guest_pid_reused_flag_reaches_the_result(monkeypatch):
    cfg, fake, start = _start_job(monkeypatch)
    fake.responses.append(_ok({"stopped": True, "alive_pids": [],
                               "job_dir_removed": True, "pid_reused": True}))
    out = guestjobs.job_stop(cfg, start["job_id"])
    assert out["pid_reused"] is True
    assert out["stopped"] is True


# (e) pinned-ticks path --------------------------------------------------------


def test_recorded_ticks_reach_status_and_stop_legs(monkeypatch):
    cfg, fake, start = _start_job(monkeypatch)
    assert start["start_time_ticks"] == TICKS
    assert guestjobs._jobs[start["job_id"]]["start_time_ticks"] == TICKS
    fake.responses.append(_ok({"status": "running", "process_name": "x"}))
    fake.responses.append(_ok({"stopped": True, "alive_pids": [],
                               "job_dir_removed": True, "pid_reused": False}))
    guestjobs.job_status(cfg, start["job_id"])
    guestjobs.job_stop(cfg, start["job_id"])
    status_inner = _inner(fake.scripts[1])
    stop_inner = _inner(fake.scripts[2])
    assert f"$want = {TICKS}" in status_inner
    assert f"$want = {TICKS}" in stop_inner


# (f) FIX-3: 7-key error contract ----------------------------------------------


def test_stop_transport_error_returns_full_key_set(monkeypatch):
    cfg, fake, start = _start_job(monkeypatch)
    fake.responses.append(
        pswindows.PSResult(stdout="", returncode=1, stderr="transport down")
    )
    out = guestjobs.job_stop(cfg, start["job_id"])
    assert set(out) == {
        "ok", "job_id", "pid", "stopped", "alive_pids", "job_dir_removed",
        "pid_reused", "error", "error_class",
    }
    assert out["ok"] is False
    assert out["stopped"] is False
    assert out["alive_pids"] == []
    assert out["job_dir_removed"] is None
    assert out["pid_reused"] is False
    assert "transport down" in out["error"]
    assert out["error_class"] == "transport"
    entry = guestjobs._jobs[start["job_id"]]
    assert entry["stopped"] is False and entry["cred"] is CRED


# (g) FIX-5: OverflowError degrade ---------------------------------------------


def test_start_overflowing_ticks_degrade_to_none(monkeypatch):
    """A JSON inf start_time_ticks (int(inf) raises OverflowError) must
    degrade to the legacy no-pin path, not strand the reserved slot."""
    cfg = Config(unrestricted=True)
    fake = FakePS([_ok({"pid": 4242, "job_dir": "C:\\t",
                        "start_time_ticks": float("inf")})])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    assert out["ok"] is True
    assert out["start_time_ticks"] is None
    entry = guestjobs._jobs[out["job_id"]]
    assert entry["start_time_ticks"] is None
    assert entry.get("in_flight") is not True  # registered, not stranded


# (h) FIX-6: malformed survivor list ------------------------------------------


def test_stop_nonnumeric_alive_pids_returns_invalid_envelope(monkeypatch):
    cfg, fake, start = _start_job(monkeypatch)
    fake.responses.append(_ok({"stopped": True, "alive_pids": ["seven"],
                               "job_dir_removed": True, "pid_reused": False}))
    out = guestjobs.job_stop(cfg, start["job_id"])
    assert set(out) == {
        "ok", "job_id", "pid", "stopped", "alive_pids", "job_dir_removed",
        "pid_reused", "error", "error_class",
    }
    assert out["ok"] is False
    assert out["error_class"] == "invalid"
    entry = guestjobs._jobs[start["job_id"]]
    assert entry["stopped"] is False and entry["cred"] is CRED


# (i) FIX-2: $LASTEXITCODE reset before the invoke -----------------------------


def test_wrapper_resets_lastexitcode_before_the_invoke(monkeypatch):
    cfg, fake, start = _start_job(monkeypatch)
    wrapper = _inner(_inner(fake.scripts[0]))
    reset_at = wrapper.find("$global:LASTEXITCODE = $null")
    invoke_at = wrapper.find("& 'x.exe'")
    assert reset_at != -1 and invoke_at != -1 and reset_at < invoke_at, (
        "the wrapper must reset $LASTEXITCODE immediately before the invoke"
    )


def test_sync_builders_reset_lastexitcode_before_the_invoke(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _ok({"exit_code": 0, "stdout": "", "stderr": ""}),
        _ok({"exit_code": 0, "stdout": "", "stderr": ""}),
        _ok({"exit_code": 0, "stdout": "", "stderr": ""}),
        _ok({"exit_code": 0, "stdout": "", "stderr": ""}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    cred_kw = {"cred": CRED}
    guestexec.guest_run_ps(cfg, "vm1", "Get-Date", **cred_kw)
    guestexec.guest_run(cfg, "vm1", "cmd.exe", ["/c", "exit", "0"],
                        cwd=r"C:\\work", cred=CRED)
    guestexec.victim_run_ps(cfg, "vm1", "whoami",
                            cred=CredentialSet("victim", "p2"))
    guestexec.victim_run(cfg, "vm1", "cmd.exe", ["/c", "exit", "0"],
                         cred=CredentialSet("victim", "p2"))
    names = ("guest_run_ps", "guest_run(cwd)", "victim_run_ps", "victim_run")
    for name, host in zip(names, fake.scripts, strict=True):
        inner = _inner(host)
        reset_at = inner.find("$global:LASTEXITCODE = $null")
        tail_at = inner.find("$ok = $?")
        assert reset_at != -1 and tail_at != -1 and reset_at < tail_at, (
            f"{name} must reset $LASTEXITCODE before the invoke (and the "
            "LE-first tail must still follow it)"
        )
        # LE-first precedence retained in the tail (native exit N propagates).
        assert "if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }" in inner
        # No banned default-to-zero literal anywhere.
        assert "else { exit 0 }" not in inner
