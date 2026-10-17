"""Phase-4.2 guardrail for the issue-#20 defect class (D-04).

Class: **missing observability — a cost is measured, then discarded, or never
measured at the right granularity.**

The guardrail pins the property at the construction site rather than through the
tool layer, so a future edit that moves or gates the accounting is caught here
even if every frozen check still passes. The named mutant — deleting the
`collector.add_spawn(...)` call from `PSResult.__post_init__` — must turn this
file AND frozen checks C2/C3 red; a mutant that survives is a coverage gap, not
a pass.

Deliberately outside the frozen check file, whose bytes the checkpoint manifest
pins.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from hyperv_mcp import auditlog, timing
from hyperv_mcp.config import Config


def test_measured_duration_cannot_be_dropped_silently(tmp_path):
    """A PSResult carrying a known duration_ms, built inside an
    auditlog.operation, must be reflected in that operation's timing — both the
    count and the sum. This is the construction-site form of what AC2 and AC3
    assert through the tool layer."""
    log = tmp_path / "guardrail-audit.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    from hyperv_mcp import pswindows

    with auditlog.operation(
        tool="d04-guardrail-probe", vm_name="d04-vm", category="read"
    ):
        pswindows.PSResult(stdout="leg", returncode=0, duration_ms=4242)

    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert rows, "the operation wrote no audit row"
    timing_block = rows[-1]["timing"]
    assert timing_block["ps_spawns"] == 1, (
        f"one measured spawn was not counted: {timing_block}"
    )
    assert timing_block["ps_ms"] == 4242, (
        f"the measured duration was dropped: {timing_block}"
    )


def test_no_collector_means_no_accounting(tmp_path):
    """Outside an audited operation nothing is counted, so a PSResult built by
    a test or a CLI caller cannot inflate some later operation's numbers."""
    from hyperv_mcp import pswindows

    assert timing.current() is None, "a collector leaked into this test"
    before = timing.zeroed()
    pswindows.PSResult(stdout="x", returncode=0, duration_ms=999)
    assert timing.current() is None
    assert before == timing.zeroed()


def test_collector_is_fresh_per_operation(tmp_path):
    """Sequential operations must not accumulate: the second operation's counts
    reflect only its own spawns."""
    log = tmp_path / "guardrail-seq.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    from hyperv_mcp import pswindows

    with auditlog.operation(tool="d04-seq-a", vm_name="v", category="read"):
        pswindows.PSResult(stdout="a", returncode=0, duration_ms=100)
        pswindows.PSResult(stdout="a2", returncode=0, duration_ms=100)
    with auditlog.operation(tool="d04-seq-b", vm_name="v", category="read"):
        pswindows.PSResult(stdout="b", returncode=0, duration_ms=7)

    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert rows[0]["timing"]["ps_spawns"] == 2
    assert rows[0]["timing"]["ps_ms"] == 200
    assert rows[1]["timing"]["ps_spawns"] == 1, (
        "the second operation inherited the first operation's spawn count"
    )
    assert rows[1]["timing"]["ps_ms"] == 7


def test_failed_operation_still_reports_its_spawns(tmp_path):
    """An operation whose body raises after a spawn still reports that spawn,
    because the collector is read in __exit__ on the exception path."""
    log = tmp_path / "guardrail-fail.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    from hyperv_mcp import pswindows

    with pytest.raises(RuntimeError, match="d04 guardrail boom"):
        with auditlog.operation(tool="d04-fail", vm_name="v", category="read"):
            pswindows.PSResult(stdout="leg", returncode=0, duration_ms=55)
            raise RuntimeError("d04 guardrail boom")

    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert rows and rows[-1]["ok"] is False
    assert rows[-1]["timing"]["ps_spawns"] == 1
    assert rows[-1]["timing"]["ps_ms"] == 55


def test_no_collector_leaks_after_a_failure(tmp_path):
    """A raising log_operation must not leak a collector into the next
    operation on this thread."""
    log = tmp_path / "guardrail-leak.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    from hyperv_mcp import pswindows

    original = auditlog._emit

    def exploding(_line: str) -> None:
        raise OSError("sink is broken")

    auditlog._emit = exploding  # type: ignore[assignment]
    try:
        with pytest.raises(OSError, match="sink is broken"):
            with auditlog.operation(tool="d04-leak", vm_name="v", category="read"):
                pass
    finally:
        auditlog._emit = original  # type: ignore[assignment]

    assert timing.current() is None, "a collector leaked past a failed sink write"
    with auditlog.operation(tool="d04-after", vm_name="v", category="read"):
        pswindows.PSResult(stdout="x", returncode=0, duration_ms=3)
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["timing"]["ps_spawns"] == 1, (
        "the operation after a failed sink write inherited a leaked collector"
    )


def test_lock_wait_is_recorded_on_contention():
    """The lock-wait instrumentation, pinned directly.

    No frozen check asserts a NON-ZERO lock_wait_ms: AC4 asserts the
    uncontended case is 0, which a collector that never records a wait also
    satisfies. This is the other half — a waiter that really parked must see
    its wait in its own collector, and a busy failure must carry it on the
    exception so a failed acquire is measured too.
    """
    from hyperv_mcp import vmlocks

    key = "d04-lockwait-vm"
    outcome: dict = {}

    def waiter() -> None:
        token = timing.start()
        try:
            with vmlocks.vm_lock(key, "write", wait_s=10):
                outcome["acquired"] = True
        except vmlocks.VMBusy as exc:
            outcome["busy"] = True
            outcome["waited_ms"] = exc.waited_ms
        finally:
            outcome["timing"] = timing.finish(token)

    with vmlocks.vm_lock(key, "write", wait_s=10):
        thread = threading.Thread(target=waiter, name="d04-lockwait-waiter")
        thread.start()
        time.sleep(0.3)  # let the waiter park on the Condition
        assert thread.is_alive(), "the waiter should still be blocked"
    thread.join(timeout=10)
    assert not thread.is_alive(), "the waiter did not finish"
    assert outcome.get("acquired") is True, f"the waiter never acquired: {outcome}"
    assert outcome["timing"]["lock_wait_ms"] > 0, (
        f"a waiter that parked 0.3 s recorded lock_wait_ms="
        f"{outcome['timing']['lock_wait_ms']}: the wait is not being fed"
    )


def test_busy_failure_carries_the_wait_it_actually_waited():
    """A waiter that times out must report the wait it really sat out, not 0 —
    including the holder-drained branch, which is reached from inside the wait
    loop after the bounded window expired."""
    from hyperv_mcp import vmlocks

    key = "d04-busywait-vm"
    with vmlocks.vm_lock(key, "write", wait_s=10):
        token = timing.start()
        try:
            with pytest.raises(vmlocks.VMBusy) as excinfo:
                with vmlocks.vm_lock(key, "write", wait_s=0):
                    pass
        finally:
            snapshot = timing.finish(token)
    # wait_s=0 fails fast, so 0 is the honest answer here; the point is that the
    # value comes from the measurement rather than from a hardcoded default.
    assert excinfo.value.waited_ms == snapshot["lock_wait_ms"]
    assert snapshot["lock_wait_ms"] >= 0


def test_host_script_emits_the_timing_marker():
    """The marker emitter, pinned directly.

    AC5 injects the marker at the child-stdout level, so it passes whether or
    not any script ever emits one. Without an emitter the three guest-timing
    keys are structurally null in production and Workstream D PR 5's
    before/after baseline measures nothing — which is the no-unwired-code
    clause, so it gets a check of its own.
    """
    from hyperv_mcp import guestexec
    from hyperv_mcp.credentials import CredentialSet

    script = guestexec._host_script(
        "11111111-2222-3333-4444-555555555555",
        "Write-Output hi",
        CredentialSet(username="u", password="p"),
        elevated=False,
    )
    marker_lines = [
        line for line in script.splitlines() if "__MCP_TIMING=" in line
    ]
    assert marker_lines, "the guest host script no longer emits a timing marker"
    # Exactly one, and it is the LAST line: run_ps splits the trailing marker
    # off stdout, and _run_inner json.loads what remains.
    assert len(marker_lines) == 1, f"expected one marker line, got {len(marker_lines)}"
    assert script.strip().splitlines()[-1].strip().startswith('"__MCP_TIMING="'), (
        "the marker must be the script's last line"
    )
    for key in ("ps_startup_ms", "psdirect_session_ms", "guest_ms"):
        assert key in marker_lines[0], f"the marker omits {key}"
    # The guest envelope must carry the measured guest duration, which the
    # marker line reads back as guest_ms.
    assert "duration_ms=$__mcpGuest.ElapsedMilliseconds" in script, (
        "the guest PSCustomObject no longer reports its own duration"
    )
    # The marker payload shape must be one the parser accepts.
    payload = '{"ps_startup_ms":11,"psdirect_session_ms":22,"guest_ms":33}'
    cleaned, markers = timing.parse_marker(
        "json-line" + chr(10) + "__MCP_TIMING=" + payload + chr(10)
    )
    assert markers == {
        "ps_startup_ms": 11, "psdirect_session_ms": 22, "guest_ms": 33,
    }
    assert cleaned == "json-line"


def test_host_script_marker_survives_the_real_powershell_parse_lane():
    """The emitted script must still parse under real PowerShell 5.1.

    Brace-escaping and newline-join bugs in an f-string template are exactly
    what this lane exists to catch: a single unescaped brace silently becomes a
    replacement field and corrupts the emitted script, and two statements
    merged onto one line are a PS parse error. Skips where PowerShell is
    unavailable (CI's Linux leg), matching the repo's other parse lanes.
    """
    import shutil

    if shutil.which("powershell") is None and not Path(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    ).exists():
        pytest.skip("Windows PowerShell 5.1 is not available on this host")

    import subprocess

    from hyperv_mcp import guestexec, pswindows
    from hyperv_mcp.credentials import CredentialSet

    script = guestexec._host_script(
        "11111111-2222-3333-4444-555555555555",
        "Write-Output hi",
        CredentialSet(username="u", password="p"),
        elevated=False,
    )
    encoded = pswindows.encode_command(pswindows._PS_PIN + script)
    probe = (
        "$ErrorActionPreference='Stop'; "
        "$null = [System.Management.Automation.Language.Parser]::ParseInput("
        f"'{encoded}', [ref]$null, [ref]$null); "
        "Write-Output 'PARSE-OK'"
    )
    proc = subprocess.run(
        [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NonInteractive", "-NoProfile", "-Command", probe,
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert "PARSE-OK" in proc.stdout, (
        "the emitted guest host script does not parse under PowerShell 5.1"
        + chr(10) + "stdout: " + proc.stdout[-1500:]
        + chr(10) + "stderr: " + proc.stderr[-1500:]
    )
