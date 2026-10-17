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
