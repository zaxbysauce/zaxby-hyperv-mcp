"""Frozen acceptance check for issue #21, AC13's executable half.

The soak harness's `--session-reuse off,on` switch (scripts/soak_bench.py) is
the only part of AC13 that can be executed without a live Hyper-V host with
guest credentials. This file is deliberately separate from
tests/unit/test_d05_psdirect_sessions.py so the frozen blob of that file is
never disturbed by an edit here.

The live before/after `psdirect_session_ms` and p50/p95 numbers are NOT
executable in this environment (no guest credentials; see 01-issue-summary.md's
probe output). They remain owed to an operator, and the issue itself states the
measurement never blocks the PR.

RED at base 9434636cb035ebdb91415c5e4809ba6db20b05c5 with argparse's
deterministic refusal of the unknown flag; GREEN after the fix.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path


def _import_soak_bench():
    """Insert the repo's scripts/ dir on sys.path and import soak_bench (the
    tests/unit/test_d04_timing.py helper)."""
    scripts_dir = str(Path(__file__).resolve().parents[2] / "scripts")
    sys.path.insert(0, scripts_dir)
    try:
        import soak_bench
    finally:
        sys.path.remove(scripts_dir)
    return soak_bench


def test_soak_bench_session_reuse_reports_both_states_for_every_agent_count():
    """AC13's executable half: driven in fake mode with
    --agents 1,4,8 --session-reuse off,on, the harness reports ONE row per
    (agent count, reuse state) - six rows - and every row carries the reuse
    state and the guest-timing median key the live comparison reads.

    Deliberately honest about scope: the fake stub emits no timing markers, so
    these rows carry no live psdirect_session_ms and prove only that the
    --session-reuse switch this PR adds is wired through the harness for every
    agent count. The live before/after numbers remain owed to an operator with
    guest credentials (the AC13 row in 02-reproduction.md)."""
    soak_bench = _import_soak_bench()

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = soak_bench.main([
            "--fake", "--agents", "1,4,8", "--iterations", "1",
            "--session-reuse", "off,on", "--json",
        ])
    assert rc == 0, f"soak_bench --session-reuse exited {rc}"
    rows = [
        json.loads(line)
        for line in buffer.getvalue().splitlines()
        if line.strip().startswith("{")
    ]
    assert len(rows) == 6, (
        f"expected six rows (3 agent counts x 2 reuse states), got {len(rows)}: "
        f"{buffer.getvalue()!r}"
    )
    assert sorted((row["agents"], str(row.get("session_reuse"))) for row in rows) == [
        (1, "False"), (1, "True"),
        (4, "False"), (4, "True"),
        (8, "False"), (8, "True"),
    ], f"the rows did not cover every (agent count, reuse state) pair: {rows}"
    assert all("guest_timing_median_ms" in row for row in rows), rows
