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


def test_fake_mode_redirects_the_state_store_and_honours_an_operator_override(
    monkeypatch,
):
    """Issue #22 / PRR-009: the harness bootstraps a real server in-process,
    so without an explicit store path the run would open (and write) the
    profile-default store — or wherever a CWD-derived fallback pointed —
    instead of the TemporaryDirectory the run owns. The startup banner names
    the store the run actually resolved; pin it for both the default (a
    soak-owned path) and an operator override (which must win).
    """
    soak_bench = _import_soak_bench()

    def _banner_state_store() -> str:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = soak_bench.main(
                ["--fake", "--agents", "1", "--iterations", "1", "--json"]
            )
        assert rc == 0, "soak_bench --fake exited nonzero"
        lines = [
            line for line in err.getvalue().splitlines()
            if "state store:" in line
        ]
        assert lines, f"no state-store banner line in stderr:\n{err.getvalue()}"
        return lines[-1].split("state store:", 1)[1].strip()

    monkeypatch.delenv("HYPERV_MCP_STATE_DB", raising=False)
    soak_owned = _banner_state_store()
    assert soak_owned.endswith("soak-state.db"), soak_owned

    import os

    operator = os.path.join(os.path.abspath(os.sep), "lab", "operator-state.db")
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", operator)
    assert _banner_state_store() == operator
