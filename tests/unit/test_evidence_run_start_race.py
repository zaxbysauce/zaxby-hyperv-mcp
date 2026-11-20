"""Issue #163 acceptance checks: start_run root-uniqueness under _RUNS_LOCK.

RED at base (f5b8e39), GREEN after the root-uniqueness fix (issue #163 AC1):
at base the stale-artifact probe runs BEFORE _RUNS_LOCK and the registry is
keyed on uuid4 run_id with no root-uniqueness check under the lock, so both
racers on one not-yet-existing run root are ADMITTED (two run_ids, one
root) - the #153 reuse guard cannot see it because a live run leaves no
manifest.json/evidence.mp4 behind. After the fix, admission is serialized
by _RUNS_LOCK and the second claimant on an already-claimed root is refused
invalid BEFORE any registry entry, directory creation, or journal write.

  AC1 test_concurrent_same_root_starts_admit_exactly_one (DISCRIMINATING)
      a barrier-aligned pair of start_run calls on one fresh run root must
      admit exactly one run; the loser is refused with error_class
      "invalid". The assertion is on the OUTCOME (exactly one admitted),
      which is deterministic under the fix (the lock serializes admission)
      and under the bug (both admitted -> the exactly-one assertion fails
      -> RED).
  AC1 test_sequential_second_start_on_claimed_root_refused (DISCRIMINATING)
      a second, sequential start_run on a root already claimed by a LIVE
      run must be refused invalid, create no second frames directory, and
      leave exactly one registry entry (the stronger same-class shape the
      issue probe observed at base).

Error-text contract with the fix: the refusal names the live run claiming
the root - the fix emits "already in use by run <id-prefix>"; the checks
assert the stable substring "already in use by run".

Plan-critic round-1 F-8 additions (three more DISCRIMINATING-shape checks
on the same admission seam):

  AC1 test_same_root_refused_while_first_initializing (DISCRIMINATING)
      a seeded registry entry in state "initializing" (the window between
      the registry insert and the directory creation) claims the root; a
      start_run on that same root must be refused invalid naming the live
      run, and the refusal must NOT remove the seeded claim. At base there
      is no root-uniqueness check under the lock, so the start is ADMITTED
      (ok=True) - RED.
  AC1 test_same_root_refused_while_first_closing (DISCRIMINATING)
      identical shape with the seeded claim in state "closing" (the window
      during stop_run's finalize). RED at base for the same reason.
  AC1 test_mkdir_failure_rollback_releases_root (PRESERVING)
      green at base AND head: when run-dir creation fails after admission,
      the rollback that pops the registry entry must actually RELEASE the
      root - a retry on the SAME root (mkdir now succeeding) is ADMITTED.
      Proves the fix cannot turn a rolled-back failure into a stuck claim.

The fixture pattern mirrors tests/unit/test_evidence_run_reuse.py (issue
#153's checks): per-test Config(unrestricted=True,
host_write_roots=[str(tmp_path)]), ej.install(get_config=...,
is_mutating=lambda name: False, screenshot=lambda *a, **k: {}), and an
autouse teardown restoring the seam tuple (ej._get_config, ej._is_mutating,
ej._screenshot) and clearing ej._RUNS under ej._RUNS_LOCK. Admission only:
no PowerShell leg, no capture, no ffmpeg, no network - exactly like the
reuse tests.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest

from hyperv_mcp import evidencejournal as ej
from hyperv_mcp import policy
from hyperv_mcp.config import Config


def _journal_cfg(tmp_path) -> Config:
    return Config(unrestricted=True, host_write_roots=[str(tmp_path)])


@pytest.fixture(autouse=True)
def _restore_seams_and_registry():
    """Undo the install() seam swap and drop any leaked registry entries.

    At base the refused starts are ACCEPTED, which leaves open runs in the
    module registry; clearing it keeps one test's base-state leak from
    counting toward another's per-agent cap (same note as the reuse tests).
    """
    saved = (ej._get_config, ej._is_mutating, ej._screenshot)
    yield
    ej._get_config, ej._is_mutating, ej._screenshot = saved
    with ej._RUNS_LOCK:
        ej._RUNS.clear()


def _install(cfg: Config) -> None:
    ej.install(
        get_config=lambda: cfg,
        is_mutating=lambda name: False,
        screenshot=lambda *a, **k: {},
    )


def test_concurrent_same_root_starts_admit_exactly_one(tmp_path):
    cfg = _journal_cfg(tmp_path)
    _install(cfg)

    root = tmp_path / "race-root"
    barrier = threading.Barrier(2)
    results: list[dict] = []

    def racer() -> None:
        try:
            barrier.wait(timeout=15)
            results.append(ej.start_run(str(root), ["test-vm"]))
        except BaseException as exc:  # diagnostics; asserted on below
            results.append({"ok": False,
                            "error": f"racer thread failed: {exc!r}",
                            "error_class": "invalid"})

    threads = [threading.Thread(target=racer, daemon=True) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not any(t.is_alive() for t in threads), (
        "a racer thread did not finish within the 15 s join timeout")

    assert len(results) == 2, results
    admitted = [r for r in results if r.get("ok") is True]
    refused = [r for r in results if r.get("ok") is not True]
    assert len(admitted) == 1, (
        "exactly one racer must be admitted on a fresh run root; "
        f"outcomes: {results!r}")
    assert len(refused) == 1, results
    assert refused[0].get("error_class") == "invalid", refused[0]
    assert "already in use by run" in refused[0].get("error", ""), (
        "the refusal must name the run root as claimed by a live run "
        f"(error text contract: 'already in use by run <id-prefix>'); "
        f"got: {refused[0].get('error', '')!r}")

    # The admitted run created its frames dir; the refused call created
    # nothing extra - after both calls the root holds exactly the admitted
    # run's set: the frames dir only.
    assert (root / "frames").is_dir(), (
        "the admitted run must create its frames directory")
    entries = sorted(p.name for p in root.iterdir())
    assert entries == ["frames"], (
        "the root must hold exactly the admitted run's frames dir (the "
        f"refused start must create nothing); got: {entries}")


def test_sequential_second_start_on_claimed_root_refused(tmp_path):
    cfg = _journal_cfg(tmp_path)
    _install(cfg)

    root = tmp_path / "seq-root"
    first = ej.start_run(str(root), ["test-vm"])
    assert first.get("ok") is True, first

    second = ej.start_run(str(root), ["test-vm"])
    assert second.get("ok") is False, (
        "a second start_run on a root already claimed by a LIVE run must "
        f"be refused; it accepted it: {second!r}")
    assert second.get("error_class") == "invalid", second
    assert f"already in use by run {first['run_id'][:8]}" in second.get(
        "error", ""), (
        "the refusal must name the claiming run's OWN id prefix "
        f"(error text contract: 'already in use by run <id-prefix>' with "
        f"the admitted run's id {first['run_id'][:8]!r}); got: "
        f"{second.get('error', '')!r}")

    # No second frames dir / nothing extra under the claimed root, and no
    # extra registry entry: exactly the admitted run's one entry remains.
    assert (root / "frames").is_dir(), (
        "the admitted run's frames directory must exist")
    entries = sorted(p.name for p in root.iterdir())
    assert entries == ["frames"], (
        f"the refused start must not add anything under the claimed root; "
        f"got: {entries}")
    with ej._RUNS_LOCK:
        assert len(ej._RUNS) == 1, (
            "a refused start must not leave a second registry entry; "
            f"registry size: {len(ej._RUNS)}")

    # Negative control (review round: overreach): a DIFFERENT root must
    # stay admissible while the first root is claimed — a refusal that is
    # too broad would silently take the feature down. Runs after the
    # registry-size assertion above (which pins the post-refusal state).
    other = ej.start_run(str(tmp_path / "other-root"), ["test-vm"])
    assert other.get("ok") is True, (
        "a start on an UNclaimed root must stay admissible while another "
        f"root is claimed (the refusal must not be over-broad); got: "
        f"{other!r}")


def _canonical_root(cfg: Config, root: Path) -> Path:
    """The run root exactly as start_run computes it (same host-write gate
    and exists-prefix resolution), so a seeded claim sits on the very path
    the uniqueness check compares against."""
    canonical = policy.check_host_write(cfg, str(root))
    return Path(str(canonical.exists_prefix_resolved or str(root)))


def _seed_registry_run(cfg: Config, root: Path, state: str):
    """Insert a registry entry claiming `root` the way start_run's
    admission block does (run_id, _Run under _RUNS_LOCK), pinned to
    `state` ("initializing"/"closing") to model the mid-flight windows
    where the claiming run is not yet (or no longer) open."""
    run_id = uuid.uuid4().hex
    run = ej._Run(run_id, _canonical_root(cfg, root), ej.current_agent(),
                  [], False)
    run.state = state
    with ej._RUNS_LOCK:
        ej._RUNS[run_id] = run
    return run_id, run


def test_same_root_refused_while_first_initializing(tmp_path):
    cfg = _journal_cfg(tmp_path)
    _install(cfg)

    root = tmp_path / "initializing-root"
    run_id, run = _seed_registry_run(cfg, root, "initializing")

    res = ej.start_run(str(root), ["test-vm"])
    assert res.get("ok") is False, (
        "a start_run on a root already claimed by a LIVE run still in "
        f"'initializing' (between registry insert and dir creation) must "
        f"be refused; it admitted it: {res!r}")
    assert res.get("error_class") == "invalid", res
    assert "already in use by run" in res.get("error", ""), (
        "the refusal must name the claiming run (error text contract: "
        f"'already in use by run <id-prefix>'); got: "
        f"{res.get('error', '')!r}")

    # The refusal happened BEFORE the registry: the seeded claim must be
    # untouched - not removed, not replaced, no second entry added.
    with ej._RUNS_LOCK:
        assert ej._RUNS.get(run_id) is run, (
            "the refusal must not remove or replace the seeded claim; "
            f"registry: {dict(ej._RUNS)!r}")
        assert len(ej._RUNS) == 1, (
            "the refused start must not add a registry entry; registry "
            f"size: {len(ej._RUNS)}")


def test_same_root_refused_while_first_closing(tmp_path):
    cfg = _journal_cfg(tmp_path)
    _install(cfg)

    root = tmp_path / "closing-root"
    run_id, run = _seed_registry_run(cfg, root, "closing")

    res = ej.start_run(str(root), ["test-vm"])
    assert res.get("ok") is False, (
        "a start_run on a root already claimed by a LIVE run in 'closing' "
        "(stop_run's finalize window) must be refused; it admitted it: "
        f"{res!r}")
    assert res.get("error_class") == "invalid", res
    assert "already in use by run" in res.get("error", ""), (
        "the refusal must name the claiming run (error text contract: "
        f"'already in use by run <id-prefix>'); got: "
        f"{res.get('error', '')!r}")

    with ej._RUNS_LOCK:
        assert ej._RUNS.get(run_id) is run, (
            "the refusal must not remove or replace the seeded claim; "
            f"registry: {dict(ej._RUNS)!r}")
        assert len(ej._RUNS) == 1, (
            "the refused start must not add a registry entry; registry "
            f"size: {len(ej._RUNS)}")


def test_cross_agent_root_uniqueness(tmp_path):
    """Review round (swarm-pr-review): the uniqueness loop is deliberately
    CROSS-agent (no `r.agent == ag` filter — unlike the per-agent cap check
    above it), and that scope is the fix's core invariant. RED at base only
    in the sense that any agent-filter regression would re-admit here: this
    test pins the cross-agent refusal so a copy-paste `and r.agent == ag`
    regression cannot pass the suite."""
    cfg = _journal_cfg(tmp_path)
    _install(cfg)

    root = tmp_path / "cross-agent-root"
    first = ej.start_run(str(root), ["test-vm"], agent="agent-a")
    assert first.get("ok") is True, first

    second = ej.start_run(str(root), ["test-vm"], agent="agent-b")
    assert second.get("ok") is False, (
        "a DIFFERENT agent's start_run on a root claimed by another "
        "agent's live run must still be refused (uniqueness is "
        f"cross-agent, not per-agent); it accepted it: {second!r}")
    assert second.get("error_class") == "invalid", second
    assert f"already in use by run {first['run_id'][:8]}" in second.get(
        "error", ""), (
        "the cross-agent refusal must name the owning run's id prefix; "
        f"got: {second.get('error', '')!r}")


def test_mkdir_failure_rollback_releases_root(tmp_path, monkeypatch):
    cfg = _journal_cfg(tmp_path)
    _install(cfg)

    root = tmp_path / "mkdir-fail-root"
    canon = _canonical_root(cfg, root)

    # Path.mkdir raises ONLY for the run root itself; every other path
    # delegates to the real mkdir (monkeypatch restores the class attribute
    # afterwards).
    orig_mkdir = ej.Path.mkdir

    def _mkdir_fails_only_for_run_root(self, *args, **kwargs):
        if str(self) == str(canon):
            raise OSError("simulated run-dir creation failure")
        return orig_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(ej.Path, "mkdir", _mkdir_fails_only_for_run_root)

    refused = ej.start_run(str(root), ["test-vm"])
    assert refused.get("ok") is False, refused
    assert refused.get("error_class") == "invalid", refused
    assert "cannot create run dir" in refused.get("error", ""), refused

    # The post-admission mkdir failure rolled the registry entry back: no
    # entry for this agent may still claim the root.
    with ej._RUNS_LOCK:
        leftover = [r for r in ej._RUNS.values()
                    if str(r.run_dir) == str(canon)]
        assert not leftover, (
            "the mkdir-failure rollback must release the root from the "
            f"registry; leftover entries: {leftover!r}")

    monkeypatch.undo()
    again = ej.start_run(str(root), ["test-vm"])
    assert again.get("ok") is True, (
        "after the rollback released the root, a retry on the SAME root "
        f"(mkdir now succeeding) must be admitted - the rollback must not "
        f"leave the root stuck as claimed; got: {again!r}")
