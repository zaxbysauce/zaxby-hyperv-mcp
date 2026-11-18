"""Issue #153 acceptance checks: the evidence-run directory reuse guard.

RED at base, GREEN after the fix (issue #153's two criteria):
  AC1 test_run_start_refuses_reused_run_dir (DISCRIMINATING)
      a start into a run_dir that already holds a previous run's
      manifest.json must be refused with an invalid-class envelope BEFORE
      any registry entry, journal file, or frames directory is created.
  AC2 test_run_start_refusal_names_preexisting_files (DISCRIMINATING)
      the refusal must name each offending pre-existing file
      (manifest.json and/or evidence.mp4) so the caller can pick a fresh
      run_dir without trial and error.

File placement note: the issue's Scope names tests/unit/test_evidence_run_journal.py,
but that file is already 642 lines — past the 500-line test-file cap the
issue-tracer acceptance-checks rule sets for new checks ("new checks live in
their own new files (never appended to an existing file already at the
500-line test-file cap)"), and no frozen manifest pins it, so these checks
live in their own new file. The test names are the issue's own.

What is faked: the journal seams only. start_run's config seam is installed
with a per-test unrestricted Config rooted at tmp_path (the same pattern as
tests/unit/test_console.py's screenshot-policy tests); no PowerShell leg, no
capture, no ffmpeg ever runs — these tests exercise admission only.
"""

from __future__ import annotations

import pytest

from hyperv_mcp import evidencejournal as ej
from hyperv_mcp.config import Config

# A minimal valid-enough mp4 header: the guard checks existence, not bytes.
_MP4_HEAD = b"\x00\x00\x00\x18ftypmp42"


def _journal_cfg(tmp_path) -> Config:
    return Config(unrestricted=True, host_write_roots=[str(tmp_path)])


@pytest.fixture(autouse=True)
def _restore_seams_and_registry():
    """Undo the install() seam swap and drop any leaked registry entries.

    At base the refused starts are ACCEPTED, which leaves open runs in the
    module registry; clearing it keeps one test's base-state leak from
    counting toward another's per-agent cap.
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


def test_run_start_refuses_reused_run_dir(tmp_path):
    cfg = _journal_cfg(tmp_path)
    _install(cfg)

    # The true scenario: run 1 completes in a fresh dir and its stop leaves
    # manifest.json behind; run 2 into the SAME dir must be refused.
    run_dir = tmp_path / "reused-run"
    first = ej.start_run(str(run_dir), ["test-vm"])
    assert first.get("ok") is True, first
    stopped = ej.stop_run(first["run_id"])
    assert stopped.get("ok") is True, stopped
    assert (run_dir / "manifest.json").exists(), (
        "run 1's stop must leave the manifest.json the reuse guard refuses")

    second = ej.start_run(str(run_dir), ["test-vm"])
    assert second.get("ok") is False, (
        "start_run must refuse a reused run dir (a previous run's "
        f"manifest.json is present); it accepted it: {second!r}")
    assert second.get("error_class") == "invalid", second

    # The refusal must create nothing. A directory holding ONLY the stale
    # manifest (no frames/) must be refused without a registry entry and
    # without the frames directory appearing.
    bare = tmp_path / "bare-stale-manifest"
    bare.mkdir()
    (bare / "manifest.json").write_text("{}", encoding="utf-8")
    with ej._RUNS_LOCK:
        before = sorted(ej._RUNS)
    third = ej.start_run(str(bare), ["test-vm"])
    with ej._RUNS_LOCK:
        after = sorted(ej._RUNS)
    assert third.get("ok") is False, (
        "start_run must refuse a run_dir holding only a stale manifest.json; "
        f"it accepted it: {third!r}")
    assert after == before, (
        f"a refused start must not leave a registry entry behind: "
        f"before={before} after={after}")
    assert not (bare / "frames").exists(), (
        "a refused start must not create the frames directory")


def test_run_start_refusal_names_preexisting_files(tmp_path):
    cfg = _journal_cfg(tmp_path)
    _install(cfg)

    # evidence.mp4 alone must be refused AND named.
    only_video = tmp_path / "only-video"
    only_video.mkdir()
    (only_video / "evidence.mp4").write_bytes(_MP4_HEAD)
    out = ej.start_run(str(only_video), ["test-vm"])
    assert out.get("ok") is False, (
        "start_run must refuse a run_dir with pre-existing run artifacts "
        f"(evidence.mp4); it accepted it: {out!r}")
    assert out.get("error_class") == "invalid", out
    assert "evidence.mp4" in out.get("error", ""), (
        "the refusal must name each offending pre-existing file; got: "
        f"{out.get('error', '')!r}")

    # Both artifacts present: BOTH must be named in one refusal.
    both = tmp_path / "both-artifacts"
    both.mkdir()
    (both / "manifest.json").write_text("{}", encoding="utf-8")
    (both / "evidence.mp4").write_bytes(_MP4_HEAD)
    out2 = ej.start_run(str(both), ["test-vm"])
    assert out2.get("ok") is False, out2
    err = out2.get("error", "")
    assert "manifest.json" in err and "evidence.mp4" in err, (
        f"the refusal must name BOTH offending pre-existing files; got: "
        f"{err!r}")
