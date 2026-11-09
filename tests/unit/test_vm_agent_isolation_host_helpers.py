"""No-host contract tests for the AC16 host-test helpers
(tests/host/test_vm_agent_isolation_host.py — plan-critic r5/r6 + review
round pr124-20261109).

These pin, WITHOUT any Hyper-V host access:
  1. vmident.resolve raises PowerShellTransportError (NOT media.MediaError)
     for a missing VM — the wrong-exception assumption that guaranteed a
     post-removal failure is dead forever;
  2. the fail-closed absence probe: returncode!=0 and raised transports are
     UNKNOWN (tracking retained, reported);
  3. review PRR-001: a SUCCESSFUL run_ps whose output is the probe's own
     PROBE-ERROR marker (the rc=3 suppressed-failure leg) is also UNKNOWN —
     the fail-open SilentlyContinue branch is dead by construction and its
     script shape is pinned;
  4. cleanup reports are emitted inside the finally (AST pin — PRR-011:
     block membership, robust to formatting/refactor) and the emission
     helper writes both the record and stderr with the "report: " kind
     (PRR-007) through a guarded write (PRR-008);
  5. benign kept rows (not_owned_ancestor / already_gone) and an
     already-gone VM (PRR-009) are inventory, never cleanup failures;
  6. failure kept rows (delete_failed) and residual child disks (PRR-012)
     are reported as cleanup failures with the entry retained.

The host-test module is loaded by file path under a unique name so the
unit suite never registers its fixtures; no env gate is touched. Fakes
mirror the production signatures (keyword-only run_ps options; the
lifecycle wait signature incl. vm_id — PRR-017).
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO = Path(__file__).resolve().parents[2]
_HOST_TEST = _REPO / "tests" / "host" / "test_vm_agent_isolation_host.py"


def _load_host_module():
    spec = importlib.util.spec_from_file_location("host_test_under_test_ac16", _HOST_TEST)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _PSResult(SimpleNamespace):
    timed_out: bool = False


def test_missing_vm_resolution_raises_transport_error_not_mediaerror(monkeypatch):
    import hyperv_mcp.media as media
    import hyperv_mcp.pswindows as pswindows
    import hyperv_mcp.vmident as vmident
    from hyperv_mcp.config import Config

    def fake_run_ps(script, *, timeout_s=None, stdin_b64=None):
        return _PSResult(returncode=1, stdout="", stderr="CommandNotFoundException: Get-VM failed")

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)
    with pytest.raises(pswindows.PowerShellTransportError) as raised:
        vmident.resolve(Config(unrestricted=True), vm_name="no-such-vm")
    assert not isinstance(raised.value, media.MediaError), (
        "resolver absence must NOT surface as media.MediaError (r6)")


def test_absence_probe_unknown_retains_tracked_entry(monkeypatch):
    module = _load_host_module()

    class _FakePS:
        def __init__(self):
            self.calls = []

        def init(self, cfg, redact=None):
            return None

        def run_ps(self, script, *, timeout_s=None, stdin_b64=None):
            self.calls.append(script)
            return _PSResult(returncode=1, stdout="", stderr="transport down")

    fake = _FakePS()
    monkeypatch.setattr(module, "pswindows", fake)

    class _FakeLife:
        def stop_vm(self, cfg, vm_name="", method="", confirm=False, vm_id=""):
            return {"status": "stopped"}

        def wait_for_vm_state(self, cfg, vm_name="", states=None, timeout_s=300, vm_id=""):
            return "Off"

    class _FakeMedia:
        def vm_remove(self, cfg, vm_name="", vm_id="", delete_disks=False, confirm=False):
            return {"ok": True, "kept": []}

    monkeypatch.setattr(module, "lifecycle", _FakeLife())
    monkeypatch.setattr(module, "media", _FakeMedia())

    tracked = [["g-1", "host-iso-a-x", "/nonexistent/child.vhdx"]]
    report, benign = [], []
    module._cleanup_tracked(cfg=None, provider=_Nop(), tracked=tracked,
                            report=report, benign=benign)
    assert tracked, "a transport-unknown absence MUST retain the tracked entry (fail-closed)"
    assert any("absence unknown" in r for r in report), report


def test_raised_transport_error_is_unknown_not_absence(tmp_path, capsys, monkeypatch):
    """r7: run_ps RAISING (pool/transport failure) is materially different
    from returncode!=0 — it must become 'unknown', retain tracking, enter
    the report, still emit the cleanup report, and never mask a primary
    exception."""
    module = _load_host_module()

    class _RaisingPS:
        def run_ps(self, script, *, timeout_s=None, stdin_b64=None):
            raise RuntimeError("transport raised")

    # wire the raising transport FIRST: the pre-patch call this test once
    # made against the real transport was environment-dependent (a bogus
    # GUID resolves GONE on a warmed slot pool, unknown cold) and failed
    # only in full-suite order — the pollution was the test's, not a
    # sibling's (fixed 2026-11-08)
    monkeypatch.setattr(module, "pswindows", _RaisingPS())
    assert module._vm_absent(cfg=None, guid="g-x") == "unknown"

    class _FakeLife:
        def stop_vm(self, cfg, vm_name="", method="", confirm=False, vm_id=""):
            return {"status": "stopped"}

        def wait_for_vm_state(self, cfg, vm_name="", states=None, timeout_s=300, vm_id=""):
            return "Off"

    class _FakeMedia:
        def vm_remove(self, cfg, vm_name="", vm_id="", delete_disks=False, confirm=False):
            return {"ok": True, "kept": []}

    monkeypatch.setattr(module, "lifecycle", _FakeLife())
    monkeypatch.setattr(module, "media", _FakeMedia())

    record = tmp_path / "record.txt"
    record_path = str(record)

    class _Host:
        record = record_path

        def note(self, line, kind="assert"):
            with open(self.record, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(f"{kind}: {line}\n")

    tracked = [["g-1", "host-iso-a-x", "/nonexistent/child.vhdx"]]
    report, benign = [], []
    try:
        try:
            raise AssertionError("primary test failure already in flight")
        finally:
            module._cleanup_tracked(cfg=None, provider=_Nop(), tracked=tracked,
                                    report=report, benign=benign)
            module._emit_cleanup_reports(_Host(), report, benign)
    except AssertionError as exc:
        assert "primary test failure" in str(exc), "primary exception survived cleanup"
    assert tracked, "raised-transport entry stays tracked"
    assert any("absence unknown" in r for r in report), report
    out = record.read_text(encoding="utf-8")
    assert "report: cleanup incomplete" in out, "cleanup reports use the report kind (PRR-007)"
    assert "absence unknown" in out
    assert "cleanup incomplete" in capsys.readouterr().err


def test_suppressed_probe_error_is_unknown_not_absence(monkeypatch):
    """PRR-001: the probe's own PROBE-ERROR leg (a silenced Get-VM failure
    would once have collapsed into GONE) must surface as rc!=0 from the
    script and therefore as 'unknown' in _vm_absent; the generated script
    must use -ErrorAction Stop + the PROBE-ERROR exit so a suppressed
    cmdlet failure can never print a bare GONE."""
    module = _load_host_module()

    class _FakePS:
        def __init__(self):
            self.scripts: list[str] = []

        def init(self, cfg, redact=None):
            return None

        def run_ps(self, script, *, timeout_s=None, stdin_b64=None):
            self.scripts.append(script)
            # the script's own contract: catch -> PROBE-ERROR -> exit 3
            return _PSResult(returncode=3, stdout="PROBE-ERROR\n", stderr="")

    fake = _FakePS()
    monkeypatch.setattr(module, "pswindows", fake)
    assert module._vm_absent(cfg=None, guid="g-x") == "unknown"
    # script-shape pin: the probe must NOT use SilentlyContinue anymore and
    # must carry the Stop/catch/exit-3 fail-closed shape
    joined = "\n".join(fake.scripts)
    assert "-ErrorAction Stop" in joined, joined
    assert "PROBE-ERROR" in joined and "exit 3" in joined, joined
    assert "SilentlyContinue" not in joined, (
        "the absence probe must never suppress Get-VM errors (PRR-001)")


def test_vm_absent_still_gone_on_successful_absent_query(monkeypatch):
    """The happy path is preserved: a SUCCESSFUL probe (rc==0) reporting
    GONE is absence."""
    module = _load_host_module()

    class _FakePS:
        def run_ps(self, script, *, timeout_s=None, stdin_b64=None):
            return _PSResult(returncode=0, stdout="GONE\n", stderr="")

    monkeypatch.setattr(module, "pswindows", _FakePS())
    assert module._vm_absent(cfg=None, guid="g-x") == "gone"


class _Nop:
    def force_clean(self):
        return None


class _FakeLife:
    def stop_vm(self, cfg, vm_name="", method="", confirm=False, vm_id=""):
        return {"status": "stopped"}

    def wait_for_vm_state(self, cfg, vm_name="", states=None, timeout_s=300, vm_id=""):
        return "Off"


def _wire_cleanup(module, monkeypatch, kept=(), child_exists=False, child_path="/nonexistent/child.vhdx"):
    class _FakePS:
        def run_ps(self, script, *, timeout_s=None, stdin_b64=None):
            return _PSResult(returncode=0, stdout="GONE\n", stderr="")

    class _FakeMedia:
        def __init__(self):
            self.kept = list(kept)

        def vm_remove(self, cfg, vm_name="", vm_id="", delete_disks=False, confirm=False):
            return {"ok": True, "status": "removed", "kept": self.kept}

    monkeypatch.setattr(module, "pswindows", _FakePS())
    monkeypatch.setattr(module, "lifecycle", _FakeLife())
    media_f = _FakeMedia()
    monkeypatch.setattr(module, "media", media_f)
    return media_f, child_exists, child_path


def test_benign_kept_rows_are_inventory_not_failures(monkeypatch):
    module = _load_host_module()
    _wire_cleanup(
        module, monkeypatch,
        kept=[{"path": "golden.vhdx", "reason": "not_owned_ancestor"},
              {"path": "child.avhdx", "reason": "already_gone"}])
    tracked = [["g-1", "host-iso-a-x", "/nonexistent/child.vhdx"]]
    report, benign = [], []
    module._cleanup_tracked(cfg=None, provider=_Nop(), tracked=tracked,
                            report=report, benign=benign)
    assert not report, f"benign kept rows must never fail cleanup: {report}"
    assert len(benign) == 2, benign
    assert not tracked, "verified-gone entries leave tracking"


def test_failure_kept_rows_are_reported(monkeypatch):
    module = _load_host_module()
    _wire_cleanup(module, monkeypatch,
                  kept=[{"path": "child.avhdx", "reason": "delete_failed"}])
    tracked = [["g-1", "host-iso-a-x", "/nonexistent/child.vhdx"]]
    report, benign = [], []
    module._cleanup_tracked(cfg=None, provider=_Nop(), tracked=tracked,
                            report=report, benign=benign)
    assert any("kept (failure)" in r and "delete_failed" in r for r in report), report
    assert not benign, benign


def test_residual_child_disk_is_reported_and_entry_retained(tmp_path, monkeypatch):
    """PRR-012: the residual branch runs against a REAL existing child file:
    the failure is reported and the tracked entry is retained."""
    module = _load_host_module()
    real_child = tmp_path / "residual.vhdx"
    real_child.write_bytes(b"residual")
    _wire_cleanup(module, monkeypatch, child_path=str(real_child))
    tracked = [["g-1", "host-iso-a-x", str(real_child)]]
    report, benign = [], []
    module._cleanup_tracked(cfg=None, provider=_Nop(), tracked=tracked,
                            report=report, benign=benign)
    assert any("residual child disk" in r for r in report), report
    assert tracked, "a residual child disk retains the tracked entry"


def test_already_gone_vm_is_benign_not_failure(tmp_path, monkeypatch):
    """PRR-009: stop/remove failing because the VM is ALREADY gone (the
    absence probe then says gone) is benign inventory on the VM axis,
    symmetric with the disk axis's already_gone."""
    module = _load_host_module()

    class _FakePS:
        def run_ps(self, script, *, timeout_s=None, stdin_b64=None):
            return _PSResult(returncode=0, stdout="GONE\n", stderr="")

    class _FailingLife:
        def stop_vm(self, cfg, vm_name="", method="", confirm=False, vm_id=""):
            raise RuntimeError("Get-VM failed: cannot resolve")

    class _FailingMedia:
        def vm_remove(self, cfg, vm_name="", vm_id="", delete_disks=False, confirm=False):
            raise RuntimeError("Get-VM failed: cannot resolve")

    monkeypatch.setattr(module, "pswindows", _FakePS())
    monkeypatch.setattr(module, "lifecycle", _FailingLife())
    monkeypatch.setattr(module, "media", _FailingMedia())

    tracked = [["g-1", "host-iso-a-x", "/nonexistent/child.vhdx"]]
    report, benign = [], []
    module._cleanup_tracked(cfg=None, provider=_Nop(), tracked=tracked,
                            report=report, benign=benign)
    assert any("already gone (VM)" in b for b in benign), benign
    assert not report, f"an already-gone VM must not be a cleanup failure: {report}"
    assert not tracked, "verified-gone entries leave tracking"


def test_cleanup_reports_emit_to_record_and_stderr(tmp_path, capsys, monkeypatch):
    module = _load_host_module()
    record = tmp_path / "record.txt"
    record_path = str(record)

    class _Host:
        record = record_path

        def note(self, line, kind="assert"):
            with open(self.record, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(f"{kind}: {line}\n")

    module._emit_cleanup_reports(_Host(), ["r1"], ["b1"])
    out = record.read_text(encoding="utf-8")
    assert "report: cleanup incomplete" in out and "r1" in out
    assert "report: cleanup benign inventory" in out and "b1" in out
    err = capsys.readouterr().err
    assert "r1" in err and "b1" in err


def test_note_failure_does_not_mask_primary_exception(tmp_path, capsys):
    """PRR-008: a failing record write inside the finally degrades to a
    stderr note and never replaces the in-flight primary exception."""
    conftest_path = _REPO / "tests" / "host" / "conftest.py"
    spec = importlib.util.spec_from_file_location("host_conftest_under_test_p8", conftest_path)
    assert spec is not None and spec.loader is not None
    host_conftest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host_conftest)

    with pytest.raises(ValueError, match="primary survived"):
        try:
            raise ValueError("primary survived")
        finally:
            host_conftest._note(str(tmp_path / "missing-dir" / "record.txt"),
                                "cleanup incomplete: x", kind="report")
    assert "result-record write failed" in capsys.readouterr().err


def test_report_emission_and_guard_live_in_the_right_places():
    """PRR-011: AST pin (block membership, robust to formatting/refactor).
    The _emit_cleanup_reports and _cleanup_tracked calls must sit INSIDE
    the finally suite of the live test, the finally must contain no
    pytest.fail call, and the post-finally pytest.fail('cleanup
    incomplete') guard must sit at module level AFTER the try/finally."""
    module = _load_host_module()
    source = inspect.getsource(module.test_owner_clone_lifecycle_with_seam)
    tree = ast.parse(source)
    func = tree.body[0]
    assert isinstance(func, ast.FunctionDef)
    try_block = next((n for n in func.body if isinstance(n, ast.Try) and n.finalbody), None)
    assert try_block is not None, "the live test must own a try/finally"

    def contains_call(node, name):
        return any(
            isinstance(sub, ast.Call)
            and (
                (isinstance(sub.func, ast.Attribute) and sub.func.attr == name)
                or (isinstance(sub.func, ast.Name) and sub.func.id == name)
            )
            for sub in ast.walk(node)
        )

    assert any(contains_call(stmt, "_emit_cleanup_reports") for stmt in try_block.finalbody), (
        "the cleanup-report emission must be called INSIDE the finally suite")
    assert any(contains_call(stmt, "_cleanup_tracked") for stmt in try_block.finalbody), (
        "the tracked cleanup must be driven INSIDE the finally suite")
    for stmt in try_block.finalbody:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call):
                fn = sub.func
                name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
                assert name != "fail", (
                    "pytest.fail must never be raised inside the finally "
                    "(it would mask the primary exception)")
    guard_outside = [
        node for node in func.body
        if isinstance(node, ast.If) and node is not try_block
        and "cleanup incomplete" in ast.dump(node)
    ]
    assert guard_outside, (
        "the pytest.fail('cleanup incomplete') guard must sit at module level "
        "AFTER the try/finally (only reached when body and finally completed)")
