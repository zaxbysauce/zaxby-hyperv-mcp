"""No-host contract tests for the AC16 host-test helpers
(tests/host/test_vm_agent_isolation_host.py — plan-critic r5/r6).

These pin, WITHOUT any Hyper-V host access:
  1. vmident.resolve raises PowerShellTransportError (NOT media.MediaError)
     for a missing VM — the wrong-exception assumption that guaranteed a
     post-removal failure is dead forever;
  2. the fail-closed absence probe: a transport failure means UNKNOWN,
     which retains the tracked entry and reports 'absence unknown';
  3. cleanup reports are emitted inside the finally (structural pin) and
     the emission helper writes both the record and stderr;
  4. benign kept rows (not_owned_ancestor / already_gone) are inventory,
     never cleanup failures;
  5. failure kept rows (delete_failed) are reported as cleanup failures.

The host-test module is loaded by file path under a unique name so the
unit suite never registers its fixtures; no env gate is touched.
"""

from __future__ import annotations

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

    def fake_run_ps(script, timeout_s=None, stdin_b64=None):
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

        def run_ps(self, script, timeout_s=None, stdin_b64=None):
            self.calls.append(script)
            return _PSResult(returncode=1, stdout="", stderr="transport down")

    fake = _FakePS()
    monkeypatch.setattr(module, "pswindows", fake)

    class _FakeLife:
        def stop_vm(self, cfg, vm_name="", method="", confirm=False, vm_id=""):
            return {"status": "stopped"}

        def wait_for_vm_state(self, cfg, name, states, timeout_s=300):
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
        def run_ps(self, script, timeout_s=None, stdin_b64=None):
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

        def wait_for_vm_state(self, cfg, name, states, timeout_s=300):
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

        def note(self, line):
            with open(self.record, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(f"assert: {line}\n")

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
    assert "cleanup incomplete" in out and "absence unknown" in out
    assert "r" in capsys.readouterr().err


class _Nop:
    def force_clean(self):
        return None


def _wire_happy_cleanup(module, monkeypatch, kept=()):
    class _FakePS:
        def run_ps(self, script, timeout_s=None, stdin_b64=None):
            return _PSResult(returncode=0, stdout="GONE\n", stderr="")

    class _FakeLife:
        def stop_vm(self, cfg, vm_name="", method="", confirm=False, vm_id=""):
            return {"status": "stopped"}

        def wait_for_vm_state(self, cfg, name, states, timeout_s=300):
            return "Off"

    class _FakeMedia:
        def __init__(self):
            self.kept = list(kept)

        def vm_remove(self, cfg, vm_name="", vm_id="", delete_disks=False, confirm=False):
            return {"ok": True, "status": "removed", "kept": self.kept}

    monkeypatch.setattr(module, "pswindows", _FakePS())
    monkeypatch.setattr(module, "lifecycle", _FakeLife())
    media_f = _FakeMedia()
    monkeypatch.setattr(module, "media", media_f)
    return media_f


def test_benign_kept_rows_are_inventory_not_failures(monkeypatch):
    module = _load_host_module()
    _wire_happy_cleanup(
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
    _wire_happy_cleanup(module, monkeypatch,
                        kept=[{"path": "child.avhdx", "reason": "delete_failed"}])
    tracked = [["g-1", "host-iso-a-x", "/nonexistent/child.vhdx"]]
    report, benign = [], []
    module._cleanup_tracked(cfg=None, provider=_Nop(), tracked=tracked,
                            report=report, benign=benign)
    assert any("kept (failure)" in r and "delete_failed" in r for r in report), report
    assert not benign, benign


def test_cleanup_reports_emit_to_record_and_stderr(tmp_path, capsys, monkeypatch):
    module = _load_host_module()
    record = tmp_path / "record.txt"
    record_path = str(record)

    class _Host:
        record = record_path

        def note(self, line):
            with open(self.record, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(f"assert: {line}\n")

    module._emit_cleanup_reports(_Host(), ["r1"], ["b1"])
    out = record.read_text(encoding="utf-8")
    assert "cleanup incomplete" in out and "r1" in out
    assert "cleanup benign inventory" in out and "b1" in out
    err = capsys.readouterr().err
    assert "r1" in err and "b1" in err


def test_report_emission_and_guard_live_in_the_right_places():
    """Structural pin (r6): report emission happens INSIDE the finally
    (before any post-finally guard), and the post-finally pytest.fail is
    reached only after body and finally both completed."""
    module = _load_host_module()
    source = inspect.getsource(module.test_owner_clone_lifecycle_with_seam)
    finally_idx = source.index("    finally:")
    emit_idx = source.index("_emit_cleanup_reports(host, report, benign)", finally_idx)
    guard_idx = source.index("pytest.fail(f\"cleanup incomplete", finally_idx)
    assert emit_idx < guard_idx, (
        "emission must be ordered before the guard inside/after the finally")
    assert "cleanup incomplete (leaks are never silent)" in source
