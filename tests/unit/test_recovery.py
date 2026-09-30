"""Recovery tests (wait_guest_recovery): bounded PS-Direct wait loop,
per-item service/process verification, failure reporting."""

import json

import pytest

from hyperv_mcp import diagnostics, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")


class FakePS:
    """Records scripts, returns canned results."""

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


# -- recovery (wait_guest_recovery) ----------------------------------------


def test_recovery_wait_loop_and_verification(monkeypatch):
    cfg = Config(unrestricted=True)
    payload = {
        "ps_direct": {"available": True, "attempts": 2, "error": ""},
        "services": [{"name": "sshd", "present": True, "status": "Running", "ok": True}],
        "processes": [{"name": "cdpclient", "present": False, "ok": False}],
    }
    fake = FakePS([_ok(payload)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = diagnostics.wait_guest_recovery(
        cfg, "test-vm", services=["sshd"], processes=["cdpclient"],
        timeout_s=30, interval_s=2, cred=CRED,
    )
    assert out["ok"] is False
    assert out["failures"] == ["process:cdpclient"]
    assert out["ps_direct"]["attempts"] == 2
    script = fake.scripts[0]
    assert "AddSeconds(30)" in script
    assert "Start-Sleep" in script
    assert "Invoke-Command -VMName" in script


def test_recovery_ps_direct_never_available(monkeypatch):
    cfg = Config(unrestricted=True)
    payload = {"ps_direct": {"available": False, "attempts": 10, "error": "no"}}
    fake = FakePS([_ok(payload)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = diagnostics.wait_guest_recovery(cfg, "test-vm", timeout_s=5, interval_s=1, cred=CRED)
    assert out["ok"] is False
    assert out["failures"] == ["ps_direct"]
    assert out["services"] == []


def test_recovery_wait_only_mode(monkeypatch):
    cfg = Config(unrestricted=True)
    payload = {"ps_direct": {"available": True, "attempts": 1, "error": ""}}
    fake = FakePS([_ok(payload)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = diagnostics.wait_guest_recovery(cfg, "test-vm", timeout_s=5, interval_s=1, cred=CRED)
    assert out["ok"] is True
    assert out["failures"] == []


def test_recovery_single_service_object_is_normalized(monkeypatch):
    """ConvertFrom-Json collapses a one-element array to a single object."""
    cfg = Config(unrestricted=True)
    payload = {
        "ps_direct": {"available": True, "attempts": 1, "error": ""},
        "services": {"name": "sshd", "present": True, "status": "Running", "ok": True},
        "processes": {"name": "x", "present": True, "ok": True},
    }
    fake = FakePS([_ok(payload)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = diagnostics.wait_guest_recovery(
        cfg, "test-vm", services=["sshd"], processes=["x"], cred=CRED,
    )
    assert out["ok"] is True
    assert out["services"][0]["name"] == "sshd"
    assert out["processes"][0]["name"] == "x"


def test_recovery_policy_denied_before_ps(monkeypatch):
    cfg = Config()
    called = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", called)
    with pytest.raises(PolicyDenied):
        diagnostics.wait_guest_recovery(cfg, "test-vm", cred=CRED)
    assert called.scripts == []


def test_recovery_timeout_envelope(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([pswindows.PSResult(stdout="", returncode=None, timed_out=True)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = diagnostics.wait_guest_recovery(cfg, "test-vm", timeout_s=5, interval_s=1, cred=CRED)
    assert out["ok"] is False
    assert out["error_class"] == "timeout"


def test_recovery_service_failure_listed(monkeypatch):
    """PRR-C1: a service with ok:False must reach the failures list (the
    service-failure append was mutation-unpinned)."""
    cfg = Config(unrestricted=True)
    payload = {
        "ps_direct": {"available": True, "attempts": 1, "error": ""},
        "services": [{"name": "sshd", "present": True, "status": "Stopped", "ok": False}],
        "processes": [],
    }
    fake = FakePS([_ok(payload)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = diagnostics.wait_guest_recovery(cfg, "test-vm", services=["sshd"], cred=CRED)
    assert out["ok"] is False
    assert out["failures"] == ["service:sshd"]
