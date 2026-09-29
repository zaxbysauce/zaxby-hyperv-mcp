"""Repair tests with mocked PowerShell: dry-run default, confirm gate,
apply+verify loop, backup recording, sibling isolation."""

import json

import pytest

from hyperv_mcp import pswindows, repair
from hyperv_mcp.config import Config, DestructivePolicy
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")


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


def _host():
    return {"state": "Running", "vm_id": "e953c649-1", "uptime_s": 1, "memory_mb": 1, "cpu_usage": 1}


def _guest(status="Running", listen="0.0.0.0", fw=True):
    return {
        "identity": {"hostname": "W"},
        "ip_addresses": {"ipv4": [{"interface": "E", "address": "10.0.0.5", "prefix": 24}], "ipv6": []},
        "ssh": {
            "service": {"present": True, "status": status, "start_type": "Automatic"},
            "agent_service": {"present": False},
            "config_present": True, "effective_ports": [22],
            "config_listen": [listen],
            "listeners": [{"address": listen, "port": 22}],
        },
        "winrm": {"service": {"present": True, "status": "Running", "start_type": "Automatic"},
                  "listeners": [], "tcp_listeners": []},
        "firewall": {"ssh22_allowed": fw, "winrm5985_allowed": True},
    }


def test_dry_run_is_default_and_mutates_nothing(monkeypatch):
    cfg = Config(unrestricted=True)
    guest = _guest(listen="192.168.50.20")
    guest["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    fake = FakePS([_ok(_host()), _ok(guest)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", cred=CRED)
    assert out["applied"] is False
    ids = [p["finding"] for p in out["plan"]]
    assert "ssh_stale_binding" in ids
    assert out["changes"] == []
    # Only the two diagnose legs ran — no mutation script.
    assert len(fake.scripts) == 2
    assert "Restart-Service" not in fake.scripts[1]


def test_apply_without_confirm_denied_before_mutation(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied, match="confirm"):
        repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=False, cred=CRED)
    assert fake.scripts == []


def test_apply_denied_when_category_disabled(monkeypatch):
    cfg = Config(allowed_vm_patterns=["test-*"], destructive=DestructivePolicy(guest_repair=False))
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied, match="guest_repair"):
        repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True, cred=CRED)
    assert fake.scripts == []


def test_apply_executes_and_verifies_each_action(monkeypatch):
    cfg = Config(unrestricted=True)
    broken = _guest(status="Stopped", listen="192.168.50.20", fw=False)
    broken["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    healthy = _guest(status="Running", listen="0.0.0.0", fw=True)
    fake = FakePS([
        _ok(_host()), _ok(broken),                 # diagnose 1
        _ok({"service": "sshd", "status": "Running"}),  # apply start sshd
        _ok({"backup": "C:/ProgramData/ssh/sshd_config.bak-20260929", "replaced": 1}),  # apply stale
        _ok({"port": "22", "enabled_rules": ["OpenSSH-Server-In-TCP"]}),  # apply firewall
        _ok(_host()), _ok(healthy),                # diagnose 2 (verify)
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True, cred=CRED)
    assert out["applied"] is True
    actions = [c["action"] for c in out["changes"]]
    assert sorted(actions) == [
        "enable_existing_firewall_rules", "rewrite_stale_ssh_bindings", "start_service",
    ]
    for change in out["changes"]:
        assert change["applied"] is True
        assert change["verified"] is True
        assert change["verify_detail"].endswith("cleared")
    assert out["backup_path"].endswith(".bak-20260929")
    # One apply script per item, then a full re-diagnose (2 legs).
    assert len(fake.scripts) == 7

    def inner(script):
        import base64
        import re as _re

        m = _re.search(r"\$enc = '([A-Za-z0-9+/=]+)'", script)
        assert m
        return base64.b64decode(m.group(1)).decode("utf-8")

    assert "Start-Service -Name 'sshd'" in inner(fake.scripts[2])
    assert "Copy-Item" in inner(fake.scripts[3])
    assert "Set-NetFirewallRule" in inner(fake.scripts[4])


def test_apply_sibling_continues_after_item_error(monkeypatch):
    cfg = Config(unrestricted=True)
    broken = _guest(status="Stopped", listen="192.168.50.20")
    broken["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    healthy = _guest(status="Running", listen="0.0.0.0")
    fake = FakePS([
        _ok(_host()), _ok(broken),
        pswindows.PSResult(stdout="", returncode=1, stderr="rewrite failed"),  # stale apply fails
        _ok({"service": "sshd", "status": "Running"}),  # start-service sibling succeeds
        _ok(_host()), _ok(healthy),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True, cred=CRED)
    assert len(out["changes"]) == 2
    assert out["changes"][0]["applied"] is False
    assert "rewrite failed" in out["changes"][0]["error"]
    assert out["changes"][1]["applied"] is True


def test_healthy_vm_empty_plan(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_ok(_host()), _ok(_guest())])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", cred=CRED)
    assert out["plan"] == []
    assert out["changes"] == []


def test_apply_nothing_to_do_when_clean(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_ok(_host()), _ok(_guest())])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True, cred=CRED)
    assert out["changes"] == []
    assert len(fake.scripts) == 2


def test_plan_items_do_not_leak_apply_scripts(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_ok(_host()), _ok(_guest(status="Stopped"))])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", cred=CRED)
    for item in out["plan"]:
        assert "apply_script" not in item
