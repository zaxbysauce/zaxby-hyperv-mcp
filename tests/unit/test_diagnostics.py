"""Diagnostics tests with mocked PowerShell: report shape, section isolation,
stale-binding findings, policy ordering, recovery wait semantics."""

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


def _host_payload():
    return {
        "state": "Running", "vm_id": "e953c649-1234-5678-9abc-def012345678",
        "uptime_s": 600, "memory_mb": 2048, "cpu_usage": 5,
    }


def _guest_payload():
    return {
        "identity": {
            "hostname": "WINVM", "domain": "WORKGROUP", "os": "Windows 10 Pro",
            "version": "10.0.19045", "build": "19045", "last_boot": "2026-09-29",
        },
        "ip_addresses": {"ipv4": [{"interface": "Ethernet", "address": "10.0.0.5", "prefix": 24}], "ipv6": []},
        "ssh": {
            "service": {"present": True, "status": "Running", "start_type": "Automatic"},
            "agent_service": {"present": True, "status": "Stopped"},
            "config_present": True,
            "effective_ports": [22],
            "config_listen": ["0.0.0.0"],
            "listeners": [{"address": "0.0.0.0", "port": 22}],
        },
        "winrm": {
            "service": {"present": True, "status": "Running", "start_type": "Automatic"},
            "listeners": [{"transport": "HTTP", "port": 5985, "address": "*"}],
            "tcp_listeners": [{"address": "0.0.0.0", "port": 5985}],
        },
        "firewall": {"ssh22_allowed": True, "winrm5985_allowed": True},
    }


def _ok_result(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


VM_GUID = "e953c649-1234-5678-9abc-def012345678"


def _guid_result():
    """Canned by-name resolution leg response (stdout = the VM GUID)."""
    return pswindows.PSResult(stdout=VM_GUID, returncode=0)


def test_diagnose_denied_without_patterns(monkeypatch):
    cfg = Config()
    called = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", called)
    with pytest.raises(PolicyDenied, match="no allowed_vm_patterns"):
        diagnostics.diagnose_vm_access(cfg, "test-vm", cred=CRED)
    assert called.scripts == []


def test_diagnose_requires_credentials():
    cfg = Config(unrestricted=True)
    with pytest.raises(ValueError, match="guest credentials are required"):
        diagnostics.diagnose_vm_access(cfg, "test-vm", cred=None)


def test_diagnose_report_shape(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_guid_result(), _ok_result(_host_payload()), _ok_result(_guest_payload())])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    report = diagnostics.diagnose_vm_access(cfg, "test-vm", cred=CRED)
    assert report["ok"] is True
    assert report["vm"]["state"] == "Running"
    assert report["ps_direct"] == {"available": True}
    guest = report["guest"]
    assert guest["identity"]["hostname"] == "WINVM"
    assert guest["ip_addresses"]["ipv4"][0]["address"] == "10.0.0.5"
    assert guest["ssh"]["service"]["status"] == "Running"
    assert guest["winrm"]["listeners"][0]["port"] == 5985
    assert isinstance(report["checked_at"], str) and report["checked_at"]
    # Three legs: by-name resolution (standalone), host Get-VM, one guest
    # PS Direct probe.
    assert len(fake.scripts) == 3
    assert fake.scripts[0].rstrip().endswith("$vmTarget")
    assert "Get-VM" in fake.scripts[1]
    assert "Invoke-Command -VMId $vmTarget" in fake.scripts[2]
    # The action scripts open with the validated GUID preamble (issue #8):
    # binding by -VMId is deterministic, no vmms name flakiness, and the lock
    # keys on the same resolved GUID.
    assert f"$vmTarget = '{VM_GUID}'" in fake.scripts[1]
    assert f"$vmTarget = '{VM_GUID}'" in fake.scripts[2]
    assert "Msvm_ComputerSystem" not in fake.scripts[1]
    assert "Msvm_ComputerSystem" not in fake.scripts[2]
    assert fake.scripts[2].index("$vmTarget = ") < fake.scripts[2].index("Invoke-Command -VMId")


def test_diagnose_section_isolation_one_failing_probe(monkeypatch):
    """A failing probe section must not abort the rest of the report."""
    cfg = Config(unrestricted=True)
    guest = _guest_payload()
    guest["ssh"] = {"error": "probe failed: service subsystem unavailable"}
    guest["ip_addresses"] = {"error": "probe failed: nettc backlog"}
    fake = FakePS([_guid_result(), _ok_result(_host_payload()), _ok_result(guest)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    report = diagnostics.diagnose_vm_access(cfg, "test-vm", cred=CRED)
    assert report["ok"] is True
    assert report["guest"]["ssh"]["error"].startswith("probe failed")
    assert report["guest"]["identity"]["hostname"] == "WINVM"
    assert report["guest"]["winrm"]["listeners"]


def test_diagnose_stale_binding_finding(monkeypatch):
    """The reporter's incident: SSH listening on an address that is no longer
    a guest IP."""
    cfg = Config(unrestricted=True)
    guest = _guest_payload()
    guest["ssh"]["config_listen"] = ["192.168.50.20"]
    guest["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    fake = FakePS([_guid_result(), _ok_result(_host_payload()), _ok_result(guest)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    report = diagnostics.diagnose_vm_access(cfg, "test-vm", cred=CRED)
    stale = [f for f in report["findings"] if f["id"] == "ssh_stale_binding"]
    assert stale, "stale binding must produce a finding"
    assert stale[0]["severity"] == "high"
    assert "192.168.50.20" in stale[0]["detail"]
    assert "10.0.0.5" in stale[0]["detail"]


def test_diagnose_no_stale_finding_for_wildcard_or_current_ip(monkeypatch):
    cfg = Config(unrestricted=True)
    guest = _guest_payload()
    guest["ssh"]["config_listen"] = ["0.0.0.0", "10.0.0.5"]
    guest["ssh"]["listeners"] = [
        {"address": "0.0.0.0", "port": 22},
        {"address": "10.0.0.5", "port": 22},
    ]
    fake = FakePS([_guid_result(), _ok_result(_host_payload()), _ok_result(guest)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    report = diagnostics.diagnose_vm_access(cfg, "test-vm", cred=CRED)
    assert not [f for f in report["findings"] if f["id"] == "ssh_stale_binding"]


def test_diagnose_ps_direct_unavailable_is_a_result(monkeypatch):
    """Transport failure surfaces as ps_direct.available=False plus a
    finding, not an exception."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_result(),
        _ok_result(_host_payload()),
        pswindows.PSResult(stdout="", returncode=1, stderr="connection failed"),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    report = diagnostics.diagnose_vm_access(cfg, "test-vm", cred=CRED)
    assert report["ok"] is True
    assert report["guest"] is None
    assert report["ps_direct"]["available"] is False
    assert report["ps_direct"]["error_class"] == "transport"
    assert any(f["id"] == "ps_direct_unavailable" for f in report["findings"])


def test_diagnose_stopped_services_findings(monkeypatch):
    cfg = Config(unrestricted=True)
    guest = _guest_payload()
    guest["ssh"]["service"]["status"] = "Stopped"
    guest["winrm"]["service"]["status"] = "Stopped"
    guest["firewall"]["ssh22_allowed"] = False
    fake = FakePS([_guid_result(), _ok_result(_host_payload()), _ok_result(guest)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    report = diagnostics.diagnose_vm_access(cfg, "test-vm", cred=CRED)
    ids = {f["id"] for f in report["findings"]}
    assert "ssh_service_stopped" in ids
    assert "winrm_service_stopped" in ids
    assert "ssh_firewall_no_allow" in ids


def test_diagnose_vm_name_wildcard_escaped(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_guid_result(), _ok_result(_host_payload()), _ok_result(_guest_payload())])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    diagnostics.diagnose_vm_access(cfg, "test[1]", cred=CRED)
    # CIM resolution matches the name LITERALLY (-eq), so wildcard chars are
    # inert by construction; the VM binds by resolved GUID (-Id) — the name
    # resolver lives only in the standalone first leg (vmident).
    assert "$_.ElementName -eq 'test[1]'" in fake.scripts[0]
    assert f"$vmTarget = '{VM_GUID}'" in fake.scripts[1]
    assert "Get-VM -Id $vmTarget" in fake.scripts[1]


def test_diagnose_guest_script_contains_probes(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_guid_result(), _ok_result(_host_payload()), _ok_result(_guest_payload())])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    diagnostics.diagnose_vm_access(cfg, "test-vm", cred=CRED)
    # The probe body rides the host script base64-encoded; decode it.
    import base64
    import re as _re

    m = _re.search(r"\$enc = '([A-Za-z0-9+/=]+)'", fake.scripts[2])
    assert m, "host script must embed the b64 probe payload"
    probe = base64.b64decode(m.group(1)).decode("utf-8")
    for marker in (
        "Get-CimInstance Win32_OperatingSystem",
        "Get-NetIPAddress",
        "Get-Service -Name sshd",
        "Get-NetTCPConnection",
        "sshd_config",
        "WinRM",
    ):
        assert marker in probe, f"probe script missing {marker}"
