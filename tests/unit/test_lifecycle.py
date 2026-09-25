"""Lifecycle tests with mocked PowerShell: contract, gates, wildcard safety."""

import json

import pytest

from hyperv_mcp import lifecycle, pswindows
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


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


def test_list_vms_denied_without_patterns(monkeypatch):
    """Critic fix: inventory honors the VM policy (deny when unconfigured)."""
    cfg = Config()
    called = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", called)
    with pytest.raises(PolicyDenied, match="no allowed_vm_patterns"):
        lifecycle.list_vms(cfg)
    assert called.scripts == []


def test_list_vms_filtered_to_patterns(monkeypatch):
    cfg = Config(allowed_vm_patterns=["test-*"])
    payload = [
        {"name": "test-vm-1", "state": "Running", "status": "OK",
         "memory_mb": 1.0, "cpu_count": 1, "uptime_seconds": 0.0},
        {"name": "prod-db", "state": "Off", "status": "OK",
         "memory_mb": 1.0, "cpu_count": 1, "uptime_seconds": 0.0},
    ]
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    rows = lifecycle.list_vms(cfg)
    assert [r["name"] for r in rows] == ["test-vm-1"]


def test_list_vms_maps_snake_and_pascal(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout=json.dumps([
        {"name": "vm1", "state": "Running", "status": "OK",
         "memory_mb": 2048.0, "cpu_count": 2, "uptime_seconds": 12.0},
    ]), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    rows = lifecycle.list_vms(unrestricted)
    assert rows[0]["name"] == "vm1"
    assert rows[0]["Name"] == "vm1"
    assert rows[0]["cpu_count"] == 2 and rows[0]["CpuCount"] == 2


def test_stop_vm_shutdown_has_no_force_flag(monkeypatch, unrestricted):
    """F7 regression: graceful shutdown must not pass -Force."""
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps({"initial_state": "Running"}), returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Off"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.stop_vm(unrestricted, "test-vm-1", "shutdown", confirm=True)
    assert out["status"] == "stopped" and out["state"] == "Off"
    assert "-Force" not in fake.scripts[0]


def test_stop_vm_shutdown_force_uses_force(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps({"initial_state": "Running"}), returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Off"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.stop_vm(unrestricted, "test-vm-1", "shutdown-force", confirm=True)
    assert "-Force" in fake.scripts[0]


def test_stop_vm_methods_validated(unrestricted):
    with pytest.raises(ValueError, match="method"):
        lifecycle.stop_vm(unrestricted, "vm", "yolo")


def test_stop_vm_waits_for_saved_state(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps({"initial_state": "Running"}), returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Saved"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.stop_vm(unrestricted, "vm1", "save", confirm=True)
    assert out["state"] == "Saved"


def test_stop_vm_requires_policy_and_confirm():
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="destructive:stop"):
        lifecycle.stop_vm(cfg, "test-vm", "shutdown", confirm=True)
    cfg.destructive.stop = True
    with pytest.raises(PolicyDenied, match="confirm=true"):
        lifecycle.stop_vm(cfg, "test-vm", "shutdown", confirm=False)


def test_vm_policy_denied_before_ps(monkeypatch):
    cfg = Config(allowed_vm_patterns=["test-*"])
    called = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", called)
    with pytest.raises(PolicyDenied):
        lifecycle.start_vm(cfg, "prod-db")
    assert called.scripts == []  # never reached PowerShell


def test_start_vm_wildcard_escaped_in_script(monkeypatch, unrestricted):
    """F2 regression: wildcard chars must arrive backtick-escaped."""
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps({"initial_state": "Off"}), returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Running"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.start_vm(unrestricted, "weird*[1]")
    assert "'weird`*`[1`]'" in fake.scripts[0]


def test_start_vm_already_running_idempotent(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps({"initial_state": "Running"}), returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Running"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.start_vm(unrestricted, "vm1")
    assert out["status"] == "already_running"
    # Start-VM only runs inside the state guard, never for an already-running VM
    assert "if ($initial -ne 'Running') { Start-VM -VM $vm" in fake.scripts[0]


def test_state_wait_timeout_error(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps({"initial_state": "Running"}), returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Stopping"}), returncode=3),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(RuntimeError, match="did not reach Off"):
        lifecycle.stop_vm(unrestricted, "vm1", "turnoff", confirm=True)


def test_checkpoint_name_autogenerated(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.checkpoint_create(unrestricted, "vm1")
    assert out["checkpoint_name"].startswith("MCP-")
    assert "MCP-" in fake.scripts[0]


def test_checkpoint_restore_gated_and_reports_state(monkeypatch):
    cfg = Config(allowed_vm_patterns=["test-*"], unrestricted=False)
    cfg.destructive.checkpoint_restore = True
    fake = FakePS([
        pswindows.PSResult(stdout="", returncode=0),
        pswindows.PSResult(stdout=json.dumps({"final_state": "Off"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied, match="confirm"):
        lifecycle.checkpoint_restore(cfg, "test-vm", "pre-kd", confirm=False)
    out = lifecycle.checkpoint_restore(cfg, "test-vm", "pre-kd", confirm=True)
    assert out["state"] == "Off"
    assert "note" in out


def test_checkpoint_remove_subtree_flag(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.checkpoint_remove(unrestricted, "vm1", "snap", include_subtree=True, confirm=True)
    assert "-IncludeAllChildSnapshots" in fake.scripts[0]
    assert "-Confirm:$false" in fake.scripts[0]


def test_checkpoint_remove_unrestricted_still_needs_confirm(monkeypatch):
    """Critic fix: unrestricted mode does not waive the confirm parameter."""
    cfg = Config(unrestricted=True)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    with pytest.raises(PolicyDenied, match="confirm=true"):
        lifecycle.checkpoint_remove(cfg, "vm1", "snap", include_subtree=True, confirm=False)


def test_kdnet_host_ip_validation(unrestricted):
    for bad in ("not-an-ip", "999.1.1.1", "192.168.1.1; calc.exe", ""):
        with pytest.raises(ValueError):
            lifecycle.configure_kdnet(
                unrestricted, "vm", bad, 50000, "", False, True, cred=CRED
            )


def test_kdnet_key_validation(unrestricted):
    with pytest.raises(ValueError, match="key"):
        lifecycle.configure_kdnet(
            unrestricted, "vm", "192.0.2.1", 50000, "bad key; calc", False, True, cred=CRED
        )
    with pytest.raises(ValueError, match="key"):
        lifecycle.configure_kdnet(
            unrestricted, "vm", "192.0.2.1", 50000, "ZZZZZ.YYYYY", False, True, cred=CRED
        )


def test_kdnet_gated_by_policy(monkeypatch):
    cfg = Config(allowed_vm_patterns=["test-*"])
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    with pytest.raises(PolicyDenied, match="destructive:kd_reboot"):
        lifecycle.configure_kdnet(
            cfg, "test-vm", "192.0.2.1", 50000, "", False, True, cred=CRED
        )


def test_kdnet_bcdedit_uses_direct_arg_form(monkeypatch, unrestricted):
    """F11 regression: native bcdedit must use separately-quoted arguments.

    PS 5.1 native binding CONCATENATES inline arrays (@('a','b') arrives as
    one 'a b' argument — verified empirically), so the direct form is required.
    """
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps({"DbgSettings": "ok"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.configure_kdnet(
        unrestricted, "vm1", "192.0.2.1", 50000, "a1b2c.d3e4f.5a6b7.c8d9e",
        reboot=False, confirm=True, cred=CRED,
    )
    assert "& 'bcdedit.exe' '/dbgsettings' 'net'" in fake.scripts[0]
    assert "@('/dbgsettings'" not in fake.scripts[0]


def test_kdnet_generated_key_returned(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps({"DbgSettings": "ok"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.configure_kdnet(
        unrestricted, "vm1", "192.0.2.1", 50000, "", reboot=False, confirm=True, cred=CRED
    )
    assert out["key"].count(".") == 3
    assert out["kernel_attach_string"] == f"net:port=50000,key={out['key']}"


def test_kdcom_pipe_name_validated(unrestricted):
    with pytest.raises(ValueError, match="pipe_name"):
        lifecycle.configure_kdcom(
            unrestricted, "vm", "\\\\.\\pipe\\bad name;calc", 1, False, True, cred=CRED
        )


def test_kdcom_requires_off_state_note_and_gates(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout="", returncode=0),   # Set-VMComPort
        pswindows.PSResult(stdout=json.dumps({"DbgSettings": "ok"}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.configure_kdcom(
        unrestricted, "vm1", "\\\\.\\pipe\\kd_vm1", 1, reboot=False, confirm=True, cred=CRED
    )
    assert out["kernel_attach_string"].startswith("com:pipe,port=")
    assert "Set-VMComPort" in fake.scripts[0]


def test_label_validation():
    unrestricted = Config(unrestricted=True)
    with pytest.raises(ValueError):
        lifecycle.checkpoint_create(unrestricted, "vm", "bad`name")
    with pytest.raises(ValueError):
        lifecycle.checkpoint_create(unrestricted, "vm", "x" * 300)
