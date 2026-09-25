"""Ops tests: per-VM locking and secret-safe audit logging."""

import json

import pytest

from hyperv_mcp import auditlog, credentials
from hyperv_mcp.config import Config
from hyperv_mcp.vmlocks import VMBusy, vm_lock


def test_vm_lock_excludes_same_vm():
    with vm_lock("vm-a"):
        with pytest.raises(VMBusy, match="already running"):
            with vm_lock("vm-a"):
                pass


def test_vm_lock_case_insensitive():
    with vm_lock("Test-VM-1"):
        with pytest.raises(VMBusy):
            with vm_lock("test-vm-1"):
                pass


def test_vm_lock_different_vms_independent():
    with vm_lock("vm-a"):
        with vm_lock("vm-b"):
            pass


def test_vm_lock_released_after_error():
    with pytest.raises(RuntimeError):
        with vm_lock("vm-x"):
            raise RuntimeError("boom")
    with vm_lock("vm-x"):
        pass


def test_audit_writes_jsonl_file(tmp_path):
    log = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(log))
    auditlog.init(cfg)
    with auditlog.operation(tool="hyperv_stop_vm", vm_name="test-vm-1", category="destructive"):
        pass
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["tool"] == "hyperv_stop_vm"
    assert rows[-1]["vm_name"] == "test-vm-1"
    assert rows[-1]["ok"] is True
    assert "duration_ms" in rows[-1]


def test_audit_records_failures(tmp_path):
    log = tmp_path / "audit.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    with pytest.raises(ValueError):
        with auditlog.operation(tool="t", vm_name="v", category="c"):
            raise ValueError("bad input")
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["ok"] is False
    assert rows[-1]["error_class"] == "ValueError"


def test_audit_redacts_secrets(tmp_path):
    """Audit lines must never carry credential values."""
    log = tmp_path / "audit.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    secret = "super-secret-pw-value"
    credentials.registry().register(secret)
    auditlog.log_operation(
        tool="hyperv_guest_run_ps", vm_name="vm", category="exec",
        ok=False, error_class=f"leak attempt {secret}",
    )
    content = log.read_text(encoding="utf-8")
    assert secret not in content
    assert "***REDACTED***" in content


def test_audit_unrestricted_forces_stderr_line(capsys):
    auditlog.init(Config(unrestricted=True, audit_log_path=None))
    auditlog.log_operation(tool="t", vm_name="v", category="c", ok=True)
    err = capsys.readouterr().err
    assert "[hyperv-mcp audit]" in err


def test_audit_operation_carries_exit_code(tmp_path):
    """Critic fix: guest tools attach exit_code to the audit record."""
    log = tmp_path / "audit-exit.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    with auditlog.operation(tool="hyperv_guest_run_ps", vm_name="v", category="exec") as op:
        op.exit_code = 42
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["exit_code"] == 42
