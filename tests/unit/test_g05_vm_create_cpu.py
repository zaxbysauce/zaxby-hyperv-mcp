"""Frozen acceptance checks for issue #94 (vm_create drops cpu_count), legs
AC20 and AC21.

Arm's-length authoring (trace 31-32-33-94-workstream-g-deployment, tier L):
written from the POST-FIX API CONTRACT only; frozen — the implementation
phase makes them green.

Contract asserted here: media.vm_create gains, after the New-VM try/catch
and before the optional Connect-VMNetworkAdapter append, a
Set-VMProcessor -VM $vm -Count <cpu_count> leg (int-formatted like
memory_mb), so vm_create(cpu_count=8, confirm=True) with mocked PowerShell
emits a script containing "Set-VMProcessor" and the count 8. The
no-confirm-refusal behavior is preserved, and README.md's hyperv_vm_create
tool-table row comes to state that the requested cpu count is applied.
"""

from pathlib import Path

import pytest

from hyperv_mcp import media, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.policy import PolicyDenied


class FakePS:
    def __init__(self, responses=()):
        self.scripts = []
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        item = self.responses.pop(0) if self.responses else pswindows.PSResult(
            stdout='{"ok": true}', returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


# ---------------------------------------------------------------------------
# AC20 — the requested cpu_count reaches the created VM
# ---------------------------------------------------------------------------

def test_requested_cpu_count_reaches_created_vm(monkeypatch, unrestricted, tmp_path):
    """RED/ERROR at base (AssertionError: the emitted vm_create script has no
    Set-VMProcessor leg — the validated cpu_count argument is dropped),
    GREEN after the fix."""
    fake = FakePS([pswindows.PSResult(
        stdout='{"id": "GUID-1", "name": "test-vm-1", "state": "Off", "generation": 2}',
        returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_create(
        unrestricted, "test-vm-1", cpu_count=8,
        vhd_path=str(tmp_path / "d.vhdx"), switch_name="LabSwitch", confirm=True,
    )
    assert out["ok"] and out["id"] == "GUID-1"
    script = fake.scripts[0]
    assert "Set-VMProcessor" in script, (
        "the requested cpu_count must be applied to the new VM "
        "(Set-VMProcessor leg missing)"
    )
    assert "-Count 8" in script, "the applied count must be the requested 8"
    # ordering: after the New-VM try/catch (the VM object must exist), before
    # the optional switch connect
    assert script.index("New-VM -Name") < script.index("Set-VMProcessor")
    assert script.index("Set-VMProcessor") < script.index("Connect-VMNetworkAdapter")


def test_vm_create_no_confirm_never_runs_powershell(monkeypatch, tmp_path):
    """GREEN at base (preserving pin: existing vm_create behavior), and it
    must STAY green after the fix — the cpu_count leg changes nothing about
    the confirm-first gate."""
    cfg = Config(allowed_vm_patterns=["test-*"])
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied, match="confirm=true"):
        media.vm_create(
            cfg, "test-vm-1", cpu_count=8,
            vhd_path=str(tmp_path / "a.vhdx"), confirm=False,
        )
    assert fake.scripts == [], "a denied call must never spawn PowerShell"


# ---------------------------------------------------------------------------
# AC21 — the README documents the applied cpu count
# ---------------------------------------------------------------------------

def test_readme_documents_applied_cpu_count():
    """RED/ERROR at base (the hyperv_vm_create tool-table row lists
    cpu_count=1 but never states it is applied), GREEN after the fix: the row
    comes to say the requested cpu count is applied."""
    readme = Path(__file__).resolve().parents[2] / "README.md"
    text = readme.read_text(encoding="utf-8")
    row = next(
        (line for line in text.splitlines()
         if line.strip().startswith("|")
         and "`hyperv_vm_create`" in line
         and "cpu_count" in line),
        None,
    )
    assert row is not None, "the hyperv_vm_create tool-table row was not found"
    assert "cpu_count" in row and "applied" in row, (
        f"the row must state the requested cpu count is applied: {row!r}"
    )
