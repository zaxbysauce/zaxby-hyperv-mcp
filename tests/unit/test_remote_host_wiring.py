"""AC2 acceptance checks: remote-host wiring of HOST-side PowerShell legs.

Contract: with a hyperv.host configured, every host-side generated script
(VM lifecycle, media, console WMI, vmident GUID resolution) executes on the
remote host — the captured script text contains
``Invoke-Command -ComputerName '<host>'`` (single-quoted literal hostname).

AC6 discriminator lives here too (test_local_mode_has_no_remote_wiring):
with NO hyperv section, the same captures contain ZERO ``-ComputerName`` —
local mode keeps today's codegen byte for byte.

All checks are captured-script structural assertions over a FakePS stub
(tests/unit/test_guestexec.py recording pattern; adaptive branches keyed by
script purpose, tests/unit/test_console.py style). No real Hyper-V, network,
or remote host is touched.
"""

import base64
import json

from hyperv_mcp import console, lifecycle, media, pswindows, vmident
from hyperv_mcp.config import Config

HOST = "nuc01"
WRAP = f"Invoke-Command -ComputerName '{HOST}'"
GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


class FakePS:
    """Adaptive stub: serves sane defaults keyed by the script's purpose.

    Branch order matters: the console capture/head scripts also mention
    Msvm_ComputerSystem, so purpose-specific branches are checked before the
    generic by-name resolution branch (which serves the VM GUID).
    """

    def __init__(self, responses=()):
        self.scripts = []
        self.kwargs = []
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if self.responses:
            item = self.responses.pop(0)
        elif "GetVirtualSystemThumbnailImage" in script:
            payload = b"\x00\x00\x00\x00" + b"\x00\x00" * (640 * 480)
            item = pswindows.PSResult(
                stdout=json.dumps({
                    "returnValue": 0,
                    "imageDataB64": base64.b64encode(payload).decode(),
                }),
                returncode=0,
            )
        elif "Msvm_VideoHead" in script:
            item = pswindows.PSResult(
                stdout='{"horizontal": 1024, "vertical": 768}', returncode=0)
        elif "Msvm_ComputerSystem" in script:
            # By-name GUID resolution leg (vmident.resolve).
            item = pswindows.PSResult(stdout=GUID, returncode=0)
        elif "final_state" in script:
            item = pswindows.PSResult(stdout='{"final_state": "Running"}', returncode=0)
        elif "Start-VM" in script:
            item = pswindows.PSResult(stdout='{"initial_state": "Off"}', returncode=0)
        else:
            # Inventory legs (list_vms, disk/media lists): zero rows.
            item = pswindows.PSResult(stdout="[]", returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


def _remote_cfg() -> Config:
    return Config.from_dict({"hyperv": {"host": HOST}, "unrestricted": True})


def _local_cfg() -> Config:
    return Config(unrestricted=True)


# -- capture helpers (shared by the remote and local-mode checks) -----------

def _capture_list_vms(monkeypatch, cfg) -> list[str]:
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.list_vms(cfg)
    assert fake.scripts
    return fake.scripts


def _capture_start_vm(monkeypatch, cfg) -> list[str]:
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.start_vm(cfg, "test-vm")
    assert fake.scripts
    return fake.scripts


def _capture_vm_disk_list(monkeypatch, cfg) -> list[str]:
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    media.vm_disk_list(cfg, "test-vm")
    assert fake.scripts
    return fake.scripts


def _capture_screenshot(monkeypatch, cfg) -> list[str]:
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.screenshot(cfg, "test-vm")
    assert fake.scripts
    return fake.scripts


def _capture_resolve(monkeypatch, cfg) -> list[str]:
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    vmident.resolve(cfg, "test-vm")
    assert fake.scripts
    return fake.scripts


# ---------------------------------------------------------------------------
# AC2: remote mode wraps every host-side leg
# ---------------------------------------------------------------------------

def test_list_vms_remote_wrap(monkeypatch):
    for script in _capture_list_vms(monkeypatch, _remote_cfg()):
        assert WRAP in script, script[:120]


def test_start_vm_remote_wrap(monkeypatch):
    for script in _capture_start_vm(monkeypatch, _remote_cfg()):
        assert WRAP in script, script[:120]


def test_vm_disk_list_remote_wrap(monkeypatch):
    for script in _capture_vm_disk_list(monkeypatch, _remote_cfg()):
        assert WRAP in script, script[:120]


def test_console_screenshot_remote_wrap(monkeypatch):
    for script in _capture_screenshot(monkeypatch, _remote_cfg()):
        assert WRAP in script, script[:120]


def test_vmident_resolution_remote_wrap(monkeypatch):
    for script in _capture_resolve(monkeypatch, _remote_cfg()):
        assert WRAP in script, script[:120]


# ---------------------------------------------------------------------------
# AC6: local mode (no hyperv section) keeps ZERO remote wiring
# ---------------------------------------------------------------------------

def test_local_mode_has_no_remote_wiring(monkeypatch):
    """AC6 discriminator: with NO hyperv section the same host-side captures
    contain zero ``-ComputerName`` (today's codegen, byte for byte).

    The default-config precondition doubles as the AC1 default-contract pin
    (absent section -> hyperv host None -> local mode), which is what keeps
    this check RED on a tree where the feature does not exist yet.
    """
    assert Config().hyperv.host is None  # absent section = local mode
    captures = {
        "list_vms": _capture_list_vms(monkeypatch, _local_cfg()),
        "start_vm": _capture_start_vm(monkeypatch, _local_cfg()),
        "vm_disk_list": _capture_vm_disk_list(monkeypatch, _local_cfg()),
        "screenshot": _capture_screenshot(monkeypatch, _local_cfg()),
        "vmident_resolve": _capture_resolve(monkeypatch, _local_cfg()),
    }
    for name, scripts in captures.items():
        assert scripts, f"{name}: expected at least one captured script"
        for script in scripts:
            assert "-ComputerName" not in script, f"{name}: {script[:120]}"
