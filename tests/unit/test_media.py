"""Media/provisioning tests: script shapes, path policy, gate matrix, errors."""

import pytest

from hyperv_mcp import media, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.media import MediaError
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


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(media.pswindows.time if hasattr(media.pswindows, "time") else media, "sleep", lambda s: None) if False else None


# ---------------------------------------------------------------------------
# vm_create
# ---------------------------------------------------------------------------

def test_vm_create_script_shape_and_confirm(monkeypatch, unrestricted, tmp_path):
    vhd = tmp_path / "new-vm" / "disk.vhdx"
    fake = FakePS([pswindows.PSResult(
        stdout='{"id": "GUID-1", "name": "test-vm-1", "state": "Off", "generation": 2}',
        returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_create(
        unrestricted, "test-vm-1", memory_mb=1024, cpu_count=2, generation=2,
        vhd_path=str(vhd), vhd_size_gb=30, switch_name="LabSwitch", confirm=True,
    )
    assert out["ok"] and out["id"] == "GUID-1"
    script = fake.scripts[0]
    assert "New-VHD -Path" in script and "30GB" in script
    assert "New-VM -Name 'test-vm-1'" in script
    assert "1024MB" in script and "Generation 2" in script
    assert "Connect-VMNetworkAdapter" in script and "'LabSwitch'" in script
    assert vhd.parent.is_dir()  # parent created


def test_vm_create_requires_confirm():
    # confirm fires BEFORE the category check (no category-enablement leak)
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="confirm=true"):
        media.vm_create(cfg, "test-vm-1", vhd_path="C:\\x\\a.vhdx", confirm=False)
    # with confirm given, the category denial surfaces
    with pytest.raises(PolicyDenied, match="vm_provision"):
        media.vm_create(cfg, "test-vm-1", vhd_path="C:\\x\\a.vhdx", confirm=True)


def test_vm_create_requires_vm_provision_category():
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="vm_provision"):
        media.vm_create(cfg, "test-vm-1", vhd_path="C:\\x\\a.vhdx", confirm=True)


def test_vm_create_name_must_match_allowlist():
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="allowed_vm_patterns"):
        media.vm_create(cfg, "prod-db-1", vhd_path="C:\\x\\a.vhdx", confirm=True)


def test_vm_create_vhd_outside_write_root_denied(tmp_path):
    cfg = Config(allowed_vm_patterns=["test-*"], host_write_roots=[str(tmp_path / "allowed")])
    cfg.destructive.vm_provision = True
    cfg.destructive.require_confirm = False
    with pytest.raises(PolicyDenied, match="host write"):
        media.vm_create(cfg, "test-vm-1", vhd_path=str(tmp_path / "elsewhere.vhdx"), confirm=True)


def test_vm_create_rejects_wrong_extension(tmp_path):
    cfg = Config(unrestricted=True)
    with pytest.raises(ValueError, match=".vhdx"):
        media.vm_create(cfg, "test-vm-1", vhd_path=str(tmp_path / "disk.iso"), confirm=True)


def test_vm_create_rejects_existing_vhd(tmp_path, unrestricted):
    vhd = tmp_path / "disk.vhdx"
    vhd.write_bytes(b"x")
    with pytest.raises(MediaError, match="refusing to overwrite"):
        media.vm_create(unrestricted, "test-vm-1", vhd_path=str(vhd), confirm=True)


def test_vm_create_validates_bounds(tmp_path, unrestricted):
    with pytest.raises(ValueError, match="memory_mb"):
        media.vm_create(unrestricted, "vm", memory_mb=1, vhd_path=str(tmp_path / "a.vhdx"), confirm=True)
    with pytest.raises(ValueError, match="cpu_count"):
        media.vm_create(unrestricted, "vm", cpu_count=100, vhd_path=str(tmp_path / "a.vhdx"), confirm=True)
    with pytest.raises(ValueError, match="generation"):
        media.vm_create(unrestricted, "vm", generation=3, vhd_path=str(tmp_path / "a.vhdx"), confirm=True)


# ---------------------------------------------------------------------------
# disk add / list
# ---------------------------------------------------------------------------

def test_disk_add_script_shape(monkeypatch, unrestricted, tmp_path):
    vhd = tmp_path / "data.vhdx"
    fake = FakePS([pswindows.PSResult(stdout='{"disk_count": 2}', returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_disk_add(unrestricted, "test-vm", str(vhd), 100, "SCSI", confirm=True)
    assert out["ok"] and out["vhd_path"].endswith("data.vhdx")
    script = fake.scripts[0]
    assert "New-VHD -Path" in script and "100GB" in script
    assert "Add-VMHardDiskDrive" in script and "-ControllerType SCSI" in script


def test_disk_add_requires_confirm():
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="confirm=true"):
        media.vm_disk_add(cfg, "test-vm", "C:\\x\\d.vhdx", 50, confirm=False)


def test_disk_add_ide_supported(monkeypatch, unrestricted, tmp_path):  # noqa: ARG001
    fake = FakePS([pswindows.PSResult(stdout='{"disk_count": 2}', returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    media.vm_disk_add(unrestricted, "vm", str(tmp_path / "d.vhdx"), 10, "IDE", confirm=True)
    assert "-ControllerType IDE" in fake.scripts[0]


def test_disk_add_rejects_unknown_controller(unrestricted, tmp_path):
    with pytest.raises(ValueError, match="controller_type"):
        media.vm_disk_add(unrestricted, "vm", str(tmp_path / "d.vhdx"), 10, "NVMe", confirm=True)


def test_disk_list_shape(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout=(
        '[{"controller_type": "SCSI", "controller_number": 0, "lun": 0, "path": "C:\\\\a.vhdx"},'
        '{"controller_type": "SCSI", "controller_number": 0, "lun": 1, "path": "C:\\\\b.vhdx"}]'
    ), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_disk_list(unrestricted, "vm")
    assert out["ok"] and len(out["disks"]) == 2


# ---------------------------------------------------------------------------
# media attach/detach/list (media category, NO confirm)
# ---------------------------------------------------------------------------

def test_media_attach_no_confirm_needed(monkeypatch, tmp_path):
    """Key design property: ISO attach is reversible — no human prompt."""
    cfg = Config(allowed_vm_patterns=["test-*"], host_read_roots=[str(tmp_path)])
    cfg.destructive.media = True
    iso = tmp_path / "media.iso"
    iso.write_bytes(b"x")
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_media_attach(cfg, "test-vm", str(iso))
    assert out["ok"] and out["iso_path"].endswith(".iso")
    assert "Add-VMDvdDrive" in fake.scripts[0]


def test_media_attach_denied_without_category(monkeypatch, tmp_path):
    cfg = Config(allowed_vm_patterns=["test-*"], host_read_roots=[str(tmp_path)])
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    with pytest.raises(PolicyDenied, match="media"):
        media.vm_media_attach(cfg, "test-vm", str(tmp_path / "media.iso"))


def test_media_attach_missing_iso_is_not_found(monkeypatch, tmp_path):
    cfg = Config(unrestricted=True)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    with pytest.raises(MediaError, match="file not found"):
        media.vm_media_attach(cfg, "vm", str(tmp_path / "nope.iso"))


def test_media_attach_rejects_non_iso(tmp_path):
    cfg = Config(unrestricted=True)
    with pytest.raises(ValueError, match=".iso"):
        media.vm_media_attach(cfg, "vm", str(tmp_path / "media.vhdx"))


def test_media_attach_iso_outside_read_roots_denied(tmp_path):
    cfg = Config(allowed_vm_patterns=["test-*"], host_read_roots=[str(tmp_path / "allowed")])
    cfg.destructive.media = True
    outside = tmp_path / "elsewhere.iso"
    outside.write_bytes(b"x")
    with pytest.raises(PolicyDenied, match="host read"):
        media.vm_media_attach(cfg, "test-vm", str(outside))


def test_media_detach_returns_removed_paths(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(
        stdout='{"removed": ["C:\\\\media.iso"]}', returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_media_detach(unrestricted, "vm")
    assert out["removed"] == ["C:\\media.iso"]
    assert "Remove-VMDvdDrive" in fake.scripts[0]


def test_media_list(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(
        stdout='[{"controller_number": 0, "lun": 0, "path": null}]', returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_media_list(unrestricted, "vm")
    assert out["ok"] and out["media"][0]["path"] is None


def test_network_set(monkeypatch, unrestricted):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_network_set(unrestricted, "vm", "LabSwitch")
    assert out["ok"] and out["switch_name"] == "LabSwitch"
    assert "Connect-VMNetworkAdapter" in fake.scripts[0]
    assert "'LabSwitch'" in fake.scripts[0]


# ---------------------------------------------------------------------------
# firmware / TPM / secure boot
# ---------------------------------------------------------------------------

def test_firmware_get_shape(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),  # generation guard
        pswindows.PSResult(stdout=(
            '{"secure_boot": "On", "secure_boot_template": "MicrosoftWindows",'
            '"boot_order": ["Drive", "Network"], "tpm_enabled": true}'), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_firmware_get(unrestricted, "vm")
    assert out["secure_boot"] == "On" and out["tpm_enabled"] is True


def test_firmware_gen1_explicit_error(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="1", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(MediaError, match="Generation 1"):
        media.vm_firmware_get(unrestricted, "vm")


def test_firmware_set_boot_order(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),
        pswindows.PSResult(stdout='{"first_boot": "Drive"}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_firmware_set_boot_order(unrestricted, "vm", "Drive", confirm=True)
    assert out["first_boot"] == "Drive"
    assert "Set-VMFirmware" in fake.scripts[1] and "-FirstBootDevice" in fake.scripts[1]


def test_firmware_boot_order_validated():
    cfg = Config(unrestricted=True)
    with pytest.raises(ValueError, match="boot_type"):
        media.vm_firmware_set_boot_order(cfg, "vm", "USB", confirm=True)


def test_firmware_boot_order_requires_confirm():
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="confirm=true"):
        media.vm_firmware_set_boot_order(cfg, "test-vm", "Drive", confirm=False)


def test_tpm_set_enable(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),
        pswindows.PSResult(stdout='{"tpm_enabled": true}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_tpm_set(unrestricted, "vm", True, confirm=True)
    assert out["tpm_enabled"] is True
    assert "Enable-VMTPM" in fake.scripts[1]


def test_tpm_set_disable(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),
        pswindows.PSResult(stdout='{"tpm_enabled": false}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    media.vm_tpm_set(unrestricted, "vm", False, confirm=True)
    assert "Disable-VMTPM" in fake.scripts[1]


def test_secureboot_set_maps_bool_to_onoff_enum(monkeypatch, unrestricted):
    """Set-VMFirmware -EnableSecureBoot binds an OnOffState enum, not a bool."""
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),
        pswindows.PSResult(stdout='{"secure_boot": "On"}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    media.vm_secureboot_set(unrestricted, "vm", True, confirm=True)
    assert "-EnableSecureBoot On" in fake.scripts[1]


def test_secureboot_set_off(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),
        pswindows.PSResult(stdout='{"secure_boot": "Off"}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    media.vm_secureboot_set(unrestricted, "vm", False, confirm=True)
    assert "-EnableSecureBoot Off" in fake.scripts[1]


def test_secureboot_template_quoted(monkeypatch, unrestricted):
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),
        pswindows.PSResult(stdout='{"secure_boot": "On"}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    media.vm_secureboot_set(unrestricted, "vm", True, "MicrosoftUEFICertificateAuthority", confirm=True)
    assert "'MicrosoftUEFICertificateAuthority'" in fake.scripts[1]


def test_secureboot_template_injection_rejected(monkeypatch, unrestricted):
    """Template with PS metacharacters must arrive ps_quote'd, not raw."""
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),
        pswindows.PSResult(stdout='{"secure_boot": "On"}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    hostile = "Microsoft'; Invoke-Expression 'calc'; '"
    media.vm_secureboot_set(unrestricted, "vm", True, hostile, confirm=True)
    script = fake.scripts[1]
    assert "Invoke-Expression" not in script.replace("'" + hostile.replace("'", "''") + "'", "")
    # the hostile text appears ONLY inside a doubled-quote literal
    assert hostile.replace("'", "''") in script


def test_secureboot_requires_confirm():
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="confirm=true"):
        media.vm_secureboot_set(cfg, "test-vm", True, confirm=False)


# ---------------------------------------------------------------------------
# power-shell error mapping
# ---------------------------------------------------------------------------

def test_ps_failure_maps_to_media_error(monkeypatch, unrestricted, tmp_path):
    fake = FakePS([
        pswindows.PSResult(stdout="2", returncode=0),
        pswindows.PSResult(returncode=1, stderr="Set-VMFirmware : Access denied"),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(MediaError, match="Access denied"):
        media.vm_secureboot_set(unrestricted, "vm", True, confirm=True)
