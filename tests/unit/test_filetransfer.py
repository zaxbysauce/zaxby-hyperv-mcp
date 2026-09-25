"""File transfer tests with mocked PowerShell: integrity, policy, validation."""

import json

import pytest

from hyperv_mcp import filetransfer, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")


class FakePS:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        item = self.responses.pop(0) if self.responses else pswindows.PSResult(returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def rooted_cfg(tmp_path):
    src = tmp_path / "host-src"
    src.mkdir()
    dst = tmp_path / "host-dst"
    dst.mkdir()
    cfg = Config(
        allowed_vm_patterns=["test-*"],
        host_read_roots=[str(src)],
        host_write_roots=[str(dst)],
        guest_read_roots=["C:\\g-read"],
        guest_write_roots=["C:\\g-write"],
    )
    cfg.destructive.guest_write = True
    cfg.destructive.require_confirm = False
    return cfg


def test_put_success_byte_counts_and_staging(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "tool.exe"
    src.write_bytes(b"MZ")
    payload = {"ok": True, "bytes_copied": 2, "bytes_local": 2, "bytes_remote": 2,
               "sha256_local": None, "sha256_remote": None}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\tool.exe",
        confirm=True, verify=False, cred=CRED,
    )
    assert out["ok"] and out["bytes_copied"] == 2
    script = fake.scripts[0]
    assert "-LiteralPath" in script
    assert ".mcptmp" in script
    assert "Move-Item" in script
    assert "-ToSession" in script


def test_put_policy_denials(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))

    # vm pattern (checked first)
    with pytest.raises(PolicyDenied, match="vm"):
        filetransfer.guest_put(rooted_cfg, "prod-db", str(src), r"C:\g-write\f", cred=CRED)
    # host read outside roots
    with pytest.raises(PolicyDenied, match="host read"):
        filetransfer.guest_put(rooted_cfg, "test-vm", str(outside), r"C:\g-write\f", cred=CRED)
    # guest write outside roots
    with pytest.raises(PolicyDenied, match="guest write"):
        filetransfer.guest_put(rooted_cfg, "test-vm", str(src), r"C:\Windows\f", cred=CRED)


def test_put_guest_write_gate_requires_category(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.bin").write_bytes(b"x")
    cfg = Config(
        allowed_vm_patterns=["test-*"],
        host_read_roots=[str(src)],
        guest_write_roots=["C:\\g-write"],
    )
    with pytest.raises(PolicyDenied, match="guest_write"):
        filetransfer.guest_put(cfg, "test-vm", str(src / "a.bin"), r"C:\g-write\f", confirm=True, cred=CRED)


def test_put_missing_source_no_ps_call(monkeypatch, rooted_cfg, tmp_path):
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(tmp_path / "host-src" / "nope.bin"), r"C:\g-write\f",
        confirm=True, cred=CRED,
    )
    assert out["ok"] is False and out["error_class"] == "not_found"
    assert fake.scripts == []


def test_put_sha_mismatch_detected(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x" * 10)
    payload = {"ok": True, "bytes_copied": 10, "sha256_local": "AAA", "sha256_remote": "BBB"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=True, cred=CRED,
    )
    assert out["ok"] is False and out["error_class"] == "integrity"


def test_put_sha_match_passes(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x" * 10)
    payload = {"ok": True, "bytes_copied": 10, "sha256_local": "AAA", "sha256_remote": "AAA"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=True, cred=CRED,
    )
    assert out["ok"] is True


def test_put_fails_closed_when_guest_denies_staging(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    fake = FakePS([pswindows.PSResult(returncode=1, stderr="Access is denied")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=False, cred=CRED,
    )
    assert out["ok"] is False and out["error_class"] == "transport"


def test_get_creates_local_parents_and_verifies(monkeypatch, rooted_cfg, tmp_path):
    dest = tmp_path / "host-dst" / "deep" / "dir" / "out.bin"
    payload = {"ok": True, "bytes_copied": 5, "bytes_remote": 5,
               "sha256_local": "S", "sha256_remote": "S"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest), verify=True, cred=CRED,
    )
    assert out["ok"]
    assert dest.parent.is_dir()
    assert "-FromSession" in fake.scripts[0]


def test_get_guest_read_outside_roots_denied(monkeypatch, rooted_cfg, tmp_path):
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    with pytest.raises(PolicyDenied, match="guest read"):
        filetransfer.guest_get(
            rooted_cfg, "test-vm", r"C:\Windows\System32\config\SAM",
            str(tmp_path / "host-dst" / "sam.hive"), cred=CRED,
        )


def test_get_sha_mismatch(monkeypatch, rooted_cfg, tmp_path):
    dest = tmp_path / "host-dst" / "out.bin"
    payload = {"ok": True, "bytes_copied": 3, "sha256_local": "X", "sha256_remote": "Y"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest), verify=True, cred=CRED,
    )
    assert out["error_class"] == "integrity"


def test_read_file_max_bytes_validation(rooted_cfg):
    for bad in (0, -1, -100):
        with pytest.raises(ValueError, match="max_bytes"):
            filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", bad, cred=CRED)


def test_read_file_slice_script_bounded(monkeypatch, rooted_cfg):
    """F9 regression: bounded Open+Read, never ReadAllBytes+slice."""
    payload = {"content_b64": "QUJD", "bytes_read": 3, "truncated": False}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", 3, cred=CRED)
    assert out["ok"] and out["bytes_read"] == 3
    script = fake.scripts[0]
    assert "[System.IO.File]::Open(" in script
    assert "ReadAllBytes" not in script
    assert "0..($maxb - 1)" not in script


def test_read_file_content_decodable(monkeypatch, rooted_cfg):
    import base64
    payload = {"content_b64": base64.b64encode(b"hello").decode(),
               "bytes_read": 5, "truncated": False}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", cred=CRED)
    assert base64.b64decode(out["content_b64"]) == b"hello"


def test_list_dir_shape(monkeypatch, rooted_cfg):
    payload = [{"name": "a.txt", "is_dir": False, "size_bytes": 3, "modified": "2026-01-01T00:00:00Z"}]
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_list_dir(rooted_cfg, "test-vm", r"C:\g-read", cred=CRED)
    assert out["ok"] and out["entries"][0]["name"] == "a.txt"


def test_list_dir_empty(monkeypatch, rooted_cfg):
    fake = FakePS([pswindows.PSResult(stdout="[]", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_list_dir(rooted_cfg, "test-vm", r"C:\g-read\empty", cred=CRED)
    assert out == {"ok": True, "entries": []}


def test_guest_root_assertion_embedded_when_roots_set(monkeypatch, rooted_cfg):
    payload = {"content_b64": "", "bytes_read": 0, "truncated": False}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", cred=CRED)
    assert "policy: guest read denied" in fake.scripts[0]
    assert "GetFullPath" in fake.scripts[0]


def test_timeout_mapping(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "big.bin"
    src.write_bytes(b"x")
    fake = FakePS([pswindows.PSResult(timed_out=True)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\big.bin",
        confirm=True, verify=False, cred=CRED,
    )
    assert out["error_class"] == "timeout" and out["ok"] is False
