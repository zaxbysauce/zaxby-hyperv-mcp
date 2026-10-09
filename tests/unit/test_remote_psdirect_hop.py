"""AC3 acceptance checks: PS-Direct guest envelopes run under the remote hop.

Contract: with a hyperv.host configured, the PS-Direct guest envelopes
(guestexec guest_run_ps, filetransfer read/list legs) execute on the remote
host too, and the secret payload crosses the hop safely:
  * the captured script contains ``Invoke-Command -ComputerName '<host>'``;
  * exactly ONE ``[Console]::In.ReadLine()`` — the LOCAL preamble reads
    stdin, then passes it into the remote block via -ArgumentList;
  * the ReadLine position is BEFORE the Invoke-Command -ComputerName wrap;
  * ``-ArgumentList`` is present (the payload/secrets cross as parameters).

D1 hazard pin (filetransfer): guest_put/guest_get keep MCP-machine filesystem
legs OUTSIDE the remote hop and the guest session legs INSIDE it:
  (a) the ComputerName wrap is present;
  (b) a ``New-PSSession -VMId`` occurrence sits AFTER the ComputerName token;
  (c) the local-file hash leg (``Get-FileHash``) sits BEFORE it.

All checks are captured-script structural assertions over a FakePS stub
(tests/unit/test_relay.py resolution-leg pattern + tests/unit/test_filetransfer.py
rooted_cfg host-roots-under-tmp_path pattern). No real Hyper-V or remote host.
"""

import json

import pytest

from hyperv_mcp import filetransfer, guestexec, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

HOST = "nuc01"
WRAP = f"Invoke-Command -ComputerName '{HOST}'"
GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
CRED = CredentialSet("Administrator", "placeholder-pass")


def _is_resolution_leg(script: str) -> bool:
    """A by-name resolution leg emits $vmTarget (vmident.resolve's leg)."""
    return "Msvm_ComputerSystem" in script and "$vmTarget" in script


class FakePS:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def _no_ambient_host_credentials(monkeypatch):
    """Keep the host-hop shape deterministic: ambient HYPERV_HOST_* variables
    would add a host -Credential (and its stdin leg) to the generated script."""
    for var in ("HYPERV_HOST_USERNAME", "HYPERV_HOST_PASSWORD", "HYPERV_HOST_PASSWORD_FILE"):
        monkeypatch.delenv(var, raising=False)


def _guest_remote_cfg() -> Config:
    return Config.from_dict({
        "hyperv": {"host": HOST},
        "allowed_vm_patterns": ["test-*"],
        "guest_read_roots": ["C:\\g-read"],
    })


def _assert_remote_hop_envelope(script: str) -> None:
    """The AC3 envelope contract for one captured PS-Direct script."""
    assert WRAP in script, script[:120]
    assert script.count("[Console]::In.ReadLine()") == 1, (
        "remote mode must read stdin exactly once (local preamble)")
    readline_at = script.index("[Console]::In.ReadLine()")
    assert readline_at < script.index(WRAP), (
        "the local preamble must read stdin BEFORE the remote hop wraps it")
    assert "-ArgumentList" in script, (
        "payload/secrets must cross the hop as scriptblock parameters")


# ---------------------------------------------------------------------------
# AC3: guest_run_ps / guest_read_file / guest_list_dir
# ---------------------------------------------------------------------------

def test_guest_run_ps_remote_hop(monkeypatch):
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 0, "stdout": "", "stderr": ""}),
        returncode=0,
    )])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run_ps(_guest_remote_cfg(), "test-vm", "Get-Date", cred=CRED)
    assert len(fake.scripts) == 2  # resolution leg + envelope leg
    _assert_remote_hop_envelope(fake.scripts[1])


def test_guest_read_file_remote_hop(monkeypatch):
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"content_b64": "aGk=", "bytes_read": 2, "truncated": False}),
        returncode=0,
    )])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_read_file(
        _guest_remote_cfg(), "test-vm", r"C:\g-read\x.bin", cred=CRED)
    assert out["ok"] is True
    assert len(fake.scripts) == 2
    _assert_remote_hop_envelope(fake.scripts[1])


def test_guest_list_dir_remote_hop(monkeypatch):
    fake = FakePS([pswindows.PSResult(stdout="[]", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_list_dir(
        _guest_remote_cfg(), "test-vm", r"C:\g-read", cred=CRED)
    assert out["ok"] is True
    assert len(fake.scripts) == 2
    _assert_remote_hop_envelope(fake.scripts[1])


# ---------------------------------------------------------------------------
# D1 hazard pin: guest_put / guest_get outside/inside ordering
# ---------------------------------------------------------------------------

@pytest.fixture()
def rooted_remote_cfg(tmp_path):
    """Remote-mode twin of tests/unit/test_filetransfer.py's rooted_cfg:
    host roots live under tmp_path (the MCP machine's filesystem)."""
    src = tmp_path / "host-src"
    src.mkdir()
    dst = tmp_path / "host-dst"
    dst.mkdir()
    cfg = Config.from_dict({
        "hyperv": {"host": HOST},
        "allowed_vm_patterns": ["test-*"],
        "host_read_roots": [str(src)],
        "host_write_roots": [str(dst)],
        "guest_read_roots": ["C:\\g-read"],
        "guest_write_roots": ["C:\\g-write"],
    })
    cfg.destructive.guest_write = True
    cfg.destructive.require_confirm = False
    return cfg, src, dst


def _transfer_ok() -> pswindows.PSResult:
    return pswindows.PSResult(
        stdout=json.dumps({
            "ok": True, "bytes_copied": 2, "bytes_local": 2, "bytes_remote": 2,
            "sha256_local": None, "sha256_remote": None,
        }),
        returncode=0,
    )


def _assert_d1_outside_inside(script: str) -> None:
    assert WRAP in script, script[:120]
    wrap_at = script.index(WRAP)
    assert script.index("New-PSSession -VMId") > wrap_at, (
        "the guest session must be created INSIDE the remote hop")
    assert script.index("Get-FileHash") < wrap_at, (
        "the local-file hash leg must stay OUTSIDE (before) the remote hop")


def test_guest_put_d1_local_legs_outside_hop(monkeypatch, rooted_remote_cfg):
    cfg, src, _dst = rooted_remote_cfg
    src_file = src / "tool.exe"
    src_file.write_bytes(b"MZ")
    fake = FakePS([_transfer_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        cfg, "test-vm", str(src_file), r"C:\g-write\tool.exe",
        confirm=True, verify=True, cred=CRED,
    )
    assert out["ok"] is True
    assert len(fake.scripts) == 2  # resolution leg + session leg
    _assert_d1_outside_inside(fake.scripts[1])


def test_guest_get_d1_local_legs_outside_hop(monkeypatch, rooted_remote_cfg):
    cfg, _src, dst = rooted_remote_cfg
    fake = FakePS([_transfer_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_get(
        cfg, "test-vm", r"C:\g-read\src.bin", str(dst / "out.bin"),
        verify=True, cred=CRED,
    )
    assert out["ok"] is True
    assert len(fake.scripts) == 2
    _assert_d1_outside_inside(fake.scripts[1])
