"""Guest execution tests with mocked PowerShell: envelope, gates, quoting."""

import base64
import json

import pytest

from hyperv_mcp import guestexec, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")
VICTIM = CredentialSet("victim", "placeholder-pass-2")


def _inner_script(host_script: str) -> str:
    """The guest-visible inner script rides in the host script as b64."""
    marker = "$enc = '"
    start = host_script.index(marker) + len(marker)
    end = host_script.index("'", start)
    return base64.b64decode(host_script[start:end]).decode("utf-8")


class FakePS:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []
        self.kwargs = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        item = self.responses.pop(0) if self.responses else pswindows.PSResult(returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


def test_run_ps_success_envelope(monkeypatch, unrestricted):
    payload = {"exit_code": 0, "stdout": "out-text", "stderr": ""}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(unrestricted, "vm1", "Get-Date", cred=CRED)
    assert out == {
        "ok": True, "exit_code": 0, "stdout": "out-text", "stderr": "",
        "timed_out": False, "truncated": False,
    }


def test_run_ps_real_exit_code_preserved(monkeypatch, unrestricted):
    payload = {"exit_code": 3, "stdout": "", "stderr": ""}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(unrestricted, "vm1", "exit 3", cred=CRED)
    assert out["ok"] and out["exit_code"] == 3


def test_separate_streams(monkeypatch, unrestricted):
    payload = {"exit_code": 0, "stdout": "to-out", "stderr": "to-err"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(unrestricted, "vm1", "x", cred=CRED)
    assert out["stdout"] == "to-out" and out["stderr"] == "to-err"


def test_timeout_reports_guest_may_continue(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(timed_out=True)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(unrestricted, "vm1", "x", timeout_ms=1000, cred=CRED)
    assert out["ok"] is False
    assert out["timed_out"] is True
    assert out["error_class"] == "timeout"
    assert "may still be running" in out["error"]


def test_transport_error_mapping(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(returncode=1, stderr="Cannot find VM")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(unrestricted, "vm1", "x", cred=CRED)
    assert out["error_class"] == "transport" and "Cannot find VM" in out["error"]


def test_parse_error_mapping(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(stdout="not json at all", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(unrestricted, "vm1", "x", cred=CRED)
    assert out["error_class"] == "parse"


def test_output_truncation_flag(monkeypatch):
    cfg = Config(unrestricted=True, max_output_bytes=1024)
    payload = {"exit_code": 0, "stdout": "A" * 5000, "stderr": ""}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(cfg, "vm1", "x", cred=CRED)
    assert out["truncated"] is True
    assert len(out["stdout"].encode("utf-8")) <= 1024


def test_elevated_gated_by_policy():
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="elevated_exec"):
        guestexec.guest_run_ps(
            cfg, "test-vm", "x", elevated=True, confirm=True, cred=CRED
        )
    cfg.destructive.elevated_exec = True
    with pytest.raises(PolicyDenied, match="confirm"):
        guestexec.guest_run_ps(
            cfg, "test-vm", "x", elevated=True, confirm=False, cred=CRED
        )


def test_elevated_uses_runas_merged_note(monkeypatch, unrestricted):
    payload = {"exit_code": 0, "stdout": "merged", "stderr": ""}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(
        unrestricted, "vm1", "x", elevated=True, confirm=True, cred=CRED
    )
    assert "Verb" in fake.scripts[0] and "'RunAs'" in fake.scripts[0]
    assert "merged" in out["note"]


def test_normal_path_uses_separate_redirects(monkeypatch, unrestricted):
    payload = {"exit_code": 0, "stdout": "o", "stderr": "e"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run_ps(unrestricted, "vm1", "x", cred=CRED)
    assert "RedirectStandardOutput" in fake.scripts[0]
    assert "RedirectStandardError" in fake.scripts[0]
    assert "'RunAs'" not in fake.scripts[0]


def test_password_via_stdin_not_script(monkeypatch, unrestricted):
    """F1/F4 regression: password must arrive via stdin_b64, never embedded."""
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 0, "stdout": "", "stderr": ""}), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run_ps(unrestricted, "vm1", "x", cred=CRED)
    script = fake.scripts[0]
    assert CRED.password not in script
    assert fake.kwargs[0].get("stdin_b64") == pswindows.utf8_b64(CRED.password)
    assert "$cred = [System.Management.Automation.PSCredential]::new('Administrator', $sec)" in script


def test_guest_run_command_quoting_and_empty_args(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 0, "stdout": "", "stderr": ""}), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run(
        unrestricted, "vm1", r"C:\path with space\tool.exe",
        ["", "arg with 'quote'", "plain"], cwd=r"C:\work dir", cred=CRED,
    )
    inner = _inner_script(fake.scripts[0])
    assert "'C:\\path with space\\tool.exe'" in inner
    assert "''" in inner
    assert "'arg with ''quote'''" in inner
    assert "Set-Location -LiteralPath 'C:\\work dir' -ErrorAction Stop" in inner
    assert "Pop-Location" in inner


def test_guest_run_exit_propagation(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 7, "stdout": "", "stderr": ""}), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run(unrestricted, "vm1", "cmd.exe", ["/c", "exit 7"], cred=CRED)
    assert guestexec._EXIT_PROPAGATION in _inner_script(fake.scripts[0])


def test_guest_run_ps_exit_propagation(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 0, "stdout": "", "stderr": ""}), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run_ps(unrestricted, "vm1", "Write-Output hi", cred=CRED)
    assert guestexec._EXIT_PROPAGATION in _inner_script(fake.scripts[0])


def test_host_script_passes_enc_via_argument_list(monkeypatch, unrestricted):
    """Round-2 regression: without -ArgumentList $enc the guest scriptblock
    binds $enc=$null, silently executes an EMPTY script, and returns
    {ok:true, exit_code:0, stdout:''} — a worse failure than an error."""
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 0, "stdout": "x", "stderr": ""}), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run_ps(unrestricted, "vm1", "Get-Date", cred=CRED)
    # Rendered f-string turns }} into }: the Invoke-Command closes with a
    # single brace followed by the ArgumentList carrying $enc across the
    # remoting boundary.
    assert "} -ArgumentList $enc" in fake.scripts[0]


def test_victim_never_elevated(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 0, "stdout": "", "stderr": ""}), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.victim_run_ps(unrestricted, "vm1", "whoami", cred=VICTIM)
    assert "'RunAs'" not in fake.scripts[0]
    assert VICTIM.username in fake.scripts[0]


def test_vm_policy_denied_raises():
    """Policy violations raise from the module layer; the server tool layer
    maps them to {ok:false, error_class:'policy'}."""
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="allowed_vm_patterns"):
        guestexec.guest_run_ps(cfg, "prod-db", "x", cred=CRED)


def test_missing_creds_rejected():
    with pytest.raises(ValueError, match="credentials"):
        guestexec.guest_run_ps(Config(unrestricted=True), "vm1", "x", cred=None)
