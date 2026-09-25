"""Parse-validate every generated PowerShell template with the real PS parser.

The first real-Hyper-V integration run exposed a script that MOCKED unit
tests accepted but real PowerShell 5.1 rejected ('An empty pipe element is
not allowed' — a leading pipe on a continuation line). This file runs each
template through [System.Management.Automation.Language.Parser]::ParseInput,
which reports syntax errors WITHOUT executing anything — no Hyper-V, no VM
side effects.
"""

import json

import pytest

from hyperv_mcp import filetransfer, guestexec, lifecycle, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")

UNRESTRICTED = Config(unrestricted=True)
ROOTED = Config(
    unrestricted=True,
    guest_read_roots=["C:\\g-read"],
    guest_write_roots=["C:\\g-write"],
)


_REAL_RUN_PS = pswindows.run_ps  # saved before any monkeypatching


class Recorder:
    """Captures generated scripts; returns benign canned results."""

    def __init__(self):
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(stdout="", returncode=0)


@pytest.fixture(scope="module")
def parsed_ps():
    """Marker skip when real PowerShell is absent."""
    import os

    if not os.path.isfile(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
        pytest.skip("Windows PowerShell not available")
    pswindows.init(UNRESTRICTED)
    yield


def _parse_errors(script: str) -> list[str]:
    """Parse-only validation via the real PS 5.1 parser (never executes).

    Uses the saved real run_ps so it works even while a Recorder is
    monkeypatched over pswindows.run_ps.
    """
    b64 = pswindows.utf8_b64(script)
    parser = (
        "$text = [System.Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String([Console]::In.ReadLine()))\n"
        "$errs = $null\n"
        "[System.Management.Automation.Language.Parser]::ParseInput("
        "$text, [ref]$null, [ref]$errs) | Out-Null\n"
        "if ($errs.Count -gt 0) {\n"
        "    $errs | ForEach-Object { Write-Output ($_.Extent.StartLineNumber.ToString() + ': ' + $_.Message) }\n"
        "    exit 1\n"
        "} else { Write-Output 'PARSE-OK' }\n"
    )
    result = _REAL_RUN_PS(parser, timeout_s=60, stdin_b64=b64)
    if result.stdout.strip() == "PARSE-OK":
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def _collect(monkeypatch, fn, *args, **kwargs) -> str:
    rec = Recorder()
    monkeypatch.setattr(pswindows, "run_ps", rec)
    try:
        fn(*args, **kwargs)
    except Exception:
        # Post-capture validation failures (canned-JSON parsing, state waits)
        # don't matter — the generated script was already captured.
        pass
    assert rec.scripts, f"{fn.__name__} produced no script"
    return rec.scripts[0]


# ---------------------------------------------------------------------------
# lifecycle templates
# ---------------------------------------------------------------------------

def test_parse_list_vms_script(parsed_ps):
    """Regression: leading pipe on a continuation line is a PS 5.1 parse error
    ('An empty pipe element is not allowed') that mocks never caught."""
    assert _parse_errors(lifecycle._LIST_VM_SCRIPT) == []


def test_parse_get_vm_info(monkeypatch, parsed_ps):
    script = _collect(monkeypatch, lifecycle.get_vm_info, UNRESTRICTED, "vm1")
    assert _parse_errors(script) == []


def test_parse_start_vm(monkeypatch, parsed_ps):
    script = _collect(monkeypatch, lifecycle.start_vm, UNRESTRICTED, "vm1")
    assert _parse_errors(script) == []


@pytest.mark.parametrize("method", ["shutdown", "shutdown-force", "save", "turnoff"])
def test_parse_stop_vm(monkeypatch, parsed_ps, method):
    script = _collect(
        monkeypatch, lifecycle.stop_vm, UNRESTRICTED, "vm1", method, True
    )
    assert _parse_errors(script) == []


def test_parse_reset_vm(monkeypatch, parsed_ps):
    script = _collect(monkeypatch, lifecycle.reset_vm, UNRESTRICTED, "vm1", True)
    assert _parse_errors(script) == []


def test_parse_checkpoint_create(monkeypatch, parsed_ps):
    script = _collect(monkeypatch, lifecycle.checkpoint_create, UNRESTRICTED, "vm1", "snap1")
    assert _parse_errors(script) == []


def test_parse_checkpoint_list(monkeypatch, parsed_ps):
    script = _collect(monkeypatch, lifecycle.checkpoint_list, UNRESTRICTED, "vm1")
    assert _parse_errors(script) == []


def test_parse_checkpoint_restore(monkeypatch, parsed_ps):
    script = _collect(
        monkeypatch, lifecycle.checkpoint_restore, UNRESTRICTED, "vm1", "snap1", True
    )
    assert _parse_errors(script) == []


def test_parse_checkpoint_remove(monkeypatch, parsed_ps):
    script = _collect(
        monkeypatch, lifecycle.checkpoint_remove, UNRESTRICTED, "vm1", "snap1", True, True
    )
    assert _parse_errors(script) == []


def test_parse_kdnet(monkeypatch, parsed_ps):
    script = _collect(
        monkeypatch, lifecycle.configure_kdnet, UNRESTRICTED, "vm1",
        "192.0.2.1", 50000, "a1b2c.d3e4f.5a6b7.c8d9e", False, True, CRED,
    )
    assert _parse_errors(script) == []


def test_parse_kdnet_reboot(monkeypatch, parsed_ps):
    captured = []

    def rec(script, **kwargs):
        captured.append(script)
        return pswindows.PSResult(
            stdout=json.dumps({"DbgSettings": "ok"}), returncode=0
        )

    monkeypatch.setattr(pswindows, "run_ps", rec)
    lifecycle.configure_kdnet(
        UNRESTRICTED, "vm1", "192.0.2.1", 50000, "", True, True, cred=CRED
    )
    for script in captured:
        assert _parse_errors(script) == []


def test_parse_kdcom(monkeypatch, parsed_ps):
    captured = []

    def rec(script, **kwargs):
        captured.append(script)
        if "Set-VMComPort" in script:
            return pswindows.PSResult(stdout="", returncode=0)
        return pswindows.PSResult(stdout=json.dumps({"DbgSettings": "ok"}), returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", rec)
    lifecycle.configure_kdcom(
        UNRESTRICTED, "vm1", "\\\\.\\pipe\\kd_vm1", 1, True, True, cred=CRED
    )
    for script in captured:
        assert _parse_errors(script) == []


# ---------------------------------------------------------------------------
# guest execution templates
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("elevated", [False, True])
def test_parse_guest_run_ps(monkeypatch, parsed_ps, elevated):
    script = _collect(
        monkeypatch, guestexec.guest_run_ps, UNRESTRICTED, "vm1",
        "Write-Output hi", elevated=elevated, confirm=True, cred=CRED,
    )
    assert _parse_errors(script) == []


def test_parse_guest_run_with_args_and_cwd(monkeypatch, parsed_ps):
    script = _collect(
        monkeypatch, guestexec.guest_run, UNRESTRICTED, "vm1",
        r"C:\tool.exe", ["a", "", "b c"], r"C:\work dir",
        confirm=True, cred=CRED,
    )
    assert _parse_errors(script) == []


def test_parse_victim_run(monkeypatch, parsed_ps):
    victim = CredentialSet("victim", "placeholder-pass-2")
    script = _collect(
        monkeypatch, guestexec.victim_run, UNRESTRICTED, "vm1",
        "cmd.exe", ["/c", "echo hi"], None, cred=victim,
    )
    assert _parse_errors(script) == []


# ---------------------------------------------------------------------------
# file transfer templates
# ---------------------------------------------------------------------------

def test_parse_guest_put(monkeypatch, parsed_ps, tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    script = _collect(
        monkeypatch, filetransfer.guest_put, ROOTED, "vm1",
        str(src), r"C:\g-write\a.bin", confirm=True, verify=True, cred=CRED,
    )
    assert _parse_errors(script) == []


def test_parse_guest_get(monkeypatch, parsed_ps, tmp_path):
    script = _collect(
        monkeypatch, filetransfer.guest_get, ROOTED, "vm1",
        r"C:\g-read\a.bin", str(tmp_path / "out.bin"), verify=True, cred=CRED,
    )
    assert _parse_errors(script) == []


def test_parse_guest_read_file(monkeypatch, parsed_ps):
    script = _collect(
        monkeypatch, filetransfer.guest_read_file, ROOTED, "vm1",
        r"C:\g-read\f.txt", 1024, cred=CRED,
    )
    assert _parse_errors(script) == []


def test_parse_guest_list_dir(monkeypatch, parsed_ps):
    script = _collect(
        monkeypatch, filetransfer.guest_list_dir, ROOTED, "vm1",
        r"C:\g-read", cred=CRED,
    )
    assert _parse_errors(script) == []
