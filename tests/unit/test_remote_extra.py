"""Phase-4 coverage additions for remote-host mode (issue #43, trace 12).

Beyond the frozen floor (tests/unit/test_remote_*.py): the two-secret stdin
param mapping, the cfg-carried mode source across consecutive calls, the
banner line in unrestricted remote mode, the remote twin of the type_text
CLIXML-leak pin, adversarial hostname config rejection, and a real-parser
lane over composed remote scripts. No real Hyper-V or network is touched.
"""

import importlib
import json
import subprocess
import sys

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import console, guestexec, lifecycle, pswindows
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.credentials import CredentialSet

HOST = "nuc01"
WRAP = f"Invoke-Command -ComputerName '{HOST}'"
GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
CRED = CredentialSet("Administrator", "placeholder-pass")


class FakePS:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []
        self.kwargs = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if "Msvm_ComputerSystem" in script and "$vmTarget" in script:
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if self.responses:
            item = self.responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return pswindows.PSResult(stdout="[]", returncode=0)


def _remote_cfg(**extra) -> Config:
    doc = {"hyperv": {"host": HOST}}
    doc.update(extra)
    return Config.from_dict(doc)


@pytest.fixture(autouse=True)
def _no_ambient_host_credentials(monkeypatch):
    for var in ("HYPERV_HOST_USERNAME", "HYPERV_HOST_PASSWORD", "HYPERV_HOST_PASSWORD_FILE"):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# two-secret stdin mapping: host password stays LOCAL, guest payload is $__p0
# ---------------------------------------------------------------------------

def test_two_secret_param_mapping(monkeypatch, tmp_path):
    pw_file = tmp_path / "host-pw.txt"
    pw_file.write_text("host-pw-123", encoding="utf-8")
    monkeypatch.setenv("HYPERV_HOST_USERNAME", "lab\\admin")
    monkeypatch.setenv("HYPERV_HOST_PASSWORD_FILE", str(pw_file))

    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 0, "stdout": "", "stderr": ""}), returncode=0,
    )])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run_ps(
        _remote_cfg(allowed_vm_patterns=["test-*"]), "test-vm", "Get-Date", cred=CRED,
    )

    envelope = fake.scripts[1]
    assert WRAP in envelope
    reads = envelope.count("[Console]::In.ReadLine()")
    assert reads == 2, "host password line + guest payload line, both local"
    first_wrap = envelope.index(WRAP)
    last_read = envelope.rindex("[Console]::In.ReadLine()")
    assert last_read < first_wrap, "both reads happen in the local preamble"
    assert "-Credential $__hostcred" in envelope, "host hop carries the local cred"
    arg_at = envelope.index("-ArgumentList")
    assert "$__hostpw" not in envelope[arg_at:], "host password never forwarded"
    assert "$__p0" in envelope[arg_at:], "guest payload crosses as the parameter"
    assert "$secRaw = $__p0" in envelope, "guest credential consumes the param"
    # stdin composition: host line first, guest payload second
    stdin = fake.kwargs[1].get("stdin_b64")
    assert stdin is not None
    lines = stdin.split("\n")
    assert len(lines) == 2
    import base64
    assert base64.b64decode(lines[0]).decode("utf-8") == "host-pw-123"
    assert base64.b64decode(lines[1]).decode("utf-8") == CRED.password


# ---------------------------------------------------------------------------
# mode source is the caller's cfg: remote then local then remote, one module
# ---------------------------------------------------------------------------

def test_mode_source_is_caller_cfg(monkeypatch):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.list_vms(_remote_cfg(unrestricted=True))     # remote
    lifecycle.list_vms(Config(unrestricted=True))          # local
    lifecycle.list_vms(_remote_cfg(unrestricted=True))     # remote again
    wraps = [WRAP in s for s in fake.scripts]
    assert wraps == [True, False, True], (
        "the wrap decision must follow each call's cfg, not any module global"
    )


# ---------------------------------------------------------------------------
# banner in unrestricted remote mode (the lab layout; prints before the
# unrestricted early return)
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_server():
    def make(environ):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def test_banner_names_target_in_unrestricted_mode(tmp_path, fresh_server, capsys):
    p = tmp_path / "unrestricted-remote.json"
    p.write_text(json.dumps({"unrestricted": True, "hyperv": {"host": HOST}}), encoding="utf-8")
    fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    err = capsys.readouterr().err
    assert "Hyper-V target:" in err
    assert HOST in err
    assert "UNRESTRICTED" in err  # the early-return path was taken; line still printed


# ---------------------------------------------------------------------------
# type_text remote twin of the CLIXML-leak pin
# ---------------------------------------------------------------------------

def test_type_text_remote_secret_not_in_script(monkeypatch):
    secret = "S3cr3t-Typed-P4ss!"
    fake = FakePS([pswindows.PSResult(stdout="e953c649-dcab-438d-9a54-3af74a82b624", returncode=0),
                   pswindows.PSResult(stdout="RC=0 CHUNK=1/1", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.type_text(_remote_cfg(unrestricted=True), "test-vm", secret)
    script = fake.scripts[-1]
    assert secret not in script
    assert fake.kwargs[-1]["stdin_b64"] == pswindows.utf8_b64(secret)
    assert WRAP in script
    assert script.count("[Console]::In.ReadLine()") == 1
    assert script.index("[Console]::In.ReadLine()") < script.index(WRAP)
    assert "-ArgumentList" in script and "$__p0" in script


# ---------------------------------------------------------------------------
# adversarial hostname configs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_host", [
    "nuc'; Invoke-Expression 'calc", 'nuc01; rm -rf', "nuc 01", "nuc'--", "a|b",
])
def test_adversarial_hostname_rejected(bad_host):
    with pytest.raises(ConfigError):
        Config.from_dict({"hyperv": {"host": bad_host}})


# ---------------------------------------------------------------------------
# real-parser lane over composed remote scripts (PS 5.1 syntax validation)
# ---------------------------------------------------------------------------

def _parse_errors(script: str) -> list[str]:
    probe = (
        "$errs = $null; "
        "[System.Management.Automation.Language.Parser]::ParseInput("
        "[Console]::In.ReadToEnd(), [ref]$null, [ref]$errs) | Out-Null; "
        "if ($errs) { $errs | ForEach-Object { $_.Message } } else { 'PARSE-OK' }"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", probe],
        input=script, capture_output=True, text=True, timeout=60,
    )
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def _capture_put_remote(monkeypatch, tmp_path):
    from hyperv_mcp import filetransfer
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
    src_file = src / "tool.exe"
    src_file.write_bytes(b"MZ")
    fake = FakePS([pswindows.PSResult(stdout=json.dumps({
        "ok": True, "bytes_copied": 2, "bytes_local": 2, "bytes_remote": 2,
        "sha256_local": None, "sha256_remote": None,
    }), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        cfg, "test-vm", str(src_file), r"C:\g-write\tool.exe",
        confirm=True, verify=True, cred=CRED,
    )
    return fake.scripts[1]


def test_composed_remote_scripts_parse(monkeypatch, tmp_path):
    pytest.importorskip("subprocess")
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.list_vms(_remote_cfg(unrestricted=True))                          # host op
    guestexec.guest_run_ps(                                                     # PS-Direct envelope
        _remote_cfg(allowed_vm_patterns=["test-*"]), "test-vm", "Get-Date", cred=CRED,
    )
    put_script = _capture_put_remote(monkeypatch, tmp_path)                     # mixed transfer
    scripts = [fake.scripts[0], fake.scripts[1], put_script]
    for script in scripts:
        assert WRAP in script
        problems = _parse_errors(script)
        assert problems == ["PARSE-OK"], problems[:5]


def test_composer_mechanics_execute_under_real_powershell(monkeypatch, tmp_path):
    """Execution lane for the composed preamble + scriptblock param binding
    (the runtime-semantics class the parse lane cannot catch).

    The full composed script executes under real powershell.exe with the
    WS-Man transport keyword removed (`-ComputerName ... -Credential ...` →
    plain Invoke-Command): everything else is byte-identical to production —
    the two-line stdin order (host password first, guest payload second),
    the base64/SecureString/PSCredential decode chain, the param($__p0)
    binding, and -ArgumentList forwarding. The WS-Man transport leg itself
    stays integration-gated (no WinRM listener on the unit-test host).
    """
    pw_file = tmp_path / "host-pw.txt"
    pw_file.write_text("host-pw-123", encoding="utf-8")
    monkeypatch.setenv("HYPERV_HOST_USERNAME", "lab\\admin")
    monkeypatch.setenv("HYPERV_HOST_PASSWORD_FILE", str(pw_file))

    body = (
        guestexec.psdirect_prefix(CRED, _remote_cfg())
        + "\n$payload_ok = ($cred.GetNetworkCredential().Password -eq '" + CRED.password + "')\n"
        + "$hostcred_ok = ($null -ne $__hostcred)\n"
        # Runner-side diagnostics: distinguish empty stdin lines from
        # per-statement errors (statement-abort-continue lets the script
        # exit 0 with nulls — the CI failure class observed on round 4).
        + "$p0_len = \"$($__p0)\".Length\n"
        + "$err0 = if ($Error.Count) { $Error[0].ToString() } else { '' }\n"
        + "[PSCustomObject]@{ user = $cred.UserName; payload_ok = $payload_ok; "
        "hostcred_ok = $hostcred_ok; p0_len = $p0_len; err0 = $err0 } | ConvertTo-Json -Compress\n"
    )
    script, stdin = pswindows.compose_remote(
        _remote_cfg(), body, payload_lines=1, stdin_b64=pswindows.utf8_b64(CRED.password),
    )
    # Drop only the transport keywords; keep the binding shape byte-identical.
    local = script.replace(
        f"Invoke-Command -ComputerName '{HOST}' -Credential $__hostcred -ScriptBlock {{",
        "Invoke-Command -ScriptBlock {",
    )
    assert local != script, "transport token must be present to strip"
    encoded = pswindows.encode_command(pswindows._PS_PIN + local)
    # Spawn EXACTLY like production pswindows.run_ps: binary stdin via
    # communicate (not text=True), eliminating the text-mode wrapper as a
    # variable between hosts.
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        input=((stdin or "") + "\n").encode("ascii"),
        capture_output=True, timeout=60,
    )
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")
    assert proc.returncode == 0, stderr[-400:]
    import json as _json
    lines = [ln for ln in stdout.strip().splitlines() if ln.strip()]
    result = None
    for ln in reversed(lines):
        try:
            candidate = _json.loads(ln)
        except ValueError:
            continue
        if isinstance(candidate, dict) and "user" in candidate:
            result = candidate
            break
    assert result is not None, (
        f"composed output JSON not found; stdout tail: {stdout[-400:]!r}; "
        f"stderr tail: {stderr[-400:]!r}"
    )
    diag = f"full result: {result}; stdout tail: {stdout[-200:]!r}; stderr tail: {stderr[-200:]!r}"
    assert result["user"] == CRED.username, diag
    assert result["payload_ok"] is True, f"guest payload crossed as $__p0; {diag}"
    assert result["hostcred_ok"] is True, f"host password decoded locally; {diag}"


# ---------------------------------------------------------------------------
# explicit host-credential mode: EVERY choke must feed the composed stdin
# (review round 1 finding 1 — vmident/media/filetransfer dropped it, so the
# preamble's host-password ReadLine hit EOF and put/get fed the GUEST
# password as the host line)
# ---------------------------------------------------------------------------

def _set_host_creds(monkeypatch, tmp_path):
    pw_file = tmp_path / "host-pw.txt"
    pw_file.write_text("host-pw-123", encoding="utf-8")
    monkeypatch.setenv("HYPERV_HOST_USERNAME", "lab\\admin")
    monkeypatch.setenv("HYPERV_HOST_PASSWORD_FILE", str(pw_file))
    return "host-pw-123"


def test_vmident_choke_feeds_host_password_stdin(monkeypatch, tmp_path):
    host_pw = _set_host_creds(monkeypatch, tmp_path)
    from hyperv_mcp import vmident
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    vmident.resolve(_remote_cfg(allowed_vm_patterns=["test-*"]), "test-vm")
    script, kwargs = fake.scripts[0], fake.kwargs[0]
    assert WRAP in script
    assert "$__hostpwRaw = [Console]::In.ReadLine()" in script
    assert "-Credential $__hostcred" in script
    assert "[Console]::In.ReadLine()" not in script.split(WRAP, 1)[1], (
        "no payload read may live inside the remote block"
    )
    stdin = kwargs.get("stdin_b64")
    assert stdin is not None, "choke must feed the composed stdin"
    import base64
    assert base64.b64decode(stdin.split("\n")[0]).decode("utf-8") == host_pw


def test_media_choke_feeds_host_password_stdin(monkeypatch, tmp_path):
    host_pw = _set_host_creds(monkeypatch, tmp_path)
    from hyperv_mcp import media
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    media.vm_disk_list(_remote_cfg(allowed_vm_patterns=["test-*"]), "test-vm")
    script, kwargs = fake.scripts[1], fake.kwargs[1]  # [0] is vmident resolve
    assert WRAP in script and "-Credential $__hostcred" in script
    stdin = kwargs.get("stdin_b64")
    assert stdin is not None
    import base64
    assert base64.b64decode(stdin).decode("utf-8") == host_pw


def test_guest_put_host_creds_two_line_stdin_and_hop_argumentlist(monkeypatch, tmp_path):
    host_pw = _set_host_creds(monkeypatch, tmp_path)
    src = tmp_path / "hs"
    src.mkdir()
    dst = tmp_path / "hd"
    dst.mkdir()
    cfg = Config.from_dict({
        "hyperv": {"host": HOST},
        "allowed_vm_patterns": ["test-*"],
        "host_read_roots": [str(src)], "host_write_roots": [str(dst)],
        "guest_read_roots": ["C:\\g-read"], "guest_write_roots": ["C:\\g-write"],
    })
    cfg.destructive.guest_write = True
    cfg.destructive.require_confirm = False
    src_file = src / "tool.exe"
    src_file.write_bytes(b"MZ")
    fake = FakePS([pswindows.PSResult(stdout=json.dumps({
        "ok": True, "bytes_copied": 2, "bytes_local": 2, "bytes_remote": 2,
        "sha256_local": None, "sha256_remote": None,
    }), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    from hyperv_mcp import filetransfer
    filetransfer.guest_put(
        cfg, "test-vm", str(src_file), r"C:\g-write\tool.exe",
        confirm=True, verify=True, cred=CRED,
    )
    script, kwargs = fake.scripts[1], fake.kwargs[1]
    reads = [i for i, _ in enumerate(script.splitlines()) if "[Console]::In.ReadLine()" in _]
    assert len(reads) == 2, "host-password line + guest payload line"
    wrap_line = next(i for i, _ in enumerate(script.splitlines()) if WRAP in _)
    assert max(reads) < wrap_line, "both reads live in the local preamble"
    assert "-Credential $__hostcred" in script
    # HOP-level -ArgumentList forwarding (the inner -ArgumentList $enc / session
    # legs must not satisfy this pin — pin the exact forwarding token):
    assert "-ArgumentList $__p0" in script, (
        "the hop must forward the guest payload as $__p0 (M2 showed the "
        "frozen pin alone cannot distinguish inner -ArgumentList)"
    )
    import base64
    stdin_lines = kwargs["stdin_b64"].split("\n")
    assert len(stdin_lines) == 2
    assert base64.b64decode(stdin_lines[0]).decode("utf-8") == host_pw
    assert base64.b64decode(stdin_lines[1]).decode("utf-8") == CRED.password


def test_guest_get_host_creds_two_line_stdin(monkeypatch, tmp_path):
    """Round-2 pin: guest_get's composed branch must feed _run_transfer the
    composed two-line stdin — deleting `composed_stdin=remote_stdin`
    (filetransfer guest_get) left the whole suite green in review round 2's
    mutation (e), silently reintroducing the round-1 Critical on the get
    path (guest password consumed as the host line)."""
    host_pw = _set_host_creds(monkeypatch, tmp_path)
    dst = tmp_path / "hd"
    dst.mkdir()
    cfg = Config.from_dict({
        "hyperv": {"host": HOST},
        "allowed_vm_patterns": ["test-*"],
        "host_read_roots": [str(tmp_path)], "host_write_roots": [str(dst)],
        "guest_read_roots": ["C:\\g-read"], "guest_write_roots": ["C:\\g-write"],
    })
    fake = FakePS([pswindows.PSResult(stdout=json.dumps({
        "ok": True, "bytes_copied": 2, "bytes_local": 2, "bytes_remote": 2,
        "sha256_local": None, "sha256_remote": None,
    }), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    from hyperv_mcp import filetransfer
    filetransfer.guest_get(
        cfg, "test-vm", r"C:\g-read\src.bin", str(dst / "out.bin"),
        verify=True, cred=CRED,
    )
    script, kwargs = fake.scripts[1], fake.kwargs[1]
    assert WRAP in script
    assert "-Credential $__hostcred" in script
    assert "-ArgumentList $__p0" in script
    import base64
    stdin_lines = kwargs["stdin_b64"].split("\n")
    assert len(stdin_lines) == 2, (
        "get must ride the composed two-line stdin: host password first, "
        "guest payload second"
    )
    assert base64.b64decode(stdin_lines[0]).decode("utf-8") == host_pw
    assert base64.b64decode(stdin_lines[1]).decode("utf-8") == CRED.password


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-q"]))
