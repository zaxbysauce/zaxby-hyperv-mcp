"""Parse-validate every NEW generated PowerShell template with the real PS 5.1
parser (0.3.0 surfaces: diagnostics, repair, guest jobs, recovery, relay,
evidence UIA).

Same discipline as test_script_parse.py: [System.Management.Automation.
Language.Parser]::ParseInput reports syntax errors WITHOUT executing
anything. Per the plan (critic R2 finding 3 / R3 N1), this covers EVERY
captured script from every flow of the eleven new tools — including the
job wrapper .ps1 (double-encoded) and the recovery verify leg — not just
the first script each flow emits.
"""

import base64
import json
import re

import pytest

from hyperv_mcp import (
    diagnostics,
    evidence,
    guestjobs,
    pswindows,
    relay,
    repair,
)
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")
UNRESTRICTED = Config(unrestricted=True)

_REAL_RUN_PS = pswindows.run_ps  # saved before any monkeypatching

_ENC_RE = re.compile(r"\$enc\d? = '([A-Za-z0-9+/=]+)'")


class Recorder:
    """Captures generated scripts; returns canned/empty results."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        item = self.responses.pop(0) if self.responses else None
        if isinstance(item, Exception):
            raise item
        stdout = item if isinstance(item, str) else ""
        return pswindows.PSResult(stdout=stdout, returncode=0)


@pytest.fixture(scope="module")
def parsed_ps():
    import os

    if not os.path.isfile(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
        pytest.skip("Windows PowerShell not available")
    pswindows.init(UNRESTRICTED)
    yield


def _parse_errors(script: str) -> list[str]:
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


def _inner_payloads(script: str) -> list[str]:
    """Decode the b64 inner payloads embedded in a host script (recursive:
    the job start script embeds the wrapper inside its own payload)."""
    out: list[str] = []
    for match in _ENC_RE.finditer(script):
        try:
            decoded = base64.b64decode(match.group(1)).decode("utf-8")
        except Exception:
            continue
        out.append(decoded)
        out.extend(_inner_payloads(decoded))
    return out


def _parse_script_and_payloads(script: str) -> list[str]:
    errors: list[str] = []
    for text in [script, *_inner_payloads(script)]:
        errors.extend(f"[{i}] {e}" for i, e in enumerate(_parse_errors(text)))
    return errors


def _collect_all(monkeypatch, fn, *args, **kwargs) -> list[str]:
    rec = Recorder(kwargs.pop("responses", None))
    monkeypatch.setattr(pswindows, "run_ps", rec)
    try:
        fn(*args, **kwargs)
    except Exception:
        pass  # capture-only; canned results rarely satisfy full flows
    assert rec.scripts, f"{getattr(fn, '__name__', fn)} produced no script"
    return rec.scripts


# -- diagnostics (host leg + sectioned guest probe) --------------------------


def test_parse_diagnose_flows(parsed_ps, monkeypatch):
    host = json.dumps({"state": "Running", "vm_id": "x", "uptime_s": 1,
                       "memory_mb": 1, "cpu_usage": 1})
    guest = json.dumps({"identity": {}, "ip_addresses": {}, "ssh": {}, "winrm": {}, "firewall": {}})
    scripts = _collect_all(
        monkeypatch, diagnostics.diagnose_vm_access, UNRESTRICTED, "test-vm",
        cred=CRED, responses=[host, guest],
    )
    assert len(scripts) == 2
    for script in scripts:
        assert _parse_script_and_payloads(script) == []


# -- repair (dry run + all three apply script kinds + verify legs) ------------


def test_parse_repair_flows(parsed_ps, monkeypatch):
    host = json.dumps({"state": "Running", "vm_id": "x", "uptime_s": 1,
                       "memory_mb": 1, "cpu_usage": 1})
    broken = json.dumps({
        "identity": {}, "ip_addresses": {"ipv4": [{"address": "10.0.0.5"}], "ipv6": []},
        "ssh": {"service": {"present": True, "status": "Stopped"},
                "config_listen": ["192.168.50.20"], "listeners": [{"address": "192.168.50.20", "port": 22}]},
        "winrm": {"service": {"present": True, "status": "Stopped"}, "listeners": [], "tcp_listeners": []},
        "firewall": {"ssh22_allowed": False, "winrm5985_allowed": False},
    })
    healthy = json.dumps({
        "identity": {}, "ip_addresses": {"ipv4": [{"address": "10.0.0.5"}], "ipv6": []},
        "ssh": {"service": {"present": True, "status": "Running"}, "config_listen": ["0.0.0.0"], "listeners": []},
        "winrm": {"service": {"present": True, "status": "Running"}, "listeners": [], "tcp_listeners": []},
        "firewall": {"ssh22_allowed": True, "winrm5985_allowed": True},
    })
    scripts = _collect_all(
        monkeypatch, repair.repair_guest_access, UNRESTRICTED, "test-vm",
        apply=True, confirm=True, cred=CRED,
        responses=[host, broken, '{"service":"sshd"}', '{"backup":"b","replaced":1}',
                   '{"port":"22","enabled_rules":[]}', host, healthy],
    )
    # 2 diagnose legs + 5 apply legs (sshd stopped, stale binding, WinRM
    # stopped, ssh firewall, winrm firewall) + 2 verify legs.
    assert len(scripts) == 9
    for script in scripts:
        assert _parse_script_and_payloads(script) == []


def test_parse_repair_dry_run(parsed_ps, monkeypatch):
    host = json.dumps({"state": "Running", "vm_id": "x", "uptime_s": 1,
                       "memory_mb": 1, "cpu_usage": 1})
    guest = json.dumps({"ssh": {"service": {"present": True, "status": "Stopped"}}})
    scripts = _collect_all(
        monkeypatch, repair.repair_guest_access, UNRESTRICTED, "test-vm",
        cred=CRED, responses=[host, guest],
    )
    for script in scripts:
        assert _parse_script_and_payloads(script) == []


# -- guest jobs (start script + wrapper .ps1 + status/output/stop) ------------


def test_parse_job_start_and_wrapper(parsed_ps, monkeypatch):
    guestjobs.clear_registry_for_tests()
    try:
        scripts = _collect_all(
            monkeypatch, guestjobs.job_start, UNRESTRICTED, "test-vm",
            "sqlprobe.exe", ["--long"], "C:\\work", cred=CRED,
            responses=[json.dumps({"pid": 100, "job_dir": "C:\\t\\j"})],
        )
        # scripts[0] host wrapper; payload level 1 = start script; level 2 = wrapper .ps1.
        payloads = _inner_payloads(scripts[0])
        assert payloads, "start script payload must decode"
        wrapper = payloads[-1]
        assert "Split-Path" in wrapper  # sanity: the innermost is the wrapper
        assert _parse_errors(wrapper) == []
        assert _parse_script_and_payloads(scripts[0]) == []
    finally:
        guestjobs.clear_registry_for_tests()


@pytest.fixture()
def _job():
    guestjobs.clear_registry_for_tests()
    guestjobs._register({
        "job_id": "abc123def456", "vm_name": "test-vm", "pid": 4242,
        "command": "x.exe", "args": [], "job_dir": "C:\\t\\hyperv-mcp-job-abc123def456",
        "out_path": "C:\\t\\hyperv-mcp-job-abc123def456\\stdout.log",
        "err_path": "C:\\t\\hyperv-mcp-job-abc123def456\\stderr.log",
        "exit_path": "C:\\t\\hyperv-mcp-job-abc123def456\\exitcode.txt",
        "started_at": "2026-01-01T00:00:00Z", "cred": CRED, "stopped": False,
    })
    yield
    guestjobs.clear_registry_for_tests()


def test_parse_job_status_script(parsed_ps, monkeypatch, _job):
    scripts = _collect_all(
        monkeypatch, guestjobs.job_status, UNRESTRICTED, "abc123def456",
        responses=[json.dumps({"status": "running", "process_name": "x"})],
    )
    for script in scripts:
        assert _parse_script_and_payloads(script) == []


def test_parse_job_output_script(parsed_ps, monkeypatch, _job):
    scripts = _collect_all(
        monkeypatch, guestjobs.job_output, UNRESTRICTED, "abc123def456",
        tail_bytes=4096,
        responses=[json.dumps({"head_hex": "", "tail_b64": "", "size": 0, "truncated": False})] * 2,
    )
    for script in scripts:
        assert _parse_script_and_payloads(script) == []


def test_parse_job_stop_script(parsed_ps, monkeypatch, _job):
    scripts = _collect_all(
        monkeypatch, guestjobs.job_stop, UNRESTRICTED, "abc123def456",
        responses=[json.dumps({"stopped": True})],
    )
    for script in scripts:
        assert _parse_script_and_payloads(script) == []


# -- recovery (wait loop + verify leg) -----------------------------------------


def test_parse_recovery_script(parsed_ps, monkeypatch):
    payload = json.dumps({"ps_direct": {"available": True, "attempts": 1, "error": ""},
                          "services": [], "processes": []})
    scripts = _collect_all(
        monkeypatch, diagnostics.wait_guest_recovery, UNRESTRICTED, "test-vm",
        ["sshd"], ["cdpclient"], timeout_s=5, interval_s=1, cred=CRED,
        responses=[payload],
    )
    for script in scripts:
        assert _parse_script_and_payloads(script) == []


# -- relay (per-request forward script) ----------------------------------------


def test_parse_relay_forward_script(parsed_ps):
    for method in ("GET", "POST"):
        script = relay._forward_script(
            9222, method, "/json/version",
            {"Accept": "application/json", "Content-Type": "application/json"},
            b"{}" if method == "POST" else b"",
        )
        assert _parse_errors(script) == []


# -- evidence (UIA walker) ------------------------------------------------------


def test_parse_evidence_uia_script(parsed_ps):
    assert _parse_errors(evidence._uia_script(3, 200)) == []
    assert _parse_errors(evidence._uia_script(6, 500)) == []


# -- execution lane (relay forward) ---------------------------------------------
# The parse lane above proves SYNTAX; the mocked run_ps suites prove PYTHON
# logic. Neither can catch runtime-semantic errors in the generated script
# itself (the shipped header-b64 bug 502'd every relay request while both
# lanes stayed green). This lane EXECUTES the generated inner script on real
# PowerShell against a live local HTTP endpoint.


def test_forward_script_executes_on_real_ps(parsed_ps, tmp_path):
    import base64 as _b64
    import json as _json
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Stub(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"Browser": "Chrome/126"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        inner = relay._forward_script(
            port, "GET", "/json/version", {"Accept": "application/json"}, b"",
        )
        script_path = tmp_path / "forward_inner.ps1"
        script_path.write_text(inner, encoding="ascii")
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
            capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        payload = _json.loads(proc.stdout.strip())
        assert payload["status"] == 200, payload
        assert payload["content_type"] == "application/json"
        assert _json.loads(
            _b64.b64decode(payload["body_b64"]).decode("utf-8")
        )["Browser"] == "Chrome/126"
        # A decode bug would take the script's catch path and emit an error
        # payload instead of a response payload.
        assert "error" not in payload
    finally:
        server.shutdown()
        server.server_close()
