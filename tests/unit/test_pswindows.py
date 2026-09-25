"""pswindows tests: quoting helpers, secret transport, real PS 5.1 behavior.

The real-PowerShell tests validate LOCAL Windows PowerShell behavior only —
they never touch Hyper-V or any VM.
"""

import base64
import subprocess

import pytest

from hyperv_mcp import pswindows
from hyperv_mcp.config import Config

SECRET = "S3cr3t-På§s'w`\"d$中文"


def _ps_available() -> bool:
    try:
        subprocess.run(
            [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "-NonInteractive", "-NoProfile", "-Command", "$null"],
            capture_output=True, timeout=60, check=False,
        )
        return True
    except OSError:
        return False


# These tests exercise real local PowerShell 5.1 behavior (no Hyper-V); they
# are skipped cleanly on hosts/CI images without Windows PowerShell.
pytestmark = pytest.mark.skipif(not _ps_available(), reason="Windows PowerShell not available")


@pytest.fixture(autouse=True)
def _init_pswindows():
    from hyperv_mcp import credentials

    pswindows.init(Config(max_output_bytes=1024 * 1024), credentials.redact)
    yield


# ---------------------------------------------------------------------------
# quoting helpers (hostile strings)
# ---------------------------------------------------------------------------

def test_ps_quote_doubles_single_quotes():
    assert pswindows.ps_quote("it's") == "'it''s'"
    assert pswindows.ps_quote("a'b'c") == "'a''b''c'"
    assert pswindows.ps_quote("$(calc)") == "'$(calc)'"


def test_ps_quote_hostile_roundtrip_in_real_ps():
    """The quoted literal must round-trip through real PowerShell."""
    for hostile in ["it's", "$(calc)", "`n", "a;b", '${env:PATH}', "\u4e2d\u6587"]:
        result = pswindows.run_ps(f"Write-Output {pswindows.ps_quote(hostile)}", timeout_s=60)
        assert result.ok(), result.stderr
        assert result.stdout == hostile, (hostile, result.stdout)


def test_ps_wildcard_escape_matches_wildcardpattern_escape():
    ref = pswindows.run_ps(
        "[System.Management.Automation.WildcardPattern]::Escape('a*[b]?`c')", timeout_s=30
    )
    mine = pswindows.ps_wildcard_escape("a*[b]?`c")
    assert ref.stdout == mine, (ref.stdout, mine)


def test_ps_name_is_wildcard_inert_quoted():
    out = pswindows.ps_name('vm*[1]?')
    assert out == "'vm`*`[1`]`?'"


def test_ps_native_args_direct_form():
    argv = pswindows.ps_native_args(["/dbgsettings", "net", "", 'has "quote"', "a b"])
    assert argv == "'/dbgsettings' 'net' '' 'has \"quote\"' 'a b'"


def test_encode_command_no_secret_in_blob():
    """F1 regression: the encoded command must not contain the secret."""
    script = "$pw = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadLine()))"
    blob = pswindows.encode_command(pswindows._PS_PIN + script)
    decoded = base64.b64decode(blob).decode("utf-16-le")
    assert SECRET not in decoded
    assert SECRET not in blob


# ---------------------------------------------------------------------------
# real PowerShell runs (local only)
# ---------------------------------------------------------------------------

def test_run_ps_echo():
    result = pswindows.run_ps("Write-Output 'hello-hardened'", timeout_s=60)
    assert result.ok()
    assert result.stdout == "hello-hardened"
    assert result.returncode == 0
    assert result.duration_ms >= 0


def test_run_ps_utf8_output():
    result = pswindows.run_ps("Write-Output 'caf\u00e9-\u4e2d\u6587'", timeout_s=60)
    assert result.ok()
    assert result.stdout == "caf\u00e9-\u4e2d\u6587"


def test_run_ps_error_exit_code():
    result = pswindows.run_ps("Write-Error 'boom' -ErrorAction Stop", timeout_s=60)
    assert not result.ok()
    assert result.returncode == 1


def test_run_ps_stdin_secret_roundtrip():
    """Password rides stdin as UTF-8 base64 and survives unicode/metachars."""
    script = (
        "$pw = [System.Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String([Console]::In.ReadLine())); "
        "Write-Output ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pw)))"
    )
    result = pswindows.run_ps(script, timeout_s=60, stdin_b64=pswindows.utf8_b64(SECRET))
    assert result.ok(), result.stderr
    assert base64.b64decode(result.stdout).decode("utf-8") == SECRET


def test_run_ps_secret_not_in_argv(monkeypatch):
    """F1 regression at the transport layer: argv carries only the encoded
    blob (secret-free); the secret arrives via stdin."""
    seen = {}

    real_popen = subprocess.Popen

    def recording_popen(argv, *a, **kw):
        seen["argv"] = list(argv)
        seen["input"] = kw.get("input")
        return real_popen(argv, *a, **kw)

    monkeypatch.setattr(pswindows.subprocess, "Popen", recording_popen)
    script = "$x = [Console]::In.ReadLine(); Write-Output 'done'"
    result = pswindows.run_ps(script, timeout_s=60, stdin_b64=pswindows.utf8_b64(SECRET))
    assert result.ok()
    blob = seen["argv"][seen["argv"].index("-EncodedCommand") + 1]
    decoded = base64.b64decode(blob).decode("utf-16-le")
    assert SECRET not in decoded
    assert SECRET not in " ".join(seen["argv"])
    # stdin delivery is proven by test_run_ps_stdin_secret_roundtrip; here the
    # guarantee under test is argv/blob secrecy only.


def test_run_ps_timeout_reports_and_kills():
    result = pswindows.run_ps("Start-Sleep -Seconds 45", timeout_s=2)
    assert result.timed_out
    assert result.returncode is None


def test_run_ps_timeout_under_bound():
    import time
    start = time.monotonic()
    pswindows.run_ps("Start-Sleep -Seconds 45", timeout_s=2)
    assert time.monotonic() - start < 15  # tree killed, not waited out


def test_check_result_raises_on_failure():
    from hyperv_mcp import pswindows as pw

    bad = pw.PSResult(stderr="NotAuthorized", returncode=1)
    with pytest.raises(RuntimeError, match="NotAuthorized"):
        pw.check_result(bad, "ctx")
    timed = pw.PSResult(timed_out=True)
    with pytest.raises(RuntimeError, match="timed out"):
        pw.check_result(timed, "ctx")


def test_redaction_applied_to_output():
    from hyperv_mcp import credentials

    credentials.registry().register(SECRET)
    result = pswindows.run_ps(
        f"Write-Output {pswindows.ps_quote(SECRET)}", timeout_s=60
    )
    # The secret was registered; even direct echo is scrubbed.
    assert SECRET not in result.stdout
    assert "***REDACTED***" in result.stdout


def test_clixml_stderr_decoded_to_plain_text():
    """Regression from the first real-Hyper-V integration run: with
    -EncodedCommand, stderr errors serialize as CLIXML; error detail must
    arrive human-readable. Fixture is the real captured Start-VM failure."""
    from hyperv_mcp.pswindows import _decode_clixml

    nl = chr(10)
    captured = (
        "#< CLIXML" + nl
        + '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/'
        + 'powershell/2004/04"><S S="Error">Start-VM : \'ZAC\' failed to start.'
        + "_x000D__x000A_</S><S S=\"Error\">Could not initialize memory: There is not "
        + 'enough space on the disk. (0x80070070)._x000D__x000A_</S></Objs>'
    )
    decoded = _decode_clixml(captured)
    assert not decoded.startswith("#< CLIXML")
    assert "<Objs" not in decoded
    assert "Start-VM : 'ZAC' failed to start." in decoded
    assert "0x80070070" in decoded
    # non-CLIXML stderr passes through untouched
    assert _decode_clixml("plain error text") == "plain error text"
