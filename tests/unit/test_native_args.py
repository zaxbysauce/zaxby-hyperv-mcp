"""PS 5.1 native-argument binding matrix — real PowerShell, no Hyper-V.

Pins the empirically verified behavior of array-form native calls
(`& 'exe' @('a','b')`) for the argument shapes guest_run must support.
"""


import pytest

from hyperv_mcp import pswindows
from hyperv_mcp.config import Config

pytestmark = pytest.mark.skipif(
    not __import__("os").path.isfile(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    reason="Windows PowerShell not available",
)

PROBE_ARGS_PS1 = r"""param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Write-Output ("ARGCOUNT=" + $Rest.Count)
$i = 0
foreach ($a in $Rest) {
  Write-Output ("ARG[$i]b64=" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($a)))
  $i++
}
"""


@pytest.fixture()
def probe_script(tmp_path):
    p = tmp_path / "probe-args.ps1"
    p.write_text(PROBE_ARGS_PS1, encoding="utf-8-sig")
    return p


def _run_native(probe_script, args):
    pswindows.init(Config())
    # Direct form: PS 5.1 concatenates inline arrays @('a','b') into one
    # argument, so the helper emits separately-quoted arguments.
    argv_list = " ".join(pswindows.ps_quote(a) for a in args)
    script = f"& {pswindows.ps_quote(str(probe_script))} {argv_list}".strip()
    result = pswindows.run_ps(script, timeout_s=60)
    assert result.ok(), result.stderr
    out = {}
    for line in result.stdout.splitlines():
        if line.startswith("ARGCOUNT="):
            out["count"] = int(line.split("=")[1])
        elif line.startswith("ARG["):
            idx = int(line.split("[")[1].split("]")[0])
            out.setdefault("args", {})[idx] = line.split("b64=")[1]
    return out


def test_empty_argument_survives_in_multi(probe_script):
    """The historically lossy case: empty string among several arguments."""
    out = _run_native(probe_script, ["first", "", "last"])
    assert out["count"] == 3
    import base64
    assert base64.b64decode(out["args"][1]).decode("utf-8") == ""


def test_empty_string_argument_survives(probe_script):
    out = _run_native(probe_script, [""])
    assert out["count"] == 1
    assert out["args"][0] == ""


def test_embedded_double_quote_survives(probe_script):
    out = _run_native(probe_script, ['he said "hi"'])
    assert out["count"] == 1
    import base64
    assert base64.b64decode(out["args"][0]).decode("utf-8") == 'he said "hi"'


def test_spaces_and_unicode_survive(probe_script):
    out = _run_native(probe_script, ["a b c", "中文-é"])
    assert out["count"] == 2
    import base64
    assert base64.b64decode(out["args"][0]).decode("utf-8") == "a b c"
    assert base64.b64decode(out["args"][1]).decode("utf-8") == "中文-é"


def test_bracket_wildcards_survive(probe_script):
    out = _run_native(probe_script, ["a*[b]?c"])
    assert out["count"] == 1
    import base64
    assert base64.b64decode(out["args"][0]).decode("utf-8") == "a*[b]?c"


def test_multiple_args_order_preserved(probe_script):
    out = _run_native(probe_script, ["one", "two", "three"])
    assert out["count"] == 3
    import base64
    assert base64.b64decode(out["args"][2]).decode("utf-8") == "three"
