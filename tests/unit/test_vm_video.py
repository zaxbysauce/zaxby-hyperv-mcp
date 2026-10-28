"""Frozen acceptance checks for issue #44: VM video settings tools.

Contract under test (implemented in hyperv_mcp.media, wired in server.py,
new `display` policy category in config.py):

  - hyperv_vm_get_video: read-only Get-VMVideo probe, NO policy gate.
  - hyperv_mcp.vm_set_resolution: category `display`; validation then a
    single set leg whose readback reports CONFIGURED dimensions (Get-VMVideo)
    separately from OBSERVED ones (Msvm_VideoHead); an optional restart leg
    gated by destructive.stop + confirm.

These checks are the acceptance contract: on the pre-feature tree every test
fails with a stable sentinel (AttributeError on the missing media functions,
"missing tool ..." on the inventory, ConfigError on the unknown `display`
config key); after implementation they all pass. No real Hyper-V, VM, or
network is touched — pswindows.run_ps is stubbed everywhere except the c7
parse lane, which only invokes the real PowerShell parser.
"""

import asyncio
import base64
import importlib
import os

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import media, pswindows
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.policy import PolicyDenied

# Canned by-name resolution answer (vmident leg emits the bare GUID).
GUID = "12345678-1234-1234-1234-123456789abc"

# Readback for the set leg: the CONFIGURED values echo the request while the
# OBSERVED head differs (1024x768) — the pin that requested dimensions are
# never reported as observed.
READBACK = (
    '{"resolution_type": "Single", "horizontal": 1920, "vertical": 1080,'
    ' "observed_horizontal": 1024, "observed_vertical": 768}'
)
WAIT_RUNNING = '{"final_state": "Running"}'
OBSERVED_HEAD = '{"observed_horizontal": 1920, "observed_vertical": 1080}'

# Saved at import, before any monkeypatching, so the c7 parse lane can reach
# the REAL PowerShell spawn while a recorder sits on pswindows.run_ps.
_REAL_RUN_PS = pswindows.run_ps


class FakePS:
    """Records every spawned script + kwargs; serves queued PSResults.

    The vmident resolution leg (queries Msvm_ComputerSystem, emits the bare
    `$vmTarget`, and contains no ConvertTo-Json) is content-served with the
    canned GUID. The discriminator is substring-based rather than
    endswith-based so it recognizes the leg in BOTH modes: in remote mode
    every composed script carries the Invoke-Command wrapper suffix, so an
    endswith($vmTarget) predicate would never match the wrapped resolver
    (CHECK_WRONG amend of the original endswith form). The action scripts
    contain ConvertTo-Json (the readback emit), which the resolver lacks, so
    the pair stays distinguishable in local and remote compositions alike.
    """

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []
        self.kwargs = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if "Msvm_ComputerSystem" in script and "ConvertTo-Json" not in script:
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if self.responses:
            item = self.responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return pswindows.PSResult(stdout='{"ok": true}', returncode=0)


@pytest.fixture(autouse=True)
def _no_ambient_host_credentials(monkeypatch):
    for var in ("HYPERV_HOST_USERNAME", "HYPERV_HOST_PASSWORD", "HYPERV_HOST_PASSWORD_FILE"):
        monkeypatch.delenv(var, raising=False)


def _display_cfg(**extra) -> Config:
    doc = {"allowed_vm_patterns": ["test-*"], "destructive": {"display": True}}
    doc.update(extra)
    return Config.from_dict(doc)


# ---------------------------------------------------------------------------
# C1: server tool inventory
# ---------------------------------------------------------------------------

def test_c1_tool_inventory():
    """Base-RED sentinel: AssertionError 'missing tool hyperv_vm_set_resolution'."""
    try:
        mod = importlib.reload(server_module)
        mod.bootstrap({})
        tools = asyncio.run(mod.get_mcp().list_tools())
        names = {t.name for t in tools}
        assert "hyperv_vm_set_resolution" in names, "missing tool hyperv_vm_set_resolution"
        assert "hyperv_vm_get_video" in names, "missing tool hyperv_vm_get_video"
        assert len(names) == 76, f"tool inventory is {len(names)}, expected 76 (68 + issue #29's eight hyperv_ui_* tools)"
        def _schema(t):
            return getattr(t, "input_schema", None) or t.inputSchema

        by_name = {t.name: t for t in tools}
        for name in ("hyperv_vm_set_resolution", "hyperv_vm_get_video"):
            props = _schema(by_name[name]).get("properties", {})
            assert {"vm_name", "vm_id"} <= set(props), f"{name}: vm_name/vm_id params"
        set_props = _schema(by_name["hyperv_vm_set_resolution"]).get("properties", {})
        get_props = _schema(by_name["hyperv_vm_get_video"]).get("properties", {})
        assert "confirm" in set_props, "hyperv_vm_set_resolution must take confirm"
        assert "confirm" not in get_props, "hyperv_vm_get_video is read-only: no confirm"
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# C2: argument validation
# ---------------------------------------------------------------------------

def test_c2_validation(monkeypatch):
    """Base-RED sentinel: AttributeError ... no attribute 'vm_set_resolution'."""
    fn = media.vm_set_resolution
    cfg = _display_cfg()
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)

    # (a) single/maximum need dimensions: zero width or height is refused
    with pytest.raises(ValueError, match="width and height are required"):
        fn(cfg, "test-vm")
    with pytest.raises(ValueError, match="width and height are required"):
        fn(cfg, "test-vm", height=1080)
    # (c) unknown resolution_type
    with pytest.raises(ValueError, match="resolution_type must be one of"):
        fn(cfg, "test-vm", 1920, 1080, "twin")
    # (d) outside the 160..4096 bounds (both axes)
    with pytest.raises(ValueError, match="160..4096"):
        fn(cfg, "test-vm", 100, 1080)
    with pytest.raises(ValueError, match="160..4096"):
        fn(cfg, "test-vm", 1920, 5000)
    # validation precedes resolution: nothing was spawned before the refusal
    assert fake.scripts == []

    # (b) Default ignores dimensions entirely: 0x0 is accepted and the
    # Set-VMVideo line carries NO dimension parameters. (The readback emit
    # `$v.HorizontalResolution` is exempt — the pinned target is the SET
    # parameters, so the dash-prefixed forms must be absent.)
    fake = FakePS([pswindows.PSResult(stdout=READBACK, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    fn(cfg, "test-vm", width=0, height=0, resolution_type="default")
    script = fake.scripts[1]  # [0] is the vmident resolution leg
    assert "-ResolutionType Default" in script
    assert "-HorizontalResolution" not in script
    assert "-VerticalResolution" not in script

    # (e) width/height stay positional (never keyword-only)
    fake = FakePS([pswindows.PSResult(stdout=READBACK, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    fn(cfg, "test-vm", 1920, 1080, confirm=True)
    assert "-HorizontalResolution 1920" in fake.scripts[1]


# ---------------------------------------------------------------------------
# C3: policy gates (display category, restart confirm leg)
# ---------------------------------------------------------------------------

def test_c3_policy_gates(monkeypatch):
    """Base-RED sentinel: AttributeError ... no attribute 'vm_set_resolution'."""
    fn = media.vm_set_resolution
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)

    # (a) category denied by a default config (display off)
    with pytest.raises(PolicyDenied, match="category:display"):
        fn(Config(allowed_vm_patterns=["test-*"]), "test-vm", 1920, 1080)
    # (b) display on + restart without confirm: the stop-leg confirm denial
    # fires BEFORE the VM is resolved
    with pytest.raises(PolicyDenied, match="confirm=true"):
        fn(_display_cfg(), "test-vm", 1920, 1080, restart=True)
    # (c) display + stop enabled, confirm still omitted -> still denied
    cfg = Config.from_dict({
        "allowed_vm_patterns": ["test-*"],
        "destructive": {"display": True, "stop": True},
    })
    with pytest.raises(PolicyDenied, match="confirm"):
        fn(cfg, "test-vm", 1920, 1080, restart=True)
    assert fake.scripts == [], "every denial above must precede any spawn"

    # (d) display + stop + confirm=True: runs to completion, no policy error.
    # Leg order is stop -> set -> start (the host refuses Set-VMVideo on a
    # running VM, probe-verified), so the canned queue feeds the stop leg
    # first and the set readback second.
    fake.responses.extend([
        pswindows.PSResult(stdout='{"ok": true}', returncode=0),  # stop leg
        pswindows.PSResult(stdout=READBACK, returncode=0),        # set leg readback
        pswindows.PSResult(stdout='{"ok": true}', returncode=0),  # start leg
        pswindows.PSResult(stdout=WAIT_RUNNING, returncode=0),    # state wait
        pswindows.PSResult(stdout=OBSERVED_HEAD, returncode=0),   # observed head
    ])
    result = fn(cfg, "test-vm", 1920, 1080, restart=True, confirm=True)
    assert len(fake.scripts) >= 2, "the action legs must be reached"
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# C4: set-leg script emission and result shape
# ---------------------------------------------------------------------------

def test_c4_script_emission(monkeypatch):
    """Base-RED sentinel: AttributeError ... no attribute 'vm_set_resolution'."""
    fn = media.vm_set_resolution
    cfg = _display_cfg()
    fake = FakePS([pswindows.PSResult(stdout=READBACK, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    result = fn(cfg, "test-vm", 1920, 1080, "single")
    script = fake.scripts[1]  # [0] is the vmident resolution leg
    assert "-HorizontalResolution 1920" in script
    assert "-VerticalResolution 1080" in script
    assert "-ResolutionType Single" in script
    assert "-ErrorAction Stop" in script
    assert "Get-VMVideo" in script
    assert "Msvm_VideoHead" in script
    assert "[Console]::In.ReadLine()" not in script  # local mode: no stdin secrets
    assert result["ok"] is True
    assert result["horizontal"] == 1920
    assert result["vertical"] == 1080
    assert result["resolution_type"] == "Single"
    assert result["vm_name"] == "test-vm"
    assert result["effective_after_restart"] is True
    # observed_* comes ONLY from Msvm_VideoHead — never the requested echo
    assert result["observed_horizontal"] == 1024
    assert result["observed_vertical"] == 768


# ---------------------------------------------------------------------------
# C5: read-only get (no policy gate)
# ---------------------------------------------------------------------------

def test_c5_get_video(monkeypatch):
    """Base-RED sentinel: AttributeError ... no attribute 'vm_get_video'."""
    fn = media.vm_get_video
    cfg = Config(allowed_vm_patterns=["test-*"])  # display stays off: read-only
    fake = FakePS([pswindows.PSResult(
        stdout='{"resolution_type": "Single", "horizontal": 1920, "vertical": 1080}',
        returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    result = fn(cfg, "test-vm")  # must NOT raise PolicyDenied
    expected = {
        "ok": True,
        "resolution_type": "Single",
        "horizontal": 1920,
        "vertical": 1080,
        "vm_name": "test-vm",
    }
    for key, value in expected.items():
        assert result.get(key) == value, (key, result)
    script = fake.scripts[1]
    assert "Get-VMVideo -VM $vm" in script
    assert "no video settings returned" in script  # empty-result guard
    assert "Set-VMVideo" not in script


# ---------------------------------------------------------------------------
# C6: remote-host composition (issue #43 media choke)
# ---------------------------------------------------------------------------

def test_c6_remote_wrap(monkeypatch, tmp_path):
    """Base-RED sentinel: AttributeError ... no attribute 'vm_set_resolution'."""
    fn = media.vm_set_resolution
    pw_file = tmp_path / "host-pw.txt"
    pw_file.write_text("host-pw-123", encoding="utf-8")
    monkeypatch.setenv("HYPERV_HOST_USERNAME", "lab\\admin")
    monkeypatch.setenv("HYPERV_HOST_PASSWORD_FILE", str(pw_file))
    cfg = Config.from_dict({
        "hyperv": {"host": "nuc01"},
        "allowed_vm_patterns": ["test-*"],
        "destructive": {"display": True},
    })
    fake = FakePS([pswindows.PSResult(stdout=READBACK, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    fn(cfg, "test-vm", 1920, 1080, "single")
    script, kwargs = fake.scripts[1], fake.kwargs[1]
    assert "Invoke-Command -ComputerName 'nuc01'" in script
    assert "-Credential $__hostcred" in script
    stdin = kwargs.get("stdin_b64")
    assert stdin is not None, "the media choke must feed the composed stdin"
    assert "\n" not in stdin, "one line only: the host password, no payload lines"
    assert base64.b64decode(stdin).decode("utf-8") == "host-pw-123"


# ---------------------------------------------------------------------------
# C7: every generated script parses under the real PS 5.1 parser
# ---------------------------------------------------------------------------

def _parse_errors(script: str) -> list[str]:
    """Parse-only validation via the real PS 5.1 parser (never executes).

    Uses the saved real run_ps so it works even while a recorder is
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
        "    $errs | ForEach-Object { Write-Output "
        "($_.Extent.StartLineNumber.ToString() + ': ' + $_.Message) }\n"
        "    exit 1\n"
        "} else { Write-Output 'PARSE-OK' }\n"
    )
    result = _REAL_RUN_PS(parser, timeout_s=60, stdin_b64=b64)
    if result.stdout.strip() == "PARSE-OK":
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def test_c7_parse_valid(monkeypatch):
    """Base-RED sentinel: AttributeError ... no attribute 'vm_set_resolution'."""
    if not os.path.isfile(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
        pytest.skip("Windows PowerShell not available")
    pswindows.init(Config(unrestricted=True))
    fn_set = media.vm_set_resolution
    fn_get = media.vm_get_video
    cfg = Config(unrestricted=True)
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    for call in (
        lambda: fn_set(cfg, "test-vm", 1920, 1080, "single", confirm=True),
        lambda: fn_set(cfg, "test-vm", 1920, 1080, "maximum", confirm=True),
        lambda: fn_set(cfg, "test-vm", resolution_type="default", confirm=True),
        lambda: fn_get(cfg, "test-vm"),
    ):
        try:
            call()
        except Exception:
            pass  # canned readbacks need not satisfy post-capture stages
    assert fake.scripts, "no scripts were generated"
    for script in fake.scripts:
        assert _parse_errors(script) == []


# ---------------------------------------------------------------------------
# C8: config schema (destructive.display)
# ---------------------------------------------------------------------------

def test_c8_config_schema():
    """Base-RED sentinel: ConfigError "unknown destructive key(s): ['display']"."""
    cfg = Config.from_dict({"destructive": {"display": True}})
    assert cfg.destructive.display is True
    assert Config().destructive.display is False
    with pytest.raises(ConfigError, match="unknown destructive"):
        Config.from_dict({"destructive": {"nuke": True}})
