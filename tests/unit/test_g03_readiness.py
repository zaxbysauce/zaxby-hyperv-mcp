"""Frozen acceptance checks for issue #32 (readiness / deployment_status),
legs AC8, AC9, AC10, AC11.

Arm's-length authoring (trace 31-32-33-94-workstream-g-deployment, tier L):
written from the POST-FIX API CONTRACT only; frozen — the implementation
phase makes them green. The module-level `from hyperv_mcp import readiness`
makes every check in this file an ERROR-at-base (ImportError) until the new
module exists; that is the frozen base signature.

Frozen response conventions asserted here (documented so the implementation
phase can conform):
  * deployment_status resolves the target with vmident.resolve (the standard
    by-name resolution leg: contains Msvm_ComputerSystem, ends with the bare
    "$vmTarget" emit) and then runs exactly ONE action PowerShell process —
    never resolving guest credentials.
  * The ONE action script emits a single JSON object:
      {"state": <str>, "uptime_s": <int>, "heartbeat": <str>,
       "kvp_items": [<raw GuestIntrinsicExchangeItems strings>]}
    and the guest facts (os_name, os_build, ipv4) are derived host-side from
    parse_kvp_items output; KVP values are guest-controlled data, never
    interpolated into PowerShell.
  * The heartbeat leg of hyperv_wait_vm_state emits the status description
    text ("OK" / "No Contact").
"""

import asyncio
import importlib
import json
import os

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import credentials, pswindows, readiness
from hyperv_mcp.config import Config

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
UNRESTRICTED = Config(unrestricted=True)

KVP_OSNAME = (
    '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
    '<PROPERTY NAME="Name" TYPE="string"><VALUE>OSName</VALUE></PROPERTY>'
    '<PROPERTY NAME="Data" TYPE="string"><VALUE>Windows 10 Enterprise</VALUE></PROPERTY>'
    '</INSTANCE>'
)
KVP_BUILD = (
    '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
    '<PROPERTY NAME="Name" TYPE="string"><VALUE>OSBuildNumber</VALUE></PROPERTY>'
    '<PROPERTY NAME="Data" TYPE="string"><VALUE>19045</VALUE></PROPERTY>'
    '</INSTANCE>'
)
KVP_IPV4 = (
    '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
    '<PROPERTY NAME="Name" TYPE="string"><VALUE>NetworkAddressIPv4</VALUE></PROPERTY>'
    '<PROPERTY NAME="Data" TYPE="string"><VALUE>10.1.2.3; 10.1.2.4</VALUE></PROPERTY>'
    '</INSTANCE>'
)
STATUS_ACTION = json.dumps({
    "state": "Running",
    "uptime_s": 300,
    "heartbeat": "OK",
    "heartbeat_enabled": True,
    "heartbeat_secondary": "OK",
    "kvp_items": [KVP_OSNAME, KVP_BUILD, KVP_IPV4, "<not-xml"],
})


def _guid_res() -> pswindows.PSResult:
    return pswindows.PSResult(stdout=GUID, returncode=0)


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


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
def fresh_server():
    """The repo's fresh_server idiom (tests/unit/test_server.py)."""
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod
    yield make
    importlib.reload(server_module)


def _schemas(mod):
    mcp = mod.get_mcp()
    tools = asyncio.run(mcp.list_tools())
    return {t.name: (getattr(t, "input_schema", None) or t.inputSchema) for t in tools}


def _call(mod, tool: str, args: dict) -> dict:
    """Invoke a registered tool in-process and return its dict result,
    handling every call_tool return shape this SDK has produced."""
    result = asyncio.run(
        mod.get_mcp()._tool_manager.call_tool(tool, args, context=None))
    if isinstance(result, dict):
        return result
    content = result[0] if isinstance(result, tuple) else result
    if hasattr(content, "content"):
        texts = [c.text for c in content.content if getattr(c, "type", "") == "text"]
        assert texts, f"expected a text envelope for {tool}"
        return json.loads(texts[0])
    raise AssertionError(f"unrecognized call_tool return shape for {tool}: {result!r}")


# ---------------------------------------------------------------------------
# AC8 — hyperv_deployment_status registration, credential-free in BOTH modes
# ---------------------------------------------------------------------------

def test_deployment_status_tool_registered(tmp_path, fresh_server):
    """RED/ERROR at base (ImportError: readiness; then KeyError — the tool is
    not registered), GREEN after the fix."""
    mod = fresh_server({})
    schemas = _schemas(mod)
    assert "hyperv_deployment_status" in schemas, (
        "hyperv_deployment_status must be registered (76 -> 80 tools)"
    )
    props = schemas["hyperv_deployment_status"].get("properties", {})
    assert "vm_name" in props and "vm_id" in props
    assert "confirm" not in props, "readout only: no human prompt"
    assert "username" not in props and "password" not in props, (
        "the tool never takes guest credentials"
    )
    # inline-credential mode must NOT grow them either: deployment_status is
    # a single registration outside the dual-variant pairs (the
    # test_inline_credential_mode_exposes_params idiom)
    doc = {"allow_inline_credentials": True}
    p = tmp_path / "inline-creds.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod2 = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    props2 = _schemas(mod2)["hyperv_deployment_status"].get("properties", {})
    assert "username" not in props2 and "password" not in props2, (
        "inline-credential mode must not expose credential params on a "
        "credential-free readout"
    )


# ---------------------------------------------------------------------------
# AC9 — hyperv_wait_vm_state reports the real heartbeat, not a constant
# ---------------------------------------------------------------------------

class _WaitRouter:
    """Content-serving run_ps stand-in: resolution leg, state-wait poll leg
    (emits {"final_state": ...}), heartbeat leg (emits the status text)."""

    def __init__(self, final: str, heartbeat: str):
        self.scripts = []
        self.final = final
        self.heartbeat = heartbeat

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if "final_state" in script:
            return pswindows.PSResult(
                stdout=json.dumps({"final_state": self.final}), returncode=0)
        if "Heartbeat" in script:
            return pswindows.PSResult(stdout=self.heartbeat, returncode=0)
        return pswindows.PSResult(stdout="{}", returncode=0)


def test_wait_vm_state_reports_heartbeat_not_a_constant(tmp_path, monkeypatch, fresh_server):
    """RED/ERROR at base (KeyError: 'heartbeat' — the tool returns the
    constant guest_channel "ps_direct_unverified"), GREEN after the fix:
    a Running final state adds exactly one heartbeat PS process and derives
    guest_channel from it; a non-Running final adds no extra process at all
    and never returns the dead constant."""
    doc = {"allowed_vm_patterns": ["test-*"]}
    cfg_file = tmp_path / "wait-cfg.json"
    cfg_file.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})

    run = _WaitRouter("Running", "OK")
    monkeypatch.setattr(pswindows, "run_ps", run)
    out = _call(mod, "hyperv_wait_vm_state", {
        "vm_name": "test-vm-1", "states": ["Running"], "timeout_s": 5})
    assert out["ok"] and out["final_state"] == "Running"
    assert out["heartbeat"] == "OK"
    assert out["guest_channel"] == "os_heartbeat_ok"
    assert out["guest_channel"] != "ps_direct_unverified"
    # exactly one extra PS process on a Running final: resolution + wait +
    # heartbeat query, and the heartbeat query is its own leg
    assert len(run.scripts) == 3, (
        f"Running final ran {len(run.scripts)} PS processes; expected 3 "
        "(resolve + wait + heartbeat)"
    )
    assert [s for s in run.scripts if "Heartbeat" in s and "final_state" not in s], (
        "the heartbeat query must exist as its own leg for Running finals"
    )

    # non-Running final (Off): heartbeat absent, NO heartbeat query spawned,
    # {ok, final_state, guest_channel} shape kept — and the constant is gone
    off = _WaitRouter("Off", "OK")
    monkeypatch.setattr(pswindows, "run_ps", off)
    out2 = _call(mod, "hyperv_wait_vm_state", {
        "vm_name": "test-vm-1", "states": ["Off"], "timeout_s": 5})
    assert out2["ok"] and out2["final_state"] == "Off"
    assert not out2.get("heartbeat"), "no heartbeat claim without a query"
    assert out2["guest_channel"] != "ps_direct_unverified", (
        "the literal 'ps_direct_unverified' must no longer be returned"
    )
    assert len(off.scripts) == 2, (
        f"non-Running final ran {len(off.scripts)} PS processes; expected 2 "
        "(resolve + wait only)"
    )
    assert not [s for s in off.scripts if "Heartbeat" in s], (
        "no heartbeat query may run for non-Running finals"
    )


# ---------------------------------------------------------------------------
# AC10 — parse_kvp_items; deployment_status needs no credentials
# ---------------------------------------------------------------------------

def test_parse_kvp_items():
    """RED/ERROR at base (ImportError: readiness), GREEN after the fix:
    well-formed Msvm_KvpExchangeDataItem strings parse to {Name: Data};
    malformed entries ("<not-xml") are skipped without raising."""
    out = readiness.parse_kvp_items(
        [KVP_OSNAME, KVP_BUILD, KVP_IPV4, "<not-xml"])
    assert out["OSName"] == "Windows 10 Enterprise"
    assert out["OSBuildNumber"] == "19045"
    assert out["NetworkAddressIPv4"] == "10.1.2.3; 10.1.2.4"
    assert len(out) == 3, "the malformed item must be skipped, not stored"
    assert "<not-xml" not in out
    assert readiness.parse_kvp_items([]) == {}
    # a fully malformed batch still does not raise
    assert readiness.parse_kvp_items(["<not-xml", "", "junk"]) == {}


def test_deployment_status_needs_no_credentials(monkeypatch):
    """RED/ERROR at base (ImportError: readiness), GREEN after the fix: ONE
    PowerShell process after identity resolution, never a guest-credential
    resolution, phase os_ready with split ipv4 from KVP data."""
    def _boom(*args, **kwargs):
        raise AssertionError(
            "deployment_status must never resolve guest credentials "
            f"(resolve_guest called with {args!r} {kwargs!r})"
        )
    monkeypatch.setattr(credentials, "resolve_guest", _boom)
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout=STATUS_ACTION, returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = readiness.deployment_status(UNRESTRICTED, "test-vm-1")
    assert out["ok"]
    # exactly ONE action PowerShell process (after the vmident leg)
    assert len(fake.scripts) == 2, (
        f"deployment_status ran {len(fake.scripts)} PS processes; the "
        "contract is vmident resolution + ONE action process"
    )
    action = fake.scripts[1]
    assert "Get-VMIntegrationService" in action and "Heartbeat" in action
    assert "Msvm_KvpExchangeComponent" in action
    # assembled result contract (issue #32 AC4 richer shape)
    assert out["phase"] == "os_ready"
    assert out["state"] == "Running" and out["uptime_s"] == 300
    assert out["heartbeat"]["primary_status"] == "OK"
    assert out["heartbeat"]["enabled"] is True
    assert out["heartbeat"]["application_status"] == "OK"
    assert out["vm_id"] == GUID
    assert out["guest"]["os_name"] == "Windows 10 Enterprise"
    assert out["guest"]["os_build"] == "19045"
    ipv4 = out["guest"]["ipv4"]
    assert sorted(ipv4) == ["10.1.2.3", "10.1.2.4"], (
        "NetworkAddressIPv4 must be split into individual addresses"
    )
    assert all(";" not in ip and " " not in ip for ip in ipv4)
    assert out["kvp"]["available"] is True
    assert out["kvp"]["items"].get("OSName") == "Windows 10 Enterprise"
    assert out["vm_name"] == "test-vm-1"


# ---------------------------------------------------------------------------
# AC11 — classify_phase table; the status script keys on the GUID
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("state,hb_enabled,hb_primary,kvp,expected", [
    ("Off", True, "OK", True, "off"),          # Off wins regardless of signals
    ("Off", False, "", False, "off"),
    ("Running", True, "OK", True, "os_ready"),
    ("Running", True, "No Contact", True, "no_guest_signal"),
    ("Starting", True, "OK", True, "no_guest_signal"),  # transition: no guest signal
    ("Stopping", True, "OK", True, "no_guest_signal"),
])
def test_classify_phase(state, hb_enabled, hb_primary, kvp, expected):
    """RED/ERROR at base (ImportError: readiness), GREEN after the fix:
    transition and precedence rows complementing test_phase_classification_v2
    (issue #32 AC5 richer signature)."""
    assert readiness.classify_phase(
        state, hb_enabled, hb_primary, kvp) == expected


def test_status_script_keys_on_guid(monkeypatch):
    """RED/ERROR at base (ImportError: readiness), GREEN after the fix: the
    action script binds $vmTarget (vmident's validated GUID) and uses it as
    the ONLY WMI key — the VM NAME never appears as a query key."""
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout=STATUS_ACTION, returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    readiness.deployment_status(UNRESTRICTED, "test-vm-1")
    assert len(fake.scripts) == 2
    script = fake.scripts[1]
    assert f"$vmTarget = '{GUID}'" in script, (
        "the action script must open with the validated GUID binding"
    )
    assert "SystemName='$vmTarget'" in script, (
        "the KVP query must filter on SystemName='$vmTarget'"
    )
    assert "'test-vm-1'" not in script, (
        "the caller-supplied NAME must never be used as a WMI key"
    )


# ---------------------------------------------------------------------------
# AC11 — the generated script parses under the real PowerShell 5.1 parser
# ---------------------------------------------------------------------------

_REAL_RUN_PS = pswindows.run_ps  # saved before any monkeypatching


@pytest.fixture(scope="module")
def parsed_ps():
    """Marker skip when real PowerShell is absent (test_script_parse idiom)."""
    if not os.path.isfile(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
        pytest.skip("Windows PowerShell not available")
    pswindows.init(UNRESTRICTED)
    yield


def _parse_errors(script: str) -> list[str]:
    """Parse-only validation via the real PS 5.1 parser (never executes)."""
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


def test_parse_readiness_script(monkeypatch, parsed_ps):
    """RED/ERROR at base (ImportError: readiness), GREEN after the fix: the
    ONE action script deployment_status generates parses clean — mocks cannot
    catch a PS 5.1 syntax error, the parser can (test_script_parse idiom)."""
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout=STATUS_ACTION, returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    try:
        readiness.deployment_status(UNRESTRICTED, "test-vm-1")
    except Exception:
        pass  # post-capture validation failures don't matter (script captured)
    actions = [s for s in fake.scripts if not _is_resolution_leg(s)]
    assert actions, "deployment_status produced no action script"
    assert _parse_errors(actions[0]) == []


# ---------------------------------------------------------------------------
# #32 AC4 / AC5 — the RICHER v2 contract (trace 55-108-31-32-33-collated;
# appended by the arm's-length acceptance-check author; the functions above
# are untouched). The shipped (PR #112) shape is the simplified one; the
# issue's reopened contract is:
#   {ok, vm_name, vm_id, state, uptime_s,
#    heartbeat: {enabled, primary_status, application_status},
#    kvp: {available, items}, guest: {os_name, os_build, fqdn, ipv4, ipv6},
#    phase, phase_basis, checked_at}
# with the six-phase vocabulary off / suspended / no_guest_signal /
# os_ready / os_unresponsive / heartbeat_disabled (plus the retained
# `degraded` row as a documented superset) and classify_phase's richer
# signature classify_phase(state, hb_enabled, hb_primary, kvp_available).
#
# Frozen canned-row convention for the ONE action process (extends the
# module's documented shape with the two heartbeat-struct sources):
#   {"state": <str>, "uptime_s": <int>, "heartbeat": <primary str>,
#    "heartbeat_enabled": <bool>, "heartbeat_secondary": <str>,
#    "kvp_items": [<raw GuestIntrinsicExchangeItems strings>]}
# `heartbeat` carries the Heartbeat PrimaryStatusDescription and
# `heartbeat_secondary` the SecondaryStatusDescription — the two sources the
# richer heartbeat struct {enabled, primary_status, application_status} is
# assembled from.
# ---------------------------------------------------------------------------

KVP_OSNAME_RICH = (
    '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
    '<PROPERTY NAME="Name" TYPE="string"><VALUE>OSName</VALUE></PROPERTY>'
    '<PROPERTY NAME="Data" TYPE="string">'
    '<VALUE>Windows 11 Enterprise</VALUE></PROPERTY>'
    '</INSTANCE>'
)
KVP_BUILD_RICH = (
    '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
    '<PROPERTY NAME="Name" TYPE="string"><VALUE>OSBuildNumber</VALUE></PROPERTY>'
    '<PROPERTY NAME="Data" TYPE="string"><VALUE>22631</VALUE></PROPERTY>'
    '</INSTANCE>'
)
KVP_FQDN = (
    '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
    '<PROPERTY NAME="Name" TYPE="string">'
    '<VALUE>FullyQualifiedDomainName</VALUE></PROPERTY>'
    '<PROPERTY NAME="Data" TYPE="string">'
    '<VALUE>lab-a-01.corp.example</VALUE></PROPERTY>'
    '</INSTANCE>'
)
KVP_IPV4_RICH = (
    '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
    '<PROPERTY NAME="Name" TYPE="string">'
    '<VALUE>NetworkAddressIPv4</VALUE></PROPERTY>'
    '<PROPERTY NAME="Data" TYPE="string">'
    '<VALUE>10.0.0.5;192.168.1.7</VALUE></PROPERTY>'
    '</INSTANCE>'
)
KVP_IPV6 = (
    '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
    '<PROPERTY NAME="Name" TYPE="string">'
    '<VALUE>NetworkAddressIPv6</VALUE></PROPERTY>'
    '<PROPERTY NAME="Data" TYPE="string">'
    '<VALUE>fe80::1;2001:db8::8</VALUE></PROPERTY>'
    '</INSTANCE>'
)
RICH_STATUS_ACTION = json.dumps({
    "state": "Running",
    "uptime_s": 1234,
    "heartbeat": "OK",
    "heartbeat_enabled": True,
    "heartbeat_secondary": "OK",
    "kvp_items": [KVP_OSNAME_RICH, KVP_BUILD_RICH, KVP_FQDN,
                  KVP_IPV4_RICH, KVP_IPV6],
})
SAVED_STATUS_ACTION = json.dumps({
    "state": "Saved",
    "uptime_s": 0,
    "heartbeat": "",
    "heartbeat_enabled": True,
    "heartbeat_secondary": "",
    "kvp_items": [],
})
DISABLED_STATUS_ACTION = json.dumps({
    "state": "Running",
    "uptime_s": 7,
    "heartbeat": "OK",
    "heartbeat_enabled": False,
    "heartbeat_secondary": "",
    "kvp_items": [KVP_OSNAME_RICH],
})


def test_deployment_status_rich_shape_no_credentials(monkeypatch):
    """#32 AC4 (trace 55-108-31-32-33-collated): the RICHER result shape —
    vm_id, TOP-LEVEL state/uptime_s, heartbeat as the {enabled,
    primary_status, application_status} struct, guest.fqdn and guest.ipv6,
    phase_basis naming the producing signals, and checked_at as UTC ISO —
    while NEVER resolving guest (or victim) credentials."""
    def _boom(name):
        def _f(*args, **kwargs):
            raise AssertionError(
                f"deployment_status must never resolve credentials "
                f"({name} called with {args!r} {kwargs!r})"
            )
        return _f

    monkeypatch.setattr(credentials, "resolve_guest", _boom("resolve_guest"))
    monkeypatch.setattr(credentials, "resolve_victim", _boom("resolve_victim"))
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout=RICH_STATUS_ACTION, returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = readiness.deployment_status(UNRESTRICTED, "test-vm-1")

    assert "vm_id" in out and out["vm_id"], (
        "deployment_status rich shape missing vm_id (#32 AC4)"
    )
    assert out["vm_id"] == GUID
    assert out["state"] == "Running", (
        f"state must be TOP-LEVEL == 'Running'; got {out.get('state')!r}"
    )
    assert out["uptime_s"] == 1234, (
        f"uptime_s must be TOP-LEVEL == 1234; got {out.get('uptime_s')!r}"
    )
    heartbeat = out["heartbeat"]
    assert isinstance(heartbeat, dict), (
        f"heartbeat must be the richer struct; got {heartbeat!r}"
    )
    assert {"enabled", "primary_status", "application_status"} <= set(heartbeat), (
        f"heartbeat struct keys incomplete: {sorted(heartbeat)!r}"
    )
    assert heartbeat["primary_status"] == "OK"
    assert heartbeat["enabled"] is True
    assert heartbeat["application_status"] == "OK", (
        "application_status must carry the Heartbeat "
        f"SecondaryStatusDescription from the action rows; got "
        f"{heartbeat.get('application_status')!r}"
    )
    guest = out["guest"]
    assert guest["fqdn"] == "lab-a-01.corp.example", (
        f"guest.fqdn must come from the FullyQualifiedDomainName KVP pair; "
        f"got {guest.get('fqdn')!r}"
    )
    assert guest["ipv4"] == ["10.0.0.5", "192.168.1.7"], (
        "NetworkAddressIPv4 must be split into individual addresses"
    )
    assert guest["ipv6"] == ["fe80::1", "2001:db8::8"], (
        "NetworkAddressIPv6 must be split into individual addresses"
    )
    assert out["phase"] == "os_ready"
    basis = out["phase_basis"]
    for signal in ("state=", "heartbeat=", "kvp="):
        assert signal in basis, (
            f"phase_basis must name the producing signals; {signal!r} "
            f"missing from {basis!r}"
        )
    import datetime as _dt

    checked_at = _dt.datetime.fromisoformat(
        str(out["checked_at"]).replace("Z", "+00:00"))
    assert checked_at.utcoffset() == _dt.timedelta(0), (
        "checked_at must parse as a UTC ISO-8601 timestamp"
    )

    # Suspended row: the basis names the state signal that produced it.
    fake2 = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout=SAVED_STATUS_ACTION, returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake2)
    out2 = readiness.deployment_status(UNRESTRICTED, "test-vm-1")
    assert out2["phase"] == "suspended", (
        f"Saved must classify as 'suspended'; got {out2.get('phase')!r}"
    )
    assert "state=Saved" in out2["phase_basis"], (
        f"the suspended row's basis must name its state signal; "
        f"got {out2.get('phase_basis')!r}"
    )


@pytest.mark.parametrize("state,hb_enabled,hb_primary,kvp_available,expected", [
    ("Off", True, "OK", True, "off"),
    ("Saved", True, "OK", True, "suspended"),
    ("Paused", True, "OK", True, "suspended"),
    ("Running", True, "No Contact", False, "no_guest_signal"),
    ("Running", True, "OK", True, "os_ready"),
    ("Running", True, "Lost Communication", True, "os_unresponsive"),
    ("Running", True, "Error", True, "os_unresponsive"),
    ("Running", False, "", False, "heartbeat_disabled"),
    # a disabled/absent Heartbeat service beats even a primary "OK"
    # reading (the host cannot vouch for the guest it never contacted)
    ("Running", False, "OK", True, "heartbeat_disabled"),
    # retained 7th row (documented superset over the six-phase vocabulary)
    ("Running", True, "OK", False, "degraded"),
])
def test_phase_classification_v2(state, hb_enabled, hb_primary,
                                 kvp_available, expected, monkeypatch):
    """#32 AC5 (trace 55-108-31-32-33-collated): the six-phase vocabulary
    under the RICHER signature
    ``classify_phase(state, hb_enabled, hb_primary, kvp_available)`` —
    off / suspended / no_guest_signal / os_ready / os_unresponsive /
    heartbeat_disabled (including a disabled-service row whose primary
    reading is "OK") — plus the retained degraded row; and
    deployment_status must pass its classify call the enabled/primary
    signals (spy asserts the exact call args for BOTH the enabled and the
    disabled fixture), with the disabled case's phase_basis naming
    heartbeat_enabled."""
    assert readiness.classify_phase(
        state, hb_enabled, hb_primary, kvp_available) == expected

    def _drive_spy(action_stdout):
        """One deployment_status drive with a fresh classify spy: returns
        (classify call args, result dict)."""
        real = readiness.classify_phase
        seen: list = []

        def _spy(cls_state, cls_enabled, cls_primary, cls_kvp):
            seen.append((cls_state, cls_enabled, cls_primary, cls_kvp))
            return real(cls_state, cls_enabled, cls_primary, cls_kvp)

        monkeypatch.setattr(readiness, "classify_phase", _spy)
        fake = FakePS([
            _guid_res(),
            pswindows.PSResult(stdout=action_stdout, returncode=0),
        ])
        monkeypatch.setattr(pswindows, "run_ps", fake)
        return seen, readiness.deployment_status(UNRESTRICTED, "test-vm-1")

    seen, _ = _drive_spy(RICH_STATUS_ACTION)
    assert seen == [("Running", True, "OK", True)], (
        "deployment_status must pass (state, hb_enabled, hb_primary, "
        f"kvp_available) to classify_phase in that order for the enabled "
        f"fixture; saw {seen!r}"
    )

    # Disabled-service fixture (primary reads "OK" but the service is
    # disabled): the spy args must carry hb_enabled=False — not just the
    # phase — and the basis must name heartbeat_enabled as its signal.
    seen2, out2 = _drive_spy(DISABLED_STATUS_ACTION)
    assert seen2 == [("Running", False, "OK", True)], (
        "the disabled fixture's classify call must receive "
        f"hb_enabled=False with the primary reading intact; saw {seen2!r}"
    )
    assert out2["phase"] == "heartbeat_disabled", (
        f"the disabled fixture must classify heartbeat_disabled; got "
        f"{out2.get('phase')!r}"
    )
    assert "heartbeat_enabled" in out2["phase_basis"], (
        "the heartbeat_disabled basis must name heartbeat_enabled as the "
        f"producing signal; got {out2.get('phase_basis')!r}"
    )
    # Gated view (PR-113 feedback round): a disabled Heartbeat service must
    # invalidate KVP even when the primary reading is "OK" and one pair is
    # present — guest identity and the kvp view read the heartbeat-GATED
    # dict, so a gate that only checks hb_primary would surface stale pairs.
    assert out2["guest"]["os_name"] == "", (
        "the gated view must drop KVP pairs when the Heartbeat service is "
        f"disabled even with a primary OK reading; got "
        f"os_name={out2['guest']['os_name']!r}"
    )
    assert out2["kvp"]["items"] == {} and out2["kvp"]["available"] is False, (
        "kvp must report the heartbeat-gated view (empty items, unavailable) "
        f"for a disabled service; got {out2['kvp']!r}"
    )
