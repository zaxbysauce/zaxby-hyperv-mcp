"""Issue #29 fix-side production-path pins (trace 29-uia-helper-element-
desktop, workstream F PR 5) — the behaviors the FROZEN acceptance files
deliberately do not carry, pinned against the implemented surface.

The frozen files (tests/unit/test_f05_uia_helper.py,
tests/unit/test_f05_interactive_helper.py) had to import hyperv_mcp.uia
INSIDE each test body, so they could only stub one seam family per test and
could never assert what a real verb call composes end to end. This UNFROZEN
companion file assumes the fix exists (module-level import of uia is the
point) and pins the production path:

  1. a verb call whose transports are stubbed really traverses the broker
     chain (validate_forward on a registration whose target matches,
     ensure_registration seeding _REGISTRATIONS from the response);
  2. the first-request gates (#28 shared-mutation gate, adapter approval)
     fire BEFORE any transport leg;
  3. the transported script IS the CLIENT_LEG_SCRIPT pipe leg (the
     strengthened C6 assertion: 'hyperv-mcp-uia' + 'NamedPipeClientStream'
     in the recorded inner script);
  4. the session_unverified contract split (host defers an unknown session
     dimension; the packaged helper refuses session-less requests) —
     content-pinned on both artifacts plus a behavioral validate_forward leg;
  5. RegistryKey.DeleteValue(name, $false) tolerates a missing value on real
     Windows PowerShell — the .NET API contract _AUTOLOGON_INNER's
     DeleteValue('DefaultPassword', $false) relies on on a clean image;
  6. PS 5.1 parse coverage (via test_script_parse_new's _parse_errors lane)
     for every PowerShell artifact the module composes: the packaged helper,
     the client leg, the composed LOCAL-mode pipe wrapper, and the three
     provisioning inner scripts.

No real Hyper-V anywhere; tests 5 and 6 run real powershell.exe only.
"""

from __future__ import annotations

import importlib.resources
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest
from test_script_parse_new import _parse_errors

from hyperv_mcp import evidence, pswindows, uia
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("testuser", "placeholder-pass")
VM_GUID = "e953c649-1234-5678-9abc-def012345678"
USER_SID = "S-1-5-21-1000-2000-3000-1001"
UNRESTRICTED = Config(unrestricted=True)

HELPER_FRAME = {
    "ok": True,
    "result": {"elements": [
        {"element_id": "42:1024", "name": "Untitled - Notepad",
         "control_type": "Window"}]},
    "session": {
        "session_id": 2,
        "interactive_user": "tester",
        "locked": False,
        "helper": {"running": True, "version": uia.HELPER_VERSION,
                   "capabilities": ["uia", "msaa"], "nonce": ""},
    },
}


# ---------------------------------------------------------------------------
# harness (mirrors the frozen files' recorder idioms)
# ---------------------------------------------------------------------------

def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


class PSResolveRecorder:
    """pswindows.run_ps stand-in: serves the vmident resolve leg (GUID out),
    swallows every other leg with empty stdout and exit 0 (the quser/sid
    discovery text legs parse nothing and fall through to None)."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=VM_GUID, returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)


class UiLegRecorder:
    """uia._run_uia_leg stand-in: records every (inner script, framed stdin)
    the module transports and serves one successful helper response frame."""

    def __init__(self, frame: dict | None = None):
        self.scripts: list[str] = []
        self.stdin_b64: list[str | None] = []
        self.frame = frame if frame is not None else HELPER_FRAME

    def __call__(self, cfg, script, *, stdin_b64=None, timeout_s=None, **kwargs):
        self.scripts.append(script)
        self.stdin_b64.append(stdin_b64)
        return pswindows.PSResult(stdout=json.dumps(self.frame), returncode=0)


@pytest.fixture()
def clean_uia_state():
    """The module's process-local broker/SID caches start and end empty so
    every test controls exactly which registration exists (first-request
    legs depend on _REGISTRATIONS being empty at call time)."""
    uia._REGISTRATIONS.clear()
    uia._SID_CACHE.clear()
    yield
    uia._REGISTRATIONS.clear()
    uia._SID_CACHE.clear()


# ---------------------------------------------------------------------------
# 1. the production verb path runs the broker chain
# ---------------------------------------------------------------------------

def test_route_is_the_production_verb_path(clean_uia_state, monkeypatch):
    """A find whose transports are stubbed (helper frame served by
    _run_uia_leg, quser discovery served by _run_quser) goes through the
    broker chain: the bootstrap response seeds a registration in
    uia._REGISTRATIONS for the VM, and the next call runs validate_forward
    with a registration whose identity matches the request target — the
    frozen C19 test could only exercise route() directly with a synthetic
    registration; this pins the production wiring between the two."""
    legs = UiLegRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    monkeypatch.setattr(uia, "_run_quser",
                        lambda cfg, ref, cred: {"user": "tester", "session_id": 2})

    seen: list[dict] = []
    real_validate = uia.validate_forward

    def recording_validate(registration, request):
        seen.append({"registration": dict(registration), "request": dict(request)})
        return real_validate(registration, request)

    monkeypatch.setattr(uia, "validate_forward", recording_validate)

    first = uia.find(UNRESTRICTED, "test-vm-1", CRED, {"name": "Untitled - Notepad"})
    assert first["ok"] is True, first
    assert legs.scripts, "the verb must reach its transport through _run_uia_leg"
    assert seen == [], "the bootstrap request has no registration to validate"

    assert any(guid == VM_GUID for (guid, _sid) in uia._REGISTRATIONS), (
        "ensure_registration must seed a registration from the bootstrap "
        "helper response (frame ok with a session block)"
    )

    second = uia.find(UNRESTRICTED, "test-vm-1", CRED, {"name": "Untitled - Notepad"})
    assert second["ok"] is True, second
    assert seen, (
        "the registered path must run validate_forward — the broker chain is "
        "the production verb path, not a side door"
    )
    for row in seen:
        registration, request = row["registration"], row["request"]
        target = request.get("target") or {}
        assert registration.get("vm_guid") == VM_GUID == target.get("vm_guid"), row
        assert registration.get("session_id") == 2 == target.get("session_id"), row


# ---------------------------------------------------------------------------
# 2. first-request gates run before any transport
# ---------------------------------------------------------------------------

def test_first_request_gates_run_before_any_transport(clean_uia_state, monkeypatch):
    """Two first-request refusals, both before any transport leg:

    (a) a shared-VM mutation (set_value, shared_vm=True) whose #28
        actor/lease gate raises propagates the refusal with ZERO _run_uia_leg
        calls — AC21's gates run on every request, bootstrap included;
    (b) an adapter 'electron' request routed with a registration lacking
        ELECTRON_CAPABILITY returns {"ok": false, "error_class":
        "adapter_unapproved"} with ZERO _pipe_request calls.
    """
    legs = UiLegRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())

    def refusing_gate(registration, request):
        raise uia.UiAError("gate refusal (issue #28 actor/lease seam, test stub)")

    monkeypatch.setattr(uia, "_shared_mutation_gate", refusing_gate)
    with pytest.raises(uia.UiAError, match="gate refusal"):
        uia.set_value(UNRESTRICTED, "test-vm-1", CRED,
                      {"automation_id": "passwordBox"}, "v", shared_vm=True)
    assert legs.scripts == [] and legs.stdin_b64 == [], (
        "the shared-VM mutation gate must refuse before any transport leg"
    )

    pipe_calls: list[tuple] = []

    def recording_pipe(*args):
        pipe_calls.append(args)
        return {"ok": True}

    monkeypatch.setattr(uia, "_pipe_request", recording_pipe)
    registration = uia.register_helper(
        vm_guid=VM_GUID, user_sid=USER_SID, session_id=1, capabilities={"uia"})
    request = {
        "verb": "find",
        "target": {"vm_guid": VM_GUID, "user_sid": USER_SID, "session_id": 1},
        "selector": {"name": "Chat"},
        "adapter": "electron",
    }
    out = uia.route(registration, request)
    assert out["ok"] is False
    assert out["error_class"] == "adapter_unapproved"
    assert pipe_calls == [], (
        "an unapproved adapter must be refused before the pipe seam sees it"
    )


# ---------------------------------------------------------------------------
# 3. the transported script IS the CLIENT_LEG_SCRIPT pipe leg
# ---------------------------------------------------------------------------

def test_pipe_leg_assertion(clean_uia_state, monkeypatch):
    """The strengthened C6 assertion the frozen file cannot carry: a read
    verb (find) with quser stubbed and the transport recording must hand
    _run_uia_leg the CLIENT_LEG_SCRIPT pipe leg — the recorded inner script
    contains the pipe name 'hyperv-mcp-uia' AND drives it through
    NamedPipeClientStream (not a Get-Content remoting shortcut, not an
    Invoke-Expression)."""
    legs = UiLegRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    monkeypatch.setattr(uia, "_run_quser",
                        lambda cfg, ref, cred: {"user": "tester", "session_id": 2})

    out = uia.find(UNRESTRICTED, "test-vm-1", CRED,
                   {"process_name": "notepad", "control_type": "Document"})
    assert out["ok"] is True, out
    pipe_legs = [s for s in legs.scripts
                 if "hyperv-mcp-uia" in s and "NamedPipeClientStream" in s]
    assert pipe_legs, (
        "the read verb's transport must include the CLIENT_LEG_SCRIPT pipe "
        "leg: a script naming the helper pipe (hyperv-mcp-uia) opened through "
        "System.IO.Pipes.NamedPipeClientStream"
    )


# ---------------------------------------------------------------------------
# 4. the session_unverified contract split
# ---------------------------------------------------------------------------

def test_session_unverified_is_refused():
    """A request whose target carries session_id None against a registration
    with a concrete session: the BROKER DEFERS (validate_forward does not
    raise — an unknown dimension on either side is the helper's to enforce,
    because discovery failing on the host must not turn into a fabricated
    mismatch), while the HELPER REFUSES session-less requests outright as
    session_unverified before any verb dispatch. Both halves are pinned:
    the marker string must exist in uia.py (the host documents and maps the
    refusal) and in the packaged guest/uia_helper.ps1 (the enforcement), and
    the behavioral leg proves the defer side so the content pins cannot
    decay into decoration."""
    source = Path(uia.__file__).read_text(encoding="utf-8")
    assert "session_unverified" in source, (
        "uia.py must carry the session_unverified refusal contract"
    )
    helper = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8")
    )
    assert "session_unverified" in helper, (
        "the packaged helper must refuse session-less requests with the "
        "session_unverified error class before any verb dispatch"
    )

    registration = uia.register_helper(
        vm_guid=VM_GUID, user_sid=USER_SID, session_id=2, capabilities={"uia"})
    request = {
        "verb": "find",
        "target": {"vm_guid": VM_GUID, "user_sid": USER_SID, "session_id": None},
        "selector": {"name": "OK"},
    }
    correlation_id = uia.validate_forward(registration, request)  # must NOT raise
    assert isinstance(correlation_id, str) and correlation_id, (
        "the broker defers an unknown session dimension to the helper"
    )


# ---------------------------------------------------------------------------
# 5. RegistryKey.DeleteValue tolerates a missing value (real PowerShell)
# ---------------------------------------------------------------------------

def test_deletevalue_tolerates_a_missing_value():
    r"""The autologon provisioning leg ends with
    $ku.DeleteValue('DefaultPassword', $false) against a Winlogon key that —
    on a clean image — never held a DefaultPassword value. This runs that
    exact .NET API contract on real Windows PowerShell against the CURRENT
    USER hive (HKLM writes would need admin; HKCU\Software is writable by
    the test account): a SetValue/DeleteValue round-trip on a scratch name,
    then DeleteValue of a name that does not exist with $false — which must
    not throw. HKCU is also where issue #29's guest tests may run without
    elevation; the API behavior is hive-independent."""
    powershell = shutil.which("powershell")
    if powershell is None:
        pytest.skip(
            "powershell.exe is not on PATH (the RegistryKey.DeleteValue leg "
            "runs on real Windows PowerShell only)"
        )
    scratch = "hyperv_mcp_f05_scratch"
    script = "\n".join([
        "$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software', $true)",
        "if ($null -eq $key) { throw 'HKCU Software could not be opened for write' }",
        "try {",
        f"    $key.SetValue('{scratch}', 'x', [Microsoft.Win32.RegistryValueKind]::String)",
        f"    $key.DeleteValue('{scratch}', $false)",
        "    $key.DeleteValue('DefinitelyMissingValue_xyz', $false)",
        "} finally { $key.Close() }",
        "Write-Output 'tolerated'",
    ])
    proc = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    assert "tolerated" in proc.stdout, (
        f"DeleteValue(name, $false) must tolerate a missing value — "
        f"stdout: {proc.stdout!r} stderr: {proc.stderr!r}"
    )


# ---------------------------------------------------------------------------
# 6. PS 5.1 parse coverage for every composed artifact
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def parsed_ps():
    """Same guard as test_script_parse_new.py's parsed_ps fixture: the parse
    lane needs the real Windows PowerShell 5.1 parser and skips without it."""
    if not os.path.isfile(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
        pytest.skip("Windows PowerShell not available")
    pswindows.init(UNRESTRICTED)
    yield


def test_parse_packaged_helper_script(parsed_ps):
    """(a) the packaged in-session helper parses clean under PS 5.1."""
    helper = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8-sig")
    )
    assert _parse_errors(helper) == []


def test_parse_client_leg_script(parsed_ps):
    """(b) the guest-side pipe-client leg parses clean under PS 5.1."""
    assert _parse_errors(uia.CLIENT_LEG_SCRIPT) == []


def test_parse_composed_pipe_leg_wrapper(parsed_ps, monkeypatch):
    """(c) the COMPOSED _uia_guest_script output for a pipe leg in LOCAL
    mode — prefix + stdin line + vm-target preamble + b64 inner script +
    Invoke-Command -VMId wrapper — parses clean as a whole."""
    leg_cred = CredentialSet("u", "p")
    monkeypatch.setattr(uia._LEG, "guid", VM_GUID)
    monkeypatch.setattr(uia._LEG, "cred", leg_cred)
    composed = uia._uia_guest_script(uia.CLIENT_LEG_SCRIPT, leg_cred, None)
    assert "Invoke-Command -VMId" in composed  # sanity: the wrapper wrapped
    assert _parse_errors(composed) == []


def test_leg_slot_is_thread_local():
    """Round-3 critic BLOCKER: the leg slot must be thread-local so
    concurrent calls for different VMs never cross (tool bodies run on
    worker threads and vm_lock is per-VM)."""
    assert isinstance(uia._LEG, threading.local)


def test_parse_provisioning_inner_scripts(parsed_ps):
    """(d) the three provisioning inner scripts parse clean: the install
    leg, the autologon leg exactly as provision_helper composes it (the
    HYPERVMCP_AUTOLOGON_USER environment line + _AUTOLOGON_INNER), and the
    scheduled-task leg (the same user line + _TASK_INNER)."""
    user_line = ("$env:HYPERVMCP_AUTOLOGON_USER = "
                 + pswindows.ps_quote(CRED.username))
    autologon_inner = user_line + "\n" + uia._AUTOLOGON_INNER
    task_inner = user_line + "\n" + uia._TASK_INNER
    for name, script in (
        ("install", uia._INSTALL_INNER),
        ("autologon", autologon_inner),
        ("task", task_inner),
    ):
        assert _parse_errors(script) == [], f"{name} inner script has parse errors"


# ---------------------------------------------------------------------------
# Round-2 reviewer-required pins (4.5 findings 1 + 2)
# ---------------------------------------------------------------------------

def test_frame_carries_min_version(clean_uia_state, monkeypatch):
    """4.5 finding 2: every framed request carries min_version so a stale
    helper refuses before dispatch. The framed stdin line 2 must decode to
    a request whose min_version equals uia.HELPER_VERSION."""
    captured = {}

    def leg(cfg, script, *, stdin_b64=None, timeout_s=None, **kw):
        captured["script"] = script
        captured["stdin_b64"] = stdin_b64
        return pswindows.PSResult(
            stdout=json.dumps({"ok": True, "result": {}, "session": {}}),
            returncode=0)

    monkeypatch.setattr(uia, "_run_uia_leg", leg)
    monkeypatch.setattr(pswindows, "run_ps",
                        lambda s, **k: pswindows.PSResult(
                            stdout="e953c649-1234-5678-9abc-def012345678",
                            returncode=0))
    cfg = Config(unrestricted=True)
    from hyperv_mcp.credentials import CredentialSet

    uia.session_state(cfg, "test-vm-1", CredentialSet("tester", "pw"))
    line2 = captured["stdin_b64"].strip().splitlines()[1]
    import base64

    request = json.loads(base64.b64decode(line2).decode("utf-8"))
    assert request["min_version"] == uia.HELPER_VERSION


def test_session_state_answer_carries_top_level_helper(clean_uia_state,
                                                       monkeypatch):
    """4.5 finding 1: a BYTE-EXACT production frame (helper facts in the
    session block, result without helper) must come back with helper at
    TOP level, or evidence's helper gate and the frozen AC17 shape starve."""
    byte_exact = {
        "ok": True, "id": "abc123",
        "result": {"active_session_id": 2, "interactive_user": "tester",
                   "locked": False,
                   "foreground_window": {"title": None, "process_name": "",
                                          "pid": 0, "hwnd": 0}},
        "session": {"session_id": 2, "interactive_user": "tester",
                    "locked": False,
                    "helper": {"running": True, "version": uia.HELPER_VERSION,
                               "capabilities": ["uia", "msaa"], "nonce": ""}},
    }

    def leg(cfg, script, *, stdin_b64=None, timeout_s=None, **kw):
        return pswindows.PSResult(stdout=json.dumps(byte_exact), returncode=0)

    monkeypatch.setattr(uia, "_run_uia_leg", leg)
    monkeypatch.setattr(uia, "_run_quser",
                        lambda cfg, ref, cred: {"user": "tester",
                                                "session_id": 2})
    monkeypatch.setattr(pswindows, "run_ps",
                        lambda s, **k: pswindows.PSResult(
                            stdout="e953c649-1234-5678-9abc-def012345678",
                            returncode=0))
    cfg = Config(unrestricted=True)
    from hyperv_mcp.credentials import CredentialSet

    out = uia.session_state(cfg, "test-vm-1", CredentialSet("tester", "pw"))
    assert out["helper"]["running"] is True
    assert out["helper"]["version"] == uia.HELPER_VERSION

    # the evidence helper-first gate opens on this exact answer shape
    from types import SimpleNamespace

    seen = {}

    def fake_inspect(cfg_, ref_, cred_, selector=None, **kw):
        seen["called"] = True
        return {"ok": True, "elements": 1, "truncated": False,
                "tree": {"name": "Desktop"}}

    monkeypatch.setattr(uia, "session_state",
                        lambda cfg_, vm, cred_: out)
    monkeypatch.setattr(uia, "inspect", fake_inspect)
    ref = SimpleNamespace(id="e953c649-1234-5678-9abc-def012345678")
    ui = evidence._uia_via_helper(cfg, ref, CredentialSet("tester", "pw"),
                                  3, 200)
    assert ui is not None and ui["source"] == "helper" and seen["called"]
