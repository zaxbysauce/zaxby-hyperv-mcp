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
     strengthened C6 assertion: 'hyperv-mcp-uia' opened through the raw
     CreateFileW P/Invoke in the recorded inner script — no remoting
     shortcut);
  4. the session_unverified contract split (host defers an unknown session
     dimension; the packaged helper refuses session-less requests) — pinned
     behaviourally on the HOST path (a session-less request surfaces the
     helper's session_unverified refusal as the returned error_class) and on
     the packaged helper artifact;
  5. the PRODUCTION registry tail of _AUTOLOGON_INNER (sliced verbatim from
     the module text, retargeted to a scratch HKCU key) runs clean on real
     Windows PowerShell — RegistryKey.DeleteValue(name, $false) must
     tolerate a value a clean image never had;
  6. PS 5.1 parse coverage (via test_script_parse_new's _parse_errors lane)
     for every PowerShell artifact the module composes: the packaged helper,
     the client leg, the composed LOCAL-mode pipe wrapper, and the three
     provisioning inner scripts.

No real Hyper-V anywhere; tests 5 and 6 run real powershell.exe only.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.resources
import json
import os
import shutil
import subprocess
import threading

import pytest
from test_f05_interactive_helper import _ps_available, _run_helper_dispatch
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


class EchoLegRecorder:
    """uia._run_uia_leg stand-in that correlates like the real helper (F4):
    it decodes the framed two-line stdin (line 1 the password, line 2 the
    request JSON), records every decoded request, and answers
    ``frame_for(request)`` with the REQUEST'S OWN id attached — a canned id
    like "abc123" can no longer stand in for a response."""

    def __init__(self, frame_for):
        self.scripts: list[str] = []
        self.requests: list[dict] = []
        self.frame_for = frame_for

    def __call__(self, cfg, script, *, stdin_b64=None, timeout_s=None, **kwargs):
        self.scripts.append(script)
        request: dict = {}
        if stdin_b64:
            lines = stdin_b64.strip().split("\n")
            if len(lines) >= 2:
                try:
                    request = json.loads(
                        base64.b64decode(lines[1]).decode("utf-8"))
                except Exception:
                    request = {}
        self.requests.append(request)
        frame = dict(self.frame_for(request))
        frame.setdefault("id", request.get("id"))
        return pswindows.PSResult(stdout=json.dumps(frame), returncode=0)


def _helper_session_block(sha256: str = "") -> dict:
    """A helper session block as the helper's Get-SessionBlock emits it."""
    helper = {"running": True, "version": uia.HELPER_VERSION,
              "capabilities": ["uia", "msaa"], "nonce": ""}
    if sha256:
        helper["sha256"] = sha256
    return {"session_id": 2, "interactive_user": "tester", "locked": False,
            "helper": helper}


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
    names the pipe ('hyperv-mcp-uia') and opens it through the raw
    CreateFileW P/Invoke (GENERIC_READ|GENERIC_WRITE, OPEN_EXISTING) with
    WriteFile/ReadFile serving the one-line-JSON protocol — not a
    NamedPipeClientStream constructor, not a Get-Content remoting shortcut,
    not an Invoke-Expression."""
    legs = UiLegRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    monkeypatch.setattr(uia, "_run_quser",
                        lambda cfg, ref, cred: {"user": "tester", "session_id": 2})

    out = uia.find(UNRESTRICTED, "test-vm-1", CRED,
                   {"process_name": "notepad", "control_type": "Document"})
    assert out["ok"] is True, out
    pipe_legs = [s for s in legs.scripts
                 if "hyperv-mcp-uia" in s and "CreateFileW" in s]
    assert pipe_legs, (
        "the read verb's transport must include the CLIENT_LEG_SCRIPT pipe "
        "leg: a script naming the helper pipe (hyperv-mcp-uia) opened through "
        "the raw CreateFileW P/Invoke"
    )
    leg = pipe_legs[0]
    assert "WriteFile" in leg and "ReadFile" in leg, (
        "the pipe client must serve the one-line-JSON protocol over raw "
        "WriteFile/ReadFile, not a remoting shortcut"
    )
    assert "NamedPipeClientStream" not in "\n".join(legs.scripts), (
        "the client leg no longer builds a NamedPipeClientStream (the helper's "
        "server end is a raw CreateNamedPipeW; the client matches it)"
    )


# ---------------------------------------------------------------------------
# 4. the session_unverified contract split
# ---------------------------------------------------------------------------

def test_session_unverified_is_refused(clean_uia_state, monkeypatch):
    """A session-less request on the HOST path: discovery finds nobody
    logged on (quser -> None), so the host forwards the request with
    target.session_id None (the broker DEFERS — validate_forward does not
    raise, because discovery failing on the host must not turn into a
    fabricated mismatch) and the HELPER's refusal comes back as the verb's
    returned error_class: session_unverified, ok False. The packaged helper
    artifact still carries the enforcement marker; the behavioural leg
    above is what keeps the contract from decaying into decoration."""
    legs = EchoLegRecorder(frame_for=lambda request: {
        "ok": False, "error_class": "session_unverified",
        "error": "the request does not carry this helper's interactive "
                 "session (2)"})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    monkeypatch.setattr(uia, "_run_quser", lambda cfg, ref, cred: None)

    out = uia.session_state(UNRESTRICTED, "test-vm-1", CRED)
    assert out["ok"] is False, out
    assert out["error_class"] == "session_unverified", out
    assert legs.requests, "the session-less request must still be forwarded"
    pipe_requests = [r for r in legs.requests if r.get("verb") == "session_state"]
    assert pipe_requests, legs.requests
    assert pipe_requests[0].get("target", {}).get("session_id") is None, (
        "the host forwarded the SESSION-LESS target for the helper to refuse"
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

    # the defer side: a request whose target carries session_id None against
    # a registration with a concrete session does NOT raise locally.
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

def test_production_autologon_registry_tail_runs_on_a_scratch_key():
    r"""F11: the old body re-implemented the DeleteValue call by hand; this
    one runs the PRODUCTION registry tail sliced verbatim out of
    uia._AUTOLOGON_INNER. The slice is the module's own text — the ONLY
    change is the retarget from LocalMachine\...\Winlogon to a scratch
    CURRENT-USER key (HKLM\Winlogon writes would need admin and must never
    run from a test; the RegistryKey API is hive-independent). On a clean
    image the Winlogon key never held DefaultPassword, so the production
    $ku.DeleteValue('DefaultPassword', $false) must tolerate a missing
    value without throwing."""
    powershell = shutil.which("powershell")
    if powershell is None:
        pytest.skip(
            "powershell.exe is not on PATH (the RegistryKey.DeleteValue leg "
            "runs on real Windows PowerShell only)"
        )
    inner = uia._AUTOLOGON_INNER
    start = inner.index("$ku = [Microsoft.Win32.Registry]")
    end_marker = "} finally { $ku.Close() }"
    end = inner.index(end_marker) + len(end_marker)
    snippet = inner[start:end]
    # sanity: this IS the production tail, not a re-implementation
    assert "AutoAdminLogon" in snippet and "DefaultPassword" in snippet
    assert "DeleteValue('DefaultPassword', $false)" in snippet
    scratch = "Software\\hyperv_mcp_f05_winlogon"
    snippet = snippet.replace(
        "[Microsoft.Win32.Registry]::LocalMachine",
        "[Microsoft.Win32.Registry]::CurrentUser")
    snippet = snippet.replace(
        "'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'",
        f"'{scratch}'")
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "$env:HYPERVMCP_AUTOLOGON_USER = 'tester'",
        f"[void][Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('{scratch}')",
        "try {",
        snippet,
        "} finally {",
        "    try { [void][Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey("
        f"'{scratch}') }} catch {{ }}",
        "}",
        "Write-Output 'tolerated'",
    ])
    proc = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    assert "tolerated" in proc.stdout, (
        f"the production registry tail must tolerate the missing "
        f"DefaultPassword value — stdout: {proc.stdout!r} "
        f"stderr: {proc.stderr!r}"
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


def test_parse_composed_pipe_leg_wrapper(parsed_ps):
    """(c) the COMPOSED _uia_guest_script output for a pipe leg in LOCAL
    mode — prefix + stdin line + vm-target preamble + b64 inner script +
    Invoke-Command -VMId wrapper — parses clean as a whole. Self-sufficient:
    the thread-local leg slot is set DIRECTLY (monkeypatch.setattr on a
    threading.local raises AttributeError when the attribute is absent, so
    the old body only passed when an earlier test had already populated the
    slot) and cleared again, so this test passes in ISOLATION."""
    leg_cred = CredentialSet("u", "p")
    uia._LEG.guid = VM_GUID
    uia._LEG.cred = leg_cred
    try:
        composed = uia._uia_guest_script(uia.CLIENT_LEG_SCRIPT, leg_cred, None)
    finally:
        uia._LEG.guid = None
        uia._LEG.cred = None
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
    TOP level, or evidence's helper gate and the frozen AC17 shape starve.
    The serving leg CORRELATES (it echoes the request's id — F4 makes a
    canned id like "abc123" unanswerable), and the mismatch case is pinned:
    a frame whose id does not correlate with the request is refused as
    helper_unavailable, never success."""
    byte_exact_result = {
        "active_session_id": 2, "interactive_user": "tester", "locked": False,
        "foreground_window": {"title": None, "process_name": "",
                              "pid": 0, "hwnd": 0}}

    legs = EchoLegRecorder(frame_for=lambda request: {
        "ok": True, "result": dict(byte_exact_result),
        "session": _helper_session_block()})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
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
    assert out["ok"] is True, out
    assert out["helper"]["running"] is True
    assert out["helper"]["version"] == uia.HELPER_VERSION

    # the mismatch case: a response whose id does not correlate with the
    # request id is refused (helper_unavailable), never success.
    def mismatched(request):
        frame = {"ok": True, "result": dict(byte_exact_result),
                 "session": _helper_session_block()}
        frame["id"] = "not-the-request-id"
        return frame

    monkeypatch.setattr(uia, "_run_uia_leg",
                        EchoLegRecorder(frame_for=mismatched))
    refused = uia.session_state(cfg, "test-vm-1", CredentialSet("tester", "pw"))
    assert refused["ok"] is False, refused
    assert refused["error_class"] == "helper_unavailable", refused

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


# ---------------------------------------------------------------------------
# 7. fix-wave behavioural pins (F11): the paths that had NO coverage
# ---------------------------------------------------------------------------

def _packaged_helper_bytes() -> bytes:
    return (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_bytes()
    )


def test_helper_sha256_integrity_gate(clean_uia_state, monkeypatch):
    """F14/F11: the host compares the helper-REPORTED sha256 with the
    PACKAGED bytes. An ok frame carrying the packaged hash surfaces
    ``helper.sha256_match: true`` (in the session block AND promoted to top
    level); an ok frame carrying any OTHER hash is refused — never success —
    with error_class helper_integrity_mismatch."""
    correct = hashlib.sha256(_packaged_helper_bytes()).hexdigest()
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    monkeypatch.setattr(uia, "_run_quser",
                        lambda cfg, ref, cred: {"user": "tester", "session_id": 2})

    legs = EchoLegRecorder(frame_for=lambda request: {
        "ok": True, "result": {},
        "session": _helper_session_block(sha256=correct)})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    out = uia.session_state(UNRESTRICTED, "test-vm-1", CRED)
    assert out["ok"] is True, out
    assert out["session"]["helper"]["sha256"] == correct
    assert out["session"]["helper"]["sha256_match"] is True, out
    assert out["helper"]["sha256_match"] is True, (
        "the helper facts (with sha256_match) are promoted to top level"
    )

    legs = EchoLegRecorder(frame_for=lambda request: {
        "ok": True, "result": {},
        "session": _helper_session_block(sha256="00" * 32)})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    refused = uia.session_state(UNRESTRICTED, "test-vm-1", CRED)
    assert refused["ok"] is False, refused
    assert refused["error_class"] == "helper_integrity_mismatch", refused


def test_wait_for_deadline_returns_the_last_slice_answer(clean_uia_state,
                                                         monkeypatch):
    """F6/F11/PRR-117 (wait_for budget): a wait whose every guest slice
    answers empty elements EXPIRES its budget and returns the LAST slice's
    answer (ok with empty elements) carrying timed_out True — the flag the
    review round required on BOTH settled outcomes — and each slice's
    request budget never exceeds one _WAIT_SLICE_S slice. The hit leg (a
    slice that ANSWERS) settles with timed_out False."""
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    monkeypatch.setattr(uia, "_run_quser",
                        lambda cfg, ref, cred: {"user": "tester", "session_id": 2})

    answered = {"now": False}
    legs = EchoLegRecorder(frame_for=lambda request: {
        "ok": True,
        "result": ({"elements": [{"element_id": "42:7", "name": "OK"}]}
                   if answered["now"] else {"elements": []}),
        "session": _helper_session_block()})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)

    out = uia.wait_for(UNRESTRICTED, "test-vm-1", CRED, {"name": "OK"},
                       timeout_s=1)
    assert out["ok"] is True, out
    assert out["elements"] == [], out
    assert out["timed_out"] is True, (
        "a wait whose whole budget expired unanswered must carry "
        "timed_out True"
    )
    assert legs.requests, "the wait must drive its pipe leg"
    wait_requests = [r for r in legs.requests if r.get("verb") == "wait_for"]
    assert wait_requests, legs.requests
    assert all(r["args"]["timeout_s"] <= uia._WAIT_SLICE_S
               for r in wait_requests), (
        "every wait slice's budget must be bounded by one _WAIT_SLICE_S slice"
    )

    # the hit leg: a slice that ANSWERS settles the wait — timed_out False.
    answered["now"] = True
    hit = uia.wait_for(UNRESTRICTED, "test-vm-1", CRED, {"name": "OK"},
                       timeout_s=5)
    assert hit["ok"] is True, hit
    assert hit["elements"], hit
    assert hit["timed_out"] is False, (
        "an answered wait must carry timed_out False, not a missing flag"
    )


class ProvisionLegRecorder:
    """uia._run_uia_leg stand-in for the provisioning path: serves each
    provision/teardown leg its documented frame, keyed by script markers."""

    def __init__(self, install_ok: bool = True):
        self.scripts: list[str] = []
        self.install_ok = install_ok

    def _ps(self, frame: dict) -> pswindows.PSResult:
        return pswindows.PSResult(stdout=json.dumps(frame), returncode=0)

    def __call__(self, cfg, script, *, stdin_b64=None, timeout_s=None, **kwargs):
        self.scripts.append(script)
        if "LsaStorePrivateDataNull" in script:      # _TEARDOWN_WINLOGON_INNER
            return self._ps({"ok": True, "lsa_secret_deleted": True,
                             "autologon_restored": True})
        if "Unregister-ScheduledTask" in script:     # _RESET_INNER
            return self._ps({"ok": True, "task_unregistered": True,
                             "directories_removed": 2})
        if "LsaStorePrivateData" in script:          # _AUTOLOGON_INNER
            return self._ps({"ok": True, "autologon": True})
        if "Register-ScheduledTask" in script:       # _TASK_INNER
            return self._ps({"ok": True, "task_registered": True,
                             "started": True})
        if "WriteAllBytes" in script:                # _INSTALL_INNER
            if not self.install_ok:
                return self._ps({"ok": False, "error": "disk full (test stub)"})
            return self._ps({"ok": True, "installed": True,
                             "helper_version": uia.HELPER_VERSION})
        # the session_state probe after install (the pipe client leg)
        return self._ps({"ok": True,
                         "result": {"active_session_id": 2},
                         "session": _helper_session_block()})


def test_provision_install_result_keys_and_failed_branch(clean_uia_state,
                                                         monkeypatch):
    """F11 (provisioning return value): the INSTALL result carries the
    documented keys, and a failed install leg returns the
    helper_install_failed branch (ok False with the error_class) instead of
    a half-populated success dict."""
    legs = ProvisionLegRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())

    out = uia.provision_helper(UNRESTRICTED, "test-vm-1", CRED,
                               autologon=True, confirm=True)
    assert out["ok"] is True, out
    assert out["autologon_configured"] is True
    assert out["task_registered"] is True
    assert out["helper_version"] == uia.HELPER_VERSION
    assert out["helper_running"] is True
    assert out["guest_uuid_read"] is False  # the stub host leg reads no UUID
    assert out["helper_dir"].startswith(
        "C:\\ProgramData\\hyperv-mcp\\uia-helper-")
    assert uia._INSTALLS[VM_GUID]["nonce"], (
        "the install records a per-install nonce"
    )

    failing = ProvisionLegRecorder(install_ok=False)
    monkeypatch.setattr(uia, "_run_uia_leg", failing)
    failed = uia.provision_helper(UNRESTRICTED, "test-vm-1", CRED,
                                  autologon=True, confirm=True)
    assert failed["ok"] is False, failed
    assert failed["error_class"] == "helper_install_failed", failed
    # PRR-117c: the failure result carries the SAME status keys as the
    # success result (the false/empty values they had at failure time),
    # never a bare {ok, error_class, error} triple.
    for key in ("autologon_configured", "task_registered", "helper_version",
                "helper_running", "reboot_required", "guest_uuid_read",
                "helper_dir"):
        assert key in failed, (key, failed)
    assert failed["helper_version"] == uia.HELPER_VERSION, failed
    assert failed["autologon_configured"] is False, failed
    assert failed["task_registered"] is False, failed
    assert failed["helper_running"] is False, failed
    assert failed["reboot_required"] is False, failed


def test_provision_teardown_result(clean_uia_state, monkeypatch):
    """F13/F11 (provisioning's inverse): teardown=True stops the task,
    removes the helper directories, deletes the LSA secret and restores
    Winlogon — the result carries the documented teardown keys, the
    install/task/autologon-store legs never run, and the recorded install
    facts for the VM are dropped."""
    legs = ProvisionLegRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    uia._INSTALLS[VM_GUID] = {
        "dir": "C:\\ProgramData\\hyperv-mcp\\uia-helper-x",
        "uuid": "", "nonce": "n", "version": "1"}
    try:
        out = uia.provision_helper(UNRESTRICTED, "test-vm-1", CRED,
                                   autologon=True, confirm=True, teardown=True)
    finally:
        uia._INSTALLS.pop(VM_GUID, None)
    assert out["ok"] is True, out
    assert out["torn_down"] is True
    assert out["task_unregistered"] is True
    assert out["helper_directories_removed"] == 2
    assert out["lsa_secret_deleted"] is True
    assert out["autologon_restored"] is True
    blob = "\n".join(legs.scripts)
    assert "Register-ScheduledTask" not in blob, (
        "teardown must not register the helper task"
    )
    assert "WriteAllBytes" not in blob, "teardown must not install helper bytes"
    assert "LsaStorePrivateData " not in blob.replace(
        "LsaStorePrivateDataNull", ""), (
        "teardown deletes the LSA secret; it never stores one"
    )
    assert VM_GUID not in uia._INSTALLS, (
        "teardown drops the recorded install facts for the VM"
    )


# ---------------------------------------------------------------------------
# 8. PRR-112 residual pins: the guest branches that had no behavioural
#    coverage, driven on the REAL helper script under local PS 5.1 (no VM,
#    no pipe, no desktop). The harness slices the packaged helper's own
#    function bodies out of the artifact — the branches under test are the
#    helper's real code, only the UIA element source is synthetic.
# ---------------------------------------------------------------------------

PIN_GUID = "11111111-2222-3333-4444-555555555555"
PIN_SID = "S-1-5-21-1000-2000-3000-1001"


def _helper_functions_and_startup_slice() -> str:
    """The packaged helper's native P/Invoke declarations, its functions,
    PLUS the startup section that reads version.txt / nonce.txt / uuid.txt
    from $HelperDir (everything between the `Add-Type -Namespace
    HypervMcp.Uia -Name Native` block and the serve-loop worker script) —
    so a scratch HelperDir provisions the identity files the real
    Read-HelperFile calls consume, and the real Get-LockState /
    Get-ForegroundWindow legs work (local user32/wtsapi32 only)."""
    helper = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8-sig")
    )
    start = helper.index("Add-Type -Namespace HypervMcp.Uia -Name Native")
    end = helper.index("$workerScript = @'")
    return helper[start:end]


def _run_helper_scratch(scratch_dir, cases_ps: str, tmp_path) -> list[dict]:
    """Run `cases_ps` after the helper's real startup read the provisioned
    files from `scratch_dir` (the harness sets $HelperDir BEFORE the startup
    slice); parse one-JSON-per-case stdout. Real powershell.exe only."""
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "Add-Type -AssemblyName UIAutomationClient",
        "Add-Type -AssemblyName UIAutomationTypes",
        "$HelperDir = " + pswindows.ps_quote(str(scratch_dir)),
        _helper_functions_and_startup_slice(),
        cases_ps,
    ])
    script_file = tmp_path / "helper-scratch-cases.ps1"
    script_file.write_text(script, encoding="utf-8-sig")
    proc = subprocess.run(
        [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(script_file)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"helper scratch harness failed — stdout: {proc.stdout!r} "
        f"stderr: {proc.stderr[-2000:]!r}"
    )
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            out.append(json.loads(line))
    assert out, f"no case JSON in scratch harness output: {proc.stdout!r}"
    return out


def _scratch_dir(tmp_path, files: dict[str, str]):
    """A helper directory with the given provisioned files (or none)."""
    scratch = tmp_path / "helper-home"
    scratch.mkdir()
    for name, text in files.items():
        (scratch / name).write_text(text + "\n", encoding="ascii")
    return scratch


def test_helper_target_and_nonce_refusals_from_provisioned_files(tmp_path):
    """PRR-112 residual (the security branches, real PS 5.1, scratch dir):
    the helper's startup REALLY reads version.txt/nonce.txt/uuid.txt from
    $HelperDir (the packaged Read-HelperFile + startup lines, not a stub),
    then Invoke-Request enforces the identity gates with those values:

      control      — everything matching serves a read verb (session_state
                     ok). This is also the round-trip probe leg: refusals
                     and a successful read verb both served locally.
      wrong_guid   — a request naming ANOTHER VM's uuid is refused
                     target_mismatch (the PRR-104 cross-VM protection).
      wrong_nonce  — a request with the wrong nonce is refused
                     nonce_mismatch BEFORE any dispatch.
      no_nonce     — a request carrying no nonce key at all is refused
                     nonce_mismatch.
      live_changed — a live SMBIOS uuid that no longer equals the recorded
                     one is refused target_mismatch (fail closed).

    What this proves: the real file-reading startup feeds the real
    pre-dispatch gates and each named refusal branch fires with its
    documented error_class. What it does NOT prove: the pipe serve loop,
    the dispatch runspace bound, or any guest/VM behaviour — Get-LiveUuid
    is stubbed after the slice (a local CIM read would return this
    machine's real SMBIOS uuid, never the scratch recording), and the
    target carries the harness process's own real sid/session (read from
    the startup's $identity) so only the named dimension mismatches."""
    if not _ps_available():
        pytest.skip("Windows PowerShell 5.1 not available")
    nonce = "nonce-p112"
    scratch = _scratch_dir(tmp_path, {
        "version.txt": "1",
        "nonce.txt": nonce,
        "uuid.txt": PIN_GUID,
    })

    def target_ps(guid="$recordedUuid") -> str:
        return (f"@{{ vm_guid = {guid}; user_sid = $identity.sid; "
                f"session_id = $identity.session_id }}")

    cases = "\n".join([
        # the live SMBIOS read is stubbed to echo the recording (the
        # live_changed leg below overrides it again — later defs win)
        "function Get-LiveUuid { $recordedUuid }",
        "$ok_target = " + target_ps(),
        # control: every dimension matches -> the read verb succeeds
        f"$r0 = Invoke-Request @{{ id = 'ctl'; verb = 'session_state'; nonce = '{nonce}'; min_version = '1'; target = $ok_target }}",
        "@{ case = 'control'; ok = $r0.ok; error_class = $r0.error_class } | ConvertTo-Json -Compress",
        # a request targeting ANOTHER VM -> target_mismatch
        "$r1 = Invoke-Request @{ id = 't1'; verb = 'session_state'; nonce = '" + nonce + "'; min_version = '1'; target = " + target_ps("'99999999-9999-9999-9999-999999999999'") + " }",
        "@{ case = 'wrong_guid'; ok = $r1.ok; error_class = $r1.error_class } | ConvertTo-Json -Compress",
        # wrong nonce -> nonce_mismatch (before any dispatch)
        "$r2 = Invoke-Request @{ id = 't2'; verb = 'session_state'; nonce = 'not-the-nonce'; min_version = '1'; target = $ok_target }",
        "@{ case = 'wrong_nonce'; ok = $r2.ok; error_class = $r2.error_class } | ConvertTo-Json -Compress",
        # no nonce key at all -> nonce_mismatch
        "$r3 = Invoke-Request @{ id = 't3'; verb = 'session_state'; min_version = '1'; target = $ok_target }",
        "@{ case = 'no_nonce'; ok = $r3.ok; error_class = $r3.error_class } | ConvertTo-Json -Compress",
        # the live uuid drifts from the recording -> target_mismatch
        "function Get-LiveUuid { 'deadbeef-0000-0000-0000-000000000000' }",
        f"$r4 = Invoke-Request @{{ id = 't4'; verb = 'session_state'; nonce = '{nonce}'; min_version = '1'; target = $ok_target }}",
        "@{ case = 'live_changed'; ok = $r4.ok; error_class = $r4.error_class } | ConvertTo-Json -Compress",
    ])
    rows = {row["case"]: row for row in _run_helper_scratch(scratch, cases, tmp_path)}

    assert rows["control"]["ok"] is True, rows["control"]
    for case in ("wrong_guid", "live_changed"):
        assert rows[case]["ok"] is False, rows[case]
        assert rows[case]["error_class"] == "target_mismatch", rows[case]
    for case in ("wrong_nonce", "no_nonce"):
        assert rows[case]["ok"] is False, rows[case]
        assert rows[case]["error_class"] == "nonce_mismatch", rows[case]


def test_helper_missing_uuid_file_fails_closed(tmp_path):
    """PRR-112 residual (fail-closed leg): a scratch helper directory with
    version.txt and nonce.txt but NO uuid.txt must refuse every request as
    target_mismatch — the recorded-identity dimension is missing, so the
    helper fails closed instead of serving. Real startup Read-HelperFile
    calls; proves the missing-record branch of the target gate and NOT the
    pipe/serve plumbing."""
    if not _ps_available():
        pytest.skip("Windows PowerShell 5.1 not available")
    scratch = _scratch_dir(tmp_path, {"version.txt": "1",
                                      "nonce.txt": "nonce-p112"})
    cases = "\n".join([
        "function Get-LiveUuid { $recordedUuid }",
        "$target = @{ vm_guid = '" + PIN_GUID + "'; user_sid = $identity.sid; session_id = $identity.session_id }",
        "$r = Invoke-Request @{ id = 't'; verb = 'session_state'; nonce = 'nonce-p112'; min_version = '1'; target = $target }",
        "@{ case = 'no_uuid_file'; ok = $r.ok; error_class = $r.error_class; recorded_empty = ([string]::IsNullOrEmpty($recordedUuid)) } | ConvertTo-Json -Compress",
    ])
    rows = {row["case"]: row for row in _run_helper_scratch(scratch, cases, tmp_path)}
    row = rows["no_uuid_file"]
    assert row["recorded_empty"] is True, (
        "sanity: the real startup must have read uuid.txt as missing/empty"
    )
    assert row["ok"] is False and row["error_class"] == "target_mismatch", row


def test_helper_ambiguous_selector_refusal(tmp_path):
    """PRR-112 residual (ambiguous_selector): a selector matching MORE than
    one element is refused with error_class ambiguous_selector and the
    matched CANDIDATES ride the refusal — driven through the REAL
    Invoke-Request dispatch and the REAL Select-One (the function sliced
    verbatim from the packaged artifact); only Resolve-Target is stubbed to
    return two synthetic elements, because a real desktop cannot be
    arranged deterministically from a unit test. Proves the multi-match
    branch and its candidates payload; does NOT prove desktop-wide
    matching itself (that is PRR-108's pinned territory)."""
    if not _ps_available():
        pytest.skip("Windows PowerShell 5.1 not available")
    uuid = PIN_GUID.lower()
    cases = "\n".join([
        "$HelperVersion = '1'",
        "$ownNonce = 'nonce-amb'",
        f"$recordedUuid = '{uuid}'",
        "$identity = @{ sid = '" + PIN_SID + "'; user = 'tester'; session_id = 1 }",
        "$capabilities = @('uia','msaa')",
        "$MaxMatches = 200; $MaxValueChars = 65536",
        "function Get-LockState { $false }",
        f"function Get-LiveUuid {{ '{uuid}' }}",
        "function Test-OwnsInputDesktop { $true }",
        "function Get-ForegroundWindow { $null }",
        "function Get-SessionBlock { @{ session_id = 1 } }",
        # synthetic matched elements: PSObjects shaped like UIA elements
        # as far as Select-One reads them (Current.Name /
        # Current.ControlType.ProgrammaticName / BoundingRectangle)
        "function New-FakeEl([string]$n) {",
        "    $ct = New-Object System.Management.Automation.PSObject",
        "    $ct | Add-Member -MemberType NoteProperty -Name ProgrammaticName -Value 'ControlType.Button'",
        "    $cur = New-Object System.Management.Automation.PSObject",
        "    $cur | Add-Member -MemberType NoteProperty -Name Name -Value $n",
        "    $cur | Add-Member -MemberType NoteProperty -Name ControlType -Value $ct",
        "    $el = New-Object System.Management.Automation.PSObject",
        "    $el | Add-Member -MemberType NoteProperty -Name Current -Value $cur",
        "    $el",
        "}",
        "function Resolve-Target { param($selector) @((New-FakeEl 'First'), (New-FakeEl 'Second')) }",
        f"$target = @{{ vm_guid = '{uuid}'; user_sid = '{PIN_SID}'; session_id = 1 }}",
        "$r = Invoke-Request @{ id = 'amb'; verb = 'find'; nonce = 'nonce-amb'; min_version = '1'; target = $target; selector = @{ name = 'Duplicate' } }",
        "@{ case = 'ambiguous'; ok = $r.ok; error_class = $r.error_class; candidates = @($r.candidates).Count; first_name = $r.candidates[0].name } | ConvertTo-Json -Compress",
    ])
    rows = {row["case"]: row for row in _run_helper_dispatch(cases, tmp_path)}
    row = rows["ambiguous"]
    assert row["ok"] is False, row
    assert row["error_class"] == "ambiguous_selector", row
    assert row["candidates"] == 2, row
    assert row["first_name"] == "First", (
        "the refusal must carry the matched candidates so a caller can "
        f"disambiguate: {row}"
    )


def test_helper_msaa_legacy_bridge_fires(tmp_path):
    """PRR-112 residual (the LegacyIAccessible msaa bridge). EMPIRICAL
    FINDING pinned here: the in-box .NET Framework UIA wrapper ships NO
    managed System.Windows.Automation.LegacyIAccessiblePattern type (and
    AutomationPattern.LookupById(10018) answers null), so the helper's old
    per-request type literal could never resolve — the bridge was dead
    code, its TypeNotFound swallowed by the surrounding catch. The helper
    now probes the pattern object ONCE at startup and skips the fallback
    cleanly where the type is absent.

    This pin drives the REAL Invoke-Request dispatch with $legacyPattern
    set to a sentinel object and a synthetic element whose GetCurrentPattern
    answers the sentinel with a recording fake: set_value routes the text
    through the bridge's SetValue and reports pattern 'LegacyIAccessible'
    with the length; invoke fires DoDefaultAction and reports the same
    pattern. Proves: the fallback ROUTING fires and reports itself (UIA
    patterns tried first, msaa bridge last). Does NOT prove: any real
    legacy control end to end — no desktop is driven, the sentinel stands
    in for a pattern object this .NET build cannot express, and on PS 5.1
    production the startup probe leaves the branch skipped (the bridge
    goes live only where the wrapper defines the type)."""
    if not _ps_available():
        pytest.skip("Windows PowerShell 5.1 not available")
    uuid = PIN_GUID.lower()
    cases = "\n".join([
        "$HelperVersion = '1'",
        "$ownNonce = 'nonce-msaa'",
        f"$recordedUuid = '{uuid}'",
        "$identity = @{ sid = '" + PIN_SID + "'; user = 'tester'; session_id = 1 }",
        "$capabilities = @('uia','msaa')",
        "$MaxMatches = 200; $MaxValueChars = 65536",
        "function Get-LockState { $false }",
        f"function Get-LiveUuid {{ '{uuid}' }}",
        "function Test-OwnsInputDesktop { $true }",
        "function Get-ForegroundWindow { $null }",
        "function Get-SessionBlock { @{ session_id = 1 } }",
        # the startup probe product: where the wrapper has no managed
        # LegacyIAccessiblePattern this is $null; the sentinel makes the
        # branch live so its routing is pinnable. (The fake speaks through
        # $global: names because PowerShell's dynamic scoping would resolve
        # a bare $legacy inside the ScriptMethod to Invoke-Request's own
        # local `$legacy = $null` on the call chain.)
        "$global:LegacySentinel = New-Object System.Management.Automation.PSObject",
        "$legacyPattern = $global:LegacySentinel",
        "$global:FakeLegacy = New-Object System.Management.Automation.PSObject",
        "$global:FakeLegacy | Add-Member -MemberType ScriptMethod -Name SetValue -Value { param($t) $global:LegacySetTo = $t }",
        "$global:FakeLegacy | Add-Member -MemberType ScriptMethod -Name DoDefaultAction -Value { $global:LegacyFired = $true }",
        "$fakeEl = New-Object System.Management.Automation.PSObject",
        "$fakeEl | Add-Member -MemberType ScriptMethod -Name GetCurrentPattern -Value {",
        "    param($p)",
        "    if ($p -eq $global:LegacySentinel) { return $global:FakeLegacy }",
        "    throw (New-Object InvalidOperationException('no UIA pattern on the synthetic legacy element'))",
        "}",
        "function Resolve-Target { param($selector) @($fakeEl) }",
        "function Select-One { param($elements, $selector) $elements[0] }",
        f"$target = @{{ vm_guid = '{uuid}'; user_sid = '{PIN_SID}'; session_id = 1 }}",
        # set_value: ValuePattern absent -> the msaa bridge carries the text
        "$global:LegacySetTo = $null",
        "$r1 = Invoke-Request @{ id = 'msaa-sv'; verb = 'set_value'; nonce = 'nonce-msaa'; min_version = '1'; target = $target; selector = @{ name = 'LegacyBox' }; args = @{ value = 'legacy-text' } }",
        "@{ case = 'set_value'; ok = $r1.ok; pattern = $r1.result.pattern; length = $r1.result.length; set_to = $global:LegacySetTo } | ConvertTo-Json -Compress",
        # invoke: no UIA action pattern -> DoDefaultAction fires
        "$global:LegacyFired = $false",
        "$r2 = Invoke-Request @{ id = 'msaa-inv'; verb = 'invoke'; nonce = 'nonce-msaa'; min_version = '1'; target = $target; selector = @{ name = 'LegacyBox' } }",
        "@{ case = 'invoke'; ok = $r2.ok; pattern = $r2.result.pattern; fired = $global:LegacyFired } | ConvertTo-Json -Compress",
        # the probe itself, recorded for the run log: on the in-box .NET
        # Framework wrapper the managed LegacyIAccessiblePattern type does
        # not exist, so production leaves the bridge skipped there.
        "$probed = $null",
        "try { $probed = [System.Windows.Automation.LegacyIAccessiblePattern]::Pattern } catch { $probed = $null }",
        "@{ case = 'probe'; type_exists = ($null -ne $probed) } | ConvertTo-Json -Compress",
    ])
    rows = {row["case"]: row for row in _run_helper_dispatch(cases, tmp_path)}

    set_row = rows["set_value"]
    assert set_row["ok"] is True, set_row
    assert set_row["pattern"] == "LegacyIAccessible", set_row
    assert set_row["length"] == len("legacy-text"), set_row
    assert set_row["set_to"] == "legacy-text", (
        "the msaa bridge must actually CARRY the value into "
        f"LegacyIAccessible.SetValue: {set_row}"
    )

    inv_row = rows["invoke"]
    assert inv_row["ok"] is True, inv_row
    assert inv_row["pattern"] == "LegacyIAccessible", inv_row
    assert inv_row["fired"] is True, (
        "DoDefaultAction must actually fire through the bridge: " f"{inv_row}"
    )


def test_helper_session_block_lock_is_per_response_fresh(tmp_path):
    """PRR-112 residual (per-response session-lock freshness): the REAL
    Get-SessionBlock (sliced verbatim from the artifact, alongside the real
    startup that reads the provisioned files) consults the lock state on
    EVERY call — flipping the lock source between two calls flips the
    reported `locked` while the session identity stays stable, so the serve
    loop's per-response `$response.session = Get-SessionBlock` cannot serve
    a stale lock from helper start. Get-LockState is replaced after the
    slice with a flippable stub (the real one queries the LOCAL session,
    which a test cannot lock). Proves: the block is computed per call, not
    cached. Does NOT prove: the serve loop itself invokes it per response —
    that wiring is pinned textually below on the packaged worker script."""
    if not _ps_available():
        pytest.skip("Windows PowerShell 5.1 not available")
    scratch = _scratch_dir(tmp_path, {"version.txt": "1"})
    cases = "\n".join([
        "$global:LockFlip = $false",
        "function Get-LockState { $global:LockFlip }",
        "$b1 = Get-SessionBlock",
        "$global:LockFlip = $true",
        "$b2 = Get-SessionBlock",
        "@{ case = 'freshness'; locked1 = [bool]$b1.locked; locked2 = [bool]$b2.locked; same_session = ($b1.session_id -eq $b2.session_id); version_stable = ($b1.helper.version -eq $b2.helper.version) } | ConvertTo-Json -Compress",
    ])
    rows = {row["case"]: row for row in _run_helper_scratch(scratch, cases, tmp_path)}
    row = rows["freshness"]
    assert row["locked1"] is False and row["locked2"] is True, (
        "the lock state must be recomputed per Get-SessionBlock call — a "
        f"session locked AFTER helper start must be reported locked: {row}"
    )
    assert row["same_session"] is True and row["version_stable"] is True, row

    # the serve-loop wiring: every response frame's session block is built
    # by a fresh Get-SessionBlock call inside the packaged worker script.
    helper_text = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8")
    )
    assert "$response.session = Get-SessionBlock" in helper_text, (
        "the worker serve loop must attach a freshly computed session "
        "block to every response (per-response lock freshness)"
    )


# ---------------------------------------------------------------------------
# 9. PRR-117 shape-contract pins: one clamp, one session key set
# ---------------------------------------------------------------------------

def test_inspect_clamps_match_the_documented_bounds(clean_uia_state, monkeypatch):
    """PRR-117d (clamp unification): ONE clamp for both tree paths. The
    helper path (uia.inspect) clamps its framed request to depth 1..6 and
    max_elements 1..500 — the numbers the tool docstrings and evidence's
    PS Direct walk (frozen pins) promise. The old helper-path divergence
    (1..8 / 1..2000) is gone, and the two modules' constants are pinned
    EQUAL so they cannot drift apart again."""
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    monkeypatch.setattr(uia, "_run_quser",
                        lambda cfg, ref, cred: {"user": "tester", "session_id": 2})
    legs = EchoLegRecorder(frame_for=lambda request: {
        "ok": True, "result": {"elements": 0, "truncated": False, "tree": None},
        "session": _helper_session_block()})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)

    out = uia.inspect(UNRESTRICTED, "test-vm-1", CRED, depth=99,
                      max_elements=99999)
    assert out["ok"] is True, out
    inspect_requests = [r for r in legs.requests if r.get("verb") == "inspect"]
    assert inspect_requests, legs.requests
    args = inspect_requests[0].get("args") or {}
    assert args.get("depth") == uia.INSPECT_MAX_DEPTH == 6, args
    assert args.get("max_elements") == uia.INSPECT_MAX_ELEMENTS == 500, args
    assert (uia.INSPECT_MAX_DEPTH, uia.INSPECT_MAX_ELEMENTS) == (
        evidence._UIA_MAX_DEPTH, evidence._UIA_MAX_ELEMENTS), (
        "the helper path and the PS Direct walk must share ONE clamp"
    )


def test_helper_worker_bounds_the_dispatch_not_just_the_read():
    """PRR-113/F12 residual pin (artifact text — the serve loop itself
    cannot run in a unit harness): the packaged worker script bounds the
    per-request VERB DISPATCH, not only the request read. It must
    (a) run the dispatch in a fresh child runspace created per request,
    (b) poll BeginInvoke's completion against a deadline,
    (c) answer a hung dispatch from the pipe-owning runspace with the
        dispatch_timeout error class,
    (d) stop/dispose the abandoned child asynchronously so the accept
        loop survives, and
    (e) hand the child ONLY the parsed request hashtable — the raw
        client stream ($line) and the pipe handle never cross into it.
    What this does NOT prove: an actual hung UIA call timing out end to
    end (that needs a live desktop wedged mid-dispatch); the markers pin
    the bound's presence and shape in the shipped worker script."""
    helper_text = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8")
    )
    worker_start = helper_text.index("$workerScript = @'")
    worker_end = helper_text.index("'@", worker_start + 1)
    worker = helper_text[worker_start:worker_end]
    # (a) fresh child runspace per request
    assert "[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($sessionState)" in worker
    # (b) the completion poll runs against a deadline
    assert "BeginInvoke()" in worker and "dispatchDeadline" in worker
    assert "while (-not $childAsync.IsCompleted)" in worker
    # (c) the timeout answer names dispatch_timeout
    assert "dispatch_timeout" in worker
    # (d) the abandoned child is stopped/disposed asynchronously
    assert "BeginStop(" in worker and "CloseAsync()" in worker
    # (e) the child script receives ONLY the parsed request hashtable
    dispatch_script = "param([hashtable]$Request) Invoke-Request $Request"
    assert dispatch_script in worker
    add_script_pos = worker.index(dispatch_script)
    assert "$line" not in worker[add_script_pos:add_script_pos + len(dispatch_script)]
    # the read deadline is still in force (the fix must not remove it)
    assert "$deadline = [DateTime]::UtcNow.AddMilliseconds($RequestTimeoutMs)" in worker


def test_evidence_ui_tree_shape_contract(monkeypatch):
    """PRR-117a (result-shape contract): whenever a tree was requested,
    ui_tree carries BOTH `session` and `source` on every path, and every
    session block carries ONE key set — {session_id, interactive,
    input_desktop} — with None filling a dimension a path cannot know.
    Pins the helper path (input_desktop None, source "helper"), the
    unchanged-skip path (session None, source "skipped_unchanged"), the
    walk failure path (session None, source "ps_direct_walk") and the
    no_interactive_session refusal (the 3-key session riding the refusal,
    source "ps_direct_walk"). The frozen test_evidence.py already pins
    the walk success path's exact shape, so it is not re-pinned here."""
    cfg = UNRESTRICTED

    def fake_screenshot(cfg_, vm_name="", width=1024, height=768, save_path="",
                        vm_id="", fmt="", quality=None, scale=None, crop=None,
                        if_changed_from=""):
        meta = {"vm_name": "test-vm-1", "vm_id": VM_GUID, "width": 8,
                "height": 8, "frame_hash": "a" * 64,
                "captured_at": "2026-10-29T00:00:00.000+00:00",
                "capture_method": "stub"}
        if if_changed_from == "a" * 64:
            return None, {**meta, "unchanged": True}
        return object(), meta

    monkeypatch.setattr(evidence.console, "screenshot", fake_screenshot)
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())

    # helper path: session_state answers a live, version-matched helper
    monkeypatch.setattr(uia, "session_state", lambda cfg_, ref, cred_: {
        "ok": True, "active_session_id": 2, "interactive_user": "tester",
        "locked": False,
        "helper": {"running": True, "version": uia.HELPER_VERSION}})
    monkeypatch.setattr(uia, "inspect", lambda cfg_, ref, cred_,
                        selector=None, **kw: {
        "ok": True, "elements": 1, "truncated": False,
        "tree": {"name": "Desktop"}})
    out = evidence.capture_evidence(cfg, "test-vm-1", ui_tree=True, cred=CRED)
    ui = out["meta"]["ui_tree"]
    assert ui["source"] == "helper", ui
    assert ui["session"] == {"session_id": 2, "interactive": True,
                             "input_desktop": None}, (
        "the helper path reports the ONE session key set, None filling the "
        f"input-desktop dimension its session_state answer cannot know: {ui}"
    )

    # unchanged frame: the skip still carries session (None) and a source
    # naming why no path ran
    out = evidence.capture_evidence(cfg, "test-vm-1", ui_tree=True, cred=CRED,
                                    if_changed_from="a" * 64)
    ui = out["meta"]["ui_tree"]
    assert ui["skipped"] is True and ui["session"] is None, ui
    assert ui["source"] == "skipped_unchanged", ui

    # walk failure: session None, source ps_direct_walk
    monkeypatch.setattr(uia, "session_state", lambda *a: {"ok": False})

    def boom(*a, **k):
        raise RuntimeError("no interactive desktop")

    monkeypatch.setattr(evidence, "run_guest_inner", boom)
    out = evidence.capture_evidence(cfg, "test-vm-1", ui_tree=True, cred=CRED)
    ui = out["meta"]["ui_tree"]
    assert ui["ok"] is False and ui["session"] is None, ui
    assert ui["source"] == "ps_direct_walk", ui

    # walk refusal: the 3-key session rides the no_interactive_session
    # refusal with source ps_direct_walk (input_desktop None when the
    # walker emitted none)
    monkeypatch.setattr(evidence, "run_guest_inner",
                        lambda *a, **k: {"session_id": 0, "interactive": False,
                                         "elements": 1, "truncated": False,
                                         "tree": {}})
    out = evidence.capture_evidence(cfg, "test-vm-1", ui_tree=True, cred=CRED)
    ui = out["meta"]["ui_tree"]
    assert ui["ok"] is False and ui["error_class"] == "no_interactive_session"
    assert ui["session"] == {"session_id": 0, "interactive": False,
                             "input_desktop": None}, ui
    assert ui["source"] == "ps_direct_walk", ui


# ---------------------------------------------------------------------------
# 10. NEW-R2-1 behavioural pin: the real serve loop answers id + session
# ---------------------------------------------------------------------------

def test_serve_loop_ok_frame_carries_id_and_session(tmp_path):
    """NEW-R2-1 (reviewer round 2, Critical): EndInvoke yields the child's
    output as a PSDataCollection, and the id/session attaches throw on a
    collection while the tolerant catches hide it — every ok frame shipped
    WITHOUT its correlation id and session block, silently killing the
    host's frame correlation, the sha256 integrity gate, evidence's
    helper-first path, registration seeding, and helper_running reporting
    while every stubbed gate stayed green. The pin starts the PACKAGED
    helper as a real process over a real local pipe (this desktop is the
    'guest'; no VM, no credential prompt) and asserts the ok frame carries
    BOTH keys plus the sha256 the host's integrity gate reads."""
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    if not os.path.isfile(ps):
        pytest.skip("powershell.exe is not present")
    helper_path = str(
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
    )
    scratch = tmp_path / "helper-home"
    scratch.mkdir()
    nonce = "nonce-" + os.urandom(6).hex()
    req_id = "ctl-" + os.urandom(4).hex()
    child = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "Add-Type -AssemblyName UIAutomationClient",
        "Add-Type -AssemblyName UIAutomationTypes",
        "$scratch = " + pswindows.ps_quote(str(scratch)),
        "$nonce = " + pswindows.ps_quote(nonce),
        # provision the helper's facts beside the script, in the scratch
        # dir the env override points at ($PSScriptRoot stays the package
        # dir, so the override is what the helper reads)
        "Set-Content -Path (Join-Path $scratch 'version.txt') -Value '1'",
        "Set-Content -Path (Join-Path $scratch 'nonce.txt') -Value $nonce",
        "$uuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID.Trim().ToLowerInvariant()",
        "Set-Content -Path (Join-Path $scratch 'uuid.txt') -Value $uuid",
        "Set-Item -Path Env:HYPERVMCP_HELPER_DIR -Value $scratch",
        "$helperProc = Start-Process -FilePath 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' "
        "-ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"
        + pswindows.ps_quote(helper_path) + " -PassThru -WindowStyle Hidden",
        "function RoundTrip($req, $connectTimeoutMs, $readTimeoutMs) {",
        "  $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'hyperv-mcp-uia', [System.IO.Pipes.PipeDirection]::InOut)",
        "  try {",
        "    $c.Connect($connectTimeoutMs)",
        "    $json = ($req | ConvertTo-Json -Compress -Depth 8)",
        "    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + \"`n\")",
        "    $c.Write($bytes, 0, $bytes.Length)",
        "    $c.Flush()",
        "    $reader = New-Object System.IO.StreamReader($c, [System.Text.Encoding]::UTF8)",
        "    $task = $reader.ReadLineAsync()",
        "    if (-not $task.Wait($readTimeoutMs)) { return $null }",
        "    return ($task.Result | ConvertFrom-Json)",
        "  } finally { $c.Dispose() }",
        "}",
        "$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        "$sess = [System.Diagnostics.Process]::GetCurrentProcess().SessionId",
        "$target = @{ vm_guid = $uuid; user_sid = $sid; session_id = $sess }",
        "$ctl = $null",
        "for ($i = 0; $i -lt 30; $i++) {",
        "  try { $ctl = RoundTrip @{ id = " + pswindows.ps_quote(req_id) + "; verb = 'session_state'; nonce = $nonce; min_version = '1'; target = $target } 10000 20000 } catch { Start-Sleep -Milliseconds 500 }",
        "  if ($null -ne $ctl) { break }",
        "  Start-Sleep -Milliseconds 500",
        "}",
        "if ($null -eq $ctl) { Write-Output 'NOFRAME'; exit 1 }",
        "($ctl | ConvertTo-Json -Compress -Depth 12)",
        "if ($helperProc -and -not $helperProc.HasExited) { Stop-Process -Id $helperProc.Id -Force -ErrorAction SilentlyContinue }",
    ])
    script_file = tmp_path / "serve-loop-pin.ps1"
    script_file.write_text(child, encoding="utf-8-sig")
    proc = subprocess.run(
        [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(script_file)],
        capture_output=True, text=True, timeout=180,
    )
    frames = [json.loads(ln) for ln in proc.stdout.splitlines()
              if ln.strip().startswith("{")]
    assert frames, (
        f"serve-loop pin produced no frame — rc={proc.returncode} "
        f"stdout: {proc.stdout[-800:]!r} stderr: {proc.stderr[-800:]!r}"
    )
    frame = frames[0]
    assert frame.get("ok") is True, (
        f"the control read verb did not succeed: {frame!r}"
    )
    assert frame.get("id") == req_id, (
        "the ok frame lost its correlation id — the EndInvoke unwrap "
        f"before the id/session attach is broken: {frame!r}"
    )
    session = frame.get("session")
    assert isinstance(session, dict), (
        "the ok frame lost its session block — the EndInvoke unwrap before "
        f"the id/session attach is broken: {frame!r}"
    )
    sha = (session.get("helper") or {}).get("sha256")
    assert isinstance(sha, str) and len(sha) == 64, (
        f"the session block carries no usable helper sha256: {session!r}"
    )
