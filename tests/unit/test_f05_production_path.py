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
    """F6/F11 (wait_for budget): a wait whose every guest slice answers
    empty elements EXPIRES its budget and returns the LAST slice's answer
    (ok with empty elements — the module emits no timed_out flag, so the
    deadline path is pinned by its bounded return, not a flag), and each
    slice's request budget never exceeds one _WAIT_SLICE_S slice."""
    monkeypatch.setattr(pswindows, "run_ps", PSResolveRecorder())
    monkeypatch.setattr(uia, "_run_quser",
                        lambda cfg, ref, cred: {"user": "tester", "session_id": 2})
    legs = EchoLegRecorder(frame_for=lambda request: {
        "ok": True, "result": {"elements": []},
        "session": _helper_session_block()})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)

    out = uia.wait_for(UNRESTRICTED, "test-vm-1", CRED, {"name": "OK"},
                       timeout_s=1)
    assert out["ok"] is True, out
    assert out["elements"] == [], out
    assert legs.requests, "the wait must drive its pipe leg"
    wait_requests = [r for r in legs.requests if r.get("verb") == "wait_for"]
    assert wait_requests, legs.requests
    assert all(r["args"]["timeout_s"] <= uia._WAIT_SLICE_S
               for r in wait_requests), (
        "every wait slice's budget must be bounded by one _WAIT_SLICE_S slice"
    )
    assert "timed_out" not in out, (
        "the module defines no timed_out flag; if one is added this pin "
        "must be updated to assert it on the deadline path"
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
