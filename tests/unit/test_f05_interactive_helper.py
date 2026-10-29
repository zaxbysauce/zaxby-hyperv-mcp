"""Issue #29 (Workstream F PR 5) supplement acceptance checks: the
interactive-helper broker, capability and isolation contract (AC19-AC21).

Sibling file to tests/unit/test_f05_uia_helper.py (AC1-AC12): this file owns
the 2026-10-26 planning supplement's three criteria for the HOST-SIDE broker
and routing layer of the future hyperv_mcp.uia module:

    AC19 -> test_helper_broker_rejects_cross_vm_or_cross_session_routing
    AC20 -> test_helper_uses_accessibility_pattern_or_returns_explicit_unsupported
    AC21 -> test_helper_capability_and_vm_isolation_support_shared_and_per_agent_paths

Every assertion is host-side against monkeypatched seams: no real VM, no real
named pipe, no real lease store. RED/absent at base (hyperv_mcp.uia does not
exist, so each test fails with ImportError), GREEN after the fix.

Pinned seam/API names on hyperv_mcp.uia. These tests are the contract; the
implementation must expose exactly these names:

  uia.VERBS
      collection[str]; the closed verb allowlist (inspect, find, invoke,
      set_value, wait_for, focus, session_state).
  uia.MUTATING_VERBS
      collection[str]; exactly {invoke, set_value, focus} — the verbs that
      mutate desktop state.
  uia.UiAError
      exception; the module's error base class.
  uia.RegistrationMismatch
      exception; subclass of UiAError; raised by validate_forward when a
      request target does not match the helper registration.
  uia.ELECTRON_CAPABILITY
      str; the capability flag a registration must carry before an
      adapter "electron" request is approved (the vendor Electron adapter is
      refused unless explicitly registered).
  uia.register_helper(vm_guid=..., user_sid=..., session_id=...,
                      capabilities=..., nonce=...) -> registration
      validates and returns a helper registration record (a mapping carrying
      those identity fields).
  uia.validate_forward(registration, request) -> str
      returns a non-empty correlation id for a bounded request whose target
      (vm_guid, user_sid, session_id) matches the registration; raises
      RegistrationMismatch BEFORE any forwarding otherwise.
  uia.route(registration, request, *, shared_vm=False) -> dict
      validate_forward, then the adapter-approval check, then (mutating verb
      on a shared VM only) uia._shared_mutation_gate, then forward through
      uia._pipe_request. On success returns the pipe response merged with the
      routing envelope (ok + correlation_id, top level). An unapproved
      adapter returns {"ok": False, "error_class": "adapter_unapproved"}
      without forwarding.
  uia._shared_mutation_gate(registration, request)
      the #28 actor/lease seam: consulted by route for MUTATING_VERBS when
      shared_vm=True; raising means refusal and NO forwarding (the exception
      propagates).
  uia._pipe_request(registration, request, correlation_id) -> dict
      the helper-pipe seam: the only path from route to the guest helper;
      these tests monkeypatch it and assert on the recorded arguments.

Request shape pinned here: a mapping with "verb" (from uia.VERBS) and a
"target" of {"vm_guid": str, "user_sid": str, "session_id": int};
selector / element_id / value / timeout_s / agent_id / adapter are optional
additional fields. Selector-field bounds are pinned by AC4 in
tests/unit/test_f05_uia_helper.py, not here.
"""

import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import pytest

GUID_A = "11111111-2222-3333-4444-555555555555"
GUID_B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GUID_S = "99999999-8888-7777-6666-555555555555"
SID_A = "S-1-5-21-1000-2000-3000-1001"
SID_B = "S-1-5-21-1000-2000-3000-2002"

_COORDINATE_KEYS = ("x", "y", "click_x", "click_y", "coords", "coordinates")
_READINESS_KEYS = ("ready", "readiness")


class _PipeRecorder:
    """Records every _pipe_request call under a lock and answers from a
    per-verb canned-response table (thread-safe: AC21 routes concurrently)."""

    def __init__(self, responses):
        self.lock = threading.Lock()
        self.calls = []
        self.responses = dict(responses)

    def __call__(self, registration, request, correlation_id):
        with self.lock:
            self.calls.append({"request": request, "correlation_id": correlation_id})
        verb = request["verb"]
        if verb in self.responses:
            return dict(self.responses[verb])
        return {"ok": True, "verb": verb, "correlation_id": correlation_id}


def _find_request(vm_guid=GUID_A, user_sid=SID_A, session_id=1):
    return {
        "verb": "find",
        "target": {
            "vm_guid": vm_guid,
            "user_sid": user_sid,
            "session_id": session_id,
        },
        "selector": {"process_name": "synthapp", "control_type": "Document"},
        "agent_id": "agent-r",
    }


def _mutating_request(vm_guid=GUID_S, user_sid=SID_A, session_id=1):
    request = _find_request(vm_guid=vm_guid, user_sid=user_sid, session_id=session_id)
    request["verb"] = "invoke"
    request["element_id"] = "rid:7"
    return request


# -- AC19: broker refuses cross-VM / cross-session registration routing -----


def test_helper_broker_rejects_cross_vm_or_cross_session_routing(monkeypatch):
    """AC19 (issue #29 supplement): a helper registration carries
    (vm_guid, user_sid, session_id, capabilities, nonce) and a request carries
    its target. WHEN the registration's VM GUID, SID, or interactive session
    does not match the request target, validation refuses BEFORE any
    forwarding; a valid bounded request routes only to its registered
    VM/session and carries a correlation id.

    RED/absent at base, GREEN after the fix."""
    from hyperv_mcp import uia

    reg = uia.register_helper(
        vm_guid=GUID_A, user_sid=SID_A, session_id=1,
        capabilities={"uia", "msaa"}, nonce="nonce-ac19",
    )
    pipe = _PipeRecorder({})
    monkeypatch.setattr(uia, "_pipe_request", pipe)

    # cross-VM, cross-SID and cross-session targets are each refused BEFORE
    # any forwarding: the pipe seam is never reached.
    for mismatched in (
        _find_request(vm_guid=GUID_B),   # another VM's registration
        _find_request(user_sid=SID_B),   # another user's session
        _find_request(session_id=2),     # another interactive session
    ):
        with pytest.raises(uia.RegistrationMismatch):
            uia.validate_forward(reg, mismatched)
        with pytest.raises(uia.RegistrationMismatch):
            uia.route(reg, mismatched)
    assert pipe.calls == []

    # the mismatch class is the module's own error type
    assert issubclass(uia.RegistrationMismatch, uia.UiAError)

    # a valid bounded request routes ONLY to its registered VM/session and
    # carries a correlation id
    request = _find_request()
    cid = uia.validate_forward(reg, request)
    assert isinstance(cid, str) and cid
    out = uia.route(reg, request)
    assert out["ok"] is True, out
    assert out["correlation_id"]
    assert len(pipe.calls) == 1
    sent = pipe.calls[0]["request"]
    assert sent["target"]["vm_guid"] == GUID_A
    assert sent["target"]["user_sid"] == SID_A
    assert sent["target"]["session_id"] == 1
    assert pipe.calls[0]["correlation_id"]
    # correlation ids are per-request: a second valid request gets its own
    second = uia.route(reg, _find_request())
    assert second["ok"] is True, second
    assert second["correlation_id"] != out["correlation_id"]
    assert len(pipe.calls) == 2


# -- AC20: accessibility pattern or an explicit unsupported-capability result -


def test_helper_uses_accessibility_pattern_or_returns_explicit_unsupported(monkeypatch):
    """AC20 (issue #29 supplement): WHEN a synthetic window exposes a
    supported UIA/MSAA pattern and an unsupported pattern is then requested,
    the supported operation returns a verified element result and the
    unsupported operation returns an explicit unsupported-capability result —
    without coordinate input and without a readiness claim. The helper pipe
    is the seam that knows which patterns the element exposes, so it is
    monkeypatched (uia._pipe_request) to model the synthetic window.

    RED/absent at base, GREEN after the fix."""
    from hyperv_mcp import uia

    reg = uia.register_helper(
        vm_guid=GUID_A, user_sid=SID_A, session_id=1,
        capabilities={"uia", "msaa"}, nonce="nonce-ac20",
    )
    # The synthetic VB window, host-side: its Document element exposes the
    # UIA Value pattern but NOT the Invoke pattern.
    pipe = _PipeRecorder({
        "set_value": {
            "ok": True, "verb": "set_value", "element_id": "rid:42", "length": 3,
        },
        "invoke": {
            "ok": False, "verb": "invoke", "element_id": "rid:42",
            "error_class": "unsupported_capability",
            "error": "the element exposes no InvokePattern",
        },
    })
    monkeypatch.setattr(uia, "_pipe_request", pipe)

    def _request(verb):
        request = _find_request()
        request["verb"] = verb
        request["element_id"] = "rid:42"
        if verb == "set_value":
            request["value"] = "abc"
        return request

    # the supported operation: a verified ELEMENT result
    supported = uia.route(reg, _request("set_value"))
    assert supported["ok"] is True, supported
    assert supported["element_id"] == "rid:42", supported
    assert supported["length"] == 3, supported
    assert supported["correlation_id"], supported

    # then the unsupported operation: an explicit unsupported-capability
    # result — never a coordinate fallback, never a readiness claim
    unsupported = uia.route(reg, _request("invoke"))
    assert unsupported["ok"] is False, unsupported
    assert unsupported["error_class"] == "unsupported_capability", unsupported

    # exactly the two element operations ran: no third call attempted a
    # coordinate-input fallback path after the unsupported result
    assert len(pipe.calls) == 2, pipe.calls
    assert {c["request"]["verb"] for c in pipe.calls} == {"set_value", "invoke"}
    # no coordinate input anywhere: neither request carries a coordinate field
    for call in pipe.calls:
        for key in _COORDINATE_KEYS:
            assert key not in call["request"], (key, call["request"])
    # no readiness claim in either result
    for result in (supported, unsupported):
        for key in _READINESS_KEYS:
            assert key not in result, (key, result)


# -- AC21: per-agent concurrency, shared-VM lease gate, adapter approval -----


def test_helper_capability_and_vm_isolation_support_shared_and_per_agent_paths(monkeypatch):
    """AC21 (issue #29 supplement): two registrations for DISTINCT per-agent
    VMs service bounded requests concurrently with no cross-VM routing; a
    shared-VM mutation path requires #28's actor/lease semantics (the gate is
    consulted before forwarding); unapproved Electron adapters are refused.

    RED/absent at base, GREEN after the fix."""
    from hyperv_mcp import uia

    assert set(uia.MUTATING_VERBS) == {"invoke", "set_value", "focus"}

    # -- per-agent VMs: two registrations service bounded requests concurrently
    reg_a = uia.register_helper(
        vm_guid=GUID_A, user_sid=SID_A, session_id=1,
        capabilities={"uia"}, nonce="nonce-a",
    )
    reg_b = uia.register_helper(
        vm_guid=GUID_B, user_sid=SID_B, session_id=1,
        capabilities={"uia"}, nonce="nonce-b",
    )
    pipe = _PipeRecorder({})
    monkeypatch.setattr(uia, "_pipe_request", pipe)

    jobs = {
        "a": (reg_a, _find_request(vm_guid=GUID_A, user_sid=SID_A)),
        "b": (reg_b, _find_request(vm_guid=GUID_B, user_sid=SID_B)),
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            key: pool.submit(uia.route, reg, request)
            for key, (reg, request) in jobs.items()
        }
        outcomes = {key: fut.result(timeout=30) for key, fut in futures.items()}
    for key, out in outcomes.items():
        assert out["ok"] is True, (key, out)
        assert out["correlation_id"], (key, out)
    assert outcomes["a"]["correlation_id"] != outcomes["b"]["correlation_id"]

    # isolation at the routing layer: each pipe call addressed exactly its
    # own registered VM, once, and route A can never address VM B.
    routed = Counter(c["request"]["target"]["vm_guid"] for c in pipe.calls)
    assert routed == {GUID_A: 1, GUID_B: 1}, routed
    with pytest.raises(uia.RegistrationMismatch):
        uia.route(reg_a, _find_request(vm_guid=GUID_B, user_sid=SID_B))
    assert len(pipe.calls) == 2  # the refused cross-VM attempt forwarded nothing

    # -- shared VM: a mutating route consults #28's actor/lease gate first
    reg_shared = uia.register_helper(
        vm_guid=GUID_S, user_sid=SID_A, session_id=1,
        capabilities={"uia"}, nonce="nonce-shared",
    )
    gate_calls = []
    gate_refuses = {"now": False}

    def _gate(registration, request):
        gate_calls.append(request)
        if gate_refuses["now"]:
            raise RuntimeError("lease held by another agent")

    monkeypatch.setattr(uia, "_shared_mutation_gate", _gate)

    calls_before = len(pipe.calls)
    shared = uia.route(reg_shared, _mutating_request(), shared_vm=True)
    assert shared["ok"] is True, shared
    assert len(gate_calls) == 1  # the shared-VM mutation consulted the gate
    assert gate_calls[0]["target"]["vm_guid"] == GUID_S
    assert len(pipe.calls) == calls_before + 1

    # the gate refusing (an actor/lease conflict) prevents any forwarding
    gate_refuses["now"] = True
    with pytest.raises(RuntimeError, match="lease held"):
        uia.route(reg_shared, _mutating_request(), shared_vm=True)
    assert len(gate_calls) == 2
    assert len(pipe.calls) == calls_before + 1  # nothing forwarded

    # a READ verb on the shared VM does not need the mutation gate
    gate_refuses["now"] = False
    read_shared = uia.route(
        reg_shared, _find_request(vm_guid=GUID_S), shared_vm=True)
    assert read_shared["ok"] is True, read_shared
    assert len(gate_calls) == 2

    # a per-agent VM mutation (shared_vm=False) does NOT consult the gate
    per_agent = uia.route(reg_a, _mutating_request(vm_guid=GUID_A), shared_vm=False)
    assert per_agent["ok"] is True, per_agent
    assert len(gate_calls) == 2

    # -- unapproved Electron adapters are refused before any forwarding
    electron_request = _find_request()
    electron_request["adapter"] = "electron"
    refused = uia.route(reg_a, electron_request)
    assert refused["ok"] is False, refused
    assert refused["error_class"] == "adapter_unapproved", refused
    assert not any(
        c["request"].get("adapter") == "electron" for c in pipe.calls
    ), "the unapproved adapter request must not reach the helper pipe"

    # the capability flag is the approval: a registration carrying it forwards
    reg_electron = uia.register_helper(
        vm_guid=GUID_A, user_sid=SID_A, session_id=1,
        capabilities={"uia", uia.ELECTRON_CAPABILITY}, nonce="nonce-electron",
    )
    approved = uia.route(reg_electron, electron_request)
    assert approved["ok"] is True, approved
    assert any(
        c["request"].get("adapter") == "electron" for c in pipe.calls
    ), "the approved adapter request must reach its registered helper"


# -- AC20 fix-wave supplement: the HELPER's own dispatch, on real PS 5.1 ----
#
# The test above drives the broker against a canned _PipeRecorder, so the
# helper's real pattern dispatch never runs. The pins below extract the
# packaged helper's function definitions (no startup, no pipe creation, no
# serve loop) and drive Invoke-Request DIRECTLY on real Windows PowerShell
# 5.1 with a synthetic element — no VM, no pipe, no desktop (the fake
# element answers GetCurrentPattern locally), so the helper's own
# pattern-selection logic is the artifact under test.


def _helper_functions_slice() -> str:
    """The packaged helper's function definitions, sliced verbatim from the
    artifact: everything between the first `function Read-HelperFile` and
    the startup section that reads the provisioned files."""
    import importlib.resources

    helper = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8-sig")
    )
    start = helper.index("function Read-HelperFile")
    end = helper.index("$HelperVersion = Read-HelperFile 'version.txt'")
    return helper[start:end]


def _ps_available() -> bool:
    import os

    return os.path.isfile(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")


def _run_helper_dispatch(cases_ps: str, tmp_path) -> list[dict]:
    """Run `cases_ps` against the helper's real functions in PS 5.1; parse
    the one-JSON-per-case stdout into dicts.

    The script travels as a -File (the -Command argv cannot carry the
    ~30 KiB helper slice past the Windows command-line limit)."""
    import json as _json
    import subprocess

    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "Add-Type -AssemblyName UIAutomationClient",
        "Add-Type -AssemblyName UIAutomationTypes",
        _helper_functions_slice(),
        cases_ps,
    ])
    script_file = tmp_path / "helper-dispatch-cases.ps1"
    script_file.write_text(script, encoding="utf-8-sig")
    proc = subprocess.run(
        [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(script_file)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"helper dispatch harness failed — stdout: {proc.stdout!r} "
        f"stderr: {proc.stderr[-2000:]!r}"
    )
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            out.append(_json.loads(line))
    assert out, f"no case JSON in harness output: {proc.stdout!r}"
    return out


def test_helper_dispatch_reports_pattern_and_names_the_tried_ones(tmp_path):
    """AC20 (fix-wave): the HELPER's own invoke dispatch (a) reports the
    pattern that fired on a supported element and (b) on an unsupported
    element returns an explicit unsupported_capability refusal naming EVERY
    pattern it tried — never a coordinate fallback, never a readiness
    claim. Runs the packaged helper's functions against a synthetic element
    on real PS 5.1; skips when Windows PowerShell is unavailable."""
    if not _ps_available():
        pytest.skip("Windows PowerShell 5.1 not available")
    uuid = GUID_A.lower()
    cases = "\n".join([
        "$HelperVersion = '1'",
        "$ownNonce = 'nonce-ac20'",
        f"$recordedUuid = '{uuid}'",
        "$identity = @{ sid = '" + SID_A + "'; user = 'tester'; session_id = 1 }",
        "$capabilities = @('uia','msaa')",
        "$MaxMatches = 200; $MaxValueChars = 65536",
        "function Get-LockState { $false }",
        f"function Get-LiveUuid {{ '{uuid}' }}",
        "function Test-OwnsInputDesktop { $true }",
        "function Get-ForegroundWindow { $null }",
        "$fakeInvoke = New-Object System.Management.Automation.PSObject",
        "$fakeInvoke | Add-Member -MemberType ScriptMethod -Name Invoke -Value { $global:InvokeFired = $true }",
        "$fakeEl = New-Object System.Management.Automation.PSObject",
        "$fakeEl | Add-Member -MemberType ScriptMethod -Name GetCurrentPattern -Value {",
        "    param($p)",
        "    if ($global:ElementSupportsInvoke -and $p -eq [System.Windows.Automation.InvokePattern]::Pattern) { return $fakeInvoke }",
        "    throw (New-Object InvalidOperationException('pattern not supported by the synthetic element'))",
        "}",
        "function Resolve-Target { param($selector) @($fakeEl) }",
        "function Select-One { param($elements, $selector) $elements[0] }",
        "function Get-SessionBlock { @{ session_id = 1 } }",
        f"$target = @{{ vm_guid = '{uuid}'; user_sid = '{SID_A}'; session_id = 1 }}",
        # case 1: the element supports InvokePattern -> the dispatch fires it
        # and REPORTS which pattern fired.
        "$global:ElementSupportsInvoke = $true; $global:InvokeFired = $false",
        "$r1 = Invoke-Request @{ id = 'req-1'; verb = 'invoke'; nonce = 'nonce-ac20'; min_version = '1'; target = $target; selector = @{ name = 'FakeButton' } }",
        "@{ case = 'supported'; fired = $global:InvokeFired; ok = $r1.ok; pattern = $r1.result.pattern } | ConvertTo-Json -Compress",
        # case 2: the element supports NOTHING -> unsupported_capability
        # naming every pattern attempted (no coordinate fallback).
        "$global:ElementSupportsInvoke = $false; $global:InvokeFired = $false",
        "$r2 = Invoke-Request @{ id = 'req-2'; verb = 'invoke'; nonce = 'nonce-ac20'; min_version = '1'; target = $target; selector = @{ name = 'FakeButton' } }",
        "@{ case = 'unsupported'; fired = $global:InvokeFired; ok = $r2.ok; error_class = $r2.error_class; error = [string]$r2.error } | ConvertTo-Json -Compress",
    ])
    results = {row["case"]: row
               for row in _run_helper_dispatch(cases, tmp_path)}

    supported = results["supported"]
    assert supported["ok"] is True, supported
    assert supported["fired"] is True, (
        "the supported element's InvokePattern must actually fire"
    )
    assert supported["pattern"] == "Invoke", (
        f"the dispatch must REPORT the pattern that fired: {supported}"
    )

    unsupported = results["unsupported"]
    assert unsupported["ok"] is False, unsupported
    assert unsupported["error_class"] == "unsupported_capability", unsupported
    for pattern in ("Invoke", "Toggle", "SelectionItem", "ExpandCollapse",
                    "LegacyIAccessible"):
        assert pattern in unsupported["error"], (
            f"the refusal must name every pattern tried — {pattern!r} "
            f"missing from: {unsupported['error']!r}"
        )
    assert unsupported["fired"] is False
    for key in _COORDINATE_KEYS + _READINESS_KEYS:
        assert key not in unsupported, (key, unsupported)


def test_helper_refuses_sessionless_and_version_mismatched_requests(tmp_path):
    """Fix-wave pins for the helper's pre-dispatch gates (behavioural, real
    PS 5.1): a SESSION-LESS request (target.session_id null) is refused
    session_unverified before any verb dispatch, and a request whose
    min_version exceeds the helper's version is refused
    helper_version_mismatch. Skips when Windows PowerShell is unavailable."""
    if not _ps_available():
        pytest.skip("Windows PowerShell 5.1 not available")
    uuid = GUID_A.lower()
    cases = "\n".join([
        "$HelperVersion = '1'",
        "$ownNonce = 'nonce-ver'",
        f"$recordedUuid = '{uuid}'",
        "$identity = @{ sid = '" + SID_A + "'; user = 'tester'; session_id = 1 }",
        "$capabilities = @('uia','msaa')",
        "$MaxMatches = 200; $MaxValueChars = 65536",
        "function Get-LockState { $false }",
        f"function Get-LiveUuid {{ '{uuid}' }}",
        "function Test-OwnsInputDesktop { $true }",
        "function Get-ForegroundWindow { $null }",
        "function Resolve-Target { param($selector) @() }",
        "function Select-One { param($elements, $selector) $null }",
        "function Get-SessionBlock { @{ session_id = 1 } }",
        # a session-LESS target: the helper refuses before any dispatch
        f"$r1 = Invoke-Request @{{ id = 'req-s'; verb = 'session_state'; nonce = 'nonce-ver'; min_version = '1'; target = @{{ vm_guid = '{uuid}'; user_sid = '{SID_A}'; session_id = $null }} }}",
        "@{ case = 'sessionless'; ok = $r1.ok; error_class = $r1.error_class } | ConvertTo-Json -Compress",
        # a min_version the helper cannot serve: refused helper_version_mismatch
        f"$r2 = Invoke-Request @{{ id = 'req-v'; verb = 'session_state'; nonce = 'nonce-ver'; min_version = '999'; target = @{{ vm_guid = '{uuid}'; user_sid = '{SID_A}'; session_id = 1 }} }}",
        "@{ case = 'stalehost'; ok = $r2.ok; error_class = $r2.error_class } | ConvertTo-Json -Compress",
    ])
    results = {row["case"]: row
               for row in _run_helper_dispatch(cases, tmp_path)}
    assert results["sessionless"]["ok"] is False
    assert results["sessionless"]["error_class"] == "session_unverified", (
        results["sessionless"]
    )
    assert results["stalehost"]["ok"] is False
    assert results["stalehost"]["error_class"] == "helper_version_mismatch", (
        results["stalehost"]
    )
