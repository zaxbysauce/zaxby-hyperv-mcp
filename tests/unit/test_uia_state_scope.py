"""Issue #136 acceptance checks (trace 136-137-uia-element-contract):
the UIA helper's tree-search scope, the selector scope keys, the
inspect-limit agreement across uia.py / the helper script / the README,
password-value hygiene on element results, and the msaa capability
advertisement.

Every check in this file is RED at base for its named reason and GREEN
after the fix. No real guest legs: the verbs run against recording fakes
of the uia pipe seam (the tests/unit/test_f05_uia_helper.py conventions),
and the script censi read the PACKAGED helper bytes. Module-level imports
use only modules that exist at base; every test that needs the #136
surface reaches for it inside the test body, so at base each test fails
with an assertion naming the missing behavior (never an import error and
never a collection error).

Contract map (check-author brief, issue #136):
  C1+C6 test_helper_never_searches_desktop_descendants
       (the desktop-descendants census AND the batched-read census: no
        GetSupportedPatterns, a CacheRequest drives the tree walk)
  C2     test_selector_scope_is_a_closed_set
  C2b    test_window_title_contains_is_forwarded
  C3     test_inspect_limits_agree_everywhere
  C4     test_password_field_value_is_never_returned
  C5     test_msaa_is_advertised_only_with_a_live_bridge

Frozen surface this file pins (the spec the fix implements against):

  uia.validate_selector accepts an OPTIONAL "scope" key whose value is
  one of {"foreground", "window", "all_windows"}; any other value raises
  ValueError MENTIONING THE INVALID VALUE, and "window_title_contains"
  is an accepted selector key forwarded to the helper UNCHANGED (same
  key name, same value) in request["selector"].
  uia.INSPECT_MAX_DEPTH == 32 and uia.INSPECT_MAX_ELEMENTS == 500; the
  packaged helper's $MaxDepth == 32 / $MaxElements == 500; the README
  hyperv_ui_inspect row names exactly those numbers.
  Element results: when a helper frame marks an element is_password
  true (element-level or inside its state block), the host drops every
  "value" key from that element before returning it; the is_password
  flag itself survives and non-password elements keep their values.
  The helper script ships a function Get-HelperCapabilities returning
  @('uia') plus 'msaa' ONLY when $legacyPattern -ne $null.
"""

import importlib.resources
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from hyperv_mcp import pswindows
from hyperv_mcp.config import Config  # noqa: F401 (lab_cfg builds these)
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("testuser", "placeholder-pass")
VM_GUID = "e953c649-1234-5678-9abc-def012345678"
HELPER_SESSION = {"session_id": 2, "interactive_user": "tester",
                  "locked": False}

VALID_SCOPES = ("foreground", "window", "all_windows")


# ---------------------------------------------------------------------------
# shared harness (no real PowerShell on any path)
# ---------------------------------------------------------------------------

class PSRecorder:
    """pswindows.run_ps stand-in: records scripts, always answers stdout."""

    def __init__(self, stdout: str = ""):
        self.scripts: list[str] = []
        self.stdout = stdout

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(stdout=self.stdout, returncode=0)


class PipeRecorder:
    """uia._pipe_request stand-in (the 4-arg verb front-door shape):
    records every request frame the verb layer builds and serves one
    hand-built helper response frame."""

    def __init__(self, frame: dict | None = None):
        self.requests: list[dict] = []
        self.frame = frame

    def __call__(self, cfg, vm, cred, request):
        self.requests.append(request)
        if self.frame is not None:
            return self.frame
        return {"ok": True, "result": {}, "session": dict(HELPER_SESSION)}


def _helper_text() -> str:
    """The PACKAGED helper script bytes (what the host installs)."""
    return (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8")
    )


def _readme_lines() -> list[str]:
    path = Path(__file__).resolve().parents[2] / "README.md"
    return path.read_text(encoding="utf-8").splitlines()


def _value_key_paths(node) -> list:
    """Every dict key literally named "value" anywhere under node."""
    found: list = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "value":
                found.append(key)
            found.extend(_value_key_paths(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_value_key_paths(item))
    return found


def _extract_ps_function(text: str, name: str) -> str:
    """Extract `function <name> { ... }` (balanced braces) from script text."""
    idx = text.find("function " + name)
    if idx == -1:
        pytest.fail(
            f"{name} is missing from the shipped helper script (issue #136)")
    start = text.find("{", idx)
    assert start != -1, f"{name} has no body"
    depth = 0
    for pos in range(start, len(text)):
        ch = text[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[idx:pos + 1]
    pytest.fail(f"{name} has unbalanced braces in the shipped helper script")


def _caps_under_powershell(body: str, legacy) -> set:
    """Run Get-HelperCapabilities under Windows PowerShell 5.1 with
    $legacyPattern forced (None -> $null, else a non-null sentinel) and
    return the reported capability set."""
    probe = ("$legacyPattern = $null" if legacy is None
             else "$legacyPattern = 'legacy-live'")
    cmd = probe + "\n" + body + "\n(Get-HelperCapabilities) -join ','"
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", cmd],
        capture_output=True, timeout=60)
    out = proc.stdout.decode("ascii", "replace").strip()
    err = proc.stderr.decode("ascii", "replace").strip()
    assert proc.returncode == 0, (
        f"Get-HelperCapabilities failed under PowerShell 5.1: {err}")
    return {c.strip() for c in out.split(",") if c.strip()}


# ---------------------------------------------------------------------------
# C1 + C6: the helper's tree walk never searches desktop descendants and
# batches its reads through a CacheRequest
# ---------------------------------------------------------------------------

def test_helper_never_searches_desktop_descendants():
    """C1: no RootElement.FindAll with TreeScope Descendants anywhere in
    the shipped helper script (a desktop-wide census hangs real guests).
    C6 rides the same census: the walk takes pattern availability from a
    CacheRequest, never a per-element GetSupportedPatterns round trip.
    RED at base (two RootElement Descendants FindAll calls, plus
    GetSupportedPatterns and no CacheRequest), GREEN after the fix."""
    text = _helper_text()
    # alias-aware census (review round TF-001): the helper binds $root
    # from RootElement once and searches through the alias - a census
    # matching only the literal 'RootElement.FindAll' would miss an
    # aliased desktop-wide search, so pin the alias binding itself and
    # census both spellings.
    aliases = re.findall(
        r"\$(\w+)\s*=\s*\[System\.Windows\.Automation\.AutomationElement"
        r"\]::RootElement", text)
    assert set(aliases) <= {"root"}, (
        "the helper must bind the desktop root element only to $root (the "
        f"census's alias allowlist); unexpected bindings: {sorted(set(aliases))}")
    hits = re.findall(r"(?:RootElement|\$root)\s*\.\s*FindAll\s*\(([^)]*)\)", text)
    offenders = [args for args in hits if "Descendants" in args]
    assert offenders == [], (
        "the helper must never search the desktop root element's "
        f"descendants; offending RootElement.FindAll invocations: {offenders}")
    assert "GetSupportedPatterns" not in text, (
        "pattern availability must come from the tree walk's cache, not a "
        "per-element GetSupportedPatterns round trip")
    assert "CacheRequest" in text, (
        "the tree walk must batch its reads through a CacheRequest")
    # non-vacuity: removing the desktop search must not remove the walk
    assert ("TreeScope]::Children" in text) or ("TreeWalker" in text), (
        "the helper must still enumerate the tree (Children scope or a "
        "TreeWalker), just never the desktop root's descendants")


# ---------------------------------------------------------------------------
# C2: the selector scope key is a closed set
# ---------------------------------------------------------------------------

def test_selector_scope_is_a_closed_set(lab_cfg, monkeypatch):
    """C2: validate_selector accepts an optional "scope" whose value is
    exactly one of {"foreground", "window", "all_windows"}; any other
    value raises ValueError MENTIONING THE INVALID VALUE, before any
    transport leg.
    RED at base ('scope' is an unknown selector key), GREEN after the fix."""
    from hyperv_mcp import uia

    for scope in VALID_SCOPES:
        try:
            sel = uia.validate_selector({"scope": scope, "name": "OK"})
        except ValueError as exc:
            raise AssertionError(
                f"validate_selector must accept the closed-set scope value "
                f"{scope!r} (issue #136): {exc}") from None
        assert sel.get("scope") == scope, (
            f"the accepted scope {scope!r} must survive normalization")

    # scope is optional
    optional = uia.validate_selector({"name": "OK"})
    assert optional.get("name") == "OK", "scope must be optional"

    # anything outside the closed set is refused NAMING the invalid value
    for bad in ("desktop", "descendants", "windowss"):
        with pytest.raises(ValueError, match=re.escape(bad)):
            uia.validate_selector({"scope": bad})

    # the refusal fires before any transport leg
    pipe = PipeRecorder()
    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))
    with pytest.raises(ValueError, match="desktop"):
        uia.find(lab_cfg, "test-vm-1", CRED,
                 {"scope": "desktop", "name": "OK"})
    assert pipe.requests == [], (
        "an invalid scope must be refused before any helper pipe leg")


# ---------------------------------------------------------------------------
# C2b: window_title_contains is forwarded UNCHANGED
# ---------------------------------------------------------------------------

def test_window_title_contains_is_forwarded(lab_cfg, monkeypatch):
    """C2b: window_title_contains is an accepted selector key and rides
    the helper request UNCHANGED (same key name, same value) beside the
    scope key.
    RED at base (unknown selector key window_title_contains), GREEN
    after the fix."""
    from hyperv_mcp import uia

    pipe = PipeRecorder()
    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))
    selector = {"window_title_contains": "Notepad", "scope": "window"}
    try:
        uia.find(lab_cfg, "test-vm-1", CRED, selector)
    except ValueError as exc:
        raise AssertionError(
            "window_title_contains must be an accepted selector key "
            f"(issue #136): {exc}") from None
    assert pipe.requests, "find must drive its helper pipe leg"
    sent = pipe.requests[0].get("selector")
    assert isinstance(sent, dict), (
        "the selector must ride the helper request frame")
    assert sent.get("window_title_contains") == "Notepad", (
        "window_title_contains must be forwarded UNCHANGED (same key name)")
    assert sent.get("scope") == "window"


# ---------------------------------------------------------------------------
# C3: the inspect limits agree everywhere
# ---------------------------------------------------------------------------

def test_inspect_limits_agree_everywhere():
    """C3: uia.INSPECT_MAX_DEPTH == 32 / INSPECT_MAX_ELEMENTS == 500, the
    shipped helper's $MaxDepth == 32 / $MaxElements == 500, and the README
    hyperv_ui_inspect row names exactly those numbers. All three agree.
    RED at base (uia says 6, the helper says 6, the README says 8/2000),
    GREEN after the fix."""
    from hyperv_mcp import uia

    assert uia.INSPECT_MAX_DEPTH == 32, (
        "uia.INSPECT_MAX_DEPTH must be 32 (issue #136); got "
        f"{getattr(uia, 'INSPECT_MAX_DEPTH', None)!r}")
    assert uia.INSPECT_MAX_ELEMENTS == 500, (
        "uia.INSPECT_MAX_ELEMENTS must be 500 (issue #136); got "
        f"{getattr(uia, 'INSPECT_MAX_ELEMENTS', None)!r}")

    text = _helper_text()
    depth = re.search(r"\$MaxDepth\s*=\s*(\d+)", text)
    elements = re.search(r"\$MaxElements\s*=\s*(\d+)", text)
    assert depth is not None and depth.group(1) == "32", (
        "the shipped helper's $MaxDepth must be 32; got "
        f"{depth.group(1) if depth else None!r}")
    assert elements is not None and elements.group(1) == "500", (
        "the shipped helper's $MaxElements must be 500; got "
        f"{elements.group(1) if elements else None!r}")

    row = next((ln for ln in _readme_lines() if "hyperv_ui_inspect" in ln),
               None)
    assert row is not None, "the README must document hyperv_ui_inspect"
    assert "32" in row, (
        f"the README hyperv_ui_inspect row must name depth 32: {row!r}")
    assert "500" in row, (
        f"the README hyperv_ui_inspect row must name 500 elements: {row!r}")


# ---------------------------------------------------------------------------
# C4: a password field's value is never returned
# ---------------------------------------------------------------------------

def test_password_field_value_is_never_returned(lab_cfg, monkeypatch):
    """C4: element results carry a state block; when a helper frame marks
    an element is_password true -- even one that WRONGLY includes a value
    beside the flag -- the host returns that element WITHOUT any value
    key (drop at the uia.py side). The flag survives; non-password
    elements keep their values.
    RED at base (the frame passes through with the password value
    attached), GREEN after the fix."""
    from hyperv_mcp import uia

    elements = [
        # a misbehaving helper: a value beside is_password true, both at
        # the element level and inside its state block
        {"name": "Password", "control_type": "Edit", "value": "hunter2",
         "state": {"is_password": True, "value": "hunter2",
                   "value_truncated": False}},
        {"name": "Notes", "control_type": "Edit",
         "state": {"value": "plain text"}},
    ]
    frame = {"ok": True, "result": {"elements": elements},
             "session": dict(HELPER_SESSION)}
    pipe = PipeRecorder(frame)
    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    out = uia.find(lab_cfg, "test-vm-1", CRED, {"automation_id": "pw"})
    assert out.get("ok") is True
    got = out.get("elements") or []
    assert len(got) == 2, "both elements must be returned"
    pw, notes = got[0], got[1]
    assert _value_key_paths(pw) == [], (
        "an is_password element must NEVER carry a value key (issue #136); "
        f"the host returned: {pw!r}")
    assert pw.get("state", {}).get("is_password") is True, (
        "the is_password flag itself must survive the drop")
    assert notes.get("state", {}).get("value") == "plain text", (
        "the drop is targeted: non-password elements keep their value")

    # F7: the ELEMENT-LEVEL flag form -- is_password carried on the
    # element itself (not inside its state block), with a value key at
    # BOTH levels -- must drop both values too. (The snapshot and
    # wait_for verbs share this same host-side normalization seam; the
    # full-suite run covers those paths, so no separate node is needed.)
    element_flagged = {"name": "Pin", "control_type": "Edit",
                       "is_password": True, "value": "top-secret",
                       "state": {"value": "top-secret"}}
    pipe2 = PipeRecorder({"ok": True,
                          "result": {"elements": [element_flagged]},
                          "session": dict(HELPER_SESSION)})
    monkeypatch.setattr(uia, "_pipe_request", pipe2)
    out2 = uia.find(lab_cfg, "test-vm-1", CRED, {"automation_id": "pin"})
    assert out2.get("ok") is True
    got2 = out2.get("elements") or []
    assert len(got2) == 1, "the element-level-flag element must be returned"
    pin = got2[0]
    assert _value_key_paths(pin) == [], (
        "an element-level is_password flag must drop the value at BOTH "
        f"levels (element and state block); the host returned: {pin!r}")
    assert pin.get("is_password") is True, (
        "the element-level is_password flag itself must survive the drop")

    # the SNAPSHOT path shares the same normalization seam (round-4
    # coverage): a password entry carrying a value inside its state block
    # must come back with no value anywhere, while a non-password entry
    # keeps its value
    snapshot = getattr(uia, "snapshot", None)
    assert snapshot is not None, (
        "uia.snapshot (tool hyperv_ui_snapshot) is missing (issue #137)")
    snap_entries = [
        {"ref": "s3:0", "control_type": "Edit", "name": "Password",
         "depth": 1, "rect": "0,0,1,1",
         "state": {"is_password": True, "value": "snap-secret"}},
        {"ref": "s3:1", "control_type": "Edit", "name": "Notes",
         "depth": 1, "rect": "0,2,1,3", "state": {"value": "kept"}},
    ]
    pipe3 = PipeRecorder({"ok": True,
                          "result": {"snapshot_id": "s3",
                                     "entries": snap_entries},
                          "session": dict(HELPER_SESSION)})
    monkeypatch.setattr(uia, "_pipe_request", pipe3)
    snap = snapshot(lab_cfg, "test-vm-1", CRED)
    assert snap.get("ok") is True
    got3 = snap.get("entries") or []
    assert len(got3) == 2, "both snapshot entries must be returned"
    assert _value_key_paths(got3[0]) == [], (
        "the snapshot path must drop the password entry's value too (the "
        f"shared normalization seam); the host returned: {got3[0]!r}")
    assert got3[0].get("state", {}).get("is_password") is True, (
        "the snapshot entry's is_password flag must survive the drop")
    assert got3[1].get("state", {}).get("value") == "kept", (
        "a non-password snapshot entry keeps its value")

    # TF-003 (swarm-pr-review round): the inspect TREE frame gets the
    # same drop -- a password-marked node anywhere in the nested tree
    # loses its value keys recursively (its descendants too), while
    # non-password nodes keep theirs
    tree = {
        "name": "Win", "control_type": "Window",
        "children": [
            {"name": "User", "control_type": "Edit",
             "state": {"value": "user typed"}},
            {"name": "Password", "control_type": "Edit",
             "state": {"is_password": True, "value": "tree-secret"},
             "children": [
                 {"name": "Child", "control_type": "Text",
                  "state": {"value": "under-password"}},
             ]},
        ],
    }
    pipe4 = PipeRecorder({"ok": True,
                          "result": {"elements": 3, "truncated": False,
                                     "tree": tree},
                          "session": dict(HELPER_SESSION)})
    monkeypatch.setattr(uia, "_pipe_request", pipe4)
    insp = getattr(uia, "inspect", None)
    assert insp is not None, (
        "uia.inspect (tool hyperv_ui_inspect) is missing (issue #136)")
    out4 = insp(lab_cfg, "test-vm-1", CRED)
    assert out4.get("ok") is True, f"inspect must succeed, got {out4!r}"
    got_tree = out4.get("tree") or {}
    pw_node = (got_tree.get("children") or [None, None])[1]
    assert isinstance(pw_node, dict), (
        f"the tree answer must preserve the probe shape, got {got_tree!r}")
    assert _value_key_paths(pw_node) == [], (
        "the tree frame's password node must lose its value keys "
        f"recursively, got: {pw_node!r}")
    non_pw = (got_tree.get("children") or [None])[0]
    assert non_pw.get("state", {}).get("value") == "user typed", (
        "the drop is targeted: a non-password tree node keeps its value, "
        f"got {non_pw!r}")


# ---------------------------------------------------------------------------
# C5: msaa is advertised only with a live LegacyIAccessible bridge
# ---------------------------------------------------------------------------

def test_msaa_is_advertised_only_with_a_live_bridge():
    """C5: the helper ships Get-HelperCapabilities, returning @('uia')
    plus 'msaa' ONLY when the LegacyIAccessible pattern probe resolved
    ($legacyPattern -ne $null). The function body is extracted from the
    shipped script text and executed under Windows PowerShell 5.1 with
    $legacyPattern forced on each side. Skipped when powershell.exe is
    absent (non-Windows).
    RED at base (the function does not exist), GREEN after the fix."""
    if shutil.which("powershell.exe") is None:
        pytest.skip("powershell.exe is absent (non-Windows)")
    body = _extract_ps_function(_helper_text(), "Get-HelperCapabilities")

    dead = _caps_under_powershell(body, None)
    assert dead == {"uia"}, (
        "with the LegacyIAccessible probe unresolved ($legacyPattern is "
        f"$null) the capabilities must be exactly {{'uia'}}, got {dead}")

    live = _caps_under_powershell(body, "legacy-live")
    assert live == {"uia", "msaa"}, (
        "with the LegacyIAccessible probe resolved ($legacyPattern "
        f"non-null) the capabilities must be exactly {{'uia', 'msaa'}}, "
        f"got {live}")
