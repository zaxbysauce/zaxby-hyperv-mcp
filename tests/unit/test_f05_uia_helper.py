"""Issue #29 acceptance checks, part 1 (trace 29-uia-helper-element-desktop,
workstream F PR 5): the in-session UI Automation helper, the element verbs
and the session-honest evidence path.

Every check in this file is RED at base 2f95c05 for its named reason and
GREEN after the fix. No real PowerShell, no live VM: the conftest autouse
fixtures pin the WMI backend off, and every host leg the new surface would
spawn is intercepted on the seams pinned below. Module-level imports use
ONLY modules that exist at base; every test that needs the future uia
module imports it INSIDE the test body, so at base each such test fails
with exactly "ImportError: cannot import name 'uia' from 'hyperv_mcp'" and
the AC1/AC2 assertion failures surface individually.

AC map (01-issue-summary.md / issue #29 body):
  AC1  test_uia_walker_reports_its_session          DISCRIMINATING
  AC2  test_session0_tree_is_not_reported_as_success DISCRIMINATING
  AC3  test_request_verbs_are_closed_set            NEW-SURFACE
  AC4  test_selector_validation                     NEW-SURFACE
  AC5  test_mutating_verbs_need_ui_input            NEW-SURFACE
  AC6  test_read_verbs_need_only_vm_policy          NEW-SURFACE
  AC7  test_set_value_rides_stdin                   NEW-SURFACE
  AC8  test_helper_unavailable_is_structured        NEW-SURFACE
  AC9  test_provision_requires_category_and_confirm NEW-SURFACE
  AC10 test_provision_script_contract               NEW-SURFACE
  AC11 test_config_categories                       NEW-SURFACE
  AC12 test_ui_tools_registered                     NEW-SURFACE
  (AC13 lives in tests/unit/test_script_parse_new.py; AC14/AC15 are the
  preserving checks in test_evidence.py/test_server.py; AC16-AC18 are
  integration; AC19-AC21 live in tests/unit/test_f05_interactive_helper.py.)

Frozen surface contract this file pins (the issue names the module, the
eight tools and the error classes; the remaining shapes are underdetermined
by the issue text, so this file IS the spec the fix implements against):

  module hyperv_mcp.uia (new):
    VERBS ........ exactly {"inspect", "find", "invoke", "set_value",
                     "wait_for", "focus", "session_state"}
    build_request(verb, args=None, agent_id="") -> {id, verb, args, agent_id};
                     ValueError mentioning "verb" for a verb outside VERBS.
    validate_selector(selector) -> dict; ValueError mentioning "selector"
                     for an empty selector or a key outside the closed set
                     {automation_id, name, name_contains, control_type,
                     class_name, window_title, process_name, hwnd,
                     element_id, index}, and plain ValueError for a field
                     longer than 1024 characters.
    inspect(cfg, vm_name, cred, selector=None, depth=3, max_elements=200)
    find(cfg, vm_name, cred, selector)
    invoke(cfg, vm_name, cred, selector)
    set_value(cfg, vm_name, cred, selector, value)
    wait_for(cfg, vm_name, cred, selector, gone=False, timeout_s=30)
    focus(cfg, vm_name, cred, selector)
    session_state(cfg, vm_name, cred)
    provision_helper(cfg, vm_name, cred, autologon=True, confirm=False)
                     Every verb gates its policy FIRST (require_category on
                     "ui_input" for invoke/set_value/focus; require_
                     destructive on "ui_provision" plus confirm for
                     provision_helper), THEN resolves the target once via
                     vmident.resolve — a denial spawns no PowerShell at all
                     and no resolution either. Read verbs need nothing
                     beyond vm policy and the credential.
    set_value's request args carry {"selector": ..., "value": ...}; the
                     returned result reports the length set, never the value.

  seams the tests replace (exact attribute names on the uia module):
    _run_uia_leg(cfg, script, *, stdin_b64=None, timeout_s=None)
                     -> pswindows.PSResult. The single choke point every
                     host PowerShell leg the module spawns passes through;
                     tests count legs and serve helper response frames.
    _pipe_request(cfg, vm, cred, request) -> dict
                     Drives one request frame through the guest pipe-client
                     leg (builds the framed stdin payload — line 1 is
                     utf8-b64 of the password, line 2 utf8-b64 of the JSON
                     request — via _run_uia_leg) and returns the helper's
                     response frame {ok, result|error, error_class,
                     session}. An unopenable pipe (the 3 s open budget
                     expiring) raises TimeoutError; the verbs map that to
                     the structured helper_unavailable envelope and never
                     re-raise it raw.
    _run_quser(cfg, vm, cred) -> {"user": <name>, "session_id": <int>} | None
                     The PS Direct quser fallback for the interactive user
                     and session id (None when nobody is logged on).
    _session_has_logonui(cfg, vm, cred, session_id) -> bool
                     LogonUI.exe presence in that session — the locked
                     signal of the fallback block
                     {"interactive_user": ..., "session_id": ..., "locked": ...}.

  evidence helper path (AC2): evidence imports uia and calls the helpers as
    MODULE-LEVEL ATTRIBUTE lookups — uia.session_state(cfg, <identity>,
    cred) and uia.inspect(cfg, <identity>, cred, selector) — never
    from-imports, so the seam stays replaceable. A session_state result of
    ok True with helper.running True means "the helper is up": the tree then
    comes from uia.inspect and ui_tree reports source "helper". A PS Direct
    walk that ran in a non-interactive session is refused as ok False,
    error_class "no_interactive_session", with the walked session id
    carried in ui["session"]["session_id"].

  provisioning (AC10): the packaged helper script at
    src/hyperv_mcp/guest/uia_helper.ps1 (UTF-8 package data) carries the
    PIPE_REJECT_REMOTE_CLIENTS flag by name; the guest legs provision_
    helper drives through _run_uia_leg carry the autologon/task contract
    asserted below and never the password.
"""

import asyncio
import base64
import binascii
import importlib
import importlib.resources
import json
import re
from functools import partial

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import evidence, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("testuser", "placeholder-pass")
VM_GUID = "e953c649-1234-5678-9abc-def012345678"

UI_TOOLS = {
    "hyperv_ui_inspect", "hyperv_ui_find", "hyperv_ui_invoke",
    "hyperv_ui_set_value", "hyperv_ui_wait_for", "hyperv_ui_focus",
    "hyperv_ui_session_state", "hyperv_ui_helper_provision",
}
UI_INTERACTION_TOOLS = UI_TOOLS - {"hyperv_ui_helper_provision"}

HELPER_SESSION = {"session_id": 2, "interactive_user": "tester", "locked": False}


# ---------------------------------------------------------------------------
# shared harness (no real PowerShell on any path)
# ---------------------------------------------------------------------------

class FakeImage:
    """Stand-in for the PIL image; the module passes it through untouched."""


def _base_meta():
    return {
        "vm_name": "test-vm",
        "vm_id": VM_GUID,
        "width": 1024, "height": 768,
        "frame_hash": "a" * 64,
        "captured_at": "2026-10-28T12:00:00.000+00:00",
        "capture_method": "GetVirtualSystemThumbnailImage",
    }


class PSRecorder:
    """pswindows.run_ps stand-in: records scripts, always answers `stdout`."""

    def __init__(self, stdout: str = ""):
        self.scripts: list[str] = []
        self.stdout = stdout

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(stdout=self.stdout, returncode=0)


def _helper_frame(result=None) -> pswindows.PSResult:
    """A successful helper response frame as the pipe leg's stdout."""
    return pswindows.PSResult(
        stdout=json.dumps(
            {"ok": True, "result": result or {}, "session": dict(HELPER_SESSION)}
        ),
        returncode=0,
    )


class LegRecorder:
    """uia._run_uia_leg stand-in: records every (script, stdin_b64) the
    module hands the transport and serves a successful helper frame."""

    def __init__(self, result=None):
        self.scripts: list[str] = []
        self.stdin_b64: list[str | None] = []
        self.result = result

    def __call__(self, cfg, script, *, stdin_b64=None, timeout_s=None, **kwargs):
        self.scripts.append(script)
        self.stdin_b64.append(stdin_b64)
        return _helper_frame(self.result)


@pytest.fixture()
def fake_screenshot(monkeypatch):
    """Stub the screenshot leg and serve the vmident resolve leg (the
    test_evidence.py idiom), so capture_evidence runs with zero spawns."""
    captured = {}

    def _capture(cfg, vm_name="", width=1024, height=768, save_path="", vm_id="",
                 fmt="", quality=None, scale=None, crop=None, if_changed_from=""):
        captured["vm_name"] = vm_name
        captured["vm_id"] = vm_id
        return FakeImage(), _base_meta()

    monkeypatch.setattr(evidence.console, "screenshot", _capture)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))
    _capture.captured = captured
    return _capture


# ---------------------------------------------------------------------------
# AC1: the walker records the session it ran in
# ---------------------------------------------------------------------------

def test_uia_walker_reports_its_session():
    """AC1: the UIA walk used by hyperv_capture_evidence(ui_tree=true)
    records the session it ran in — the script emits the walker process's
    SessionId (and input-desktop ownership per the issue).
    RED at base (the walker emits only elements/truncated/tree),
    GREEN after the fix."""
    assert "SessionId" in evidence._uia_script(3, 200)


# ---------------------------------------------------------------------------
# AC2: a session-0 tree is not success; the helper path reports its source
# ---------------------------------------------------------------------------

def test_session0_tree_is_not_reported_as_success(fake_screenshot, monkeypatch):
    """AC2: a PS Direct walk that returns a tree from a NON-interactive
    session (session_id 0) is refused as ok False with error_class
    "no_interactive_session" and the walked session id; when the helper
    answers session_state, capture_evidence takes the tree from the
    helper's inspect verb and reports source "helper".
    RED at base (the success branch hard-sets ok True; leg 2 fails with the
    uia ImportError), GREEN after the fix."""
    cfg = Config(unrestricted=True)

    def session0_walk(cfg_, vm, inner, cred_, timeout_ms=60000, mode="read"):
        return {"session_id": 0, "interactive": False, "elements": 3,
                "truncated": False, "tree": {"name": "Desktop", "children": []}}

    monkeypatch.setattr(evidence, "run_guest_inner", session0_walk)
    out = evidence.capture_evidence(cfg, "test-vm", ui_tree=True, cred=CRED)
    ui = out["meta"]["ui_tree"]
    assert ui["ok"] is False
    assert ui["error_class"] == "no_interactive_session"
    assert ui["session"]["session_id"] == 0

    # Second leg: the helper answers session_state, so the tree comes from
    # the helper's inspect verb — not from the PS Direct walker above.
    from hyperv_mcp import uia  # RED at base: cannot import name 'uia'

    helper_tree = {"name": "Desktop", "control_type": "Pane",
                   "children": [{"name": "Untitled - Notepad"}]}

    def helper_session(cfg_, vm, cred_):
        return {"ok": True, "active_session_id": 2, "interactive_user": "tester",
                "locked": False, "helper": {"running": True, "version": "1"}}

    def helper_inspect(cfg_, vm, cred_, selector=None, **kw):
        return {"ok": True, "elements": 5, "truncated": False, "tree": helper_tree}

    monkeypatch.setattr(uia, "session_state", helper_session)
    monkeypatch.setattr(uia, "inspect", helper_inspect)
    out2 = evidence.capture_evidence(cfg, "test-vm", ui_tree=True, cred=CRED)
    ui2 = out2["meta"]["ui_tree"]
    assert ui2["ok"] is True
    assert ui2["source"] == "helper"
    assert ui2["elements"] == 5
    assert ui2["tree"] == helper_tree


# ---------------------------------------------------------------------------
# AC3: the request verbs are a closed set
# ---------------------------------------------------------------------------

def test_request_verbs_are_closed_set():
    """AC3: uia.VERBS is exactly the seven verbs; build_request refuses
    anything else with a ValueError naming the verb; the happy path builds
    {id, verb, args, agent_id}. The allowlist holds on both ends, so the
    pipe can never become a command channel.
    RED at base (uia absent, ImportError), GREEN after the fix."""
    from hyperv_mcp import uia

    assert uia.VERBS == {"inspect", "find", "invoke", "set_value",
                         "wait_for", "focus", "session_state"}
    with pytest.raises(ValueError, match="verb"):
        uia.build_request("runspace", args={})
    req = uia.build_request("inspect", args={"selector": {"name": "Desktop"}},
                            agent_id="agent-f05")
    assert set(req) == {"id", "verb", "args", "agent_id"}
    assert req["verb"] == "inspect"
    assert req["agent_id"] == "agent-f05"


# ---------------------------------------------------------------------------
# AC4: selector validation
# ---------------------------------------------------------------------------

def test_selector_validation():
    """AC4: an empty selector, a field longer than 1024 characters, or a
    key outside the closed selector-key set raises ValueError (naming
    "selector" for the empty and unknown-key cases).
    RED at base (uia absent, ImportError), GREEN after the fix."""
    from hyperv_mcp import uia

    with pytest.raises(ValueError, match="selector"):
        uia.validate_selector({})
    with pytest.raises(ValueError, match="selector"):
        uia.validate_selector(None)
    with pytest.raises(ValueError):  # a field longer than 1024 characters
        uia.validate_selector({"name": "n" * 1025})
    with pytest.raises(ValueError, match="selector"):
        uia.validate_selector({"name": "OK", "rectangle": "0,0,1,1"})
    sel = uia.validate_selector({"automation_id": "File", "index": 0})
    assert isinstance(sel, dict) and sel.get("automation_id") == "File"


# ---------------------------------------------------------------------------
# AC5: invoke/set_value/focus need destructive.ui_input, before any leg
# ---------------------------------------------------------------------------

def test_mutating_verbs_need_ui_input(monkeypatch):
    """AC5: the input-injecting verbs are denied by a non-unrestricted
    config lacking destructive.ui_input, with a PolicyDenied naming
    ui_input BEFORE any PowerShell runs (neither a resolution leg on
    pswindows.run_ps nor a uia leg on _run_uia_leg may start).
    RED at base (uia absent, ImportError), GREEN after the fix."""
    from hyperv_mcp import uia

    cfg = Config(allowed_vm_patterns=["f05-*"])  # name allowed, ui_input off
    legs = LegRecorder()
    ps = PSRecorder(VM_GUID)
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", ps)
    sel = {"automation_id": "File"}
    with pytest.raises(PolicyDenied, match="ui_input"):
        uia.invoke(cfg, "f05-vm-1", CRED, sel)
    with pytest.raises(PolicyDenied, match="ui_input"):
        uia.set_value(cfg, "f05-vm-1", CRED, sel, "v")
    with pytest.raises(PolicyDenied, match="ui_input"):
        uia.focus(cfg, "f05-vm-1", CRED, sel)
    assert legs.scripts == [], "the ui_input denial must fire before any uia leg"
    assert legs.stdin_b64 == []
    assert ps.scripts == [], "the ui_input denial must fire before any resolution leg"


# ---------------------------------------------------------------------------
# AC6: read verbs need only vm policy plus the credential
# ---------------------------------------------------------------------------

def test_read_verbs_need_only_vm_policy(lab_cfg, monkeypatch):
    """AC6: find/inspect/wait_for/session_state run under a lab-style
    config that sets only allowed_vm_patterns — no destructive category,
    no unrestricted — and each read verb drives its pipe leg. Vm policy
    plus guest credentials are their only requirements.
    RED at base (uia absent, ImportError), GREEN after the fix."""
    from hyperv_mcp import uia

    legs = LegRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))
    reads = [
        partial(uia.find, lab_cfg, "test-vm-1", CRED, {"automation_id": "File"}),
        partial(uia.inspect, lab_cfg, "test-vm-1", CRED, {"name": "Desktop"}),
        partial(uia.wait_for, lab_cfg, "test-vm-1", CRED, {"name": "OK"}, timeout_s=5),
        partial(uia.session_state, lab_cfg, "test-vm-1", CRED),
    ]
    seen = 0
    for call in reads:
        call()
        assert len(legs.scripts) > seen, (
            "each read verb must reach the pipe leg under vm-policy-only config")
        seen = len(legs.scripts)


# ---------------------------------------------------------------------------
# AC7: set_value's value rides the framed stdin, never a script or an error
# ---------------------------------------------------------------------------

def _assert_value_absent(value: str, text: str, what: str) -> None:
    """The value appears neither in clear text nor inside any base64 payload
    embedded in `text` (the -EncodedCommand argv is the base64 of the whole
    script, so a clean script implies a clean argv)."""
    assert value not in text, f"{what} carries the set_value value in clear"
    for run in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            decoded = base64.b64decode(run + "=" * (-len(run) % 4))
        except (binascii.Error, ValueError):
            continue
        assert value not in decoded.decode("utf-8", "replace"), (
            f"{what} carries the set_value value inside a base64 payload")


def test_set_value_rides_stdin(monkeypatch):
    """AC7: set_value carries the value in a framed stdin payload together
    with the credential — line 1 is the utf8-b64 password, line 2 the
    utf8-b64 JSON request — and the value never appears in the generated
    script, its base64 embeddings, any raised error text, or the returned
    result (the response reports the length set, never the value).
    RED at base (uia absent, ImportError), GREEN after the fix."""
    from hyperv_mcp import uia

    value = "s3cret-value"
    cfg = Config(unrestricted=True)
    legs = LegRecorder(result={"length_set": len(value)})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    out = uia.set_value(cfg, "test-vm-1", CRED, {"automation_id": "passwordBox"}, value)
    assert legs.scripts, "set_value must drive its pipe leg"
    for script in legs.scripts:
        _assert_value_absent(value, script, "the leg script")
        assert value not in pswindows.encode_command(script)
    assert value not in json.dumps(out, default=str), (
        "the set_value result must report the length set, never the value")

    framed = [sb for sb in legs.stdin_b64
              if sb and len(sb.strip().split("\n")) == 2]
    assert framed, "the set_value leg must carry the framed two-line stdin payload"
    lines = framed[0].strip().split("\n")
    assert base64.b64decode(lines[0]).decode("utf-8") == CRED.password
    request = json.loads(base64.b64decode(lines[1]).decode("utf-8"))
    assert request["verb"] == "set_value"
    assert request["args"]["value"] == value

    # A failing leg must not leak the value through error text either.
    def failing_leg(cfg, script, *, stdin_b64=None, timeout_s=None, **kwargs):
        return pswindows.PSResult(returncode=1, stderr="pipe connection failed")

    monkeypatch.setattr(uia, "_run_uia_leg", failing_leg)
    blob = ""
    try:
        failed = uia.set_value(
            cfg, "test-vm-1", CRED, {"automation_id": "passwordBox"}, value)
    except Exception as exc:  # every error path must stay value-free
        blob = str(exc)
        failed = None
    if failed is not None:
        blob += json.dumps(failed, default=str)
    assert value not in blob


# ---------------------------------------------------------------------------
# AC8: helper-unavailable is a structured envelope, never a raise
# ---------------------------------------------------------------------------

def test_helper_unavailable_is_structured(lab_cfg, monkeypatch):
    """AC8: when the pipe cannot be opened (the seam raises TimeoutError,
    the 3 s open budget), the verbs return {ok: False, error_class:
    "helper_unavailable"} with a PS Direct fallback session block — the
    interactive user and session id from quser, locked from LogonUI.exe in
    that session — and do not raise.
    RED at base (uia absent, ImportError), GREEN after the fix."""
    from hyperv_mcp import uia

    def pipe_unavailable(cfg, vm, cred, request):
        raise TimeoutError("named pipe open budget expired")

    def quser_ok(cfg, vm, cred):
        return {"user": "tester", "session_id": 2}

    def logonui_present(cfg, vm, cred, session_id):
        return True

    monkeypatch.setattr(uia, "_pipe_request", pipe_unavailable)
    monkeypatch.setattr(uia, "_run_quser", quser_ok)
    monkeypatch.setattr(uia, "_session_has_logonui", logonui_present)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    out = uia.session_state(lab_cfg, "test-vm-1", CRED)
    assert out["ok"] is False
    assert out["error_class"] == "helper_unavailable"
    assert out["session"]["interactive_user"] == "tester"
    assert out["session"]["session_id"] == 2
    assert out["session"]["locked"] is True

    out2 = uia.find(lab_cfg, "test-vm-1", CRED, {"name": "OK"})
    assert out2["ok"] is False
    assert out2["error_class"] == "helper_unavailable"
    assert out2["session"]["locked"] is True


# ---------------------------------------------------------------------------
# AC9: provisioning needs ui_provision plus confirm, before any leg
# ---------------------------------------------------------------------------

def test_provision_requires_category_and_confirm(monkeypatch):
    """AC9: provision_helper without destructive.ui_provision raises
    PolicyDenied naming ui_provision; with the category granted but
    confirm=False it raises PolicyDenied naming confirm; both denials fire
    before any PowerShell runs.
    RED at base (uia absent, ImportError), GREEN after the fix."""
    from hyperv_mcp import uia

    cfg = Config(allowed_vm_patterns=["f05-*"])  # ui_provision not granted
    legs = LegRecorder()
    ps = PSRecorder(VM_GUID)
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", ps)

    with pytest.raises(PolicyDenied, match="ui_provision"):
        uia.provision_helper(cfg, "f05-vm-1", CRED, autologon=True, confirm=True)

    granted = Config.from_dict({
        "allowed_vm_patterns": ["f05-*"],
        "destructive": {"ui_provision": True},
    })
    with pytest.raises(PolicyDenied, match="confirm"):
        uia.provision_helper(granted, "f05-vm-1", CRED, autologon=True, confirm=False)

    assert legs.scripts == [], "both denials must fire before any uia leg"
    assert ps.scripts == [], "both denials must fire before any resolution leg"


# ---------------------------------------------------------------------------
# AC10: the provisioning script contract
# ---------------------------------------------------------------------------

def _split_top_level_args(text: str) -> list[str]:
    """Split a call's argument text on top-level commas (parens respected)."""
    args: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


def _eval_int_expr(expr: str):
    """Evaluate a small integer expression (literals, -bor/|/+/& casts).

    Returns None when the expression is anything richer (a variable, a
    method call) — the caller then refuses to certify the flag.
    """
    import ast

    cleaned = expr.strip()
    for cast in ("[uint32]", "[int]", "[int64]", "[uint64]"):
        cleaned = cleaned.replace(cast, "")
    cleaned = cleaned.replace("-bor", "|").replace("-band", "&").strip()
    try:
        tree = ast.parse(cleaned, mode="eval")
    except SyntaxError:
        return None

    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(
                node.op, (ast.Add, ast.BitOr, ast.BitAnd)):
            left, right = visit(node.left), visit(node.right)
            if left is None or right is None:
                return None
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.BitOr):
                return left | right
            return left & right
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            inner = visit(node.operand)
            return None if inner is None else -inner
        return None

    return visit(tree)


def _createpipe_dwpipemode(helper_text: str):
    """The dwPipeMode (3rd argument) of the helper's CreateNamedPipeW call.

    Returns the evaluated integer, or None when the invocation is absent or
    its mode argument is not a statically resolvable integer expression.
    """
    marker = "::CreateNamedPipeW("
    idx = helper_text.find(marker)
    while idx != -1:
        line_start = helper_text.rfind("\n", 0, idx) + 1
        line = helper_text[line_start:helper_text.find("\n", idx)]
        if line.lstrip().startswith("#"):
            idx = helper_text.find(marker, idx + 1)
            continue
        open_paren = idx + len(marker) - 1
        depth = 0
        end = None
        for pos in range(open_paren, len(helper_text)):
            if helper_text[pos] == "(":
                depth += 1
            elif helper_text[pos] == ")":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        if end is None:
            return None
        args = _split_top_level_args(helper_text[open_paren + 1:end])
        if len(args) < 3:
            return None
        return _eval_int_expr(args[2])
    return None


def test_provision_script_contract(monkeypatch):
    """AC10: the generated provisioning guest legs store the autologon
    password as the LSA secret DefaultPassword via LsaStorePrivateData
    (never a Winlogon registry value), set AutoAdminLogon, register the
    helper task with -LogonType Interactive, -RunLevel Highest and an
    -AtLogOn trigger for the autologon user; the packaged helper script
    creates its pipe with PIPE_REJECT_REMOTE_CLIENTS; the password never
    appears in a script.
    RED at base (uia absent, ImportError), GREEN after the fix."""
    from hyperv_mcp import uia

    cfg = Config(unrestricted=True)
    legs = LegRecorder(result={})
    monkeypatch.setattr(uia, "_run_uia_leg", legs)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    uia.provision_helper(cfg, "test-vm-1", CRED, autologon=True, confirm=True)
    assert legs.scripts, "provisioning must drive at least one guest leg"
    blob = "\n".join(legs.scripts)

    assert "LsaStorePrivateData" in blob
    assert not re.search(
        r"ItemProperty[\s\S]{0,200}DefaultPassword"
        r"|DefaultPassword[\s\S]{0,200}ItemProperty",
        blob,
    ), "the autologon password must never be written as a Winlogon registry value"
    assert "AutoAdminLogon" in blob
    assert "Register-ScheduledTask" in blob
    assert "-LogonType Interactive" in blob
    assert "-RunLevel Highest" in blob
    assert "-AtLogOn" in blob
    assert CRED.username in blob, "the task principal and trigger name the autologon user"
    assert CRED.password not in blob, "the password rides stdin, never a script"

    helper_text = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8")
    )
    # BEHAVIOURAL (F11): the reject-remote guarantee is the dwPipeMode the
    # helper's CreateNamedPipeW invocation actually passes — the old pin
    # matched the header COMMENT. Parse the invocation's third argument
    # (dwPipeMode) and assert it carries the PIPE_REJECT_REMOTE_CLIENTS bit
    # (0x8), and that the invalid .NET [PipeOptions] cast (0xC threw on
    # .NET Framework 4.x — the flag set the helper could never apply) is
    # gone.
    mode = _createpipe_dwpipemode(helper_text)
    assert mode is not None, (
        "the helper must create its pipe through the CreateNamedPipeW "
        "P/Invoke with a literal dwPipeMode expression"
    )
    assert mode & 0x8 == 0x8, (
        f"dwPipeMode {mode:#x} does not carry PIPE_REJECT_REMOTE_CLIENTS "
        "(0x8) - the remote-client rejection is not in force"
    )
    assert "PipeOptions]0xC" not in helper_text and (
        "NamedPipeServerStream(" not in helper_text), (
        "the invalid .NET Framework [PipeOptions]0xC pipe construction must "
        "not survive beside the raw CreateNamedPipeW path"
    )


# ---------------------------------------------------------------------------
# AC11: the ui_input / ui_provision config categories
# ---------------------------------------------------------------------------

def test_config_categories():
    """AC11: DestructivePolicy defaults ui_input and ui_provision to False,
    and a config file may set both under "destructive".
    RED at base ('DestructivePolicy' object has no attribute 'ui_input'),
    GREEN after the fix."""
    cfg = Config()
    assert cfg.destructive.ui_input is False
    assert cfg.destructive.ui_provision is False
    cfg2 = Config.from_dict({"destructive": {"ui_input": True, "ui_provision": True}})
    assert cfg2.destructive.ui_input is True
    assert cfg2.destructive.ui_provision is True


# ---------------------------------------------------------------------------
# AC12: the eight element tools are registered in both credential modes
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def _schemas(mod) -> dict:
    mcp = mod.get_mcp()
    tools = asyncio.run(mcp.list_tools())
    # mcp 1.x Tool exposes inputSchema; 2.x exposes input_schema.
    return {t.name: (getattr(t, "input_schema", None) or t.inputSchema) for t in tools}


def test_ui_tools_registered(tmp_path, fresh_server):
    """AC12: default mode registers the eight ui tools; only
    hyperv_ui_helper_provision carries confirm (the seven interaction tools
    do not); inline-credential mode exposes username/password on all eight.
    RED at base (none of the eight exists — the missing-tools assertion
    fails listing them), GREEN after the fix."""
    mod = fresh_server({})
    schemas = _schemas(mod)
    missing = sorted(UI_TOOLS - set(schemas))
    assert missing == []

    assert "confirm" in schemas["hyperv_ui_helper_provision"].get("properties", {})
    for name in sorted(UI_INTERACTION_TOOLS):
        assert "confirm" not in schemas[name].get("properties", {}), name

    doc = {"allow_inline_credentials": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod2 = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    cred_schemas = _schemas(mod2)
    for name in sorted(UI_TOOLS):
        props = cred_schemas[name].get("properties", {})
        assert "username" in props, name
        assert "password" in props, name
