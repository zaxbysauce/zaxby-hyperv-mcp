"""PR #142 swarm-pr-review feedback pins (NEW non-frozen file — the frozen
44-row contract is untouched).

PRR-007: the registered hyperv_ui_* READ tools must surface the minted
state_receipt to the caller. Both reviewer shards reproduced a drop-mutant
(deleting the key from server._run_ui_tool's ok-path return) that kept the
entire certified suite green — the 44 rows exercise the uia VERB layer, and
C29 only greps descriptions. Pins here: (1) an end-to-end registered-tool
call with a REAL mint over the faked transport must return the id AND that
id must be a live registry member; (2) BOTH credential-variant
_run_ui_tool wrappers (server.py defines two; call_tool reaches one) are
structurally pinned to return the verb dict unchanged — the drop mutant
destroys that literal and this pin goes RED.

PRR-008: a guarded click citing a fresh receipt WITHOUT frame_width/
frame_height must ALLOW — the documented distinguishing property of the
receipt channel ("no pixel-domain requirement"). Every frozen receipt click
supplies 320x240, so the reviewer's mutant moving the pixel-domain demand
BEFORE the receipt branch survived 160/160. These rows make that mutant RED
for both transport twins (PS via click dispatch, WMI via direct twin call
with the backend capture armed to explode if consulted)."""

import ast
import asyncio
import json
import pathlib
import threading

import pytest
import test_console_commit_guard_uia as frozen

from hyperv_mcp import console, pswindows, uia, vmident
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

CRED = frozen.CRED
GUID = frozen.GUID

SERVER_SRC = (pathlib.Path(__file__).resolve().parents[2]
              / "src" / "hyperv_mcp" / "server.py")


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


@pytest.fixture(autouse=True)
def _clean_ledger():
    console.reset_input_ledger()
    yield
    console.reset_input_ledger()


@pytest.fixture()
def fresh_server(monkeypatch):
    """a05 pattern: reload+bootstrap per test, reload again on teardown so
    no later test inherits an unrestricted/bootstrapped module (verification
    round-1 nit)."""
    import importlib

    import hyperv_mcp.server as server_module

    def make(environ: dict, config=None):
        monkeypatch.setenv("HYPERV_MCP_UNRESTRICTED", "1")
        mod = importlib.reload(server_module)
        if config is not None:
            mod.bootstrap(environ, config=config)
        else:
            mod.bootstrap(environ)
        return mod

    yield make
    importlib.reload(server_module)


def _meta(result) -> dict:
    from conftest import content_blocks

    texts = [c for c in content_blocks(result)
             if getattr(c, "type", "") == "text"]
    assert texts, "no metadata text block in the success result"
    return json.loads(texts[0].text)


# ---- PRR-007: registered read-tool envelope + wrapper pass-through ------


def test_registered_read_tool_surfaces_state_receipt(monkeypatch, unrestricted,
                                                     fresh_server):
    """End-to-end through the registered FastMCP tool: hyperv_ui_find's
    envelope carries the minted state_receipt, and the id is a live
    registry member (citable), not a fabricated string."""
    frozen._ui_transport(monkeypatch, guids={"vm1": GUID})
    # The registered variant takes NO inline credentials (env-sourced, per
    # the tool docs): supply them the way a deployment does.
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "tester")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "placeholder-pass")
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()
    result = asyncio.run(mcp.call_tool("hyperv_ui_find", {
        "vm_name": "vm1", "selector": {"automation_id": "File"},
    }))
    meta = _meta(result)
    assert meta.get("ok") is True, meta
    rid = meta.get("state_receipt")
    assert isinstance(rid, str) and rid, (
        "PRR-007: the registered read tool's envelope must carry the minted "
        "state_receipt — the agent's only handle into the receipt channel"
    )
    assert (console._lookup_state_receipt(rid, console._ledger_key("vm1", GUID))
            is not None
            or console._lookup_state_receipt(rid, console._ledger_key("vm1", ""))
            is not None), (
        "PRR-007: the surfaced id must be a live registry member under this "
        "VM's ledger key, not a pass-through of some foreign string")


def _result_mutations(w: ast.FunctionDef) -> list:
    """Every syntax that could silently alter the verb result BEFORE it
    reaches the caller's envelope: method calls on `result`, subscript
    store/delete, re-binding `result` to anything but the verb call, and
    rebuilds embedding `**result` (verification round-1: the first version
    of this pin only checked a `return result` existed, and
    `result.pop("state_receipt", None)` before it survived both shards)."""
    MUTATORS = {"pop", "update", "clear", "setdefault", "popitem"}
    bad = []
    for node in ast.walk(w):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "result"
                and node.func.attr in MUTATORS):
            # READ methods (result.get(...) for the ok/error_class audit)
            # are legitimate; only mutators can silently drop the key.
            bad.append(ast.unparse(node))
        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                base = t.value if isinstance(t, ast.Subscript) else t
                if isinstance(base, ast.Name) and base.id == "result":
                    value = node.value
                    keeps_call = (isinstance(value, ast.Call)
                                  and getattr(value.func, "id", "") == "fn")
                    if not keeps_call:
                        bad.append(ast.unparse(node))
        elif isinstance(node, ast.Delete):
            for t in node.targets:
                base = t.value if isinstance(t, ast.Subscript) else t
                if isinstance(base, ast.Name) and base.id == "result":
                    bad.append(ast.unparse(node))
        elif isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Name) and k.id == "result":
                    bad.append(f"rebuild **{ast.unparse(node)}")
    return bad


def test_both_ui_tool_wrappers_return_the_verb_dict_unchanged():
    """Structural pin over BOTH credential variants of _run_ui_tool: the
    ok-path must be a bare `return result`, and NOTHING in the wrapper may
    mutate or rebuild `result` first — any key filtering, .pop, del, or
    envelope rebuild silently drops state_receipt from one credential
    variant while the other variant's behavioral test still passes
    (verification round-1 Finding 2: the earlier existence-only pin was
    bypassable by a pre-return result.pop in the wrapper this test does
    not behaviorally reach)."""
    tree = ast.parse(SERVER_SRC.read_text(encoding="utf-8"))
    wrappers = [n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "_run_ui_tool"]
    assert len(wrappers) == 2, (
        f"expected both credential-variant _run_ui_tool wrappers, found "
        f"{len(wrappers)} — if the registration shape legitimately changed, "
        "update this pin deliberately, never silently")
    for w in wrappers:
        ok_returns = [n for n in ast.walk(w)
                      if isinstance(n, ast.Return)
                      and isinstance(n.value, ast.Name)
                      and n.value.id == "result"]
        assert ok_returns, (
            f"_run_ui_tool at line {w.lineno} must return the verb result "
            "dict unchanged on the success path (PRR-007): filtering or "
            "rebuilding the envelope silently drops state_receipt")
        bad = _result_mutations(w)
        assert not bad, (
            f"_run_ui_tool at line {w.lineno} mutates the verb result "
            f"before returning it: {bad} — the registered envelope must "
            "carry state_receipt for BOTH credential variants")


def test_registered_read_tool_surfaces_state_receipt_inline_credentials(
        monkeypatch, unrestricted, fresh_server):
    """Behavioral coverage for the OTHER credential variant (PRR-007,
    verification round-1 Finding 2): with allow_inline_credentials on, the
    registered hyperv_ui_find takes username/password and its envelope must
    still carry the minted state_receipt. Without this row the
    creds_allowed wrapper was only covered by the AST pin."""
    frozen._ui_transport(monkeypatch, guids={"vm1": GUID})
    from hyperv_mcp.config import Config

    mod = fresh_server({}, config=Config(unrestricted=True,
                                         allow_inline_credentials=True))
    mcp = mod.get_mcp()
    result = asyncio.run(mcp.call_tool("hyperv_ui_find", {
        "vm_name": "vm1", "selector": {"automation_id": "File"},
        "username": "tester", "password": "placeholder-pass",
    }))
    meta = _meta(result)
    assert meta.get("ok") is True, meta
    rid = meta.get("state_receipt")
    assert isinstance(rid, str) and rid, (
        "PRR-007: the inline-credentials variant's envelope must carry "
        "the minted state_receipt too — one variant silently dropping it "
        "breaks the receipt channel for deployments with inline creds on")


# ---- PRR-008: receipt click without the pixel domain, both twins ------


def test_receipt_click_without_frame_dims_dispatches(unrestricted, monkeypatch):
    fake = frozen._ui_transport(monkeypatch, guids={"vm1": GUID})
    rid = uia.find(unrestricted, "vm1", CRED,
                   {"automation_id": "File"})["state_receipt"]
    out = console.click(unrestricted, "vm1", 160, 120,
                        commit_guard=True, verified_state_receipt=rid)
    assert out.get("ok") is True, (
        "PRR-008: the documented receipt channel demands no pixel domain — "
        "a fresh citation without frame_width/frame_height must be allowed"
    )
    assert any("ClickButton" in s or "SetAbsolutePosition" in s
               for s in fake.scripts), (
        "PRR-008: an allowed guarded click must actually dispatch the mouse "
        "input; this also kills the demand-pixels-first mutant, which "
        "refuses commit_unverified before the receipt branch is reached")


def test_wmi_twin_receipt_without_dims_never_captures(unrestricted, monkeypatch):
    frozen._ui_transport(monkeypatch, guids={"vm1": GUID})
    rid = uia.find(unrestricted, "vm1", CRED,
                   {"automation_id": "File"})["state_receipt"]
    consulted: list = []

    class _ExplodingBE:
        def capture(self, vm_id, width, height):
            consulted.append((vm_id, width, height))
            raise AssertionError(
                "PRR-008: the receipt path must never consult the live "
                "capture leg (C22 parity, now pinned WITHOUT frame dims)")

    ref = vmident.VMRef(id=GUID, name="vm1")
    console._commit_guard_check_wmi(_ExplodingBE(), ref, 0, 0, "",
                                    verified_state_receipt=rid)
    assert consulted == [], (
        "PRR-008: WMI twin must skip capture entirely on the receipt branch")


# ---- PRR-002/003: structural guard — receipt branch BEFORE the pixel ------
# ---- demand and before the capture leg, in BOTH twins (order matters as    ----
# ---- much as behavior: a mutant that merely SWAPS the two blocks survives   ----
# ---- pure-behavior tests that always supply frame dims) --------------------


def _guard_twin(name: str) -> ast.FunctionDef:
    tree = ast.parse(pathlib.Path(console.__file__).read_text(encoding="utf-8"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn is not None, f"{name} vanished"
    return fn


def _first_if_testing_receipt(fn: ast.FunctionDef) -> int:
    for node in ast.walk(fn):
        if isinstance(node, ast.If) and "verified_state_receipt" in \
                ast.unparse(node.test):
            assert any(isinstance(n, ast.Return) for n in node.body), (
                "the receipt branch must RETURN (audit + dispatch by the "
                "caller), not fall through into the capture leg")
            return node.lineno
    raise AssertionError("no receipt branch found — the twin lost it")


def _pixel_demand_lineno(fn: ast.FunctionDef) -> int:
    for node in ast.walk(fn):
        if isinstance(node, ast.Raise) and "frame_width/frame_height" in \
                ast.unparse(node):
            return node.lineno
    raise AssertionError("no pixel-domain demand found in the twin")


@pytest.mark.parametrize("twin", ["_commit_guard_check_ps", "_commit_guard_check_wmi"])
def test_receipt_branch_precedes_pixel_demand_in_both_twins(twin):
    fn = _guard_twin(twin)
    assert _first_if_testing_receipt(fn) < _pixel_demand_lineno(fn), (
        "PRR-002/003: the receipt branch must be evaluated BEFORE the "
        "pixel-domain demand — swapping the order re-imposes "
        "frame_width/frame_height on documented receipt citations "
        "(the reviewer's surviving mutant)")


# ---- AC15-lineage (C15/C35 class): the observation->stamp window is       ----
# ---- barrier-deterministic even WITHOUT frame dims (C35's guarantee        ----
# ---- re-proven on the no-dims click path — NOTE: the feedback round first  ----
# ---- labeled this "PRR-001", a mislabel; synthesis PRR-001 (guest-CIM) was ----
# ---- path; thread-free-oracle: events decide ordering, sleeps decide        ----
# ---- nothing — a dropped _read_console_exclusion makes the bump land       ----
# ---- BEFORE the stamp and the citation go falsely FRESH (test goes RED))   ----


def test_no_dims_stamp_window_blocks_concurrent_bump(unrestricted, monkeypatch):
    ref = vmident.VMRef(id=GUID, name="vm1")
    parked = threading.Event()
    attempted = threading.Event()
    order: list[str] = []

    def stub_pipe(cfg, r, cred, request):
        # Observation is complete at entry here; park BEFORE returning so
        # the stamp (which runs after _frame_out) is held up INSIDE the
        # exclusion region — the exact window the dual-key hold guards.
        parked.set()
        assert attempted.wait(10), "input thread never attempted its bump"
        order.append("park-observed-attempt")
        return frozen._ok_frame()

    monkeypatch.setattr(uia, "_pipe_request", stub_pipe)
    monkeypatch.setattr(pswindows, "run_ps",
                        frozen.FakePS(guids={"vm1": GUID}))

    def input_dispatch():
        attempted.set()
        with console._input_lock(ref):
            order.append("bump")
            console.record_console_input(vm_name=ref.name, vm_id=ref.id)

    result: dict = {}

    def reader():
        result.update(uia.find(unrestricted, "vm1", CRED,
                               {"automation_id": "File"}))

    t_reader = threading.Thread(target=reader)
    t_input = threading.Thread(target=input_dispatch)
    t_reader.start()
    assert parked.wait(10), "read never reached the pre-stamp park"
    t_input.start()
    t_reader.join(30)
    t_input.join(30)
    assert not t_reader.is_alive() and not t_input.is_alive()
    rid = result.get("state_receipt")
    assert isinstance(rid, str) and rid, "the read must still mint (no dims)"
    assert order == ["park-observed-attempt", "bump"], (
        "PRR-001: the bump must have been BLOCKED by the read's console-key "
        f"hold until after the stamp — order {order}; a dropped exclusion "
        "lets the bump land first and the citation reads falsely fresh")
    with pytest.raises(ConsoleError, match="stale"):
        # Direct click (NOT frozen._guarded_receipt_click — that helper
        # presets frame dims, and passing them again would TypeError; the
        # no-dims citation is the point of this row).
        console.click(unrestricted, "vm1", 160, 120,
                      commit_guard=True, verified_state_receipt=rid)


# ---- PRR-005: the receipt-key refusal covers EVERY step kind (the hoist)  ----


@pytest.mark.parametrize("step", [
    {"action": "press_key", "key": "enter", "verified_state_receipt": "f" * 32},
    {"action": "key_combo", "keys": ["ctrl", "alt", "delete"],
     "verified_state_receipt": "f" * 32},
    {"action": "type_text", "text": "hi", "verified_state_receipt": "f" * 32},
    {"action": "type_scancodes", "scancodes": [28, 156],
     "verified_state_receipt": "f" * 32},
    {"action": "mouse_move", "x": 1, "y": 2, "verified_state_receipt": "f" * 32},
    {"action": "mouse_button", "button": 1, "is_down": True,
     "verified_state_receipt": "f" * 32},
    {"action": "scroll", "delta": 1, "verified_state_receipt": "f" * 32},
    {"action": "wait_frame_stable", "stable_ms": 1,
     "verified_state_receipt": "f" * 32},
])
def test_every_step_kind_refuses_the_receipt_key(unrestricted, monkeypatch, step):
    """Published contract: a step carrying verified_state_receipt is a
    step-indexed refusal, NEVER a silently ignored key — the first version
    scoped the refusal to click steps only (reviewer PRR-005); non-click
    steps silently dropped the safety parameter. The transport is a
    recording sentinel (verification round-1 Finding 3): with the hoist
    removed the step PLANS and dispatches, so the modeled defect surfaces
    as pytest.raises DID NOT RAISE (plus a recorded script) — not as an
    environmental transport error."""
    stub = frozen.SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(ValueError) as excinfo:
        console.run_sequence(unrestricted, "vm1", [dict(step)])
    message = str(excinfo.value)
    assert "step 0" in message, message
    assert message.count("step 0:") == 1, (
        "the step prefix must appear exactly once — the first version "
        "double-prefixed ('step 0: step 0: ...')")
    assert "verified_state_receipt" in message, (
        "the refusal must name the refused key for every step action, "
        f"got: {message}")
    assert stub.scripts == [], (
        "a refused step key must dispatch nothing (sentinel transport "
        "records any attempted leg — the hoist-removal mutant lands here)")


# ---- PRR-004: guardrail exemptions are (module, function) pairs — no      ----
# ---- bare-name escape; every pair must correspond to a real def           ----


def test_allowed_lock_keys_are_module_qualified_and_live():
    import test_vm_identity_guardrail as guard

    assert all(isinstance(entry, tuple) and len(entry) == 2
               for entry in guard.ALLOWED_LOCK_KEYS), (
        "PRR-004: allowlist entries must be (module, function) PAIRS — "
        "bare function names exempt the name in EVERY module")
    for mod, func in guard.ALLOWED_LOCK_KEYS:
        path = guard.SRC / mod
        assert path.exists(), f"allowlist points at vanished module {mod}"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert any(isinstance(n, ast.FunctionDef) and n.name == func
                   for n in ast.walk(tree)), (
            f"allowlist entry ({mod}, {func}) names no real function — "
            "stale exemptions must die, not linger as wildcards")
