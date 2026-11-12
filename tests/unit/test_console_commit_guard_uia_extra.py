"""Issue #140 expansion checks (critic round 1, Required Revisions 1-3/6-7):
the UIA state-receipt channel's critic-required guardrails, authored BEFORE
the fix (arm's-length author; round 1's C1-C12 lives, manifest-frozen, in
tests/unit/test_console_commit_guard_uia.py — imported here as `frozen`,
never edited).

Contract bound (REV-2 plan, critic-verified): a UIA read teaches the
console name->GUID hint at leg entry and mints its receipt inside the
console-key exclusion; UIA MUTATING verbs bump the input ledger at the
_pipe_forward dispatch seam (pre-dispatch refusals never bump); evidence's
internal reads mint nothing; the receipt channel has WMI parity with NO
live capture; the registry is FIFO-capped; refusals keep the frozen token
family. Every positively-cited id is one a faked read (or, for C14's
pre-hint mint, the internal record_state_read seam) RETURNED. Two transport
tiers after the frozen file's idioms — the PIPE tier (the frozen PipeStub
on uia._pipe_request) where only the mint matters, and the LEG tier (see
LegStub below) where the mutating-verb bump site must be exercised.
PRE-FIX: every NEW-SURFACE check fails on the missing surface (naming
`state_receipt`, or `record_state_read` in C14); C21 is PRESERVING.
"""

import asyncio
import base64
import importlib
import json
import threading
import time

import pytest
import test_console_commit_guard_uia as frozen
from test_console_wmi_guard import FakeWMI

from hyperv_mcp import auditlog, console, pswindows, uia
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

CRED = frozen.CRED
FRAME_W, FRAME_H = frozen.FRAME_W, frozen.FRAME_H
GUID = frozen.GUID

#: The genuine time.sleep (C20 re-installs short REAL poll sleeps).
_REAL_SLEEP = time.sleep

#: C28's forwarding probe: the spy intercepts console.click (pass-through).
_FORWARD_PROBE = "forwarding-probe-receipt-id"
_SESSION = {"session_id": 2, "interactive_user": "tester", "locked": False}


def _click_kw(cfg, vm, receipt):
    """The C25/C26 matrix's subject: a guarded x/y click citing `receipt`."""
    kw = dict(frame_width=FRAME_W, frame_height=FRAME_H, commit_guard=True, verified_state_receipt=receipt)
    return console.click(cfg, vm, 160, 120, **kw)


def _helper_frame() -> dict:
    """An ok frame with a RUNNING, version-matched helper session."""
    return {
        "ok": True,
        "result": {"elements": 1, "truncated": False, "tree": {"name": "Desktop"}},
        "session": {
            **_SESSION,
            "helper": {"running": True, "version": uia.HELPER_VERSION},
        },
    }


def _empty_elements_frame() -> dict:
    """An ok frame answering a wait_for slice with NO match."""
    return {"ok": True, "result": {"elements": []}, "session": dict(_SESSION)}


class LegStub:
    """Deep stub at uia._run_uia_leg (the f05 seam): answers the pipe-client
    leg with a correlation/integrity-valid frame, keeping _verb_request ->
    _front_door -> _pipe_forward REAL — the plan's UIA-mutation bump site,
    which a _pipe_request stub would bypass."""

    def __init__(self, frame: dict | None = None):
        self.requests: list[dict] = []
        self.frame = frame or frozen._ok_frame()

    def __call__(self, cfg, script, *, stdin_b64=None, timeout_s=None):
        if "hyperv-mcp-uia" not in script:
            return pswindows.PSResult(stdout="", returncode=0)
        line2 = (stdin_b64 or "").splitlines()[1]
        request = json.loads(base64.b64decode(line2).decode("utf-8"))
        self.requests.append(request)
        frame = dict(self.frame)
        frame["id"] = request.get("id")
        session = dict(frame.get("session") or {})
        helper = dict(session.get("helper") or {})
        helper.setdefault("running", True)
        helper.setdefault("version", uia.HELPER_VERSION)
        helper.setdefault("sha256", uia._packaged_helper_sha256() or "")
        session["helper"] = helper
        frame["session"] = session
        return pswindows.PSResult(stdout=json.dumps(frame), returncode=0)


def _ui_leg_transport(monkeypatch, frame: dict | None = None, gate: bool = False):
    """Wire the LEG tier (gate=True also neutralizes the #28 mutation gate
    so a mutating verb can dispatch in the fake). Returns the recorder."""
    fake = frozen.FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(uia, "_run_uia_leg", LegStub(frame))
    monkeypatch.setattr(uia, "_run_quser", lambda cfg, ref, cred: None)
    monkeypatch.setattr(uia, "_ps_guest_text", lambda cfg, ref, cred, guest_command, timeout_s=30: "")
    if gate:
        monkeypatch.setattr(uia, "_shared_mutation_gate", lambda *a, **k: None)
    return fake


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


# C13 (critic Critical 1): the COLD by-name path — no manual hint seeding


def test_cold_name_read_then_by_name_click_allows(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch)
    rid = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"}).get("state_receipt")
    assert isinstance(rid, str) and rid, "C13: a read must mint `state_receipt` with NO manual hint seeding"
    clicked = frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    assert clicked["ok"] is True, (
        "C13: a guarded click by NAME must resolve the receipt a by-name "
        "read minted — the name-vs-GUID ledger-key fork refuses the "
        "issue's target workflow"
    )
    assert any("ClickButton" in s for s in fake.scripts)


# C14 (critic Critical 1): hint-learn migration preserves the receipt


def test_hint_learn_migrates_receipt_preserving_freshness(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch)
    console.record_console_input(vm_name="vm1")  # a pre-hint name-keyed input
    rid = console.record_state_read(vm_name="vm1")  # the pre-hint mint
    assert isinstance(rid, str) and rid, "C14: record_state_read must return the minted id"
    console.note_name_guid_hint("vm1", GUID)  # the newly-learned transition
    clicked = frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    assert clicked["ok"] is True, (
        "C14: a pre-hint receipt must migrate to the GUID key PRESERVING "
        "its seq (still citable, still fresh against the pre-mint input)"
    )
    assert any("ClickButton" in s for s in fake.scripts)


# C15 (critic Critical 2): an input dispatch cannot interleave observation
# and stamp (spy-ordering formulation; see trace notes for the race caveat)


def test_input_cannot_interleave_between_read_and_stamp(monkeypatch, unrestricted):
    entered = threading.Event()
    proceed = threading.Event()

    class ParkingPipe:
        def __call__(self, cfg, vm, cred, request):
            entered.set()
            assert proceed.wait(20), "the parked read leg was never released"
            return frozen._ok_frame()

    fake = frozen.FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(uia, "_pipe_request", ParkingPipe())
    order: list[str] = []  # atomic appends; read after both joins
    real_input = console.record_console_input

    def spy_input(*a, **k):
        order.append("input")
        return real_input(*a, **k)

    monkeypatch.setattr(console, "record_console_input", spy_input)
    real_mint = getattr(console, "record_state_read", None)

    def spy_mint(*a, **k):
        order.append("mint")
        return real_mint(*a, **k) if real_mint is not None else ""

    monkeypatch.setattr(console, "record_state_read", spy_mint, raising=False)
    holder: dict = {}

    def run_read():
        holder["out"] = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})

    reader = threading.Thread(target=run_read)
    reader.start()
    assert entered.wait(20), "the read never reached its transport leg"

    def run_input():  # a real input dispatch, STARTED mid-leg
        try:
            console.press_key(unrestricted, "vm1", "enter")
        except Exception:
            pass  # the oracle is the ledger order, not the op's own result

    inp = threading.Thread(target=run_input)
    inp.start()
    proceed.set()
    reader.join(30)
    inp.join(30)
    assert not reader.is_alive() and not inp.is_alive(), "both threads must finish"
    rid = (holder.get("out") or {}).get("state_receipt")
    assert isinstance(rid, str) and rid, "C15: the parked read must still mint `state_receipt`"
    assert "input" in order, "the concurrent input dispatch must have bumped"
    if "mint" in order:
        assert order.index("mint") < order.index("input"), (
            "C15: an input dispatch started while the read leg was parked "
            f"must land AFTER the receipt stamp; observed order {order}"
        )
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


# C16/C17/C18 (critic Critical 3): every MUTATING verb stales the receipt
# (the LEG tier keeps _pipe_forward — the bump seam — real)


def test_read_then_invoke_stales_receipt(monkeypatch, unrestricted):
    fake = _ui_leg_transport(monkeypatch, gate=True)
    rid = frozen._mint_receipt(unrestricted, "vm1")
    out = uia.invoke(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert out.get("ok") is True, "the fake helper transport must serve invoke"
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


def test_read_then_set_value_stales_receipt(monkeypatch, unrestricted):
    fake = _ui_leg_transport(monkeypatch, gate=True)
    rid = frozen._mint_receipt(unrestricted, "vm1")
    out = uia.set_value(unrestricted, "vm1", CRED, {"automation_id": "File"}, "v")
    assert out.get("ok") is True, "the fake helper transport must serve set_value"
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


def test_read_then_focus_stales_receipt(monkeypatch, unrestricted):
    fake = _ui_leg_transport(monkeypatch, gate=True)
    rid = frozen._mint_receipt(unrestricted, "vm1")
    out = uia.focus(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert out.get("ok") is True, "the fake helper transport must serve focus"
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


# C19: a pre-dispatch refusal (the #28 mutation gate, BEFORE the pipe
# forward — the documented deterministic seam) never stales a receipt


def test_pre_dispatch_mutation_refusal_does_not_stale(monkeypatch, unrestricted):
    fake = _ui_leg_transport(monkeypatch)

    def refusing_gate(*a, **k):
        raise uia.UiAError("shared-VM mutation refused: lease held")

    monkeypatch.setattr(uia, "_shared_mutation_gate", refusing_gate)
    rid = frozen._mint_receipt(unrestricted, "vm1")
    with pytest.raises(uia.UiAError):
        uia.invoke(unrestricted, "vm1", CRED, {"automation_id": "File"})
    clicked = frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    assert clicked["ok"] is True, (
        "C19: a mutating verb refused BEFORE dispatch must not bump the "
        "input ledger — the prior receipt stays citable"
    )
    assert any("ClickButton" in s for s in fake.scripts)


# C20: a wait_for budget expiry still mints a citable receipt


def test_wait_for_expiry_mints_citable_receipt(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch, frame=_empty_elements_frame())
    monkeypatch.setattr(console.time, "sleep", lambda s: _REAL_SLEEP(min(s, 0.05)))
    out = uia.wait_for(unrestricted, "vm1", CRED, {"name": "NeverAppears"}, timeout_s=1)
    assert out.get("ok") is True, "the expiring wait's last slice succeeded"
    assert out.get("timed_out") is True, "the wait must expire unanswered"
    rid = out.get("state_receipt")
    assert isinstance(rid, str) and rid, (
        "C20: a wait_for budget expiry must still mint and return "
        "`state_receipt` (the last successful slice's)"
    )
    clicked = frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    assert clicked["ok"] is True, "the expiry receipt must be citable"
    assert any("ClickButton" in s for s in fake.scripts)


# C21 (PRESERVING): evidence's hidden internal reads mint NOTHING


def test_evidence_ui_tree_mints_nothing(monkeypatch, unrestricted):
    from hyperv_mcp import evidence

    fake = frozen._ui_transport(monkeypatch, frame=_helper_frame())
    mints = []

    def spy_mint(*a, **k):
        mints.append(a)
        return ""

    monkeypatch.setattr(console, "record_state_read", spy_mint, raising=False)
    monkeypatch.setattr(console, "screenshot", lambda *a, **k: (None, {"vm_id": GUID}))
    out = evidence.capture_evidence(unrestricted, "vm1", ui_tree=True, cred=CRED)
    assert out["ok"] is True
    assert out["meta"]["ui_tree"].get("source") == "helper", (
        "the helper ui-tree path must actually run for this pin to bite"
    )
    assert mints == [], (
        "C21: evidence's internal UIA reads must mint ZERO receipts — "
        "hidden mints churn the registry and can evict caller receipts"
    )
    assert fake.scripts, "sanity: the evidence leg resolved its VM"


# C22: WMI parity — forward, skip the live capture, audit once, zero
# mouse ops on stale/unknown refusals


def test_wmi_receipt_channel_parity(monkeypatch, tmp_path, unrestricted):
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    frozen._ui_transport(monkeypatch, guids={"wmi-vm": GUID})
    be = FakeWMI()  # the wmi-guard suite's fake backend (imported above)
    monkeypatch.setattr(console, "_try_backend", lambda cfg: (be, 0.0))
    rid = frozen._mint_receipt(cfg, "wmi-vm")
    clicked = frozen._guarded_receipt_click(cfg, "wmi-vm", rid)
    assert clicked["ok"] is True, "a fresh receipt must let the WMI click through"
    assert "capture" not in be.calls, "the receipt channel takes NO live WMI capture"
    assert be.clicks == [(GUID, 1, 512, 384)]
    rid2 = frozen._mint_receipt(cfg, "wmi-vm")
    console.record_console_input(vm_name="wmi-vm", vm_id=GUID)
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(cfg, "wmi-vm", rid2)
    with pytest.raises(ConsoleError, match="unverified"):
        frozen._guarded_receipt_click(cfg, "wmi-vm", frozen.NEVER_MINTED)
    assert be.calls.count("mouse_click") == 1, "refusals dispatch ZERO mouse ops"
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert len(guard_rows) == 1, "exactly ONE guard audit row (the allow)"


# C23: FIFO eviction past the 512-entry cap


def test_receipt_registry_fifo_eviction(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch)
    ids = []
    for _ in range(513):
        rid = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"}).get("state_receipt")
        assert isinstance(rid, str) and rid, "C23: every faked read must mint `state_receipt`"
        ids.append(rid)
    assert len(set(ids)) == len(ids), "each read mints a DISTINCT receipt id"
    with pytest.raises(ConsoleError, match="unverified"):
        frozen._guarded_receipt_click(unrestricted, "vm1", ids[0])
    frozen._assert_no_mouse(fake)
    clicked = frozen._guarded_receipt_click(unrestricted, "vm1", ids[-1])
    assert clicked["ok"] is True, "the NEWEST receipt must survive the cap"
    assert any("ClickButton" in s for s in fake.scripts)


# C24: input BEFORE read stays fresh (kills separate-counter
# implementations; complements frozen C4 read->input->stale)


def test_input_before_read_receipt_stays_fresh(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch)
    console.note_name_guid_hint("vm1", GUID)
    console.record_console_input(vm_name="vm1")  # the input BEFORE the read
    rid = frozen._mint_receipt(unrestricted, "vm1")  # the verification read
    clicked = frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    assert clicked["ok"] is True, (
        "C24: a receipt minted AFTER the last input must stay fresh — "
        "receipts and inputs share ONE ledger sequence domain"
    )
    assert any("ClickButton" in s for s in fake.scripts)


# C25/C26/C27: the citation validation matrix at console.click level


def test_receipt_citation_type_discipline(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch)
    console.note_name_guid_hint("vm1", GUID)
    frozen._mint_receipt(unrestricted, "vm1")
    for bad in (123, b"x"):  # truthy non-str: a clean ValueError
        with pytest.raises(ValueError, match="verified_state_receipt"):
            _click_kw(unrestricted, "vm1", bad)
    for absent in (None, False, b""):  # falsy non-str: treated ABSENT
        with pytest.raises(ConsoleError, match="unverified"):
            _click_kw(unrestricted, "vm1", absent)
    frozen._assert_no_mouse(fake)


def test_receipt_channel_discipline(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch)
    console.note_name_guid_hint("vm1", GUID)
    rid = frozen._mint_receipt(unrestricted, "vm1")
    with pytest.raises(ValueError, match="verified_state_receipt"):  # BOTH
        frozen._guarded_receipt_click(unrestricted, "vm1", rid, verified_frame_hash="a" * 64)
    with pytest.raises(ConsoleError, match="unverified"):  # NEITHER
        console.click(
            unrestricted, "vm1", 160, 120, frame_width=FRAME_W, frame_height=FRAME_H, commit_guard=True
        )
    frozen._assert_no_mouse(fake)


def test_guarded_receipt_click_without_xy_refused(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch)
    console.note_name_guid_hint("vm1", GUID)
    rid = frozen._mint_receipt(unrestricted, "vm1")
    with pytest.raises(ValueError, match="x/y"):
        console.click(unrestricted, "vm1", commit_guard=True, verified_state_receipt=rid)
    frozen._assert_no_mouse(fake)


# C28: the REGISTERED hyperv_console_click forwards the new parameter


def test_registered_click_forwards_state_receipt(monkeypatch):
    import hyperv_mcp.server as server_module

    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
    try:
        forwarded: dict = {}

        def spy_click(cfg, *args, **kwargs):
            forwarded.update(kwargs)
            return {"ok": True, "vm_name": "vm1"}

        monkeypatch.setattr(console, "click", spy_click)
        args = {
            "vm_name": "vm1",
            "x": 160,
            "y": 120,
            "frame_width": FRAME_W,
            "frame_height": FRAME_H,
            "button": 1,
            "commit_guard": True,
            "verified_state_receipt": _FORWARD_PROBE,
        }
        try:
            asyncio.run(mod.get_mcp().call_tool("hyperv_console_click", args))
        except Exception:
            pass  # the pre-fix surface refuses the unknown parameter; the
            # oracle is the spy, not the call's own envelope
        assert forwarded.get("verified_state_receipt") == _FORWARD_PROBE, (
            "C28: the registered hyperv_console_click must forward "
            "verified_state_receipt to console.click through the real "
            "FastMCP call surface (wired, not just documented)"
        )
    finally:
        importlib.reload(server_module)


# C29: the four UIA read tools document state_receipt in BOTH
# credential configurations


def test_read_tools_document_state_receipt_both_variants(tmp_path):
    from mcp.server.mcpserver import MCPServer

    from hyperv_mcp import server as server_mod

    default_tools = {t.name: t for t in asyncio.run(server_mod.get_mcp().list_tools())}
    cfg = Config(
        unrestricted=True, audit_log_path=str(tmp_path / "audit.jsonl"), allow_inline_credentials=True
    )
    inline_mcp = MCPServer("hyperv_mcp_inline_variant", version="0.0.0-test")
    server_mod._register_tools(cfg, inline_mcp)
    inline_tools = {t.name: t for t in asyncio.run(inline_mcp.list_tools())}
    missing = []
    for tools, label in ((default_tools, "default"), (inline_tools, "inline")):
        for name in ("hyperv_ui_inspect", "hyperv_ui_find", "hyperv_ui_wait_for", "hyperv_ui_session_state"):
            tool = tools.get(name)
            desc = (tool.description or "") if tool is not None else ""
            if "state_receipt" not in desc:
                missing.append(f"{label}:{name}")
    assert missing == [], (
        "C29: every UIA read tool's published description must document the "
        f"`state_receipt` return in BOTH variants; missing: {missing}"
    )
