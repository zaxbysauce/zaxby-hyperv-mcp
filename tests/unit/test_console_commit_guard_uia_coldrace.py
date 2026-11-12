"""Issue #140 round-4 expansion checks (critic round 2, Required Revisions
2-6): the cold in-flight exclusion, the barriered post-hint pin, migration
sequence preservation, all-verb citability, direct pre-dispatch no-bump
polarity, RegistrationMismatch no-mint, and the registered-tool coercion
boundary — authored BEFORE the fix (arm's-length author; rounds 1-3 live,
manifest-frozen, in tests/unit/test_console_commit_guard_uia.py / _extra.py
/ _polarity.py — imported here as frozen/extra/polarity, never edited).

Contract bound (implementation-agnostic): a UIA read's terminal observation
and its receipt stamp are linearized against console-input dispatch on BOTH
console key namespaces the VM's identity spans — the resolved GUID console
key AND the caller-name console key — across leg+stamp, so any input
dispatch (cold name-keyed like C34's, or hinted GUID-keyed like C35's)
orders strictly against observation->stamp. C34 parks a COLD (unhinted)
name-keyed press_key mid-dispatch AFTER its ledger bump (the bump lands
under the NAME key at cold start — the hint is taught only later by the
read) and proves a read started afterwards cannot even ENTER its observation
leg until the input finishes; the read's receipt is then FRESH (observation
post-dispatch) and must allow the guarded click. C35 parks a hinted read
BETWEEN observation and stamp behind an input-attempted barrier (the
criticized C15 scheduling accident, upgraded as a NEW row) and proves the
bump cannot land inside that window; the receipt is then stale. C36 kills
seq-REFRESHING hint migration (name mint -> name input -> hint learn ->
stale). C37/C38 cite receipts returned by inspect/session_state. C39 pins
the adapter-refusal no-bump polarity at the LEG tier (a _pipe_request-entry
bump mutant stales the receipt and fails). C40 pins RegistrationMismatch
read no-mint behind a mint-once positive control. C41 binds AC25 at the
published FastMCP surface: bytes coerce through pydantic lax str and are
refused by the GUARD's unverified family; ints are rejected at the schema
boundary — disjoint acceptable sets, asserted explicitly.

Determinism disclosure (flagged in the trace notes): every positive barrier
is a deterministic Event; bounded negative waits (C34 4 s, C35 1 s) appear
only where a correct implementation PROVABLY cannot fire the event (the
excluded read holds no path to it while the input's lock is held), and no
sleep is an oracle. At the PRE-FIX tree every row fails on the missing
surface or the missing exclusion, naming its row id.
"""

import asyncio
import importlib
import json
import threading

import pytest
import test_console_commit_guard_uia as frozen
import test_console_commit_guard_uia_extra as extra
import test_console_commit_guard_uia_polarity as polarity

from hyperv_mcp import auditlog, console, pswindows, uia, vmident
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

CRED = frozen.CRED
GUID = frozen.GUID


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


# C34 (critic round 2, Critical "cold-input window"): an input already in
# flight under the COLD NAME console key before any hint exists is excluded
# from the read's observation->stamp region across the namespace transition.


def test_cold_inflight_input_excluded_from_read_region(monkeypatch, unrestricted):
    release_input = threading.Event()
    bumped = threading.Event()
    leg_entered = threading.Event()
    order: list[str] = []

    class BlockingPS(frozen.FakePS):
        """FakePS whose INPUT-DISPATCH leg (the TypeScancodes script) parks on
        release_input AFTER the op bumped — mid-dispatch, inside _input_lock."""

        def __call__(self, script, **kwargs):
            if "TypeScancodes" in script:
                self.scripts.append(script)
                if not release_input.wait(30):
                    raise AssertionError("C34: the parked input leg was never released")
                return pswindows.PSResult(stdout="RC=0 CHUNK=1/1", returncode=0)
            return super().__call__(script, **kwargs)

    class FastPipe:
        """The read's fake helper leg: signals entry, answers immediately."""

        def __call__(self, cfg, vm, cred, request):
            leg_entered.set()
            return frozen._ok_frame()

    real_input = console.record_console_input

    def spy_input(*a, **k):
        out = real_input(*a, **k)
        order.append("input")
        bumped.set()
        return out

    monkeypatch.setattr(console, "record_console_input", spy_input)
    real_mint = getattr(console, "record_state_read", None)

    def spy_mint(*a, **k):
        rid = real_mint(*a, **k) if real_mint is not None else ""
        order.append("mint")
        return rid

    monkeypatch.setattr(console, "record_state_read", spy_mint, raising=False)
    fake = BlockingPS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(uia, "_pipe_request", FastPipe())

    def run_input():  # a REAL input op, unhinted by-name: NAME-keyed console lock
        try:
            console.press_key(unrestricted, "vm1", "enter")
        except Exception:
            pass  # the oracle is the ledger order, not the op's own result

    inp = threading.Thread(target=run_input)
    inp.start()
    assert bumped.wait(20), "C34: the input dispatch never bumped — the parked-leg construction failed"

    holder: dict = {}

    def run_read():  # starts AFTER the bump is recorded and the leg is parked
        holder["out"] = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})

    reader = threading.Thread(target=run_read)
    reader.start()
    assert not leg_entered.wait(4.0), (
        "C34: the read's observation leg RAN while the cold NAME-keyed input "
        "was still parked mid-dispatch — the read region must hold the "
        "caller-name console-key exclusion too (AC15's cold in-flight case; "
        "a design that skips the name key lets the read stamp against a "
        "pre-observation input)"
    )
    assert order == ["input"], f"C34: no stamp may land while the input leg is parked (order {order})"
    release_input.set()
    inp.join(30)
    reader.join(30)
    assert not inp.is_alive() and not reader.is_alive(), "C34: both threads must finish"
    rid = (holder.get("out") or {}).get("state_receipt")
    assert isinstance(rid, str) and rid, "C34: the excluded read must still mint and return `state_receipt`"
    assert "mint" in order, f"C34: the stamp must be recorded (order {order})"
    assert order.index("input") < order.index("mint"), (
        f"C34: the input bump must be ordered before the stamp — unconditional (order {order})"
    )
    clicked = frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    assert clicked["ok"] is True, (
        "C34: the observation happened AFTER the input dispatched — the "
        "receipt must be FRESH and allow the by-name guarded click"
    )
    assert any("ClickButton" in s for s in fake.scripts), "C34: the fresh receipt must let the click through"


# C35 (critic round 2, Critical "C15 does not establish that its input was
# blocked"): a HINTED read parked BETWEEN observation and stamp; the input's
# attempt is barriered, its bump provably withheld while parked, and the
# stamp-before-bump ordering asserted UNCONDITIONALLY.


def test_barriered_post_hint_input_blocked_until_stamp(monkeypatch, unrestricted):
    console.note_name_guid_hint("vm1", GUID)
    stamp_reached = threading.Event()
    proceed = threading.Event()
    input_attempted = threading.Event()
    bumped = threading.Event()
    order: list[str] = []

    class FastPipe:  # observation completes immediately; the park is the stamp
        def __call__(self, cfg, vm, cred, request):
            return frozen._ok_frame()

    real_input = console.record_console_input

    def spy_input(*a, **k):
        out = real_input(*a, **k)
        order.append("bump")
        bumped.set()
        return out

    monkeypatch.setattr(console, "record_console_input", spy_input)
    real_mint = getattr(console, "record_state_read", None)

    def spy_mint(*a, **k):
        stamp_reached.set()  # observation done, stamp pending: the parked region
        if not proceed.wait(30):
            raise AssertionError("C35: the parked stamp region was never released")
        rid = real_mint(*a, **k) if real_mint is not None else ""
        order.append("stamp")
        return rid

    monkeypatch.setattr(console, "record_state_read", spy_mint, raising=False)
    fake = frozen.FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(uia, "_pipe_request", FastPipe())

    holder: dict = {}

    def run_read():
        holder["out"] = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})

    reader = threading.Thread(target=run_read)
    reader.start()
    assert stamp_reached.wait(10), (
        "C35: the read never reached its stamp (observation done, stamp "
        "pending) — the mint surface is missing"
    )

    before = console._last_input_seq_for(GUID)

    def run_input():  # the input-attempted barrier, set immediately pre-call
        input_attempted.set()
        try:
            console.press_key(unrestricted, "vm1", "enter")
        except Exception:
            pass

    inp = threading.Thread(target=run_input)
    inp.start()
    assert input_attempted.wait(10), "C35: the input thread never started"
    assert not bumped.wait(1.0), (
        "C35: the input's bump LANDED while the read was parked between "
        "observation and stamp — the read region must exclude console input "
        "across the stamp (AC15)"
    )
    assert console._last_input_seq_for(GUID) == before, (
        f"C35: the ledger moved while the read was parked ({before} -> {console._last_input_seq_for(GUID)})"
    )
    assert not any("TypeScancodes" in s for s in fake.scripts), (
        "C35: the input's dispatch script EXECUTED while the read was parked"
    )
    proceed.set()
    reader.join(30)
    inp.join(30)
    assert not reader.is_alive() and not inp.is_alive(), "C35: both threads must finish"
    rid = (holder.get("out") or {}).get("state_receipt")
    assert isinstance(rid, str) and rid, "C35: the parked read must still mint and return `state_receipt`"
    assert "stamp" in order and "bump" in order, f"C35: both events must be recorded (order {order})"
    assert order.index("stamp") < order.index("bump"), (
        f"C35: the stamp must precede the input bump — UNCONDITIONAL, no scheduling accident (order {order})"
    )
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


# C36 (critic round 2, Important "C14 proves migration lookup, not sequence
# preservation"): a seq-REFRESHING migration mutant would re-stamp the name
# minted receipt above the name-keyed input bump and wrongly allow the click.


def test_migration_preserves_receipt_sequence_stale_after_learn(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch)
    rid = console.record_state_read(vm_name="vm1")  # NAME key (internal seam, C14)
    assert isinstance(rid, str) and rid, "C36: record_state_read must return the minted id"
    console.record_console_input(vm_name="vm1")  # the name bump, AFTER the mint
    console.note_name_guid_hint("vm1", GUID)  # learn/migrate (name -> GUID)
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


# C37/C38 (critic round 2, Unwired "no row proves an inspect or session_state
# receipt is registered and citable"): positive guarded-click citations.


def _citable_allow(cfg, fake, out, row: str, verb: str, audit):
    rid = out.get("state_receipt")
    assert isinstance(rid, str) and rid, (
        f"{row}: the {verb} read must mint and return a non-empty "
        f"`state_receipt` id (a wrong implementation could mint only find)"
    )
    clicked = frozen._guarded_receipt_click(cfg, "vm1", rid)
    assert clicked["ok"] is True, (
        f"{row}: a receipt returned by {verb} must be citable on a guarded by-name click"
    )
    assert any("ClickButton" in s for s in fake.scripts), f"{row}: the allowed click must dispatch"
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert len(guard_rows) == 1 and guard_rows[0]["ok"] is True, (
        f"{row}: exactly ONE console_click_commit_guard audit row (the allow)"
    )


def test_inspect_receipt_citable_on_guarded_click(monkeypatch, tmp_path):
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    fake = frozen._ui_transport(monkeypatch)
    out = uia.inspect(cfg, "vm1", CRED, {"name": "Desktop"})
    assert out.get("ok") is True, "the fake transport must serve inspect"
    _citable_allow(cfg, fake, out, "C37", "inspect", audit)


def test_session_state_receipt_citable_on_guarded_click(monkeypatch, tmp_path):
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    fake = frozen._ui_transport(monkeypatch)
    out = uia.session_state(cfg, "vm1", CRED)
    assert out.get("ok") is True, "the fake transport must serve session_state"
    _citable_allow(cfg, fake, out, "C38", "session_state", audit)


# C39 (critic round 2, Required Revision 5): a DIRECT adapter refusal never
# dispatches, so it must NOT bump — a bump placed at _pipe_request entry
# stales the prior receipt and fails this row (LEG tier keeps the gate real).


def test_adapter_refused_mutation_does_not_bump(monkeypatch, unrestricted):
    fake = extra._ui_leg_transport(monkeypatch, gate=True)
    rid = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"}).get("state_receipt")
    assert isinstance(rid, str) and rid, (
        "C39: the fresh read must mint `state_receipt` before the adapter-refusal leg"
    )
    try:
        out = uia.invoke(unrestricted, "vm1", CRED, {"automation_id": "File"}, adapter="electron")
    except TypeError as exc:  # invoke never grew the parameter: the raise IS
        # the pre-forward refusal; drive the same dispatch layer directly
        assert "adapter" in str(exc), "C39: the only acceptable TypeError is the missing adapter parameter"
        ref = vmident.VMRef(id=GUID, name="vm1")
        out = uia._verb_request(
            unrestricted, ref, CRED, "invoke", {}, selector={"automation_id": "File"}, adapter="electron"
        )
    assert out.get("ok") is False and out.get("error_class") == "adapter_unapproved", (
        "C39: the adapter-gated mutating verb must refuse BEFORE any forward"
    )
    clicked = frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    assert clicked["ok"] is True, (
        "C39: an adapter refusal (never dispatched) must NOT bump the input "
        "ledger — the prior receipt stays fresh and citable"
    )
    assert any("ClickButton" in s for s in fake.scripts), (
        "C39: the still-fresh receipt must let the click through"
    )


# C40 (critic round 2, Required Revision 5): a RegistrationMismatch read
# mints NOTHING. Seeded via the public uia.register_helper (a mismatched
# target_guid), driven through the real verb layer at the LEG tier; a
# mint-once positive control makes the zero-mint leg non-vacuous.


def test_registration_mismatch_read_mints_nothing(monkeypatch, unrestricted):
    real_mint = getattr(console, "record_state_read", None)
    mints: list[dict] = []

    def spy_mint(*a, **k):
        mints.append(k)
        return real_mint(*a, **k) if real_mint is not None else ""

    monkeypatch.setattr(console, "record_state_read", spy_mint, raising=False)
    polarity._wire_leg(monkeypatch, quser=polarity._QUSER_SESSION)
    ok_out = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert ok_out.get("ok") is True, "C40 control: the plain read must succeed first"
    assert len(mints) == 1, (
        "C40 control: one successful read must mint exactly once via "
        f"console.record_state_read (observed {len(mints)}) — without it the "
        "mismatch leg's zero-mint pin below would be vacuous"
    )
    uia.register_helper(  # replaces (GUID, 2): target_guid now MISMATCHES
        vm_guid=GUID,
        user_sid="S-1-5-21-control",
        session_id=2,
        capabilities={"uia"},
        target_guid="22222222-2222-2222-2222-222222222222",
    )
    with pytest.raises(uia.RegistrationMismatch):
        uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert len(mints) == 1, (
        "C40: a RegistrationMismatch read must mint NOTHING — the stamp may "
        f"not land before the registration validates (observed {len(mints)}); "
        "the mismatch read raised, so no result envelope can carry "
        "`state_receipt` either"
    )


# C41 (critic round 2, Required Revision 6 / AC25 at the published surface):
# truthy BYTES coerce through pydantic lax str, reach console.click as text,
# and are refused by the GUARD's unverified family; a truthy INT is rejected
# at the schema boundary and never forwarded. The acceptable sets are
# DISJOINT and asserted explicitly; neither probe may crash the surface
# (a follow-up string citation still forwards) or dispatch any mouse input.


def test_registered_click_nonstring_receipt_coercion(monkeypatch):
    import hyperv_mcp.server as server_module

    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_UNRESTRICTED": "1"})
    try:
        fake = frozen.FakePS()
        monkeypatch.setattr(pswindows, "run_ps", fake)
        seen: list[dict] = []
        refusals: list[Exception] = []
        real_click = console.click

        def spy_click(cfg, *args, **kwargs):
            seen.append(kwargs)
            try:
                return real_click(cfg, *args, **kwargs)
            except Exception as exc:
                refusals.append(exc)
                raise

        monkeypatch.setattr(console, "click", spy_click)

        def call(receipt):  # neither probe may crash the registered surface
            args = {
                "vm_name": "vm1",
                "x": 160,
                "y": 120,
                "frame_width": frozen.FRAME_W,
                "frame_height": frozen.FRAME_H,
                "button": 1,
                "commit_guard": True,
                "verified_state_receipt": receipt,
            }
            try:
                asyncio.run(mod.get_mcp().call_tool("hyperv_console_click", args))
            except Exception:
                pass  # the oracle is the spy + refusal record, not the envelope

        forwarded_guard_refusal = "forwarded-and-guard-refused"
        schema_rejected = "schema-rejected-at-boundary"
        # The acceptable outcome sets are DISJOINT by construction.
        assert {forwarded_guard_refusal}.isdisjoint({schema_rejected})

        def probe(receipt) -> str:
            before = len(seen)
            call(receipt)
            return forwarded_guard_refusal if len(seen) > before else schema_rejected

        bytes_outcome = probe(b"0" * 32)  # (a) truthy bytes
        assert bytes_outcome == forwarded_guard_refusal, (
            "C41(a): the registered click must ACCEPT the bytes citation at "
            "the schema boundary (pydantic lax str coerces bytes to text) and "
            "let console.click — the GUARD — refuse it; the value never "
            "reached console.click"
        )
        coerced = seen[0].get("verified_state_receipt")
        assert isinstance(coerced, str) and coerced == "0" * 32, (
            f"C41(a): bytes must coerce to the 32-char text '0'*32, got {coerced!r}"
        )
        assert any("unverified" in str(exc) for exc in refusals), (
            "C41(a): the coerced unknown receipt must refuse in the structured commit_unverified family"
        )
        int_outcome = probe(123)  # (b) truthy int
        assert int_outcome == schema_rejected, (
            "C41(b): an int citation must be rejected at the schema boundary "
            "— the registered surface may NOT forward a non-string receipt"
        )
        assert bytes_outcome != int_outcome, "C41: the (a)/(b) outcomes must land in DISJOINT acceptable sets"
        call("a" * 64)  # (c) the surface still answers after both probes
        assert len(seen) == 2, (
            "C41(c): a well-formed string citation must still forward after "
            "the bytes/int probes — neither probe may crash the surface"
        )
        frozen._assert_no_mouse(fake)
    finally:
        importlib.reload(server_module)
