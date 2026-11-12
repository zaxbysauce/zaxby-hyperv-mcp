"""Issue #140 acceptance checks: the UIA state-receipt verification channel
for the #126 console commit guard.

Authored BEFORE the fix exists (arm's-length check author, trace
140-126-uia-state-receipt): these tests are the frozen contract the
implementation must satisfy. The four UIA read verbs mint a state-read
receipt (id + seq in the existing per-VM input ledger) and return its id; a
`commit_guard` click accepts `verified_state_receipt=<id>` as an ALTERNATIVE
to `verified_frame_hash`, with freshness = receipt seq later than the VM's
last input seq in the same ledger.

Frozen result-shape decision (the implementer must obey): the read-verb
result key carrying the receipt id is `state_receipt` (a non-empty string).
The id's length/charset is deliberately NOT pinned — an unknown-format id is
simply refused as an unknown citation. Every positively-cited id in these
tests is one a fake-transport read RETURNED; only the deliberately
never-minted sentinels are fabricated.

Pinned refusal tokens (mirroring the frame-hash channel's family; recorded in
the acceptance table): unknown/evicted/neither-citation refusals carry
"unverified" (the commit_unverified family), the stale refusal "stale", the
receipt-without-guard refusal "requires commit_guard", the PRR-015 parity
refusal "x/y"; a BOTH-channels click refuses naming "verified_state_receipt".
The sequence step grammar stays frame-hash-only (assumption A1): a step dict
carrying "verified_state_receipt" is a step-indexed ValueError, never a
silently ignored key.

Transport: the FakePS folded stub from tests/unit/test_console_commit_guard.py
(per-name GUID table added so two VMs resolve to two ledger identities) and
the uia._pipe_request seam pinned by tests/unit/test_f05_uia_helper.py (the
mutating-verb lease gate is neutralized after test_f05_interactive_helper.py's
monkeypatch pattern). No frozen check takes a guard live capture — the
receipt channel has no pixel domain — so FakePS serves no capture branch. No
live host, no sleeps; the ledger is reset around every test.

Expected on the PRE-FIX tree: every test fails on the missing surface —
AssertionError naming `state_receipt` where a mint is asserted first, TypeError
"unexpected keyword argument" where the click's `verified_state_receipt`
parameter is the first missing surface, "DID NOT RAISE" for the sequence
step-key refusal — never on collection.
"""

import json
import re
from functools import partial

import pytest

from hyperv_mcp import auditlog, console, pswindows, uia
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError
from hyperv_mcp.credentials import CredentialSet

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
GUID_B = "0f2d81b6-4c31-4a9e-9d57-2b6c8f01a3de"  # vm-b's identity (C11)
CRED = CredentialSet("tester", "placeholder-pass")
NEVER_MINTED = "state-receipt-never-minted"

FRAME_W, FRAME_H = 320, 240  # 4:3, same aspect as the fake 1024x768 head


def _folded_position(script: str, head: tuple[int, int]) -> tuple[int, int] | None:
    """The head-space position a folded positional-mouse script computes,
    after the #126 suite's helper but against a configurable head."""
    x = y = fw = fh = 0
    seen = False
    for line in script.splitlines():
        ls = line.strip()
        for name in ("$x", "$y", "$fw", "$fh"):
            if ls.startswith(name + " ="):
                raw = ls.split("=", 1)[1].strip()
                if raw.lstrip("-").isdigit():
                    val = int(raw)
                    seen = True
                    if name == "$x":
                        x = val
                    elif name == "$y":
                        y = val
                    elif name == "$fw":
                        fw = val
                    else:
                        fh = val
    if not seen:
        return None
    if fw or fh:
        hx = round(x * head[0] / fw) if fw else x
        hy = round(y * head[1] / fh) if fh else y
    else:
        hx, hy = x, y
    return max(0, min(hx, head[0] - 1)), max(0, min(hy, head[1] - 1))


class FakePS:
    """Folded-transport stub after tests/unit/test_console_commit_guard.py's
    FakePS, plus a per-name GUID table so two VMs resolve to two identities.
    No capture branch: no frozen check takes a guard live capture."""

    def __init__(self, head=(1024, 768), guids=None):
        self.scripts = []
        self.head = head
        self.guids = dict(guids or {})

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            m = re.search(r"-eq '([^']*)'", script)
            name = m.group(1) if m else ""
            item = pswindows.PSResult(stdout=self.guids.get(name, GUID), returncode=0)
        elif "SetAbsolutePosition" in script:
            pos = _folded_position(script, self.head)
            lines = []
            if pos is not None:
                lines.append("HEADX=" + str(pos[0]))
                lines.append("HEADY=" + str(pos[1]))
            lines.append("RC=0")
            item = pswindows.PSResult(stdout="\n".join(lines), returncode=0)
        elif "RC=" in script or "CHUNK" in script or "DOWN" in script:
            item = pswindows.PSResult(stdout="RC=1 CHUNK=1/1", returncode=0)
        else:
            item = pswindows.PSResult(stdout="", returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


_HELPER_SESSION = {"session_id": 2, "interactive_user": "tester", "locked": False}


def _ok_frame() -> dict:
    """A successful helper response frame (an answered read with elements)."""
    return {
        "ok": True,
        "result": {"elements": [{"name": "File", "control_type": "MenuItem"}]},
        "session": dict(_HELPER_SESSION),
    }


def _fail_frame() -> dict:
    """A helper error frame (ok False): a failed read attests nothing."""
    return {
        "ok": False,
        "error_class": "helper_error",
        "error": "the helper frame exploded",
        "session": dict(_HELPER_SESSION),
    }


class PipeStub:
    """uia._pipe_request stand-in (the module's fake helper transport, after
    the seam pinned in tests/unit/test_f05_uia_helper.py): records every verb
    request and serves one canned helper frame."""

    def __init__(self, frame: dict):
        self.requests = []
        self.frame = frame

    def __call__(self, cfg, vm, cred, request):
        self.requests.append(request)
        return dict(self.frame)


class SeqPS:
    """Recording run_ps stub answering the folded sequence leg with the
    frozen success protocol, after the #126 sequence suite's SeqPS."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(stdout="VMID=" + GUID + "\nEPOCH=4242\nSTEP=0 OK=1\n", returncode=0)


def _mint_receipt(cfg, vm_name: str) -> str:
    """One fake-transport UIA read; returns the receipt id it minted. The
    assertion names the frozen result key so the PRE-FIX tree fails on the
    missing read surface itself."""
    out = uia.find(cfg, vm_name, CRED, {"automation_id": "File"})
    rid = out.get("state_receipt")
    assert isinstance(rid, str) and rid, (
        "issue #140 AC1: the UIA read must mint a state-read receipt and "
        "return its id as `state_receipt` (a non-empty string)"
    )
    return rid


def _guarded_receipt_click(cfg, vm_name: str, rid: str, **extra):
    """The canonical subject of these checks: a guarded click with x/y at the
    standard frame size, citing a state receipt."""
    return console.click(
        cfg,
        vm_name,
        160,
        120,
        frame_width=FRAME_W,
        frame_height=FRAME_H,
        commit_guard=True,
        verified_state_receipt=rid,
        **extra,
    )


def _assert_no_mouse(fake) -> None:
    assert not any("ClickButton" in s for s in fake.scripts), (
        "a refused guarded click must dispatch no mouse click"
    )
    assert not any("SetAbsolutePosition" in s for s in fake.scripts), (
        "a refused guarded click must dispatch no positional script"
    )


def _ui_transport(monkeypatch, frame: dict | None = None, **fake_kw) -> FakePS:
    """Wire the UIA fake helper transport + the console folded stub; returns
    the FakePS recorder for zero-input assertions."""
    fake = FakePS(**fake_kw)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(uia, "_pipe_request", PipeStub(frame or _ok_frame()))
    return fake


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


@pytest.fixture(autouse=True)
def _clean_ledger():
    """Reset the module's ledger family around every test (the #126 suites'
    isolation discipline; reset must also forget receipts, pinned by C8)."""
    console.reset_input_ledger()
    yield
    console.reset_input_ledger()


# C1 (#140 AC1): every read verb mints and returns a state receipt


def test_uia_read_mints_receipt(monkeypatch, unrestricted):
    # AC1 (140): each of the four read verbs, through the module's fake
    # helper transport, records a receipt and returns its id.
    fake = _ui_transport(monkeypatch)
    pipe = uia._pipe_request
    reads = [
        ("find", partial(uia.find, unrestricted, "vm1", CRED, {"automation_id": "File"})),
        ("inspect", partial(uia.inspect, unrestricted, "vm1", CRED, {"name": "Desktop"})),
        ("wait_for", partial(uia.wait_for, unrestricted, "vm1", CRED, {"name": "OK"}, timeout_s=5)),
        ("session_state", partial(uia.session_state, unrestricted, "vm1", CRED)),
    ]
    for name, call in reads:
        out = call()
        assert out.get("ok") is True, f"the {name} read must succeed first"
        rid = out.get("state_receipt")
        assert isinstance(rid, str) and rid, (
            f"issue #140 AC1: the {name} read must mint and return a non-empty `state_receipt` id"
        )
    assert len(pipe.requests) == 4, "each read verb must drive the transport"
    assert fake.scripts, "the reads must resolve their VM through the transport"


# C2 (AC1/A2 negatives): mutating verbs and failed reads mint nothing citable


def test_mutating_and_failed_reads_mint_nothing_citable(monkeypatch, unrestricted):
    # A2: only SUCCESSFUL reads mint. A mutating verb (invoke) and a failed
    # read (helper error envelope ok False) return nothing citable; citing a
    # never-minted id is refused as an unknown citation and sends no input.
    fake = _ui_transport(monkeypatch)
    monkeypatch.setattr(uia, "_shared_mutation_gate", lambda *a, **k: None)
    pipe = uia._pipe_request
    invoked = uia.invoke(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert invoked.get("ok") is True
    assert "state_receipt" not in invoked, "a MUTATING verb must not mint"
    pipe.frame = _fail_frame()
    failed = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert failed.get("ok") is False
    assert "state_receipt" not in failed, "a FAILED read must not mint"
    with pytest.raises(ConsoleError, match="unverified"):
        _guarded_receipt_click(unrestricted, "vm1", NEVER_MINTED)
    _assert_no_mouse(fake)


# C3 (#140 AC2): a fresh receipt lets the click through and is audited


def test_receipt_verified_click_allows_and_audits(monkeypatch, tmp_path):
    # AC2 (140): a guarded click citing a receipt captured after the most
    # recent input performs the click AND audits the allow decision through
    # the existing guard audit row.
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    fake = _ui_transport(monkeypatch)
    # one canonical identity for the mint, the bump and the click
    console.note_name_guid_hint("vm1", GUID)
    rid = _mint_receipt(cfg, "vm1")  # the UIA selection read (fresh)
    out = _guarded_receipt_click(cfg, "vm1", rid)
    assert out["ok"] is True and out["vm_name"] == "vm1"
    assert out["head_x"] == 512 and out["head_y"] == 384
    assert any("ClickButton" in s for s in fake.scripts), "a fresh receipt must let the click through"
    assert audit.exists(), "the allow decision must be audited"
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert len(guard_rows) == 1
    row = guard_rows[0]
    assert row["ok"] is True and row["vm_name"] == "vm1"
    assert row["category"] == "console_input"


# C4 (AC3): a receipt older than the VM's last input is stale


def test_receipt_older_than_last_input_is_stale(monkeypatch, unrestricted):
    # AC3: freshness = receipt seq later than the last input seq in the SAME
    # ledger; a receipt minted before the selecting input proves nothing and
    # refuses as stale with zero mouse input.
    fake = _ui_transport(monkeypatch)
    console.note_name_guid_hint("vm1", GUID)
    rid = _mint_receipt(unrestricted, "vm1")  # the verification read
    console.record_console_input(vm_name="vm1")  # the selecting input, AFTER
    with pytest.raises(ConsoleError, match="stale"):
        _guarded_receipt_click(unrestricted, "vm1", rid)
    _assert_no_mouse(fake)


# C5 (AC4): an unknown (never-minted) receipt citation refuses


def test_unknown_receipt_citation_refuses(monkeypatch, unrestricted):
    # AC4: refusals are structured like the frame-hash channel's — an id this
    # process never minted refuses with the commit_unverified family and no
    # mouse input (the frozen refusal token is "unverified").
    fake = _ui_transport(monkeypatch)
    with pytest.raises(ConsoleError, match="unverified"):
        _guarded_receipt_click(unrestricted, "vm1", NEVER_MINTED)
    _assert_no_mouse(fake)


# C6 (AC5): citation parameter discipline


def test_receipt_citation_parameter_discipline(monkeypatch, unrestricted):
    # AC5: neither citation, both citations, a receipt without the guard, and
    # a guarded receipt click without x/y are all structured refusals that
    # dispatch no input.
    fake = _ui_transport(monkeypatch)
    console.note_name_guid_hint("vm1", GUID)
    rid = _mint_receipt(unrestricted, "vm1")
    # (a) commit_guard with NEITHER citation
    with pytest.raises(ConsoleError, match="unverified"):
        console.click(
            unrestricted, "vm1", 160, 120, frame_width=FRAME_W, frame_height=FRAME_H, commit_guard=True
        )
    # (b) BOTH channels cited at once is an ambiguous commit — refused naming
    # the receipt parameter (a legitimately fresh frame hash is cited so the
    # refusal can only be the both-cited discipline)
    console.register_capture(
        "a" * 64,
        head_resolution=(1024, 768),
        content_rect=[0, 0, FRAME_W, FRAME_H],
        vm_name="vm1",
        frame_size=(FRAME_W, FRAME_H),
    )
    with pytest.raises((ValueError, ConsoleError), match="verified_state_receipt"):
        _guarded_receipt_click(unrestricted, "vm1", rid, verified_frame_hash="a" * 64)
    # (c) the receipt citation requires the guard (the #126 rule's parallel)
    with pytest.raises(ValueError, match="requires commit_guard"):
        console.click(
            unrestricted,
            "vm1",
            160,
            120,
            frame_width=FRAME_W,
            frame_height=FRAME_H,
            verified_state_receipt=rid,
        )
    # (d) PRR-015 parity: a click-at-current-position has no point to verify
    with pytest.raises(ValueError, match="x/y"):
        console.click(unrestricted, "vm1", commit_guard=True, verified_state_receipt=rid)
    _assert_no_mouse(fake)


# C8 (AC4/A4): reset_input_ledger forgets receipts


def test_reset_ledger_forgets_receipts(monkeypatch, unrestricted):
    # A4/test-isolation discipline: the ledger reset that clears captures and
    # input stamps must also forget minted receipts — a pre-reset receipt
    # cites nothing afterwards.
    fake = _ui_transport(monkeypatch)
    console.note_name_guid_hint("vm1", GUID)
    rid = _mint_receipt(unrestricted, "vm1")
    console.reset_input_ledger()
    with pytest.raises(ConsoleError, match="unverified"):
        _guarded_receipt_click(unrestricted, "vm1", rid)
    _assert_no_mouse(fake)


# C9 (A1): the sequence step grammar refuses the receipt key fail-closed


def test_sequence_receipt_step_key_is_refused(unrestricted, monkeypatch):
    # A1: sequences stay frame-hash-only — a click step carrying
    # `verified_state_receipt` must be a step-indexed ValueError (the key is
    # refused, never silently ignored) and dispatch nothing. The id value is
    # irrelevant to this check (the KEY is the refusal), so a placeholder is
    # cited deliberately.
    stub = SeqPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    steps = [
        {
            "action": "click",
            "x": 10,
            "y": 10,
            "frame_width": 320,
            "frame_height": 240,
            "verified_state_receipt": "receipts-have-no-sequence-channel",
        }
    ]
    with pytest.raises(ValueError) as excinfo:
        console.run_sequence(unrestricted, "vm1", steps)
    message = str(excinfo.value)
    assert "step 0" in message
    assert "verified_state_receipt" in message, "the refusal must name the refused step key"
    assert stub.scripts == [], "a refused step key must dispatch nothing"


# C11 (AC4): receipts are keyed per VM


def test_receipt_is_keyed_per_vm(unrestricted, monkeypatch):
    # The receipt registry keys on the VM identity: a receipt minted for
    # vm-a is unknown to vm-b's ledger key and refuses vm-b's guarded click.
    fake = _ui_transport(monkeypatch, guids={"vm-a": GUID, "vm-b": GUID_B})
    console.note_name_guid_hint("vm-a", GUID)
    console.note_name_guid_hint("vm-b", GUID_B)
    rid = _mint_receipt(unrestricted, "vm-a")
    with pytest.raises(ConsoleError, match="unverified"):
        _guarded_receipt_click(unrestricted, "vm-b", rid)
    _assert_no_mouse(fake)
