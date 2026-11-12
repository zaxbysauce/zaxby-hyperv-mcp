"""Issue #140 round-5 identity-domain checks (independent implementation
reviewer's EXECUTION finding, confidence 88): a false-fresh ALLOW that
survived all 41 frozen rows — authored arm's-length, round-4 files live and
manifest-frozen in tests/unit/test_console_commit_guard_uia.py / _extra.py /
_polarity.py / _coldrace.py (imported here as `frozen`, never edited).

The reviewer's public-API repro (the central binding target, C42): a receipt
minted under the GUID key while the VM's name-keyed input high-water carries a
later cold-ref bump — `record_console_input(vm_name=NAME, vm_id=NAME)` is the
exact ledger shape `_bump_input(VMRef(id=NAME, name=NAME))` stamps on the cold
by-name path (the name echoed into vm_id short-circuits the key resolution) —
was ALLOWED by a freshness leg that read only the GUID high-water. The fixed
guard compares against the MAX input seq across the identity's ledger-key
spellings (name, explicit id, hint-resolved GUID).

C43 verdict reasoning (pinned to TRUTH, not to a predetermined outcome): the
invariant is "no input dispatched after the observation may pass". In the
reverse spelling — name-keyed mint (seq 1) -> GUID-keyed bump (seq 2) -> hint
learned (migration re-keys the receipt onto the GUID PRESERVING its seq; the
input high-water already lives under the GUID) — the observation strictly
precedes the input dispatch in the ONE shared ledger order, so the citation
MUST refuse stale. Migration could only make this ALLOW by re-stamping the
receipt above the bump, and a re-stamp would FORGE freshness — the receipt's
observation genuinely happened before that input — which is exactly the
C36-pinned seq-preservation contract. Ordering note (flagged): the scenario's
"bump after the hint exists" and "then learn the hint" clauses conflict; the
literal order below bumps BEFORE the learn — the explicit vm_id short-circuits
key resolution, so the bump lands under the GUID either way, and both orders
yield stale under the same invariant.

C44 is the regression floor for the widening: the legitimate fresh flow still
ALLOWS, and the max() is scoped to the SAME VM's identity spellings — a bump
to a DIFFERENT VM (vm2) between mint and cite must NOT stale vm1's citation.

Determinism: thread-free (direct ledger calls mirroring the cold-ref call
shapes — the closest honest reproduction of the executed scenario), no sleeps
as oracles, ledger reset around every test. Mint paths (flagged per row):
C42/C44 mint through the REAL path (a faked-transport uia.find whose resolved
ref carries id=GUID); C43's name-keyed mint is unreachable publicly (a UIA
read always resolves a GUID), so it uses the internal record_state_read seam —
the same documented deviation as C14/C36. At the PRE-FIX base every row fails
on the missing receipt surface with a row-named signature (the mint legs fire
first).
"""

import json

import pytest
import test_console_commit_guard_uia as frozen

from hyperv_mcp import auditlog, console, uia
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

CRED = frozen.CRED
GUID = frozen.GUID
GUID_B = frozen.GUID_B


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


# C42 (the reviewer's reproduced scenario): hint taught -> GUID-keyed receipt
# -> a cold in-flight ref's bump lands under the NAME key -> a guarded BY-NAME
# click citing that receipt refuses stale with ZERO mouse dispatch.


def test_guid_receipt_cold_name_bump_stales_by_name_click(monkeypatch, unrestricted):
    console.note_name_guid_hint("vm1", GUID)  # a prior UIA read's entry teaching
    fake = frozen._ui_transport(monkeypatch, guids={"vm1": GUID})
    rid = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"}).get("state_receipt")
    assert isinstance(rid, str) and rid, (
        "C42: the faked-transport read must mint and return `state_receipt` "
        "under the GUID key (the real mint path — the ref resolves id=GUID)"
    )
    # The in-flight cold-ref bump, exactly as _bump_input(VMRef(id="vm1",
    # name="vm1")) records it on the cold by-name path: the name echoed into
    # vm_id short-circuits the key resolution, so the stamp lands under NAME.
    console.record_console_input(vm_name="vm1", vm_id="vm1")
    assert console._last_input_seq_for("vm1") > 0, (
        "C42: the bump must land under the NAME key (the reviewer's ledger shape)"
    )
    assert console._last_input_seq_for(GUID) == 0, (
        "C42: the reviewer's reproduced shape is name>0 guid=0 — a GUID-keyed "
        "bump here would make this row unable to discriminate the widening"
    )
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


# C43 (the symmetric domain case): the receipt is minted under the NAME key
# pre-hint, the bump lands under the GUID key, and the hint's learning
# migrates the receipt (seq preserved) onto the GUID — where the high-water
# carries the bump. Verdict per the invariant (see module docstring): STALE.


def test_name_receipt_guid_bump_migration_stales_by_name_click(monkeypatch, unrestricted):
    fake = frozen._ui_transport(monkeypatch, guids={"vm1": GUID})
    mint = getattr(console, "record_state_read", None)
    assert mint is not None, (
        "C43: the internal mint seam console.record_state_read must exist for "
        "the pre-hint NAME-keyed mint (the same documented deviation as C14/C36)"
    )
    rid = mint(vm_name="vm1")  # vm_id empty -> the casefolded NAME key (pre-hint)
    assert isinstance(rid, str) and rid, "C43: the pre-hint mint must return a receipt id"
    console.record_console_input(vm_name="vm1", vm_id=GUID)  # the GUID-keyed bump
    console.note_name_guid_hint("vm1", GUID)  # learn: receipt migrates, seq preserved
    assert console._last_input_seq_for(GUID) > 0, (
        "C43: the GUID high-water must carry the bump — the migrated receipt's "
        "own seq is pre-bump, so only the high-water can expose the dispatch"
    )
    assert console._last_input_seq_for("vm1") == 0, (
        "C43: mirrored reviewer shape with the spellings reversed (name=0 "
        "guid>0) — nothing may re-stamp the name key during migration"
    )
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


# C44 (regression floor for the widening): the legitimate fresh flow ALLOWS
# under the widened comparison — and the widening is scoped to the SAME VM's
# identity spellings: a bump to a DIFFERENT VM (vm2) between mint and cite
# must NOT stale vm1's citation (an over-broad max() mixing VMs fails here).


def test_fresh_receipt_allows_and_foreign_vm_bump_never_stales(monkeypatch, tmp_path):
    audit = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(audit))
    monkeypatch.setattr(auditlog, "_config", cfg)
    fake = frozen._ui_transport(monkeypatch, guids={"vm1": GUID, "vm2": GUID_B})
    rid = uia.find(cfg, "vm1", CRED, {"automation_id": "File"}).get("state_receipt")
    assert isinstance(rid, str) and rid, (
        "C44: the faked-transport read must mint and return `state_receipt` "
        "(the real mint path — vm1 resolves id=GUID, and NO vm1 input follows)"
    )
    console.record_console_input(vm_name="vm2", vm_id=GUID_B)  # a DIFFERENT VM's bump
    assert console._last_input_seq_for(GUID_B) > 0, (
        "C44: the vm2 bump must record between mint and cite — otherwise the "
        "foreign-identity probe below would be vacuous"
    )
    clicked = frozen._guarded_receipt_click(cfg, "vm1", rid)
    assert clicked["ok"] is True, (
        "C44: with no input dispatched to vm1 after the observation the "
        "receipt must stay FRESH — and a DIFFERENT VM's bump must never stale "
        "it (the max() is over vm1's identity spellings only)"
    )
    assert any("ClickButton" in s for s in fake.scripts), (
        "C44: the allowed guarded click must dispatch the mouse"
    )
    rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()]
    guard_rows = [r for r in rows if r.get("tool") == "console_click_commit_guard"]
    assert len(guard_rows) == 1 and guard_rows[0]["ok"] is True, (
        "C44: exactly ONE console_click_commit_guard audit row (the allow)"
    )
