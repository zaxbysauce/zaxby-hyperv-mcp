"""Issue #151 acceptance checks: the relay kind survives a store round trip.

RED at base, GREEN after the fix (issue #151's three criteria):
  AC1 test_tcp_kind_survives_a_store_round_trip (DISCRIMINATING)
      a relay started with kind="tcp" and persisted through relay._row (the
      exact write relay_start performs at registration) must read back with
      kind "tcp" through relay_status, not the hardcoded "http".
  AC2 test_schema_v5_migration_adds_the_kind_column (DISCRIMINATING)
      a v4-era store (relays table without the kind column, user_version=4)
      must migrate forward to version 5 gaining the kind column without
      losing any relay row.
  AC3 test_a_v5_store_opens_without_remigrating (PRESERVING)
      a store already at SCHEMA_VERSION must reopen with zero migration
      lookups and its rows intact — version-parametric so it is GREEN at
      base (v4) and after the fix (v5), pinning the forward-only contract
      the issue's "why" names (a migration that runs twice would rewrite
      rows it already converted).

What is faked: nothing. Every test drives the real sqlite state store in a
per-test temp database (the conftest HYPERV_MCP_STATE_DB isolation covers the
store_for round trip; the migration tests open explicit paths). No
PowerShell leg runs: a store-only relay has no listener and relay_status
reads it through _restored_entry without touching pswindows.
"""

from __future__ import annotations

import sqlite3

import pytest

from hyperv_mcp import relay, statestore
from hyperv_mcp.config import Config, DestructivePolicy
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")

V4_RELAY_FIELDS = (
    "relay_id, vm_name, vm_id, guest_port, bind, host_port, started_at, "
    "state, cred_ref, owner, cred_profile, cred_username"
)


def _kind_cfg() -> Config:
    # The same shape tests/unit/test_relay.py's _relay_cfg uses; the
    # conftest HYPERV_MCP_STATE_DB isolation points store_for at tmp.
    return Config(
        allowed_vm_patterns=["test-*"],
        destructive=DestructivePolicy(relay=True),
    )


@pytest.fixture(autouse=True)
def _clean_registry():
    relay.clear_registry_for_tests()
    yield
    relay.clear_registry_for_tests()


def test_tcp_kind_survives_a_store_round_trip():
    """AC1: kind='tcp' in, kind='tcp' out — across the persisted row.

    The write is relay._row(entry, RELAY_ACTIVE), the same projection
    relay_start upserts at registration; the read is relay_status, whose
    store-only path rebuilds the entry through _restored_entry. RED at base
    because _restored_entry hardcodes "kind": "http" (relay.py:260 at the
    issue's anchor) and the persisted RelayRow carries no kind to recover.
    """
    cfg = _kind_cfg()
    relay_id = "relay-9443-kind" + "0" * 22
    entry = {
        # The live-entry shape relay_start registers for kind="tcp"
        # (relay.py writes "kind": kind into the entry at registration).
        "relay_id": relay_id,
        "vm_name": "test-vm",
        "vm_id": "11111111-2222-3333-4444-555555555555",
        "guest_port": 9443,
        "bind": "127.0.0.1",
        "host_port": 0,
        "started_at": "2026-01-01T00:00:00Z",
        "kind": "tcp",
        "context": {"cred": None},
        "cred_ref": "inline",
        "owner": None,
        "cred_profile": "",
        "cred_username": "",
    }
    row = relay._row(entry, statestore.RELAY_ACTIVE)
    statestore.store_for(cfg).relay_upsert(row)
    # Nothing was registered in the in-process registry, so the read below
    # is the restart path: the row, and only the row.
    reported = None
    for item in relay.relay_status(cfg, relay_id)["relays"]:
        if item["relay_id"] == relay_id:
            reported = item["kind"]
    assert reported == "tcp", (
        f"the restored entry reports kind {reported!r} for a relay started "
        "with kind='tcp'")


def test_schema_v5_migration_adds_the_kind_column(tmp_path):
    """AC2: a v4 store migrates to v5, gaining relays.kind, losing no row.

    The fixture is built with the current store, then put back into the v4
    shape (kind column dropped if the current schema has it, user_version
    stamped 4) — exactly what a 0.20.0 database looks like to 0.21.0 code.
    Issue #157 moved SCHEMA_VERSION to 6, so the precondition follows the
    chain: the 4-to-5 step must still exist and a v4 store migrates forward
    through v5 to the current version. (The original AC2 gate pinned
    SCHEMA_VERSION == 5; the Change-6 inventory re-pins it to the chain.)
    """
    if statestore.SCHEMA_VERSION < 5 or 4 not in statestore._MIGRATIONS:
        raise AssertionError(
            "the migration to version 5 does not exist (SCHEMA_VERSION is "
            f"{statestore.SCHEMA_VERSION} and _MIGRATIONS has no 4 to 5 "
            "entry)")

    db = str(tmp_path / "v4-to-v5.db")
    store = statestore.open(db)
    rows = [
        statestore.RelayRow(
            relay_id=f"relay-94{i:02d}-mig" + "0" * 22,
            vm_name="test-vm",
            vm_id=f"{i}" * 36,
            guest_port=9400 + i,
            started_at=f"2026-01-0{i}T00:00:00Z",
            state=statestore.RELAY_ACTIVE,
            cred_ref="inline",
        )
        for i in (1, 2)
    ]
    for row in rows:
        store.relay_upsert(row)
    store.close()

    con = sqlite3.connect(db)
    try:
        columns = {r[1] for r in con.execute("PRAGMA table_info(relays)")}
        if "kind" in columns:
            # Back to the v4 shape: a real v4 store has no kind column.
            con.execute("ALTER TABLE relays DROP COLUMN kind")
        con.execute("PRAGMA user_version=4")
        con.commit()
        snapshot = con.execute(
            f"SELECT {V4_RELAY_FIELDS} FROM relays ORDER BY relay_id"
        ).fetchall()
    finally:
        con.close()
    assert len(snapshot) == 2, snapshot

    reopened = statestore.open(db)
    reopened.close()

    con = sqlite3.connect(db)
    try:
        version = con.execute("PRAGMA user_version").fetchone()[0]
        columns = [r[1] for r in con.execute("PRAGMA table_info(relays)")]
        after = con.execute(
            f"SELECT {V4_RELAY_FIELDS} FROM relays ORDER BY relay_id"
        ).fetchall()
        kinds = [r[0] for r in con.execute(
            "SELECT kind FROM relays ORDER BY relay_id")]
    finally:
        con.close()
    assert version >= 5, f"a v4 store must migrate forward (>= 5, now through v6), got {version}"
    assert "kind" in columns, (
        f"the v4 -> v5 migration must add the relays.kind column; columns: "
        f"{columns}")
    # Pre-v5 rows predate the kind axis: http was the only kind that
    # existed, so every migrated row must read back as 'http'. The
    # migration supplies that value via ADD COLUMN ... DEFAULT 'http';
    # a DEFAULT of anything else would invert the disclosed semantics on
    # every legacy relay.
    assert kinds == ["http", "http"], (
        f"migrated pre-v5 relays must restore as kind 'http'; got {kinds}")
    # Issue #24's durable-operations recovery, not the migration, owns the
    # `state` field: an `active` row whose owning process is gone is
    # reclassified `interrupted` at open. The migration itself is
    # additive-only (ALTER ADD COLUMN); row preservation is asserted on the
    # identity/credential fields, and the state delta is asserted to be
    # exactly that documented recovery outcome.
    identity = tuple(range(7)) + tuple(range(8, len(V4_RELAY_FIELDS.split(","))))
    before_identity = [tuple(r[i] for i in identity) for r in snapshot]
    after_identity = [tuple(r[i] for i in identity) for r in after]
    assert len(after) == len(snapshot), (
        "the v4 -> v5 migration must not lose any relay row")
    assert after_identity == before_identity, (
        "the v4 -> v5 migration must preserve every relay row's identity "
        f"and credential fields; before={before_identity} "
        f"after={after_identity}")
    assert all(r[7] == "active" for r in snapshot), snapshot
    assert all(r[7] == "interrupted" for r in after), (
        "the open-time recovery must reclassify dead-owner active rows to "
        f"interrupted (issue #24); got {[r[7] for r in after]}")


def test_a_v5_store_opens_without_remigrating(tmp_path, monkeypatch):
    """AC3: a store already at SCHEMA_VERSION reopens migration-free.

    Version-parametric by design: at base the current version is 4, after
    the fix it is 5, and the contract is the same at both ends — reopening
    an up-to-date store consults no migration step and disturbs no row. The
    emptied _MIGRATIONS registry turns any regression that re-ran a step on
    an up-to-date store into a hard failure.
    """
    db = str(tmp_path / "at-version.db")
    canary = statestore.RelayRow(
        relay_id="relay-9443-canary" + "0" * 20,
        vm_name="test-vm",
        vm_id="9" * 36,
        guest_port=9443,
        started_at="2026-01-01T00:00:00Z",
        state=statestore.RELAY_ACTIVE,
        cred_ref="inline",
    )
    store = statestore.open(db)
    store.relay_upsert(canary)
    store.close()

    con = sqlite3.connect(db)
    stamped = con.execute("PRAGMA user_version").fetchone()[0]
    con.close()
    assert stamped == statestore.SCHEMA_VERSION, stamped

    monkeypatch.setattr(statestore, "_MIGRATIONS", {})
    reopened = statestore.open(db)
    try:
        reread = reopened.relay_get(canary.relay_id)
    finally:
        reopened.close()

    con = sqlite3.connect(db)
    restamped = con.execute("PRAGMA user_version").fetchone()[0]
    con.close()
    assert reread is not None and reread.relay_id == canary.relay_id, (
        "reopening an up-to-date store must not disturb its rows")
    assert restamped == statestore.SCHEMA_VERSION, restamped


def test_reservation_row_carries_the_requested_kind(monkeypatch):
    """A relay that dies between reservation and registration must restore
    with the kind it was started with: the RESERVATION row (written before
    the listener exists) must carry kind=kind, never a default. KILLS:
    dropping the kind= kind argument from the reservation upsert —
    AC1's round-trip arm only sees the registration row, so a reservation
    that lost its kind would pass AC1 and every row-level test alike."""
    import uuid

    from hyperv_mcp import pswindows, uia

    cfg = _kind_cfg()
    recorded: dict[str, object] = {}

    def _fake_run_ps(script, **kwargs):
        # Only the VM resolution leg runs a PowerShell script: the tcp
        # stream-capability leg is stubbed below (uia seam), and the
        # listener is stubbed before any per-request leg.
        if "Msvm_ComputerSystem" in script:
            return pswindows.PSResult(
                stdout=str(uuid.uuid5(uuid.NAMESPACE_OID, "test-vm")),
                returncode=0)
        raise AssertionError(f"unexpected run_ps leg: {script[:80]}")

    class StubTcpServer:
        def __init__(self, addr, entry):
            # The reservation transaction has committed by the time the
            # listener is built, so the placeholder row is already durable:
            # read it back through the same store handle relay_start used.
            row = statestore.store_for(cfg).relay_get(entry["relay_id"])
            recorded["kind"] = row.kind if row is not None else None
            raise OSError("stubbed bind failure")

    monkeypatch.setattr(pswindows, "run_ps", _fake_run_ps)
    # The tcp-only stream-capability probe (relay.py _require_stream_capability)
    # runs a second PS leg via uia; stub the seam so the only PS leg is the
    # resolution leg above, and the helper advertises "stream" so the tcp
    # start proceeds to the (stubbed) listener.
    monkeypatch.setattr(uia, "helper_capabilities", lambda cfg, **kwargs: ["stream"])
    monkeypatch.setattr(relay, "_TcpRelayServer", StubTcpServer)
    with pytest.raises(RuntimeError, match="could not bind"):
        relay.relay_start(cfg, "test-vm", 9222, kind="tcp", cred=CRED)
    assert recorded["kind"] == "tcp", (
        f"the reservation row must carry the requested kind 'tcp'; got "
        f"{recorded['kind']!r}")
