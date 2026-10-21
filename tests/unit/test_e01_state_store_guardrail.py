"""Phase 4.2 guardrail for the durable-state-store defect class (issue #22).

Class: **process-local registry for state whose lifetime exceeds the process** —
a module-level dict that is the only copy of something a client holds a handle
to, so a restart strands the handle while the underlying resource keeps running.

Two pins, both proven by mutation:

1. **Restart survival.** With a live job and a live relay, reloading BOTH
   registry modules (which re-creates their module dicts, exactly as a process
   restart does) must leave both addressable. Killing this pin is removing the
   `_lookup` / `relay_status` store fallback.
2. **Schema shape.** No column in either table may be able to hold a password,
   a command, an argument list, or the relay's capability secret. Killing this
   pin is adding such a column.
"""

from __future__ import annotations

import importlib
import json
import re
import uuid

import pytest

from hyperv_mcp import credentials, guestjobs, pswindows, relay
from hyperv_mcp.config import Config

CRED = credentials.CredentialSet("Administrator", "placeholder-pass")

_NAME_RE = re.compile(r"ElementName -eq '([^']*)'")

# Column-name fragments that would let a row carry material the audit posture
# forbids (auditlog.py: "Command content, file content and credentials are
# NEVER logged"). The store is a strictly larger surface than the log, so the
# same prohibition applies.
_FORBIDDEN_COLUMN_FRAGMENTS = (
    "password", "passwd", "secret", "token", "credential", "command",
    "argv", "args", "body", "content", "stdin", "script",
)

_REQUIRED_JOB_COLUMNS = {
    "job_id", "vm_name", "vm_id", "pid", "start_time_ticks", "job_dir",
    "out_path", "err_path", "exit_path", "started_at", "state", "cred_ref",
    "owner",
}
_REQUIRED_RELAY_COLUMNS = {
    "relay_id", "vm_name", "vm_id", "guest_port", "bind", "host_port",
    "started_at", "state", "cred_ref", "owner",
}


def _is_resolution_leg(script: str) -> bool:
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _resolved_guid(script: str) -> str:
    m = _NAME_RE.search(script)
    return str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1) if m else ""))


class _LegFakePS:
    """run_ps fake that routes by leg KIND, not by global call order.

    Identity resolution is answered by content (it is the only leg carrying
    `Msvm_ComputerSystem` and ending in `$vmTarget`), so a second VM resolve —
    the relay start's — is answered correctly however many legs precede it.
    Among the remaining legs the FIRST is the guest start (it must carry a pid)
    and every later one is a status observation.
    """

    def __init__(self, start: dict, later: dict):
        self.start = start
        self.later = later
        self.scripts: list[str] = []
        self._actions = 0

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        self._actions += 1
        payload = self.start if self._actions == 1 else self.later
        return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


@pytest.fixture(autouse=True)
def _clean_registries():
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()
    yield
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()


def test_live_job_and_relay_survive_a_registry_reload(monkeypatch, tmp_path):
    """A live job and a live relay are both addressable after a simulated
    restart. RED at base: the reload empties both registries and the follow-up
    calls raise `unknown job_id` / `unknown relay_id`."""
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    # Environment-sourced credentials, so the restored job re-resolves from the
    # same source it started with (an inline set would correctly refuse).
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "placeholder-pass")
    # A directly-constructed Config (state_db_path is None) exercises the
    # store_for() re-resolution path: the env var still names the store.
    cfg = Config(
        unrestricted=True, allowed_vm_patterns=["test-*"],
        destructive={"relay": True},
    )
    credentials.init(cfg)

    fake = _LegFakePS(
        start={"pid": 4242, "job_dir": "d", "start_time_ticks": 1},
        later={"status": "running"},
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    started = guestjobs.job_start(cfg, "test-vm", "x.exe",
                                  cred=credentials.resolve_guest())
    job_id = started["job_id"]

    relay_started = relay.relay_start(cfg, "test-vm", 9333, cred=CRED)
    relay_id = relay_started["relay_id"]

    # The restart: both module dicts are re-created empty, exactly as a fresh
    # interpreter would have them.
    importlib.reload(guestjobs)
    importlib.reload(relay)

    assert guestjobs.job_status(cfg, job_id)["status"] == "running"
    row = relay.relay_status(cfg, relay_id)["relays"][0]
    assert row["state"] == "interrupted"
    assert row["thread_alive"] is False

    # The stop must be PERSISTED, not just remembered in this process: drop the
    # local registry (a second restart) and read the row back from the store.
    # Without the store write the row still says `active`, which a restore
    # normalizes to `interrupted` — a relay the operator already stopped would
    # come back as a live duplicate and re-block its vm:guest_port.
    relay.relay_stop(cfg, relay_id)
    relay.clear_registry_for_tests()
    stopped_row = relay.relay_status(cfg, relay_id)["relays"][0]
    assert stopped_row["state"] == "stopped", stopped_row


def test_store_schema_holds_no_secret_or_command_column(tmp_path):
    """No column in either table can carry a password, a command, an argument
    list, or the relay's capability secret. RED at base: the store does not
    exist, so there is no schema to inspect."""
    import sqlite3

    from hyperv_mcp import statestore

    db = tmp_path / "state.db"
    store = statestore.open(str(db))
    store.close()

    con = sqlite3.connect(str(db))
    try:
        tables = {
            name: [row[1] for row in con.execute(f'PRAGMA table_info("{name}")')]
            for (name,) in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        con.close()

    assert set(tables) >= {"jobs", "relays"}, sorted(tables)
    assert set(tables["jobs"]) == _REQUIRED_JOB_COLUMNS
    assert set(tables["relays"]) == _REQUIRED_RELAY_COLUMNS
    for table, columns in tables.items():
        for column in columns:
            for fragment in _FORBIDDEN_COLUMN_FRAGMENTS:
                assert fragment not in column.lower(), (
                    f"{table}.{column} could hold material the audit posture "
                    "forbids persisting"
                )


# ---------------------------------------------------------------------------
# Round-2 implementation-review pins.
#
# Each of these pins an invariant the shipped suite did not cover when the
# reviewer's own probes found the defect. Every one is proven by an executed
# mutation probe (see 08a-recurrence-sweep.md).
# ---------------------------------------------------------------------------


def test_cap_eviction_never_drops_a_live_local_relay(monkeypatch, tmp_path):
    """A key present in the local registry is judged on its LOCAL stopped flag.

    A peer's `open()` flips this process's active rows to `interrupted` in the
    store, so consulting the store for a locally-present key would evict a
    relay whose listener is alive HERE — leaking the listener and the
    credential and leaving the id unaddressable.
    """
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    cfg = Config(
        unrestricted=True, allowed_vm_patterns=["test-*"],
        destructive={"relay": True},
    )
    credentials.init(cfg)
    monkeypatch.setattr(pswindows, "run_ps", _LegFakePS({}, {}))
    live = relay.relay_start(cfg, "test-vm", 9401, cred=CRED)
    relay_id = live["relay_id"]

    # Simulate a peer process opening the same store: recovery flips this
    # process's `active` row to `interrupted` in the FILE.
    from hyperv_mcp import statestore

    store = statestore.store_for(cfg)
    row = store.relay_get(relay_id)
    store.relay_upsert(statestore.RelayRow(
        **{**row.as_dict(), "state": statestore.RELAY_INTERRUPTED},
    ))

    relay._MAX_RELAYS = 1
    try:
        with pytest.raises(RuntimeError, match="relay registry is full"):
            relay.relay_start(cfg, "test-vm", 9402, cred=CRED)
        # The live relay survived, is still local, and is still stoppable.
        assert relay_id in relay._relays
        assert relay._relays[relay_id]["stopped"] is False
        stopped = relay.relay_stop(cfg, relay_id)
        assert stopped["stopped"] is True, stopped
    finally:
        relay._MAX_RELAYS = 16


def test_no_id_listing_never_discloses_a_mid_bind_relay(monkeypatch, tmp_path):
    """The no-id listing must not publish a relay that is still binding.

    During the bind window the store row exists (the reservation wrote it)
    while the local entry is an in-flight placeholder. `local_ids` is the RAW
    local key set, so the row is excluded; deriving it from the filtered
    selection would publish the id as a ghost row with a dead thread while
    by-id answered `unknown relay_id` for the very same id.
    """
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    cfg = Config(
        unrestricted=True, allowed_vm_patterns=["test-*"],
        destructive={"relay": True},
    )
    credentials.init(cfg)
    monkeypatch.setattr(pswindows, "run_ps", _LegFakePS({}, {}))
    started = relay.relay_start(cfg, "test-vm", 9403, cred=CRED)
    relay_id = started["relay_id"]

    # Recreate the mid-bind window: the placeholder is in `_relays` (so by-id
    # answers `unknown relay_id`) and its store row exists.
    with relay._relays_lock:
        relay._relays[relay_id]["in_flight"] = True
    with pytest.raises(ValueError, match="unknown relay_id"):
        relay.relay_status(cfg, relay_id)

    rows = relay.relay_status(cfg)["relays"]
    assert relay_id not in {r["relay_id"] for r in rows}, rows
    # Back out of the simulated window so teardown can stop the listener.
    with relay._relays_lock:
        relay._relays[relay_id]["in_flight"] = False
    relay.relay_stop(cfg, relay_id)


def test_relay_stop_already_flag_is_atomic(monkeypatch, tmp_path):
    """Exactly one of two racing stops performs the shutdown.

    The read and the write of `stopped` are one critical section. Reading the
    flag outside the lock lets both threads observe `already=False`, which
    double-shuts-down, double-writes the store, and returns zero
    "was already stopped" notes — the PRR-027b invariant base held.
    """
    import threading

    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    cfg = Config(
        unrestricted=True, allowed_vm_patterns=["test-*"],
        destructive={"relay": True},
    )
    credentials.init(cfg)
    monkeypatch.setattr(pswindows, "run_ps", _LegFakePS({}, {}))
    started = relay.relay_start(cfg, "test-vm", 9404, cred=CRED)
    relay_id = started["relay_id"]

    # A dict subclass that yields the moment `stopped` is READ. Under the fixed
    # code that read happens while `_relays_lock` is held, so the other thread
    # blocks and cannot interleave; under the mutant the read is outside the
    # lock, the other thread completes first, and both take the real-stop path.
    gate = threading.Event()
    proceed = threading.Event()

    class _YieldingEntry(dict):
        def __getitem__(self, key):
            if key == "stopped" and not gate.is_set():
                gate.set()
                proceed.wait(10)
            return super().__getitem__(key)

    with relay._relays_lock:
        relay._relays[relay_id] = _YieldingEntry(relay._relays[relay_id])

    results = []
    lock = threading.Lock()

    def stopper():
        r = relay.relay_stop(cfg, relay_id)
        with lock:
            results.append(r)

    first = threading.Thread(target=stopper)
    first.start()
    assert gate.wait(10), "the stop never read the stopped flag"
    second = threading.Thread(target=stopper)
    second.start()
    second.join(20)
    proceed.set()
    first.join(20)

    assert len(results) == 2, results
    assert sum(1 for r in results if "note" in r) == 1, results


def test_restored_starting_row_answers_still_starting(monkeypatch, tmp_path):
    """A `starting` row belongs to a LIVE peer's in-flight start.

    This process already ran recovery, so nothing of its own is left in that
    state. Answering it "still starting" (and never caching it) is the honest
    response; caching it instead poisons later reads, because the placeholder's
    cred_ref is "inline" by construction.
    """
    from hyperv_mcp import statestore

    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    cfg = Config(unrestricted=True)
    credentials.init(cfg)
    store = statestore.store_for(cfg)
    job_id = "a" * 32
    store.job_upsert(statestore.JobRow(
        job_id=job_id, vm_name="test-vm",
        vm_id="11111111-2222-3333-4444-555555555555",
        state=statestore.JOB_STARTING, cred_ref="inline",
    ))

    with pytest.raises(ValueError, match="still starting"):
        guestjobs.job_status(cfg, job_id)
    # Nothing was cached, so the answer is stable across reads.
    with pytest.raises(ValueError, match="still starting"):
        guestjobs.job_output(cfg, job_id)
    assert job_id not in guestjobs._jobs
