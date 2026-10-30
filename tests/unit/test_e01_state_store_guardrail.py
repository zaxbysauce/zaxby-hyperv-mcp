"""Phase 4.2 guardrail for the durable-state-store defect class (issue #22).

Class: **process-local registry for state whose lifetime exceeds the process** —
a module-level dict that is the only copy of something a client holds a handle
to, so a restart strands the handle while the underlying resource keeps running.

Sixteen pins. The two phase-4.2 originals are each proven by an executed
mutation probe; the round-2/round-3 block and the PR-review block carry
their own provenance notes where a probe was run (every PR-review pin was
probed against a byte copy of the fixed source and restored with
byte-identity asserted):

1. **Restart survival.** With a live job and a live relay, reloading BOTH
   registry modules (which re-creates their module dicts, exactly as a process
   restart does) must leave both addressable. Killing this pin is removing the
   `_lookup` / `relay_status` store fallback.
2. **Schema shape.** No column in either table may be able to hold a password,
   a command, an argument list, or the relay's capability secret. Killing this
   pin is adding such a column.
"""

from __future__ import annotations

import base64
import gc
import importlib
import json
import os
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
    # Issue #30: the credential identity a job started with (never the
    # secret). '' profile = the global credential sentinel.
    "cred_profile", "cred_username",
}
_REQUIRED_RELAY_COLUMNS = {
    "relay_id", "vm_name", "vm_id", "guest_port", "bind", "host_port",
    "started_at", "state", "cred_ref", "owner",
    # Issue #30: same identity binding as the jobs table.
    "cred_profile", "cred_username",
}
# Issue #23. The fencing counter columns are named *_seq (NOT *_token)
# deliberately: "token" is a forbidden fragment, and narrowing that list to
# keep a column name would weaken a security pin for a cosmetic choice.
_REQUIRED_LEASE_COLUMNS = {
    "row_key", "lease_id", "vm_key", "vm_name", "scope", "holder_agent",
    "fencing_seq", "acquired_at", "ttl_s", "expires_at", "kind", "write_lock",
}
_REQUIRED_FENCE_COLUMNS = {"vm_key", "scope", "last_seq"}
# Issue #24. Same naming discipline: the argument fingerprint is `params_hmac`
# and the dedup key `idem_key` (never *token*/*args*), and the stored result
# is `result_json` (never *content*). Event payloads live in `data_json`.
_REQUIRED_OPS_COLUMNS = {
    "op_id", "agent", "tool", "vm_id", "vm_name", "status", "error_class",
    "created_at", "updated_at", "runner", "heartbeat_at", "cancel_requested",
    "params_hmac", "idem_key", "result_json", "result_size", "poll_interval_ms",
}
_REQUIRED_EVENT_COLUMNS = {
    "seq", "ts", "agent", "kind", "ref_id", "vm_id", "data_json",
}
_REQUIRED_META_COLUMNS = {"key", "value"}


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
        self.credentials: list[tuple[str, str]] = []
        self._actions = 0

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        self._actions += 1
        # Record the identity this leg carries: the username rides the composed
        # script as `PSCredential]::new('<user>', ...)` and the password rides
        # stdin as base64. That is what lets a check assert WHICH credential a
        # restored leg used, rather than only that a leg ran.
        user = ""
        m = re.search(r"PSCredential\]?::new\('([^']*)'", script)
        if m:
            user = m.group(1)
        secret = ""
        raw = kwargs.get("stdin_b64")
        if raw:
            secret = base64.b64decode(raw).decode("utf-8", "replace")
        self.credentials.append((user, secret))
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

    assert set(tables) >= {
        "jobs", "relays", "leases", "fence_counters", "ops", "events", "meta",
    }, sorted(tables)
    assert set(tables["jobs"]) == _REQUIRED_JOB_COLUMNS
    assert set(tables["relays"]) == _REQUIRED_RELAY_COLUMNS
    assert set(tables["leases"]) == _REQUIRED_LEASE_COLUMNS
    assert set(tables["fence_counters"]) == _REQUIRED_FENCE_COLUMNS
    assert set(tables["ops"]) == _REQUIRED_OPS_COLUMNS
    assert set(tables["events"]) == _REQUIRED_EVENT_COLUMNS
    assert set(tables["meta"]) == _REQUIRED_META_COLUMNS
    for table, columns in tables.items():
        for column in columns:
            for fragment in _FORBIDDEN_COLUMN_FRAGMENTS:
                assert fragment not in column.lower(), (
                    f"{table}.{column} could hold material the audit posture "
                    "forbids persisting"
                )


# ---------------------------------------------------------------------------
# Round-2 and round-3 implementation-review pins.
#
# Each of these pins an invariant the shipped suite did not cover when the
# reviewer's own probes found the defect. Every one is proven by an executed
# mutation probe; the probes and their outputs are recorded in
# 08a-recurrence-sweep.md.
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


def test_relay_stop_reads_stopped_under_the_registry_lock(monkeypatch, tmp_path):
    """`relay_stop` reads AND writes `stopped` inside ONE critical section.

    Reading the flag outside the lock lets two racing stops both observe
    `already=False`, which double-shuts-down, double-writes the store, and
    returns zero "was already stopped" notes — the PRR-027b invariant base
    held and frozen C13 pins behaviourally.

    The pin observes the discipline rather than the outcome: a lock wrapper
    records whether `_relays_lock` is held, and the entry records whether
    each `stopped` read AND write happened while it was. Deterministic,
    single-threaded, and it cannot pass for an unrelated reason. The count
    is deliberately NOT pinned to exactly one per kind: a correct
    implementation may re-read the flag (the guard's own finally is one
    such shape), so the pin requires every observed access to have happened
    UNDER the lock — a write moved outside the critical section is what it
    exists to kill.
    """
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    cfg = Config(
        unrestricted=True, allowed_vm_patterns=["test-*"],
        destructive={"relay": True},
    )
    credentials.init(cfg)
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "placeholder-pass")
    monkeypatch.setattr(pswindows, "run_ps", _LegFakePS({}, {}))
    started = relay.relay_start(
        cfg, "test-vm", 9405, cred=credentials.resolve_guest(),
    )
    relay_id = started["relay_id"]

    real_lock = relay._relays_lock
    held = [False]

    class _TrackingLock:
        def __enter__(self):
            real_lock.acquire()
            held[0] = True
            return self

        def __exit__(self, *exc):
            held[0] = False
            real_lock.release()

    reads: list[bool] = []
    writes: list[bool] = []

    class _TrackingEntry(dict):
        def __getitem__(self, key):
            if key == "stopped":
                reads.append(held[0])
            return super().__getitem__(key)

        def __setitem__(self, key, value):
            if key == "stopped":
                writes.append(held[0])
            super().__setitem__(key, value)

    monkeypatch.setattr(relay, "_relays_lock", _TrackingLock())
    with relay._relays_lock:
        relay._relays[relay_id] = _TrackingEntry(relay._relays[relay_id])

    stopped = relay.relay_stop(cfg, relay_id)
    assert stopped["stopped"] is True, stopped
    # Every `stopped` access — read AND write — happened with the lock held.
    assert reads, "relay_stop never read the stopped flag"
    assert all(reads), reads
    assert writes, "relay_stop never wrote the stopped flag"
    assert all(writes), writes
    # The relay row keeps the reference it was started with (R2-N5).
    from hyperv_mcp import statestore

    row = statestore.store_for(cfg).relay_get(relay_id)
    assert row is not None and row.state == statestore.RELAY_STOPPED, row
    assert row.cred_ref == "env", row


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


def test_inline_tool_argument_credential_is_not_reattachable(monkeypatch, tmp_path):
    """A per-call inline credential is NOT an environment credential.

    `resolve_guest(u, p)` with inline arguments is how an operator overrides the
    environment for ONE call. Persisting that as `cred_ref="env"` would make a
    restored job re-resolve the ENVIRONMENT identity and run guest legs as a
    different account — the silent substitution the issue's constraint and the
    README both forbid.
    """
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "env-admin")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "env-placeholder-pass")
    # allow_inline_credentials is a config key with no environment equivalent;
    # without it resolve_guest drops the inline arguments by policy.
    cfg = Config(
        unrestricted=True, allowed_vm_patterns=["test-*"],
        allow_inline_credentials=True,
    )
    credentials.init(cfg)

    inline = credentials.resolve_guest("inline-admin", "inline-placeholder-pass")
    assert inline.source == "inline", inline.source

    fake = _LegFakePS(
        start={"pid": 4242, "job_dir": "d", "start_time_ticks": 1},
        later={"status": "running"},
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    started = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=inline)
    job_id = started["job_id"]

    importlib.reload(guestjobs)
    # The environment holds a DIFFERENT identity. Reattach must refuse rather
    # than substitute it.
    with pytest.raises(credentials.CredentialError) as excinfo:
        guestjobs.job_status(cfg, job_id)
    # No substitution: the environment identity never appears in the error.
    assert "env-admin" not in str(excinfo.value)

    # The username-only dimension. `server._cred_args` takes the inline branch
    # when EITHER argument is set, and resolve_guest honours an inline username,
    # so a username-only override still starts the job as that account. Keying
    # the reference on the password source alone would label it "env" and
    # substitute the environment username after a restart.
    username_only = credentials.resolve_guest("inline-user", "")
    assert username_only.username == "inline-user", username_only
    assert username_only.source == "inline", username_only.source

    fake2 = _LegFakePS(
        start={"pid": 4243, "job_dir": "d", "start_time_ticks": 2},
        later={"status": "running"},
    )
    monkeypatch.setattr(pswindows, "run_ps", fake2)
    started2 = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=username_only)
    job_id2 = started2["job_id"]
    assert fake2.credentials, fake2.credentials
    assert fake2.credentials[0][0] == "inline-user", fake2.credentials

    importlib.reload(guestjobs)
    with pytest.raises(credentials.CredentialError):
        guestjobs.job_status(cfg, job_id2)


def test_stop_persists_the_credential_reference(monkeypatch, tmp_path):
    """A stopped row keeps the credential reference it was started with.

    The live entry carries no `cred_ref` of its own, so capturing it after the
    credential is nulled silently rewrites the persisted provenance to
    "inline". Stopped rows never re-resolve today, so the loss is invisible
    until something reads it — which is exactly why it is pinned here.
    """
    from hyperv_mcp import statestore

    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "placeholder-pass")
    cfg = Config(unrestricted=True, allowed_vm_patterns=["test-*"])
    credentials.init(cfg)
    fake = _LegFakePS(
        start={"pid": 4242, "job_dir": "d", "start_time_ticks": 1},
        later={"status": "running"},
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    started = guestjobs.job_start(
        cfg, "test-vm", "x.exe", cred=credentials.resolve_guest(),
    )
    job_id = started["job_id"]
    store = statestore.store_for(cfg)
    assert store.job_get(job_id).cred_ref == "env"

    fake.later = {"stopped": True, "alive_pids": [], "job_dir_removed": True}
    stopped = guestjobs.job_stop(cfg, job_id)
    assert stopped["stopped"] is True, stopped
    row = store.job_get(job_id)
    assert row is not None and row.state == statestore.JOB_STOPPED, row
    assert row.cred_ref == "env", row


def test_store_refuses_a_network_path(tmp_path):
    """The store must refuse a UNC path: WAL mode needs shared memory and does
    not work over a network filesystem, and a half-working store over SMB is
    worse than a clear refusal. PRR-012: the refusal names the condition
    without disclosing the host/share it names either.
    """
    from hyperv_mcp import statestore

    # Both spellings of a UNC path. The Windows form needs TWO leading
    # backslashes in the runtime string (four in source); a single leading
    # backslash is a root-relative path on the current drive, not a UNC path,
    # and must NOT be refused.
    unc_paths = ("\\\\fileserver\\share\\state.db", "//fileserver/share/state.db")
    for unc in unc_paths:
        with pytest.raises(statestore.StateStoreError) as excinfo:
            statestore.open(unc)
        message = str(excinfo.value)
        assert "network" in message.lower(), message
        assert "wal" in message.lower(), message
        # PRR-012: the UNC host/share never reaches the client envelope.
        assert "fileserver" not in message, message
        assert "share\\state.db" not in message, message
    # A single leading backslash is drive-relative, not a network path.
    assert statestore._is_unc("\\state.db") is False
    assert statestore._is_unc("C:\\hyperv-mcp\\state.db") is False
    assert statestore._is_unc(str(tmp_path / "state.db")) is False


# ---------------------------------------------------------------------------
# PR #96 swarm-review pins (PRR-002 / PRR-005 / PRR-008 / PRR-011 / PRR-012 /
# PRR-015). Every one was probed against a byte copy of the fixed source and
# restored with byte-identity asserted; each is red at the pre-fix shape.
# ---------------------------------------------------------------------------


def test_stop_refuses_an_orphaned_row_without_a_guest_leg(monkeypatch, tmp_path):
    """PRR-015: job_stop's "never taskkill PID 0" refusal. An orphaned row is
    pid 0 with an empty job_dir by construction — running _stop_script(0, "")
    would enumerate and taskkill the Win32 children of PID 0 as guest admin.
    The refusal must answer with the full-key invalid envelope and NEVER
    reach a guest leg."""
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    cfg = Config(unrestricted=True)
    credentials.init(cfg)
    from hyperv_mcp import statestore

    job_id = "0" * 32
    statestore.store_for(cfg).job_upsert(statestore.JobRow(
        job_id=job_id, vm_name="test-vm",
        vm_id="11111111-2222-3333-4444-555555555555",
        state=statestore.JOB_ORPHANED, cred_ref="env",
    ))

    def no_guest_leg(script, **kwargs):
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        raise AssertionError("an orphaned stop must never run a guest leg")

    monkeypatch.setattr(pswindows, "run_ps", no_guest_leg)
    out = guestjobs.job_stop(cfg, job_id)
    assert out["ok"] is False, out
    assert out["error_class"] == "invalid", out
    assert "no PID to stop" in out["error"], out
    assert out["stopped"] is False and out["alive_pids"] == [], out


def test_recovery_interrupts_a_populated_relays_table(monkeypatch, tmp_path):
    """PRR-015: `_recover`'s relay UPDATE had no test that ever ran it against
    a populated relays table. A fresh open of a store holding an `active`
    relay row must flip that row to `interrupted` — that flip is what makes a
    dead process's relay evictable instead of a permanent cap wedge."""
    from hyperv_mcp import statestore

    db = str(tmp_path / "state.db")
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", db)
    cfg = Config(unrestricted=True)
    store = statestore.store_for(cfg)
    relay_id = "relay-9500-recover" + "0" * 18
    store.relay_upsert(statestore.RelayRow(
        relay_id=relay_id, vm_name="test-vm",
        vm_id="11111111-2222-3333-4444-555555555555", guest_port=9500,
        state=statestore.RELAY_ACTIVE, cred_ref="env",
    ))
    # A fresh process opens the same file — recovery runs inside open().
    statestore.clear_store_cache_for_tests()
    fresh = statestore.open(db)
    try:
        row = fresh.relay_get(relay_id)
        assert row is not None and row.state == statestore.RELAY_INTERRUPTED, row
    finally:
        fresh.close()


def test_recovery_orphans_inline_rows_whose_pid_is_gone(monkeypatch, tmp_path):
    """PRR-002: recovery must demote a leftover `active` job row that can
    never re-attach — an inline-credential row, whose every restored read
    raises before a guest leg — once its recorded pid is provably no live
    process. An env/file row is NEVER demoted this way: its pid is a GUEST
    pid a host probe cannot see, and a false dead verdict would orphan a
    live peer's running job. A row that cannot be probed is left alone."""
    import subprocess
    import sys

    from hyperv_mcp import statestore

    db = str(tmp_path / "state.db")
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", db)
    cfg = Config(unrestricted=True)
    store = statestore.store_for(cfg)
    inline_id, env_id, unknown_id = "i" * 32, "e" * 32, "u" * 32
    for job_id, ref, pid in (
        (inline_id, "inline", 4242), (env_id, "env", 4242),
        (unknown_id, "inline", 7),
    ):
        store.job_upsert(statestore.JobRow(
            job_id=job_id, vm_name="test-vm",
            vm_id="11111111-2222-3333-4444-555555555555",
            pid=pid, state=statestore.JOB_ACTIVE, cred_ref=ref,
        ))

    verdicts = {"4242": False}
    real_probe = statestore._default_pid_probe
    monkeypatch.setattr(
        statestore, "_default_pid_probe",
        lambda pid: verdicts.get(str(pid)),
    )
    statestore.clear_store_cache_for_tests()
    fresh = statestore.open(db)
    try:
        assert fresh.job_get(inline_id).state == statestore.JOB_ORPHANED
        assert fresh.job_get(env_id).state == statestore.JOB_ACTIVE
        assert fresh.job_get(unknown_id).state == statestore.JOB_ACTIVE
    finally:
        fresh.close()

    # The real helper's own verdicts, pinned directly through the injectable
    # probe parameter: a process we own is alive, a process that already
    # exited is dead, and pid 0 is not probed at all.
    assert statestore._pid_is_live(0, real_probe) is None
    assert statestore._pid_is_live(0) is None
    assert statestore._pid_is_live(os.getpid(), real_probe) is True
    exited = subprocess.Popen([sys.executable, "-c", "pass"])
    exited.wait(timeout=60)
    dead_pid = exited.pid
    # Drop the Popen (and its process handle) first: on Windows an exited
    # process whose handle is still held keeps its kernel object alive, and
    # the honest probe answer for it is True, not False.
    del exited
    gc.collect()
    assert statestore._pid_is_live(dead_pid, real_probe) is False


def test_job_cap_counts_store_only_rows(monkeypatch, tmp_path):
    """PRR-015: the job cap counts the UNION with the store — a store-only
    key must count, or separate server processes collectively exceed
    _MAX_JOBS."""
    from hyperv_mcp import statestore

    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    cfg = Config(unrestricted=True)
    store = statestore.store_for(cfg)
    for i in range(2):
        store.job_upsert(statestore.JobRow(
            job_id=f"{i}" * 32, vm_name="test-vm",
            vm_id="11111111-2222-3333-4444-555555555555",
            state=statestore.JOB_ACTIVE, cred_ref="env",
        ))
    guestjobs._MAX_JOBS = 2
    try:
        with pytest.raises(RuntimeError, match="registry is full"):
            guestjobs._reserve_slot("n" * 32, None, cfg=cfg)
    finally:
        guestjobs._MAX_JOBS = 128


def test_resolve_state_db_path_honours_the_config_key(monkeypatch, tmp_path):
    """PRR-015: the config-key branch of resolve_state_db_path was
    unreachable from the suite. A directly-constructed Config naming
    state_db_path resolves to exactly that path (env var absent)."""
    from hyperv_mcp import statestore

    monkeypatch.delenv("HYPERV_MCP_STATE_DB", raising=False)
    configured = str(tmp_path / "cfg-key.db")
    cfg = Config(unrestricted=True, state_db_path=configured)
    assert statestore.resolve_state_db_path(cfg) == configured
    assert statestore.store_for(cfg).path == configured


def test_store_errors_name_the_directory_not_the_path(tmp_path):
    """PRR-012: StateStoreError messages never interpolate the absolute path
    (the profile default would disclose the local account name); they name
    the directory NAME only, matching the pswindows slot-directory posture.
    The full detail stays on the chained exception for local logs."""
    import sqlite3

    from hyperv_mcp import statestore

    newer = tmp_path / "guardrail-newer.db"
    con = sqlite3.connect(str(newer))
    try:
        con.execute(f"PRAGMA user_version = {statestore.SCHEMA_VERSION + 1}")
        con.commit()
    finally:
        con.close()
    with pytest.raises(statestore.StateStoreError) as excinfo:
        statestore.open(str(newer))
    message = str(excinfo.value)
    assert str(newer) not in message, message
    assert str(tmp_path) not in message, message
    # The refusal still names both versions (C7's clause), relative to the
    # live schema version so the pin survives forward migrations.
    assert str(statestore.SCHEMA_VERSION + 1) in message, message
    assert str(statestore.SCHEMA_VERSION) in message, message

    # The makedirs site: a FILE squatting the parent-of-the-parent slot makes
    # directory creation fail with an OSError whose __str__ embeds the FULL
    # absolute path of the directory it could not create (measured:
    # "[WinError 3] The system cannot find the path specified:
    # 'C:\\Users\\<account>\\AppData\\...\\sub'"). The message may carry the
    # directory NAME and the OSError's own text — never the path.
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory", encoding="utf-8")
    with pytest.raises(statestore.StateStoreError) as excinfo:
        statestore.open(str(blocker / "sub" / "state.db"))
    message = str(excinfo.value)
    # The FULL path is absent — not just the basename check: nothing of the
    # absolute prefix (what an account-bearing profile default would
    # disclose) and nothing of the failing directory's own path may appear.
    # OSError embeds the filename repr-escaped (quotes + DOUBLED
    # backslashes), so un-double before the substring check — a plain `in`
    # on the raw message would miss the escaped leak.
    unescaped = message.replace("\\\\", "\\")
    assert str(tmp_path) not in unescaped, message
    assert str(blocker / "sub") not in unescaped, message
    # The directory NAME is still named.
    assert "sub" in message, message
    # Local logs keep the detail: the chain still carries the original
    # OSError, whose text embeds the full path (repr-escaped by
    # OSError.__str__, so un-double before matching).
    cause = excinfo.value.__cause__
    assert isinstance(cause, OSError), cause
    assert str(blocker / "sub") in str(cause).replace("\\\\", "\\"), str(cause)


def test_open_refuses_an_embedded_nul_path_as_state_store_error(tmp_path):
    """A path carrying an embedded NUL must surface StateStoreError from the
    public open() entry. The raw header pre-read opens the file directly, and
    a NUL makes every file API raise a bare ValueError ("embedded null
    byte") that its OSError-only handler used to let escape un-enveloped."""
    from hyperv_mcp import statestore

    with pytest.raises(statestore.StateStoreError) as excinfo:
        statestore.open(str(tmp_path / "nul\0byte.db"))
    message = str(excinfo.value)
    # The refusal names the condition only — no path, no NUL echo.
    assert "\0" not in message
    assert str(tmp_path) not in message, message


def test_unattributed_caller_cannot_address_an_owned_row(monkeypatch, tmp_path):
    """PRR-008: `owner is None` used to bypass the ownership check on the
    restore paths. The store made the registry cross-process, so an
    unattributed stdio/anonymous caller must read the SAME `unknown` answer
    as a foreign agent for a row that carries an owner."""
    from hyperv_mcp import statestore

    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.db"))
    cfg = Config(unrestricted=True, allowed_vm_patterns=["test-*"],
                 destructive={"relay": True})
    credentials.init(cfg)
    store = statestore.store_for(cfg)
    job_id = "a" * 32
    relay_id = "relay-9501-owned" + "0" * 18
    store.job_upsert(statestore.JobRow(
        job_id=job_id, vm_name="test-vm",
        vm_id="11111111-2222-3333-4444-555555555555",
        pid=4242, state=statestore.JOB_ACTIVE, cred_ref="env",
        owner="agent-a",
    ))
    store.relay_upsert(statestore.RelayRow(
        relay_id=relay_id, vm_name="test-vm",
        vm_id="11111111-2222-3333-4444-555555555555", guest_port=9501,
        state=statestore.RELAY_ACTIVE, cred_ref="env", owner="agent-a",
    ))
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "placeholder-pass")
    monkeypatch.setattr(pswindows, "run_ps", _LegFakePS(
        {"status": "running"},
        {"status": "running"},
    ))
    # The unattributed principal and a foreign agent read the SAME refusal.
    with pytest.raises(ValueError, match="unknown job_id"):
        guestjobs.job_status(cfg, job_id, owner=None)
    with pytest.raises(ValueError, match="unknown job_id"):
        guestjobs.job_status(cfg, job_id, owner="agent-b")
    with pytest.raises(ValueError, match="unknown relay_id"):
        relay.relay_status(cfg, relay_id, owner=None)
    with pytest.raises(ValueError, match="unknown relay_id"):
        relay.relay_stop(cfg, relay_id, owner="agent-b")
    # The owner still addresses its own rows.
    assert guestjobs.job_status(cfg, job_id, owner="agent-a")["status"] == "running"
    row = relay.relay_status(cfg, relay_id, owner="agent-a")["relays"][0]
    assert row["state"] == "interrupted", row
