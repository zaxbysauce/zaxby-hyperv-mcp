"""Durable state store for guest jobs and host-to-guest relays (issue #22).

Both registries used to be module-level dicts whose only copies lived in process
memory, so a server restart — a stdio client restart is enough — made every
``job_id`` and ``relay_id`` an agent held unaddressable while the guest process
and its ``%TEMP%\\hyperv-mcp-job-<id>`` directory kept running. This module is
the repo's first persistent store: a SQLite database in WAL mode holding a
*projection* of those registries.

What the store deliberately does NOT hold, and why:

* No password, no password-file content, no ``CredentialSet`` repr. The row
  carries a credential *reference* (``env``, ``file``, ``inline``) and the live
  object stays in process memory, exactly as before. Persisting a secret would
  contradict the audit posture in ``auditlog.py``.
* No command text, no argument text, no file content. Same reason.
* No relay secret. ``relay``'s capability URL secret lives in the per-relay
  context and never crosses into a row.

The registries in ``guestjobs`` and ``relay`` stay the process-local view — a
write-through cache. ``guestjobs._jobs`` and ``relay._relays`` remain real dicts
because existing tests read and poke them directly.

Concurrency: one connection per process, guarded by a reentrant lock, with
``BEGIN IMMEDIATE`` for writes and a 5 s busy timeout. Separate stdio server
processes are the normal deployment, so the store must take its writes with a
bounded wait rather than assume a single writer.

Schema versioning uses ``PRAGMA user_version``. Migrations only go forward, run
in one transaction, and a database written by a NEWER build is refused rather
than silently corrupted. This module sets version 1; Workstream E PR 2 (leases)
and PR 3 (operations) extend it through migrations.
"""

from __future__ import annotations

import builtins
import os
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config, default_state_db_path

SCHEMA_VERSION = 4
BUSY_TIMEOUT_MS = 5000

# Lease scopes (issue #23). `lifecycle` is exclusive against every other
# scope: a restore or stop invalidates all other activity on the VM.
LEASE_SCOPES = ("lifecycle", "guest_exec", "transfer", "console")

# Lease kinds. `explicit` is an agent-held lease minted by hyperv_lease_acquire
# and carried across calls by lease_id + fencing_token. `call` is the short
# per-call row vmlocks.vm_lock writes, which is what turns an in-process lock
# into an exclusion that spans processes sharing this database.
LEASE_KIND_EXPLICIT = "explicit"
LEASE_KIND_CALL = "call"

# Job lifecycle. `starting` is the reservation placeholder committed BEFORE the
# guest leg runs, so a hard kill inside the leg leaves an addressable row.
JOB_STARTING = "starting"
JOB_ACTIVE = "active"
JOB_STOPPED = "stopped"
JOB_ORPHANED = "orphaned"
JOB_STATES = (JOB_STARTING, JOB_ACTIVE, JOB_STOPPED, JOB_ORPHANED)

# Relay lifecycle. `interrupted` means the listener is gone: the process that
# owned it died, so no listener is re-bound automatically.
RELAY_ACTIVE = "active"
RELAY_STOPPED = "stopped"
RELAY_INTERRUPTED = "interrupted"
RELAY_STATES = (RELAY_ACTIVE, RELAY_STOPPED, RELAY_INTERRUPTED)

# Operation lifecycle (issue #24). The names are SEP-2663's task statuses;
# `input_required` is reserved (this server never enters it). A crash must
# surface as `failed` + error_class `interrupted` at READ time, never as a
# `working` that never ends.
OP_WORKING = "working"
OP_INPUT_REQUIRED = "input_required"
OP_COMPLETED = "completed"
OP_FAILED = "failed"
OP_CANCELLED = "cancelled"
OP_TERMINAL_STATES = (OP_COMPLETED, OP_FAILED, OP_CANCELLED)
OP_STATUSES = (OP_WORKING, OP_INPUT_REQUIRED, OP_COMPLETED, OP_FAILED, OP_CANCELLED)
#: error_class recorded when a `working` op's heartbeat lapsed (AC5).
OP_INTERRUPTED = "interrupted"

# Issue #24 agent sentinel. Ops/events rows store the caller identity as
# NOT NULL: an unattributed (stdio) caller is the empty string, never SQL
# NULL, so the (agent, tool, idem_key) UNIQUE dedup index sees one key space
# and no caller is exempt from another's ownership scope (the leases
# "unattributed never exempt" property, expressed without NULL binding).
_UNATTRIBUTED = ""

# One statement per element: executescript() implicitly COMMITs a pending
# transaction, which would make the schema and the user_version write two
# separate units and let a concurrent opener observe a half-created schema.
_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        vm_name TEXT NOT NULL DEFAULT '',
        vm_id TEXT NOT NULL DEFAULT '',
        pid INTEGER NOT NULL DEFAULT 0,
        start_time_ticks INTEGER,
        job_dir TEXT NOT NULL DEFAULT '',
        out_path TEXT NOT NULL DEFAULT '',
        err_path TEXT NOT NULL DEFAULT '',
        exit_path TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'starting'
            CHECK (state IN ('starting','active','stopped','orphaned')),
        cred_ref TEXT NOT NULL DEFAULT 'inline',
        -- Issue #30: the credential IDENTITY a job started with. cred_ref is
        -- the source KIND; these two pin the identity so a restored job can
        -- never silently re-attach under a different account. '' = pre-v4 row
        -- (no recorded identity) or a reservation placeholder.
        cred_profile TEXT NOT NULL DEFAULT '',
        cred_username TEXT NOT NULL DEFAULT '',
        owner TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS relays (
        relay_id TEXT PRIMARY KEY,
        vm_name TEXT NOT NULL DEFAULT '',
        vm_id TEXT NOT NULL DEFAULT '',
        guest_port INTEGER NOT NULL DEFAULT 0,
        bind TEXT NOT NULL DEFAULT '127.0.0.1',
        host_port INTEGER NOT NULL DEFAULT 0,
        started_at TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'active'
            CHECK (state IN ('active','stopped','interrupted')),
        cred_ref TEXT NOT NULL DEFAULT 'inline',
        -- Issue #30: same identity binding as the jobs table.
        cred_profile TEXT NOT NULL DEFAULT '',
        cred_username TEXT NOT NULL DEFAULT '',
        owner TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS leases (
        row_key      TEXT PRIMARY KEY,
        lease_id     TEXT NOT NULL,
        vm_key       TEXT NOT NULL,
        vm_name      TEXT NOT NULL DEFAULT '',
        scope        TEXT NOT NULL,
        holder_agent TEXT,
        fencing_seq  INTEGER NOT NULL DEFAULT 0,
        acquired_at  REAL NOT NULL DEFAULT 0,
        ttl_s        INTEGER NOT NULL DEFAULT 0,
        expires_at   REAL NOT NULL DEFAULT 0,
        kind         TEXT NOT NULL DEFAULT 'explicit'
            CHECK (kind IN ('explicit','call')),
        write_lock   INTEGER NOT NULL DEFAULT 1
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS leases_active ON leases(vm_key, expires_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS leases_by_id ON leases(lease_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS leases_by_name ON leases(vm_name COLLATE NOCASE)
    """,
    """
    CREATE TABLE IF NOT EXISTS fence_counters (
        vm_key   TEXT NOT NULL,
        scope    TEXT NOT NULL,
        last_seq INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (vm_key, scope)
    )
    """,
    # -- v3 (issue #24): durable operation handles, event log, metadata. ----
    # Column names avoid every guardrail-forbidden fragment (no *token* /
    # *args* / *command* / *content* substrings): the argument fingerprint is
    # `params_hmac` and the dedup key is `idem_key`, mirroring the fencing_seq
    # rename precedent. `result_json` stores the redacted envelope only.
    # The idempotency dedup is a PARTIAL unique index: rows without an
    # idempotency key (idem_key = '') must never collide with each other, so
    # the constraint applies only to keyed rows.
    """
    CREATE TABLE IF NOT EXISTS ops (
        op_id TEXT PRIMARY KEY,
        agent TEXT NOT NULL DEFAULT '',
        tool TEXT NOT NULL,
        vm_id TEXT NOT NULL DEFAULT '',
        vm_name TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'working'
            CHECK (status IN ('working','input_required','completed','failed','cancelled')),
        error_class TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        runner TEXT NOT NULL DEFAULT '',
        heartbeat_at REAL NOT NULL DEFAULT 0,
        cancel_requested INTEGER NOT NULL DEFAULT 0,
        params_hmac TEXT NOT NULL DEFAULT '',
        idem_key TEXT NOT NULL DEFAULT '',
        result_json TEXT,
        result_size INTEGER NOT NULL DEFAULT 0,
        poll_interval_ms INTEGER NOT NULL DEFAULT 2000
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ops_by_agent ON ops(agent, status)
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS ops_idem
        ON ops(agent, tool, idem_key) WHERE idem_key <> ''
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        agent TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL,
        ref_id TEXT NOT NULL DEFAULT '',
        vm_id TEXT NOT NULL DEFAULT '',
        data_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS events_by_agent ON events(agent, seq)
    """,
    """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
)

# Statement positions the forward migrations depend on. Every migration is
# SLICED from _SCHEMA_STATEMENTS, so each slice must stay coupled to the
# version it targets: the pin tuples below fail loudly the moment a statement
# is inserted, removed, or reordered anywhere the slices reach (review
# PRR-022, extended to the v3 boundary by the plan-critic F5 finding).
_SCHEMA_PIN_POSITIONS = (
    (0, "jobs"),
    (1, "relays"),
    (2, "leases"),
    (6, "fence_counters"),
    (7, "ops"),
    (10, "events"),
    (12, "meta"),
)
_V1_STATEMENTS = (2, 7)
_V3_STATEMENTS = (7, 13)

# Forward-only migrations, applied inside open()'s single BEGIN IMMEDIATE.
# Without this branch a store already at user_version 1 would never receive
# the v1 -> v2 tables: open() only created the schema when it found 0
# (issue #23 localization finding C7). Each entry is (from_version, statements).
_V2_STATEMENTS = _SCHEMA_STATEMENTS[2:7]
_V3_TABLE_STATEMENTS = _SCHEMA_STATEMENTS[7:13]
# -- v4 (issue #30): the credential identity columns. The fresh-schema CREATE
# TABLE statements already carry them; this migration is the additive ALTER
# pair-of-pairs for stores created at v3 or earlier. Same naming rule as the
# rest of the schema: no guardrail-forbidden fragments.
_V4_COLUMN_STATEMENTS = (
    "ALTER TABLE jobs ADD COLUMN cred_profile TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE relays ADD COLUMN cred_profile TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN cred_username TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE relays ADD COLUMN cred_username TEXT NOT NULL DEFAULT ''",
)
_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: _V2_STATEMENTS,
    2: _V3_TABLE_STATEMENTS,
    3: _V4_COLUMN_STATEMENTS,
}


def _tables_present(con: sqlite3.Connection) -> bool:
    """Whether the current schema's tables all exist."""
    for table in ("jobs", "relays", "leases", "fence_counters", "ops", "events", "meta"):
        present = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if present is None:
            return False
    return True


def _migrate_to(con: sqlite3.Connection, found: int) -> None:
    """Apply every forward migration from `found` up to SCHEMA_VERSION.

    Migrations are additive only: no existing column changes type, no row is
    rewritten, no index is dropped. Each step is the same CREATE ... IF NOT
    EXISTS shape as the fresh-database path, so re-running one is harmless.
    """
    version = found
    while version < SCHEMA_VERSION:
        statements = _MIGRATIONS.get(version)
        if statements is None:
            raise StateStoreError(
                f"state store schema version {version} has no migration to "
                f"{SCHEMA_VERSION}; refusing to open it"
            )
        # Review PRR-022 (asm-01): the migration content is SLICED from
        # _SCHEMA_STATEMENTS, so it must stay coupled to the version it
        # targets. The slice is valid only while the first two statements
        # are exactly the v1 tables; this pin fails loudly the moment the
        # tuple is reordered or a statement is inserted ahead of them.
        for position, table in _SCHEMA_PIN_POSITIONS:
            if "CREATE TABLE IF NOT EXISTS " + table not in _SCHEMA_STATEMENTS[position]:
                raise StateStoreError(
                    f"state store migration pin broken: schema statement "
                    f"{position} no longer creates {table}"
                )
        if len(_SCHEMA_STATEMENTS) != _V3_STATEMENTS[1]:
            raise StateStoreError(
                "state store migration pin broken: the schema tuple must hold "
                f"exactly {_V3_STATEMENTS[1]} statements at version {SCHEMA_VERSION}"
            )
        if _MIGRATIONS[1] != _V2_STATEMENTS or not _MIGRATIONS[1]:
            raise StateStoreError(
                "state store migration pin broken: the v1->v2 migration must be "
                "exactly the v2 statements (leases .. fence_counters)"
            )
        if _MIGRATIONS[2] != _V3_TABLE_STATEMENTS or not _MIGRATIONS[2]:
            raise StateStoreError(
                "state store migration pin broken: the v2->v3 migration must be "
                "exactly the v3 statements (ops .. meta)"
            )
        if _MIGRATIONS[3] != _V4_COLUMN_STATEMENTS or not _MIGRATIONS[3]:
            raise StateStoreError(
                "state store migration pin broken: the v3->v4 migration must be "
                "exactly the v4 statements (cred_profile/cred_username ALTERs)"
            )
        # The migration is additive CREATE ... IF NOT EXISTS, so it must not
        # paper over a schema that is missing the versions BELOW it: a store
        # stamped `user_version=1` with no jobs/relays tables is corrupt, and
        # stamping it 2 over that would hide the corruption behind a clean
        # version number. The required set is exactly the tables the versions
        # BELOW the current step created (plan-critic F5, extended to the
        # v3 -> v4 boundary by issue #30): the step's OWN tables are not
        # required — it creates them.
        if version == 1:
            required_below: tuple[str, ...] = ("jobs", "relays")
        elif version == 2:
            required_below = ("jobs", "relays", "leases", "fence_counters")
        else:
            required_below = (
                "jobs", "relays", "leases", "fence_counters", "ops", "events",
                "meta",
            )
        for table in required_below:
            present = con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if present is None:
                raise StateStoreError(
                    f"state store schema version {version} is missing its "
                    f"{table} table; refusing to open it"
                )
        for statement in statements:
            con.execute(statement)
        version += 1
    con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

# How long open() will keep retrying a transient SQLITE_BUSY while another
# process is creating the same database, across EVERY leg of the open (the
# WAL switch used to carry an independent budget of its own, so one call
# could block ~8x longer than any caller expects — PRR-011). Separate stdio
# server processes are the normal deployment, so first-open contention is
# expected, not exceptional.
_OPEN_BUDGET_S = 10.0
_OPEN_BACKOFF_S = 0.15


def _is_busy(exc: sqlite3.Error) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


#: Windows OpenProcess/PROCESS_QUERY_LIMITED_INFORMATION, resolved lazily so a
#: non-Windows host never touches ctypes. ERROR_INVALID_PARAMETER (87) is the
#: no-such-process answer; any other failure is an unknown, never a verdict.
_WIN_OPENPROCESS_QUERY_LIMITED = 0x1000
_WIN_ERROR_INVALID_PARAMETER = 87


def _windows_pid_probe(pid: int) -> bool | None:
    """True = a live process, False = provably none, None = cannot tell.

    Deliberately NOT ``os.kill(pid, 0)``: CPython maps signal 0 to
    CTRL_C_EVENT on Windows and calls GenerateConsoleCtrlEvent, so that call
    delivers a console Ctrl-C to the named process GROUP — it interrupts the
    caller instead of asking a question. Probing our own pid raised
    KeyboardInterrupt on CI (the runner has a console attached) and was inert
    locally (Git Bash pipes leave the process with none), which is exactly the
    kind of environment split a probe must not have.
    """
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(
        ctypes.c_uint32(_WIN_OPENPROCESS_QUERY_LIMITED), ctypes.c_int(0),
        ctypes.c_uint32(pid),
    )
    if handle:
        kernel32.CloseHandle(handle)
        return True
    error = ctypes.get_last_error()
    if error == _WIN_ERROR_INVALID_PARAMETER:
        return False
    # ERROR_ACCESS_DENIED (5) means the process exists but we may not query
    # it — alive, not dead.
    if error == 5:
        return True
    return None


def _default_pid_probe(pid: int) -> bool | None:
    """Best-effort HOST-side liveness probe. Never raises.

    True = a live process, False = provably no such process, None = cannot
    tell. POSIX signal 0 is the standard probe (ESRCH = dead, EPERM = exists
    but not ours, hence alive); Windows uses OpenProcess instead, because
    ``os.kill(pid, 0)`` there is a Ctrl-C delivery, not a query.
    """
    if pid <= 0:
        return None
    if os.name == "nt":
        try:
            return _windows_pid_probe(pid)
        except Exception:
            return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    except Exception:
        return None


def _pid_is_live(pid: int, probe=None) -> bool | None:
    """One liveness verdict through an injectable probe callable.

    Recovery needs a verdict it can act on, and the act (demoting a row) is
    destructive, so the only answers that matter are ``False`` (act) and
    everything else (leave the row alone). The probe runs inside the guard
    so a raising probe degrades to "cannot tell" instead of failing open().
    """
    if pid <= 0:
        return None
    if probe is None:
        probe = _default_pid_probe
    try:
        return probe(int(pid))
    except Exception:
        return None


class StateStoreError(RuntimeError):
    """Raised when the state store cannot be opened or is the wrong version."""


@dataclass(frozen=True)
class JobRow:
    """The persisted projection of a guest job. Never carries a secret."""

    job_id: str
    vm_name: str = ""
    vm_id: str = ""
    pid: int = 0
    start_time_ticks: int | None = None
    job_dir: str = ""
    out_path: str = ""
    err_path: str = ""
    exit_path: str = ""
    started_at: str = ""
    state: str = JOB_STARTING
    cred_ref: str = "inline"
    owner: str | None = None
    # Issue #30: the credential identity the job started with ('' = pre-v4
    # row or a reservation placeholder). Never the secret itself.
    cred_profile: str = ""
    cred_username: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "vm_name": self.vm_name,
            "vm_id": self.vm_id,
            "pid": self.pid,
            "start_time_ticks": self.start_time_ticks,
            "job_dir": self.job_dir,
            "out_path": self.out_path,
            "err_path": self.err_path,
            "exit_path": self.exit_path,
            "started_at": self.started_at,
            "state": self.state,
            "cred_ref": self.cred_ref,
            "owner": self.owner,
            "cred_profile": self.cred_profile,
            "cred_username": self.cred_username,
        }


@dataclass(frozen=True)
class RelayRow:
    """The persisted projection of a relay. Never carries the secret."""

    relay_id: str
    vm_name: str = ""
    vm_id: str = ""
    guest_port: int = 0
    bind: str = "127.0.0.1"
    host_port: int = 0
    started_at: str = ""
    state: str = RELAY_ACTIVE
    cred_ref: str = "inline"
    owner: str | None = None
    # Issue #30: the credential identity the relay started with ('' = pre-v4
    # row or a reservation placeholder). Never the secret itself.
    cred_profile: str = ""
    cred_username: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "relay_id": self.relay_id,
            "vm_name": self.vm_name,
            "vm_id": self.vm_id,
            "guest_port": self.guest_port,
            "bind": self.bind,
            "host_port": self.host_port,
            "started_at": self.started_at,
            "state": self.state,
            "cred_ref": self.cred_ref,
            "owner": self.owner,
            "cred_profile": self.cred_profile,
            "cred_username": self.cred_username,
        }


def _row_to_job(values: tuple) -> JobRow:
    return JobRow(
        job_id=str(values[0]),
        vm_name=str(values[1] or ""),
        vm_id=str(values[2] or ""),
        pid=int(values[3] or 0),
        start_time_ticks=None if values[4] is None else int(values[4]),
        job_dir=str(values[5] or ""),
        out_path=str(values[6] or ""),
        err_path=str(values[7] or ""),
        exit_path=str(values[8] or ""),
        started_at=str(values[9] or ""),
        state=str(values[10] or JOB_STARTING),
        cred_ref=str(values[11] or "inline"),
        owner=None if values[12] is None else str(values[12]),
        cred_profile=str(values[13] or ""),
        cred_username=str(values[14] or ""),
    )


def _row_to_relay(values: tuple) -> RelayRow:
    return RelayRow(
        relay_id=str(values[0]),
        vm_name=str(values[1] or ""),
        vm_id=str(values[2] or ""),
        guest_port=int(values[3] or 0),
        bind=str(values[4] or "127.0.0.1"),
        host_port=int(values[5] or 0),
        started_at=str(values[6] or ""),
        state=str(values[7] or RELAY_ACTIVE),
        cred_ref=str(values[8] or "inline"),
        owner=None if values[9] is None else str(values[9]),
        cred_profile=str(values[10] or ""),
        cred_username=str(values[11] or ""),
    )


_JOB_COLUMNS = (
    "job_id, vm_name, vm_id, pid, start_time_ticks, job_dir, out_path, "
    "err_path, exit_path, started_at, state, cred_ref, owner, "
    "cred_profile, cred_username"
)
_RELAY_COLUMNS = (
    "relay_id, vm_name, vm_id, guest_port, bind, host_port, started_at, "
    "state, cred_ref, owner, cred_profile, cred_username"
)


@dataclass(frozen=True)
class OpRow:
    """The persisted projection of a durable operation (issue #24).

    Never carries a secret: arguments live only as a keyed fingerprint
    (`params_hmac`), results only as the redacted envelope (`result_json`).
    `agent` is the caller identity with the empty-string sentinel for an
    unattributed caller, so the (agent, tool, idem_key) dedup index has one
    key space."""

    op_id: str
    tool: str
    agent: str = _UNATTRIBUTED
    vm_id: str = ""
    vm_name: str = ""
    status: str = OP_WORKING
    error_class: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    runner: str = ""
    heartbeat_at: float = 0.0
    cancel_requested: int = 0
    params_hmac: str = ""
    idem_key: str = ""
    result_json: str | None = None
    result_size: int = 0
    poll_interval_ms: int = 2000

    def as_dict(self) -> dict[str, Any]:
        return {
            "op_id": self.op_id,
            "tool": self.tool,
            "agent": self.agent,
            "vm_id": self.vm_id,
            "vm_name": self.vm_name,
            "status": self.status,
            "error_class": self.error_class,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "runner": self.runner,
            "heartbeat_at": self.heartbeat_at,
            "cancel_requested": self.cancel_requested,
            "params_hmac": self.params_hmac,
            "idem_key": self.idem_key,
            "result_json": self.result_json,
            "result_size": self.result_size,
            "poll_interval_ms": self.poll_interval_ms,
        }


def _row_to_op(values: tuple) -> OpRow:
    return OpRow(
        op_id=str(values[0]),
        agent=str(values[1] or ""),
        tool=str(values[2] or ""),
        vm_id=str(values[3] or ""),
        vm_name=str(values[4] or ""),
        status=str(values[5] or OP_WORKING),
        error_class=str(values[6] or ""),
        created_at=float(values[7] or 0.0),
        updated_at=float(values[8] or 0.0),
        runner=str(values[9] or ""),
        heartbeat_at=float(values[10] or 0.0),
        cancel_requested=int(values[11] or 0),
        params_hmac=str(values[12] or ""),
        idem_key=str(values[13] or ""),
        result_json=None if values[14] is None else str(values[14]),
        result_size=int(values[15] or 0),
        poll_interval_ms=int(values[16] or 2000),
    )


_OPS_COLUMNS = (
    "op_id, agent, tool, vm_id, vm_name, status, error_class, created_at, "
    "updated_at, runner, heartbeat_at, cancel_requested, params_hmac, "
    "idem_key, result_json, result_size, poll_interval_ms"
)


class Store:
    """One SQLite connection, serialized. Not thread-safe by SQLite's rules, so
    every method takes the lock; the lock is reentrant so a transaction helper
    can call a plain reader without deadlocking on itself."""

    def __init__(self, path: str, clock: Callable[[], float] | None = None) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._con: sqlite3.Connection | None = None
        # >0 while an explicit transaction() block owns the connection, so the
        # single-statement write helpers below do not commit it out from under
        # the caller (SQLite rejects a nested BEGIN outright).
        self._depth = 0
        # Issue #23: an injectable clock so lease TTLs are testable without
        # sleeping. Defaults to None -> time.time, because statestore.open()
        # constructs Store(path) itself and must keep working unchanged.
        # Wall clock (not monotonic) is deliberate: lease expiry is PERSISTED
        # and compared across restarts, and monotonic resets every boot.
        self._clock = clock if clock is not None else time.time

    def now(self) -> float:
        """The store's clock. Every lease comparison must go through this."""
        return float(self._clock())

    # -- lifecycle ---------------------------------------------------------

    @property
    def busy_timeout_ms(self) -> int:
        """The busy timeout THIS store's connection was configured with.

        Read through the store's own connection, not a fresh one: SQLite's
        busy timeout is per-connection, and a fresh connection reports Python's
        own default, so a raw read proves nothing about what the store set.
        """
        with self._lock:
            con = self._connect()
            return int(con.execute("PRAGMA busy_timeout").fetchone()[0])

    def _connect(self) -> sqlite3.Connection:
        if self._con is None:
            con = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
            con.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            self._con = con
        return self._con

    def close(self) -> None:
        with self._lock:
            if self._con is not None:
                try:
                    self._con.close()
                finally:
                    self._con = None

    @contextmanager
    def transaction(self) -> Iterator[Store]:
        """One write transaction: BEGIN IMMEDIATE, then COMMIT or ROLLBACK.

        BEGIN IMMEDIATE takes the write lock up front, so a second writer waits
        on the busy timeout instead of failing mid-transaction with
        "database is locked". The lock is reentrant, so plain readers may be
        called inside the block, and so may the single-statement write helpers —
        they see _depth > 0 and leave the commit to this block.
        """
        with self._lock:
            self._begin()
            self._depth += 1
            try:
                yield self
            except BaseException:
                self._depth -= 1
                self._rollback()
                raise
            self._depth -= 1
            self._commit()

    def _begin(self) -> None:
        con = self._connect()
        if not con.in_transaction:
            con.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        if self._depth > 0:
            return
        con = self._con
        if con is not None and con.in_transaction:
            con.execute("COMMIT")

    def _rollback(self) -> None:
        if self._depth > 0:
            return
        con = self._con
        if con is not None and con.in_transaction:
            try:
                con.execute("ROLLBACK")
            except sqlite3.Error:  # pragma: no cover - rollback of a dead txn
                pass

    # -- jobs --------------------------------------------------------------

    def job_upsert(self, row: JobRow) -> None:
        with self._lock:
            self._begin()
            try:
                self._connect().execute(
                    "INSERT INTO jobs (" + _JOB_COLUMNS + ") "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(job_id) DO UPDATE SET "
                    "vm_name=excluded.vm_name, vm_id=excluded.vm_id, "
                    "pid=excluded.pid, start_time_ticks=excluded.start_time_ticks, "
                    "job_dir=excluded.job_dir, out_path=excluded.out_path, "
                    "err_path=excluded.err_path, exit_path=excluded.exit_path, "
                    "started_at=excluded.started_at, state=excluded.state, "
                    "cred_ref=excluded.cred_ref, owner=excluded.owner, "
                    "cred_profile=excluded.cred_profile, "
                    "cred_username=excluded.cred_username",
                    (
                        row.job_id, row.vm_name, row.vm_id, row.pid,
                        row.start_time_ticks, row.job_dir, row.out_path,
                        row.err_path, row.exit_path, row.started_at, row.state,
                        row.cred_ref, row.owner,
                        row.cred_profile, row.cred_username,
                    ),
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise

    def job_get(self, job_id: str) -> JobRow | None:
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + _JOB_COLUMNS + " FROM jobs WHERE job_id = ?", (job_id,)
            )
            values = cur.fetchone()
        return None if values is None else _row_to_job(values)

    def job_rows(self) -> list[JobRow]:
        with self._lock:
            cur = self._connect().execute("SELECT " + _JOB_COLUMNS + " FROM jobs")
            values = cur.fetchall()
        return [_row_to_job(v) for v in values]

    def job_delete(self, job_id: str) -> None:
        with self._lock:
            self._begin()
            try:
                self._connect().execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
                self._commit()
            except BaseException:
                self._rollback()
                raise

    # -- relays ------------------------------------------------------------

    def relay_upsert(self, row: RelayRow) -> None:
        with self._lock:
            self._begin()
            try:
                self._connect().execute(
                    "INSERT INTO relays (" + _RELAY_COLUMNS + ") "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(relay_id) DO UPDATE SET "
                    "vm_name=excluded.vm_name, vm_id=excluded.vm_id, "
                    "guest_port=excluded.guest_port, bind=excluded.bind, "
                    "host_port=excluded.host_port, started_at=excluded.started_at, "
                    "state=excluded.state, cred_ref=excluded.cred_ref, "
                    "owner=excluded.owner, cred_profile=excluded.cred_profile, "
                    "cred_username=excluded.cred_username",
                    (
                        row.relay_id, row.vm_name, row.vm_id, row.guest_port,
                        row.bind, row.host_port, row.started_at, row.state,
                        row.cred_ref, row.owner,
                        row.cred_profile, row.cred_username,
                    ),
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise

    def relay_get(self, relay_id: str) -> RelayRow | None:
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + _RELAY_COLUMNS + " FROM relays WHERE relay_id = ?", (relay_id,)
            )
            values = cur.fetchone()
        return None if values is None else _row_to_relay(values)

    def relay_rows(self) -> list[RelayRow]:
        with self._lock:
            cur = self._connect().execute("SELECT " + _RELAY_COLUMNS + " FROM relays")
            values = cur.fetchall()
        return [_row_to_relay(v) for v in values]

    def relay_delete(self, relay_id: str) -> None:
        with self._lock:
            self._begin()
            try:
                self._connect().execute("DELETE FROM relays WHERE relay_id = ?", (relay_id,))
                self._commit()
            except BaseException:
                self._rollback()
                raise

    # -- leases (issue #23) ------------------------------------------------
    #
    # `row_key` is the ONLY unique column. Several rows may share the same
    # (lease_id, vm_key, scope) triple: a multi-scope acquire writes one row per
    # scope, and ONE tool call's nested vm_locks each write their own row under
    # the call's shared lease_id. Making lease_id the primary key would make all
    # three shapes impossible.
    #
    # Every method takes the lock and uses the same single-statement write
    # discipline as the job/relay helpers, so callers never have to.

    _LEASE_COLUMNS = (
        "row_key, lease_id, vm_key, vm_name, scope, holder_agent, fencing_seq, "
        "acquired_at, ttl_s, expires_at, kind, write_lock"
    )

    def lease_insert(self, values: tuple) -> str:
        """Insert one lease row; `values` is positional per _LEASE_COLUMNS."""
        with self._lock:
            self._begin()
            try:
                self._connect().execute(
                    "INSERT INTO leases (" + self._LEASE_COLUMNS
                    + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    values,
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return str(values[0])

    def lease_rows_by_id(self, lease_id: str) -> list[tuple]:
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + self._LEASE_COLUMNS + " FROM leases WHERE lease_id = ?",
                (lease_id,),
            )
            return cur.fetchall()

    def lease_candidates_by_vm(self, vm_key: str, now: float, agent: str | None) -> list[tuple]:
        """Unexpired rows for a VM, excluding the caller's OWN.

        NULL-safe on purpose: binding None to `holder_agent != ?` matches
        nothing, which would silently disable the gate for every unattributed
        (stdio) caller. `X IS ?` is SQLite's NULL-safe equality, and an
        unattributed caller gets NO benefit of the doubt -- every row is a
        candidate -- matching the pinned posture for jobs and relays.
        """
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + self._LEASE_COLUMNS + " FROM leases "
                "WHERE vm_key = ? AND expires_at > ? "
                "AND (? IS NULL OR NOT (holder_agent IS ?))",
                (vm_key, now, agent, agent),
            )
            return cur.fetchall()

    def lease_candidates_by_name(self, vm_name: str, now: float, agent: str | None) -> list[tuple]:
        """The name-hint twin of lease_candidates_by_vm (SQLite NOCASE)."""
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + self._LEASE_COLUMNS + " FROM leases "
                "WHERE vm_name = ? COLLATE NOCASE AND expires_at > ? "
                "AND (? IS NULL OR NOT (holder_agent IS ?))",
                (vm_name, now, agent, agent),
            )
            return cur.fetchall()

    def lease_rows_live(self, vm_key: str, now: float, agent: str | None) -> list[tuple]:
        """Live rows, optionally VM- and agent-scoped.

        An empty vm_key means "any VM". The agent filter uses the same NULL-safe
        shape as the candidate queries, but with `owner_visible` semantics: a
        None agent means NO filter here (the caller-level ownership checks are
        what decide who may act, not this read).
        """
        where = ["expires_at > ?"]
        params: list[Any] = [now]
        if vm_key:
            where.append("vm_key = ?")
            params.append(vm_key)
        if agent is not None:
            where.append("NOT (holder_agent IS ?)")
            params.append(agent)
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + self._LEASE_COLUMNS + " FROM leases WHERE " + " AND ".join(where),
                params,
            )
            return cur.fetchall()

    def lease_expired_by_id(self, lease_id: str, now: float) -> list[tuple]:
        """Rows for a lease id that exist but are past expiry.

        Expired rows are RETAINED, not reaped on acquire: a later renew must be
        able to report "expired" rather than "unknown", and a stale token must
        be reportable as fenced rather than silently absent.
        """
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + self._LEASE_COLUMNS + " FROM leases "
                "WHERE lease_id = ? AND expires_at <= ?",
                (lease_id, now),
            )
            return cur.fetchall()

    def lease_touch(self, row_key: str, expires_at: float) -> None:
        with self._lock:
            self._begin()
            try:
                self._connect().execute(
                    "UPDATE leases SET expires_at = ? WHERE row_key = ?", (expires_at, row_key)
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise

    def lease_touch_if_live(self, row_key: str, now: float, expires_at: float) -> int:
        """Touch ONLY a row that is still live at `now` (review PRR-009).

        Returns the number of rows updated: 0 means the row lapsed between the
        caller's read and this write, and the caller must report expiry rather
        than silently resurrect it.
        """
        with self._lock:
            self._begin()
            try:
                cur = self._connect().execute(
                    "UPDATE leases SET expires_at = ? WHERE row_key = ? AND expires_at > ?",
                    (expires_at, row_key, now),
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return int(cur.rowcount or 0)

    def fence_last_explicit(self, vm_key: str, scope: str) -> int:
        """The highest fencing token ever minted for (vm_key, scope) by an
        EXPLICIT lease (review PRR-007).

        Per-call rows bump the same counter, so a plain counter read would
        fence every lease after its holder's first tool call; only explicit
        grants -- the holder's own or a takeover's -- supersede a token."""
        with self._lock:
            cur = self._connect().execute(
                "SELECT MAX(fencing_seq) FROM leases WHERE vm_key = ? AND scope = ?"
                " AND kind = ?",
                (vm_key, scope, "explicit"),
            )
            value = cur.fetchone()[0]
        return int(value or 0)

    def lease_delete_by_id(self, lease_id: str) -> None:
        """Delete a lease's EXPLICIT rows only (review PRR-010).

        Call rows that adopted the id share it while their mutation runs;
        deleting them would strip a live call's cross-process exclusion
        mid-flight."""
        with self._lock:
            self._begin()
            try:
                self._connect().execute(
                    "DELETE FROM leases WHERE lease_id = ? AND kind = ?",
                    (lease_id, "explicit"),
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise

    def lease_delete_row(self, row_key: str) -> None:
        """Delete exactly one row -- one vm_lock's own call row."""
        with self._lock:
            self._begin()
            try:
                self._connect().execute("DELETE FROM leases WHERE row_key = ?", (row_key,))
                self._commit()
            except BaseException:
                self._rollback()
                raise

    def fence_bump(self, vm_key: str, scope: str) -> int:
        """Next fencing token for (vm_key, scope): strictly increasing and
        PERSISTED, so it survives a restart and cannot be re-issued to a stale
        holder. The first token handed out for a pair is 1, never 0."""
        with self._lock:
            self._begin()
            try:
                con = self._connect()
                con.execute(
                    "INSERT INTO fence_counters (vm_key, scope, last_seq) VALUES (?,?,0) "
                    "ON CONFLICT(vm_key, scope) DO NOTHING",
                    (vm_key, scope),
                )
                con.execute(
                    "UPDATE fence_counters SET last_seq = last_seq + 1 "
                    "WHERE vm_key = ? AND scope = ?",
                    (vm_key, scope),
                )
                value = int(
                    con.execute(
                        "SELECT last_seq FROM fence_counters WHERE vm_key = ? AND scope = ?",
                        (vm_key, scope),
                    ).fetchone()[0]
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return value

    def sweep_expired_leases(self, horizon: float) -> int:
        """Delete lease rows whose expiry is more than `horizon` in the past.

        Runs ONLY from open()'s path with the default clock, never from
        _connect/__init__: a store opened later against a session using an
        injected clock would otherwise reap that session's rows, whose
        expires_at sits far in the (real-clock) past.
        """
        with self._lock:
            self._begin()
            try:
                cur = self._connect().execute(
                    "DELETE FROM leases WHERE expires_at < ?", (horizon,)
                )
                removed = cur.rowcount
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return int(removed or 0)

    # -- ops (issue #24) ----------------------------------------------------

    def op_insert(self, row: OpRow) -> None:
        """Insert one op row. Raises StateStoreError on a duplicate op_id or a
        conflicting (agent, tool, idem_key) UNIQUE key; callers that implement
        idempotency consult find_idem FIRST inside the same transaction()."""
        with self._lock:
            self._begin()
            try:
                try:
                    self._connect().execute(
                        "INSERT INTO ops (" + _OPS_COLUMNS + ") "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            row.op_id, row.agent, row.tool, row.vm_id, row.vm_name,
                            row.status, row.error_class, row.created_at,
                            row.updated_at, row.runner, row.heartbeat_at,
                            row.cancel_requested, row.params_hmac, row.idem_key,
                            row.result_json, row.result_size, row.poll_interval_ms,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise StateStoreError(f"op insert conflict: {exc}") from exc
                self._commit()
            except BaseException:
                self._rollback()
                raise

    def op_get(self, op_id: str) -> OpRow | None:
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + _OPS_COLUMNS + " FROM ops WHERE op_id = ?", (op_id,)
            )
            values = cur.fetchone()
        return None if values is None else _row_to_op(values)

    def op_get_scoped(self, op_id: str, agent: str) -> OpRow | None:
        """Ownership-scoped read: another principal's op answers like an
        unknown id (AC8). `agent` uses the empty-string sentinel for an
        unattributed caller, so plain equality is NULL-safe by construction."""
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + _OPS_COLUMNS + " FROM ops WHERE op_id = ? AND agent = ?",
                (op_id, agent),
            )
            values = cur.fetchone()
        return None if values is None else _row_to_op(values)

    def op_find_idem(self, agent: str, tool: str, idem_key: str) -> OpRow | None:
        """The idempotency consult for (agent, tool, idem_key). Must run inside
        the caller's transaction() alongside op_insert so a concurrent retry
        cannot pass the consult and lose the insert race (BEGIN IMMEDIATE
        serializes both)."""
        with self._lock:
            cur = self._connect().execute(
                "SELECT " + _OPS_COLUMNS + " FROM ops "
                "WHERE agent = ? AND tool = ? AND idem_key = ?",
                (agent, tool, idem_key),
            )
            values = cur.fetchone()
        return None if values is None else _row_to_op(values)

    def op_rows_by_agent(
        self, agent: str, include_terminal: bool = False, limit: int = 200
    ) -> list[OpRow]:
        with self._lock:
            if include_terminal:
                cur = self._connect().execute(
                    "SELECT " + _OPS_COLUMNS + " FROM ops WHERE agent = ? "
                    "ORDER BY created_at ASC, op_id ASC LIMIT ?",
                    (agent, int(limit)),
                )
            else:
                cur = self._connect().execute(
                    "SELECT " + _OPS_COLUMNS + " FROM ops WHERE agent = ? "
                    "AND status NOT IN ('completed','failed','cancelled') "
                    "ORDER BY created_at ASC, op_id ASC LIMIT ?",
                    (agent, int(limit)),
                )
            values = cur.fetchall()
        return [_row_to_op(v) for v in values]

    def op_transition(
        self,
        op_id: str,
        from_statuses: tuple[str, ...],
        to_status: str,
        *,
        error_class: str = "",
        result_json: str | None = None,
        result_size: int = 0,
        updated_at: float,
    ) -> bool:
        """Status move guarded on the current state; False when the row is no
        longer in `from_statuses` (a lost race against cancel/recovery)."""
        placeholders = ",".join("?" for _ in from_statuses)
        with self._lock:
            self._begin()
            try:
                cur = self._connect().execute(
                    "UPDATE ops SET status = ?, error_class = ?, result_json = ?, "
                    "result_size = ?, updated_at = ? "
                    f"WHERE op_id = ? AND status IN ({placeholders})",
                    (to_status, error_class, result_json, int(result_size),
                     float(updated_at), op_id, *from_statuses),
                )
                moved = cur.rowcount
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return bool(moved)

    def op_heartbeat(self, op_id: str, at: float) -> None:
        with self._lock:
            self._begin()
            try:
                self._connect().execute(
                    "UPDATE ops SET heartbeat_at = ?, updated_at = ? WHERE op_id = ?",
                    (float(at), float(at), op_id),
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise

    def op_delete(self, op_id: str) -> None:
        """Remove one op row (the idempotency-TTL expiry retires its record so
        a fresh retry can insert under the same (agent, tool, idem_key))."""
        with self._lock:
            self._begin()
            try:
                self._connect().execute("DELETE FROM ops WHERE op_id = ?", (op_id,))
                self._commit()
            except BaseException:
                self._rollback()
                raise

    def ops_prune(self, older_than: float) -> int:
        """Retention: delete TERMINAL op rows (with their result payloads)
        whose created_at is older than the cutoff. Working rows are never
        swept here — a live detached op's row is owned by its runner; stale
        ones are failed at read time and retire on the next retention pass."""
        with self._lock:
            self._begin()
            try:
                cur = self._connect().execute(
                    "DELETE FROM ops WHERE created_at < ? AND status IN "
                    "('completed','failed','cancelled')",
                    (float(older_than),),
                )
                removed = int(cur.rowcount or 0)
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return removed

    def op_request_cancel(self, op_id: str, agent: str, at: float) -> int:
        """Record a cooperative cancel request. Ownership-scoped like every
        read: another principal's op_id is simply not found (0 rows)."""
        with self._lock:
            self._begin()
            try:
                cur = self._connect().execute(
                    "UPDATE ops SET cancel_requested = 1, updated_at = ? "
                    "WHERE op_id = ? AND agent = ?",
                    (float(at), op_id, agent),
                )
                moved = cur.rowcount
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return int(moved or 0)

    # -- events (issue #24) --------------------------------------------------

    def event_append(
        self, ts: str, agent: str, kind: str, ref_id: str, vm_id: str, data_json: str
    ) -> int:
        """Append one event; returns its AUTOINCREMENT seq (never reused after
        a prune, which is what keeps cursors monotonic across restarts)."""
        with self._lock:
            self._begin()
            try:
                cur = self._connect().execute(
                    "INSERT INTO events (ts, agent, kind, ref_id, vm_id, data_json) "
                    "VALUES (?,?,?,?,?,?)",
                    (ts, agent, kind, ref_id, vm_id, data_json),
                )
                seq = cur.lastrowid
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return int(seq or 0)

    def events_after(self, agent: str, after_seq: int, limit: int = 100) -> list[dict[str, Any]]:
        """Agent-scoped events with seq strictly greater than `after_seq`, in
        sequence order. `data_json` stays a string; the tool layer parses it."""
        with self._lock:
            cur = self._connect().execute(
                "SELECT seq, ts, agent, kind, ref_id, vm_id, data_json FROM events "
                "WHERE agent = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
                (agent, int(after_seq), int(limit)),
            )
            values = cur.fetchall()
        return [
            {
                "seq": int(v[0]),
                "ts": str(v[1] or ""),
                "agent": str(v[2] or ""),
                "kind": str(v[3] or ""),
                "ref_id": str(v[4] or ""),
                "vm_id": str(v[5] or ""),
                "data_json": str(v[6] or "{}"),
            }
            for v in values
        ]

    def events_oldest(self, agent: str) -> int | None:
        """The oldest surviving seq for this agent (None when no events)."""
        with self._lock:
            cur = self._connect().execute(
                "SELECT MIN(seq) FROM events WHERE agent = ?", (agent,)
            )
            values = cur.fetchone()
        if not values or values[0] is None:
            return None
        return int(values[0])

    def events_prune(self, older_than_ts: str, keep_rows: int) -> int:
        """Retention: drop events older than the ISO timestamp, then cap the
        table at `keep_rows` newest. Returns the number removed. Runs best-
        effort from store_for()'s first-open sweep, never from open()."""
        removed = 0
        with self._lock:
            self._begin()
            try:
                cur = self._connect().execute(
                    "DELETE FROM events WHERE ts < ?", (older_than_ts,)
                )
                removed += int(cur.rowcount or 0)
                cur = self._connect().execute(
                    "DELETE FROM events WHERE seq NOT IN "
                    "(SELECT seq FROM events ORDER BY seq DESC LIMIT ?)",
                    (int(keep_rows),),
                )
                removed += int(cur.rowcount or 0)
                self._commit()
            except BaseException:
                self._rollback()
                raise
        return removed

    # -- meta (issue #24) ----------------------------------------------------

    def meta_get(self, key: str) -> str | None:
        with self._lock:
            cur = self._connect().execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            )
            values = cur.fetchone()
        return None if values is None else str(values[0])

    def meta_put(self, key: str, value: str) -> None:
        with self._lock:
            self._begin()
            try:
                self._connect().execute(
                    "INSERT INTO meta (key, value) VALUES (?,?) "
                    "ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise


def _iso_timestamp(epoch: float) -> str:
    """ISO-8601 UTC (millisecond) rendering of a store-clock epoch — the same
    shape events.ts carries, so retention compares like with like."""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat(
        timespec="milliseconds"
    )


def _is_unc(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized.startswith("//") or normalized.startswith("\\\\")


def _where(path: str) -> str:
    """The directory NAME a client-facing message may name, never the path.

    The full absolute path would disclose the host filesystem layout — and,
    on the profile default, the local account name — to MCP clients; the
    repo's established posture for exactly this trade is the slot-directory
    error in pswindows.py, which reports the name and keeps the detail for
    local logs (here: the chained exception, PRR-012). A path whose parent
    has no name (a drive root, a UNC share) yields no name at all — any part
    of a UNC host/share is itself the disclosure.
    """
    parent = os.path.dirname(os.path.abspath(path))
    return os.path.basename(parent.rstrip("\\/"))


def _oserror_text(exc: OSError) -> str:
    """An OSError's text WITHOUT the filename it embeds.

    ``OSError.__str__`` appends ``exc.filename`` — the full absolute path,
    which for the profile default contains the local account name — so a
    client-facing message cannot interpolate ``str(exc)`` directly (PRR-012,
    the same posture as the pswindows slot-directory error). Render the
    ``[WinError N] message`` / ``[Errno N] message`` head alone; the original
    exception stays chained on the raised StateStoreError so local logs keep
    the full path.
    """
    winerror = getattr(exc, "winerror", None)
    if winerror is not None:
        return f"[WinError {winerror}] {exc.strerror}"
    if exc.errno is not None and exc.strerror:
        return f"[Errno {exc.errno}] {exc.strerror}"
    return str(exc.strerror or exc.__class__.__name__)


def _recover_locked(store: Store, pid_probe=None) -> None:
    """Mark state left behind by a process that is no longer here.

    Runs inside the caller's open write transaction (open() folds this into
    its ONE initialization transaction, so a busy failure can no longer
    abort an already-created store in a second, separate transaction —
    PRR-011). The caller holds ``store._lock``.

    A `starting` job row is a reservation placeholder whose only legitimate
    transitions are promote-to-active (by the process that created it, which
    writes unconditionally) or delete-on-clean-failure. Marking it `orphaned`
    is therefore idempotent-safe: the creator's next write wins either way,
    and a third reader seeing `orphaned` for a job that is about to become
    `active` is a transient state, not a wrong answer.

    An `active` job row whose credential reference is `inline` is demoted to
    `orphaned` once its recorded pid is provably no live process (PRR-002).
    These are the rows nothing else can ever heal: every restored read of an
    inline row raises CredentialError BEFORE a guest leg, so job_status can
    never observe the exit that would demote it, and a different principal
    is refused outright — without this demotion, 128 of them permanently
    block job_start host-wide. The demotion fires only on a definitive
    False verdict: the recorded pid is a GUEST pid this host-side probe
    cannot really see, so a false `dead` on an env/file row would orphan a
    live peer's running job (the PRR-005 live-peer rule), and a row that
    cannot be probed is left alone, not assumed dead.

    A host-PID liveness check would be the tighter rule for the `starting`
    flip too, but its failure mode is a permanently stuck `starting` row
    that `_lookup` then refuses with "still starting" — strictly worse and
    non-deterministic across platforms.
    """
    con = store._connect()  # noqa: SLF001 - same module, recovery owns the write
    con.execute(
        "UPDATE jobs SET state = ? WHERE state = ?", (JOB_ORPHANED, JOB_STARTING)
    )
    for row in store.job_rows():
        if row.state != JOB_ACTIVE or row.cred_ref != "inline":
            continue
        if _pid_is_live(row.pid, pid_probe) is False:
            con.execute(
                "UPDATE jobs SET state = ? WHERE job_id = ?",
                (JOB_ORPHANED, row.job_id),
            )
    con.execute(
        "UPDATE relays SET state = ? WHERE state = ?",
        (RELAY_INTERRUPTED, RELAY_ACTIVE),
    )


def _header_user_version(path: str) -> int | None:
    """user_version read straight from the file header (offset 60, 4 bytes,
    big-endian), or None when no file exists or it is too short to carry one.

    Costs nothing and opens nothing, which is what lets open() refuse the
    common case (a cleanly closed store) with no sqlite involvement at all.
    Its blind spot: a crashed WAL writer leaves the newer version inside the
    uncheckpointed -wal while the main file's header still shows the old one
    — only sqlite sees through that (see _probed_user_version).
    """
    try:
        # builtins.open, not open: this module defines its own open() below,
        # which shadows the builtin inside this file.
        with builtins.open(path, "rb") as fh:
            head = fh.read(64)
    except (OSError, ValueError):
        # ValueError: a path carrying an embedded NUL makes every file API
        # raise ("embedded null byte") before anything exists — read as "no
        # header", never a raw escape from the store's error type.
        return None
    if len(head) < 64:
        return None
    return int.from_bytes(head[60:64], "big")


def _probed_user_version(path: str) -> int | None:
    """The refusal verdict on user_version, or None for "no verdict".

    The raw header is the first opinion; when it does not already settle the
    matter, a READ-ONLY sqlite connection gives the WAL-aware one. Read-only
    is the load-bearing property: closing an rw connection CHECKPOINTS a WAL
    database — merging the -wal into the file — which is exactly the byte
    modification a refusal must never make (PRR-011/AC7), while a read-only
    connection cannot checkpoint and cannot create the -shm sidecar. A
    missing file, a missing -shm, or any probe failure is "no verdict", and
    open() proceeds to its authoritative read-write read.
    """
    header = _header_user_version(path)
    if header is not None and header > SCHEMA_VERSION:
        return header
    try:
        con = sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True)
    except (OSError, ValueError, sqlite3.Error):
        return header
    try:
        return int(con.execute("PRAGMA user_version").fetchone()[0])
    except sqlite3.Error:
        return header
    finally:
        try:
            con.close()
        except sqlite3.Error:  # pragma: no cover - close of a dead handle
            pass


def open(path: str) -> Store:
    """Open (creating if needed) the state store at ``path``.

    ``PRAGMA user_version`` is settled BEFORE any directory is created and
    BEFORE any read-write connection is opened — raw header first, then a
    read-only sqlite probe that sees through an uncheckpointed -wal — so
    refusing a newer schema leaves the file byte-untouched (an rw close
    would checkpoint a WAL database). Schema creation and recovery land in
    ONE transaction, and every SQLITE_BUSY retry (including the WAL-mode
    switch, which SQLite does not route through the busy handler reliably)
    draws on ONE shared time budget instead of per-leg budgets.
    """
    if not path or not str(path).strip():
        raise StateStoreError("state store path is empty")
    path = str(path)
    if "\0" in path:
        # An embedded NUL makes every file API raise a bare ValueError
        # ("embedded null byte") — SQLite's path converter included — which
        # would escape this entry un-enveloped. The public open() must
        # surface StateStoreError for every unusable path, so refuse here,
        # naming the condition only (PRR-012: the path never rides along).
        raise StateStoreError(
            "state store path contains an embedded NUL byte"
        )
    if _is_unc(path):
        # No part of the UNC host/share is nameable — the host name IS the
        # disclosure (PRR-012) — so the message names the condition only.
        raise StateStoreError(
            "refusing to open the state store on a network path: SQLite WAL "
            "mode needs shared memory and does not work over a network "
            "filesystem"
        )
    early = _probed_user_version(path)
    if early is not None and early > SCHEMA_VERSION:
        # PRR-012: both version numbers and the directory NAME only — the
        # path never reaches a client envelope. Nothing that could touch
        # bytes has run yet (PRR-011: no directory, no rw connection).
        where = f" in ({_where(path)})" if _where(path) else ""
        raise StateStoreError(
            f"state store{where} has schema version {early}, "
            f"newer than this build supports ({SCHEMA_VERSION}); refusing "
            "to open it"
        )
    parent = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        # PRR-012: the message names the directory NAME (``_where`` yields
        # no name for a drive-root parent, so the parenthetical is omitted
        # rather than rendered empty) and the OSError's own text WITHOUT its
        # filename — ``str(exc)`` embeds the full absolute path, which on the
        # profile default contains the local account name. Chained (not
        # ``from None``) so local logs keep the full path.
        where = f" ({_where(path)})" if _where(path) else ""
        raise StateStoreError(
            f"could not create the state store directory{where}: "
            f"{_oserror_text(exc)}"
        ) from exc

    deadline = time.monotonic() + _OPEN_BUDGET_S
    backoff = _OPEN_BACKOFF_S
    last: sqlite3.Error | None = None
    while True:
        store = Store(path)
        try:
            con = store._connect()  # noqa: SLF001 - open() owns construction
            found = int(con.execute("PRAGMA user_version").fetchone()[0])
            if found > SCHEMA_VERSION:
                # The header pre-check above usually refuses first; this
                # catches a store created between the two reads.
                store.close()
                raise StateStoreError(
                    f"state store schema version {found} is newer than this "
                    f"build supports ({SCHEMA_VERSION}); refusing to open it"
                )
            # journal_mode=WAL needs a brief exclusive lock when converting a
            # fresh database, and SQLite does not apply the busy handler to
            # it reliably, so a busy answer here unwinds to the shared
            # outer retry below — it no longer carries a budget of its own
            # (PRR-011).
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            con.execute("PRAGMA foreign_keys=ON")
            with store._lock:  # noqa: SLF001 - open() owns construction
                store._begin()  # noqa: SLF001
                try:
                    if found == SCHEMA_VERSION and not _tables_present(con):
                        # A store claiming the CURRENT version with none of
                        # its tables is corrupt (hand-stamped, truncated
                        # restore, ...). Refuse naming both versions, like
                        # the newer-store refusal, rather than letting the
                        # recovery read fail with a bare "no such table".
                        store.close()
                        raise StateStoreError(
                            f"state store schema version {found} is newer "
                            f"than its own tables (expected version "
                            f"{SCHEMA_VERSION}, found an unversioned empty "
                            f"store, oldest supported 1); refusing to open it"
                        )
                    if found == 0:
                        # One transaction: the schema, the version write and
                        # recovery land together, so a concurrent opener never
                        # sees a half-created database with user_version
                        # still 0, and a busy failure cannot abort an
                        # already-created store (PRR-011).
                        for statement in _SCHEMA_STATEMENTS:
                            con.execute(statement)
                        con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    elif 0 < found < SCHEMA_VERSION:
                        # Issue #23: FORWARD MIGRATION. Without this branch a
                        # store already at user_version 1 never receives the
                        # v1->v2 tables, because open() only created the
                        # schema when it found 0 -- every lease call would
                        # then fail against an already-deployed store.
                        # `PRAGMA user_version` is transactional, so a crash
                        # here rolls the whole thing back and the next open
                        # retries cleanly on a still-v1 database.
                        #
                        # A found version this build cannot migrate from
                        # (older than the oldest migration, i.e. a v0 file
                        # with user_version stamped but no tables) fails
                        # LOUDLY here rather than stamping itself v2 over an
                        # empty schema.
                        _migrate_to(con, found)
                    _recover_locked(store)
                    # Issue #23: expired-lease sweeping lives in store_for()
                    # (first open per process, horizon = leases.max_ttl_s from
                    # the caller's config), NOT here: open() has no Config, so
                    # its horizon could not honor the operator's boundary, and
                    # a sweep on this default-clock path would reap a
                    # fake-clock session's rows (their expires_at sits in the
                    # real past).
                    store._commit()  # noqa: SLF001
                except BaseException:
                    store._rollback()  # noqa: SLF001
                    raise
            return store
        except sqlite3.Error as exc:
            store.close()
            if not _is_busy(exc):
                where = f" ({_where(path)})" if _where(path) else ""
                raise StateStoreError(
                    f"could not open the state store{where}: {exc}"
                ) from exc
            last = exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(backoff, remaining))
            backoff += _OPEN_BACKOFF_S

    where = f" ({_where(path)})" if _where(path) else ""
    raise StateStoreError(
        f"could not open the state store{where}: another process "
        f"holds it ({last})"
    )


_stores: dict[str, Store] = {}
_stores_lock = threading.Lock()


def resolve_state_db_path(cfg: Config, environ: dict[str, str] | None = None) -> str:
    """Resolve the effective store path for ``cfg``.

    Precedence: the environment variable, then the config key, then the
    per-profile default. Resolved at call time (not as a dataclass default) so a
    test that repoints ``LOCALAPPDATA`` is honoured, and so a directly
    constructed ``Config()`` — which never went through ``load()`` — still gets
    the documented default rather than an empty path.

    The default comes from ``config.default_state_db_path`` so the precedence
    has exactly one definition.
    """
    import os as _os

    env = dict(_os.environ if environ is None else environ)
    override = (env.get("HYPERV_MCP_STATE_DB") or "").strip()
    if override:
        return override
    configured = (cfg.state_db_path or "").strip()
    if configured:
        return configured
    return default_state_db_path(env)


def store_for(cfg: Config, environ: dict[str, str] | None = None) -> Store:
    """The process's Store for ``cfg``, cached by resolved path."""
    path = resolve_state_db_path(cfg, environ)
    with _stores_lock:
        found = _stores.get(path)
        if found is None:
            first_open = True
            store = open(path)
            _stores[path] = store
        else:
            first_open = False
            store = found
    if first_open:
        # Issue #23: sweep lease rows whose expiry lapsed more than one
        # leases.max_ttl_s ago -- the plan's expired-vs-unknown boundary. Runs
        # ONLY on the first open in this process (a cached hit would make every
        # lease call pay a DELETE) and never inside open() itself, whose
        # default clock would reap a fake-clock session's rows.
        horizon = int(getattr(cfg.leases, "max_ttl_s", 3600) or 3600)
        try:
            store.sweep_expired_leases(store.now() - horizon)
        except Exception:
            # A sweep failure must never block the caller; the rows just live
            # until the next first-open.
            pass
        # Issue #24: prune the event log by age and row count on the same
        # first-open-only, best-effort schedule. Idempotency-record expiry is
        # enforced at consult time (operations.py), not swept here, so an
        # injected-clock session's rows are never reaped by a real clock.
        try:
            cutoff = _iso_timestamp(store.now() - int(
                getattr(cfg.operations, "event_retention_s", 7 * 86400) or 7 * 86400
            ))
            store.events_prune(cutoff, int(
                getattr(cfg.operations, "event_max_rows", 10000) or 10000
            ))
        except Exception:
            pass
        # Issue #24 (implementation-review R8): op/result retention is a real
        # knob — terminal op rows (and their stored payloads) older than
        # operations.retention_s are pruned on the same first-open schedule.
        try:
            store.ops_prune(store.now() - int(
                getattr(cfg.operations, "retention_s", 86400) or 86400
            ))
        except Exception:
            pass
    return store


def clear_store_cache_for_tests() -> None:
    """Close every cached Store. Called by the unit-test conftest teardown so a
    long suite does not accumulate open SQLite connections (and, on Windows,
    open ``-wal``/``-shm`` files that pytest's tmp cleanup cannot delete)."""
    with _stores_lock:
        stores = list(_stores.values())
        _stores.clear()
    for store in stores:
        store.close()
