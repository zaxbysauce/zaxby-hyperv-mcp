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

import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from .config import Config, default_state_db_path

SCHEMA_VERSION = 1
BUSY_TIMEOUT_MS = 5000

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

_SCHEMA = """
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
    owner TEXT
);
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
    owner TEXT
);
"""


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
    )


_JOB_COLUMNS = (
    "job_id, vm_name, vm_id, pid, start_time_ticks, job_dir, out_path, "
    "err_path, exit_path, started_at, state, cred_ref, owner"
)
_RELAY_COLUMNS = (
    "relay_id, vm_name, vm_id, guest_port, bind, host_port, started_at, "
    "state, cred_ref, owner"
)


class Store:
    """One SQLite connection, serialized. Not thread-safe by SQLite's rules, so
    every method takes the lock; the lock is reentrant so a transaction helper
    can call a plain reader without deadlocking on itself."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._con: sqlite3.Connection | None = None
        # >0 while an explicit transaction() block owns the connection, so the
        # single-statement write helpers below do not commit it out from under
        # the caller (SQLite rejects a nested BEGIN outright).
        self._depth = 0

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
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(job_id) DO UPDATE SET "
                    "vm_name=excluded.vm_name, vm_id=excluded.vm_id, "
                    "pid=excluded.pid, start_time_ticks=excluded.start_time_ticks, "
                    "job_dir=excluded.job_dir, out_path=excluded.out_path, "
                    "err_path=excluded.err_path, exit_path=excluded.exit_path, "
                    "started_at=excluded.started_at, state=excluded.state, "
                    "cred_ref=excluded.cred_ref, owner=excluded.owner",
                    (
                        row.job_id, row.vm_name, row.vm_id, row.pid,
                        row.start_time_ticks, row.job_dir, row.out_path,
                        row.err_path, row.exit_path, row.started_at, row.state,
                        row.cred_ref, row.owner,
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

    def job_ids(self) -> set[str]:
        with self._lock:
            cur = self._connect().execute("SELECT job_id FROM jobs")
            return {str(r[0]) for r in cur.fetchall()}

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
                    "VALUES (?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(relay_id) DO UPDATE SET "
                    "vm_name=excluded.vm_name, vm_id=excluded.vm_id, "
                    "guest_port=excluded.guest_port, bind=excluded.bind, "
                    "host_port=excluded.host_port, started_at=excluded.started_at, "
                    "state=excluded.state, cred_ref=excluded.cred_ref, "
                    "owner=excluded.owner",
                    (
                        row.relay_id, row.vm_name, row.vm_id, row.guest_port,
                        row.bind, row.host_port, row.started_at, row.state,
                        row.cred_ref, row.owner,
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


def _is_unc(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized.startswith("//") or normalized.startswith("\\\\")


def _recover(store: Store) -> None:
    """Mark state left behind by a process that is no longer here.

    A `starting` job row is a reservation placeholder whose only legitimate
    transitions are promote-to-active (by the process that created it, which
    writes unconditionally) or delete-on-clean-failure. Marking it `orphaned` is
    therefore idempotent-safe: the creator's next write wins either way, and a
    third reader seeing `orphaned` for a job that is about to become `active` is
    a transient state, not a wrong answer.

    A host-PID liveness check would be the tighter rule, but its failure mode is
    a permanently stuck `starting` row that `_lookup` then refuses with "still
    starting" — strictly worse and non-deterministic across platforms.
    """
    with store._lock:  # noqa: SLF001 - same module, recovery owns the write
        store._begin()  # noqa: SLF001
        try:
            con = store._connect()  # noqa: SLF001
            con.execute(
                "UPDATE jobs SET state = ? WHERE state = ?", (JOB_ORPHANED, JOB_STARTING)
            )
            con.execute(
                "UPDATE relays SET state = ? WHERE state = ?",
                (RELAY_INTERRUPTED, RELAY_ACTIVE),
            )
            store._commit()  # noqa: SLF001
        except BaseException:
            store._rollback()  # noqa: SLF001
            raise


def open(path: str) -> Store:
    """Open (creating if needed) the state store at ``path``.

    Reads ``PRAGMA user_version`` FIRST, before applying any pragma that writes
    to the file, so refusing a newer schema leaves the file byte-untouched.
    """
    if not path or not str(path).strip():
        raise StateStoreError("state store path is empty")
    path = str(path)
    if _is_unc(path):
        raise StateStoreError(
            f"refusing to open the state store on a network path ({path}): "
            "SQLite WAL mode needs shared memory and does not work over a "
            "network filesystem"
        )
    parent = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise StateStoreError(f"could not create the state store directory ({parent}): {exc}") from None

    store = Store(path)
    try:
        con = store._connect()  # noqa: SLF001 - open() owns construction
        found = int(con.execute("PRAGMA user_version").fetchone()[0])
    except sqlite3.Error as exc:
        store.close()
        raise StateStoreError(f"could not open the state store ({path}): {exc}") from None

    if found > SCHEMA_VERSION:
        store.close()
        raise StateStoreError(
            f"state store schema version {found} is newer than this build "
            f"supports ({SCHEMA_VERSION}); refusing to open {path}"
        )

    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA foreign_keys=ON")
        if found == 0:
            with store._lock:  # noqa: SLF001
                store._begin()  # noqa: SLF001
                try:
                    con.executescript(_SCHEMA)
                    con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    store._commit()  # noqa: SLF001
                except BaseException:
                    store._rollback()  # noqa: SLF001
                    raise
        _recover(store)
    except sqlite3.Error as exc:
        store.close()
        raise StateStoreError(f"could not initialize the state store ({path}): {exc}") from None
    return store


# Process-local by design: this caches Store HANDLES, not state. The
# authoritative copy is in the database file, which outlives the process, so a
# restart simply re-opens it and runs recovery. Nothing a client holds is lost
# when this dict dies with the process.
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
        store = _stores.get(path)
        if store is None:
            store = open(path)
            _stores[path] = store
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
