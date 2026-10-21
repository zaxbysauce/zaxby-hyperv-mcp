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
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
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
        owner TEXT
    )
    """,
)

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


def _default_pid_probe(pid: int) -> bool | None:
    """Best-effort HOST-side liveness probe. Never raises.

    True = a live process, False = provably no such process, None = cannot
    tell. POSIX signal 0 is the standard probe (ESRCH = dead, EPERM = exists
    but not ours, hence alive). On Windows ``os.kill(pid, 0)`` is likewise an
    existence probe, where ERROR_INVALID_PARAMETER (87) is the no-such-pid
    answer; an inaccessible live pid surfaces as anything from
    PermissionError to SystemError depending on build, so every other error
    is an unknown, never a verdict.
    """
    if pid <= 0:
        return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 87:
            return False
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
    except OSError:
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
        # Chained (not `from None`) so local logs keep the full path; the
        # message itself names only the directory (PRR-012).
        raise StateStoreError(
            f"could not create the state store directory ({os.path.basename(parent)}): {exc}"
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
                    if found == 0:
                        # One transaction: the schema, the version write and
                        # recovery land together, so a concurrent opener never
                        # sees a half-created database with user_version
                        # still 0, and a busy failure cannot abort an
                        # already-created store (PRR-011).
                        for statement in _SCHEMA_STATEMENTS:
                            con.execute(statement)
                        con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    _recover_locked(store)
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
