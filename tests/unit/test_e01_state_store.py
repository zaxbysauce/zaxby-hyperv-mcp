"""Acceptance checks C7 and C8 for the durable-state store (E01): the
schema contract of hyperv_mcp.statestore, and that two processes can share
one store without lock errors.

C7 (AC7, NEW-SURFACE) — statestore.open() creates a WAL database with
user_version 1 and busy_timeout >= 5000, and refuses (StateStoreError
naming BOTH version numbers, file left unmodified) a database whose
user_version is greater than the code's. RED at base: the module does not
exist, so this file fails at COLLECTION with ImportError (the correct
NEW-SURFACE absence signature — C7 and C8 never run as tests).
C8 (AC8, NEW-SURFACE) — two child processes started in parallel each add
25 jobs to one shared store; 50 distinct job ids come back on stdout, 50
job rows exist in the database, and neither child ever reports
"database is locked". RED at base with the same collection-time
ImportError.

The schema facts are read back through RAW sqlite3 connections so the
checks depend on nothing about the Store object's API beyond open()
itself; the job-row count queries sqlite_master for a job-named table
for the same reason.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

# NEW-SURFACE: absent until the durable-state change lands; at base this
# import fails the whole file at collection time, which is the pinned
# absence signature for C7 and C8.
from hyperv_mcp import statestore

_SRC = Path(__file__).resolve().parents[2] / "src"
_MULTI_CHILD = Path(__file__).resolve().parent / "_e01_multi_child.py"


def _close(store) -> None:
    """Close `store` when it exposes a close.

    Every fact under test lives in the FILE (header pragmas, row counts),
    so the checks read them through raw sqlite3 connections and only need
    open() from the Store itself; closing it when possible just avoids
    holding the WAL side files open for the rest of the session.
    """
    close = getattr(store, "close", None)
    if callable(close):
        close()


def _read_pragmas(path: str) -> tuple[str, int, int]:
    con = sqlite3.connect(path)
    try:
        mode = con.execute("PRAGMA journal_mode").fetchone()[0]
        version = con.execute("PRAGMA user_version").fetchone()[0]
        timeout = con.execute("PRAGMA busy_timeout").fetchone()[0]
    finally:
        con.close()
    return str(mode), int(version), int(timeout)


def test_store_schema_contract(tmp_path):
    """C7 (AC7): open() yields a WAL database at user_version 1 with a
    busy_timeout of at least 5000 ms, and a database from a NEWER schema is
    refused with StateStoreError naming both versions and left BYTE-UNTOUCHED
    (PRR-011: the refusal path must never open a read-write connection,
    because closing one checkpoints a WAL database).
    RED at base: `from hyperv_mcp import statestore` fails this file at
    collection, so neither half of the contract can be exercised.

    Honest scope of the busy_timeout clause, stated rather than implied
    (PRR-015): the store configures its pragma to 5000 ms, which EQUALS the
    sqlite3 module's own connect() default, so no observable through the
    connection can distinguish the store's pragma from Python's default —
    including a busy-writer timing probe, which would wait ~5 s either way.
    What the assertion below pins is the EFFECTIVE value on the store's OWN
    connection (the control proves the read reflects that connection's
    timeout); which of the two equal mechanisms set it is not provable from
    outside, and this check does not claim it is.
    """
    path = str(tmp_path / "state.sqlite3")
    store = statestore.open(path)
    try:
        mode, version, _raw_timeout = _read_pragmas(path)
        assert mode.lower() == "wal"
        assert version == 1

        # busy_timeout is PER CONNECTION, so a raw sqlite3.connect cannot
        # observe what the store configured: Python's default timeout=5.0
        # already makes PRAGMA busy_timeout report 5000. Prove the read is
        # sensitive before trusting it, then read it through the connection
        # the store actually owns.
        blind = sqlite3.connect(path, timeout=0.0)
        try:
            assert blind.execute("PRAGMA busy_timeout").fetchone()[0] == 0, (
                "the busy_timeout control read must reflect the connection's "
                "own timeout, otherwise the assertion below proves nothing"
            )
        finally:
            blind.close()
        assert store.busy_timeout_ms >= 5000
    finally:
        _close(store)

    # A newer schema must be refused loudly, naming BOTH the code's version
    # and the file's, and the refusal must not touch the file — not even its
    # BYTES, and not even when the newer version only lives in an
    # uncheckpointed -wal (PRR-011/AC7): a crashed writer leaves exactly
    # that, and the one refusal path that could modify the file is an
    # rw connection, whose close merges the -wal into it. open() settles the
    # version before opening one.
    newer = str(tmp_path / "newer.sqlite3")
    crashed = subprocess.run(
        [sys.executable, "-c",
         "import os, sqlite3, sys\n"
         "con = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
         "con.execute('PRAGMA journal_mode=WAL')\n"
         "con.execute('PRAGMA user_version=2')\n"
         "con.execute('CREATE TABLE t(x)')\n"
         "con.execute('INSERT INTO t VALUES (1)')\n"
         "os._exit(0)\n", newer],
        capture_output=True, text=True, timeout=60,
    )
    assert crashed.returncode == 0, crashed.stderr
    assert os.path.exists(newer + "-wal"), "the crashed writer left a -wal"
    before = open(newer, "rb").read()
    sidecars_before = sorted(
        name for name in os.listdir(str(tmp_path)) if name.startswith("newer.sqlite3")
    )
    with pytest.raises(statestore.StateStoreError) as excinfo:
        statestore.open(newer)
    message = str(excinfo.value)
    assert "1" in message
    assert "2" in message
    # Byte comparison FIRST: reading the pragmas below opens its own rw
    # connection, whose close would checkpoint the -wal and legitimately
    # change the bytes — the refusal itself must not have.
    assert open(newer, "rb").read() == before, (
        "a refused store must stay byte-untouched"
    )
    assert sorted(
        name for name in os.listdir(str(tmp_path)) if name.startswith("newer.sqlite3")
    ) == sidecars_before, "a refused store must not disturb its -wal/-shm"
    _, version_after, _ = _read_pragmas(newer)
    assert version_after == 2


def test_two_processes_share_store(tmp_path):
    """C8 (AC8): two concurrent processes against one store file both
    complete 25 job starts each — 50 distinct job ids, 50 job rows, and no
    "database is locked" from either child. RED at base: the module-level
    statestore import fails this file at collection."""
    db = tmp_path / "state.sqlite3"
    # dict(os.environ, **overrides) keeps SYSTEMROOT and friends, so the
    # child Python processes start cleanly on Windows.
    env = dict(os.environ, **{
        "HYPERV_MCP_UNRESTRICTED": "1",
        "HYPERV_MCP_STATE_DB": str(db),
        "HYPERV_GUEST_USERNAME": "Administrator",
        "HYPERV_GUEST_PASSWORD": "placeholder-pass",
        "PYTHONPATH": str(_SRC),
    })
    children = [
        subprocess.Popen(
            [sys.executable, str(_MULTI_CHILD), str(db), "25"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(2)
    ]
    # Both are started before either is joined, so the two writers
    # genuinely overlap on the database.
    results = []
    for proc in children:
        try:
            out, err = proc.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        results.append((proc.returncode, out, err))

    for code, out, err in results:
        assert code == 0, err or out
    ids: list[str] = []
    for _code, out, _err in results:
        ids.extend(json.loads(out.strip()))
    assert len(ids) == 50
    assert len(set(ids)) == 50
    for _code, _out, err in results:
        assert "database is locked" not in err

    # A third opener must attach cleanly to what the two writers left, and
    # the job rows must be in the file, not just in either child's memory.
    store = statestore.open(str(db))
    _close(store)
    con = sqlite3.connect(str(db))
    try:
        tables = {
            row[0] for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        con.close()
    # The issue's schema names the two tables this PR introduces; pinning the
    # names keeps the row count below from passing on any job-named table.
    assert {"jobs", "relays"} <= tables, sorted(tables)
    con = sqlite3.connect(str(db))
    try:
        job_rows = con.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        relay_rows = con.execute("SELECT COUNT(*) FROM relays").fetchone()[0]
    finally:
        con.close()
    assert job_rows == 50, job_rows
    assert relay_rows == 0, relay_rows
