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
