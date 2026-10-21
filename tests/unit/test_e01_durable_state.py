"""Acceptance checks for the durable SQLite state store (E01): a process
restart must not strand guest jobs or relays, and the store must never
persist secret material.

C1 (AC1, DISCRIMINATING) — job_status reattaches to a job started before a
simulated restart (importlib.reload of guestjobs) by re-resolving the
credential from the environment it was started with, and reports the live
status. RED at base: the reload empties the process-local registry and the
call raises ValueError: unknown job_id.
C2 (AC2, DISCRIMINATING) — relay_status reports a relay whose listener
died as state "interrupted" instead of raising, and a later relay_start
for the same VM + guest port is not refused as a duplicate. RED at base:
ValueError: unknown relay_id.
C3 (AC3, DISCRIMINATING) — a child process that hard-exits inside the
guest start leg leaves an addressable row whose status is "orphaned".
RED at base: ValueError: unknown job_id.
C4 (AC4, DISCRIMINATING) — a job started with an inline CredentialSet (one
not produced by credentials.resolve_guest()) raises CredentialError from
job_status after a restart; the message does not name the environment
username, so no substitution happened. RED at base: the raised error is a
ValueError, not a CredentialError.
C5 (AC5, DISCRIMINATING) — Config gains a state_db_path field, settable by
the state_db_path config key and overridden by HYPERV_MCP_STATE_DB. RED at
base: ConfigError: unknown config key(s).
C6 (AC6, NEW-SURFACE) — credentials, command text and argument text never
reach the store file, its -wal or its -shm, in UTF-8 or UTF-16-LE. RED at
base: no store file is created at all.
C9 (AC9, DISCRIMINATING) — with neither the config key nor the env var,
the store path defaults to <LOCALAPPDATA>/hyperv-mcp/state.db and
statestore.open() creates the parent directory. RED at base: Config has no
state_db_path attribute.

Every guest leg runs against a fake pswindows.run_ps; no Hyper-V and no
guest is touched. statestore is imported INSIDE C9 (not at module scope) —
only test_e01_state_store.py carries the NEW-SURFACE collection-time
ImportError; this file collects at base and each check fails on its own
signature. AC11/AC12/AC13 (PRESERVING) stay in test_guestjobs.py and
test_relay.py, which this change does not touch.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from hyperv_mcp import credentials, guestjobs, pswindows, relay
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")

_SRC = Path(__file__).resolve().parents[2] / "src"
_CRASH_CHILD = Path(__file__).resolve().parent / "_e01_crash_child.py"

# Identity resolution (issue #8): vmident.resolve runs a by-name leg before
# job_start / relay_start. Distinct VM names must resolve to DISTINCT GUIDs
# (test_a04_vm_identity FakePS pattern, per-name guid).
_NAME_RE = re.compile(r"ElementName -eq '([^']*)'")


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _resolved_guid(script: str) -> str:
    """Stable per-name GUID: distinct names are distinct VMs."""
    m = _NAME_RE.search(script)
    return str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1) if m else ""))


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


class OrderedFakePS:
    """run_ps fake answering legs by CALL ORDER.

    The start action's PowerShell (Start-Process and everything around it)
    rides the wrapper's base64 $enc payload, so the OUTER script handed to
    run_ps carries no recognisable start substring — legs after the identity
    resolution cannot be told apart by content. Call #1 is always the
    by-name resolution leg, #2 the guest start, and every later call a
    follow-up observation leg answered from `later`.
    """

    def __init__(self, start: dict, later: dict):
        self.start = start
        self.later = later
        self.scripts: list[str] = []
        self._n = 0

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self._n += 1
        if self._n == 1:
            assert _is_resolution_leg(script), "first leg must be identity resolution"
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        if self._n == 2:
            return _ok(self.start)
        return _ok(self.later)


class FakePS:
    """run_ps fake answering only the identity-resolution leg (the
    test_relay.py pattern): relay lifecycle calls spawn no other leg."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        raise AssertionError("unexpected non-resolution run_ps call")


@pytest.fixture(autouse=True)
def _clean_registries():
    """Per-test registry hygiene mirroring test_guestjobs.py and
    test_relay.py: no job entry, relay entry, or live listener crosses a
    test, whichever module reload happened inside it."""
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()
    yield
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()


def _state_env(monkeypatch, tmp_path, *, username="Administrator",
               password="placeholder-pass") -> None:
    """Point the durable store and the guest credential environment at
    tmp_path, unrestricted so the fake-VM name passes policy."""
    monkeypatch.setenv("HYPERV_MCP_UNRESTRICTED", "1")
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.sqlite3"))
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", username)
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", password)


def test_job_status_after_restart_reattaches(monkeypatch, tmp_path):
    """C1 (AC1): after a simulated restart (importlib.reload empties the
    process-local registry), job_status reattaches to the job started
    before it — re-resolving the credential from the environment the job
    was started with — and reports the guest's live status. RED at base:
    the reload strands the job and the call raises ValueError: unknown
    job_id '<32 hex>'."""
    _state_env(monkeypatch, tmp_path)
    cfg = Config.load()
    credentials.init(cfg)
    original = pswindows.run_ps
    try:
        fake = OrderedFakePS(
            start={"pid": 4242, "job_dir": "d", "start_time_ticks": 1},
            later={"status": "running"},
        )
        monkeypatch.setattr(pswindows, "run_ps", fake)
        start = guestjobs.job_start(
            cfg, "test-vm", "x.exe", cred=credentials.resolve_guest(),
        )
        job_id = start["job_id"]
        # The restart: the process-local registry dies with the process;
        # the durable store must not.
        importlib.reload(guestjobs)
        assert guestjobs.job_status(cfg, job_id)["status"] == "running"
    finally:
        pswindows.run_ps = original


def test_relay_status_after_restart_reports_interrupted(monkeypatch, tmp_path):
    """C2 (AC2): a relay whose listener died (process death, simulated by
    shutting the server down without any registry bookkeeping) is reported
    by a restarted process as state "interrupted" instead of raising, and
    the same VM + guest port is startable again — an interrupted row is
    not a live duplicate. RED at base: the reload strands the relay and
    relay_status raises ValueError: unknown relay_id 'relay-9222-<32 hex>'."""
    cfg_file = tmp_path / "relay-config.json"
    cfg_file.write_text(json.dumps({
        "allowed_vm_patterns": ["test-*"],
        "destructive": {"relay": True},
    }), encoding="utf-8")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(cfg_file))
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(tmp_path / "state.sqlite3"))
    try:
        cfg = Config.load()
        fake = FakePS()
        monkeypatch.setattr(pswindows, "run_ps", fake)
        out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
        # Process death: the listener dies with NO registry bookkeeping (no
        # stopped flag, no credential nulling) — exactly the state a killed
        # process leaves behind. _shutdown_server is best-effort and only
        # stops the server/thread.
        relay._shutdown_server(relay._relays[out["relay_id"]])
        importlib.reload(relay)
        rows = relay.relay_status(cfg, out["relay_id"])["relays"]
        assert len(rows) == 1
        assert rows[0]["state"] == "interrupted"
        # The duplicate check must ignore interrupted rows: starting the
        # same VM + guest port again must not raise.
        second = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
        relay.relay_stop(cfg, second["relay_id"])
    finally:
        for entry in list(relay._relays.values()):
            relay._shutdown_server(entry)
        os.environ.pop("HYPERV_MCP_CONFIG", None)


def test_crash_during_start_leaves_addressable_row(monkeypatch, tmp_path):
    """C3 (AC3): a hard crash inside the guest start leg (a child process
    that os._exit(1)s after the reservation exists but before any payload
    or cleanup) leaves a row the parent process can still address, whose
    status is "orphaned". The assertion is on the STATUS VALUE, never on
    the absence of an exception. RED at base: the parent's job_status
    raises ValueError: unknown job_id '<32 hex>'."""
    _state_env(monkeypatch, tmp_path)
    record = tmp_path / "crash-record.txt"
    # dict(os.environ, **overrides) keeps SYSTEMROOT and friends, so the
    # child Python starts cleanly on Windows.
    env = dict(os.environ, **{
        "HYPERV_MCP_UNRESTRICTED": "1",
        "HYPERV_MCP_STATE_DB": str(tmp_path / "state.sqlite3"),
        "HYPERV_GUEST_USERNAME": "Administrator",
        "HYPERV_GUEST_PASSWORD": "placeholder-pass",
        "PYTHONPATH": str(_SRC),
    })
    crashed = subprocess.run(
        [sys.executable, str(_CRASH_CHILD), str(record)],
        env=env, capture_output=True, text=True, timeout=120,
    )
    assert crashed.returncode != 0
    job_id = record.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"[0-9a-f]{32}", job_id), job_id

    cfg = Config.load()
    credentials.init(cfg)

    def fake_run_ps(script, **kwargs):
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        return _ok({"status": "orphaned"})

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)
    out = guestjobs.job_status(cfg, job_id)
    assert out["status"] == "orphaned"


def test_inline_credential_job_after_restart_needs_credentials(monkeypatch, tmp_path):
    """C4 (AC4): a job started with an inline CredentialSet (hand-built, not
    from credentials.resolve_guest()) cannot be re-attached after a restart
    — job_status raises CredentialError rather than substituting the
    environment credentials, and the message does not name the environment
    username. RED at base: the reload strands the job and the raised error
    is a ValueError, so the type assertion reads
    AssertionError: assert 'ValueError' == 'CredentialError'."""
    _state_env(monkeypatch, tmp_path,
               username="env-admin", password="env-placeholder-pass")
    cfg = Config.load()
    fake = OrderedFakePS(start={"pid": 7, "job_dir": "d"}, later={"status": "running"})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(
        cfg, "test-vm", "x.exe",
        cred=CredentialSet("inline-admin", "inline-pass"),
    )
    job_id = start["job_id"]
    importlib.reload(guestjobs)
    exc = None
    try:
        guestjobs.job_status(cfg, job_id)
    except Exception as caught:  # the exact type is what the check pins
        exc = caught
    assert exc is not None
    assert type(exc).__name__ == "CredentialError"
    # No substitution: the environment username must not appear in the
    # error, because the environment credential was never used.
    assert "env-admin" not in str(exc)


def test_state_db_path_config_key_and_env_override(tmp_path):
    """C5 (AC5): Config gains a state_db_path field — settable by the
    state_db_path config key and overridden by the HYPERV_MCP_STATE_DB
    environment variable. RED at base: the key is rejected with
    ConfigError: unknown config key(s): ['state_db_path']."""
    p1 = tmp_path / "a.sqlite3"
    p2 = tmp_path / "b.sqlite3"
    assert Config.from_dict({"state_db_path": str(p1)}).state_db_path == str(p1)
    assert Config.load({"HYPERV_MCP_STATE_DB": str(p2)}).state_db_path == str(p2)


def test_credentials_never_persisted(monkeypatch, tmp_path):
    """C6 (AC6): the store file, its -wal and its -shm never contain the
    guest password or the command's argument text, in UTF-8 or UTF-16-LE —
    the store records job identity and re-attach metadata only. RED at
    base: no store file is created at all, so the first assertion reads
    AssertionError: assert False (where False = exists())."""
    _state_env(monkeypatch, tmp_path,
               username="canary-admin", password="S3cret-canary-pass")
    cfg = Config.load()
    credentials.init(cfg)
    fake = OrderedFakePS(
        start={"pid": 4242, "job_dir": "d", "start_time_ticks": 1},
        later={"status": "running"},
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestjobs.job_start(
        cfg, "test-vm", "x.exe", ["--token=Arg-canary-77"],
        cred=credentials.resolve_guest(),
    )
    assert (tmp_path / "state.sqlite3").exists()
    needles = []
    for secret in (b"S3cret-canary-pass", b"--token=Arg-canary-77"):
        needles.append(secret)
        needles.append(secret.decode("ascii").encode("utf-16-le"))
    for suffix in ("", "-wal", "-shm"):
        path = tmp_path / ("state.sqlite3" + suffix)
        if not path.exists():
            # Side files may legitimately be absent; the main database was
            # asserted to exist above.
            continue
        data = path.read_bytes()
        for needle in needles:
            assert needle not in data, f"{path.name} persists secret material"


def test_state_db_defaults_under_localappdata(monkeypatch, tmp_path):
    """C9 (AC9): with neither the config key nor HYPERV_MCP_STATE_DB set,
    the store path defaults to <LOCALAPPDATA>/hyperv-mcp/state.db, and
    statestore.open() creates the parent directory. RED at base: Config has
    no state_db_path attribute, so the first access raises
    AttributeError: 'Config' object has no attribute 'state_db_path'."""
    monkeypatch.delenv("HYPERV_MCP_STATE_DB", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    cfg = Config.load({"LOCALAPPDATA": str(tmp_path)})
    assert cfg.state_db_path == os.path.join(str(tmp_path), "hyperv-mcp", "state.db")
    from hyperv_mcp import statestore  # deferred: this file collects at base
    statestore.open(cfg.state_db_path)
    assert os.path.isdir(os.path.join(str(tmp_path), "hyperv-mcp"))
