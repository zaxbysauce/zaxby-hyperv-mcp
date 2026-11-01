"""Frozen acceptance checks for issue #33 (offline log harvest), legs AC14,
AC15, AC16, AC17.

Arm's-length authoring (trace 31-32-33-94-workstream-g-deployment, tier L):
written from the POST-FIX API CONTRACT only; frozen — the implementation
phase makes them green. The module-level `from hyperv_mcp import harvest`
makes every check in this file an ERROR-at-base (ImportError) until the new
module exists; that is the frozen base signature.

Frozen response conventions asserted here (documented so the implementation
phase can conform):
  * harvest_offline_logs resolves the target with vmident.resolve (the
    standard by-name leg), then a state-gate leg whose stdout is the bare
    state string ("Off"/"Running"), then the SeBackup privilege precheck leg
    whose stdout lists the session privileges (no "SeBackupPrivilege" in it
    -> refusal), then ONE action script (mount/copy/hash/dismount with a
    finally).
  * The action script emits JSON with at least {"files": [...], "skipped":
    [...]} and the tool assembles {ok, dest_dir, files, skipped, vm_name}.
"""

import contextlib
import importlib

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import harvest, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.policy import PolicyDenied

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


def _guid_res() -> pswindows.PSResult:
    return pswindows.PSResult(stdout=GUID, returncode=0)


class FakePS:
    def __init__(self, responses=()):
        self.scripts = []
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        item = self.responses.pop(0) if self.responses else pswindows.PSResult(
            stdout='{"ok": true}', returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def fresh_server():
    """The repo's fresh_server idiom (tests/unit/test_server.py)."""
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod
    yield make
    importlib.reload(server_module)


def _schemas(mod):
    import asyncio
    mcp = mod.get_mcp()
    tools = asyncio.run(mcp.list_tools())
    return {t.name: (getattr(t, "input_schema", None) or t.inputSchema) for t in tools}


# ---------------------------------------------------------------------------
# AC14 — tool registration + the offline_harvest config category
# ---------------------------------------------------------------------------

def test_harvest_tool_registered(fresh_server):
    """RED/ERROR at base (ImportError: harvest; then the tool is absent),
    GREEN after the fix: vm_name|vm_id addressing, category-gated with NO
    confirm and NO credential params."""
    mod = fresh_server({})
    schemas = _schemas(mod)
    assert "hyperv_harvest_offline_logs" in schemas, (
        "hyperv_harvest_offline_logs must be registered (76 -> 80 tools)"
    )
    props = schemas["hyperv_harvest_offline_logs"].get("properties", {})
    assert "vm_name" in props and "vm_id" in props
    assert "confirm" not in props, (
        "the gate is the offline_harvest category, not a per-call prompt"
    )
    assert "username" not in props and "password" not in props, (
        "offline harvest never enters the guest: no credential params"
    )


def test_config_accepts_offline_harvest_category(monkeypatch, tmp_path):
    """RED/ERROR at base (ImportError: harvest; then ConfigError: unknown
    destructive key 'offline_harvest'), GREEN after the fix: accepted by
    Config.from_dict, deny-by-default, denial shape category:offline_harvest."""
    cfg = Config.from_dict({"destructive": {"offline_harvest": True}})
    assert cfg.destructive.offline_harvest is True
    assert Config.from_dict({"schema_version": 1}).destructive.offline_harvest is False
    assert Config().destructive.offline_harvest is False
    # denial shape: the category gate fires (before any PowerShell) when the
    # switch is off, even with a writable dest and an allowed VM name
    off = Config(
        allowed_vm_patterns=["test-*"],
        host_write_roots=[str(tmp_path / "out")],
    )
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied, match=r"category:offline_harvest"):
        harvest.harvest_offline_logs(
            off, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    assert fake.scripts == []


# ---------------------------------------------------------------------------
# AC15 — refuse before mounting; dest under host_write_roots
# ---------------------------------------------------------------------------

def test_harvest_refuses_running_vm_before_mount(monkeypatch, tmp_path):
    """RED/ERROR at base (ImportError: harvest), GREEN after the fix: any
    state except Off is refused with HarvestError naming the state AND Off,
    before any Mount-VHD exists."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Running", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(harvest.HarvestError, match="Off") as excinfo:
        harvest.harvest_offline_logs(
            cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    assert "Running" in str(excinfo.value), (
        "the refusal must name the offending state"
    )
    assert not [s for s in fake.scripts if "Mount-VHD" in s], (
        "no script may mount when the VM is not Off"
    )


def test_harvest_dest_outside_write_roots_denied(monkeypatch, tmp_path):
    """RED/ERROR at base (ImportError: harvest), GREEN after the fix:
    check_host_write(dest_dir) runs BEFORE any PowerShell."""
    cfg = Config(
        allowed_vm_patterns=["test-*"],
        host_write_roots=[str(tmp_path / "allowed")],
    )
    cfg.destructive.offline_harvest = True
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied, match="host write"):
        harvest.harvest_offline_logs(
            cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "elsewhere"))
    assert fake.scripts == [], "the write-root denial must precede any spawn"


# ---------------------------------------------------------------------------
# AC16 — the fixed documented log set
# ---------------------------------------------------------------------------

def test_harvest_log_set_covers_setup_mdt_and_task_sequence():
    """RED/ERROR at base (ImportError: harvest), GREEN after the fix:
    LOG_PATHS is the frozen guest-relative set from the issue (setup/MDT/
    SCCM task-sequence logs), compared case-insensitively and
    separator-agnostically; the two MDT directories also carry *.log globs."""
    assert isinstance(harvest.LOG_PATHS, frozenset)
    folded = {p.replace("/", "\\").casefold() for p in harvest.LOG_PATHS}
    required = [
        # Windows setup ($WINDOWS.~BT + committed Panther)
        r"$windows.~bt\sources\panther\setupact.log",
        r"$windows.~bt\sources\panther\setuperr.log",
        r"windows\panther\setupact.log",
        r"windows\panther\setuperr.log",
        r"windows\panther\unattendgc\setupact.log",
        r"windows\inf\setupapi.dev.log",
        # MDT (MININT LTI + SMS/OSD deployment logs)
        r"minint\smsosd\osdlogs\bdd.log",
        r"minint\smsosd\osdlogs\*.log",
        r"windows\temp\deploymentlogs\bdd.log",
        r"windows\temp\deploymentlogs\*.log",
        # SCCM task sequences (both the SMSTS-in-TS and committed CCM homes)
        r"_smstasksequence\logs\smstslog\smsts.log",
        r"windows\ccm\logs\smstslog\smsts.log",
        r"windows\ccm\logs\smsts.log",
        r"windows\system32\ccm\logs\smsts.log",
        r"smstslog\smsts.log",
    ]
    missing = [p for p in required if p not in folded]
    assert missing == [], f"LOG_PATHS is missing: {missing}"


# ---------------------------------------------------------------------------
# AC17 — exclusive lock across mount..dismount; remote + privilege refusals
# ---------------------------------------------------------------------------

def test_harvest_holds_exclusive_lock_and_dismounts_in_finally(monkeypatch, tmp_path):
    """RED/ERROR at base (ImportError: harvest), GREEN after the fix: the
    per-VM write lock (keyed on the resolved GUID) is held across the whole
    mount..dismount span, and the ONE action script mounts read-only with no
    drive letter, robocopies with backup semantics, hashes every file and
    dismounts in a finally."""
    cfg = Config(unrestricted=True)
    events = []
    real_lock = harvest.vmlocks.vm_lock

    @contextlib.contextmanager
    def spy_lock(key, *args, **kwargs):
        events.append(("lock", key))
        with real_lock(key, *args, **kwargs):
            yield
        events.append(("unlock", key))

    responses = [
        _guid_res(),                                                    # vmident resolve
        pswindows.PSResult(stdout="Off", returncode=0),                 # state gate
        pswindows.PSResult(stdout="SeBackupPrivilege SeShutdownPrivilege",
                           returncode=0),                               # privilege precheck
        pswindows.PSResult(stdout='{"files": [], "skipped": []}',
                           returncode=0),                               # action leg
    ]

    def spy_run_ps(script, **kwargs):
        events.append(("script", script))
        item = responses.pop(0) if responses else pswindows.PSResult(
            stdout='{"ok": true}', returncode=0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(harvest.vmlocks, "vm_lock", spy_lock)
    monkeypatch.setattr(pswindows, "run_ps", spy_run_ps)
    out = harvest.harvest_offline_logs(
        cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    assert out["ok"]
    for key in ("ok", "dest_dir", "files", "skipped", "vm_name"):
        assert key in out, f"harvest result missing {key!r}"
    # the action script shape: read-only, no drive letter, backup copy,
    # per-file hash, and the dismount/access-path removal
    scripts = [e[1] for e in events if e[0] == "script"]
    action = next(s for s in scripts if "Mount-VHD" in s)
    assert "Mount-VHD -Path" in action and "-ReadOnly" in action
    assert "-NoDriveLetter" in action
    lowered = action.lower()
    assert "robocopy" in lowered and " /b" in lowered, (
        "copies must run with backup semantics (robocopy /B)"
    )
    assert "/r:0" in lowered and "/w:0" in lowered
    assert "Get-FileHash" in action
    assert "Remove-PartitionAccessPath" in action
    assert "Dismount-VHD" in action
    assert "finally" in lowered, "the dismount must live in a finally block"
    # lock ordering: acquired before the mount leg, released after the
    # dismount leg (the vmident resolution leg necessarily precedes the lock
    # because the lock key IS the resolved GUID)
    lock_idx = [i for i, e in enumerate(events) if e[0] == "lock"]
    unlock_idx = [i for i, e in enumerate(events) if e[0] == "unlock"]
    mount_idx = [i for i, e in enumerate(events)
                 if e[0] == "script" and "Mount-VHD" in e[1]]
    dismount_idx = [i for i, e in enumerate(events)
                    if e[0] == "script" and "Dismount-VHD" in e[1]]
    assert len(lock_idx) == 1 and events[lock_idx[0]][1] == GUID, (
        "exactly one per-VM lock, keyed on the resolved VM GUID"
    )
    assert mount_idx and dismount_idx
    assert lock_idx[0] < mount_idx[0], "the lock must precede the mount leg"
    assert unlock_idx[0] > dismount_idx[-1], (
        "the lock must outlive the dismount leg"
    )


def test_harvest_refuses_remote_host(monkeypatch, tmp_path):
    """RED/ERROR at base (ImportError: harvest), GREEN after the fix: a
    remote-host config is refused with HarvestError naming remote (the
    media._reject_remote_file_ops shape) before any PowerShell."""
    cfg = Config.from_dict({
        "unrestricted": True,
        "hyperv": {"host": "nuc01"},
    })
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(harvest.HarvestError, match="remote"):
        harvest.harvest_offline_logs(
            cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    assert fake.scripts == [], (
        "the remote-host refusal must precede any PowerShell"
    )


def test_harvest_requires_backup_privilege(monkeypatch, tmp_path):
    """RED/ERROR at base (ImportError: harvest), GREEN after the fix: the
    SeBackup privilege precheck runs BEFORE any mount; a session without
    SeBackupPrivilege (empty privilege listing) is refused with HarvestError
    naming SeBackupPrivilege and no Mount-VHD is ever generated."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout="", returncode=0),  # privileges: none listed
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(harvest.HarvestError, match="SeBackupPrivilege"):
        harvest.harvest_offline_logs(
            cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    assert not [s for s in fake.scripts if "Mount-VHD" in s], (
        "no mount may run without SeBackupPrivilege"
    )
