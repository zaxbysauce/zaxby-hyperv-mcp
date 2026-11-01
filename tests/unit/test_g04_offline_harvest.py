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


# ---------------------------------------------------------------------------
# #33 AC7 — the RICHER evidence-grade manifest (trace
# 55-108-31-32-33-collated; appended by the arm's-length acceptance-check
# author; the functions above are untouched). Frozen canned-row convention
# for the ONE aggregate action script's stdout (the richer provenance shape):
#   {"vm_id": <guid>,
#    "files": [{"volume", "source", "dest", "size", "last_write_utc",
#               "sha256"}],       # sha256 here is PS-side and NOT trusted
#    "missing": [<guest-relative source paths>],
#    "skipped": [{"volume", "reason"}]}
# The manifest's files[].sha256 must be RECOMPUTED IN PYTHON over the copied
# host files (hashlib over the bytes at files[].dest), per-file/total caps
# demote over-budget files to skipped{reason: cap_exceeded} and set the
# manifest-level `truncated` flag.
# ---------------------------------------------------------------------------


def _ac7_rows(dest, entries, missing=(), skipped=(), size_override=None):
    """Canned aggregate-script stdout rows: `entries` are (source_rel,
    payload_bytes) pairs; real files are expected to exist at dest/<rel>."""
    import json as _json

    files = []
    for rel, payload in entries:
        files.append({
            "volume": "\\\\?\\Volume{55108000-0000-0000-0000-000000000001}\\",
            "source": rel,
            "dest": str(dest / rel),
            "size": size_override if size_override is not None else len(payload),
            "last_write_utc": "2026-10-01T00:00:00Z",
            # Deliberately WRONG: the PS-side hash is what the manifest must
            # NOT carry — Python recomputation is the contract under test.
            "sha256": "ps-side-hash-not-trusted-" + rel,
        })
    return _json.dumps({
        "vm_id": GUID,
        "files": files,
        "missing": list(missing),
        "skipped": list(skipped),
    })


def test_harvest_manifest_hashes_match_copies(monkeypatch, tmp_path):
    """#33 AC7: the manifest is evidence-grade — richer keys (vm_id,
    missing, truncated), per-file volume/source/dest/size/last_write_utc
    provenance, and sha256 recomputed IN PYTHON over the copied host files
    (the canned PS-side hashes are deliberately wrong, so a manifest that
    merely forwards them fails); over-cap files land in skipped with reason
    cap_exceeded and the manifest reports truncated."""
    import hashlib

    dest = tmp_path / "out"
    rel1 = "Windows\\Panther\\setupact.log"
    rel2 = "MININT\\SMSOSD\\OSDLOGS\\BDD.log"
    payload1 = b"setupact-content-55-108\n"
    payload2 = b"bdd-content-55-108\n"
    for rel, payload in ((rel1, payload1), (rel2, payload2)):
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    missing_rel = "Windows\\Panther\\setuperr.log"
    locked = {"volume": "\\\\?\\Volume{55108000-0000-0000-0000-000000000002}\\",
              "reason": "volume_locked"}

    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout="SeBackupPrivilege SeShutdownPrivilege",
                           returncode=0),
        pswindows.PSResult(stdout=_ac7_rows(
            dest, [(rel1, payload1), (rel2, payload2)],
            missing=[missing_rel], skipped=[locked]), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = harvest.harvest_offline_logs(cfg, vm_name="test-vm-1", dest_dir=str(dest))

    for key in ("ok", "vm_name", "vm_id", "dest_dir", "files", "missing",
                "skipped", "truncated"):
        assert key in out, f"harvest manifest missing {key!r} (#33 AC7)"
    assert out["vm_id"] == GUID
    assert out["vm_name"] == "test-vm-1"

    listed = {f["source"] for f in out["files"]}
    assert listed == {rel1, rel2}, f"both copied files must be listed: {listed!r}"
    for row in out["files"]:
        for field in ("volume", "source", "dest", "size", "sha256",
                      "last_write_utc"):
            assert field in row, (
                f"files rows must carry {field!r} provenance: {row!r}"
            )
        real = hashlib.sha256(_read(row["dest"])).hexdigest()
        assert row["sha256"] == real, (
            f"sha256 must be recomputed in Python over the copied host file "
            f"({row['source']}); manifest carries {row['sha256']!r} while the "
            f"real copy hashes to {real!r}"
        )

    assert missing_rel in out["missing"], (
        "the absent source path must land in missing[], not skipped[]"
    )
    assert out["skipped"] and all(
        {"volume", "reason"} <= set(s) for s in out["skipped"]), (
        f"skipped rows must be {{volume, reason}} shaped: {out['skipped']!r}"
    )
    assert any(s["reason"] == "volume_locked" for s in out["skipped"])
    assert out["truncated"] is False

    # --- action-script contract (plan-critic round-1 finding 3) ---
    # The script is captured from the recorded PS spy leg (the seam the
    # existing lock test uses — it stays valid whatever builder shape the
    # implementation settles on): the aggregate script must (i) enumerate
    # source sizes over the per-file cap BEFORE any copy runs and emit
    # volume-bearing cap_exceeded skip rows, (ii) emit the per-file
    # provenance fields, and (iii) still carry Get-FileHash (Python
    # recomputes the hash and ignores the PS-side value — the recompute
    # assertions above prove it is not trusted).
    import re as _re

    action = next(s for s in fake.scripts if "Mount-VHD" in s)
    lowered = action.lower()
    assert "Get-FileHash" in action, (
        "the action script keeps a Get-FileHash leg; the manifest hash is "
        "the PYTHON recomputation over the copy, and the PS-side value is "
        "deliberately not trusted"
    )
    for token in ("volume", "source", "dest", "size", "last_write_utc"):
        assert token in lowered, (
            f"the action script must emit {token!r} provenance per copied "
            "file (the richer files[] rows are built from these fields)"
        )
    robocopy_at = lowered.find("robocopy")
    assert robocopy_at != -1, "the action script must contain the copy step"
    screening = [i for i in (lowered.find(".length"), lowered.find("size"))
                 if i != -1]
    assert screening and min(screening) < robocopy_at, (
        "source sizes must be enumerated BEFORE any copy runs, so over-cap "
        "sources are skipped up front instead of partially copied"
    )
    assert "cap_exceeded" in lowered, (
        "the action script must emit cap_exceeded skip rows for over-cap "
        "sources"
    )
    assert _re.search(r"volume\s*=", lowered), (
        "cap_exceeded skip rows must carry the volume they were skipped for"
    )

    # Over-cap file: an oversized reported size is demoted to skipped with
    # reason cap_exceeded and the manifest reports truncated=True.
    oversized_rel = "Windows\\INF\\setupapi.dev.log"
    tiny = dest / oversized_rel
    tiny.parent.mkdir(parents=True, exist_ok=True)
    tiny.write_bytes(b"tiny\n")
    fake2 = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout="SeBackupPrivilege SeShutdownPrivilege",
                           returncode=0),
        pswindows.PSResult(stdout=_ac7_rows(
            dest, [(oversized_rel, b"tiny\n")],
            size_override=128 * 1024 * 1024), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake2)
    out2 = harvest.harvest_offline_logs(
        cfg, vm_name="test-vm-1", dest_dir=str(dest))
    assert [f["source"] for f in out2["files"]] == [], (
        "an over-cap file must not appear in files[]"
    )
    assert any(
        "cap_exceeded" in s["reason"] for s in out2["skipped"]), (
        f"the over-cap file must land in skipped with reason cap_exceeded: "
        f"{out2['skipped']!r}"
    )
    assert out2["truncated"] is True


def _read(path):
    from pathlib import Path

    return Path(path).read_bytes()
