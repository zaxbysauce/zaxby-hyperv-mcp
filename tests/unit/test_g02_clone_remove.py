"""Frozen acceptance checks for issue #31 (vm_clone / vm_remove), legs AC1,
AC2 and the vm_clone half of AC4.

Arm's-length authoring (trace 31-32-33-94-workstream-g-deployment, tier L):
these tests were written from the POST-FIX API CONTRACT only, never from an
implementation, and are frozen — the implementation phase makes them green.

Contract asserted here (per the issue's acceptance criteria):
  * media.vm_clone(cfg, name, parent_vhd_path, vhd_path, memory_mb=2048,
    cpu_count=1, generation=2, switch_name="", confirm=False):
      - _checked_new_name allowlist, then policy.require_destructive(
        cfg, "vm_provision", confirm, ...) — clone is a provision op;
      - parent validated read/must_exist (.vhdx/.vhd), child validated
        write/must-not-exist, parent and child share the extension;
      - ONE script under vmlocks.vm_lock(name) containing, IN ORDER: the
        vm_create duplicate-name CIM guard (Msvm_ComputerSystem + literal
        ElementName -eq + GUID-shape Name + "VM name already exists"), the
        parent-not-attached refusal (Get-VMHardDiskDrive path match ->
        throw naming the attached VM/'attached'), New-VHD -Differencing
        -ParentPath with NO -SizeBytes, New-VM on the child inside the same
        try/catch orphan-cleanup (Remove-Item -LiteralPath on failure),
        optional switch connect, JSON emit;
      - Python marks a writable parent read-only BEFORE running the script
        (chmod/stat.S_IWRITE) and reports parent_made_read_only true/false;
      - returns {ok, id, name, state, generation, vhd_path,
        parent_vhd_path, parent_made_read_only}.
  * config.DestructivePolicy gains vm_remove: bool = False, accepted by
    Config.from_dict, deny-by-default.
  * server registers hyperv_vm_clone (name-only + confirm) and
    hyperv_vm_remove (vm_name|vm_id + confirm + lease_id/fencing_token);
    tool inventory 76 -> 80.

Frozen response conventions for the vm_remove legs (AC5; documented so the
implementation phase can conform):
  * media.vm_remove(cfg, vm_name="", vm_id="", delete_disks=False,
    confirm=False) resolves via vmident.resolve (by-name leg emits the bare
    GUID; by-id leg emits the bare NAME), then runs a PYTHON-side state gate
    BEFORE any removal script is generated: a leg carrying the
    _resolve_vm_prefix preamble whose stdout is the bare state string
    ("Off"/"Running"). A non-Off state raises MediaError (media's existing
    error path) naming the state, 'Off' and hyperv_stop_vm — so no script
    containing Remove-VM is ever emitted for a running VM.
  * The ONE removal script (delete_disks=False) opens with the
    _resolve_vm_prefix preamble ("$vmTarget = '<guid>'" +
    "$vm = Get-VM -Id $vmTarget"), collects disk candidates
    (Get-VMHardDiskDrive + the checkpoint avhdx chain), removes via
    "Remove-VM -VM $vm" (NEVER "Remove-VM -Name") and emits JSON
    {"status": "removed", "disks": [<candidate paths>]}. With
    delete_disks=False no deletion leg runs (no Remove-Item anywhere, no
    Python-side file deletion) and the result is
    {ok, status: "removed", vm_name}.
  * With delete_disks=True: a bounded merge wait polls (each poll leg's
    stdout is the bare marker "merge_pending" or "merge_complete") under the
    module-level bound media._MERGE_WAIT_S (float seconds); on timeout the
    result is ok=False, error_class "timeout", retryable True, and the
    blocked candidates land in kept with reason "merge_pending" (reported,
    never raised). Then a usage leg (JSON list of paths) reports disk paths
    still referenced by OTHER registered VMs; PYTHON then deletes only the
    owned candidates inside host_write_roots and absent from that usage list
    (deletion via media's os.remove) and returns
    {ok, status, vm_name, deleted: [...], kept: [{path, reason}, ...]}.
"""

import asyncio
import importlib
import json
import os
import stat as stat_mod

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import media, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.media import MediaError
from hyperv_mcp.policy import PolicyDenied

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


def _guid_res() -> pswindows.PSResult:
    """The by-name vmident resolution leg's canned answer (bare GUID)."""
    return pswindows.PSResult(stdout=GUID, returncode=0)


class FakePS:
    """Queue pswindows.run_ps responses; record every generated script."""

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
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture()
def fresh_server():
    """The repo's fresh_server idiom (tests/unit/test_server.py): reload the
    server module and bootstrap it with the given environ snapshot."""
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod
    yield make
    importlib.reload(server_module)


def _schemas(mod):
    mcp = mod.get_mcp()
    tools = asyncio.run(mcp.list_tools())
    # mcp 1.x Tool exposes inputSchema; 2.x exposes input_schema.
    return {t.name: (getattr(t, "input_schema", None) or t.inputSchema) for t in tools}


# ---------------------------------------------------------------------------
# AC1 — tool registration (76 -> 80, confirm carried, vm_remove by name|id)
# ---------------------------------------------------------------------------

def test_clone_and_remove_tools_registered_with_confirm(fresh_server):
    """RED/ERROR at base (neither tool exists in the 76-tool inventory),
    GREEN after the fix."""
    mod = fresh_server({})
    schemas = _schemas(mod)
    missing = [t for t in ("hyperv_vm_clone", "hyperv_vm_remove") if t not in schemas]
    assert missing == [], f"unregistered tools: {missing}"
    assert len(schemas) == 80, (
        f"tool inventory is {len(schemas)} tools; expected 80 "
        "(76 plus hyperv_vm_clone, hyperv_vm_remove, hyperv_deployment_status, "
        "hyperv_harvest_offline_logs)"
    )
    clone_props = schemas["hyperv_vm_clone"].get("properties", {})
    remove_props = schemas["hyperv_vm_remove"].get("properties", {})
    # clone is a provision op: the human prompt is mandatory
    assert "confirm" in clone_props, "hyperv_vm_clone must carry confirm"
    assert "confirm" in remove_props, "hyperv_vm_remove must carry confirm"
    # clone CREATES a VM from a fresh name (vm_create's name-only shape);
    # remove ADDRESSES one, so it takes the name|id pair like every VM tool
    assert "name" in clone_props
    assert "vm_id" not in clone_props, (
        "hyperv_vm_clone creates a VM; it must not pretend to address one by GUID"
    )
    assert "vm_name" in remove_props
    assert "vm_id" in remove_props, "hyperv_vm_remove must accept vm_id"
    # removal is a lease-fenced mutation like every other destructive op
    assert "lease_id" in remove_props
    assert "fencing_token" in remove_props


# ---------------------------------------------------------------------------
# AC2 — destructive.vm_remove config category
# ---------------------------------------------------------------------------

def test_config_accepts_vm_remove_category():
    """RED/ERROR at base (ConfigError: unknown destructive key 'vm_remove'),
    GREEN after the fix."""
    cfg = Config.from_dict({"destructive": {"vm_remove": True}})
    assert cfg.destructive.vm_remove is True
    # deny-by-default: an untouched config (and the JSON default path) leaves
    # the switch off, same as every other destructive category
    assert Config.from_dict({"schema_version": 1}).destructive.vm_remove is False
    assert Config().destructive.vm_remove is False


# ---------------------------------------------------------------------------
# AC4 — vm_clone script shape (the vm_create idiom, differencing-disk variant)
# ---------------------------------------------------------------------------

def test_vm_clone_script_shape(monkeypatch, unrestricted, tmp_path):
    """RED/ERROR at base (AttributeError: media has no vm_clone), GREEN after
    the fix."""
    parent = tmp_path / "gold" / "parent.vhdx"
    parent.parent.mkdir(parents=True, exist_ok=True)
    parent.write_bytes(b"golden-image")
    child = tmp_path / "clones" / "child.vhdx"
    fake = FakePS([pswindows.PSResult(
        stdout='{"id": "GUID-2", "name": "test-vm-2", "state": "Off", "generation": 2}',
        returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_clone(
        unrestricted, "test-vm-2", str(parent), str(child), confirm=True,
    )
    assert out["ok"] and out["id"] == "GUID-2"
    # ONE script under the lock (vm_clone is name-based like vm_create: no
    # vmident resolution leg)
    assert len(fake.scripts) == 1
    script = fake.scripts[0]
    # duplicate-name guard: vm_create's full CIM predicate, BEFORE anything
    # is created
    assert "Msvm_ComputerSystem" in script and "VM name already exists" in script
    assert "($_.ElementName -eq 'test-vm-2')" in script  # literal -eq, ps_quote
    assert "-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'" in script  # GUID-shape Name half
    # parent-not-attached refusal: probe attached disks, throw naming the
    # hazard — and it precedes the differencing-disk creation
    assert "Get-VMHardDiskDrive" in script
    assert "ttached" in script, "the refusal must name the attached hazard"
    # differencing child of the golden parent: no size of its own
    assert "New-VHD -Path" in script
    assert "-ParentPath" in script and "-Differencing" in script
    assert "-SizeBytes" not in script, "a differencing disk must not size itself"
    # ordering: guard -> attached refusal -> New-VHD -> New-VM
    assert script.index("Msvm_ComputerSystem") < script.index("Get-VMHardDiskDrive")
    assert script.index("Get-VMHardDiskDrive") < script.index("New-VHD -Path")
    assert "New-VM -Name 'test-vm-2'" in script
    assert str(parent) in script and str(child) in script
    # the orphan-cleanup pattern carried over from vm_create: a failed New-VM
    # removes the staged child differencing disk
    assert script.index("try {") < script.index("New-VM -Name")
    assert "Remove-Item -LiteralPath" in script.split("} catch {", 1)[1]
    # result contract keys (both paths + the read-only flag)
    for key in ("ok", "id", "name", "state", "generation", "vhd_path",
                "parent_vhd_path", "parent_made_read_only"):
        assert key in out, f"vm_clone result missing {key!r}"
    assert out["vhd_path"] == os.path.normpath(str(child))
    assert out["parent_vhd_path"] == os.path.normpath(str(parent))


def test_vm_clone_refuses_attached_parent(monkeypatch, unrestricted, tmp_path):
    """The in-script attached-parent refusal surfaces as a MediaError naming
    the attached VM (driven by queuing the PowerShell failure the script's own
    throw produces). RED/ERROR at base, GREEN after the fix."""
    parent = tmp_path / "parent.vhdx"
    parent.write_bytes(b"x")
    fake = FakePS([pswindows.PSResult(
        returncode=1,
        stderr="Get-VMHardDiskDrive : 'parent.vhdx' is already attached to VM 'gold-vm'",
    )])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(MediaError, match="gold-vm"):
        media.vm_clone(
            unrestricted, "test-vm-2", str(parent), str(tmp_path / "c.vhdx"),
            confirm=True,
        )
    assert len(fake.scripts) == 1
    script = fake.scripts[0]
    # the probe is real and runs before anything is created on the host
    assert "Get-VMHardDiskDrive" in script
    assert script.index("Get-VMHardDiskDrive") < script.index("New-VHD -Path")


# ---------------------------------------------------------------------------
# AC4 — vm_clone policy gates and the read-only golden parent
# ---------------------------------------------------------------------------

def test_vm_clone_name_must_match_allowlist():
    """RED/ERROR at base, GREEN after the fix: a NEW VM name outside
    allowed_vm_patterns would create an unmanageable, out-of-policy VM."""
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(PolicyDenied, match="allowed_vm_patterns"):
        media.vm_clone(
            cfg, "prod-db-1",
            parent_vhd_path="C:\\x\\parent.vhdx",
            vhd_path="C:\\x\\child.vhdx",
            confirm=True,
        )


def test_vm_clone_child_outside_write_roots_denied(tmp_path):
    """RED/ERROR at base, GREEN after the fix: the child VHD is a host WRITE
    (New-VHD creates it), so it must sit inside host_write_roots."""
    parent = tmp_path / "parent.vhdx"
    parent.write_bytes(b"x")
    cfg = Config(
        allowed_vm_patterns=["test-*"],
        host_read_roots=[str(tmp_path)],          # parent is a read
        host_write_roots=[str(tmp_path / "allowed")],  # child is a write
    )
    cfg.destructive.vm_provision = True
    cfg.destructive.require_confirm = False
    with pytest.raises(PolicyDenied, match="host write"):
        media.vm_clone(
            cfg, "test-vm-2", str(parent),
            str(tmp_path / "elsewhere" / "child.vhdx"), confirm=True,
        )


def test_vm_clone_marks_parent_read_only(monkeypatch, unrestricted, tmp_path):
    """RED/ERROR at base, GREEN after the fix: a writable golden parent is
    chmod'd read-only BEFORE the script runs (os.stat + stat.S_IWRITE, so the
    check works on Linux CI too); an already-read-only parent reports
    parent_made_read_only=False instead of claiming work it skipped."""
    parent = tmp_path / "gold.vhdx"
    parent.write_bytes(b"gold")
    assert os.stat(parent).st_mode & stat_mod.S_IWRITE, "fixture: parent starts writable"
    ok_json = '{"id": "G-1", "name": "test-vm-2", "state": "Off", "generation": 2}'
    fake = FakePS([
        pswindows.PSResult(stdout=ok_json, returncode=0),
        pswindows.PSResult(stdout=ok_json, returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_clone(
        unrestricted, "test-vm-2", str(parent), str(tmp_path / "c1.vhdx"),
        confirm=True,
    )
    assert out["parent_made_read_only"] is True
    assert os.stat(parent).st_mode & stat_mod.S_IWRITE == 0, (
        "the golden parent must be read-only after the call"
    )
    # second clone from the now-read-only parent: no chmod work to do
    out2 = media.vm_clone(
        unrestricted, "test-vm-2", str(parent), str(tmp_path / "c2.vhdx"),
        confirm=True,
    )
    assert out2["parent_made_read_only"] is False


# ---------------------------------------------------------------------------
# AC5 — vm_remove module behavior (issue #31 AC8/AC9 unit legs)
# ---------------------------------------------------------------------------

def test_vm_remove_addresses_vm_by_id(monkeypatch, unrestricted):
    """RED/ERROR at base (AttributeError: media has no vm_remove), GREEN
    after the fix: removal addresses the VM through the resolved GUID
    (_resolve_vm_prefix binding + Remove-VM -VM $vm), never by name; with
    delete_disks=False no deletion leg runs at all."""
    fake = FakePS([
        # by-id vmident leg emits the resolved NAME (bare final line)
        pswindows.PSResult(stdout="test-vm-1", returncode=0),
        # state gate: bare state string
        pswindows.PSResult(stdout="Off", returncode=0),
        # removal leg JSON
        pswindows.PSResult(
            stdout='{"status": "removed", "disks": []}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_remove(unrestricted, vm_id=GUID, confirm=True)
    assert out["ok"] is True
    assert out["status"] == "removed"
    assert out["vm_name"] == "test-vm-1"
    # resolution + state gate + ONE removal script — nothing else
    assert len(fake.scripts) == 3
    removal = fake.scripts[-1]
    assert f"$vmTarget = '{GUID}'" in removal, (
        "the removal script must open with the validated GUID binding"
    )
    assert "$vm = Get-VM -Id $vmTarget" in removal, (
        "the _resolve_vm_prefix preamble must bind $vm by Id"
    )
    assert "Remove-VM -VM $vm" in removal
    assert "Remove-VM -Name" not in removal, (
        "name-based removal is forbidden (wildcard/ambiguity hazard)"
    )
    assert "Get-VMHardDiskDrive" in removal, "candidates are collected"
    # delete_disks=False: no disk-file deletion anywhere
    assert not [s for s in fake.scripts if "Remove-Item" in s], (
        "no deletion leg may run with delete_disks=False"
    )
    assert out.get("deleted", []) in ([], None)


def test_vm_remove_refuses_non_off_vm(monkeypatch, unrestricted):
    """RED/ERROR at base (AttributeError: media has no vm_remove), GREEN
    after the fix: a Running VM is refused (MediaError — media's existing
    error path) naming the state, Off, and hyperv_stop_vm, BEFORE any
    removal script exists."""
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Running", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(MediaError) as excinfo:
        media.vm_remove(unrestricted, vm_name="test-vm-1", confirm=True)
    msg = str(excinfo.value)
    assert "Off" in msg and "Running" in msg
    assert "hyperv_stop_vm" in msg, "the refusal must point at the stop tool"
    assert not [s for s in fake.scripts if "Remove-VM -VM" in s], (
        "no script may carry the removal cmdlet for a non-Off VM"
    )


def test_vm_remove_delete_disks_keeps_parent_and_deletes_only_owned(monkeypatch, tmp_path):
    """RED/ERROR at base (AttributeError: media has no vm_remove), GREEN
    after the fix: only the removed VM's OWN disks (child vhdx + avhdx chain)
    are deleted; the golden parent (referenced by another registered VM) and
    any out-of-root candidate are kept with reasons."""
    child = tmp_path / "vms" / "test-vm-1" / "disk.vhdx"
    avhdx = tmp_path / "vms" / "test-vm-1" / "disk.avhdx"
    parent = tmp_path / "gold" / "parent.vhdx"
    for p in (child, avhdx, parent):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    out_of_root = tmp_path.parent / "vm-remove-out-of-root.vhdx"
    cfg = Config(
        allowed_vm_patterns=["test-*"],
        host_write_roots=[str(tmp_path)],
    )
    cfg.destructive.vm_remove = True
    disks_json = json.dumps({
        "status": "removed",
        "disks": [str(child), str(avhdx), str(parent), str(out_of_root)],
    })
    fake = FakePS([
        _guid_res(),                                  # vmident resolve
        pswindows.PSResult(stdout="Off", returncode=0),   # state gate
        pswindows.PSResult(stdout=disks_json, returncode=0),  # removal + candidates
        pswindows.PSResult(stdout="merge_complete", returncode=0),  # merge poll
        pswindows.PSResult(stdout=json.dumps([str(parent)]), returncode=0),  # usage
    ])
    deleted = []
    real_remove = os.remove

    def spy_remove(path, *args, **kwargs):
        deleted.append(os.path.normcase(str(path)))
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(media.os, "remove", spy_remove)
    out = media.vm_remove(
        cfg, vm_name="test-vm-1", delete_disks=True, confirm=True)
    assert out["ok"] is True
    nc = lambda p: os.path.normcase(os.path.normpath(str(p)))  # noqa: E731
    # owned child + checkpoint avhdx deleted...
    assert nc(child) in deleted and nc(avhdx) in deleted
    assert nc(child) in [nc(p) for p in out["deleted"]]
    assert nc(avhdx) in [nc(p) for p in out["deleted"]]
    # ...the golden parent NEVER (neither on disk-listing nor in deleted)
    assert nc(parent) not in deleted
    assert nc(parent) not in [nc(p) for p in out["deleted"]]
    # out-of-root candidate kept with a reason; parent kept with a reason
    kept_paths = {nc(k["path"]) for k in out["kept"]}
    kept_reasons = {nc(k["path"]): k["reason"] for k in out["kept"]}
    assert nc(out_of_root) in kept_paths
    assert nc(parent) in kept_paths
    assert kept_reasons[nc(out_of_root)], "kept entries must carry a reason"
    assert kept_reasons[nc(parent)], "kept entries must carry a reason"


def test_vm_remove_merge_wait_timeout_is_reported_not_raised(monkeypatch, tmp_path):
    """RED/ERROR at base (AttributeError: media has no vm_remove), GREEN
    after the fix: a merge that stays pending past the bound is REPORTED —
    ok False, error_class "timeout", retryable True, the blocked candidate
    kept with reason "merge_pending" — never raised, and nothing is deleted.
    The bound seam is the module-level media._MERGE_WAIT_S (seconds), patched
    to 0 here; the poll legs keep answering "merge_pending"."""
    child = tmp_path / "disk.vhdx"
    child.write_bytes(b"x")
    avhdx = tmp_path / "disk.avhdx"
    avhdx.write_bytes(b"x")
    disks_json = json.dumps({
        "status": "removed", "disks": [str(child), str(avhdx)],
    })
    pending = [pswindows.PSResult(stdout="merge_pending", returncode=0)
               for _ in range(12)]
    fake = FakePS([
        _guid_res(),                                      # vmident resolve
        pswindows.PSResult(stdout="Off", returncode=0),   # state gate
        pswindows.PSResult(stdout=disks_json, returncode=0),  # removal + candidates
        *pending,                                         # merge polls stay pending
    ])
    deleted = []
    real_remove = os.remove

    def spy_remove(path, *args, **kwargs):
        deleted.append(os.path.normcase(str(path)))
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(media.os, "remove", spy_remove)
    # raising=False keeps the base-leg signature uniform (the call itself
    # raises the vm_remove AttributeError first); at head the seam must exist
    # or the result assertions below fail.
    monkeypatch.setattr(media, "_MERGE_WAIT_S", 0, raising=False)
    out = media.vm_remove(
        Config(unrestricted=True), vm_name="test-vm-1",
        delete_disks=True, confirm=True,
    )
    assert out["ok"] is False
    assert out["error_class"] == "timeout"
    assert out["retryable"] is True
    assert out.get("deleted", []) == [] and deleted == []
    nc = lambda p: os.path.normcase(os.path.normpath(str(p)))  # noqa: E731
    merge_kept = [k for k in out["kept"] if k["reason"] == "merge_pending"]
    assert merge_kept, "the pending candidate must be kept with reason merge_pending"
    assert nc(merge_kept[0]["path"]) in (nc(child), nc(avhdx))
