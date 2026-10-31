"""Non-frozen plan-extras for the Workstream G bundle (trace
31-32-33-94-workstream-g-deployment): the plan-critic-mandated regression
tests that could not live in the frozen files.

  * [PC2/r3] vm_remove ownership: the golden parent is kept even when NO
    other registered VM references it (the frozen C5 leg feeds the parent
    through the usage list; this pin drives the ancestry channel) — and the
    base child is deleted when the attached path is a current .avhdx.
  * [PC7] the _lease_gate name-hint extension: a lease for VM A must not
    authorize clone/create for VM B, and an unleased clone of B conflicts
    with B's lifecycle lease (the pre-existing degenerate gate treated every
    lease row as matching any name-keyed tool).
"""

import contextlib
import json
import os
import time

import pytest

from hyperv_mcp import harvest, media, pswindows
from hyperv_mcp.config import Config

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
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture()
def fresh_server():
    """The repo's fresh_server idiom (tests/unit/test_server.py)."""
    import importlib

    import hyperv_mcp.server as server_module

    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


# ---------------------------------------------------------------------------
# [PC2/r3] ownership: ancestors kept regardless of other-VM usage
# ---------------------------------------------------------------------------

def test_vm_remove_keeps_unreferenced_golden_parent(monkeypatch, tmp_path):
    """The frozen C5 leg keeps the parent via the usage list; this pin drives
    the ANCESTRY channel: the removal leg reports the golden parent as an
    ancestor of the VM's own base disk and the usage list is EMPTY — the
    parent must still never be deleted (plan r3 ownership rule)."""
    child = tmp_path / "vms" / "disk.vhdx"
    avhdx = tmp_path / "vms" / "disk.avhdx"
    parent = tmp_path / "gold" / "parent.vhdx"
    for p in (child, avhdx, parent):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    cfg = Config(allowed_vm_patterns=["test-*"], host_write_roots=[str(tmp_path)])
    cfg.destructive.vm_remove = True
    disks_json = json.dumps({
        "status": "removed",
        # the real host's walk would emit exactly this shape: the avhdx chain
        # + the VM's own base child as disks, the golden parent as ancestor
        "disks": [str(child), str(avhdx)],
        "ancestors": [str(parent)],
    })
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout=disks_json, returncode=0),
        pswindows.PSResult(stdout="merge_complete", returncode=0),
        pswindows.PSResult(stdout="[]", returncode=0),  # usage: NO other VM
    ])
    deleted = []
    real_remove = os.remove

    def spy_remove(path, *args, **kwargs):
        deleted.append(os.path.normcase(str(path)))
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(media.os, "remove", spy_remove)
    out = media.vm_remove(cfg, vm_name="test-vm-1", delete_disks=True, confirm=True)
    assert out["ok"] is True
    nc = lambda p: os.path.normcase(os.path.normpath(str(p)))  # noqa: E731
    assert nc(child) in deleted and nc(avhdx) in deleted, "owned disks deleted"
    assert nc(parent) not in deleted, "the unreferenced golden parent survives"
    kept_reasons = {nc(k["path"]): k["reason"] for k in out["kept"]}
    assert kept_reasons.get(nc(parent)) == "not_owned_ancestor"


def test_vm_remove_deletes_base_child_when_attached_path_is_avhdx(monkeypatch, tmp_path):
    """The r3 boundary: with the ATTACHED path itself a current .avhdx (a
    checkpoint is active), the walk still reaches and owns the base child —
    it is deleted together with the avhdx; only the base's ParentPath
    ancestors are kept."""
    avhdx_attached = tmp_path / "cur.avhdx"
    base_child = tmp_path / "child.vhdx"
    golden = tmp_path / "gold" / "parent.vhdx"
    for p in (avhdx_attached, base_child, golden):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    cfg = Config(allowed_vm_patterns=["test-*"], host_write_roots=[str(tmp_path)])
    cfg.destructive.vm_remove = True
    disks_json = json.dumps({
        "status": "removed",
        "disks": [str(avhdx_attached), str(base_child)],
        "ancestors": [str(golden)],
    })
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout=disks_json, returncode=0),
        pswindows.PSResult(stdout="merge_complete", returncode=0),
        pswindows.PSResult(stdout="[]", returncode=0),
    ])
    deleted = []
    real_remove = os.remove

    def spy_remove(path, *args, **kwargs):
        deleted.append(os.path.normcase(str(path)))
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(media.os, "remove", spy_remove)
    out = media.vm_remove(cfg, vm_name="test-vm-1", delete_disks=True, confirm=True)
    nc = lambda p: os.path.normcase(os.path.normpath(str(p)))  # noqa: E731
    assert nc(avhdx_attached) in deleted and nc(base_child) in deleted, (
        "the VM's own base child is owned even when the attached path is an .avhdx"
    )
    assert nc(golden) not in deleted
    assert out["ok"] is True


# ---------------------------------------------------------------------------
# [PC7] _lease_gate name-hint: leases are VM-specific for name-keyed tools
# ---------------------------------------------------------------------------

def test_lease_for_other_vm_does_not_authorize_clone(fresh_server, tmp_path):
    """A lease granted on VM 'gold-image' must NOT authorize cloning under
    the name 'test-clone-1': the name hint makes authorize VM-specific (the
    pre-extension gate treated every lease row as matching any name-keyed
    tool)."""
    import hyperv_mcp.leases as leases

    doc = {"allowed_vm_patterns": ["test-*", "gold-*"], "leases": {"required": True}}
    cfg_file = tmp_path / "lease-cfg.json"
    cfg_file.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})
    rows = leases.acquire(
        mod._cfg(), "gold-image", ["lifecycle"], "agent-a", vm_name="gold-image")
    row = rows[0]
    env, _present = mod._lease_gate("hyperv_vm_clone", {
        "name": "test-clone-1", "confirm": True,
        "lease_id": row.lease_id, "fencing_token": row.fencing_token,
    })
    assert env is not None and env.get("ok") is False, (
        "a lease for another VM must not authorize this clone"
    )
    assert "lease" in str(env.get("error", "")).lower()


def test_unleased_clone_conflicts_with_lifecycle_lease(fresh_server, tmp_path):
    """Without a presented lease, cloning under a name whose lifecycle lease
    someone else holds must fail the gate (assert_unleased sees the name
    hint); with leases not required the gate stays open as configured."""
    import hyperv_mcp.leases as leases

    doc = {"allowed_vm_patterns": ["test-*"], "leases": {"required": True}}
    cfg_file = tmp_path / "lease-cfg2.json"
    cfg_file.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})
    leases.acquire(
        mod._cfg(), "test-clone-1", ["lifecycle"], "agent-a",
        vm_name="test-clone-1")
    env, _present = mod._lease_gate("hyperv_vm_clone", {
        "name": "test-clone-1", "confirm": True})
    assert env is not None and env.get("ok") is False, (
        "an unleased clone must conflict with the target name's lifecycle lease"
    )


# ---------------------------------------------------------------------------
# Implementation-review round 1 (reviewer findings 1+2): pins for the
# delete-time host_write_roots recheck and the harvest caps.
# ---------------------------------------------------------------------------

def test_vm_remove_out_of_root_candidate_is_kept_not_deleted(monkeypatch, tmp_path):
    """Reviewer finding 1: the frozen C5 fixture never materializes its
    out-of-root candidate, so removing the delete-time root recheck read
    already_gone and the truthy-reason assert still passed. This pin
    MATERIALIZES the file and asserts the exact keep reason AND that it
    survives on disk."""
    import json as _json
    child = tmp_path / "vms" / "disk.vhdx"
    child.parent.mkdir(parents=True, exist_ok=True)
    child.write_bytes(b"x")
    out_of_root = tmp_path.parent / f"vm-remove-out-of-root-{int(time.time() * 1000)}.vhdx"
    out_of_root.write_bytes(b"x")  # materialized: an unguarded delete would remove it
    cfg = Config(allowed_vm_patterns=["test-*"], host_write_roots=[str(tmp_path)])
    cfg.destructive.vm_remove = True
    disks_json = _json.dumps({
        "status": "removed",
        "disks": [str(child), str(out_of_root)],
        "ancestors": [],
    })
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout=disks_json, returncode=0),
        # no .avhdx candidate -> no merge-poll leg; the usage leg is next
        pswindows.PSResult(stdout="[]", returncode=0),
    ])
    deleted = []
    real_remove = os.remove

    def spy_remove(path, *args, **kwargs):
        deleted.append(os.path.normcase(str(path)))
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(media.os, "remove", spy_remove)
    out = media.vm_remove(cfg, vm_name="test-vm-1", delete_disks=True, confirm=True)
    nc = lambda q: os.path.normcase(os.path.normpath(str(q)))  # noqa: E731
    assert nc(child) in deleted
    assert nc(out_of_root) not in deleted, "an out-of-root candidate must never be deleted"
    assert out_of_root.exists(), "the out-of-root file must survive on disk"
    kept_reasons = {nc(k["path"]): k["reason"] for k in out["kept"]}
    assert kept_reasons[nc(out_of_root)] == "outside_host_write_roots"


def test_harvest_caps_are_pinned(monkeypatch, tmp_path):
    """Reviewer finding 2: all three cap layers (robocopy /MAX, the in-script
    running total, the Python re-check) were removable with a green suite.
    This pin asserts the action script carries the per-file and total guards
    and that an over-total payload demotes every file to skipped/cap_exceeded."""
    import json as _json
    cfg = Config(unrestricted=True)
    big = [
        {"path": f"Windows/Panther/setupact.log.{i}", "bytes": 2 * 1024 * 1024 * 1024,
         "sha256": "0" * 64}
        for i in range(3)
    ]
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout="SeBackupPrivilege", returncode=0),
        pswindows.PSResult(stdout=_json.dumps({"files": big, "skipped": []}), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = harvest.harvest_offline_logs(
        cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    # the script-level guards are present in the captured action script
    action = next(s for s in fake.scripts if "Mount-VHD" in s)
    assert "/MAX:$fileMax" in action, "robocopy must carry the per-file /MAX cap"
    assert "-gt $totalMax" in action, "the in-script running-total guard must be present"
    # the Python re-check demotes the over-total tail: with a 2 GiB total
    # cap, the first 2 GiB file fits (boundary inclusive) and the remaining
    # two are demoted to skipped/cap_exceeded
    assert out["ok"] is True
    assert len(out["files"]) == 1, (
        f"only the first in-budget file may survive: {out['files']}")
    reasons = [s["reason"] for s in out["skipped"]]
    assert reasons.count("cap_exceeded") == 2, (
        f"the over-budget tail must be skipped as cap_exceeded: {reasons}")


def test_harvest_missing_reason_for_absent_fixed_entries(monkeypatch, tmp_path):
    """Plan-promised 'missing' skip reason (reviewer question): a fixed
    (non-glob) LOG_PATHS entry that does not exist on the volume is reported
    under skipped with reason 'missing' rather than vanishing."""
    cfg = Config(unrestricted=True)
    events = []
    real_lock = harvest.vmlocks.vm_lock

    @contextlib.contextmanager
    def spy_lock(key, *args, **kwargs):
        events.append(("lock", key))
        with real_lock(key, *args, **kwargs):
            yield

    monkeypatch.setattr(harvest.vmlocks, "vm_lock", spy_lock)
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout="SeBackupPrivilege", returncode=0),
        pswindows.PSResult(stdout='{"files": [], "skipped": []}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    harvest.harvest_offline_logs(
        cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    action = next(s for s in fake.scripts if "Mount-VHD" in s)
    assert "reason = 'missing'" in action, (
        "the action script must emit the 'missing' skip reason for absent fixed entries")


def test_deployment_status_drops_stale_kvp_when_heartbeat_not_ok(monkeypatch):
    """Final-critic round-1 (FC3): the heartbeat-gated KVP view is the entire
    'no stale KVP after a WinPE reboot' mechanism (#32 AC11) — a guest whose
    KVP service stopped can leave the previous OS's pairs lingering while the
    heartbeat reads No Contact. This pin drives that state directly: KVP
    items exist, heartbeat is not OK -> nothing stale may surface."""
    import json as _json

    from hyperv_mcp import readiness as _readiness
    kvp_items = [
        '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
        '<PROPERTY NAME="Name"><VALUE>OSName</VALUE></PROPERTY>'
        '<PROPERTY NAME="Data"><VALUE>Windows Previous OS</VALUE></PROPERTY></INSTANCE>',
        '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
        '<PROPERTY NAME="Name"><VALUE>NetworkAddressIPv4</VALUE></PROPERTY>'
        '<PROPERTY NAME="Data"><VALUE>10.9.9.9</VALUE></PROPERTY></INSTANCE>',
    ]
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout=_json.dumps({
            "state": "Running", "uptime_s": 5, "heartbeat": "No Contact",
            "kvp_items": kvp_items,
        }), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = _readiness.deployment_status(Config(unrestricted=True), vm_name="test-vm-1")
    assert out["phase"] == "no_guest_signal"
    assert out["kvp"]["available"] is False, "stale KVP must not read as available"
    assert out["kvp"]["items"] == {}, "stale KVP pairs must be suppressed"
    assert out["guest"]["ipv4"] == [], "stale addresses must not surface"
    assert out["guest"]["os_name"] == ""
