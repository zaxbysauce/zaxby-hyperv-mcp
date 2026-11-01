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

import pytest

from hyperv_mcp import harvest, media, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.media import MediaError

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
    the name 'test-clone-1': the name hint makes authorize VM-specific.
    Review H5: the pin must reach matches_hint — the lease holder is the
    SAME principal the gate presents in-process (None), so ownership passes
    and the VM-mismatch is what refuses; the assertion demands the exact
    different-VM conflict text. (Mutant check 2026-10-31: reverting the
    name-fallback makes this gate PASS the call — the test fails.)"""
    import hyperv_mcp.leases as leases

    doc = {"allowed_vm_patterns": ["test-*", "gold-*"], "leases": {"required": False}}
    cfg_file = tmp_path / "lease-cfg.json"
    cfg_file.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})
    rows = leases.acquire(
        mod._cfg(), "gold-image", ["lifecycle"], None, vm_name="gold-image")
    row = rows[0]
    env, _present = mod._lease_gate("hyperv_vm_clone", {
        "name": "test-clone-1", "confirm": True,
        "lease_id": row.lease_id, "fencing_token": row.fencing_token,
    })
    assert env is not None and env.get("ok") is False, (
        "a lease for another VM must not authorize this clone"
    )
    assert "different VM" in str(env.get("error", "")), (
        f"the refusal must be the hint mismatch, not another refusal: "
        f"{env.get('error')!r}")


def test_unleased_clone_conflicts_with_lifecycle_lease(fresh_server, tmp_path):
    """Without a presented lease (and with leases NOT required, so the
    required short-circuit cannot answer for us), cloning under a name whose
    lifecycle lease is held must fail via assert_unleased seeing the NAME
    HINT (review H5: the old pin short-circuited at lease_required and the
    hint path was never executed; reverting the name-fallback makes this
    gate pass the call and the test fail)."""
    import hyperv_mcp.leases as leases

    doc = {"allowed_vm_patterns": ["test-*"], "leases": {"required": False}}
    cfg_file = tmp_path / "lease-cfg2.json"
    cfg_file.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})
    leases.acquire(
        mod._cfg(), "test-clone-1", ["lifecycle"], None,
        vm_name="test-clone-1")
    env, _present = mod._lease_gate("hyperv_vm_clone", {
        "name": "test-clone-1", "confirm": True})
    assert env is not None and env.get("ok") is False, (
        "an unleased clone must conflict with the target name's lifecycle lease"
    )
    assert "different VM" not in str(env.get("error", ""))


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
    # L9 (review): per-test out-of-root location — OUTSIDE host_write_roots
    # (that is the point of the pin) but uniquely named for THIS test
    # (tmp_path.name is unique per test; the old fixed name collided across
    # runs in the shared session dir). tmp_path.parent is the session temp
    # root, never inside the write root.
    out_of_root = tmp_path.parent / (tmp_path.name + "-out-of-root.vhdx")
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
def test_vm_clone_applies_cpu_count(monkeypatch, unrestricted, tmp_path):
    """Review M14: the clone path honors cpu_count exactly like vm_create —
    the leg must be present, carry the requested count, and sit after
    New-VM (a hard-coded count or a dropped leg both fail)."""
    parent = tmp_path / "gold.vhdx"
    parent.write_bytes(b"x")
    fake = FakePS([pswindows.PSResult(
        stdout='{"id": "G-9", "name": "test-vm-9", "state": "Off", "generation": 2}',
        returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    media.vm_clone(unrestricted, "test-vm-9", str(parent), str(tmp_path / "c.vhdx"),
                   cpu_count=4, confirm=True)
    script = fake.scripts[0]
    assert "Set-VMProcessor" in script
    assert " -Count 4 " in script, (
        "the applied count must be the requested 4 (exact token, not a prefix)")
    assert script.index("New-VM -Name") < script.index("Set-VMProcessor")


def test_deployment_status_degraded_phase_end_to_end(monkeypatch):
    """Review M15: Running + heartbeat OK + NO KVP must classify degraded
    through the assembled result (not just the pure function)."""
    import json as _json

    from hyperv_mcp import readiness as _readiness
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout=_json.dumps({
            "state": "Running", "uptime_s": 60, "heartbeat": "OK",
            "kvp_items": [],
        }), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = _readiness.deployment_status(Config(unrestricted=True), vm_name="test-vm-1")
    assert out["phase"] == "degraded", out["phase"]
    assert out["heartbeat"] == "OK" and out["kvp"]["available"] is False


def test_deployment_status_skips_dtd_items(monkeypatch):
    """Review M27: a KVP item carrying an internal DTD is hostile input (the
    CIM provider never emits one) — it is skipped, never handed to the
    parser, and the well-formed siblings still parse."""
    import json as _json

    from hyperv_mcp import readiness as _readiness
    bomb = ('<!DOCTYPE INSTANCE [<!ENTITY a "aaaaaaaaaa">'
            '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            '<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
            '<PROPERTY NAME="Name"><VALUE>OSName</VALUE></PROPERTY>'
            '<PROPERTY NAME="Data"><VALUE>&b;</VALUE></PROPERTY></INSTANCE>')
    good = ('<INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">'
            '<PROPERTY NAME="Name"><VALUE>OSBuildNumber</VALUE></PROPERTY>'
            '<PROPERTY NAME="Data"><VALUE>19045</VALUE></PROPERTY></INSTANCE>')
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout=_json.dumps({
            "state": "Running", "uptime_s": 1, "heartbeat": "OK",
            "kvp_items": [bomb, good],
        }), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = _readiness.deployment_status(Config(unrestricted=True), vm_name="test-vm-1")
    assert out["kvp"]["items"] == {"OSBuildNumber": "19045"}
    assert "OSName" not in out["kvp"]["items"], "the DTD item must be skipped"


def test_wait_vm_state_non_ok_heartbeat_channel(fresh_server, tmp_path, monkeypatch):
    """Review M18: a Running final with a NON-OK heartbeat reports
    guest_channel == "no_guest_signal" (exact equality, not just != constant)
    with the real status text in heartbeat."""
    import asyncio
    import json as _json


    doc = {"allowed_vm_patterns": ["test-*"]}
    cfg_file = tmp_path / "wait-cfg2.json"
    cfg_file.write_text(_json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})

    class _Router:
        def __init__(self):
            self.scripts = []

        def __call__(self, script, **kwargs):
            self.scripts.append(script)
            if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
                return pswindows.PSResult(stdout=GUID, returncode=0)
            if "final_state" in script:
                return pswindows.PSResult(
                    stdout=_json.dumps({"final_state": "Running"}), returncode=0)
            if "Heartbeat" in script:
                return pswindows.PSResult(stdout="No Contact", returncode=0)
            return pswindows.PSResult(stdout="{}", returncode=0)

    router = _Router()
    monkeypatch.setattr(pswindows, "run_ps", router)
    result = asyncio.run(
        mod.get_mcp()._tool_manager.call_tool(
            "hyperv_wait_vm_state",
            {"vm_name": "test-vm-1", "states": ["Running"], "timeout_s": 5},
            context=None))
    texts = None
    if not isinstance(result, dict):
        content = result[0] if isinstance(result, tuple) else result
        if hasattr(content, "content"):
            texts = [c.text for c in content.content if getattr(c, "type", "") == "text"]
    if texts:
        result = _json.loads(texts[0])
    assert result["ok"] and result["final_state"] == "Running"
    assert result["heartbeat"] == "No Contact"
    assert result["guest_channel"] == "no_guest_signal"


def test_vm_remove_usage_scalar_shape_keeps_referenced_disk(monkeypatch, tmp_path):
    """Review H4 (the fix's own pin): the removed VM's OWN disk is still
    referenced by the ONE other registered VM, so the usage leg collects
    exactly one path — and ConvertTo-Json emits a bare JSON STRING for a
    1-element array (probed on PS 5.1). The consumer must normalize the
    scalar or in_use collapses to empty and the referenced disk is DELETED.
    The queued response is the real scalar shape."""
    import json as _json
    child = tmp_path / "vms" / "disk.vhdx"
    child.parent.mkdir(parents=True, exist_ok=True)
    child.write_bytes(b"x")
    cfg = Config(allowed_vm_patterns=["test-*"], host_write_roots=[str(tmp_path)])
    cfg.destructive.vm_remove = True
    disks_json = _json.dumps({
        "status": "removed", "disks": [str(child)], "ancestors": []})
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout=disks_json, returncode=0),
        # no .avhdx candidate -> no merge-poll leg; the usage leg is next and
        # returns the REAL one-element shape: a bare JSON string
        pswindows.PSResult(stdout=_json.dumps(str(child)), returncode=0),
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
    assert nc(child) not in deleted, (
        "a disk still referenced by the one other VM must NEVER be deleted "
        "(the scalar usage shape must normalize)")
    assert os.path.isfile(child), "the referenced disk must survive on disk"
    kept_reasons = {nc(k["path"]): k["reason"] for k in out["kept"]}
    assert kept_reasons.get(nc(child)) == "in_use_by_other_vm"
    # the usage script binds $vmTarget (the self-exclusion guard, UR-10)
    usage_script = fake.scripts[-1]
    assert "$vmTarget = '" in usage_script


def test_vm_remove_post_removal_failure_keeps_inventory(monkeypatch, tmp_path):
    """Review M25: a merge-poll leg failure after Remove-VM reports the
    removal with a full kept inventory (retryable), never a bare error."""
    import json as _json
    child = tmp_path / "disk.vhdx"
    child.write_bytes(b"x")
    avhdx = tmp_path / "disk.avhdx"
    avhdx.write_bytes(b"x")
    cfg = Config(unrestricted=True)
    cfg.destructive.vm_remove = True
    disks_json = _json.dumps({
        "status": "removed", "disks": [str(child), str(avhdx)], "ancestors": []})
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout=disks_json, returncode=0),
        # merge-poll leg FAILS (transport)
        pswindows.PSResult(returncode=1, stderr="Call cancelled"),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(media.os, "remove", lambda *a, **k: None)
    out = media.vm_remove(cfg, vm_name="test-vm-1", delete_disks=True, confirm=True)
    assert out["ok"] is False and out["retryable"] is True
    assert "removed" in out.get("status", "")
    kept_reasons = {k["reason"] for k in out["kept"]}
    assert "merge_pending" in kept_reasons
    assert any(r.startswith("cleanup_leg_failed") for r in kept_reasons), (
        f"the un-deleted candidate must carry the failed-leg reason: {kept_reasons}")
    assert not out["deleted"]


def test_vm_remove_cancel_requested_before_deletion(monkeypatch, tmp_path):
    """Review M24: a cancel-requested op stops the deletion pass (the hook
    raises OperationCancelled before os.remove runs)."""
    import json as _json
    child = tmp_path / "disk.vhdx"
    child.write_bytes(b"x")
    cfg = Config(unrestricted=True)
    cfg.destructive.vm_remove = True
    disks_json = _json.dumps({
        "status": "removed", "disks": [str(child)], "ancestors": []})
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
        deleted.append(str(path))
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(media.os, "remove", spy_remove)
    from hyperv_mcp import operations as _operations
    monkeypatch.setattr(
        _operations, "raise_if_cancelled",
        lambda: (_ for _ in ()).throw(_operations.OperationCancelled("op-1")))
    # OperationCancelled inherits BaseException (issue #24: envelope
    # wrappers must not swallow it) — raise it, never Exception.
    with pytest.raises(_operations.OperationCancelled):
        media.vm_remove(cfg, vm_name="test-vm-1", delete_disks=True, confirm=True)
    assert deleted == [], "a cancelled removal must not delete anything"
# ---------------------------------------------------------------------------
# Reviewer round 2 (pr112-20261031): one discriminating pin per fix — each
# named revert mutant below was executed against the suite and survived
# before its pin existed; each pin now fails under that mutant.
# ---------------------------------------------------------------------------

def test_enrich_failure_preserves_explicit_retryable():
    """M1: a module envelope that explicitly sets retryable keeps it
    (vm_remove's bounded merge wait is retryable by design); one without
    the key still derives from retry_fields."""
    from hyperv_mcp import errors as _errors
    env = _errors.enrich_failure({
        "ok": False, "error": "merge pending", "error_class": "timeout",
        "retryable": True})
    assert env["retryable"] is True, (
        "an explicit retryable must survive enrich_failure (the server "
        "boundary must not clobber it to False)")
    env2 = _errors.enrich_failure({
        "ok": False, "error": "x", "error_class": "timeout"})
    assert env2["retryable"] is False
    env3 = _errors.enrich_failure({
        "ok": False, "error": "x", "error_class": "invalid",
        "retryable": False})
    assert env3["retryable"] is False and env3["retry_after_ms"] is None


def test_wait_vm_state_heartbeat_leg_failure_keeps_final_state(fresh_server, tmp_path, monkeypatch):
    """M2: a heartbeat-leg EXCEPTION must not void an accomplished wait —
    final_state survives with the unknown-signal shape (heartbeat "")."""
    import asyncio
    import json as _json
    doc = {"allowed_vm_patterns": ["test-*"]}
    cfg_file = tmp_path / "wait-cfg3.json"
    cfg_file.write_text(_json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})

    class _Router:
        def __call__(self, script, **kwargs):
            if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
                return pswindows.PSResult(stdout=GUID, returncode=0)
            if "final_state" in script:
                return pswindows.PSResult(
                    stdout=_json.dumps({"final_state": "Running"}), returncode=0)
            if "Heartbeat" in script:
                # the transient failure the M2 fix exists for
                return pswindows.PSResult(returncode=1, stderr="Call cancelled")
            return pswindows.PSResult(stdout="{}", returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", _Router())
    result = asyncio.run(
        mod.get_mcp()._tool_manager.call_tool(
            "hyperv_wait_vm_state",
            {"vm_name": "test-vm-1", "states": ["Running"], "timeout_s": 5},
            context=None))
    if not isinstance(result, dict):
        content = result[0] if isinstance(result, tuple) else result
        texts = [c.text for c in content.content if getattr(c, "type", "") == "text"]
        result = _json.loads(texts[0])
    assert result["ok"] is True, (
        "a heartbeat-leg failure must not void the accomplished wait")
    assert result["final_state"] == "Running"
    assert result["heartbeat"] == ""
    assert result["guest_channel"] == "no_guest_signal"


def _harvest_action_script_for_pins(monkeypatch, tmp_path):
    """Capture the harvest action script (helper shared by the script-shape
    pins; the frozen g04 convention: resolve -> Off -> privilege -> action)."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout="SeBackupPrivilege", returncode=0),
        pswindows.PSResult(stdout='{"files": [], "skipped": []}', returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    import contextlib
    real_lock = harvest.vmlocks.vm_lock

    @contextlib.contextmanager
    def spy_lock(key, *a, **kw):
        with real_lock(key, *a, **kw):
            yield

    monkeypatch.setattr(harvest.vmlocks, "vm_lock", spy_lock)
    harvest.harvest_offline_logs(
        cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    return next(s for s in fake.scripts if "Mount-VHD" in s)


def test_harvest_action_script_review_pins(monkeypatch, tmp_path):
    """C1/M4/M5/M7 script-shape pins (script-text level: the unit suite
    never executes PS, so the emitted shape is the contract):
    C1  - the final emission uses the PS-5.1-safe ToArray() shape and never
          the @()-around-List[object] shape that throws;
    M4  - glob entries are enumerated after the copy;
    M5  - the robocopy exit code is inspected and copy failures reported;
    M7  - the access-path directory is removed after the access path."""
    action = _harvest_action_script_for_pins(monkeypatch, tmp_path)
    assert "$files.ToArray()" in action and "$skipped.ToArray()" in action, (
        "C1: the final emission must use the ToArray shape (PS 5.1 throws "
        "on @() around List[object])")
    assert "@($files)" not in action and "@($skipped)" not in action
    assert "Get-ChildItem -LiteralPath $dstDir -Filter $name" in action, (
        "M4: glob copies must be enumerated so they are hashed and capped")
    assert "$LASTEXITCODE -ge 8" in action and "copy_failed" in action, (
        "M5: a failed robocopy must be reported, never silently dropped")
    assert "Remove-Item -LiteralPath $ap -Recurse -Force" in action, (
        "M7: the access-path directory must be removed (os.rmdir cannot)")


def test_harvest_recovery_leg_runs_after_action_failure(monkeypatch, tmp_path):
    """M6: an action-leg failure must trigger the fresh-process dismount
    recovery leg (a killed action process never runs its PS finally) —
    the original error still propagates."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_res(),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(stdout="SeBackupPrivilege", returncode=0),
        # the action leg dies (transport)
        pswindows.PSResult(returncode=1, stderr="harvest script exploded"),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    import contextlib
    real_lock = harvest.vmlocks.vm_lock

    @contextlib.contextmanager
    def spy_lock(key, *a, **kw):
        with real_lock(key, *a, **kw):
            yield

    monkeypatch.setattr(harvest.vmlocks, "vm_lock", spy_lock)
    with pytest.raises(harvest.HarvestError):
        harvest.harvest_offline_logs(
            cfg, vm_name="test-vm-1", dest_dir=str(tmp_path / "out"))
    recovery = [s for s in fake.scripts if "Dismount-VHD" in s and "Get-VMHardDiskDrive" in s]
    assert recovery, (
        "the recovery dismount leg must run after an action-script failure "
        "(the killed process never ran its in-script finally)")
    assert any("recovery" in s or "SilentlyContinue" in s for s in recovery)


def test_vm_clone_restores_parent_attribute_on_refusal(monkeypatch, unrestricted, tmp_path):
    """M8: a refused clone (attached-parent throw) must leave the golden
    parent's attribute exactly as found — no permanent mutation on a
    refusal path."""
    import os as _os
    import stat as _stat
    parent = tmp_path / "gold.vhdx"
    parent.write_bytes(b"x")
    assert _os.stat(parent).st_mode & _stat.S_IWRITE, "fixture starts writable"
    fake = FakePS([pswindows.PSResult(
        returncode=1,
        stderr="Get-VMHardDiskDrive : 'gold.vhdx' is already attached to VM 'gold-vm'",
    )])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(MediaError, match="gold-vm"):
        media.vm_clone(
            unrestricted, "test-vm-2", str(parent), str(tmp_path / "c.vhdx"),
            confirm=True)
    assert _os.stat(parent).st_mode & _stat.S_IWRITE, (
        "the refused clone must RESTORE the writable attribute (M8)")


def test_vm_remove_removal_script_reasserts_off(monkeypatch, unrestricted):
    """M9: the removal script itself re-asserts Off on the same $vm object
    it removes (the standalone state gate cannot bind an out-of-band actor
    starting the VM between the two PS processes)."""
    fake = FakePS([
        pswindows.PSResult(stdout=GUID, returncode=0),
        pswindows.PSResult(stdout="Off", returncode=0),
        pswindows.PSResult(
            stdout='{"status": "removed", "disks": [], "ancestors": []}',
            returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = media.vm_remove(unrestricted, vm_name="test-vm-1", confirm=True)
    assert out["ok"] is True
    removal = fake.scripts[-1]
    assert "vm_remove requires state Off" in removal, (
        "the removal script must re-assert Off before Remove-VM -Force")
    assert removal.index("requires state Off") < removal.index("Remove-VM -VM")


def test_lease_gate_invalid_name_envelope(fresh_server, tmp_path):
    """M10: a blank or >260-char create-style name gets the audited invalid
    ENVELOPE from the gate — never an escaping ValueError (MINOR-13)."""
    doc = {"allowed_vm_patterns": ["test-*"]}
    cfg_file = tmp_path / "gate-cfg.json"
    cfg_file.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})
    for bad in ("   ", "x" * 261):
        env, _present = mod._lease_gate("hyperv_vm_clone", {
            "name": bad, "confirm": True})
        assert env is not None and env.get("ok") is False, (
            f"a blank/>260-char name must be refused by the gate: {bad[:20]!r}")
        assert env.get("error_class") == "invalid", env.get("error_class")


def test_harvest_error_classification():
    """M20: deterministic harvest refusals classify as their own classes —
    never the transport catch-all."""
    from hyperv_mcp import errors as _errors
    assert _errors.classify(harvest.HarvestPrivilegeError("no SeBackupPrivilege")) == "privilege"
    assert _errors.classify(harvest.HarvestError("requires state Off")) == "invalid"
    assert _errors.classify(harvest.HarvestError("remote host mode")) == "invalid"


def test_destructive_policy_field_order_frozen():
    """M22 (completed): the two new fields sit AFTER every pre-existing
    field, so pre-#112 positional constructions keep their bindings
    (require_confirm was still shifted by the first reorder attempt)."""
    import dataclasses

    from hyperv_mcp.config import DestructivePolicy
    names = [f.name for f in dataclasses.fields(DestructivePolicy)]
    assert names[:16] == [
        "stop", "reset", "checkpoint_restore", "checkpoint_remove",
        "kd_reboot", "elevated_exec", "guest_write", "console_input",
        "media", "vm_provision", "display", "guest_repair", "relay",
        "ui_input", "ui_provision", "require_confirm",
    ], f"pre-#112 positional bindings moved: {names}"
    assert names[16:] == ["vm_remove", "offline_harvest"]


def test_vm_create_detached_gate_names_the_vm():
    """M23: the detached preflight for vm_create reads the `name` argument
    (the tool's actual parameter), so refusals name the VM instead of
    'None'."""
    from hyperv_mcp import policy as _policy
    from hyperv_mcp.server import _OPERATIONS_DESTRUCTIVE_GATES
    cfg = Config(allowed_vm_patterns=["test-*"])
    with pytest.raises(_policy.PolicyDenied, match="create VM 'test-vm-1'") as excinfo:
        _OPERATIONS_DESTRUCTIVE_GATES["hyperv_vm_create"](
            cfg, {"name": "test-vm-1", "confirm": False})
    assert "'None'" not in str(excinfo.value)
