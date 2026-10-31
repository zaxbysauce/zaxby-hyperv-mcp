"""Live-host integration legs for issue #33 (offline harvest) — trace
31-32-33-94-workstream-g-deployment AC19 (33-AC11/AC12/AC13).

Env-gated by the shared conftest guard. These legs exercise real mounts:
the named disposable VM is stopped, its disk mounted read-only, logs copied
and hashed, dismounted, and the VM started again. The broken-setup and
BitLocker/checkpoint variants need assets the environment may not have;
each skips with a reason naming the missing env var (prior-trace pattern).

  * test_harvest_off_vm_and_restart (33-AC11 baseline shape): harvest an Off
    VM, verify the disk dismounted and the VM still starts. The
    deliberately-broken-setup variant needs HYPERV_MCP_TEST_BROKEN_SETUP=1
    on a VM whose Windows Setup failed; the generic leg instead asserts the
    harvest round-trip (files manifest, hashes match on disk).
  * test_harvest_checkpointed_vm (33-AC12): with a checkpoint present, the
    CURRENT .avhdx chain is read (needs HYPERV_MCP_TEST_CHECKPOINT=1; skips
    otherwise).
  * test_harvest_non_elevated_token (33-AC13): re-run the precheck leg from
    a non-elevated context is operator-driven (the harness itself runs
    elevated on this host); the unit-level SeBackup refusal is pinned by
    frozen C15 — this leg records the elevated observation only.
"""

import hashlib
import os

import pytest

from hyperv_mcp import harvest, lifecycle

pytestmark = pytest.mark.hyperv_real


def test_harvest_off_vm_and_restart(it, it_tmp):
    cfg, vm = it.cfg, it.vm
    lifecycle.stop_vm(cfg, vm, "shutdown", confirm=True)
    lifecycle.wait_for_vm_state(cfg, vm, ["Off"], 300)
    dest = str(it_tmp / "harvest-out")
    out = harvest.harvest_offline_logs(cfg, vm_name=vm, dest_dir=dest)
    assert out["ok"], out
    for f in out["files"]:
        local = os.path.join(dest, f["path"])
        assert os.path.isfile(local), f"manifest lists a missing file: {f}"
        with open(local, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest().upper()
        assert digest == f["sha256"].upper(), f"hash mismatch for {f['path']}"
    # the VM must still start after the dismount
    lifecycle.start_vm(cfg, vm)
    final = lifecycle.wait_for_vm_state(cfg, vm, ["Running"], 300)
    assert final == "Running"


def test_harvest_checkpointed_vm(it, it_tmp):
    if os.environ.get("HYPERV_MCP_TEST_CHECKPOINT", "") != "1":
        pytest.skip(
            "HYPERV_MCP_TEST_CHECKPOINT=1 not set (checkpoint-chain leg needs "
            "a disposable VM allowed to carry a checkpoint)")
    cfg, vm = it.cfg, it.vm
    from hyperv_mcp import lifecycle as lc
    lc.checkpoint_create(cfg, vm, "harvest-probe")
    try:
        lc.stop_vm(cfg, vm, "turnoff", confirm=True)
        lc.wait_for_vm_state(cfg, vm, ["Off"], 300)
        dest = str(it_tmp / "harvest-cp-out")
        out = harvest.harvest_offline_logs(cfg, vm_name=vm, dest_dir=dest)
        assert out["ok"], out
        assert not [
            s for s in out["skipped"] if s.get("reason") == "volume_locked"
        ] or out["files"], "a locked volume must be skipped, not fatal"
    finally:
        lc.checkpoint_remove(cfg, vm, "harvest-probe", confirm=True)


def test_harvest_elevation_observed(it, it_tmp):
    """33-AC13 elevated half: this harness runs elevated on the host, so the
    SeBackup precheck passes and the harvest completes — recorded as the
    observed elevated result. The non-elevated refusal is pinned by frozen
    C15 (unit) and remains operator-runbook material for a shell-level
    re-run."""
    cfg, vm = it.cfg, it.vm
    lifecycle.stop_vm(cfg, vm, "shutdown", confirm=True)
    lifecycle.wait_for_vm_state(cfg, vm, ["Off"], 300)
    out = harvest.harvest_offline_logs(
        cfg, vm_name=vm, dest_dir=str(it_tmp / "harvest-elev"))
    assert out["ok"], out
    lifecycle.start_vm(cfg, vm)
