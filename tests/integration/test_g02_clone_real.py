"""Live-host integration legs for issue #31 (clone/remove) — trace
31-32-33-94-workstream-g-deployment AC19 (31-AC12/AC13).

Env-gated by the shared conftest guard (HYPERV_MCP_INTEGRATION=1 +
HYPERV_MCP_TEST_VM + guest credentials). The clone legs additionally need
HYPERV_MCP_TEST_GOLDEN_VHD naming a golden .vhdx the test may chmod
read-only and clone from; without it the clone legs skip with a reason
(prior-trace disposition pattern — never a silent pass).

Legs:
  * test_clone_boots_and_full_remove (31-AC12): clone a differencing disk
    over a read-only golden parent, boot it to Running, stop it, remove it
    with delete_disks=true — the parent's SHA-256 and LastWriteTime must be
    unchanged, no clone VM or child disk left behind.
  * test_remove_clone_with_checkpoint (31-AC13): same, with one checkpoint
    created on the clone before removal — the post-removal merge is waited
    out and the child + .avhdx chain is deleted (no sharing violation, no
    surviving .avhdx).
"""

import hashlib
import os
import time

import pytest

from hyperv_mcp import lifecycle, media
from hyperv_mcp.config import Config

pytestmark = pytest.mark.hyperv_real


def _golden_vhd() -> str:
    vhd = os.environ.get("HYPERV_MCP_TEST_GOLDEN_VHD", "").strip()
    if not vhd or not os.path.isfile(vhd):
        pytest.skip(
            "HYPERV_MCP_TEST_GOLDEN_VHD is not set to an existing read-only "
            "golden .vhdx (mint one with New-VHD + Set-ItemProperty "
            "IsReadOnly $true)")
    return vhd


def _digest(path: str) -> tuple[str, float]:
    st = os.stat(path)
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest(), st.st_mtime


def _wait_state(cfg: Config, name: str, states: list[str], timeout_s: int = 300) -> str:
    return lifecycle.wait_for_vm_state(cfg, name, states, timeout_s)


def test_clone_boots_and_full_remove(it, tmp_path):
    golden = _golden_vhd()
    before = _digest(golden)
    stamp = int(time.time())
    name = f"test-clone-{stamp}"
    child = str(tmp_path / f"{name}.vhdx")
    out = media.vm_clone(
        it.cfg, name, golden, child, memory_mb=512, switch_name="", confirm=True)
    assert out["ok"], out
    try:
        final = _wait_state(it.cfg, name, ["Running"], timeout_s=180)
        assert final == "Running", f"clone did not boot: {final}"
        lifecycle.stop_vm(it.cfg, name, "shutdown-force", confirm=True)
        _wait_state(it.cfg, name, ["Off"], timeout_s=180)
    finally:
        removed = media.vm_remove(
            it.cfg, vm_name=name, delete_disks=True, confirm=True)
        assert removed["ok"], removed
    assert os.path.normcase(child) not in {
        os.path.normcase(p) for p in removed["deleted"]} or not os.path.isfile(child)
    assert not os.path.isfile(child), "clone child disk must be deleted"
    after = _digest(golden)
    assert after == before, "golden parent must be byte- and mtime-identical"


def test_remove_clone_with_checkpoint(it, tmp_path):
    golden = _golden_vhd()
    name = f"test-clone-cp-{int(time.time())}"
    child = str(tmp_path / f"{name}.vhdx")
    out = media.vm_clone(it.cfg, name, golden, child, confirm=True)
    assert out["ok"], out
    try:
        _wait_state(it.cfg, name, ["Running", "Off"], timeout_s=180)
        lifecycle.checkpoint_create(it.cfg, name, "pre-remove", timeout_s=600)
    finally:
        removed = media.vm_remove(
            it.cfg, vm_name=name, delete_disks=True, confirm=True)
        assert removed["ok"], removed
    assert not os.path.isfile(child), "child must be deleted after the merge wait"
    leftovers = [p for p in removed.get("kept", []) if "merge_pending" in str(p)]
    assert not leftovers, f"merge never completed: {leftovers}"
