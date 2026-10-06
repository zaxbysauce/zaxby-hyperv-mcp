"""Real-Hyper-V acceptance checks for issue #8: duplicate VM names fail closed.

Opt-in like every file in this directory (see conftest.py): the suite skips
unless HYPERV_MCP_INTEGRATION=1, HYPERV_MCP_TEST_VM names a disposable test
VM, and guest credentials are in the environment. The scenario mirrors the
issue report: a second diskless VM is created with the SAME name as the
disposable test VM, name-addressed operations must then refuse while
naming both candidate GUIDs, id-addressed operations keep working, and the
duplicate is torn down by GUID.
"""

import pytest

pytestmark = [pytest.mark.hyperv_real]


def test_duplicate_name_fails_closed(it):
    """AC7: with two VMs sharing one name, ambiguous name-addressed calls
    refuse closed naming both GUIDs; by-id calls keep working; the real VM's
    state and checkpoints are untouched."""
    from hyperv_mcp import guestexec, lifecycle, pswindows

    def raw(script: str) -> str:
        result = pswindows.run_ps(script, timeout_s=120)
        pswindows.check_result(result, "duplicate-name probe")
        return result.stdout.strip()

    baseline_info = lifecycle.get_vm_info(it.cfg, it.vm)
    baseline_state = baseline_info["state"]
    baseline_checkpoints = {s["name"] for s in lifecycle.checkpoint_list(it.cfg, it.vm)}
    orig_id = baseline_info["id"]

    dup_id = raw(
        "(New-VM -Name " + pswindows.ps_name(it.vm)
        + " -NoVHD -ErrorAction Stop).Id.ToString()"
    )
    try:
        rows = [r for r in lifecycle.list_vms(it.cfg) if r["name"] == it.vm]
        ids = {r["id"] for r in rows}
        assert len(rows) == 2, f"expected the duplicate to double the name, got: {rows}"
        assert len(ids) == 2 and dup_id in ids and orig_id in ids

        refusals = (
            lambda: lifecycle.start_vm(it.cfg, vm_name=it.vm),
            lambda: lifecycle.checkpoint_create(
                it.cfg, vm_name=it.vm, checkpoint_name="ac7-refused-probe"),
            lambda: guestexec.guest_run_ps(
                it.cfg, vm_name=it.vm, script="Write-Output 'must-not-run'",
                cred=it.creds),
        )
        for refuse in refusals:
            with pytest.raises(Exception) as exc:
                refuse()
            detail = str(exc.value)
            assert dup_id in detail and orig_id in detail, (
                f"ambiguity error must name both candidate GUIDs, got: {detail}"
            )

        after = next(r for r in lifecycle.list_vms(it.cfg) if r["id"] == orig_id)
        assert after["state"] == baseline_state
        assert {s["name"] for s in lifecycle.checkpoint_list(it.cfg, vm_id=orig_id)} == (
            baseline_checkpoints
        )

        started = lifecycle.start_vm(it.cfg, vm_id=orig_id)
        assert started["status"] in ("started", "already_running")
    finally:
        raw(f"Remove-VM -Id '{dup_id}' -Force -ErrorAction Stop")

    remaining = [r for r in lifecycle.list_vms(it.cfg) if r["name"] == it.vm]
    assert len(remaining) == 1 and remaining[0]["id"] == orig_id
