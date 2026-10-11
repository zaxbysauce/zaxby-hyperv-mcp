"""Real-host acceptance for issue #44 (AC7): set 1920x1080 Single with a
restart (the host refuses Set-VMVideo on a running VM, so the tool stops
first), verify the CONFIGURED mode is committed and the observed head is
honestly reported, then revert with Default.

The observed head is guest-dependent: on the dev host (probe 2026-10-10,
Deployment Test 3) this host commits Single/1920x1080 but the test image's
display driver keeps its own mode, so the test asserts the observed values
are real reads (never the request echo) and consistent with
get_display_info — not that the guest obeyed the mode.

Runs only under the standard integration gate (HYPERV_MCP_INTEGRATION=1 +
disposable VM + guest credentials; see tests/integration/conftest.py).
"""

import itertools
import json
import time

import pytest

pytestmark = [pytest.mark.hyperv_real]

_SEQ = itertools.count(1)


@pytest.fixture()
def guarded_vm(it):
    """Checkpoint before invasive work; restore afterwards."""
    from hyperv_mcp import lifecycle

    # timestamp like test_hyperv_real: restored snapshots persist on the VM,
    # so a fixed per-process counter would collide on the next run
    checkpoint = f"issue44-video-{time.strftime('%Y%m%d-%H%M%S')}-{next(_SEQ)}"
    lifecycle.checkpoint_create(it.cfg, it.vm, checkpoint)
    yield it
    try:
        lifecycle.checkpoint_restore(it.cfg, it.vm, checkpoint, confirm=True)
    except Exception as exc:  # noqa: BLE001 - report, don't hide
        with open("hyperv-it-cleanup-report.json", "w", encoding="utf-8") as fh:
            json.dump(
                {"unrestored_vm": it.vm, "checkpoint": checkpoint, "error": str(exc)},
                fh,
            )


def test_set_resolution_real(guarded_vm):
    from hyperv_mcp import console, media

    cfg, vm = guarded_vm.cfg, guarded_vm.vm

    result = media.vm_set_resolution(cfg, vm, 1920, 1080, "single", restart=True, confirm=True)
    assert result["ok"] is True
    assert result["effective_after_restart"] is False
    assert result["resolution_type"] == "Single"
    assert result["horizontal"] == 1920
    assert result["vertical"] == 1080
    # observed_* is a real Msvm_VideoHead read, never the request echo
    assert result["observed_horizontal"] is not None
    assert result["observed_vertical"] is not None

    video = media.vm_get_video(cfg, vm)
    assert video["ok"] is True
    assert video["resolution_type"] == "Single"
    assert video["horizontal"] == 1920
    assert video["vertical"] == 1080

    info = console.get_display_info(cfg, vm)
    assert info["ok"] is True
    assert info["head_horizontal"] == result["observed_horizontal"]
    assert info["head_vertical"] == result["observed_vertical"]

    # Reverting also needs the VM off (same host refusal): reuse the
    # stop-first restart flow.
    revert = media.vm_set_resolution(
        cfg, vm, resolution_type="default", restart=True, confirm=True)
    assert revert["ok"] is True
    video_after = media.vm_get_video(cfg, vm)
    assert video_after["resolution_type"] == "Default"
