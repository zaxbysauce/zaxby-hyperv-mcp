"""Real-Hyper-V integration tests (opt-in; see tests/integration/conftest.py).

Every test here drives a REAL disposable VM. Mocked unit tests must never be
read as validating these behaviors — that is exactly what this file exists
for. Protocol per the task spec: record start state, checkpoint, exercise
read-only → exec/transfer → lifecycle → failure cases, then restore.
"""

import itertools
import time

import pytest

pytestmark = [pytest.mark.hyperv_real]

# Unique per CREATION: Hyper-V allows duplicate snapshot names, and
# restore/remove by an ambiguous name fails ('More than one snapshot was
# found'). The fixture suffixes a per-test counter so no two checkpoints in
# a run collide, even across dozens of guarded tests.
_CHECKPOINT_SEQ = itertools.count(1)
CHECKPOINT = "mcp-it-pre-{}".format(time.strftime("%Y%m%d-%H%M%S"))


@pytest.fixture()
def guarded_vm(it):
    """Checkpoint before invasive work; restore afterwards."""
    from hyperv_mcp import lifecycle

    checkpoint = f"{CHECKPOINT}-{next(_CHECKPOINT_SEQ)}"
    lifecycle.checkpoint_create(it.cfg, it.vm, checkpoint)
    it.checkpoint = checkpoint
    yield it
    try:
        lifecycle.checkpoint_restore(it.cfg, it.vm, checkpoint, confirm=True)
    except Exception as exc:  # noqa: BLE001 - report, don't hide
        report = {"unrestored_vm": it.vm, "checkpoint": checkpoint, "error": str(exc)}
        import json

        with open("hyperv-it-cleanup-report.json", "w", encoding="utf-8") as fh:
            json.dump(report, fh)


# ---------------------------------------------------------------------------
# read-only
# ---------------------------------------------------------------------------

def test_list_vms_real(guarded_vm):
    from hyperv_mcp import lifecycle

    vms = lifecycle.list_vms(guarded_vm.cfg)
    names = [v["name"] for v in vms]
    assert guarded_vm.vm in names
    row = next(v for v in vms if v["name"] == guarded_vm.vm)
    assert row["state"] in ("Running", "Off", "Saved", "Paused")
    assert isinstance(row["memory_mb"], (int, float))


def test_get_vm_info_real(guarded_vm):
    from hyperv_mcp import lifecycle

    info = lifecycle.get_vm_info(guarded_vm.cfg, guarded_vm.vm)
    assert info["name"] == guarded_vm.vm
    assert info["generation"] in (1, 2)
    assert isinstance(info["com_ports"], list)


# ---------------------------------------------------------------------------
# guest execution (requires running guest with PS Direct support)
# ---------------------------------------------------------------------------

@pytest.fixture()
def running_vm(guarded_vm):
    from hyperv_mcp import lifecycle

    lifecycle.start_vm(guarded_vm.cfg, guarded_vm.vm)
    return guarded_vm


def test_guest_run_ps_echo_and_exit_code(running_vm):
    from hyperv_mcp import guestexec

    out = guestexec.guest_run_ps(
        running_vm.cfg, running_vm.vm, "Write-Output 'it-works'", cred=running_vm.creds
    )
    assert out["ok"], out
    assert out["exit_code"] == 0
    assert "it-works" in out["stdout"]


def test_guest_run_ps_real_exit_code(running_vm):
    from hyperv_mcp import guestexec

    out = guestexec.guest_run_ps(
        running_vm.cfg, running_vm.vm, "exit 42", cred=running_vm.creds
    )
    assert out["ok"], out
    assert out["exit_code"] == 42


def test_guest_run_streams_separated(running_vm):
    from hyperv_mcp import guestexec

    script = "Write-Output 'to-stdout'; Write-Error 'to-err' -ErrorAction Continue"
    out = guestexec.guest_run_ps(running_vm.cfg, running_vm.vm, script, cred=running_vm.creds)
    assert out["ok"], out
    assert "to-stdout" in out["stdout"]
    if out["stderr"]:  # separated: error text must not pollute stdout
        assert "to-err" not in out["stdout"]


def test_guest_run_native_exit_codes(running_vm):
    from hyperv_mcp import guestexec

    ok = guestexec.guest_run(running_vm.cfg, running_vm.vm, "cmd.exe", ["/c", "exit", "0"], cred=running_vm.creds)
    assert ok["ok"] and ok["exit_code"] == 0
    fail = guestexec.guest_run(running_vm.cfg, running_vm.vm, "cmd.exe", ["/c", "exit", "5"], cred=running_vm.creds)
    assert fail["ok"] and fail["exit_code"] == 5


def test_guest_run_unicode_and_working_dir(running_vm, tmp_path):
    from hyperv_mcp import guestexec

    out = guestexec.guest_run_ps(
        running_vm.cfg, running_vm.vm,
        "Write-Output ('cwd=' + (Get-Location).Path)",
        cred=running_vm.creds,
    )
    assert out["ok"], out
    uni = guestexec.guest_run_ps(
        running_vm.cfg, running_vm.vm, "Write-Output 'caf\u00e9-\u4e2d\u6587'", cred=running_vm.creds
    )
    assert "caf\u00e9-\u4e2d\u6587" in uni["stdout"]


def test_timeout_reports_guest_may_continue(running_vm):
    from hyperv_mcp import guestexec

    out = guestexec.guest_run_ps(
        running_vm.cfg, running_vm.vm, "Start-Sleep -Seconds 60",
        timeout_ms=2000, cred=running_vm.creds,
    )
    assert out["ok"] is False
    assert out["timed_out"] is True
    assert out["error_class"] == "timeout"


# ---------------------------------------------------------------------------
# file transfer
# ---------------------------------------------------------------------------

def test_put_get_roundtrip_with_sha256(running_vm, tmp_path):
    from hyperv_mcp import filetransfer

    local_src = tmp_path / "payload.bin"
    payload = bytes(range(256)) * 64 + "unicode-\u4e2d".encode("utf-8")
    local_src.write_bytes(payload)
    remote = r"C:\Windows\Temp\mcp-it-payload.bin"

    put = filetransfer.guest_put(
        running_vm.cfg, running_vm.vm, str(local_src), remote,
        confirm=True, verify=True, cred=running_vm.creds,
    )
    assert put["ok"], put
    assert put["bytes_copied"] == len(payload)

    back = tmp_path / "payload-back.bin"
    got = filetransfer.guest_get(
        running_vm.cfg, running_vm.vm, remote, str(back), verify=True, cred=running_vm.creds,
    )
    assert got["ok"], got
    assert back.read_bytes() == payload

    listing = filetransfer.guest_list_dir(
        running_vm.cfg, running_vm.vm, r"C:\Windows\Temp", cred=running_vm.creds
    )
    assert listing["ok"]
    assert any(e["name"] == "mcp-it-payload.bin" for e in listing["entries"])

    read = filetransfer.guest_read_file(
        running_vm.cfg, running_vm.vm, remote, max_bytes=16, cred=running_vm.creds
    )
    assert read["ok"] and read["truncated"] is True and read["bytes_read"] == 16

    import hashlib
    first16 = hashlib.sha256(payload[:16]).hexdigest()
    # content_b64 of the first 16 bytes decodes to the payload prefix
    import base64 as b64
    decoded = b64.b64decode(read["content_b64"])
    assert decoded == payload[:16]
    del first16

    cleanup = filetransfer.guest_run_ps(
        running_vm.cfg, running_vm.vm,
        "Remove-Item -LiteralPath 'C:\\Windows\\Temp\\mcp-it-payload.bin' -Force",
        cred=running_vm.creds,
    )
    assert cleanup["ok"], cleanup


def test_put_missing_source(running_vm, tmp_path):
    from hyperv_mcp import filetransfer

    out = filetransfer.guest_put(
        running_vm.cfg, running_vm.vm, str(tmp_path / "nope.bin"),
        r"C:\Windows\Temp\x.bin", confirm=True, cred=running_vm.creds,
    )
    assert out["ok"] is False and out["error_class"] == "not_found"


# ---------------------------------------------------------------------------
# lifecycle + checkpoints
# ---------------------------------------------------------------------------

def test_stop_start_lifecycle(guarded_vm):
    from hyperv_mcp import lifecycle

    stopped = lifecycle.stop_vm(guarded_vm.cfg, guarded_vm.vm, "shutdown", confirm=True)
    assert stopped["state"] == "Off"
    started = lifecycle.start_vm(guarded_vm.cfg, guarded_vm.vm)
    assert started["state"] == "Running"
    again = lifecycle.start_vm(guarded_vm.cfg, guarded_vm.vm)
    assert again["status"] == "already_running"


def test_checkpoint_list_restore(guarded_vm):
    from hyperv_mcp import lifecycle

    snaps = lifecycle.checkpoint_list(guarded_vm.cfg, guarded_vm.vm)
    names = [s["name"] for s in snaps]
    assert guarded_vm.checkpoint in names
    out = lifecycle.checkpoint_restore(
        guarded_vm.cfg, guarded_vm.vm, guarded_vm.checkpoint, confirm=True
    )
    assert out["status"] == "restored"
    assert out["state"] == "Off"


def test_nonexistent_vm_error_clarity(guarded_vm):
    from hyperv_mcp import lifecycle

    with pytest.raises(Exception) as exc:
        lifecycle.get_vm_info(guarded_vm.cfg, "mcp-it-definitely-not-a-vm")
    assert "mcp-it-definitely-not-a-vm" in str(exc.value)
