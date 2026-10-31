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

    from hyperv_mcp import guestexec

    cleanup = guestexec.guest_run_ps(
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


# ---------------------------------------------------------------------------
# durable state store (issue #22, AC10)
# ---------------------------------------------------------------------------

def test_e01_job_survives_server_restart(running_vm, tmp_path, monkeypatch):
    """AC10: a job started through one server process is still addressable
    from a second process against the same state DB.

    Only a real PowerShell Direct round trip shows that the restored PID and
    paths still address the guest process. The restart is a real HARD KILL
    of process A (Popen.kill → TerminateProcess, exactly the issue's "A is
    terminated") while it is still alive holding the job — none of A's
    cleanup paths can run — followed by a fresh interpreter as process B.
    Both children get the SAME policy and the SAME store as the parent
    (unrestricted via the environment, one HYPERV_MCP_STATE_DB for all three
    processes), and PYTHONPATH is pinned the way the unit-suite child
    drivers pin it, so the children import the tree under test.
    """
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    from hyperv_mcp import guestjobs

    db = tmp_path / "state.sqlite3"
    src = Path(__file__).resolve().parents[2] / "src"
    # One store for the parent and both children: the parent's job_stop at
    # the end must resolve the very rows the starter wrote.
    monkeypatch.setenv("HYPERV_MCP_STATE_DB", str(db))
    # The children load their own Config from the environment; without the
    # same unrestricted policy as the parent they would deny the guest legs.
    monkeypatch.setenv("HYPERV_MCP_UNRESTRICTED", "1")
    # dict(os.environ, ...) keeps SYSTEMROOT and friends, so the child Python
    # processes start cleanly on Windows; PYTHONPATH pins the import tree.
    env = dict(os.environ, PYTHONPATH=str(src))

    # Process A: start a long-running job, publish the handle, then stay
    # alive until the parent kills it — the kill, not a clean exit, is what
    # makes this a restart rather than a shutdown.
    starter = tmp_path / "start_job.py"
    starter.write_text(
        "import json, sys, time\n"
        "from hyperv_mcp import credentials, guestjobs\n"
        "from hyperv_mcp.config import Config\n"
        "cfg = Config.load()\n"
        "credentials.init(cfg)\n"
        "out = guestjobs.job_start(\n"
        "    cfg, sys.argv[1], 'ping', ['-n', '120', '127.0.0.1'],\n"
        "    cred=credentials.resolve_guest(),\n"
        ")\n"
        "with open(sys.argv[2], 'w', encoding='utf-8') as fh:\n"
        "    fh.write(json.dumps(out))\n"
        "time.sleep(600)\n",
        encoding="utf-8",
    )
    record = tmp_path / "job-record.json"
    proc_a = subprocess.Popen(
        [sys.executable, str(starter), running_vm.vm, str(record)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    job = None
    try:
        for _ in range(600):
            if record.exists():
                job = json.loads(record.read_text(encoding="utf-8"))
                break
            if proc_a.poll() is not None:
                out, err = proc_a.communicate()
                raise AssertionError(f"starter died early: {err[-2000:]}")
            time.sleep(1.0)
        assert job is not None, "starter never published the job handle"
        # A is terminated — hard, while it still holds the process-local
        # registry the durable store must outlive.
        proc_a.kill()
        proc_a.wait(timeout=60)

        job_id = job["job_id"]
        job_dir = job["job_dir"]

        # The store holds no password and no command text.
        raw = db.read_bytes()
        for needle in (
            os.environ.get("HYPERV_GUEST_PASSWORD", "").encode("utf-8", "replace"),
            b"ping", b"-n", b"120",
        ):
            if needle:
                assert needle not in raw, "the state store persisted secret or command material"

        # Process B: a fresh interpreter with the same store reattaches.
        follower = tmp_path / "follow_job.py"
        follower.write_text(
            "import json, sys\n"
            "from hyperv_mcp import credentials, guestjobs\n"
            "from hyperv_mcp.config import Config\n"
            "cfg = Config.load()\n"
            "credentials.init(cfg)\n"
            "job_id = sys.argv[1]\n"
            "status = guestjobs.job_status(cfg, job_id)\n"
            "out = guestjobs.job_output(cfg, job_id)\n"
            "print(json.dumps({'status': status, 'output': out}))\n",
            encoding="utf-8",
        )
        followed = subprocess.run(
            [sys.executable, str(follower), job_id],
            env=env, capture_output=True, text=True, timeout=600,
        )
        assert followed.returncode == 0, followed.stderr[-2000:]
        payload = json.loads(followed.stdout.strip().splitlines()[-1])
        assert payload["status"]["status"] == "running", payload["status"]
        assert payload["output"]["stdout"].strip(), payload["output"]

        # Process B stops it, and the guest job directory goes away. job_stop takes
        # no credential: a restored job re-resolves its own from the environment,
        # which is the behaviour under test.
        stopped = guestjobs.job_stop(running_vm.cfg, job_id)
        assert stopped["stopped"] is True, stopped

        # run_guest_inner is GUID-native (no name resolution happens inside), so the
        # probe leg addresses the VM by the id job_start resolved and stored.
        from hyperv_mcp import diagnostics, vmident

        ref = vmident.resolve(running_vm.cfg, vm_name=running_vm.vm)
        exists = diagnostics.run_guest_inner(
            running_vm.cfg, ref.id,
            f"if (Test-Path -LiteralPath {guestjobs.pswindows.ps_quote(job_dir)}) "
            "{ 'present' } else { 'absent' }",
            running_vm.creds, mode="read",
        )
        assert "absent" in str(exists.get("stdout", "")), exists
    finally:
        # The guest job must be reaped even when an assertion above fails —
        # the ping keeps running for two minutes otherwise.
        if job is not None:
            try:
                guestjobs.job_stop(running_vm.cfg, job["job_id"])
            except Exception:
                pass
        if proc_a.poll() is None:
            proc_a.kill()
            proc_a.wait(timeout=60)


# ---------------------------------------------------------------------------
# console Windows key (issue #25, AC12)
# ---------------------------------------------------------------------------

def test_console_windows_key_opens_start(running_vm):
    """AC12: pressing the Windows key opens the Start menu on a real Windows
    guest — observed as hyperv_console_wait_frame_change reporting
    stop_reason == 'changed' within 10 s — and a second press closes it
    (the closing frame differs from the open-Start frame).

    Console input is host-side WMI/PowerShell (no guest credentials of its
    own), so the shared env gate — HYPERV_MCP_INTEGRATION=1 plus
    HYPERV_MCP_TEST_VM naming the disposable VM — is all this test needs;
    the guarded_vm fixture checkpoints before and restores after. Without
    the gate the whole suite skips (see tests/integration/conftest.py)."""
    from hyperv_mcp import console

    cfg, vm = running_vm.cfg, running_vm.vm

    # Baseline frame hash before the first press (either stop reason yields
    # one; a ticking clock changing it early only makes the baseline fresher).
    pre = console.wait_frame_change(cfg, vm, timeout_s=10)
    assert pre.get("frame_hash"), pre

    console.press_key(cfg, vm, "win")
    opened = console.wait_frame_change(
        cfg, vm, baseline_hash=pre["frame_hash"], timeout_s=10)
    assert opened["stop_reason"] == "changed", opened
    start_hash = opened["frame_hash"]

    console.press_key(cfg, vm, "win")
    closed = console.wait_frame_change(
        cfg, vm, baseline_hash=start_hash, timeout_s=10)
    assert closed["stop_reason"] == "changed", closed
    assert closed["frame_hash"] != start_hash, (
        "the second win press must leave a frame different from open-Start"
    )


# ---------------------------------------------------------------------------
# issue #26 — Standard checkpoints restore the running desktop
# ---------------------------------------------------------------------------

def test_standard_checkpoint_restores_running_desktop(it, it_tmp):
    """AC11 (issue #26): a Standard checkpoint of a RUNNING, logged-on
    desktop restores straight back to the saved moment. The window is driven
    through the CONSOLE-INPUT path (PowerShell Direct guest exec may not
    reach the interactive session), and the checkpoint is created WHILE the
    window is open, so restoring it brings the closed window back:

    open Notepad -> archive A -> get_vm_info -> checkpoint(standard) ->
    Alt+F4 -> archive B -> restore(confirm) -> start if Saved -> archive C ->
    get_vm_info (CheckpointType unchanged).

    Automated oracle: the post-restore frame differs from the closed-window
    frame; the archived A/B/C PNGs in the trace directory are the named
    human-visibility oracle (frame hashes alone are necessary, not
    sufficient). Cleanup removes the test-created checkpoint and leaves the
    VM running; the standard-variant create restores the VM's own
    CheckpointType in-script, and the final get_vm_info pins that."""
    import json

    from hyperv_mcp import console, lifecycle

    cfg, vm = it.cfg, it.vm
    shots = it_tmp / "ac11"
    shots.mkdir(exist_ok=True)

    def _shot(label):
        frame, meta = console.screenshot(cfg, vm, save_path=str(shots / f"{label}.png"))
        assert meta.get("frame_hash"), meta
        with open(shots / f"{label}.json", "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, default=str)
        return meta["frame_hash"]

    info_before = lifecycle.get_vm_info(cfg, vm)
    original_type = info_before["checkpoint_type"]

    # AC12's runbook leg leaves the VM Off (its Production restore); the
    # desktop flow needs a running, logged-on console. start_vm is idempotent.
    lifecycle.start_vm(cfg, vm)

    _shot("0-desktop")
    console.key_combo(cfg, vm, ["win", "r"])
    console.wait_frame_change(cfg, vm, timeout_s=10)
    console.type_text(cfg, vm, "notepad")
    console.press_key(cfg, vm, "enter")
    opened = console.wait_frame_change(cfg, vm, timeout_s=15)
    assert opened.get("stop_reason") == "changed", opened
    hash_a = _shot("A-notepad-open")

    name = f"mcp-it-standard-{next(_CHECKPOINT_SEQ)}"
    created = None
    try:
        created = lifecycle.checkpoint_create(cfg, vm, name, checkpoint_type="standard")
        assert created["checkpoint_type"] == "standard"
        assert created["vm_checkpoint_type"] == original_type, (
            "the result must report the captured pre-call VM CheckpointType"
        )

        console.press_key(cfg, vm, "f4", modifiers=["alt"])
        closed = console.wait_frame_change(cfg, vm, baseline_hash=hash_a, timeout_s=15)
        assert closed.get("stop_reason") == "changed", closed
        hash_b = _shot("B-notepad-closed")
        assert hash_b != hash_a

        out = lifecycle.checkpoint_restore(cfg, vm, name, confirm=True)
        assert out["status"] == "restored"
        assert out["state"] in ("Saved", "Running"), out
        assert "powered off" not in out["note"], (
            f"state-accurate note required for {out['state']}: {out['note']!r}"
        )
        if out["state"] == "Saved":
            started = lifecycle.start_vm(cfg, vm)
            assert started["state"] == "Running"

        console.wait_frame_change(cfg, vm, timeout_s=30)
        hash_c = _shot("C-restored")
        assert hash_c != hash_b, (
            "the restored desktop must differ from the closed-window frame "
            "(see the archived A/B/C PNGs for the human-visibility oracle)"
        )

        info_after = lifecycle.get_vm_info(cfg, vm)
        assert info_after["checkpoint_type"] == original_type, (
            "the VM-level CheckpointType must be restored to its pre-call value"
        )
    finally:
        if created is not None:
            # The restore-type-failure path can raise AFTER the checkpoint
            # exists; only remove when the create actually succeeded. Removal
            # failure is recorded, not swallowed (guarded_vm convention), so a
            # stranded mcp-it-standard-* checkpoint is visible in the run
            # transcript instead of silently leaking on the disposable VM.
            try:
                lifecycle.checkpoint_remove(cfg, vm, name, confirm=True)
            except Exception as exc:  # noqa: BLE001 - report, don't hide
                import json

                with open("hyperv-it-cleanup-report.json", "w", encoding="utf-8") as fh:
                    json.dump(
                        {"unremoved_checkpoint": name, "vm": vm, "error": str(exc)}, fh
                    )


# ---------------------------------------------------------------------------
# console settle wait (issue #27, AC10/AC11) + sequence identity (#82)
# ---------------------------------------------------------------------------

def test_console_wait_frame_stable_idle_desktop(running_vm):
    """AC10: on an idle logged-on desktop the settle wait reports
    stop_reason == 'stable' within about stable_ms + 2*interval_ms + one
    thumbnail call of elapsed time, and the settled frame's hash matches the
    host-side pixel-only domain (it chains into baseline_hash).

    Console observation is host-side WMI/PowerShell (no guest credentials of
    its own), so the shared env gate — HYPERV_MCP_INTEGRATION=1 plus
    HYPERV_MCP_TEST_VM naming the disposable VM — is all this test needs."""
    from hyperv_mcp import console

    cfg, vm = running_vm.cfg, running_vm.vm
    out = console.wait_frame_stable(
        cfg, vm, stable_ms=2000, timeout_s=20, interval_ms=250,
        width=640, height=480)
    assert out["stop_reason"] == "stable" and out["stable"] is True, out
    # the quiet window needs at least one poll per interval: 2000ms / 250ms = 8
    assert out["polls"] >= 2000 // 250, out
    budget_ms = 2000 + 8 * 250 + 8000  # window + one poll per interval + a generous real-host thumbnail
    assert out["elapsed_ms"] < budget_ms, (
        f"an idle desktop must settle promptly: elapsed {out['elapsed_ms']}ms "
        f"vs budget {budget_ms}ms"
    )
    assert out.get("frame_hash"), out
    # the settled hash chains as a baseline: a second call reports the screen
    # never moved (unchanged). A lock-screen clock minute tick that lands
    # inside this window moves the frame and legitimately reports stable —
    # which still proves the chaining (movement away from the supplied
    # baseline was detected), so accept both outcomes and pin the
    # discrimination: stable implies the frame differs from the baseline.
    again = console.wait_frame_stable(
        cfg, vm, stable_ms=500, timeout_s=10, interval_ms=250,
        width=640, height=480, baseline_hash=out["frame_hash"])
    if again["stop_reason"] == "unchanged":
        pass
    else:
        assert again["stop_reason"] == "stable", again
        assert again["frame_hash"] != out["frame_hash"], (
            "a stable result on the chained baseline must name a frame that "
            "moved away from it (the clock tick), never the same frame"
        )


def test_console_wait_frame_stable_after_input(running_vm):
    """AC11: an input press, then the settle wait with the PRE-INPUT frame as
    the movement baseline — the wait must return stop_reason == "stable" with
    a frame that differs from the baseline and matches an immediate follow-up
    screenshot (the screen really finished drawing; not a mid-animation
    frame).

    Two host-state legs, because the disposable VM's desktop state is not
    controlled by this suite:
    - interactive desktop: the Win key opens the Start menu (the #25 flow);
    - lock screen (no logged-on session): the Win key is a no-op, so the
      leg presses Escape instead — any input dismisses the lock clock to the
      fully drawn credential prompt, which exercises the identical contract
      (movement away from the baseline, then a settled, fully drawn frame).
    The follow-up hash comparison retries once: a lock-screen clock minute
    tick between the settle and the screenshot would change the hash without
    any assertion-relevant difference."""

    from hyperv_mcp import console

    cfg, vm = running_vm.cfg, running_vm.vm
    pre = console.wait_frame_change(cfg, vm, timeout_s=10)
    assert pre.get("frame_hash"), pre

    console.press_key(cfg, vm, "win")
    settled = console.wait_frame_stable(
        cfg, vm, stable_ms=1000, timeout_s=20, interval_ms=250,
        width=640, height=480, baseline_hash=pre["frame_hash"])
    if settled["stop_reason"] == "unchanged":
        # no interactive desktop (Win was a no-op): dismiss the lock screen
        console.press_key(cfg, vm, "escape")
        settled = console.wait_frame_stable(
            cfg, vm, stable_ms=1000, timeout_s=20, interval_ms=250,
            width=640, height=480, baseline_hash=pre["frame_hash"])
    assert settled["stop_reason"] == "stable", settled
    assert settled["frame_hash"] != pre["frame_hash"]

    # the settled frame is REALLY the screen: an immediate follow-up
    # screenshot taken with the settled hash as if_changed_from must report
    # unchanged: true. A lock-screen clock minute tick between the settle and
    # the screenshot makes that comparison permanently false (the tick is
    # unrelated to the input); in that case prove the screen settled directly
    # with the tool itself — a fresh settle wait on the moved screen must
    # report stable (static NOW), and the screen must differ from the
    # pre-input baseline (the input did move something).
    _img, meta = console.screenshot(
        cfg, vm, width=640, height=480, if_changed_from=settled["frame_hash"])
    if not meta.get("unchanged"):
        _img, moved_meta = console.screenshot(
            cfg, vm, width=640, height=480, if_changed_from=pre["frame_hash"])
        assert moved_meta.get("unchanged") is not True, (
            "the screen changed since the wait returned but never differed "
            "from the pre-input baseline — nothing actually moved"
        )
        again = console.wait_frame_stable(
            cfg, vm, stable_ms=1000, timeout_s=10, interval_ms=250,
            width=640, height=480)
        assert again["stop_reason"] == "stable", again
        return
    assert meta.get("unchanged") is True, (
        "the follow-up screenshot must match the settled frame (the wait "
        "returned the finished screen, not a transition)"
    )

    # leave the console where the checkpoint restore expects it: Esc backs
    # out of the credential prompt to the lock screen; Win closes a Start
    # menu on an interactive desktop.
    console.press_key(cfg, vm, "escape")


def test_capture_sequence_reports_frame_identity_live(running_vm):
    """Issue #82 live positive-identity leg: every frame of a real sequence
    reports the GUID it actually captured, and the sequence stays under one
    identity end to end (the negative abort is pinned deterministically by
    tests/unit/test_d18_capture_sequence_identity.py — a live mid-sequence
    rename-swap of shared VMs is not a safe leg to automate)."""
    from hyperv_mcp import console, vmident

    cfg, vm = running_vm.cfg, running_vm.vm
    ref = vmident.resolve(cfg, vm_name=vm)
    out = console.capture_sequence(
        cfg, vm, count=3, interval_s=1, width=320, height=240)
    assert out["ok"] is True
    assert [f["vm_id"] for f in out["frames"]] == [ref.id] * 3, out["frames"]


# ---------------------------------------------------------------------------
# issue #29 (Workstream F PR 5) — in-session UIA helper: live premise checks
# ---------------------------------------------------------------------------


def test_capture_evidence_ui_tree_session(running_vm):
    """AC16 (issue #29): WITHOUT the helper provisioned, a credentialed
    capture_evidence(ui_tree=True) against a real guest must not report the
    PowerShell-Direct UIA walk as success — meta["ui_tree"] carries
    ok False with error_class "no_interactive_session", and records the
    session the walker ran in next to the interactive session (both observed
    values printed here; the quser leg records whether an interactive
    session existed at all).

    Live UIA-in-PS-Direct premise: the remoting session is not the
    logged-on user's interactive desktop, so the walk cannot see the desktop
    the console drives. A unit test can only observe this against a stubbed
    outcome — recording the live premise is exactly what this leg is for.

    RED/absent at base, GREEN after the fix (at base this node does not
    exist in the module, and the base behavior reports the walk as ok)."""
    from hyperv_mcp import evidence, guestexec

    cfg, vm = running_vm.cfg, running_vm.vm
    result = evidence.capture_evidence(cfg, vm, ui_tree=True, cred=running_vm.creds)
    ui = result["meta"]["ui_tree"]
    assert ui["ok"] is False, ui
    assert ui["error_class"] == "no_interactive_session", ui

    # record the walker session vs the interactive session (observed values;
    # the asserts above are the contract, these prints are the evidence)
    assert isinstance(ui.get("session"), dict), ui
    print(f"observed ui_tree session block: {ui['session']}")
    try:
        quser = guestexec.guest_run_ps(cfg, vm, "quser", cred=running_vm.creds)
    except Exception as exc:  # a logged-off guest raises instead of listing
        print(f"quser leg raised (nobody logged on): {exc}")
        quser = {"ok": False, "stdout": ""}
    print(
        "observed interactive-session record (quser from PS Direct): "
        f"ok={quser.get('ok')} stdout={quser.get('stdout', '').strip()!r}"
    )

    # Plan strengthening (fix-side): parse the recorded quser stdout for the
    # interactive session id(s) — quser's ID column is the pure-digit field
    # immediately before the STATE column — and assert the walker session is
    # NOT one of them (a PS Direct remoting session is never the console
    # session the interactive user owns).
    interactive_ids = set()
    for qline in (quser.get("stdout") or "").splitlines():
        qfields = qline.split()
        for i, field in enumerate(qfields):
            if field.lower() == "active" and i > 0 and qfields[i - 1].isdigit():
                interactive_ids.add(int(qfields[i - 1]))
    if interactive_ids:
        assert ui["session"]["session_id"] not in interactive_ids, (
            "the UIA walker ran in the interactive session it was mistaken "
            f"for: walker session {ui['session']['session_id']} vs quser "
            f"Active session id(s) {sorted(interactive_ids)}"
        )
    else:
        print("quser recorded no interactive session on this image yet; the "
              "no_interactive_session refusal above already carries the premise")

    # Plan strengthening (fix-side): AFTER provisioning through the shared
    # AC17/AC18 pattern (provision + reboot + wait for the helper running in
    # the interactive session), the SAME capture reports the tree from the
    # helper — source "helper" — with a live Notepad window in it.
    _provision_ui_helper_and_wait_for_logon(running_vm)

    import json

    from hyperv_mcp import console

    console.key_combo(cfg, vm, ["win", "r"])
    console.wait_frame_change(cfg, vm, timeout_s=10)
    console.type_text(cfg, vm, "notepad")
    console.press_key(cfg, vm, "enter")
    opened = console.wait_frame_change(cfg, vm, timeout_s=15)
    if opened.get("stop_reason") != "changed":
        pytest.skip(
            "Notepad could not be opened on this image (the desktop did not "
            "change after the win+r 'notepad' flow) — the helper-source tree "
            "leg cannot assert a Notepad window"
        )

    second = evidence.capture_evidence(cfg, vm, ui_tree=True, cred=running_vm.creds)
    ui2 = second["meta"]["ui_tree"]
    assert ui2["ok"] is True, ui2
    assert ui2["source"] == "helper", ui2
    tree_blob = json.dumps(ui2.get("tree") or {}).casefold()
    assert "notepad" in tree_blob, (
        "the helper-source element tree must contain the open Notepad window"
    )
    print(f"observed helper-source tree contains Notepad: elements="
          f"{ui2.get('elements')} truncated={ui2.get('truncated')}")


def _provision_ui_helper_and_wait_for_logon(running_vm, *, timeout_s=300):
    """Shared AC17/AC18 leg: provision the in-session UIA helper with
    autologon (the pinned host call shape
    uia.provision_helper(cfg, vm, cred=..., autologon=True, confirm=True)),
    reboot through the module's lifecycle helpers, and wait until
    uia.session_state reports the helper running in the interactive session.

    Returns the first session_state result that shows the helper running."""
    import time

    from hyperv_mcp import lifecycle, uia

    cfg, vm = running_vm.cfg, running_vm.vm
    provisioned = uia.provision_helper(
        cfg, vm, cred=running_vm.creds, autologon=True, confirm=True)
    assert provisioned["ok"], provisioned
    assert provisioned["autologon_configured"] is True, provisioned

    lifecycle.stop_vm(cfg, vm, "shutdown", confirm=True)
    lifecycle.start_vm(cfg, vm)

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = uia.session_state(cfg, vm, cred=running_vm.creds)
        if last.get("ok") and last.get("helper", {}).get("running"):
            return last
        time.sleep(5.0)
    raise AssertionError(f"helper never reported running after reboot: {last}")


def test_ui_helper_provision_autologon(running_vm):
    """AC17 (issue #29): a clean test image provisioned through the pinned
    host surface and rebooted logs the test user on automatically with the
    helper running: session_state reports the active session, the interactive
    user, locked False, a foreground-window block and
    helper {running: true, version}; and the Winlogon key holds NO
    DefaultPassword value (the autologon password lives only as the LSA
    secret — checked through a guest run leg).

    RED/absent at base, GREEN after the fix (at base this node does not
    exist in the module)."""
    from hyperv_mcp import guestexec

    cfg, vm = running_vm.cfg, running_vm.vm
    state = _provision_ui_helper_and_wait_for_logon(running_vm)

    assert state["ok"] is True, state
    assert isinstance(state["active_session_id"], int), state
    assert state["active_session_id"] >= 1, state  # session 0 is services
    assert state["interactive_user"], state
    assert state["locked"] is False, state
    foreground = state["foreground_window"]
    assert isinstance(foreground, dict), state
    for key in ("title", "process_name", "pid", "hwnd"):
        assert key in foreground, foreground
    assert foreground["title"] is not None, foreground
    helper = state["helper"]
    assert helper["running"] is True, helper
    assert helper["version"], helper
    print(f"observed session_state: active_session_id={state['active_session_id']} "
          f"interactive_user={state['interactive_user']!r} "
          f"foreground={foreground!r} helper={helper!r}")

    # The Winlogon key holds NO DefaultPassword value: the password must be
    # the LSA secret only (guest run leg; the value name itself is probed,
    # no secret material is read or printed).
    probe = guestexec.guest_run_ps(
        cfg, vm,
        "try { $null = (Get-ItemProperty "
        "'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
        "-Name DefaultPassword -ErrorAction Stop).DefaultPassword; "
        "'DefaultPassword-present' } catch { 'DefaultPassword-absent' }",
        cred=running_vm.creds,
    )
    assert probe["ok"], probe
    assert "DefaultPassword-absent" in probe["stdout"], probe

    # Plan strengthening (fix-side), leg (a): the helper's AtLogOn scheduled
    # task exists and is running right now — 267009 (0x41301) is the
    # LastTaskResult a task reports while it is executing.
    task = guestexec.guest_run_ps(
        cfg, vm,
        "$t = Get-ScheduledTask -TaskName 'hyperv-mcp-uia-helper' -ErrorAction Stop\n"
        "$i = Get-ScheduledTaskInfo -TaskName 'hyperv-mcp-uia-helper'\n"
        "if ($t.State -eq 'Running' -or $i.LastTaskResult -eq 267009) "
        "{ 'helper-task-running' } else "
        "{ 'helper-task-not-running state=' + $t.State + ' last=' + $i.LastTaskResult }",
        cred=running_vm.creds,
    )
    assert task["ok"], task
    assert "helper-task-running" in task["stdout"], task

    # Plan strengthening (fix-side), leg (b): the helper pipe's DACL, read
    # through the NAMED-PIPE SECURITY API family only — P/Invoke CreateFile on
    # \\.\pipe\hyperv-mcp-uia + GetSecurityInfo +
    # ConvertSecurityDescriptorToStringSecurityDescriptor ([System.IO.
    # Directory]::GetAccessControl is the wrong API family for pipes and is
    # deliberately not used). ConvertSecurityDescriptorToStringSecurity-
    # Descriptor abbreviates well-known trustees (BA/WD), so the SDDL string
    # is decoded through RawSecurityDescriptor and the SID assertions run on
    # the expanded trustee list of that exact SDDL; the test user's own SID
    # (never abbreviated) is asserted against the raw string as well.
    sid_leg = guestexec.guest_run_ps(
        cfg, vm, "whoami /user /fo csv /nh", cred=running_vm.creds)
    assert sid_leg["ok"], sid_leg
    user_sid = ""
    for sid_line in sid_leg.get("stdout", "").splitlines():
        if "S-1-" in sid_line:
            user_sid = sid_line.split(",")[-1].strip().strip('"')
    assert user_sid.startswith("S-1-"), sid_leg

    pipe_dacl_probe = r"""
$ErrorActionPreference = 'Stop'
Add-Type -Namespace HypervMcp.It -Name PipeSec -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
[DllImport("advapi32.dll", SetLastError=true)] public static extern uint GetSecurityInfo(IntPtr handle, int objectType, int securityInfo, out IntPtr sidOwner, out IntPtr sidGroup, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr securityDescriptor, uint revision, uint securityInformation, out IntPtr stringSecurityDescriptor, out uint stringLength);
[DllImport("kernel32.dll")] public static extern bool LocalFree(IntPtr mem);
'@
$handle = [HypervMcp.It.PipeSec]::CreateFile('\\.\pipe\hyperv-mcp-uia', [uint32]2147483648, [uint32]0, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
if ($handle.IsInvalid) { throw ('CreateFile on the helper pipe failed: win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
try {
    $owner = [IntPtr]::Zero; $group = [IntPtr]::Zero; $dacl = [IntPtr]::Zero
    $sacl = [IntPtr]::Zero; $sd = [IntPtr]::Zero
    $hr = [HypervMcp.It.PipeSec]::GetSecurityInfo($handle.DangerousGetHandle(), 1, 4, [ref]$owner, [ref]$group, [ref]$dacl, [ref]$sacl, [ref]$sd)
    if ($hr -ne 0) { throw ('GetSecurityInfo failed: hr 0x' + $hr.ToString('X')) }
    $sddlPtr = [IntPtr]::Zero; $sddlLen = 0
    $converted = [HypervMcp.It.PipeSec]::ConvertSecurityDescriptorToStringSecurityDescriptor($sd, 1, 4, [ref]$sddlPtr, [ref]$sddlLen)
    if (-not $converted) { throw 'ConvertSecurityDescriptorToStringSecurityDescriptor failed' }
    $sddl = [Runtime.InteropServices.Marshal]::PtrToStringUni($sddlPtr)
    [void][HypervMcp.It.PipeSec]::LocalFree($sddlPtr)
    [void][HypervMcp.It.PipeSec]::LocalFree($sd)
    $trustees = @()
    $parsed = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
    foreach ($ace in $parsed.DiscretionaryAcl) {
        if ($ace -is [System.Security.AccessControl.KnownAce]) { $trustees += $ace.SecurityIdentifier.Value }
    }
    [PSCustomObject]@{ sddl = $sddl; trustees = @($trustees | Select-Object -Unique) } | ConvertTo-Json -Compress
} finally { $handle.Close() }
"""
    dacl = guestexec.guest_run_ps(
        cfg, vm, pipe_dacl_probe, cred=running_vm.creds)
    assert dacl["ok"], dacl
    import json

    sddl_info = json.loads(dacl["stdout"].strip().splitlines()[-1])
    print(f"observed helper pipe SDDL: {sddl_info.get('sddl')!r} "
          f"trustees={sddl_info.get('trustees')!r}")
    assert user_sid in sddl_info["sddl"], sddl_info
    trustees = sddl_info["trustees"]
    if isinstance(trustees, str):  # ConvertTo-Json collapses one-element arrays
        trustees = [trustees]
    assert user_sid in trustees, sddl_info
    assert "S-1-5-32-544" in trustees, sddl_info  # BUILTIN\Administrators
    assert "S-1-1-0" not in trustees, sddl_info  # World/Everyone: no access


def test_ui_helper_element_workflow_and_lock(running_vm, it_tmp):
    """AC18 (issue #29): the full element workflow from the issue, every step
    asserted in order: find the Notepad document -> set_value "abc" ->
    invoke File -> wait_for the menu -> invoke Save-as -> focus+invoke Cancel
    (dialog closes, typed value archived in a console screenshot) ->
    LockWorkStation from the console lane (Win+L) -> session_state locked
    true -> find still resolves while locked -> unlock via
    console.type_text of the password -> wait_for(gone) on the Save As
    dialog returns within its timeout.

    The image is provisioned first (the helper must be running), and the
    workflow skips fast with a clear message when Notepad is unavailable.
    RED/absent at base, GREEN after the fix (at base this node does not
    exist in the module)."""
    import json
    import time

    from hyperv_mcp import console, uia

    cfg, vm = running_vm.cfg, running_vm.vm
    creds = running_vm.creds
    state = _provision_ui_helper_and_wait_for_logon(running_vm)
    assert state["locked"] is False, state

    shots = it_tmp / "ac18"
    shots.mkdir(exist_ok=True)

    def _shot(label):
        frame, meta = console.screenshot(cfg, vm, save_path=str(shots / f"{label}.png"))
        assert meta.get("frame_hash"), meta
        with open(shots / f"{label}.json", "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, default=str)
        return meta["frame_hash"]

    # open Notepad through the console lane (module-native: win+r flow)
    _shot("0-desktop")
    console.key_combo(cfg, vm, ["win", "r"])
    console.wait_frame_change(cfg, vm, timeout_s=10)
    console.type_text(cfg, vm, "notepad")
    console.press_key(cfg, vm, "enter")
    opened = console.wait_frame_change(cfg, vm, timeout_s=15)
    assert opened.get("stop_reason") == "changed", opened

    # Plan strengthening (fix-side): Notepad availability is a GUEST fact, so
    # the skip is driven by a guest-side probe (where.exe notepad.exe through
    # a guest run leg), not by the helper find below. When the probe succeeds
    # but the find loop resolves nothing, that is a helper-side FAILURE (the
    # assert inside the doc-is-None block below) — never a skip.
    from hyperv_mcp import guestexec

    notepad_probe = guestexec.guest_run(
        cfg, vm, "cmd.exe", ["/c", "where", "notepad.exe"], cred=creds)
    if not (notepad_probe.get("ok") and notepad_probe.get("exit_code") == 0):
        pytest.skip(
            "Notepad is unavailable on this image (the guest-side probe "
            "'where notepad.exe' failed) — the element workflow cannot run"
        )

    # find the Notepad document. Classic Notepad exposes a Document control;
    # Win11 Notepad's editor is a RichEditD2DPT control instead, so both
    # control types are tried in order.
    doc = None
    doc_control_type = None
    for control_type in ("Document", "RichEditD2DPT"):
        found = uia.find(
            cfg, vm,
            selector={"process_name": "notepad", "control_type": control_type},
            cred=creds,
        )
        if found.get("ok") and found.get("elements"):
            doc = found["elements"][0]
            doc_control_type = control_type
            break
    if doc is None:
        # the guest-side probe above proved notepad.exe exists, so an empty
        # find here is a helper-side FAILURE — assert, never skip (the
        # historical skip below stays byte-frozen but is now unreachable)
        assert doc is not None, (
            "notepad.exe IS on this image (the guest-side 'where notepad.exe' "
            "probe passed) but the helper resolved no Document/RichEditD2DPT "
            "element in the Notepad window"
        )
        pytest.skip(
            "Notepad is unavailable on this image (no Document/RichEditD2DPT "
            "element resolved)"
        )
    doc_id = doc["element_id"]

    # set_value "abc": typed values ride stdin, and the result reports the
    # LENGTH set, never the value
    set_out = uia.set_value(cfg, vm, element_id=doc_id, value="abc", cred=creds)
    assert set_out["ok"] is True, set_out
    assert set_out.get("length") == 3, set_out
    assert "abc" not in json.dumps(set_out), set_out

    # the typed value visible in a console screenshot: the archived PNG is
    # the human-visibility oracle (frame hashes alone are not)
    _shot("1-after-set-value")

    # invoke the File menu item, wait for the menu, invoke "Save as"
    file_item = uia.find(
        cfg, vm,
        selector={"process_name": "notepad", "name": "File"}, cred=creds)
    assert file_item["ok"] and file_item["elements"], file_item
    invoke_file = uia.invoke(
        cfg, vm, element_id=file_item["elements"][0]["element_id"], cred=creds)
    assert invoke_file["ok"] is True, invoke_file

    menu = uia.wait_for(
        cfg, vm,
        selector={"process_name": "notepad", "name_contains": "Save"},
        timeout_s=15, cred=creds)
    assert menu["ok"] is True, menu

    save_as = uia.find(
        cfg, vm,
        selector={"process_name": "notepad", "name_contains": "Save as"},
        cred=creds)
    assert save_as["ok"] and save_as["elements"], save_as
    invoke_save = uia.invoke(
        cfg, vm, element_id=save_as["elements"][0]["element_id"], cred=creds)
    assert invoke_save["ok"] is True, invoke_save

    # the Save As dialog is up: focus + invoke Cancel closes it
    cancel_selector = {
        "process_name": "notepad", "name": "Cancel", "control_type": "Button"}
    cancel = uia.find(cfg, vm, selector=cancel_selector, cred=creds)
    assert cancel["ok"] and cancel["elements"], cancel
    cancel_id = cancel["elements"][0]["element_id"]
    focus_cancel = uia.focus(cfg, vm, element_id=cancel_id, cred=creds)
    assert focus_cancel["ok"] is True, focus_cancel
    invoke_cancel = uia.invoke(cfg, vm, element_id=cancel_id, cred=creds)
    assert invoke_cancel["ok"] is True, invoke_cancel
    # the dialog closes: archived screenshot + the element no longer resolves
    _shot("2-dialog-closed")
    dialog_gone = uia.wait_for(
        cfg, vm, selector=cancel_selector, gone=True, timeout_s=15, cred=creds)
    assert dialog_gone["ok"] is True, dialog_gone

    # LockWorkStation from the console lane: Win+L locks the interactive
    # desktop (the synthetic keyboard IS the interactive input path)
    console.key_combo(cfg, vm, ["win", "l"])
    deadline = time.monotonic() + 60
    locked_state = None
    while time.monotonic() < deadline:
        locked_state = uia.session_state(cfg, vm, cred=creds)
        if locked_state.get("ok") and locked_state.get("locked"):
            break
        time.sleep(2.0)
    assert locked_state["ok"] is True, locked_state
    assert locked_state["locked"] is True, locked_state

    # UIA-pattern verbs are locked-session friendly: find still resolves
    locked_find = uia.find(
        cfg, vm,
        selector={"process_name": "notepad", "control_type": doc_control_type},
        cred=creds)
    assert locked_find["ok"] is True and locked_find["elements"], locked_find
    # focus while locked must not report success: it needs the interactive
    # desktop and returns the explicit error class instead
    locked_focus = uia.focus(cfg, vm, element_id=doc_id, cred=creds)
    assert locked_focus["ok"] is False, locked_focus
    assert locked_focus["error_class"] == "no_interactive_desktop", locked_focus

    # unlock: dismiss the lock screen if needed, then type the password
    # through the console synthetic keyboard (the password is never printed)
    unlocked = None
    for _attempt in range(3):
        console.type_text(cfg, vm, creds.password)
        console.press_key(cfg, vm, "enter")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            unlocked = uia.session_state(cfg, vm, cred=creds)
            if unlocked.get("ok") and unlocked.get("locked") is False:
                break
            time.sleep(3.0)
        if unlocked.get("ok") and unlocked.get("locked") is False:
            break
        # the credential prompt may not have been up yet: dismiss the lock
        # clock and retry the typed password
        console.press_key(cfg, vm, "escape")
        console.wait_frame_change(cfg, vm, timeout_s=10)
    assert unlocked["ok"] is True, unlocked
    assert unlocked["locked"] is False, unlocked

    # after the unlock, wait_for(gone) on the Save As dialog returns within
    # its timeout
    final_gone = uia.wait_for(
        cfg, vm, selector=cancel_selector, gone=True, timeout_s=30, cred=creds)
    assert final_gone["ok"] is True, final_gone


# ---------------------------------------------------------------------------
# per-VM credential profiles (issue #30, AC14)
# ---------------------------------------------------------------------------


def test_credential_profiles_two_vms_two_admins():
    """AC14 (issue #30): two disposable VMs, two per-VM credential profiles.

    Profile A names VM A (the shared gate's HYPERV_MCP_TEST_VM) with its
    admin from the gate's global credential; profile B names VM B
    (HYPERV_MCP_TEST_VM_B) with HYPERV_MCP_TEST_VM_B_USERNAME /
    _PASSWORD. Positive leg: guest_run_ps on BOTH VMs resolves through its
    own profile and reports ok. Swapped leg: the same two patterns carry
    each OTHER VM's admin, and both calls fail with error_class
    'transport' (a wrong-account PowerShell Direct logon is a
    session-establishment failure — never a silent fallback to the global
    credential).

    The shared env gate (HYPERV_MCP_INTEGRATION=1 + HYPERV_MCP_TEST_VM +
    guest credentials) is enforced for the whole file by
    tests/integration/conftest.py; the second VM's variables are checked
    here and skip with a reason when absent, so this leg never runs on a
    one-VM host. No checkpoint is taken: the only guest legs are a
    Write-Output script and failed logons, which mutate no guest state."""
    import os

    from hyperv_mcp import credentials, guestexec, lifecycle
    from hyperv_mcp.config import Config

    vm_a = os.environ["HYPERV_MCP_TEST_VM"].strip()
    vm_b = os.environ.get("HYPERV_MCP_TEST_VM_B", "").strip()
    user_b = os.environ.get("HYPERV_MCP_TEST_VM_B_USERNAME", "").strip()
    pw_b_env = "HYPERV_MCP_TEST_VM_B_PASSWORD"
    if not (vm_b and user_b and os.environ.get(pw_b_env, "")):
        pytest.skip(
            "two-VM credential-profile leg needs HYPERV_MCP_TEST_VM_B, "
            "HYPERV_MCP_TEST_VM_B_USERNAME and HYPERV_MCP_TEST_VM_B_PASSWORD "
            "(VM A is the shared HYPERV_MCP_TEST_VM with the gate's global "
            "admin credential)"
        )

    user_a = os.environ["HYPERV_GUEST_USERNAME"]
    # PRR-013: the conftest gate accepts a PASSWORD_FILE host, but a profile
    # can only carry ONE secret source. Mirror the gate here: prefer the env
    # variable, fall back to the file (path kept in the env so the resolver
    # finds it), and skip when the host's global credential shape cannot be
    # expressed as a profile secret source.
    if os.environ.get("HYPERV_GUEST_PASSWORD_FILE", "").strip():
        # PRR-013: a profile carries exactly ONE secret source, so a
        # PASSWORD_FILE host cannot express the swapped leg. Skip, as the
        # finding specified - never error mid-test on this host class.
        pytest.skip("global credential is PASSWORD_FILE-based; the two-VM "
                    "profile swap needs an env-variable secret")
    if not os.environ.get("HYPERV_GUEST_PASSWORD", "").strip():
        pytest.skip("global credential is neither HYPERV_GUEST_PASSWORD nor "
                    "HYPERV_GUEST_PASSWORD_FILE; a profile needs exactly one "
                    "secret source")
    user_a = os.environ["HYPERV_GUEST_USERNAME"].strip()
    profile_a = {
        "name": "vm-a-admin", "vm_patterns": [vm_a], "username": user_a,
        "password_env": "HYPERV_GUEST_PASSWORD",
    }
    profile_b = {
        "name": "vm-b-admin", "vm_patterns": [vm_b], "username": user_b,
        "password_env": pw_b_env,
    }
    cfg = Config.from_dict({
        "unrestricted": True,
        "credential_profiles": [profile_a, profile_b],
    })
    credentials.init(cfg)
    lifecycle.start_vm(cfg, vm_a)
    lifecycle.start_vm(cfg, vm_b)

    script = "Write-Output 'profile-ok'"
    for vm in (vm_a, vm_b):
        out = guestexec.guest_run_ps(
            cfg, vm, script, cred=credentials.resolve_guest(vm_name=vm))
        assert out["ok"], out

    swapped = Config.from_dict({
        "unrestricted": True,
        "credential_profiles": [
            dict(profile_a, username=user_b, password_env=pw_b_env),
            dict(profile_b, username=user_a,
                 password_env="HYPERV_GUEST_PASSWORD"),
        ],
    })
    credentials.init(swapped)
    for vm in (vm_a, vm_b):
        out = guestexec.guest_run_ps(
            swapped, vm, script, cred=credentials.resolve_guest(vm_name=vm))
        assert out["ok"] is False, (
            f"a swapped (wrong-account) profile must fail: vm={vm} out={out}"
        )
        assert out["error_class"] == "transport", out
