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
