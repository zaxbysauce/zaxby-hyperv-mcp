"""AC7 integration check for issue #14 (trace issue-14-vm-rw-locks, C-01).

On a real disposable VM: two concurrent guest file reads through
filetransfer.guest_read_file must BOTH succeed with overlapping wall-clock
intervals (a shared read scope on one VM), and a checkpoint_create called
WHILE both readers hold the VM must start its Checkpoint-VM leg only after
both readers release (writer exclusion under real contention — feedback
PRR-010: starting the writer after reader joins made that assertion true
by construction).

Real-host constraint observed live 2026-10-13 (the issue's own AC7 note
 anticipated this: "PS Direct session setup is serialized per VM inside
 Hyper-V"): two PS Direct session ESTABLISHMENTS fired at the same instant
 against one VM collide at the transport layer ("The credential is
 invalid" / "A remote session might have ended") — one or both legs break
 before the lock can matter. Overlapping READS are still real: a staggered
 second reader (session establishes while the first leg is mid-flight)
 completes successfully with genuinely overlapping intervals, and at base
 that same staggered second reader still dies with VMBusy (the exclusive
 lock), so the check stays discriminating. The reads use a multi-MB file
 so each leg outlives the stagger, per the issue's AC7 wording.

Never runs accidentally: tests/integration/conftest.py skips the whole suite
with an actionable reason unless HYPERV_MCP_INTEGRATION=1,
HYPERV_MCP_TEST_VM names a disposable VM, and guest credentials are
configured (HYPERV_GUEST_USERNAME plus HYPERV_GUEST_PASSWORD or
HYPERV_GUEST_PASSWORD_FILE). Without a Hyper-V host the gates stay unset
and this module skips with the conftest reason (the issue sanctions
recording AC7 as not-run there).

This file is RED at base f4b2862, GREEN after the fix: at base the second
concurrent read on one VM fails fast with VMBusy instead of sharing the VM.
"""

import threading
import time

import pytest

from hyperv_mcp import filetransfer, lifecycle, pswindows

pytestmark = [pytest.mark.hyperv_real]

# Multi-MB read so each leg lasts long enough for the second reader to
# overlap the first (the issue's AC7: "a file of a few MB").
_GUEST_FILE = r"C:\Windows\System32\ntoskrnl.exe"
_READ_BYTES = 4 * 1024 * 1024
# Stagger clear of the PS Direct handshake collision window (measured:
# same-instant establishment collides; 2.0 s leaves margin over the ~1-2 s
# setup) yet well inside the first read's 4 MB hold (observed ~4-6 s per
# leg), so the intervals overlap with >= 2 s of margin.
_STAGGER_S = 2.0
_SNAPSHOT = "c01-locks-probe"


def test_guest_reads_share_vm_and_writer_waits(it, monkeypatch):
    """AC7: concurrent reads on one VM overlap; a writer called while both
    hold the VM starts its checkpoint leg only after they release."""
    cfg = it.cfg
    reads: dict[str, dict] = {}
    second_read_entered = threading.Event()
    read_leg_entries = 0
    leg_lock = threading.Lock()
    checkpoint_leg_starts: list[float] = []

    real_run_ps = pswindows.run_ps

    def watching_run_ps(script, **kwargs):
        nonlocal read_leg_entries
        if _GUEST_FILE in script:
            with leg_lock:
                read_leg_entries += 1
                if read_leg_entries >= 2:
                    second_read_entered.set()
        if "Checkpoint-VM" in script:
            checkpoint_leg_starts.append(time.monotonic())
        return real_run_ps(script, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", watching_run_ps)

    def read_worker(label: str, delay: float) -> None:
        time.sleep(delay)
        began = time.monotonic()
        try:
            out = filetransfer.guest_read_file(
                cfg, it.vm, _GUEST_FILE, max_bytes=_READ_BYTES, cred=it.creds
            )
            reads[label] = {
                "start": began,
                "end": time.monotonic(),
                "ok": bool(out.get("ok")),
                "error": out.get("error"),
            }
        except Exception as exc:  # contention outcomes are the behavior under test
            reads[label] = {
                "start": began,
                "end": time.monotonic(),
                "ok": False,
                "error": type(exc).__name__,
            }

    r1 = threading.Thread(target=read_worker, args=("r1", 0.0))
    r2 = threading.Thread(target=read_worker, args=("r2", _STAGGER_S))
    r1.start()
    r2.start()

    # The writer is called only once BOTH reader legs are live — genuine
    # three-way contention, not a post-hoc sequence (PRR-010).
    writer: dict = {}

    def write_worker() -> None:
        began = time.monotonic()
        try:
            out = lifecycle.checkpoint_create(
                cfg, vm_name=it.vm, checkpoint_name=_SNAPSHOT
            )
            writer.update({"called": began, "end": time.monotonic(), "result": out})
        except Exception as exc:
            writer.update(
                {"called": began, "end": time.monotonic(), "error": type(exc).__name__,
                 "error_text": str(exc)[:200]}
            )

    w = threading.Thread(target=write_worker)
    assert second_read_entered.wait(120), "second reader leg never started"
    w.start()

    r1.join(timeout=180)
    r2.join(timeout=180)
    w.join(timeout=300)

    # Both reads succeeded and overlapped in wall-clock time.
    assert reads["r1"]["ok"], f"first read failed: {reads['r1'].get('error')}"
    assert reads["r2"]["ok"], f"second read failed: {reads['r2'].get('error')}"
    r1_start, r1_end = reads["r1"]["start"], reads["r1"]["end"]
    r2_start, r2_end = reads["r2"]["start"], reads["r2"]["end"]
    assert r1_start <= r2_end and r2_start <= r1_end, (
        "the two concurrent reads did not overlap in time"
    )

    # The writer really contended: it was CALLED while both reads were
    # still in flight (before the later read ended) ...
    assert writer.get("called", float("inf")) < max(r1_end, r2_end), (
        f"writer was not called during the reads: {writer}"
    )
    # ... yet its Checkpoint-VM leg only STARTED after both released, and
    # the checkpoint succeeded (writer exclusion under live contention).
    assert checkpoint_leg_starts, f"checkpoint leg never ran: {writer}"
    assert min(checkpoint_leg_starts) >= max(r1_end, r2_end), (
        "checkpoint leg started while readers still held the VM"
    )
    assert writer.get("result", {}).get("status") == "created", (
        f"checkpoint_create did not succeed: {writer}"
    )
    try:  # best-effort cleanup on a disposable VM
        lifecycle.checkpoint_remove(
            cfg, vm_name=it.vm, checkpoint_name=_SNAPSHOT, confirm=True
        )
    except Exception:
        pass
