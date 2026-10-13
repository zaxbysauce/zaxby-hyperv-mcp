"""AC7 integration check for issue #14 (trace issue-14-vm-rw-locks, C-01).

On a real disposable VM: two concurrent guest file reads through
filetransfer.guest_read_file must BOTH succeed with overlapping wall-clock
intervals (a shared read scope on one VM), and a checkpoint_create that
runs after them starts only once both readers have released (writer
exclusion).

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

from hyperv_mcp import filetransfer, lifecycle

pytestmark = [pytest.mark.hyperv_real]

# Multi-MB read so each leg lasts long enough for the second reader to
# overlap the first (the issue's AC7: "a file of a few MB").
_GUEST_FILE = r"C:\Windows\System32\ntoskrnl.exe"
_READ_BYTES = 2 * 1024 * 1024
# Stagger past the PS Direct handshake collision window (session
# establishment takes ~1-2 s on real hosts); well inside the first read's
# multi-MB hold, so the intervals still overlap.
_STAGGER_S = 2.5
_SNAPSHOT = "c01-locks-probe"


def test_guest_reads_share_vm_and_writer_waits(it):
    """AC7: concurrent reads on one VM overlap; the writer starts only after
    both readers release."""
    cfg = it.cfg
    reads: dict[str, dict] = {}

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
    r1.join(timeout=180)
    r2.join(timeout=180)

    # The two read legs shared the VM: both ok and their intervals overlapped.
    assert reads["r1"]["ok"], f"first read failed: {reads['r1']['error']}"
    assert reads["r2"]["ok"], f"second read failed: {reads['r2']['error']}"
    r1_start, r1_end = reads["r1"]["start"], reads["r1"]["end"]
    r2_start, r2_end = reads["r2"]["start"], reads["r2"]["end"]
    assert r1_start <= r2_end and r2_start <= r1_end, (
        "the two concurrent reads did not overlap in time"
    )

    # The writer runs only after both readers released: its call begins at or
    # after the later read's end, and it succeeds (no busy, no overlap).
    writer: dict = {}

    def write_worker() -> None:
        began = time.monotonic()
        try:
            out = lifecycle.checkpoint_create(cfg, vm_name=it.vm, checkpoint_name=_SNAPSHOT)
            writer.update(
                {"start": began, "end": time.monotonic(), "result": out}
            )
        except Exception as exc:
            writer.update(
                {"start": began, "end": time.monotonic(), "error": type(exc).__name__}
            )

    try:
        w = threading.Thread(target=write_worker)
        w.start()
        w.join(timeout=300)
        assert writer.get("result", {}).get("status") == "created", (
            f"checkpoint_create did not succeed: {writer}"
        )
        assert writer["start"] >= max(r1_end, r2_end), (
            "writer started before both readers released"
        )
    finally:
        try:  # best-effort cleanup on a disposable VM
            lifecycle.checkpoint_remove(
                cfg, vm_name=it.vm, checkpoint_name=_SNAPSHOT, confirm=True
            )
        except Exception:
            pass
