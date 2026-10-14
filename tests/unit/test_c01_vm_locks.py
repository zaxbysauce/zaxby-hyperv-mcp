"""Issue #14 acceptance checks (trace issue-14-vm-rw-locks, class C-01):
per-VM read/write scoping, bounded waits, and holder metadata.

Every check in this file is RED at base f4b2862, GREEN after the fix: at
base the per-VM lock is a single exclusive non-blocking mutex, so two
read-only legs on one VM cannot both run, a conflicting caller fails fast
instead of waiting inside a bounded window, VMBusy carries no holder
metadata, and vm_lock accepts no wait bound. Each test drives REAL threads
through PUBLIC functions (guestjobs.job_status, lifecycle.checkpoint_create)
with PowerShell faked to a sleeping probe that records peak concurrency and
admission order, so the checks pin observable scheduling behavior and
result contracts, not lock internals.

AC map (01-issue-summary.md):
  AC1 test_concurrent_job_reads_on_same_vm_share_the_lock
  AC2 test_conflicting_writer_waits_for_short_holder
  AC3 test_reader_waits_for_writer_without_overlap
  AC4 test_waiting_writer_is_not_starved_by_later_readers
  AC5 test_busy_error_names_the_holder
  AC6 test_bounded_wait_expires_with_busy
"""

import threading
import time

import pytest

from hyperv_mcp import auditlog, guestjobs, lifecycle, pswindows, vmident
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.vmident import VMRef
from hyperv_mcp.vmlocks import VMBusy, vm_lock

CRED = CredentialSet("Administrator", "placeholder-pass")

# job_status legs parse the payload; checkpoint legs only need returncode 0.
_STATUS_OK = '{"status": "running", "process_name": "probe.exe"}'


@pytest.fixture(autouse=True)
def _clean_job_registry():
    guestjobs.clear_registry_for_tests()
    yield
    guestjobs.clear_registry_for_tests()


def _seed_job(job_id: str, vm_id: str, pid: int) -> None:
    """Registry entry as job_start would leave it (direct dict insert, the
    test_guestjobs seeding pattern); follow-up legs address vm_id directly."""
    guestjobs._jobs[job_id] = {
        "job_id": job_id,
        "vm_name": f"vm-{job_id}",
        "vm_id": vm_id,
        "pid": pid,
        "job_dir": "C:\\job",
        "out_path": "C:\\job\\stdout.log",
        "err_path": "C:\\job\\stderr.log",
        "exit_path": "C:\\job\\exitcode.txt",
        "started_at": "2026-01-01T00:00:00Z",
        "cred": CRED,
        "stopped": False,
    }


class SleepPS:
    """Fake pswindows.run_ps: sleeps per caller, tracks the peak number of
    concurrently running legs plus admission order and entry/exit times.

    Each worker thread adopts a label first (fake.adopt); beyond that this
    is the FakePS pattern from test_guestjobs — run_ps is replaced
    wholesale, so every leg (read or write) flows through __call__ under
    whatever lock the real code holds around it."""

    def __init__(self, hold_s):
        self.hold_s = hold_s  # float for all callers, or {label: seconds}
        self._mu = threading.Lock()
        self._current = 0
        self._labels: dict[int, str] = {}
        self.peak = 0
        self.entered: list[str] = []
        self.entry_t: dict[str, float] = {}
        self.exit_t: dict[str, float] = {}

    def adopt(self, label: str) -> None:
        self._labels[threading.get_ident()] = label

    def __call__(self, script, **kwargs):
        label = self._labels.get(threading.get_ident(), "?")
        hold = self.hold_s if not isinstance(self.hold_s, dict) else self.hold_s.get(label, 0.3)
        with self._mu:
            self._current += 1
            self.peak = max(self.peak, self._current)
            self.entered.append(label)
            self.entry_t[label] = time.monotonic()
        time.sleep(hold)
        with self._mu:
            self._current -= 1
            self.exit_t[label] = time.monotonic()
        return pswindows.PSResult(stdout=_STATUS_OK, returncode=0)


def _stub_resolve(ref: VMRef):
    """checkpoint_create resolves the VM by name before locking; the stub
    pins the identity to a fixed GUID so the writer and the readers keyed
    on the same registry vm_id address ONE VM."""

    def resolve(cfg, vm_name="", vm_id=""):
        return ref

    return resolve


def _read_worker(cfg, fake, outcomes, began, job_id: str, label: str) -> None:
    fake.adopt(label)
    began[label] = time.monotonic()
    try:
        out = guestjobs.job_status(cfg, job_id)
        outcomes[label] = "ok" if out.get("ok") and out.get("status") else "bad"
    except Exception as exc:  # contention outcomes are the behavior under test
        outcomes[label] = type(exc).__name__


def _write_worker(cfg, fake, outcomes, began, vm_name: str, label: str) -> None:
    fake.adopt(label)
    began[label] = time.monotonic()
    try:
        out = lifecycle.checkpoint_create(cfg, vm_name=vm_name, checkpoint_name=f"c01-{label}")
        outcomes[label] = "ok" if out.get("status") == "created" else "bad"
    except Exception as exc:
        outcomes[label] = type(exc).__name__


def test_concurrent_job_reads_on_same_vm_share_the_lock(monkeypatch):
    """AC1: two job_status reads for two jobs on ONE VM (same vm_id) both
    succeed and their guest legs run concurrently — a shared read scope.
    At base the second read loses the single exclusive lock and dies with
    VMBusy (peak stays 1)."""
    guid = "11111111-1111-4111-8111-111111111111"
    _seed_job("c01-job-a", guid, 101)
    _seed_job("c01-job-b", guid, 102)
    fake = SleepPS(0.6)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    cfg = Config(unrestricted=True)
    outcomes: dict[str, str] = {}
    began: dict[str, float] = {}
    readers = [
        threading.Thread(target=_read_worker, args=(cfg, fake, outcomes, began, "c01-job-a", "a")),
        threading.Thread(target=_read_worker, args=(cfg, fake, outcomes, began, "c01-job-b", "b")),
    ]
    for t in readers:
        t.start()
    for t in readers:
        t.join(timeout=30)
    assert (outcomes, fake.peak) == ({"a": "ok", "b": "ok"}, 2)


def test_conflicting_writer_waits_for_short_holder(monkeypatch):
    """AC2: a second checkpoint_create arriving 0.05 s into a 0.4 s hold
    waits inside the bounded window and then succeeds; the two checkpoint
    legs never overlap, and the second call demonstrably waited rather than
    failing fast (its leg entry trails its call begin by the remaining
    hold time)."""
    guid = "22222222-2222-4222-8222-222222222222"
    monkeypatch.setattr(vmident, "resolve", _stub_resolve(VMRef(id=guid, name="c01-writers")))
    fake = SleepPS(0.4)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    cfg = Config(unrestricted=True)
    outcomes: dict[str, str] = {}
    began: dict[str, float] = {}
    w1 = threading.Thread(target=_write_worker, args=(cfg, fake, outcomes, began, "c01-writers", "w1"))
    w1.start()
    time.sleep(0.05)  # w1 holds the VM before w2 arrives
    w2 = threading.Thread(target=_write_worker, args=(cfg, fake, outcomes, began, "c01-writers", "w2"))
    w2.start()
    w1.join(timeout=30)
    w2.join(timeout=30)
    assert (outcomes, fake.peak) == ({"w1": "ok", "w2": "ok"}, 1)
    assert fake.entered == ["w1", "w2"]
    assert fake.exit_t["w1"] <= fake.entry_t["w2"]  # legs never overlapped
    waited = fake.entry_t["w2"] - began["w2"]
    assert waited >= 0.25, f"w2 entered after only {waited:.3f}s — it failed fast instead of waiting"


def test_reader_waits_for_writer_without_overlap(monkeypatch):
    """AC3: a read-scope job_status arriving 0.1 s into a write-scope
    checkpoint_create hold waits for the writer and then succeeds; the
    reader's leg never overlaps the writer's leg. At base the reader fails
    fast with VMBusy."""
    guid = "33333333-3333-4333-8333-333333333333"
    _seed_job("c01-job-r", guid, 201)
    monkeypatch.setattr(vmident, "resolve", _stub_resolve(VMRef(id=guid, name="c01-mixed")))
    fake = SleepPS({"w": 0.4, "r": 0.3})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    cfg = Config(unrestricted=True)
    outcomes: dict[str, str] = {}
    began: dict[str, float] = {}
    w = threading.Thread(target=_write_worker, args=(cfg, fake, outcomes, began, "c01-mixed", "w"))
    w.start()
    time.sleep(0.1)  # the writer holds the VM before the reader arrives
    r = threading.Thread(target=_read_worker, args=(cfg, fake, outcomes, began, "c01-job-r", "r"))
    r.start()
    w.join(timeout=30)
    r.join(timeout=30)
    assert (outcomes, fake.peak) == ({"w": "ok", "r": "ok"}, 1)
    assert fake.entered == ["w", "r"]
    assert fake.exit_t["w"] <= fake.entry_t["r"]  # legs never overlapped


def test_waiting_writer_is_not_starved_by_later_readers(monkeypatch):
    """AC4: while reader r1 holds the VM, writer w queues and reader r2
    arrives after w is already waiting — admission order must be r1, w, r2
    (the waiting writer is not starved by later readers), and everyone
    succeeds."""
    guid = "44444444-4444-4444-8444-444444444444"
    _seed_job("c01-job-r1", guid, 301)
    _seed_job("c01-job-r2", guid, 302)
    monkeypatch.setattr(vmident, "resolve", _stub_resolve(VMRef(id=guid, name="c01-starve")))
    fake = SleepPS({"r1": 0.5, "w": 0.3, "r2": 0.3})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    cfg = Config(unrestricted=True)
    outcomes: dict[str, str] = {}
    began: dict[str, float] = {}
    r1 = threading.Thread(target=_read_worker, args=(cfg, fake, outcomes, began, "c01-job-r1", "r1"))
    r1.start()
    time.sleep(0.1)  # r1 holds the read scope
    w = threading.Thread(target=_write_worker, args=(cfg, fake, outcomes, began, "c01-starve", "w"))
    w.start()
    time.sleep(0.1)  # w is queued behind r1 when r2 arrives
    r2 = threading.Thread(target=_read_worker, args=(cfg, fake, outcomes, began, "c01-job-r2", "r2"))
    r2.start()
    for t in (r1, w, r2):
        t.join(timeout=30)
    assert fake.entered == ["r1", "w", "r2"]
    assert outcomes == {"r1": "ok", "w": "ok", "r2": "ok"}


def test_busy_error_names_the_holder():
    """AC5: a conflicting acquire made inside
    auditlog.operation(tool="hyperv_checkpoint_restore", ...) raises VMBusy
    whose message names the holding tool and whose `holder` dict carries
    tool/mode/since/held_ms. Same-thread re-entry makes the contention
    deterministic (AC8 pins that re-entry still fails fast)."""
    auditlog.init(Config(unrestricted=True))
    with auditlog.operation(
        tool="hyperv_checkpoint_restore", vm_name="c01-holder", category="destructive"
    ):
        with vm_lock("c01-holder-vm"):
            with pytest.raises(VMBusy) as raised:
                with vm_lock("c01-holder-vm"):
                    pass
    exc = raised.value
    holder = getattr(exc, "holder", None)
    assert ("hyperv_checkpoint_restore" in str(exc), isinstance(holder, dict)) == (True, True)
    assert set(holder) == {"tool", "mode", "since", "held_ms"}


def test_bounded_wait_expires_with_busy():
    """AC6: vm_lock(key, wait_s=0.3) against an indefinite holder raises
    VMBusy after roughly the wait window (never proceeding without the
    lock), with holder metadata attached; the server default wait comes
    from the new registered Config key vm_lock_wait_s (default 30)."""
    acquired = threading.Event()
    release = threading.Event()

    def hold_until_released():
        with vm_lock("c01-bounded-vm"):
            acquired.set()
            release.wait(10)

    holder = threading.Thread(target=hold_until_released)
    holder.start()
    assert acquired.wait(5), "holder never acquired the VM lock"
    t0 = time.monotonic()
    try:
        with pytest.raises(VMBusy) as raised:
            with vm_lock("c01-bounded-vm", wait_s=0.3):
                pass
    finally:
        release.set()
        holder.join(timeout=5)
    waited = time.monotonic() - t0
    assert 0.25 <= waited < 1.0, f"bounded wait expired after {waited:.3f}s"
    assert isinstance(getattr(raised.value, "holder", None), dict), "busy must carry holder metadata"
    assert Config().vm_lock_wait_s == 30
