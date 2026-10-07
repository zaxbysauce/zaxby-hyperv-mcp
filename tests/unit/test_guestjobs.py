"""Guest job tests with mocked PowerShell: async start semantics, registry
thread safety, status transitions, bounded tail decode, exact-PID stop."""

import base64
import json
import re
import threading
import uuid

import pytest

from hyperv_mcp import guestjobs, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")

# Identity resolution (issue #8): vmident.resolve runs a by-name leg before
# job_start. Distinct VM names must resolve to DISTINCT GUIDs — the lock and
# the registry now key on the GUID, so a shared fake GUID would falsely make
# different VMs collide (test_a04_vm_identity FakePS pattern, per-name guid).
_NAME_RE = re.compile(r"ElementName -eq '([^']*)'")


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _resolved_guid(script: str) -> str:
    """Stable per-name GUID: distinct names are distinct VMs."""
    m = _NAME_RE.search(script)
    return str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1) if m else ""))


class FakePS:
    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


def _start_ok():
    return _ok({"pid": 4242, "job_dir": "C:\\Users\\x\\AppData\\Local\\Temp\\hyperv-mcp-job-abc"})


@pytest.fixture(autouse=True)
def _clean_registry():
    guestjobs.clear_registry_for_tests()
    yield
    guestjobs.clear_registry_for_tests()


def _inner(script: str) -> str:
    import re

    m = re.search(r"\$enc = '([A-Za-z0-9+/=]+)'", script)
    assert m, "script must embed a b64 payload"
    return base64.b64decode(m.group(1)).decode("utf-8")


def test_start_returns_job_handle_without_wait(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_start_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestjobs.job_start(cfg, "test-vm", "sqlprobe.exe", ["--long"], cwd="C:\\work", cred=CRED)
    assert out["ok"] is True
    assert out["pid"] == 4242
    assert out["job_id"] and len(out["job_id"]) == 12
    assert out["out_path"].endswith("stdout.log")
    assert out["exit_path"].endswith("exitcode.txt")
    # Async by construction: splat Start-Process, NO Wait member.
    # scripts[0] is the identity-resolution leg; scripts[1] the start action.
    inner = _inner(fake.scripts[1])
    assert "Start-Process @sp" in inner
    assert "-Wait" not in inner
    assert "Wait" not in inner.replace("WindowStyle", "")
    assert "PassThru     = $true" in inner
    # The wrapper .ps1 rides the start script's own b64 payload: decode twice.
    wrapper = _inner(inner)
    assert "1> $outf 2> $errf" in wrapper
    assert "LASTEXITCODE" in wrapper
    assert "Set-Location -LiteralPath 'C:\\work'" in wrapper
    assert "& 'sqlprobe.exe' '--long'" in wrapper


def test_start_denied_without_vm_patterns(monkeypatch):
    cfg = Config()
    called = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", called)
    with pytest.raises(PolicyDenied):
        guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    assert called.scripts == []


def test_concurrent_starts_unique_ids(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_start_ok(), _start_ok(), _start_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    ids = []
    lock = threading.Lock()

    def worker():
        out = guestjobs.job_start(cfg, "vm-A", "x.exe", cred=CRED)
        with lock:
            ids.append(out["job_id"])

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ids) == 3
    assert len(set(ids)) == 3


def test_status_running_then_exited(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_start_ok(), _ok({"status": "running", "process_name": "sqlprobe"}),
                   _ok({"status": "exited", "exit_code": "0"})])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "sqlprobe.exe", cred=CRED)
    running = guestjobs.job_status(cfg, start["job_id"])
    assert running["status"] == "running"
    assert running["process_name"] == "sqlprobe"
    assert running["vm_name"] == "test-vm"  # resolved name from the registry (PRR-005)
    exited = guestjobs.job_status(cfg, start["job_id"])
    assert exited["status"] == "exited"
    assert exited["exit_code"] == "0"
    # Status probes the exact pid (leg index +1: resolution leg precedes start).
    assert "Get-Process -Id 4242" in _inner(fake.scripts[2])


def test_status_exiting_when_exit_file_missing(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_start_ok(), _ok({"status": "exiting"})])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    out = guestjobs.job_status(cfg, start["job_id"])
    assert out["status"] == "exiting"
    # Load-bearing (review r1 finding 15): the guest-side 'exiting' branch
    # must actually be generated, not just echoed from a canned payload.
    assert "'exiting'" in _inner(fake.scripts[2])


def test_output_tail_and_encodings(monkeypatch):
    cfg = Config(unrestricted=True)
    text = "hello world"
    fake = FakePS([
        _start_ok(),
        _ok({"head_hex": "", "tail_b64": base64.b64encode(text.encode()).decode(),
             "size": len(text), "truncated": False}),
        _ok({"head_hex": "", "tail_b64": "", "size": 0, "truncated": False}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    out = guestjobs.job_output(cfg, start["job_id"], tail_bytes=1024)
    assert out["stdout"] == text
    assert out["stdout_encoding"] == "utf-8"
    assert out["stdout_truncated"] is False
    assert out["stderr"] == ""
    assert out["vm_name"] == "test-vm"  # resolved name from the registry (PRR-005)


def test_output_truncated_utf16_tail_decodes_via_head_bom(monkeypatch):
    """The tail slice has no BOM; the stream HEAD supplies it (critic R4)."""
    cfg = Config(unrestricted=True)
    full = "long utf16 output line"
    data = full.encode("utf-16-le")  # PS 5.1 1> writes UTF-16LE
    head = b"\xff\xfe" + data[:2]
    tail = data[-13:]  # odd length on purpose: mid-codeunit start
    fake = FakePS([
        _start_ok(),
        _ok({"head_hex": head.hex(), "tail_b64": base64.b64encode(tail).decode(),
             "size": 2 + len(data), "truncated": True}),
        _ok({"head_hex": "", "tail_b64": "", "size": 0, "truncated": False}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    out = guestjobs.job_output(cfg, start["job_id"], tail_bytes=13)
    assert out["stdout_encoding"] == "utf-16"
    assert out["stdout_truncated"] is True
    # Odd byte dropped to align, then decoded without mojibake NULs.
    aligned = tail[1:].decode("utf-16-le", "replace")
    assert out["stdout"] == aligned
    assert "\x00" not in out["stdout"]


def test_stop_targets_exact_pid_and_nulls_cred(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_start_ok(), _ok({"stopped": True})])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    out = guestjobs.job_stop(cfg, start["job_id"])
    assert out["ok"] is True
    assert out["stopped"] is True
    inner = _inner(fake.scripts[2])
    assert "Stop-Process -Id 4242 -Force" in inner
    assert "Remove-Item" in inner
    # Registry: stopped + cred nulled.
    entry = guestjobs._jobs[start["job_id"]]
    assert entry["stopped"] is True
    assert entry["cred"] is None
    # A later status short-circuits without another guest leg.
    status = guestjobs.job_status(cfg, start["job_id"])
    assert status["status"] == "stopped"
    # resolve + start + stop legs only.
    assert len(fake.scripts) == 3


def test_unknown_job_id_rejected():
    cfg = Config(unrestricted=True)
    with pytest.raises(ValueError, match="unknown job_id"):
        guestjobs.job_status(cfg, "nope")


def test_registry_cap_evicts_stopped_and_nulls_cred(monkeypatch):
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestjobs._jobs["old"] = {
        "job_id": "old", "vm_name": "vm", "pid": 1, "job_dir": "d",
        "out_path": "o", "err_path": "e", "exit_path": "x",
        "started_at": "2026-01-01T00:00:00Z", "cred": CRED, "stopped": True,
    }
    guestjobs._MAX_JOBS = 1
    try:
        # Reservation evicts the stopped entry, then admits.
        guestjobs._reserve_slot("new")
        assert "new" in guestjobs._jobs
        assert "old" not in guestjobs._jobs
        assert guestjobs._jobs["new"]["in_flight"] is True
        guestjobs._release_slot("new")
        assert "new" not in guestjobs._jobs
    finally:
        guestjobs._MAX_JOBS = 128


def test_registry_cap_rejects_when_full_of_active_jobs(monkeypatch):
    """Review r1 finding 13: no silent growth when nothing is evictable."""
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestjobs._MAX_JOBS = 1
    guestjobs._jobs["active"] = {
        "job_id": "active", "vm_name": "vm", "pid": 1, "job_dir": "d",
        "out_path": "o", "err_path": "e", "exit_path": "x",
        "started_at": "2026-01-01T00:00:00Z", "cred": CRED, "stopped": False,
    }
    try:
        with pytest.raises(RuntimeError, match="registry is full"):
            guestjobs._reserve_slot("next")
        assert len(guestjobs._jobs) == 1
        # And job_start surfaces the same rejection BEFORE any guest start
        # leg: identity resolution now runs BEFORE the reservation (PRR-008
        # — a rejected identity must not consume a slot or evict history),
        # so the by-name resolution leg is the ONLY script recorded.
        with pytest.raises(RuntimeError, match="registry is full"):
            guestjobs.job_start(Config(unrestricted=True), "test-vm", "x.exe", cred=CRED)
        assert len(fake.scripts) == 1 and _is_resolution_leg(fake.scripts[0])
    finally:
        guestjobs._MAX_JOBS = 128


def test_rejected_resolve_does_not_evict_registry(monkeypatch):
    """PRR-008: identity resolution runs BEFORE the slot reservation — a
    start whose resolve REJECTS (denied VM name) must not evict stopped-job
    history nor null stored credentials, even at the cap."""
    cfg = Config(allowed_vm_patterns=["test-*"])  # 'prod-db' is denied
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    guestjobs._jobs["old"] = {
        "job_id": "old", "vm_name": "vm", "pid": 1, "job_dir": "d",
        "out_path": "o", "err_path": "e", "exit_path": "x",
        "started_at": "2026-01-01T00:00:00Z", "cred": CRED, "stopped": True,
    }
    guestjobs._MAX_JOBS = 1
    try:
        with pytest.raises(PolicyDenied):
            guestjobs.job_start(cfg, "prod-db", "x.exe", cred=CRED)
        # Registry untouched: the stopped entry survives WITH its credential
        # and no in-flight placeholder was left behind.
        assert set(guestjobs._jobs) == {"old"}
        assert guestjobs._jobs["old"]["cred"] is CRED
    finally:
        guestjobs._MAX_JOBS = 128


def test_registry_cap_atomic_across_concurrent_starts(monkeypatch):
    """Review r2 N2: the reservation must bound CONCURRENT starts on
    different VMs (vm_lock does not serialize them)."""
    import threading

    guestjobs._MAX_JOBS = 3
    try:
        cfg = Config(unrestricted=True)
        barrier = threading.Barrier(3, timeout=15)
        calls = []

        def fake_run(script, **kwargs):
            calls.append(script)
            if _is_resolution_leg(script):
                # Identity leg answers before the barrier and now runs BEFORE
                # the reservation (PRR-008): every attempt resolves first,
                # only admitted starts reach the barrier/start leg. Per-name
                # GUIDs keep the 3 VMs distinct under the GUID-keyed lock.
                return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
            barrier.wait()  # all admitted starts overlap before any registers
            return pswindows.PSResult(
                stdout=json.dumps({"pid": 100 + len(calls), "job_dir": "d"}), returncode=0,
            )

        monkeypatch.setattr(pswindows, "run_ps", fake_run)
        results: list = []
        lock = threading.Lock()

        def worker(i: int):
            try:
                out = guestjobs.job_start(cfg, f"test-vm-{i}", "x.exe", cred=CRED)
                with lock:
                    results.append(("ok", out["job_id"]))
            except RuntimeError as exc:
                with lock:
                    results.append(("rejected", str(exc)))
            except threading.BrokenBarrierError:
                with lock:
                    results.append(("barrier", ""))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        ok = [r for r in results if r[0] == "ok"]
        rejected = [r for r in results if r[0] == "rejected"]
        assert len(ok) == 3, results
        assert len(rejected) == 3, results
        assert all("registry is full" in r[1] for r in rejected)
        assert len(guestjobs._jobs) == 3
        # Every attempt resolves first (PRR-008); the 3 admitted starts add
        # one guest leg each: 6 resolution legs + 3 start legs.
        assert len(calls) == 9
    finally:
        guestjobs._MAX_JOBS = 128


def test_start_failure_releases_reserved_slot(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([pswindows.PSResult(stdout="", returncode=1, stderr="boom")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(RuntimeError, match="boom"):
        guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    assert guestjobs._jobs == {}


def test_stop_failure_keeps_entry_stoppable(monkeypatch):
    """Review r1 finding 12: a failed kill leg must not claim stopped."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _start_ok(),
        pswindows.PSResult(stdout="", returncode=1, stderr="transport down"),
        _ok({"stopped": True}),  # retry succeeds
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    first = guestjobs.job_stop(cfg, start["job_id"])
    assert first["ok"] is False
    assert first["stopped"] is False
    assert "transport down" in first["error"]
    # Entry remains stoppable: cred retained, retry reaches the guest.
    entry = guestjobs._jobs[start["job_id"]]
    assert entry["stopped"] is False
    assert entry["cred"] is not None
    second = guestjobs.job_stop(cfg, start["job_id"])
    assert second["ok"] is True
    assert second["stopped"] is True
    assert guestjobs._jobs[start["job_id"]]["cred"] is None
    assert len(fake.scripts) == 4  # resolve + start + failed stop + retry


def test_repeat_stop_returns_full_result_contract(monkeypatch):
    """Round-1 review follow-up: a repeat stop must carry every key a real
    stop returns (observation fields as honest unknowns — this call observed
    nothing), so a client written to the documented contract never hits a
    missing key on the idempotent second call."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _start_ok(),
        _ok({"stopped": True, "alive_pids": [], "job_dir_removed": True,
             "pid_reused": False}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    first = guestjobs.job_stop(cfg, start["job_id"])
    assert first["ok"] is True
    assert first["stopped"] is True
    second = guestjobs.job_stop(cfg, start["job_id"])
    assert second == {
        "ok": True, "job_id": start["job_id"], "vm_name": "test-vm", "pid": 4242,
        "stopped": True, "alive_pids": [], "job_dir_removed": None,
        "pid_reused": False, "note": "was already stopped",
    }
    # The documented key set of a real stop is a subset of the repeat's.
    assert set(first).issubset(set(second))
    # The short-circuit must not reach the guest again.
    assert len(fake.scripts) == 3  # resolve + start + first stop only


def test_output_rejects_nonpositive_tail():
    """PRR-016b: tail_bytes < 1 must ValueError (guard precedes lookup)."""
    cfg = Config(unrestricted=True)
    with pytest.raises(ValueError, match="tail_bytes"):
        guestjobs.job_output(cfg, "whatever", tail_bytes=0)


def test_output_full_read_utf16_has_no_bom_leak(monkeypatch):
    """COP-2: when the output fits tail_bytes the tail slice INCLUDES the
    UTF-16LE BOM; decoding must strip it, not leak U+FEFF."""
    cfg = Config(unrestricted=True)
    text = "small output"
    data = b"\xff\xfe" + text.encode("utf-16-le")
    fake = FakePS([
        _start_ok(),
        _ok({"head_hex": data[:4].hex(), "tail_b64": base64.b64encode(data).decode(),
             "size": len(data), "truncated": False}),
        _ok({"head_hex": "", "tail_b64": "", "size": 0, "truncated": False}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    out = guestjobs.job_output(cfg, start["job_id"], tail_bytes=4096)
    assert out["stdout"] == text
    assert out["stdout_encoding"] == "utf-16"
    assert not out["stdout"].startswith("\ufeff")
