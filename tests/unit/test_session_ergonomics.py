"""Issue #133 acceptance checks: long-run ergonomics.

RED at base, GREEN after the fix. Five checks, one per acceptance criterion:
  AC1 test_results_report_input_idle_seconds — console tool results gain
      input_idle_s, seconds since the last console input to that VM
      (a fake clock in the console module drives the measure).
  AC2 test_heartbeat_sends_key_while_leased — the opt-in per-VM heartbeat
      sends the configured benign key at the configured interval while the
      VM's lease is active.
  AC3 test_heartbeat_stops_when_lease_ends — the heartbeat stops once the
      lease is released.
  AC4 test_timeout_promotes_to_job — hyperv_guest_run_ps with
      on_timeout="job" returns a managed-job handle (the hyperv_guest_job_start
      shape) instead of a timeout error when the guest is still running at
      the deadline; the handle works with hyperv_guest_job_status.
  AC5 test_default_timeout_behavior_unchanged — without on_timeout a
      timeout still reports the current timeout error envelope
      (PRESERVING floor: error_class "timeout", timed_out true).

Surface reconciliation (the issue leaves these free; the observables here
are the contract): input_idle_s is asserted exactly on a READ console tool
after a preceding input (the unambiguous "since last input" point) and as
key-presence on an input tool's own result; the heartbeat surface is
discovered in the tool registry by name (any tool containing "heartbeat")
and driven with the common argument spellings (key/interval_s, and the
lease-bound variant) at a 50 ms interval so a bounded real-time poll
observes several sends without a single sleep over ~0.2 s.

What is faked: every PowerShell leg (pswindows.run_ps stubbed after the
FakePS patterns in tests/unit/test_console.py and test_guestexec.py — the
timeout leg reuses the frozen PSResult(timed_out=True) shape; the job lane
reuses the canned start/status payloads from test_a03_guest_jobs.py). The
idle clock is the console module's own time seam, patched after the
SimpleNamespace pattern in tests/unit/test_console_unlock_secrets.py. The
console input ledger and the guest-jobs registry are reset around every
test.
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import re
import time
import uuid
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import console, guestjobs, pswindows

VM = "ergo-vm"
GUID = str(uuid.uuid5(uuid.NAMESPACE_OID, VM))
START_TICKS = 638765432100000000
# press_key "shift" scancode literal in a folded input script (42,170 make/break)
SHIFT_CODES = "(42,170)"


class ErgoPS:
    """Adaptive run_ps stub: by-name resolution -> the stable VM GUID;
    folded display-info, video-head and capture legs; input legs -> the
    RC/CHUNK protocol."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            m = re.search(r"ElementName -eq '([^']*)'", script)
            return pswindows.PSResult(
                stdout=str(uuid.uuid5(uuid.NAMESPACE_OID,
                                      m.group(1) if m else "")),
                returncode=0)
        if "GetVirtualSystemThumbnailImage" in script:
            return pswindows.PSResult(stdout="{}", returncode=0)
        if "EnabledState" in script:
            body = json.dumps({
                "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
                "keyboard_present": True, "keyboard_enabled": 2,
                "mouse_present": True, "mouse_enabled": 2,
            })
            return pswindows.PSResult(
                stdout="VMID=" + GUID + "\n" + body, returncode=0)
        if "Msvm_VideoHead" in script:
            return pswindows.PSResult(
                stdout='{"horizontal": 1024, "vertical": 768}', returncode=0)
        if "RC=" in script or "CHUNK" in script or "TypeText" in script:
            return pswindows.PSResult(stdout="RC=1 CHUNK=1/1", returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)


class PromotePS:
    """The timeout-to-job lane, content-classified like the FakePS pattern in
    test_guestexec.py / test_a03_guest_jobs.py. The on_timeout="job" lane runs
    the script ONCE, as a managed job (single execution — the synchronous
    attempt-then-adopt shape would run the guest script twice), so the legs
    are identified by their script content rather than a call queue:
    - the by-name resolution leg answers the stable GUID;
    - the job start leg (guestjobs._start_script writes the
      hyperv-mcp-job-<id>/job.ps1 wrapper) answers the canned managed-job
      start payload once;
    - every status leg (guestjobs._status_script reads Get-Process -Id and
      emits the status='running' JSON) answers running, so the lane is
      deterministic for any poll count;
    - the plain synchronous exec leg (the no-on_timeout floor, guestexec's
      Wait = $true body) draws the frozen PSResult(timed_out=True) from the
      queue and is COUNTED in sync_count, so C14 can require zero sync legs
      (single execution: a synchronous-attempt-then-adopt implementation
      trips sync_count even though its job legs would succeed).
      (guestexec's sync leg ALSO splats Start-Process @sp — the job markers
      and Wait = $true, not the splat, discriminate the lanes.)
    """

    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.sync_count = 0
        self.start_count = 0
        # one-shot payloads per leg (job lanes answer by content below)
        self._pending: dict[str, pswindows.PSResult] = {
            "start": pswindows.PSResult(stdout=json.dumps({
                "pid": 4242,
                "job_dir": "C:\\guest-tmp\\hyperv-mcp-job-promoted",
                "start_time_ticks": START_TICKS,
            }), returncode=0),
        }
        self._actions: list[pswindows.PSResult] = [
            # the synchronous exec leg: still running at deadline
            pswindows.PSResult(timed_out=True, returncode=None, duration_ms=7),
        ]

    @staticmethod
    def _decoded(script: str) -> str:
        """CHECK_WRONG (implementation review): diagnostics.run_guest_inner
        wraps the guest-job inner script as `$enc = '<base64>'` before the
        host hop, so the job markers live in the DECODED payload, not in the
        raw script text this fake used to classify. Decode it (the same way
        test_a03_guest_jobs.py::\_inner does) before marker matching; keep the
        raw text too for legs that carry their markers literally."""
        m = re.search(r"\$enc = '([A-Za-z0-9+/=]+)'", script)
        if not m:
            return script
        try:
            return script + "\n" + base64.b64decode(m.group(1)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return script

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        body = self._decoded(script)
        # job-start leg is the only one that materializes the job dir + wrapper;
        # discriminate on those markers (guestexec's synchronous exec leg also
        # splats Start-Process @sp, so the splat is NOT a safe discriminator).
        if "hyperv-mcp-job-" in body and "job.ps1" in body:
            self.start_count += 1
            return self._pending.pop("start", pswindows.PSResult(
                stdout="{}", returncode=1))
        # status leg (guestjobs._status_script): running, stable for any poll
        # count and the later public job_status call.
        if "Get-Process -Id" in body and "status = 'running'" in body:
            return pswindows.PSResult(stdout=json.dumps({
                "status": "running", "process_name": "powershell",
            }), returncode=0)
        # the synchronous exec leg (guestexec splats Wait = $true, aligned) is
        # COUNTED, so a double-executing implementation (sync-to-timeout THEN
        # job start) trips sync_count even though its job legs would return
        # the handle. The managed-job splat has NO Wait key (guestjobs runs
        # WITHOUT -Wait by design), so normalization cannot false-positive.
        if "wait=$true" in "".join(script.split()).lower():
            self.sync_count += 1
        # synchronous exec leg (no on_timeout): the frozen timeout shape.
        if self._actions:
            return self._actions.pop(0)
        return pswindows.PSResult(stdout="{}", returncode=0)


class _FrozenClock:
    """The console module's time seam, frozen until the test moves it —
    the idle-seconds measure reads exactly this clock."""

    def __init__(self, t: float = 100.0) -> None:
        self.t = float(t)

    def monotonic(self) -> float:
        return self.t

    def perf_counter(self) -> float:
        return self.t

    def time(self) -> float:
        return self.t

    def sleep(self, s) -> None:
        return None


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)
    console.reset_input_ledger()
    guestjobs.clear_registry_for_tests()
    yield
    console.reset_input_ledger()
    guestjobs.clear_registry_for_tests()


def _boot(tmp_path: Path):
    cfg_file = tmp_path / "ergo-cfg.json"
    cfg_file.write_text(json.dumps({
        "unrestricted": True,
        "audit_log_path": str(tmp_path / "audit.jsonl"),
    }), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_file)})
    return mod


def _call(mcp, tool: str, args: dict) -> dict:
    result = asyncio.run(mcp.call_tool(tool, args))
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {tool}"
    return json.loads(texts[0].text)


# ---------------------------------------------------------------------------
# AC1 — console results report input_idle_s (fake clock)
# ---------------------------------------------------------------------------

def test_results_report_input_idle_seconds(tmp_path, monkeypatch):
    """AC1: console tool results for a VM gain input_idle_s — the seconds
    since the last console input sent to that VM through this server
    process. The clock is the console module's own time seam, so the 37.5 s
    gap is exact, not wall-clock precision.

    RED at base: no console result carries input_idle_s."""
    mod = _boot(tmp_path)
    try:
        stub = ErgoPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        clock = _FrozenClock(100.0)
        monkeypatch.setattr(console, "time", clock)
        mcp = mod.get_mcp()

        first = _call(mcp, "hyperv_console_press_key",
                      {"vm_name": VM, "key": "enter"})
        assert first.get("ok") is True, (
            "AC1: the input call must succeed against the fake transport "
            f"(envelope: {json.dumps(first)[:300]})")

        clock.t += 37.5
        # a READ console tool after the input: the unambiguous measurement
        # point — nothing this call dispatches can reset the ledger
        info = _call(mcp, "hyperv_console_get_display_info", {"vm_name": VM})
        assert info.get("ok") is True, (
            f"AC1: get_display_info must succeed (got {json.dumps(info)[:300]})")
        assert "input_idle_s" in info, (
            "AC1: console tool results must gain input_idle_s "
            f"(envelope: {json.dumps(info)[:300]})")
        assert isinstance(info["input_idle_s"], (int, float)), (
            "AC1: input_idle_s must be a number of seconds "
            f"(got {info['input_idle_s']!r})")
        assert info["input_idle_s"] == pytest.approx(37.5, abs=0.05), (
            "AC1: input_idle_s must equal the seconds since the last "
            f"console input (expected 37.5, got {info['input_idle_s']!r})")

        # an input tool's own result also carries the key (its value may be
        # the pre-dispatch gap or ~0 once its own input lands — both are
        # conformant readings of "since the last input")
        second = _call(mcp, "hyperv_console_press_key",
                       {"vm_name": VM, "key": "space"})
        assert second.get("ok") is True, "AC1: the second input must succeed"
        assert "input_idle_s" in second, (
            "AC1: input tool results must carry input_idle_s too "
            f"(envelope: {json.dumps(second)[:300]})")
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC2 / AC3 — the opt-in per-VM heartbeat, tied to the lease
# ---------------------------------------------------------------------------

def _heartbeat_tools(mcp) -> list[str]:
    tools = asyncio.run(mcp.list_tools())
    names = [t.name for t in tools]
    return sorted(n for n in names if "heartbeat" in n.lower())


def _enable_heartbeat(mcp, lease_id: str, ac: str = "AC2") -> str:
    """Discover the heartbeat surface in the tool registry and enable it
    with the common argument spellings (the issue pins neither the tool
    name nor the parameter names)."""
    beats = _heartbeat_tools(mcp)
    assert beats, (
        f"{ac}: no heartbeat surface is registered (searched the tool "
        "registry for a name containing 'heartbeat')")
    candidates = [
        {"vm_name": VM, "key": "shift", "interval_s": 0.05},
        {"vm_name": VM, "key": "shift", "interval_s": 0.05, "lease_id": lease_id},
        {"vm_name": VM, "heartbeat_key": "shift", "heartbeat_interval_s": 0.05},
        {"vm_name": VM, "key": "shift", "interval_ms": 50},
    ]
    last: object = None
    for name in beats:
        for args in candidates:
            try:
                env = _call(mcp, name, args)
            except Exception as exc:  # an incompatible spelling refuses
                last = exc
                continue
            if env.get("ok") is True:
                return name
            last = env
    raise AssertionError(
        f"{ac}: could not enable the heartbeat on {beats} with the common "
        f"argument spellings (last outcome: {last!r})")


def _heartbeat_sends(stub: ErgoPS) -> int:
    return sum(1 for s in stub.scripts if SHIFT_CODES in s)


def _wait_for_heartbeat(stub: ErgoPS, count: int, budget_s: float = 5.0) -> int:
    deadline = time.monotonic() + budget_s
    seen = _heartbeat_sends(stub)
    while seen < count and time.monotonic() < deadline:
        time.sleep(0.05)
        seen = _heartbeat_sends(stub)
    return seen


def test_heartbeat_sends_key_while_leased(tmp_path, monkeypatch):
    """AC2: with a console lease held and the heartbeat enabled at a 50 ms
    interval, the configured benign key (shift) is sent to the VM
    repeatedly — observed as its scancode literal in the dispatched fake
    scripts, addressed to the leased VM only.

    RED at base: no heartbeat surface is registered."""
    mod = _boot(tmp_path)
    lease_id = ""
    try:
        stub = ErgoPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()

        acquired = _call(mcp, "hyperv_lease_acquire",
                         {"vm_name": VM, "scopes": ["console"]})
        assert acquired.get("ok") is True, (
            "AC2: the console lease the heartbeat rides on must acquire "
            f"(envelope: {json.dumps(acquired)[:300]})")
        lease_id = acquired["lease_id"]

        _enable_heartbeat(mcp, lease_id)

        sends = _wait_for_heartbeat(stub, 3)
        assert sends >= 3, (
            "AC2: while the lease is active the heartbeat must send the "
            f"configured key at the configured interval (saw {sends} sends)")
        shift_scripts = [s for s in stub.scripts if SHIFT_CODES in s]
        assert all(f"ElementName -eq '{VM}'" in s for s in shift_scripts), (
            "AC2: every heartbeat send must address the leased VM "
            f"(scripts: {[s[:60] for s in shift_scripts]})")
    finally:
        if lease_id:
            try:
                _call(mod.get_mcp(), "hyperv_lease_release", {"lease_id": lease_id})
            except Exception:
                pass
        importlib.reload(server_module)


def test_heartbeat_stops_when_lease_ends(tmp_path, monkeypatch):
    """AC3: once the lease is released the heartbeat stops — after a short
    grace for an in-flight send, the send count is stable across a window
    in which a still-live 50 ms heartbeat would have fired several more
    times.

    RED at base: no heartbeat surface is registered."""
    mod = _boot(tmp_path)
    lease_id = ""
    try:
        stub = ErgoPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()

        acquired = _call(mcp, "hyperv_lease_acquire",
                         {"vm_name": VM, "scopes": ["console"]})
        assert acquired.get("ok") is True, (
            "AC3: the console lease must acquire "
            f"(envelope: {json.dumps(acquired)[:300]})")
        lease_id = acquired["lease_id"]

        _enable_heartbeat(mcp, lease_id, ac="AC3")
        assert _wait_for_heartbeat(stub, 2) >= 2, (
            "AC3: the heartbeat must be sending while the lease is active "
            "before its end is observed")

        released = _call(mcp, "hyperv_lease_release", {"lease_id": lease_id})
        assert released.get("ok") is True, (
            "AC3: the lease must release "
            f"(envelope: {json.dumps(released)[:300]})")
        lease_id = ""

        # grace for an in-flight send to land (each sleep <= ~0.2 s)
        time.sleep(0.15)
        time.sleep(0.15)
        baseline = _heartbeat_sends(stub)
        time.sleep(0.15)
        time.sleep(0.15)
        after = _heartbeat_sends(stub)
        assert after == baseline, (
            "AC3: the heartbeat kept sending after the lease ended "
            f"({baseline} sends at release grew to {after})")
    finally:
        if lease_id:
            try:
                _call(mod.get_mcp(), "hyperv_lease_release", {"lease_id": lease_id})
            except Exception:
                pass
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC4 — on_timeout="job" promotes the still-running call to a managed job
# ---------------------------------------------------------------------------

def test_timeout_promotes_to_job(tmp_path, monkeypatch):
    """AC4: with on_timeout="job" the guest script's run_ps leg times out
    while the guest process is still running; the call returns ok:true
    with a managed-job handle (the hyperv_guest_job_start shape) instead
    of a timeout error, and the handle works with hyperv_guest_job_status.

    RED at base: hyperv_guest_run_ps accepts no on_timeout, so no promotion
    exists."""
    mod = _boot(tmp_path)
    try:
        monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
        monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "placeholder-pass")
        stub = PromotePS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()

        out = _call(mcp, "hyperv_guest_run_ps", {
            "vm_name": VM,
            "script": "Start-Sleep -Seconds 600",
            "timeout_ms": 1000,
            "on_timeout": "job",
        })
        assert out.get("ok") is True, (
            "AC4: a still-running script at the deadline must return ok "
            f"with the promoted job handle, not a timeout error "
            f"(envelope: {json.dumps(out)[:400]})")
        for key in ("job_id", "pid", "job_dir", "out_path", "err_path",
                    "exit_path"):
            assert out.get(key), (
                f"AC4: the promoted handle must carry {key} like "
                f"hyperv_guest_job_start's (envelope: {json.dumps(out)[:400]})")
        assert out.get("pid") == 4242, (
            "AC4: the promoted handle must report the guest-launched pid")
        # single execution: the script ran ONCE as a managed job — a
        # synchronous-attempt-then-adopt implementation would fire the guest
        # script twice and is forbidden by the issue's data-integrity intent.
        assert stub.start_count == 1, (
            f"AC4: the promoted script must start exactly once as a managed "
            f"job (start_count={stub.start_count})")
        assert stub.sync_count == 0, (
            "AC4: on_timeout=job must NOT also run the synchronous exec leg "
            f"(double execution) — sync_count={stub.sync_count}")

        status = _call(mcp, "hyperv_guest_job_status",
                       {"job_id": out["job_id"]})
        assert status.get("ok") is True, (
            "AC4: the promoted handle must work with hyperv_guest_job_status "
            f"(envelope: {json.dumps(status)[:400]})")
        assert status.get("status") == "running", (
            "AC4: the promoted job must report running "
            f"(envelope: {json.dumps(status)[:400]})")
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC5 — without on_timeout the timeout error envelope stays (PRESERVING)
# ---------------------------------------------------------------------------

def test_default_timeout_behavior_unchanged(tmp_path, monkeypatch):
    """AC5: on_timeout not set — a timed-out guest script still reports
    the current timeout error envelope: ok false, error_class "timeout",
    timed_out true.

    GREEN-preserving at base by design (the floor #133 must not move)."""
    mod = _boot(tmp_path)
    try:
        monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
        monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "placeholder-pass")
        stub = PromotePS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()

        out = _call(mcp, "hyperv_guest_run_ps", {
            "vm_name": VM,
            "script": "Start-Sleep -Seconds 600",
            "timeout_ms": 1000,
        })
        assert out.get("ok") is False, (
            "AC5: without on_timeout a timeout must stay a failure "
            f"(envelope: {json.dumps(out)[:400]})")
        assert out.get("error_class") == "timeout", (
            "AC5: the timeout error class must stay 'timeout' (got "
            f"{out.get('error_class')!r})")
        assert out.get("timed_out") is True, (
            "AC5: the envelope must keep timed_out true")
        assert stub.sync_count == 1 and stub.start_count == 0, (
            "AC5: without on_timeout the synchronous leg must run exactly "
            "once and no managed job may start "
            f"(sync={stub.sync_count} start={stub.start_count})")
    finally:
        importlib.reload(server_module)
