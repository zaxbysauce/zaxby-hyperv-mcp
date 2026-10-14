"""Busy-taxonomy wiring tests for issue #15 (Change 6b of the approved plan).

The frozen acceptance checks pin pswindows.run_ps's pool behavior
(test_c02_ps_cap.py) and errors.classify directly (C4); these tests pin the
WIRING — that a PowerShellBusy raised through a real module path surfaces as
error_class "busy" at the layer that owns each key:

- guestexec's module result dicts carry {ok, error, error_class} only;
  retryable/retry_after_ms are attached by errors.enrich_failure at the
  server boundary (server.py), so that is where the retryable assertion
  lives.
- guestjobs.job_stop keeps its documented stop-result key set; a busy stop
  leg reports error_class "busy" with stopped=False and the entry stays
  retryable.

No real process spawns: run_ps is monkeypatched at the pswindows module
attribute each consumer calls.
"""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import hyperv_mcp.http_entry as http_entry
from hyperv_mcp import errors, guestexec, guestjobs, pswindows
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")


def _raising_run_ps(exc):
    def fake_run_ps(script, *, timeout_s=None, stdin_b64=None):
        raise exc

    return fake_run_ps

VM_GUID = "e953c649-1234-5678-9abc-def012345678"  # same canned GUID as test_guestexec


class SeqPS:
    """Sequenced fake like tests/unit/test_guestexec.py::FakePS: first leg
    resolves the VM (GUID stdout), the guest leg raises the given exception."""

    def __init__(self, exc):
        self.exc = exc
        self.calls = 0

    def __call__(self, script, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return pswindows.PSResult(stdout=VM_GUID, returncode=0)
        raise self.exc


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


def test_guestexec_busy_wires_to_busy_class(monkeypatch, unrestricted):
    """A PowerShellBusy through guest_run_ps's except-Exception arm reports
    error_class "busy" (not "transport"); enrich_failure then marks it
    retryable with the 2000 ms guidance — the layer that owns those keys."""
    fake = SeqPS(pswindows.PowerShellBusy("pool saturated"))
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = guestexec.guest_run_ps(unrestricted, "vm1", "Get-Date", cred=CRED)
    assert fake.calls == 2  # the exception came from the guest leg, post-resolve
    assert out["ok"] is False
    assert out["error_class"] == "busy"
    enriched = errors.enrich_failure(out)
    assert enriched["retryable"] is True
    assert enriched["retry_after_ms"] == errors.BUSY_RETRY_MS


def test_guestexec_transport_still_transport(monkeypatch, unrestricted):
    """The wiring must not reclassify ordinary transport failures."""
    monkeypatch.setattr(
        pswindows, "run_ps", SeqPS(RuntimeError("transport down"))
    )
    out = guestexec.guest_run_ps(unrestricted, "vm1", "Get-Date", cred=CRED)
    assert out["error_class"] == "transport"
    assert errors.enrich_failure(out)["retryable"] is False


def test_guestjobs_stop_busy_keeps_entry_stoppable(monkeypatch):
    """A PowerShellBusy stop leg reports error_class "busy" with stopped
    False; the entry stays registered so a retry can stop it later."""
    monkeypatch.setattr(
        guestjobs,
        "_jobs",
        {
            "job-1": {
                "vm_name": "vm-a",
                "pid": 4242,
                "job_dir": "dummy",
                "vm_id": "11111111-2222-3333-4444-555555555555",
                "cred": CRED,
            }
        },
    )
    def raising_run_ps(script, *, timeout_s=None, stdin_b64=None):
        raise pswindows.PowerShellBusy("pool saturated")

    monkeypatch.setattr(pswindows, "run_ps", raising_run_ps)
    out = guestjobs.job_stop(Config(unrestricted=True), "job-1")
    assert out["ok"] is False
    assert out["error_class"] == "busy"
    assert out["stopped"] is False
    assert "job-1" in guestjobs._jobs  # entry remains stoppable
    enriched = errors.enrich_failure(out)
    assert enriched["retryable"] is True


def test_busy_envelope_end_to_end():
    """classify -> envelope: the catch-all envelope every server tool uses
    emits {error_class: busy, retryable: true, retry_after_ms: 2000}."""
    env = errors.envelope(pswindows.PowerShellBusy("pool saturated"))
    assert env["error_class"] == "busy"
    assert env["retryable"] is True
    assert env["retry_after_ms"] == errors.BUSY_RETRY_MS


def test_slot_dir_fault_is_transport_error(tmp_path, monkeypatch):
    """Reviewer round-1 revision: an uncreatable slot directory fails the leg
    as PowerShellTransportError (redacted), not a raw OSError traceback."""
    from hyperv_mcp import diagnostics  # noqa: F401  (import-order sanity)

    blocker = tmp_path / "probe-file.txt"
    blocker.write_text("x", encoding="utf-8")
    cfg = Config(ps_slot_dir=str(blocker / "sub"))
    monkeypatch.setattr(pswindows, "_config", cfg)
    with pytest.raises(pswindows.PowerShellTransportError) as excinfo:
        pswindows._ps_slot_dir()
    assert "cannot create PowerShell slot directory" in str(excinfo.value)


def test_host_leg_busy_reports_class(monkeypatch, unrestricted):
    """Reviewer round-1 revision: a busy host leg carries error_class "busy"
    on the host_query_failed finding (plan Change 4 site 4, second half)."""
    from hyperv_mcp import diagnostics

    def host_busy(*args, **kwargs):
        raise pswindows.PowerShellBusy("pool saturated")

    def guest_timeout(*args, **kwargs):
        raise TimeoutError("guest probe timed out")

    monkeypatch.setattr(diagnostics, "_run_host_leg", host_busy)
    monkeypatch.setattr(diagnostics, "_run_guest_probe", guest_timeout)
    report = diagnostics.diagnose_report(
        unrestricted, "11111111-2222-3333-4444-555555555555", "vm1", CRED, 3000
    )
    finding = next(
        (f for f in report["findings"] if f["id"] == "host_query_failed"), None
    )
    assert finding is not None, "host_query_failed finding missing"
    assert finding["error_class"] == "busy"  # the HOST leg's class, attributed
    assert report["ps_direct"]["error_class"] == "timeout"  # the guest leg's own


def test_slot_dir_hardening_survives_popen_patches(tmp_path, monkeypatch):
    """CI regression (PR #61 round 1): the ACL hardening spawn must use the
    import-time REAL Popen, never the module attribute — issue #5's frozen
    a01 checks patch subprocess.Popen with fakes that have no context-manager
    surface, and the first-ever creation of the derived default slot dir runs
    icacls right in the middle of such a test on a fresh CI runner."""
    class _NoEnterPopen:
        def __init__(self, *args, **kwargs):
            raise AssertionError("hardening must not use the patched Popen attribute")

    monkeypatch.setattr(pswindows.subprocess, "Popen", _NoEnterPopen)
    monkeypatch.setattr(pswindows, "_SLOT_ACLS_DONE", set())  # force the fresh-run path
    monkeypatch.setattr(pswindows, "_config", Config(unrestricted=True))  # open the harden gate (conftest autouse resets _config=None)
    monkeypatch.setenv("ProgramData", str(tmp_path))  # derived default -> fresh dir
    directory = pswindows._ps_slot_dir()
    assert directory.exists()
    assert directory.parent.name == "hyperv-mcp"


# -- PR-review round pins (PR #61 feedback) ---------------------------------
# The pins below close the coverage gaps the swarm-pr-review run found; they
# live in this non-frozen file (the four checkpoint-frozen files must stay
# byte-identical).


class _SlicingPopen:
    """Records the input= kwarg of every communicate() call, then completes
    after two polling slices (so the stdin-once contract is observable)."""

    def __init__(self, *args, **kwargs):
        self.pid = 424242
        self._handle = 0
        self.inputs: list = []
        self._slices = 0
        self.returncode = 0

    def communicate(self, input=None, timeout=None):
        self.inputs.append(input)
        self._slices += 1
        if self._slices >= 2:
            return b"out", b""
        raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)

    def kill(self):
        return None


def test_stdin_secret_delivered_exactly_once(monkeypatch, tmp_path):
    """PRR-017a: the stdin secret rides the FIRST communicate slice only —
    never re-sent on a retry slice, never dropped."""
    monkeypatch.setattr(pswindows, "_ps_path", "powershell")
    monkeypatch.setattr(pswindows, "_config", Config(unrestricted=True))
    monkeypatch.setattr(pswindows, "_make_kill_on_close_job", lambda: None)
    monkeypatch.setattr(pswindows, "_resume_process", lambda pid: True)
    proc = _SlicingPopen()
    monkeypatch.setattr(pswindows.subprocess, "Popen", lambda *a, **k: proc)
    # isolate the pool so no host-global slot dir is touched
    monkeypatch.setattr(pswindows, "_ps_slot_dir", lambda: tmp_path)
    monkeypatch.setattr(pswindows, "_SLOT_ACLS_DONE", set())

    result = pswindows.run_ps("# probe", stdin_b64="c2VjcmV0", timeout_s=30)

    assert result.returncode == 0
    assert proc.inputs[0] == b"c2VjcmV0\n"  # delivered, with the newline
    assert all(item is None for item in proc.inputs[1:])  # exactly once


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_host_powershell": 0},
        {"max_host_powershell": 65},
        {"max_host_powershell": True},
        {"max_host_powershell": "8"},
        {"host_powershell_wait_s": -1},
        {"host_powershell_wait_s": 601},
        {"host_powershell_wait_s": True},
        {"host_powershell_wait_s": "60"},
        {"ps_slot_dir": "   "},
        {"ps_slot_dir": "relative-slots"},
    ],
)
def test_pool_config_validation_rejects_bad_values(kwargs):
    """PRR-017b: every new config key's validation branch rejects out-of-range
    and wrong-typed values (including a RELATIVE ps_slot_dir, which would
    silently split the host-wide pool per CWD)."""
    with pytest.raises(ConfigError):
        Config(**kwargs).validate()


def test_pool_config_from_dict_propagates_errors():
    """PRR-017b: from_dict surfaces the same validation errors as the ctor."""
    with pytest.raises(ConfigError):
        Config.from_dict({"max_host_powershell": 0})
    with pytest.raises(ConfigError):
        Config.from_dict({"ps_slot_dir": "relative"})


def test_slot_file_open_fault_is_transport_error(tmp_path):
    """PRR-017c: an unopenable slot FILE (not just an uncreatable directory)
    fails the leg as PowerShellTransportError, not a raw OSError."""
    directory = tmp_path / "slots"
    directory.mkdir()
    (directory / "slot-00.lock").mkdir()  # a directory where the lock file goes
    monkey_cfg = Config(unrestricted=True, max_host_powershell=1, ps_slot_dir=str(directory))
    original = pswindows._config
    pswindows._config = monkey_cfg
    try:
        with pytest.raises(pswindows.PowerShellTransportError) as excinfo:
            pswindows._acquire_ps_slot()
        assert "cannot open PowerShell slot file" in str(excinfo.value)
    finally:
        pswindows._config = original


def test_slot_dir_fault_surfaces_through_run_ps(monkeypatch, tmp_path):
    """PRR-018a: an uncreatable slot directory surfaces to a real run_ps
    caller as PowerShellTransportError (asserted at the run_ps layer, not the
    private helper)."""
    blocker = tmp_path / "probe-file.txt"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(pswindows, "_ps_path", "powershell")
    monkeypatch.setattr(pswindows, "_config", Config(ps_slot_dir=str(blocker / "sub")))
    with pytest.raises(pswindows.PowerShellTransportError) as excinfo:
        pswindows.run_ps("# probe")
    message = str(excinfo.value)
    assert "cannot create PowerShell slot directory sub" in message
    # minimization: the client-visible message names the directory leaf, not
    # the absolute path (which would disclose host layout, and on the tempdir
    # fallback the local account name)
    assert str(tmp_path) not in message


def test_hardening_pin_proves_hardening_ran(monkeypatch, tmp_path):
    """PRR-018b: the hardening pin must fail if the hardening call disappears
    — it records the icacls spawn (argv + sanitized env) instead of only
    asserting mkdir-produced facts. Also closes follow-up #62's second pin."""
    seen: dict = {}

    class _RecordingPopen:
        def __init__(self, argv, **kwargs):
            seen["argv"] = list(argv)
            seen["env"] = kwargs.get("env")
            self.returncode = 0

        def communicate(self, timeout=None):
            return b"", b""

    monkeypatch.setattr(pswindows, "_REAL_POPEN", _RecordingPopen)
    monkeypatch.setattr(pswindows, "_SLOT_ACLS_DONE", set())
    monkeypatch.setattr(pswindows, "_config", Config(unrestricted=True))
    monkeypatch.setenv("ProgramData", str(tmp_path))  # derived default -> fresh dir

    directory = pswindows._ps_slot_dir()

    assert seen, "ACL hardening never ran — the pin must fail without it"
    assert seen["argv"][:2] == ["icacls", str(directory)]
    assert "/inheritance:r" in seen["argv"]
    assert any("S-1-5-32-544" in a for a in seen["argv"])  # Administrators by SID
    assert any("S-1-5-32-578" in a for a in seen["argv"])  # Hyper-V Admins by SID
    env = seen["env"]
    assert env is not None and env is not os.environ  # sanitized child env
    assert not any(k.upper() == "HYPERV_GUEST_PASSWORD" for k in env)


def test_media_busy_sites_surface_busy(monkeypatch):
    """PRR-017e: both media PowerShellBusy sites report busy/retryable rather
    than conflating it into a timeout or a non-retryable MediaError."""
    from hyperv_mcp import media

    cfg = Config.from_dict(
        {"allowed_vm_patterns": ["vm*"], "destructive": {"display": True, "stop": True}}
    )
    vm_id = "11111111-2222-3333-4444-555555555555"

    def busy_run(cfg_, script, ctx, timeout_s=300):
        raise pswindows.PowerShellBusy("pool saturated")

    def resolve_ok(script, **kwargs):
        # the resolve leg's stdout is the resolved ElementName (policy target)
        return pswindows.PSResult(stdout="vm1", returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", resolve_ok)

    # site 1: the _wait_for_state conflation (busy must not become TimeoutError)
    monkeypatch.setattr(media, "_run", busy_run)
    monkeypatch.setattr(media.lifecycle, "_wait_for_state", busy_run)
    with pytest.raises(pswindows.PowerShellBusy):
        media.vm_set_resolution(cfg, vm_id=vm_id, width=1920, height=1080)

    # site 2: the restart-compensation re-raise (busy original + state note)
    def resolve_ok(cfg_, script, ctx, timeout_s=300):
        return pswindows.PSResult(stdout="{}", returncode=0)

    calls = {"n": 0}

    def compensation_busy(cfg_, script, ctx, timeout_s=300):
        calls["n"] += 1
        if calls["n"] == 1:  # the stop leg succeeds
            return pswindows.PSResult(stdout="", returncode=0)
        raise pswindows.PowerShellBusy("pool saturated")

    monkeypatch.setattr(media, "_run", compensation_busy)
    with pytest.raises(pswindows.PowerShellBusy) as excinfo:
        media.vm_set_resolution(
            cfg, vm_id=vm_id, width=1920, height=1080, restart=True, confirm=True
        )
    assert "this call stopped the VM" in str(excinfo.value)
    assert "still OFF" in str(excinfo.value)


@pytest.mark.skipif(os.name != "nt", reason="Job Object tree kill is Windows-only")
def test_failing_kill_helper_does_not_mask_propagating_exception(monkeypatch, tmp_path):
    """PRR-017d: a kill helper that raises (non-OSError) must neither skip the
    remaining cleanup nor replace the exception run_ps is propagating."""

    class _Unwinding:
        pid = 424242
        _handle = 0

        def communicate(self, input=None, timeout=None):
            raise RuntimeError("probe: non-timeout unwind")

        def kill(self):
            return None

    monkeypatch.setattr(pswindows, "_ps_path", "powershell")
    monkeypatch.setattr(pswindows, "_config", Config(unrestricted=True))
    monkeypatch.setattr(pswindows, "_make_kill_on_close_job", lambda: 1234)
    monkeypatch.setattr(pswindows, "_assign_to_job", lambda job, handle: True)
    monkeypatch.setattr(pswindows, "_resume_process", lambda pid: True)
    monkeypatch.setattr(pswindows, "_ps_slot_dir", lambda: tmp_path)
    monkeypatch.setattr(pswindows, "_SLOT_ACLS_DONE", set())
    monkeypatch.setattr(pswindows.subprocess, "Popen", lambda *a, **k: _Unwinding())

    def exploding_taskkill(pid):
        raise subprocess.TimeoutExpired(cmd="taskkill", timeout=15)

    monkeypatch.setattr(pswindows, "_taskkill_tree", exploding_taskkill)
    monkeypatch.setattr(
        pswindows.ctypes.windll.kernel32, "TerminateJobObject",
        lambda job, code: (_ for _ in ()).throw(RuntimeError("job machinery down")),
    )
    released: list[int] = []
    real_release = pswindows._release_ps_slot

    def tracking_release(fd):
        released.append(fd)
        real_release(fd)

    monkeypatch.setattr(pswindows, "_release_ps_slot", tracking_release)

    with pytest.raises(RuntimeError, match="non-timeout unwind"):
        pswindows.run_ps("# probe")
    assert released, "the slot was not released when the kill helper raised"


# -- merge-blocker regression pins (reviewer round 2: probes proved the
# -- committed suite could not detect a regression of either fix) -----------

_RECORDER_SRC = (
    "import json, os, sys, time\n"
    "recorder = os.environ['RECORDER_FILE']\n"
    "sleep_s = float(os.environ.get('SLEEP_S', '1'))\n"
    "with open(recorder, 'a', encoding='utf-8') as fh:\n"
    "    fh.write(json.dumps({'pid': os.getpid(), 'event': 'start'}) + chr(10))\n"
    "time.sleep(sleep_s)\n"
    "with open(recorder, 'a', encoding='utf-8') as fh:\n"
    "    fh.write(json.dumps({'pid': os.getpid(), 'event': 'end'}) + chr(10))\n"
)


def _write_recorder_shim(workdir: Path) -> Path:
    recorder_py = workdir / "fake_ps_recorder.py"
    recorder_py.write_text(_RECORDER_SRC, encoding="utf-8")
    shim = workdir / "fake_ps.cmd"
    shim.write_text(
        f'@echo off\r\n"{sys.executable}" "{recorder_py}"\r\n', encoding="utf-8"
    )
    return shim


def test_slot_wait_does_not_consume_the_leg_timeout(monkeypatch, tmp_path):
    """PRR-001 regression pin: the leg clock starts AFTER the slot wait, so a
    queued caller gets its full timeout budget. With a 0.9 s wait and a
    1.5 s timeout, a 1.2 s child must still run to completion — at base the
    wait was charged against the timeout and the child was killed at 0.6 s."""
    workdir = tmp_path / "w"
    workdir.mkdir()
    shim = _write_recorder_shim(workdir)
    events = workdir / "events.jsonl"
    monkeypatch.setenv("RECORDER_FILE", str(events))
    monkeypatch.setenv("SLEEP_S", "1.2")
    monkeypatch.setattr(
        pswindows, "_ps_path", str(shim)
    )
    monkeypatch.setattr(
        pswindows, "_config",
        Config(max_host_powershell=1, host_powershell_wait_s=5.0,
               ps_timeout_s=1.5, ps_slot_dir=str(tmp_path / "slots")),
    )
    held = pswindows._acquire_ps_slot()
    threading.Timer(0.9, pswindows._release_ps_slot, args=(held,)).start()

    result = pswindows.run_ps("# leg", timeout_s=1.5)

    assert result.returncode == 0, (
        "the child did not survive its own budget after the slot wait — "
        "the wait is still being charged against the leg timeout"
    )
    records = [json.loads(line) for line in events.read_text().splitlines()]
    assert [r["event"] for r in records] == ["start", "end"]


def test_cancelled_caller_does_not_wait_out_the_slot_pool(monkeypatch, tmp_path):
    """PRR-002 regression pin: a cancelled caller blocked in the slot wait
    must be cancelled promptly, not sit out host_powershell_wait_s and then
    be told to retry a call it cancelled."""
    import anyio

    workdir = tmp_path / "w"
    workdir.mkdir()
    monkeypatch.setattr(
        pswindows, "_config",
        Config(max_host_powershell=1, host_powershell_wait_s=10.0,
               ps_timeout_s=10, ps_slot_dir=str(tmp_path / "slots")),
    )
    monkeypatch.setattr(pswindows, "_ps_path", "powershell")
    held = pswindows._acquire_ps_slot()  # saturate the pool
    outcome: dict = {}

    async def scenario():
        started = time.monotonic()
        with anyio.move_on_after(0.5):
            try:
                await anyio.to_thread.run_sync(lambda: pswindows.run_ps("# leg"))
                outcome["result"] = "completed"
            except BaseException as exc:  # noqa: BLE001 - recording the outcome
                outcome["result"] = type(exc).__name__
        outcome["elapsed"] = time.monotonic() - started

    try:
        anyio.run(scenario)
    finally:
        pswindows._release_ps_slot(held)

    assert outcome["result"] == "CancelledError", (
        f"a cancelled caller in the slot wait ended as {outcome['result']!r} "
        "(at base it blocked the full wait and then raised PowerShellBusy)"
    )
    assert outcome["elapsed"] < 2.0


def test_pre_existing_default_slot_dir_is_hardened(monkeypatch, tmp_path):
    """PRR-011 regression pin: the derived default directory is hardened even
    when it already existed before this process first saw it (a squatted or
    deployment-pre-created directory must not be adopted unhardened)."""
    seen: dict = {}

    class _RecordingPopen:
        def __init__(self, argv, **kwargs):
            seen["argv"] = list(argv)
            self.returncode = 0

        def communicate(self, timeout=None):
            return b"", b""

    monkeypatch.setattr(pswindows, "_REAL_POPEN", _RecordingPopen)
    monkeypatch.setattr(pswindows, "_SLOT_ACLS_DONE", set())
    monkeypatch.setattr(pswindows, "_config", Config(unrestricted=True))
    program_data = tmp_path / "ProgramData"
    (program_data / "hyperv-mcp" / "ps-slots").mkdir(parents=True)  # pre-existing
    monkeypatch.setenv("ProgramData", str(program_data))

    pswindows._ps_slot_dir()

    assert seen, "a pre-existing default slot dir was adopted without hardening"


def test_host_leg_timeout_classifies_as_timeout(monkeypatch):
    """PRR-016 regression pin: the host leg's timeout raises TimeoutError, so
    errors.classify reports 'timeout' — the class its sibling guest leg
    reports for the same condition on the same report."""
    from hyperv_mcp import diagnostics

    monkeypatch.setattr(
        diagnostics, "_run",
        lambda cfg, script, **kw: pswindows.PSResult(timed_out=True),
    )
    with pytest.raises(TimeoutError):
        diagnostics._run_host_leg(
            Config(unrestricted=True), "11111111-2222-3333-4444-555555555555"
        )


def test_check_env_renders_pool_busy_distinctly(monkeypatch, capsys):
    """PRR-017/026 regression pin: pool saturation renders as POOL_BUSY in the
    operator-facing target probe, not under the UNREACHABLE label."""
    from hyperv_mcp import server as server_module
    from hyperv_mcp.config import HyperVTarget

    cfg = Config(unrestricted=True, hyperv=HyperVTarget(host="nuc01"))
    monkeypatch.setattr(server_module, "bootstrap", lambda: cfg)
    monkeypatch.setattr(server_module.pswindows, "run_ps", _raising_run_ps(
        pswindows.PowerShellBusy("pool saturated: 8 children; waited 60s")))
    monkeypatch.setattr(server_module.pswindows, "compose_remote",
                        lambda cfg, script, **kw: (script, None))
    monkeypatch.setattr(server_module, "_powershell_provenance",
                        lambda cfg: {"path": "p", "edition": "e", "version": "v",
                                     "psmodulepath": "m"})
    rc = server_module.main(["--check-env"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "POOL_BUSY" in out
    assert "UNREACHABLE" not in out


def test_http_entry_token_probe_transport_error_is_clean(monkeypatch, capsys, tmp_path):
    """PRR-017/027 regression pin: a transport failure in the logon-task token
    probe prints a diagnostic and exits 1 instead of a traceback."""
    # no token in the environment: the logon-task path then runs the
    # user-registry probe leg, which is where the transport catch lives
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setattr(
        pswindows, "run_ps", _raising_run_ps(
            pswindows.PowerShellTransportError("powershell.exe missing")))
    cfg = Config(unrestricted=True)
    rc = http_entry._handle_logon_task(cfg, True, host="127.0.0.1", port="8787")
    assert rc == 1
    assert "PowerShell transport failed" in capsys.readouterr().err
