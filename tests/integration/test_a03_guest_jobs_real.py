"""AC8/AC9 integration checks for issue 7 (trace 7-guest-jobs-truthful-reporting).

Never runs accidentally: tests/integration/conftest.py skips the whole suite
with an actionable reason unless HYPERV_MCP_INTEGRATION=1,
HYPERV_MCP_TEST_VM names a disposable VM, and guest credentials are set. In
an environment without a Hyper-V host the gates stay unset, this module skips
with the conftest reason, and AC8/AC9 are recorded as not-run in
02-reproduction.md (the issue sanctions that).

AC8 (tree kill): start a job whose target is a long-lived native child
(`ping.exe -n 600 127.0.0.1`), prove the child is really alive, then stop the
job and require that no ping.exe descendant survives, the job directory is
gone, and the stop reports `stopped: true, job_dir_removed: true`.

AC9 (exit-code truthfulness): run the three jobs the pre-fix wrapper
mislabelled, and require the recorded codes to be truthful — a failing
cmdlet (`Get-Item` on a missing path) and a command-not-found both record
non-zero, while `cmd.exe /c exit 0` records exactly "0" (the pre-fix wrapper
wrote 0 for the first two because $LASTEXITCODE was null). The exec path is
checked too: `Get-Item` on a missing path must return a non-zero
`exit_code`.

These call guestjobs/guestexec directly: the MCP tools are thin wrappers
over exactly these functions, and their argument threading is already
covered by the unit suite. The host cannot read the guest process table
directly, so process facts are observed with the same PowerShell Direct legs
the tools use and the host asserts on what those legs return.
"""

import json
import time

import pytest

from hyperv_mcp import guestexec, guestjobs

pytestmark = [pytest.mark.hyperv_real]

# Long enough for a job to be observed running and then stopped; short
# enough that a leaked ping.exe is not a long-lived orphan.
_PING_ARGS = ["-n", "600", "127.0.0.1"]
_MISSING_PATH = r"C:\hyperv-mcp-a03-does-not-exist"


def _wait_for_status(cfg, it, job_id: str, wanted: set[str], timeout_s: int = 60) -> dict:
    """Poll job_status until it reports one of `wanted`; return that report."""
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = guestjobs.job_status(cfg, job_id)
        if last.get("status") in wanted:
            return last
        time.sleep(1.0)
    return last


def _guest_ping_pids(cfg, it) -> list[int]:
    """PIDs of every live ping.exe in the guest, via a PS Direct leg."""
    result = guestexec.guest_run_ps(
        cfg, it.vm,
        "$p = @(Get-Process -Name ping -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Id)\n"
        "[PSCustomObject]@{ pids = $p } | ConvertTo-Json -Compress",
        cred=it.creds,
    )
    assert result.get("ok") is True, f"ping probe leg failed: {result}"
    return [int(p) for p in json.loads(str(result.get("stdout") or "{}")).get("pids") or []]


def _stop_quietly(cfg, job_id: str) -> None:
    """Best-effort cleanup so a failed assertion never leaks a job."""
    try:
        guestjobs.job_stop(cfg, job_id)
    except Exception:
        pass


def test_ac8_stop_kills_the_descendant_tree(it):
    """AC8: stopping the job leaves no ping.exe descendant alive."""
    cfg = it.cfg
    started = guestjobs.job_start(cfg, it.vm, "ping.exe", _PING_ARGS, cred=it.creds)
    job_id = started["job_id"]
    try:
        assert started.get("ok") is True, f"job_start failed: {started}"
        # The recorded start time is what pins the process identity later.
        assert started.get("start_time_ticks"), (
            f"job_start did not record a start time: {started}"
        )

        # The child must be observably alive before the stop, otherwise the
        # check would pass trivially.
        deadline = time.monotonic() + 60
        alive_before: list[int] = []
        while time.monotonic() < deadline and not alive_before:
            alive_before = _guest_ping_pids(cfg, it)
            if not alive_before:
                time.sleep(1.0)
        assert alive_before, "the job's ping.exe child never became visible in the guest"

        stop = guestjobs.job_stop(cfg, job_id)
        assert stop.get("stopped") is True, f"stop must report the tree killed: {stop}"
        assert stop.get("ok") is True, f"stop must report ok: {stop}"
        assert list(stop.get("alive_pids") or []) == [], f"stop reported survivors: {stop}"
        assert stop.get("job_dir_removed") is True, (
            f"the job directory must be removed when nothing survived: {stop}"
        )
        assert stop.get("pid_reused") is False, f"the recorded process was not reused: {stop}"

        # Independent of the stop payload: no ping.exe may remain.
        deadline = time.monotonic() + 30
        after: list[int] = list(alive_before)
        while time.monotonic() < deadline and after:
            after = _guest_ping_pids(cfg, it)
            if after:
                time.sleep(1.0)
        assert after == [], f"ping.exe descendants survived the stop: {after}"
    finally:
        _stop_quietly(cfg, job_id)


@pytest.mark.parametrize(
    ("command", "args", "expect_zero"),
    [
        ("Get-Item", [_MISSING_PATH], False),
        (r"C:\hyperv-mcp-a03-does-not-exist.exe", [], False),
        ("cmd.exe", ["/c", "exit", "0"], True),
    ],
    ids=["cmdlet-error", "command-not-found", "native-success"],
)
def test_ac9_job_records_the_real_outcome(it, command, args, expect_zero):
    """AC9: the recorded exit code reflects what the command actually did."""
    cfg = it.cfg
    started = guestjobs.job_start(cfg, it.vm, command, args, cred=it.creds)
    job_id = started["job_id"]
    try:
        assert started.get("ok") is True, f"job_start failed: {started}"
        report = _wait_for_status(cfg, it, job_id, {"exited", "exiting"})
        assert report.get("status") == "exited", (
            f"job {command!r} never reported a terminal exit: {report}"
        )
        code = str(report.get("exit_code") or "").strip()
        assert code != "", f"no exit code was recorded for {command!r}: {report}"
        if expect_zero:
            assert code == "0", f"{command!r} succeeded but recorded {code!r}"
        else:
            assert code not in ("", "0"), (
                f"{command!r} failed but recorded the success code {code!r}"
            )
    finally:
        _stop_quietly(cfg, job_id)


def test_ac9_exec_path_reports_a_failing_cmdlet(it):
    """AC9: the exec path must not report success for a failing cmdlet."""
    result = guestexec.guest_run_ps(
        it.cfg, it.vm, f"Get-Item -LiteralPath '{_MISSING_PATH}'", cred=it.creds,
    )
    assert result.get("ok") is True, f"the leg itself must succeed: {result}"
    assert int(result.get("exit_code") or 0) != 0, (
        f"a failing cmdlet must exit non-zero, got {result}"
    )
