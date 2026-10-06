"""AC8/AC9 integration checks for issue 7 (trace 7-guest-jobs-truthful-reporting).

Never runs accidentally: tests/integration/conftest.py skips the whole suite
with an actionable reason unless HYPERV_MCP_INTEGRATION=1,
HYPERV_MCP_TEST_VM names a disposable VM, and guest credentials are set. In
an environment without a Hyper-V host the gates stay unset, this module skips
with the conftest reason, and AC8/AC9 are recorded as not-run in
02-reproduction.md (the issue sanctions that).

AC8 (tree kill): start a job whose target is a long-lived native child
(`ping.exe -n 600 127.0.0.1`), prove the job's own descendant is really
alive (a Win32_Process parent-chain walk from the recorded wrapper pid —
NOT a guest-wide ping census, which both false-fails on unrelated
processes and could pass without this job's tree being killed), then stop
the job and require that no descendant of this job survives, the job
directory is gone, and the stop reports `stopped: true, job_dir_removed:
true`.

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


def _guest_job_tree(cfg, it, root_pid: int) -> tuple[bool, list[int]]:
    """Observe the JOB'S OWN tree in the guest, not every process of that
    name: (root alive?, descendant pids) via a Win32_Process parent-chain
    walk from the recorded wrapper pid (PRR-011 / CUB-4 — a guest-wide
    census both false-fails on unrelated processes and can pass without
    this job's tree being killed)."""
    result = guestexec.guest_run_ps(
        cfg, it.vm,
        f"$root = {int(root_pid)}\n"
        "$all = @(Get-CimInstance -ClassName Win32_Process | "
        "Select-Object ProcessId, ParentProcessId)\n"
        "$kids = New-Object 'System.Collections.Generic.List[int]'\n"
        "$frontier = @($root)\n"
        "while ($frontier.Count -gt 0) {\n"
        "    $next = @()\n"
        "    foreach ($pp in $frontier) {\n"
        "        foreach ($proc in $all) {\n"
        "            if ($proc.ParentProcessId -eq $pp -and -not $kids.Contains([int]$proc.ProcessId)) {\n"
        "                $kids.Add([int]$proc.ProcessId) | Out-Null\n"
        "                $next += [int]$proc.ProcessId\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    $frontier = $next\n"
        "}\n"
        "$rootAlive = [bool](Get-Process -Id $root -ErrorAction SilentlyContinue)\n"
        "[PSCustomObject]@{ root_alive = $rootAlive; descendants = @($kids) } "
        "| ConvertTo-Json -Compress",
        cred=it.creds,
    )
    assert result.get("ok") is True, f"tree probe leg failed: {result}"
    payload = json.loads(str(result.get("stdout") or "{}"))
    return (
        bool(payload.get("root_alive")),
        [int(p) for p in payload.get("descendants") or []],
    )


def _stop_quietly(cfg, job_id: str) -> None:
    """Best-effort cleanup so a failed assertion never leaks a job."""
    try:
        guestjobs.job_stop(cfg, job_id)
    except Exception:
        pass


def test_ac8_stop_kills_the_descendant_tree(it):
    """AC8: stopping the job leaves no descendant of THIS job alive."""
    cfg = it.cfg
    started = guestjobs.job_start(cfg, it.vm, "ping.exe", _PING_ARGS, cred=it.creds)
    job_id = started["job_id"]
    try:
        assert started.get("ok") is True, f"job_start failed: {started}"
        # The recorded start time is what pins the process identity later.
        assert started.get("start_time_ticks"), (
            f"job_start did not record a start time: {started}"
        )

        # The job's own descendant (the ping child) must be observably alive
        # before the stop, otherwise the check would pass trivially.
        deadline = time.monotonic() + 60
        root_alive, descendants = _guest_job_tree(cfg, it, started["pid"])
        while time.monotonic() < deadline and not descendants:
            time.sleep(1.0)
            root_alive, descendants = _guest_job_tree(cfg, it, started["pid"])
        assert root_alive and descendants, (
            "the job's wrapper/descendant tree never became visible in the guest "
            f"(root_alive={root_alive}, descendants={descendants})"
        )

        stop = guestjobs.job_stop(cfg, job_id)
        assert stop.get("stopped") is True, f"stop must report the tree killed: {stop}"
        assert stop.get("ok") is True, f"stop must report ok: {stop}"
        assert list(stop.get("alive_pids") or []) == [], f"stop reported survivors: {stop}"
        assert stop.get("job_dir_removed") is True, (
            f"the job directory must be removed when nothing survived: {stop}"
        )
        assert stop.get("pid_reused") is False, f"the recorded process was not reused: {stop}"

        # Independent of the stop payload: this job's descendants (observed
        # alive before the stop) must be gone, and so must the wrapper.
        seen_descendants = set(descendants)
        deadline = time.monotonic() + 30
        root_alive, after = _guest_job_tree(cfg, it, started["pid"])
        while time.monotonic() < deadline and (after or root_alive):
            if seen_descendants & set(after):
                break  # a specific descendant survived: fail now, no retry
            time.sleep(1.0)
            root_alive, after = _guest_job_tree(cfg, it, started["pid"])
        assert not (seen_descendants & set(after)), (
            f"this job's descendants {sorted(seen_descendants & set(after))} "
            f"survived the stop: {after}"
        )
        assert not root_alive and after == [], (
            f"the job tree (wrapper or descendants) survived the stop: "
            f"root_alive={root_alive}, descendants={after}"
        )
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
