"""Live PS Direct session-reuse checks for issue #21 (AC11, AC12).

Opt-in like every tests/integration module: these drive a REAL disposable VM
through the real Hyper-V stack and PowerShell Direct, and are skipped unless
HYPERV_MCP_INTEGRATION=1, HYPERV_MCP_TEST_VM and guest credentials are all
present (see tests/integration/conftest.py — the guarded_vm / running_vm
fixture protocol is copied from tests/integration/test_hyperv_real.py).

  * AC11: agent isolation under reuse — agent A plants $global:d05, agent B
    must read NOTHING (a distinct session), A's second call must still see
    its own value, and first-call vs reuse latency is measured and printed.
  * AC12: checkpoint restore and an in-guest restart each invalidate the VM's
    sessions; the next guest call is served from a new session with
    exit_code == 0, no Broken-session error, and the invalidation reason is
    observable in the audit record.
"""

import itertools
import json
import time
from pathlib import Path

import pytest

pytestmark = [pytest.mark.hyperv_real]

# Unique per CREATION (the test_hyperv_real.py protocol): Hyper-V allows
# duplicate snapshot names, so the fixture suffixes a per-test counter.
_CHECKPOINT_SEQ = itertools.count(1)
CHECKPOINT = "mcp-it-d05-{}".format(time.strftime("%Y%m%d-%H%M%S"))


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
        with open("hyperv-it-cleanup-report.json", "w", encoding="utf-8") as fh:
            json.dump(report, fh)


@pytest.fixture()
def running_vm(guarded_vm):
    from hyperv_mcp import lifecycle

    lifecycle.start_vm(guarded_vm.cfg, guarded_vm.vm)
    return guarded_vm


# ---------------------------------------------------------------------------
# AC11: per-agent isolation under reuse, plus the reuse latency
# ---------------------------------------------------------------------------


def test_agent_isolation_and_reuse_latency(running_vm):
    """AC11: with reuse enabled, agent A's $global:d05 is invisible to agent
    B on the same VM and profile (B's stdout is empty — a distinct session),
    A's second call still sees 'agent-a', and first-call vs reuse latency is
    printed for the issue's measurement record."""
    from mcp.server.auth.middleware.auth_context import (
        AuthenticatedUser,
        auth_context_var,
    )
    from mcp.server.auth.provider import AccessToken

    from hyperv_mcp import guestexec

    cfg, vm, creds = running_vm.cfg, running_vm.vm, running_vm.creds

    def as_agent(client_id: str, script: str) -> tuple[dict, float]:
        user = AuthenticatedUser(AccessToken(token="t", client_id=client_id, scopes=[]))
        ctx_token = auth_context_var.set(user)
        started = time.monotonic()
        try:
            return (
                guestexec.guest_run_ps(cfg, vm, script, cred=creds),
                (time.monotonic() - started) * 1000.0,
            )
        finally:
            auth_context_var.reset(ctx_token)

    # Emit only when the variable is set, so "unset" reads as truly empty
    # output rather than an empty Write-Output line.
    read_d05 = "$v = [string]$global:d05; if ($v) { Write-Output $v }"

    first, first_ms = as_agent("agent-a", "$global:d05 = 'agent-a'")
    assert first.get("ok") is True and first.get("exit_code") == 0, first

    as_b, _ = as_agent("agent-b", read_d05)
    assert as_b.get("ok") is True, as_b
    assert (as_b.get("stdout") or "").strip() == "", (
        f"agent B observed agent A's session state: {as_b.get('stdout')!r}"
    )

    second_a, reuse_ms = as_agent("agent-a", read_d05)
    assert second_a.get("ok") is True and second_a.get("exit_code") == 0, second_a
    assert (second_a.get("stdout") or "").strip() == "agent-a", (
        f"agent A's second call lost its own session state: {second_a}"
    )
    print(
        f"\nD05 AC11 latency (vm={vm}): first_call_ms={first_ms:.1f} "
        f"reuse_ms={reuse_ms:.1f}"
    )


# ---------------------------------------------------------------------------
# AC12: restore / in-guest restart invalidate the VM's sessions
# ---------------------------------------------------------------------------


def _audit_rows(cfg) -> list[dict]:
    path = cfg.audit_log_path
    if not path or not Path(path).exists():
        return []
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _assert_clean_guest_call(result: dict, label: str) -> None:
    assert result.get("ok") is True, f"{label} failed: {result}"
    assert result.get("exit_code") == 0, f"{label} exit code: {result}"
    blob = json.dumps(result)
    assert "PSSessionStateBroken" not in blob and "Broken" not in blob, (
        f"{label} served a broken-session error: {result}"
    )


def test_session_survives_checkpoint_restore_and_guest_restart(running_vm):
    """AC12: after a checkpoint restore (+ start) and, separately, after a
    restart initiated from inside the guest, the next guest call is served
    from a NEW session — exit_code == 0, no Broken-session error — and the
    invalidation reason is observable in the audit record (a row other than
    the restore tool's own row carries the reason; the mechanism is the
    fix's to choose, the issue only demands the reason be visible)."""
    from hyperv_mcp import diagnostics, guestexec, lifecycle

    cfg, vm, creds = running_vm.cfg, running_vm.vm, running_vm.creds

    # Warm the pool so the invalidation has something to invalidate.
    warm = guestexec.guest_run_ps(cfg, vm, "Write-Output warm", cred=creds)
    assert warm.get("ok") is True, warm

    # (a) checkpoint restore, then start: the sessions for this VM die with
    # the restored guest state.
    lifecycle.checkpoint_restore(cfg, vm, running_vm.checkpoint, confirm=True)
    lifecycle.start_vm(cfg, vm)
    after_restore = guestexec.guest_run_ps(
        cfg, vm, "Write-Output after-restore", cred=creds
    )
    _assert_clean_guest_call(after_restore, "post-restore guest call")
    reason_rows = [
        row
        for row in _audit_rows(cfg)
        if "checkpoint_restore" in json.dumps(row)
        and row.get("tool") != "hyperv_checkpoint_restore"
    ]
    assert reason_rows, (
        "no audit row records the checkpoint_restore session invalidation"
    )

    # (b) restart from INSIDE the guest: no lifecycle leg runs, so the pool
    # must notice the broken session epoch on its own. wait_guest_recovery
    # deliberately opens fresh sessions (the issue rules it out of pooling),
    # so it is the honest "the guest is back" gate before the assertion call.
    reboot = guestexec.guest_run_ps(
        cfg, vm, "& 'shutdown.exe' '/r' '/t' '5'", cred=creds
    )
    assert reboot.get("ok") is True, reboot
    diagnostics.wait_guest_recovery(
        cfg, vm, timeout_s=420, interval_s=10, cred=creds
    )
    after_reboot = guestexec.guest_run_ps(
        cfg, vm, "Write-Output after-reboot", cred=creds
    )
    _assert_clean_guest_call(after_reboot, "post-reboot guest call")
