"""AC5 integration check for issue 5 (trace 5-ps51-sanitized-env).

Never runs accidentally: tests/integration/conftest.py skips the whole suite
with an actionable reason unless HYPERV_MCP_INTEGRATION=1,
HYPERV_MCP_TEST_VM names a disposable VM, and guest credentials are set.
pwsh 7 and Hyper-V are additionally required on the host — without them the
gates stay unset and this module skips with the conftest reason.

The test simulates a server process started from a PowerShell 7 session
(pwsh7 PSModulePath entries plus secret variables in the SERVER environment),
then:

  1. runs the credentialed guest leg — the same implementation
     hyperv_guest_run_ps uses — against the disposable VM and requires
     ok: true. This step is a connectivity / leg-success check: the guest
     spawn is hard-wired to powershell.exe (Windows PowerShell 5.1) inside
     the VM, so its $PSVersionTable output cannot reflect host-side child_env
     sanitization. Host-side sanitization evidence lives in step 2 and the
     CI-run unit checks (tests/unit/test_a01_ps_environment.py AC1/AC2,
     tests/unit/test_ps_child_env.py, tests/unit/test_spawn_env_guardrail.py).
  2. calls the real hyperv_server_info tool and requires
     powershell.edition == "Desktop" with no pwsh7 module entry in
     powershell.psmodulepath, even though the server env is pwsh7-polluted.
"""

import asyncio
import importlib
import json
import os
import time

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows

pytestmark = [pytest.mark.hyperv_real]

# What the server environment looks like when the stdio server is started
# from a PowerShell 7 session: pwsh7 user/shared/versioned module directories
# ahead of the Windows PowerShell 5.1 directories.
PWSH7_PARENT_PSMODULEPATH = ";".join([
    r"C:\Users\probe-user\Documents\PowerShell\Modules",
    r"C:\Program Files\PowerShell\Modules",
    r"C:\Program Files\PowerShell\7\Modules",
    pswindows.PS51_SYSTEM_MODULES,
    r"C:\Program Files\WindowsPowerShell\Modules",
])

VICTIM_SENTINEL = "DUMMY-SENTINEL-ac5-victim-password"
TOKEN_SENTINEL = "DUMMY-SENTINEL-ac5-http-token"

# Per-creation uniqueness suffix for checkpoint names (repo protocol from
# tests/integration/test_hyperv_real.py): Hyper-V allows duplicate snapshot
# names and restore/remove by an ambiguous name fails, so the checkpoint name
# must never collide — a same-second second creation (parametrize/retry)
# would otherwise become ambiguous.
_CHECKPOINT_SEQ = 0


@pytest.fixture()
def guarded_vm(it):
    """Checkpoint before exercising; restore afterwards (repo protocol)."""
    from hyperv_mcp import lifecycle

    global _CHECKPOINT_SEQ
    _CHECKPOINT_SEQ += 1
    checkpoint = (
        "mcp-it-a01-" + time.strftime("%Y%m%d-%H%M%S") + f"-{_CHECKPOINT_SEQ}"
    )
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


def test_credentialed_leg_from_pwsh7_parent(running_vm, monkeypatch):
    """AC5: with a pwsh7-flavored, secret-carrying server environment, the
    credentialed guest leg completes ok:true and hyperv_server_info reports a
    clean Windows PowerShell 5.1 provenance (edition Desktop, no pwsh7 module
    entries)."""
    from hyperv_mcp import guestexec

    has_creds = bool(
        os.environ.get("HYPERV_GUEST_PASSWORD", "")
        or os.environ.get("HYPERV_GUEST_PASSWORD_FILE", "")
    )
    assert os.environ.get("HYPERV_GUEST_USERNAME", "") and has_creds, (
        "integration gates promised guest credentials but they are not set"
    )

    monkeypatch.setenv("PSModulePath", PWSH7_PARENT_PSMODULEPATH)
    monkeypatch.setenv("HYPERV_GUEST_VICTIM_PASSWORD", VICTIM_SENTINEL)
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", TOKEN_SENTINEL)

    # 1. Credentialed leg against the disposable VM (real password from the
    #    gated environment; sentinels above must not be needed by the leg).
    #    The guest spawn is hard-wired to powershell.exe 5.1, so the guest
    #    edition is pinned exactly (this step is leg-success evidence only —
    #    see the module docstring for where sanitization is proven).
    out = guestexec.guest_run_ps(
        running_vm.cfg, running_vm.vm, "$PSVersionTable.PSEdition",
        cred=running_vm.creds,
    )
    assert out["ok"], out
    assert out["exit_code"] == 0, out
    assert out["stdout"].strip() == "Desktop", out

    # 2. Real provenance tool under the same polluted server environment.
    mod = importlib.reload(server_module)
    try:
        mod.bootstrap({})
        mcp = mod.get_mcp()
        raw = asyncio.run(mcp.call_tool("hyperv_server_info", {}))
        content = raw[0] if isinstance(raw, tuple) else raw
        response_text = "".join(
            getattr(block, "text", "")
            for block in content
            if getattr(block, "type", "") == "text"
        )
        payload = json.loads(response_text)
    finally:
        importlib.reload(server_module)

    ps = payload["powershell"]
    assert ps["edition"] == "Desktop", (
        f"hyperv_server_info powershell.edition is {ps['edition']!r}, "
        "expected 'Desktop' (Windows PowerShell 5.1 host probe)"
    )
    entries = [e for e in ps["psmodulepath"].split(";") if e.strip()]
    pwsh7_entries = [e for e in entries if pswindows._is_pwsh7_module_entry(e)]
    assert pwsh7_entries == [], (
        "hyperv_server_info powershell.psmodulepath still carries PowerShell 7 "
        f"module entries while the server env is pwsh7-polluted: {pwsh7_entries}"
    )
    assert pswindows._norm_path(pswindows.PS51_SYSTEM_MODULES) in {
        pswindows._norm_path(e) for e in entries
    }, "hyperv_server_info powershell.psmodulepath lost the 5.1 system module directory"

    # No secret value (real credential or test sentinel) in the serialized
    # response. The value-level check must execute under BOTH credential gate
    # forms (F-005/cub-04): with HYPERV_GUEST_PASSWORD set, use the env value;
    # with HYPERV_GUEST_PASSWORD_FILE set, credentials.py resolves the file
    # first and the resolved secret lives on running_vm.creds.password, never
    # in os.environ.
    serialized = response_text + json.dumps(payload, default=str)
    real_password = os.environ.get("HYPERV_GUEST_PASSWORD", "")
    if not real_password:
        real_password = running_vm.creds.password or ""
    assert real_password, (
        "test precondition: neither HYPERV_GUEST_PASSWORD nor a resolvable "
        "running_vm.creds.password is available for the value-level check"
    )
    assert real_password not in serialized, (
        "hyperv_server_info response contains the real guest password"
    )
    assert VICTIM_SENTINEL not in serialized
    assert TOKEN_SENTINEL not in serialized
