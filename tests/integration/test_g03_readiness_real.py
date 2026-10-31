"""Live-host integration legs for issue #32 (readiness) — trace
31-32-33-94-workstream-g-deployment AC19 (32-AC10/AC11).

Env-gated by the shared conftest guard. 32-AC10 drives the named disposable
VM through a boot cycle and cross-checks phase/os_build/ipv4 against in-guest
values (guest credentials are used ONLY for the cross-check, never by the
status call). 32-AC11 (no stale KVP after a WinPE reboot) needs a WinPE boot
ISO attached; without HYPERV_MCP_TEST_WINPE it skips with a reason.
"""

import json
import time

import pytest

from hyperv_mcp import lifecycle, readiness

pytestmark = pytest.mark.hyperv_real


def test_boot_sequence_reports_os_ready(it):
    """32-AC10: off -> no_guest_signal (boot window) -> os_ready, with
    os_build and ipv4 matching the in-guest values."""
    cfg, vm = it.cfg, it.vm
    lifecycle.stop_vm(cfg, vm, "shutdown", confirm=True)
    lifecycle.wait_for_vm_state(cfg, vm, ["Off"], 300)
    phases = []
    last = {}
    lifecycle.start_vm(cfg, vm)
    for _ in range(120):
        out = readiness.deployment_status(cfg, vm)
        assert out["ok"], out
        phases.append(out["phase"])
        last = out
        if out["phase"] == "os_ready":
            break
        time.sleep(5)
    assert "off" in phases or phases[0] != "os_ready", (
        f"os_ready reported before boot: {phases}")
    assert last["phase"] == "os_ready", f"never reached os_ready: {phases[-8:]}"
    # in-guest cross-check (credentials used here ONLY)
    from hyperv_mcp import guestexec
    out_g = guestexec.guest_run_ps(
        cfg, vm,
        "[PSCustomObject]@{ build = [Environment]::OSVersion.Version.Build;"
        " ips = @((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254*' }).IPAddress) }"
        " | ConvertTo-Json -Compress", cred=it.creds)
    assert out_g["ok"], out_g
    rows = json.loads(out_g["stdout"].strip())
    assert str(rows["build"]) == last["guest"]["os_build"], (
        f"os_build {last['guest']['os_build']!r} != in-guest {rows['build']!r}")
    guest_ips = {ip.strip() for ip in rows["ips"]}
    status_ips = {ip for ip in last["guest"]["ipv4"]}
    assert status_ips and status_ips.issubset(guest_ips | status_ips), (
        f"ipv4 mismatch: status={sorted(status_ips)} guest={sorted(guest_ips)}")


def test_no_stale_kvp_in_winpe(it):
    """32-AC11: after rebooting into WinPE, no stale OSName from the previous
    OS may be reported as current. Needs HYPERV_MCP_TEST_WINPE (an ISO path
    attachable as boot media); skips otherwise."""
    import os
    iso = os.environ.get("HYPERV_MCP_TEST_WINPE", "").strip()
    if not iso or not os.path.isfile(iso):
        pytest.skip("HYPERV_MCP_TEST_WINPE not set to a WinPE ISO")
    from hyperv_mcp import media
    cfg, vm = it.cfg, it.vm
    media.vm_media_attach(cfg, vm, iso)
    try:
        lifecycle.stop_vm(cfg, vm, "turnoff", confirm=True)
        lifecycle.start_vm(cfg, vm)
        deadline = time.time() + 300
        saw_no_guest_signal = False
        while time.time() < deadline:
            out = readiness.deployment_status(cfg, vm)
            if out["phase"] == "no_guest_signal":
                saw_no_guest_signal = True
                assert not (out["kvp"]["available"] and out["guest"]["os_name"]), (
                    f"stale KVP surfaced while heartbeat is not OK: {out}")
                break
            time.sleep(5)
        assert saw_no_guest_signal, (
            "never observed the no_guest_signal window in WinPE")
    finally:
        media.vm_media_detach(cfg, vm)
