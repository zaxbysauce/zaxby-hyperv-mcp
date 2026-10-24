"""Real-Hyper-V integration tests for issue #18 (Workstream D PR 2): every
console call starts ONE PowerShell process (capture_sequence is the one
exception — it runs one folded process per frame), and the mouse lookup is
SystemName-scoped.

Opt-in like every file here (see tests/integration/conftest.py): the suite
skips unless HYPERV_MCP_INTEGRATION=1, HYPERV_MCP_TEST_VM names a disposable
VM, and guest credentials are set. Console observation and input are host-side
WMI, so these tests need no guest credentials of their own — the shared gate
is simply stricter.

The VM is addressed BY NAME (the shape AC1-AC8 measure: one folded process per
call). Input is driven with the VM at the Windows lock screen so every op is
inert; the typed text is cleared with backspaces afterwards.
"""

import time

import pytest

pytestmark = [pytest.mark.hyperv_real]

from hyperv_mcp import console, guestexec, pswindows, wmiconsole  # noqa: E402
from hyperv_mcp.config import Config  # noqa: E402


class _CountingRunPs:
    """Delegating wrapper: counts calls (== powershell.exe children) and adds
    nothing to the behavior."""

    def __init__(self, real):
        self.real = real
        self.count = 0

    def __call__(self, script, timeout_s=None, stdin_b64=None):
        self.count += 1
        return self.real(script, timeout_s=timeout_s, stdin_b64=stdin_b64)


@pytest.fixture()
def ps_transport(monkeypatch):
    """Force the PowerShell transport and count its children."""
    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", False)
    counter = _CountingRunPs(pswindows.run_ps)
    monkeypatch.setattr(pswindows, "run_ps", counter)
    return counter


def _cfg():
    return Config(unrestricted=True)


def test_console_ops_single_spawn_live(it, ps_transport):
    """AC13: screenshot, mouse_move, click, scroll, press_key and type_text each
    complete with exactly one powershell.exe child, and the SystemName filter
    returns exactly one device on this Hyper-V build."""
    vm = it.vm
    cfg = _cfg()
    pswindows.init(cfg)

    for op in (
        lambda: console.screenshot(cfg, vm, width=320, height=240),
        lambda: console.mouse_move(cfg, vm, 400, 300),
        lambda: console.click(cfg, vm, 400, 300),
        lambda: console.scroll(cfg, vm, 1),
        lambda: console.press_key(cfg, vm, "escape"),
        lambda: console.type_text(cfg, vm, "d02-live-probe"),
    ):
        before = ps_transport.count
        wall0 = time.monotonic()
        op()
        wall_ms = int((time.monotonic() - wall0) * 1000)
        spawns = ps_transport.count - before
        assert spawns == 1, f"one op started {spawns} PowerShell processes"
        print(f"live op: spawns={spawns} wall_ms={wall_ms}")

    # clear the typed text from the lock-screen password field
    for _ in range(len("d02-live-probe")):
        console.press_key(cfg, vm, "backspace")

    # the SystemName filter is valid WQL on this build and returns exactly one
    # device for the VM
    guid = console.vmident.resolve(cfg, vm).id
    result = pswindows.run_ps(
        "$m = Get-CimInstance -Namespace 'root\\virtualization\\v2' "
        "-ClassName Msvm_SyntheticMouse -Filter \"SystemName='" + guid + "'\"\n"
        "@($m).Count\n",
        timeout_s=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1", (
        f"SystemName filter returned {result.stdout.strip()!r} devices"
    )


def _gen1_vm_or_skip(cfg, name):
    """Resolve the named Gen1 VM or SKIP: a stale name must skip this file
    rather than fail it, and a VM that is not Generation 1 cannot exercise the
    PS/2 fallback (it would expose a synthetic mouse)."""
    try:
        ref = console.vmident.resolve(cfg, name)
    except Exception as exc:  # noqa: BLE001 - any resolution failure is a skip
        pytest.skip(f"HYPERV_MCP_TEST_VM_GEN1 names '{name}', which does not resolve: {exc}")
    script = (
        guestexec.vm_target_preamble(ref.id)
        + "\n(Get-VM -Id $vmTarget -ErrorAction Stop).Generation.ToString()\n"
    )
    result = pswindows.run_ps(script, timeout_s=60)
    generation = result.stdout.strip()
    if result.returncode != 0 or not generation.isdigit():
        pytest.skip(f"cannot read the generation of '{name}': {result.stderr[:120]}")
    if generation != "1":
        pytest.skip(f"'{name}' is Generation {generation}, not 1")
    return ref


def test_ps2_mouse_fallback_live(it, ps_transport):
    """AC14: a VM whose WMI model exposes no Msvm_SyntheticMouse but has an
    Msvm_Ps2Mouse (Gen1 without integration services) serves button, scroll and
    click-at-current-position through the PS/2 device, while positional calls
    report the structured error instead of acting.

    Selected by HYPERV_MCP_TEST_VM_GEN1; skipped when it names no VM, names a VM
    that does not resolve, or names a VM that is not Generation 1."""
    import os

    gen1 = os.environ.get("HYPERV_MCP_TEST_VM_GEN1", "").strip()
    if not gen1:
        pytest.skip("HYPERV_MCP_TEST_VM_GEN1 is not set (no Gen1 test VM named)")

    cfg = _cfg()
    pswindows.init(cfg)
    ref = _gen1_vm_or_skip(cfg, gen1)

    before = ps_transport.count
    out = console.mouse_button(cfg, gen1, 1, True)
    assert out["ok"] is True
    assert ps_transport.count - before == 1

    before = ps_transport.count
    out = console.scroll(cfg, gen1, 1)
    assert out["ok"] is True
    assert ps_transport.count - before == 1

    before = ps_transport.count
    out = console.click(cfg, gen1)
    assert out["ok"] is True
    assert ps_transport.count - before == 1

    # absolute positioning has no PS/2 equivalent: a structured error, never a
    # silent no-op and never faked with relative moves
    with pytest.raises(console.ConsoleError, match="no synthetic mouse"):
        console.mouse_move(cfg, gen1, 10, 10)
    with pytest.raises(console.ConsoleError, match="no synthetic mouse"):
        console.click(cfg, gen1, 10, 10)

    # the PS/2 fallback's SystemName filter is valid WQL on this build and
    # returns exactly one device for the VM (the Gen2 test's synthetic-mouse
    # assertion, for the fallback device)
    result = pswindows.run_ps(
        "$m = Get-CimInstance -Namespace 'root\\virtualization\\v2' "
        "-ClassName Msvm_Ps2Mouse -Filter \"SystemName='" + ref.id + "'\"\n"
        "@($m).Count\n",
        timeout_s=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1", (
        f"SystemName filter returned {result.stdout.strip()!r} PS/2 devices"
    )
