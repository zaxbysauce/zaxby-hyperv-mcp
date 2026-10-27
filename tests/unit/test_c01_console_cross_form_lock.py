"""Issue #77 acceptance checks (trace 77-28-console-actor-batched-sequences,
class C-01 follow-on): canonical console-actor identity — cross-form (name vs
GUID) exclusion, the host-side name->GUID hint map, and execution-time
revalidation.

Every check in this file is RED at base 4c7ac52 for its named reason and
GREEN after the fix. The transport is the folded PowerShell one (the conftest
autouse fixture pins wmiconsole.COM_AVAILABLE to False) and pswindows.run_ps
is stubbed per the FakePS idiom in test_console.py; nothing here touches a
real Hyper-V host.

Frozen seam this file names (the issues underdetermine it, so the check
author pins the symbol and the implementer must provide exactly this name —
it is the same map the folded scripts' VMID= stdout feed fills):

  console.note_name_guid_hint(vm_name, guid) -> None
      Record a host-side name->GUID hint (no spawn, no guest effect). Used by
      the stale-mapping checks below to construct the "VM deleted and
      recreated under the same name" scenario deterministically.

AC map (01-issue-summary.md):
  AC-77.1 test_cross_form_console_input_serializes_on_guid_key
  AC-77.2 test_stale_name_guid_hint_must_not_act
  AC-77.4 test_by_name_raw_input_takes_canonical_guid_console_key
  AC-77.5 test_identity_revalidated_at_execution_before_any_input
"""

import contextlib
import json
import re
import threading

import pytest

from hyperv_mcp import console, pswindows, vmlocks
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
#: the GUID the replacement VM carries after a delete-and-recreate under the
#: same name (well-formed so guestexec.validate_vm_guid accepts it)
REPLACEMENT_GUID = "0f7d1c22-2222-4b3c-8d1e-6a5b4c3d2e1f"


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


class AdaptivePS:
    """FakePS-shaped recording stub (test_console.py idiom): serves the bare
    by-name resolver leg, the folded display-info leg with a VMID= metadata
    line (the documented host-side name->GUID hint feed), and every other
    folded op as a success."""

    def __init__(self, guid: str = GUID):
        self.scripts: list[str] = []
        self.kwargs: list[dict] = []
        self.guid = guid

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=self.guid, returncode=0)
        if "EnabledState" in script:
            body = json.dumps({
                "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
                "keyboard_present": True, "keyboard_enabled": 2,
                "mouse_present": True, "mouse_enabled": 2,
            })
            return pswindows.PSResult(
                stdout="VMID=" + self.guid + "\n" + body, returncode=0)
        return pswindows.PSResult(stdout="RC=0 CHUNK=1/1", returncode=0)


class ReplacementVMPs:
    """Recording stub playing a LIVE host whose VM under NAME now carries
    live_guid. A folded input script that embeds the stale expectation
    (the in-script identity guard the fix must ship) trips that guard before
    any input: this stub answers with the nonzero exit + stderr the real
    script produces. A script with NO embedded expectation is the pre-fix
    shape: input executes against the replacement VM and the flag records
    it."""

    def __init__(self, name: str, live_guid: str, stale_guid: str):
        self.scripts: list[str] = []
        self.kwargs: list[dict] = []
        self.name = name
        self.live_guid = live_guid
        self.stale_guid = stale_guid
        self.input_executed = False

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=self.live_guid, returncode=0)
        if self.stale_guid in script:
            return pswindows.PSResult(returncode=1, stderr=(
                "console input precondition: VM identity changed under name '"
                + self.name + "': locked " + self.stale_guid
                + " but resolved " + self.live_guid))
        self.input_executed = True
        return pswindows.PSResult(stdout="RC=0 CHUNK=1/1", returncode=0)


# ---------------------------------------------------------------------------
# AC-77.1: cross-form serialization (by-name input vs a (GUID, "console")
# write lock held by the "other agent")
# ---------------------------------------------------------------------------

def test_cross_form_console_input_serializes_on_guid_key(monkeypatch, unrestricted):
    """AC-77.1: a by-name PowerShell-transport console input must NOT
    complete while another agent holds the (GUID, 'console') write key for
    the same VM — the two addressing forms share one canonical lock.

    The hint is seeded the way the issue says hints arrive (a prior folded
    read op whose stdout carries VMID=GUID), so at base this test runs to the
    final assertion: the by-name input completes anyway (the base lock key is
    the caller name, probe A2) and the assertion fails.
    RED at base for the named reason (the by-name input completes under a
    held GUID-form console lock), GREEN after the fix."""
    cfg = unrestricted
    name = "t771-cross-form-vm"
    fake = AdaptivePS(GUID)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    # Seed the host name->GUID hint through the documented feed: a folded
    # read op by name emits VMID=GUID on stdout. At base this call is a
    # harmless extra stub leg; after the fix it is what makes the following
    # by-name input lock on the canonical GUID key.
    console.get_display_info(cfg, name)

    done = threading.Event()

    def _by_name_input():
        console.press_key(cfg, name, "enter")
        done.set()

    worker = threading.Thread(target=_by_name_input, daemon=True)
    with vmlocks.vm_lock((GUID, "console")):
        worker.start()
        # generous bounded wait, asserting a STATE not a duration; never join
        # the worker while still holding — post-fix it parks on this very key
        completed_while_held = done.wait(2.0)
    try:
        assert not completed_while_held, (
            "AC-77.1 cross-form console input did not serialize: the by-name "
            "PowerShell-transport input completed while the (GUID, 'console') "
            "write key was held by another agent — the by-name path still "
            "keys its console lock on the caller-supplied name")
        # Blocked on the canonical key, not broken: once the holder releases,
        # the by-name input must complete.
        assert done.wait(10), (
            "the by-name input did not complete after the console key was "
            "released — it must park on the canonical console key, not fail")
    finally:
        worker.join(timeout=10)
        assert not worker.is_alive(), "the by-name input worker never finished"


# ---------------------------------------------------------------------------
# AC-77.2: a stale host-side name->GUID mapping must not act
# ---------------------------------------------------------------------------

def test_stale_name_guid_hint_must_not_act(monkeypatch, unrestricted):
    """AC-77.2: when the host name->GUID mapping is stale (the VM was deleted
    and recreated under the same name), a by-name console input addressing
    that name must NOT act on the stale identity: no input reaches the
    replacement VM and the call fails with a structured identity/precondition
    error. The stale expectation must ride the folded script (the in-script
    compare against the live $vmTarget is the issue's stated fail-closed
    mechanism — a host-side resolve spawn would break the one-process
    contract pinned by AC-77.3).
    RED at base for the named reason (console.note_name_guid_hint, the seam
    that constructs the stale mapping, is absent), GREEN after the fix."""
    cfg = unrestricted
    name = "t772-recreated-vm"
    # Base dies here: AttributeError naming the missing hint seam.
    console.note_name_guid_hint(name, GUID)
    stub = ReplacementVMPs(name, live_guid=REPLACEMENT_GUID, stale_guid=GUID)
    monkeypatch.setattr(pswindows, "run_ps", stub)

    with pytest.raises((ConsoleError, ValueError)) as raised:
        console.press_key(cfg, name, "enter")
    assert re.search(r"identity|precondition|stale|changed", str(raised.value), re.I), (
        f"the stale-mapping refusal must be a structured identity/precondition "
        f"error, got {raised.value!r}")
    assert stub.input_executed is False, (
        "AC-77.2: guest input executed against the replacement VM while the "
        "host mapping was stale — the stale identity must not act")
    assert any(GUID in s for s in stub.scripts), (
        "the folded input script must embed the expected (locked) GUID so the "
        "in-script live-$vmTarget compare can fail closed before any input")


# ---------------------------------------------------------------------------
# AC-77.4: one canonical console key across name and GUID addressing forms
# ---------------------------------------------------------------------------

def test_by_name_raw_input_takes_canonical_guid_console_key(monkeypatch, unrestricted):
    """AC-77.4: a raw by-name console input whose name has a GUID hint takes
    the CANONICAL (guid, 'console') console key — exactly the same key a
    by-id caller takes — and never the caller-name form, so no two raw input
    calls can overlap across addressing forms.
    RED at base for the named reason (console.note_name_guid_hint is
    absent), GREEN after the fix."""
    cfg = unrestricted
    name = "t774-canonical-key-vm"
    console.note_name_guid_hint(name, GUID)
    fake = AdaptivePS(GUID)
    monkeypatch.setattr(pswindows, "run_ps", fake)

    recorded: list[tuple[object, dict]] = []
    real = vmlocks.vm_lock

    @contextlib.contextmanager
    def spy(key, *args, **kwargs):
        recorded.append((key, kwargs))
        with real(key, *args, **kwargs):
            yield

    monkeypatch.setattr(vmlocks, "vm_lock", spy)
    console.press_key(cfg, name, "enter")

    console_keys = [key for key, _kwargs in recorded if isinstance(key, tuple)]
    assert console_keys == [(GUID, "console")], (
        "AC-77.4: raw input by name and by GUID must share ONE canonical "
        f"console lock key — recorded console key(s) {console_keys!r}; the "
        "caller-name form must never be taken once the GUID is known")
    plain_keys = [str(key).casefold() for key, _kwargs in recorded
                  if isinstance(key, str)]
    assert GUID in plain_keys, (
        "the VM-scope (read) acquisition must also key on the canonical GUID, "
        f"not the caller name (recorded plain keys: {plain_keys!r})")


# ---------------------------------------------------------------------------
# AC-77.5: execution-time revalidation before any input
# ---------------------------------------------------------------------------

def test_identity_revalidated_at_execution_before_any_input(monkeypatch, unrestricted):
    """AC-77.5: a by-name input whose identity went stale between the hint
    being current and the call executing (the VM was replaced under the name
    before the transport leg ran) is revalidated AT EXECUTION: the stale
    operation is rejected before any input is sent. Whether the refusal comes
    from the in-script guard (a folded script ran) or host-side (no script at
    all), the stub must never report executed input.
    RED at base for the named reason (console.note_name_guid_hint is
    absent), GREEN after the fix."""
    cfg = unrestricted
    name = "t775-revalidated-vm"
    console.note_name_guid_hint(name, GUID)
    stub = ReplacementVMPs(name, live_guid=REPLACEMENT_GUID, stale_guid=GUID)
    monkeypatch.setattr(pswindows, "run_ps", stub)

    with pytest.raises((ConsoleError, ValueError)) as raised:
        console.press_key(cfg, name, "enter")
    assert re.search(r"identity|precondition|stale|changed", str(raised.value), re.I), (
        f"the execution-time refusal must be a structured identity/precondition "
        f"error, got {raised.value!r}")
    assert stub.input_executed is False, (
        "AC-77.5: the stale operation was not rejected before input — the "
        "guest received console input under a stale identity")
    if stub.scripts:
        assert GUID in stub.scripts[-1], (
            "when the folded script runs, it must carry the expected GUID so "
            "the live identity is revalidated at execution time")
