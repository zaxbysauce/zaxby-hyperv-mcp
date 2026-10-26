"""Issue #26 acceptance checks: checkpoint_type end-to-end (RED at base).

Issue #26 adds a `checkpoint_type` choice to checkpoint creation. Today's
tree has none of it: `lifecycle.checkpoint_create` runs a bare Checkpoint-VM
with no type parameter, `checkpoint_restore` returns a constant "powered
off" note regardless of the observed final state, `get_vm_info` never reads
`$vm.CheckpointType`, and the server tool schema has no `checkpoint_type`
property (nor any memory disclosure in its description).

Every test's FIRST assertion carries a signed "F02-AC<n>-RED-AT-BASE:"
prefix so a replay against the unfixed tree classifies as RED for the right
reason — an assertion failure with that message, never an import/collection
error. Detail assertions follow the signed one.

Transport is stubbed at `pswindows.run_ps` (tests/unit/test_lifecycle.py's
pattern). Legs are discriminated by substring predicates only — a resolver
leg contains "Msvm_ComputerSystem" and no "ConvertTo-Json" — because a
remote-host wrapper appends a suffix to every emitted script, so positional
or endswith anchors would be wrong. No PowerShell, network or Hyper-V is
touched.
"""

import asyncio
import importlib
import json

import pytest

from hyperv_mcp import lifecycle, pswindows
from hyperv_mcp.config import Config
import hyperv_mcp.server as server_module

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
RESOLUTION = pswindows.PSResult(stdout=GUID, returncode=0)


class FakePS:
    """Records scripts, returns canned results (test_lifecycle.py pattern)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _is_resolver_leg(script):
    """The by-name resolution leg: Msvm_ComputerSystem present, no JSON emit."""
    return "Msvm_ComputerSystem" in script and "ConvertTo-Json" not in script


def _action_legs(scripts):
    """Every non-resolver leg, in order (the action script(s) of the call)."""
    return [s for s in scripts if not _is_resolver_leg(s)]


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture()
def fresh_server():
    """Mirror of test_server.py's fixture: reload server, bootstrap, restore."""
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


# --------------------------------------------------------------------------
# AC1 — checkpoint_create accepts checkpoint_type="standard"
# --------------------------------------------------------------------------

def test_checkpoint_create_accepts_standard_type(monkeypatch, unrestricted):
    fake = FakePS([RESOLUTION, pswindows.PSResult(stdout="", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    captured = "ok"
    out = {}
    try:
        out = lifecycle.checkpoint_create(
            unrestricted, "vm1", "base", checkpoint_type="standard"
        )
    except Exception as exc:
        captured = type(exc).__name__
    assert captured == "ok", (
        "F02-AC1-RED-AT-BASE: lifecycle.checkpoint_create does not accept a "
        f"checkpoint_type parameter yet (call outcome: {captured!r}); a "
        "Standard checkpoint must be requestable as checkpoint_type='standard'"
    )
    assert out["status"] == "created"
    assert "Checkpoint-VM" in fake.scripts[1], (
        "the action leg must still create the checkpoint with Checkpoint-VM"
    )


# --------------------------------------------------------------------------
# AC2 — Standard type: set before, restore after, inside finally
# --------------------------------------------------------------------------

def test_standard_type_sets_and_restores_vm_checkpoint_type(monkeypatch, unrestricted):
    fake = FakePS([RESOLUTION, pswindows.PSResult(stdout="", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    try:
        lifecycle.checkpoint_create(
            unrestricted, "vm1", "base", checkpoint_type="standard"
        )
    except Exception:
        pass  # a base-leg failure is reported by the signed marker assert below
    action_legs = _action_legs(fake.scripts)
    action = action_legs[-1] if action_legs else ""
    idx_std = action.find("-CheckpointType Standard")
    idx_c = action.find("Checkpoint-VM")
    idx_fin = action.find("finally")
    assert -1 not in (idx_std, idx_c, idx_fin) and idx_std < idx_c < idx_fin, (
        "F02-AC2-RED-AT-BASE: the action script must set the Standard type "
        "BEFORE Checkpoint-VM and restore it in a finally block "
        f"(markers -CheckpointType Standard@{idx_std}, Checkpoint-VM@{idx_c}, "
        f"finally@{idx_fin}; action script captured: {action!r})"
    )
    assert "$vm.CheckpointType" in action, (
        "the script must read the VM's original CheckpointType before changing it"
    )
    assert "-CheckpointType $orig" in action, (
        "the finally block must restore the original CheckpointType "
        "(-CheckpointType $orig)"
    )
    for line in action.splitlines():
        if "Set-VM" in line or "Checkpoint-VM" in line:
            assert "-ErrorAction Stop" in line, (
                f"mutating cmdlet without -ErrorAction Stop: {line.strip()!r}"
            )


# --------------------------------------------------------------------------
# AC3 — invalid checkpoint_type rejected before any PowerShell
# --------------------------------------------------------------------------

def test_invalid_checkpoint_type_rejected(monkeypatch, unrestricted):
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    captured = "ok"
    try:
        lifecycle.checkpoint_create(
            unrestricted, "vm1", "base", checkpoint_type="Standard; rm"
        )
    except ValueError:
        captured = "ValueError"
    except Exception as exc:
        captured = type(exc).__name__
    assert captured == "ValueError", (
        "F02-AC3-RED-AT-BASE: an injection-shaped checkpoint_type "
        f"('Standard; rm') must raise ValueError before anything runs "
        f"(call outcome: {captured!r})"
    )
    assert fake.scripts == [], (
        "validation must precede any PowerShell, including the resolution leg"
    )


# --------------------------------------------------------------------------
# AC4 / AC4B — restore note must match the observed final state
# --------------------------------------------------------------------------

def _restore_transport(final_state):
    """Content-discriminating run_ps stub for checkpoint_restore.

    Resolver leg (Msvm_ComputerSystem, no ConvertTo-Json) -> GUID; the
    state-wait leg (its script names final_state) -> the canned final state;
    every other leg (the Restore-VMSnapshot action) -> empty success.
    """

    def fake(script, **kwargs):
        if _is_resolver_leg(script):
            return RESOLUTION
        if "final_state" in script:
            return pswindows.PSResult(
                stdout=json.dumps({"final_state": final_state}), returncode=0
            )
        return pswindows.PSResult(stdout="", returncode=0)

    return fake


def test_restore_note_matches_saved_state(monkeypatch, unrestricted):
    monkeypatch.setattr(pswindows, "run_ps", _restore_transport("Saved"))
    out = lifecycle.checkpoint_restore(unrestricted, "vm1", "snap", confirm=True)
    note = out["note"]
    assert "powered off" not in note, (
        "F02-AC4-RED-AT-BASE: checkpoint_restore returns the constant "
        "'powered off' note even when the observed final state is Saved "
        f"(note: {note!r})"
    )
    assert "hyperv_start_vm" in note, (
        f"the Saved-state note must point at hyperv_start_vm (note: {note!r})"
    )
    assert "memor" in note, (
        "the Saved-state note must disclose that resuming restores the saved "
        f"memory state (note: {note!r})"
    )


def test_restore_note_matches_paused_state(monkeypatch, unrestricted):
    monkeypatch.setattr(pswindows, "run_ps", _restore_transport("Paused"))
    out = lifecycle.checkpoint_restore(unrestricted, "vm1", "snap", confirm=True)
    note = out["note"]
    assert "powered off" not in note, (
        "F02-AC4B-RED-AT-BASE: checkpoint_restore returns the constant "
        "'powered off' note even when the observed final state is Paused "
        f"(note: {note!r})"
    )
    assert out["state"] == "Paused"
    assert "resum" in note.lower(), (
        "the Paused-state note must name resume semantics (resume/resuming "
        f"the VM) rather than claiming the VM is powered off (note: {note!r})"
    )


# --------------------------------------------------------------------------
# AC5 — get_vm_info reports the VM's CheckpointType
# --------------------------------------------------------------------------

def test_vm_info_reports_checkpoint_type(monkeypatch, unrestricted):
    row = {
        "id": GUID,
        "name": "vm1",
        "state": "Running",
        "status": "OK",
        "generation": 2,
        "memory_mb": 2048.0,
        "dynamic_memory": False,
        "cpu_count": 2,
        "uptime_seconds": 1.0,
        "checkpoint_count": 0,
        "com_ports": [],
        "network_adapters": [],
        "hard_drives": [],
        "checkpoint_type": "Production",
    }
    fake = FakePS([
        RESOLUTION,
        pswindows.PSResult(stdout=json.dumps(row), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.get_vm_info(unrestricted, "vm1")
    action = _action_legs(fake.scripts)[-1]
    assert "CheckpointType" in action, (
        "F02-AC5-RED-AT-BASE: the get_vm_info action script never reads "
        "$vm.CheckpointType (script: "
        f"{' '.join(action.split())!r})"
    )
    assert out["checkpoint_type"] == "Production", (
        "the emitted info must carry the snake_case checkpoint_type field"
    )
    assert out["CheckpointType"] == "Production", (
        "the PascalCase CheckpointType legacy alias must round-trip through "
        "_add_legacy_aliases like every other info field"
    )


# --------------------------------------------------------------------------
# AC6 — the server tool exposes checkpoint_type and discloses memory
# --------------------------------------------------------------------------

def test_checkpoint_create_tool_exposes_type(fresh_server):
    mod = fresh_server({})
    mcp = mod.get_mcp()
    tools = asyncio.run(mcp.list_tools())
    schemas = {
        t.name: (getattr(t, "input_schema", None) or t.inputSchema) for t in tools
    }
    tool = next(t for t in tools if t.name == "hyperv_checkpoint_create")
    assert "checkpoint_type" in schemas["hyperv_checkpoint_create"].get("properties", {}), (
        "F02-AC6-RED-AT-BASE: the hyperv_checkpoint_create tool schema has no "
        "checkpoint_type property, so a Standard checkpoint cannot be "
        "requested through the MCP surface"
    )
    description = getattr(tool, "description", "") or ""
    assert "guest memory" in description, (
        "the tool description must disclose that a Standard checkpoint "
        "writes guest memory to the host checkpoint store (description: "
        f"{description!r})"
    )
