"""Issue #8 value-level compensating pins (review PRR-022).

tests/unit/test_a04_vm_identity.py and tests/integration/
test_a04_vm_identity_real.py are FROZEN by the trace's anti-tampering
contract and pin generated SCRIPT TEXT; these non-frozen pins (precedent:
tests/unit/test_issue7_feedback_pins.py) assert the parsed VALUES the frozen
files could not: inventory rows carry the GUID, the vm_create duplicate-name
guard actually refuses, the not-unique resolver message formats every
candidate as ElementName=GUID, the tool layer maps neither-given and
mismatched name/id pairs to invalid envelopes, and a by-id call audits under
the RESOLVED name.
"""

import asyncio
import importlib
import json

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import auditlog, guestexec, lifecycle, media, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.media import MediaError

VM_GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
OTHER_GUID = "0f6e6a8a-1d3c-4a52-9a43-6f0b2f0c1a11"


class FakePS:
    """Content-dispatching stub (test_console.py pattern): the two identity
    legs are recognized by content FIRST (the by-name resolver emits the
    GUID; the by-id leg emits the resolved name), then queued responses
    serve the action legs in order."""

    def __init__(self, responses=(), *, by_name_guid=VM_GUID, by_id_name="test-vm-1"):
        self.scripts = []
        self.responses = list(responses)
        self.by_name_guid = by_name_guid
        self.by_id_name = by_id_name

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            item = pswindows.PSResult(stdout=self.by_name_guid, returncode=0)
        elif "Get-VM -Id $vmTarget" in script and script.rstrip().endswith("$vm.Name"):
            item = pswindows.PSResult(stdout=self.by_id_name, returncode=0)
        elif self.responses:
            item = self.responses.pop(0)
        else:
            raise AssertionError(f"unexpected run_ps call: {script[:120]!r}")
        if isinstance(item, Exception):
            raise item
        return item


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


# ---------------------------------------------------------------------------
# 1. inventory VALUES: rows carry the GUID, not just a script that asks for it
# ---------------------------------------------------------------------------


def test_list_vms_rows_carry_the_guid_value(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_ok([
        {"id": VM_GUID, "name": "test-vm-1", "state": "Running",
         "status": "Operating normally", "memory_mb": 2048, "cpu_count": 2,
         "uptime_seconds": 600},
        {"id": OTHER_GUID, "name": "test-vm-2", "state": "Off",
         "status": "", "memory_mb": 1024, "cpu_count": 1, "uptime_seconds": 0},
    ])])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    rows = lifecycle.list_vms(cfg)
    assert [row["id"] for row in rows] == [VM_GUID, OTHER_GUID]
    assert rows[0]["name"] == "test-vm-1" and rows[1]["name"] == "test-vm-2"
    assert len(fake.scripts) == 1


def test_get_vm_info_parsed_dict_carries_the_guid_value(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = FakePS([_ok({
        "id": VM_GUID, "name": "test-vm-1", "state": "Running",
        "status": "Operating normally", "generation": 2, "memory_mb": 2048,
        "dynamic_memory": True, "cpu_count": 2, "uptime_seconds": 600,
        "checkpoint_count": 0, "com_ports": [], "network_adapters": [],
        "hard_drives": [],
    })])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    info = lifecycle.get_vm_info(cfg, "test-vm-1")
    assert info["id"] == VM_GUID
    assert info["name"] == "test-vm-1"
    # One resolution leg (by name) + one info leg.
    assert len(fake.scripts) == 2
    assert f"$vmTarget = '{VM_GUID}'" in fake.scripts[1]


# ---------------------------------------------------------------------------
# 2. vm_create duplicate-name guard actually REFUSES
# ---------------------------------------------------------------------------


def test_vm_create_duplicate_name_guard_refuses(monkeypatch, tmp_path):
    """The guard is more than script text: when its throw fires the call
    surfaces as MediaError naming the VM, and no second leg runs (the guard
    precedes New-VM inside the ONE script, so nothing is created)."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        pswindows.PSResult(stdout="", returncode=1, stderr="VM name already exists"),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(MediaError) as excinfo:
        media.vm_create(
            cfg, "test-dup", vhd_path=str(tmp_path / "test-dup.vhdx"), confirm=True,
        )
    # Exactly one script ran; it carries the guard AND the New-VM leg (the
    # guard firing at the TOP of that script is what keeps New-VM inert).
    assert len(fake.scripts) == 1
    script = fake.scripts[0]
    assert "Msvm_ComputerSystem" in script
    assert "VM name already exists" in script
    assert "New-VM -Name 'test-dup'" in script
    # The guard predicate tests the caller's literal name.
    assert "$_.ElementName -eq 'test-dup'" in script
    # The surfaced error names the VM (the _run context label) and the guard.
    assert "vm_create(test-dup)" in str(excinfo.value)
    assert "VM name already exists" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 3. resolver not-unique message formats BOTH candidates as ElementName=GUID
# ---------------------------------------------------------------------------


def test_resolver_not_unique_line_formats_candidates_as_name_eq_guid():
    """The not-unique branch must render EVERY candidate via the
    ElementName=Name expression sourced from $vmCandidates (the value-level
    message contract: 'name=guid, name=guid' so the caller can retry by id).
    The message itself is built inside PowerShell; pinning the formatting
    expression plus its $vmCandidates source on the not-unique line is the
    non-frozen value check."""
    lines = guestexec.psdirect_vm_target("dup-name").splitlines()
    branch = [i for i, ln in enumerate(lines) if "$vmCandidates.Count -gt 1" in ln]
    assert len(branch) == 1, "exactly one not-unique branch line"
    payload = lines[branch[0] + 1]
    assert "not unique" in payload
    # Every candidate flows through the pipeline (both, never a picked one).
    assert "$vmCandidates | ForEach-Object" in payload
    # And each is formatted ElementName=GUID (ElementName is the display
    # name; Name is the CIM GUID Msvm_ComputerSystem keys on).
    assert "$_.ElementName + '=' + $_.Name" in payload


# ---------------------------------------------------------------------------
# 4. tool layer: neither given / mismatched pair -> invalid envelope
# ---------------------------------------------------------------------------


@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)
    # Drop any tmp audit sink this test installed before other tests run.
    auditlog.init(Config())


@pytest.fixture()
def unrestricted_server(tmp_path, fresh_server):
    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return fresh_server({"HYPERV_MCP_CONFIG": str(p)}).get_mcp()


def _envelope_from_call(mcp, tool: str, args: dict) -> dict:
    result = asyncio.run(mcp.call_tool(tool, args))
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content  # in-process call_tool returns a CallToolResult
    text_blocks = [c for c in content if getattr(c, "type", "") == "text"]
    assert text_blocks, f"expected a text envelope for {tool}"
    return json.loads(text_blocks[0].text)


def test_start_vm_neither_name_nor_id_is_invalid_envelope(unrestricted_server, monkeypatch):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    envelope = _envelope_from_call(unrestricted_server, "hyperv_start_vm", {})
    assert envelope["ok"] is False
    assert envelope["error_class"] == "invalid"
    assert fake.scripts == []  # rejected before any PowerShell leg


def test_start_vm_mismatched_name_and_id_is_invalid_envelope(unrestricted_server, monkeypatch):
    """A by-id leg resolving a DIFFERENT name than the caller-supplied
    vm_name must reject the call as invalid after exactly one read-only leg."""
    fake = FakePS(by_id_name="prod-db")
    monkeypatch.setattr(pswindows, "run_ps", fake)
    envelope = _envelope_from_call(
        unrestricted_server, "hyperv_start_vm",
        {"vm_name": "test-vm-1", "vm_id": OTHER_GUID},
    )
    assert envelope["ok"] is False
    assert envelope["error_class"] == "invalid"
    assert "different VMs" in envelope["error"]
    assert len(fake.scripts) == 1  # only the by-id resolution leg
    assert "Get-VM -Id $vmTarget" in fake.scripts[0]


# ---------------------------------------------------------------------------
# 5. audit attribution: a by-id call audits under the RESOLVED name
# ---------------------------------------------------------------------------


def test_by_id_start_vm_audit_row_carries_resolved_name(tmp_path, fresh_server, monkeypatch):
    log = tmp_path / "audit.jsonl"
    doc = {
        "allowed_vm_patterns": ["test-*"],
        "unrestricted": True,
        "audit_log_path": str(log),
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mcp = fresh_server({"HYPERV_MCP_CONFIG": str(p)}).get_mcp()
    fake = FakePS(
        [
            _ok({"initial_state": "Stopped"}),
            _ok({"final_state": "Running"}),
        ],
        by_id_name="test-vm-1",
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    result = _envelope_from_call(mcp, "hyperv_start_vm", {"vm_id": VM_GUID})
    assert result["status"] == "started" and result["vm_name"] == "test-vm-1"
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    row = [r for r in rows if r["tool"] == "hyperv_start_vm"][-1]
    # The caller passed NO name; the audit row must carry the RESOLVED one,
    # never the empty caller input (issue #8 audit clause).
    assert row["vm_name"] == "test-vm-1"
    assert row["ok"] is True
