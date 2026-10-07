"""Acceptance checks for issue #8: VMs are addressed by GUID end to end.

Every discriminating check here encodes one slice of the fixed contract:
inventory surfaces the VM GUID, the per-VM lock keys on the resolved GUID
(not the spelling of the name), vm_create refuses to shadow an existing
name, the not-unique resolver error names the candidate GUIDs, every
vm_name tool also accepts vm_id (exactly one of the two), and the VM
policy gates the name a vm_id resolves to.
"""

import asyncio
import importlib
import json
import threading

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import guestexec, lifecycle, media, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.vmlocks import VMBusy

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
PROD_ID = "0f6e6a8a-1d3c-4a52-9a43-6f0b2f0c1a11"


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


class FakePS:
    """Adaptive PowerShell stub (test_console.py style).

    Serves the GUID-resolution leg first — pre-fix trees embed the resolver
    inline in every script, post-fix trees run it as a separate short leg —
    then queued responses, then sane defaults keyed by the script's purpose.
    """

    def __init__(self, responses=(), guid=GUID):
        self.scripts = []
        self.responses = list(responses)
        self.guid = guid

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            item = pswindows.PSResult(stdout=self.guid, returncode=0)
        elif self.responses:
            item = self.responses.pop(0)
        elif "final_state" in script:
            item = pswindows.PSResult(stdout='{"final_state": "Running"}', returncode=0)
        else:
            item = pswindows.PSResult(stdout="", returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def test_inventory_reports_vm_id(monkeypatch):
    """AC1: both inventory surfaces must emit the VM GUID (the .Id axis)."""
    cfg = Config(unrestricted=True)
    info_row = json.dumps({
        "name": "test-vm", "state": "Off", "status": "OK", "generation": 2,
        "memory_mb": 1024.0, "dynamic_memory": False, "cpu_count": 1,
        "uptime_seconds": 0.0, "checkpoint_count": 0,
        "com_ports": [], "network_adapters": [], "hard_drives": [],
    })
    fake = FakePS([pswindows.PSResult(stdout=info_row, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.get_vm_info(cfg, "test-vm")
    scripts = {
        "list_vms": lifecycle._LIST_VM_SCRIPT,
        "get_vm_info": fake.scripts[-1],
    }
    without_id = sorted(name for name, script in scripts.items() if ".Id" not in script)
    assert without_id == []


def test_lock_follows_guid_across_rename(monkeypatch, unrestricted_cfg):
    """AC2: the per-VM lock keys on the resolved GUID, so one VM under two
    name spellings (a rename mid-flight) still excludes a second operation."""
    entered = threading.Event()
    release = threading.Event()
    stats = {"action_legs": 0}
    fake = FakePS()

    def blocking_run_ps(script, **kwargs):
        if not _is_resolution_leg(script) and "final_state" not in script:
            stats["action_legs"] += 1
            if stats["action_legs"] == 1:
                entered.set()
                if not release.wait(timeout=30):
                    raise AssertionError("start_vm action leg was never released")
        return fake(script, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", blocking_run_ps)
    outcome = {}

    def hold_start_vm():
        try:
            lifecycle.start_vm(unrestricted_cfg, "test-vm")
        except BaseException as exc:  # noqa: BLE001 - recorded, asserted below
            outcome["error"] = exc

    worker = threading.Thread(target=hold_start_vm)
    worker.start()
    try:
        assert entered.wait(timeout=30), "start_vm never reached its in-flight action leg"
        with pytest.raises(VMBusy):
            lifecycle.checkpoint_create(unrestricted_cfg, "test-vm-renamed", "ac2-lock-probe")
    finally:
        release.set()
        worker.join(timeout=30)
    assert not worker.is_alive()
    assert "error" not in outcome


def test_vm_create_refuses_existing_name(monkeypatch, tmp_path, unrestricted_cfg):
    """AC3: vm_create must look for an existing VM with the target name
    BEFORE creating anything, so a same-name VM can never be shadowed."""
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    vhd = tmp_path / "ac3-disk.vhdx"
    media.vm_create(
        unrestricted_cfg, "test-vm", vhd_path=str(vhd), vhd_size_gb=1, confirm=True
    )
    script = next(s for s in fake.scripts if "New-VM" in s)
    assert 0 <= script.find("Msvm_ComputerSystem") < script.find("New-VM")


def test_ambiguity_error_lists_candidate_guids():
    """AC4: the not-unique resolution failure must name the candidate GUIDs
    so the operator can disambiguate by id."""
    resolver = guestexec.psdirect_vm_target("any-vm")
    line = next(cand for cand in resolver.splitlines() if "not unique" in cand)
    assert "$vmCandidates" in line


def test_every_vm_tool_accepts_vm_id(fresh_server):
    """AC5: every tool that addresses a VM by name also accepts vm_id, with
    exactly one of vm_name/vm_id required (neither is schema-required)."""
    mod = fresh_server({})
    tools = asyncio.run(mod.get_mcp().list_tools())
    schemas = {t.name: t.inputSchema for t in tools}
    missing = sorted(
        name
        for name, schema in schemas.items()
        if "vm_name" in schema.get("properties", {})
        and "vm_id" not in schema.get("properties", {})
    )
    assert missing == []
    for name, schema in schemas.items():
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if "vm_name" in props and "vm_id" in props:
            assert "vm_name" not in required, f"{name}: vm_name must be optional"
            assert not ("vm_name" in required and "vm_id" in required), (
                f"{name}: must not require both vm_name and vm_id"
            )


def test_vm_id_policy_runs_on_resolved_name(tmp_path, monkeypatch, fresh_server):
    """AC6: addressing by vm_id resolves the VM name first, so the VM policy
    still gates the resolved name — an id pointing at a prod-named VM is
    denied before any mutating PowerShell runs."""
    doc = {"allowed_vm_patterns": ["test-*"]}
    cfg_file = tmp_path / "ac6-config.json"
    cfg_file.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_file)})

    scripts = []

    def fake_run_ps(script, **kwargs):
        scripts.append(script)
        if PROD_ID in script:
            return pswindows.PSResult(stdout="prod-db", returncode=0)
        return pswindows.PSResult(stdout=GUID, returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)

    try:
        result = asyncio.run(mod.get_mcp()._tool_manager.call_tool(
            "hyperv_start_vm", {"vm_id": PROD_ID}, context=None))
    except Exception as exc:  # noqa: BLE001 - the outcome IS the assertion input
        outcome = "raised: " + str(exc)[:120]
    else:
        if isinstance(result, dict):
            outcome = result.get("error_class", "")
        elif hasattr(result, "content"):  # issue #9: failures deliver as CallToolResult
            import json as _json
            texts = [c for c in result.content if getattr(c, "type", "") == "text"]
            outcome = _json.loads(texts[0].text).get("error_class", "") if texts else ""
        else:
            outcome = repr(result)[:120]
    mutating = ("Start-VM", "Stop-VM", "Invoke-Command", "New-VM")
    mutating_scripts = [
        index for index, script in enumerate(scripts)
        if any(token in script for token in mutating)
    ]
    assert (outcome, mutating_scripts) == ("policy", [])
