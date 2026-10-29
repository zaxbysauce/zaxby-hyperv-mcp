"""Issue #23 acceptance checks (trace issue-23-leases, class E-02):
cross-agent VM leases — tool-surface and cross-process legs.

ACs carried (01-issue-summary.md):
  AC1  test_vm_lock_excludes_across_processes_sharing_state_db  (DISCRIMINATING)
  AC2  test_unknown_lease_rejected_before_mutation              (DISCRIMINATING)
  AC3  test_mutating_tools_accept_lease_arguments               (DISCRIMINATING)
  AC12 test_vm_lock_excludes_same_vm                            (PRESERVING)
  AC13 test_vm_lock_released_after_error                        (PRESERVING)
  AC14 test_destructive_tools_have_confirm_param                (PRESERVING)

RED at base c1da890, GREEN after the fix: AC1, AC2, AC3.
  AC1: the per-VM lock is a module-dict entry, so a second PROCESS sharing
       the same state DB is never excluded — DID NOT RAISE VMBusy.
  AC2: lease_id/fencing_token are unknown arguments, so the call is rejected
       as error_class "invalid" instead of "lease_unknown".
  AC3: none of the mutating tools declare lease_id/fencing_token yet.

GREEN at base and must STAY green (PRESERVING): AC12, AC13, AC14 — the
in-process vm_lock semantics and the destructive-confirm surface the lease
work builds on, re-declared here so this file is self-contained.

What is faked: every PowerShell leg (pswindows.run_ps answers by-name VM
resolution legs with a stable per-name GUID, plus benign start/state JSON);
nothing fake touches the cross-process child — that is a real spawned
interpreter (tests/unit/_e02_lease_child.py) holding vmlocks.vm_lock against
the shared HYPERV_MCP_STATE_DB.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows
from hyperv_mcp.vmlocks import VMBusy, vm_lock

_CHILD = Path(__file__).resolve().parent / "_e02_lease_child.py"
_SRC = Path(__file__).resolve().parents[2] / "src"

# The 40 mutating tools that must grow lease_id + fencing_token (AC3).
# RECONCILIATION (recorded in the trace): the issue text says 34 tools; the
# four enumerated categories (lifecycle / guest_exec / transfer / console)
# against the 57-tool surface of the day yielded 36 — the enumerated set
# below IS the contract. Issue #29 added the four lease-gated console-scope
# UI tools (invoke/set_value/focus/helper_provision), bringing the surface
# to 76 tools and this list to 40.
LEASED_TOOLS = [
    # lifecycle (17)
    "hyperv_start_vm",
    "hyperv_stop_vm",
    "hyperv_reset_vm",
    "hyperv_checkpoint_create",
    "hyperv_checkpoint_restore",
    "hyperv_checkpoint_remove",
    "hyperv_configure_kdnet",
    "hyperv_configure_kdcom",
    "hyperv_vm_create",
    "hyperv_vm_disk_add",
    "hyperv_vm_media_attach",
    "hyperv_vm_media_detach",
    "hyperv_vm_network_set",
    "hyperv_vm_firmware_set_boot_order",
    "hyperv_vm_tpm_set",
    "hyperv_vm_secureboot_set",
    "hyperv_vm_set_resolution",
    # guest_exec (9)
    "hyperv_guest_run_ps",
    "hyperv_guest_run",
    "hyperv_victim_run",
    "hyperv_victim_run_ps",
    "hyperv_guest_job_start",
    "hyperv_guest_job_stop",
    "hyperv_relay_start",
    "hyperv_relay_stop",
    "hyperv_repair_guest_access",
    # transfer (2)
    "hyperv_guest_put",
    "hyperv_guest_get",
    # console (8)
    "hyperv_console_type_text",
    "hyperv_console_press_key",
    "hyperv_console_key_combo",
    "hyperv_console_type_scancodes",
    "hyperv_console_mouse_move",
    "hyperv_console_click",
    "hyperv_console_button",
    "hyperv_console_scroll",
    # console-scope UIA mutation (4, issue #29)
    "hyperv_ui_invoke",
    "hyperv_ui_set_value",
    "hyperv_ui_focus",
    "hyperv_ui_helper_provision",
]

# The 17 destructive tools whose `confirm` gate must survive the lease work
# (AC14, PRESERVING — pinned at base c1da890 as 16; issue #29's
# hyperv_ui_helper_provision is the 17th and only later confirm carrier).
CONFIRM_TOOLS = [
    "hyperv_stop_vm",
    "hyperv_reset_vm",
    "hyperv_checkpoint_restore",
    "hyperv_checkpoint_remove",
    "hyperv_configure_kdnet",
    "hyperv_configure_kdcom",
    "hyperv_guest_run",
    "hyperv_guest_run_ps",
    "hyperv_guest_put",
    "hyperv_vm_create",
    "hyperv_vm_disk_add",
    "hyperv_vm_firmware_set_boot_order",
    "hyperv_vm_tpm_set",
    "hyperv_vm_secureboot_set",
    "hyperv_vm_set_resolution",
    "hyperv_repair_guest_access",
    "hyperv_ui_helper_provision",
]


@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def _schema_of(tool) -> dict:
    schema = getattr(tool, "inputSchema", None)
    if schema is None:
        schema = getattr(tool, "input_schema", None)  # mcp 2.x field name
    return schema or {}


def _envelope_from(result, label: str) -> dict:
    """Parse the first text block of a call_tool result into the envelope."""
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {label}"
    return json.loads(texts[0].text)


class FakePS:
    """Record every run_ps script and answer the legs hyperv_start_vm runs:
    by-name resolution -> stable per-name GUID; the start leg and the state
    wait leg -> benign JSON. The recording is the oracle: the checks assert
    on WHICH legs ran (never Start-VM under a refused lease)."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(
                stdout=str(uuid.uuid5(uuid.NAMESPACE_OID, "test-vm")), returncode=0
            )
        if "final_state" in script:
            return pswindows.PSResult(stdout='{"final_state": "Running"}', returncode=0)
        if "Start-VM" in script:
            return pswindows.PSResult(stdout='{"initial_state": "Off"}', returncode=0)
        return pswindows.PSResult(stdout="{}", returncode=0)


# ---------------------------------------------------------------------------
# AC1 — cross-process exclusion through the shared state DB (DISCRIMINATING)
# ---------------------------------------------------------------------------


def test_vm_lock_excludes_across_processes_sharing_state_db(tmp_path, fresh_server):
    """AC1: while ANOTHER PROCESS holds vm_lock(vm_id) against the shared
    HYPERV_MCP_STATE_DB, this process's vm_lock(vm_id) must raise VMBusy.

    RED at base: the lock is a module-dict entry, so the other process is
    invisible and the acquire succeeds — the assert below fails with the
    DID-NOT-RAISE signature."""
    vm_id = "e02-ac-one-cross-process-vm"
    db = tmp_path / "state.db"  # conftest already points THIS process here
    ready = tmp_path / "child-holds-lock.txt"
    env = dict(
        os.environ,
        **{
            "HYPERV_MCP_UNRESTRICTED": "1",
            "HYPERV_MCP_STATE_DB": str(db),
            "PYTHONPATH": str(_SRC),
        },
    )
    child = subprocess.Popen(
        [sys.executable, str(_CHILD), vm_id, str(ready)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 20.0
        while not ready.exists() and time.monotonic() < deadline:
            if child.poll() is not None:
                _out, err = child.communicate(timeout=10)
                pytest.fail(
                    "AC1: the lock-holder child died before signaling "
                    f"readiness (rc={child.returncode}); stderr tail: "
                    f"{err.decode('utf-8', 'replace')[-2000:]}"
                )
            time.sleep(0.1)
        assert ready.exists(), (
            "AC1: the lock-holder child never signaled readiness within 20s"
        )

        # Bootstrap THIS process against the same state DB the child holds
        # the lock through, then try to take the same VM's lock.
        fresh_server(
            {"HYPERV_MCP_UNRESTRICTED": "1", "HYPERV_MCP_STATE_DB": str(db)}
        )
        blocked = False
        try:
            # wait_s=0 fails fast instead of parking on the default bounded
            # wait: the AC signature is whether cross-process contention is
            # VISIBLE at all, not how long the waiter parks on it.
            with vm_lock(vm_id, wait_s=0):
                pass
        except VMBusy:
            blocked = True
        assert blocked, (
            "AC1: DID NOT RAISE VMBusy — this process's vm_lock admitted a VM "
            "another PROCESS holds through the shared HYPERV_MCP_STATE_DB, so "
            "the per-VM lock is still process-local"
        )
    finally:
        child.kill()
        try:
            child.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - kill refused
            child.kill()


# ---------------------------------------------------------------------------
# AC2 — an unknown lease_id is refused BEFORE any mutation (DISCRIMINATING)
# ---------------------------------------------------------------------------


def test_unknown_lease_rejected_before_mutation(tmp_path, fresh_server, monkeypatch):
    """AC2: a mutating call citing a lease_id that does not exist must fail
    with error_class "lease_unknown" and never run the mutation.

    RED at base: lease_id/fencing_token are unknown arguments, so the call is
    rejected as error_class "invalid" instead — the error_class assert fires
    FIRST so the base log carries the AC2 signature rather than a bare
    AssertionError about scripts."""
    doc = {"allowed_vm_patterns": ["test-*"]}
    p = tmp_path / "ac2-config.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)

    result = asyncio.run(
        mod.get_mcp().call_tool(
            "hyperv_start_vm",
            {"vm_name": "test-vm", "lease_id": "lease-does-not-exist", "fencing_token": 1},
        )
    )
    env = _envelope_from(result, "hyperv_start_vm")
    assert env.get("error_class") == "lease_unknown", (
        "AC2: a mutating call citing an unknown lease_id must be refused with "
        f"error_class 'lease_unknown'; got {env.get('error_class')!r} "
        f"(envelope: {json.dumps(env)[:400]})"
    )
    assert not any("Start-VM" in s for s in fake.scripts), (
        "AC2: PowerShell ran a mutation under an unknown lease: "
        f"{[s[:80] for s in fake.scripts]}"
    )


# ---------------------------------------------------------------------------
# AC3 — the 36 mutating tools take lease arguments (DISCRIMINATING)
# ---------------------------------------------------------------------------


def test_mutating_tools_accept_lease_arguments(fresh_server):
    """AC3: every one of the 40 enumerated mutating tools must declare
    lease_id and fencing_token, and NO tool may take a caller-identity
    parameter (agent identity comes from auth, never from arguments).

    RED at base: all 36 pre-UI tools are missing both arguments (reported
    in one list)."""
    mod = fresh_server({})
    tools = asyncio.run(mod.get_mcp().list_tools())
    schemas = {t.name: _schema_of(t) for t in tools}

    missing = sorted(
        name
        for name in LEASED_TOOLS
        if not {"lease_id", "fencing_token"}
        <= set(schemas.get(name, {}).get("properties", {}))
    )
    assert not missing, (
        f"AC3: {len(missing)} of the {len(LEASED_TOOLS)} enumerated mutating "
        f"tools do not declare lease_id + fencing_token: {missing}"
    )

    identity_params = {"agent_id", "agent", "identity", "client_id", "owner"}
    offenders = sorted(
        name
        for name, schema in schemas.items()
        if identity_params & set(schema.get("properties", {}))
    )
    assert not offenders, (
        f"AC3: tools must not declare caller-identity parameters: {offenders}"
    )


# ---------------------------------------------------------------------------
# AC12 / AC13 / AC14 — PRESERVING (green at base, re-declared from
# tests/unit/test_ops.py so this check file is self-contained)
# ---------------------------------------------------------------------------


def test_vm_lock_excludes_same_vm():
    """AC12 (preserving): within one process, a second holder of the same VM
    key fails with VMBusy."""
    with vm_lock("e02-ac12-vm"):
        with pytest.raises(VMBusy, match="already running"):
            with vm_lock("e02-ac12-vm"):
                pass


def test_vm_lock_released_after_error():
    """AC13 (preserving): an exception inside the lock releases it."""
    with pytest.raises(RuntimeError):
        with vm_lock("e02-ac13-vm"):
            raise RuntimeError("boom")
    with vm_lock("e02-ac13-vm"):
        pass


def test_destructive_tools_have_confirm_param(fresh_server):
    """AC14 (preserving): the 17 destructive tools still gate on confirm
    (16 pinned at base; issue #29's hyperv_ui_helper_provision joined)."""
    mod = fresh_server({})
    schemas = {t.name: _schema_of(t) for t in asyncio.run(mod.get_mcp().list_tools())}
    missing = sorted(
        name
        for name in CONFIRM_TOOLS
        if "confirm" not in schemas.get(name, {}).get("properties", {})
    )
    assert not missing, (
        f"AC14: destructive tools lost their confirm parameter: {missing}"
    )
