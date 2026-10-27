"""Acceptance checks for issue #16, part 4 — the preserved tool surface.

AC10 (credential error envelope at the tool layer), AC11 (screenshot returns
a real PNG ImageContent block plus metadata), AC12 (same 57-tool inventory
with the same parameters per credential mode). Sibling c03 files:
test_c03_tool_concurrency.py (AC1-AC5), test_c03_sdk_port.py (AC7-AC9),
test_c03_http_entry.py (AC6, AC13).

Every check passes at the pre-fix base and must keep passing after the
SDK-generation port. SDK shapes are read defensively
(`inputSchema`/`input_schema`, `mimeType`/`mime_type`) so the same assertion
holds on both generations.
"""

import asyncio
import base64
import importlib
import io
import json

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows
from hyperv_mcp.pswindows import PSResult

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

# The live 57-tool inventory pinned at authoring time (issue #35 added
# hyperv_server_info on top of the issue text's stale count of 54).
TOOL_NAMES = {
    "hyperv_list_vms",
    "hyperv_get_vm_info",
    "hyperv_start_vm",
    "hyperv_stop_vm",
    "hyperv_reset_vm",
    "hyperv_checkpoint_create",
    "hyperv_checkpoint_list",
    "hyperv_checkpoint_restore",
    "hyperv_checkpoint_remove",
    "hyperv_configure_kdnet",
    "hyperv_configure_kdcom",
    "hyperv_guest_run",
    "hyperv_guest_run_ps",
    "hyperv_guest_put",
    "hyperv_guest_get",
    "hyperv_guest_read_file",
    "hyperv_guest_list_dir",
    "hyperv_victim_run",
    "hyperv_victim_run_ps",
    "hyperv_console_screenshot",
    "hyperv_console_get_display_info",
    "hyperv_console_type_text",
    "hyperv_console_press_key",
    "hyperv_console_key_combo",
    "hyperv_console_type_scancodes",
    "hyperv_console_mouse_move",
    "hyperv_console_click",
    "hyperv_console_button",
    "hyperv_console_scroll",
    "hyperv_console_wait_frame_change",
    "hyperv_console_wait_frame_stable",
    "hyperv_console_capture_sequence",
    "hyperv_console_sequence",
    "hyperv_vm_create",
    "hyperv_vm_disk_add",
    "hyperv_vm_disk_list",
    "hyperv_vm_media_attach",
    "hyperv_vm_media_detach",
    "hyperv_vm_media_list",
    "hyperv_vm_firmware_get",
    "hyperv_vm_firmware_set_boot_order",
    "hyperv_vm_tpm_set",
    "hyperv_vm_secureboot_set",
    "hyperv_vm_network_set",
    "hyperv_vm_get_video",
    "hyperv_vm_set_resolution",
    "hyperv_wait_vm_state",
    "hyperv_server_info",
    "hyperv_diagnose_vm_access",
    "hyperv_repair_guest_access",
    "hyperv_guest_job_start",
    "hyperv_guest_job_status",
    "hyperv_guest_job_output",
    "hyperv_guest_job_stop",
    "hyperv_wait_guest_recovery",
    "hyperv_relay_start",
    "hyperv_relay_status",
    # issue #23: the lease surface
    "hyperv_lease_acquire", "hyperv_lease_renew",
    "hyperv_lease_release", "hyperv_lease_list",
    "hyperv_relay_stop",
    "hyperv_capture_evidence",
    # issue #24: the durable-operation / event-cursor surface
    "hyperv_op_status", "hyperv_op_result",
    "hyperv_op_cancel", "hyperv_op_list", "hyperv_events",
}
CRED_TOOLS = {
    "hyperv_configure_kdnet",
    "hyperv_configure_kdcom",
    "hyperv_guest_run",
    "hyperv_guest_run_ps",
    "hyperv_guest_put",
    "hyperv_guest_get",
    "hyperv_guest_read_file",
    "hyperv_guest_list_dir",
    "hyperv_diagnose_vm_access",
    "hyperv_repair_guest_access",
    "hyperv_guest_job_start",
    "hyperv_wait_guest_recovery",
    "hyperv_relay_start",
    "hyperv_capture_evidence",
}


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


class FakeScriptedPS:
    """Queue-ordered run_ps stand-in (test_image_content model)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return self.responses.pop(0)


def _schema_of(tool) -> dict:
    schema = getattr(tool, "inputSchema", None)
    if schema is None:
        schema = getattr(tool, "input_schema", None)  # mcp 2.x field name
    return schema or {}


def test_ac10_credential_error_envelope_at_tool_layer(tmp_path, fresh_server):
    """AC10: a guest credential error inside a registered guest tool called
    through call_tool still returns {ok: false, error_class: "credential"}."""
    from conftest import envelope_from_result

    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    result = asyncio.run(
        mod.get_mcp().call_tool(
            "hyperv_capture_evidence",
            {"vm_name": "test-vm", "ui_tree": True},
        )
    )
    envelope = envelope_from_result(result, "hyperv_capture_evidence")
    assert envelope["ok"] is False, f"AC10: envelope.ok is not False: {envelope!r}"
    assert envelope["error_class"] == "credential", (
        f"AC10: error_class {envelope.get('error_class')!r} != 'credential'"
    )


def test_ac11_screenshot_returns_image_content(monkeypatch, fresh_server):
    """AC11: the screenshot tool through call_tool returns a real PNG
    ImageContent block plus a metadata text block."""
    from mcp.types import ImageContent
    from PIL import Image as PILImage

    def _raw_thumbnail(w: int, h: int) -> bytes:
        pixels = bytearray()
        for y in range(h):
            for x in range(w):
                v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
                pixels.append(v & 0xFF)
                pixels.append((v >> 8) & 0xFF)
        return b"\x00\x00\x96\x04" + bytes(pixels)

    payload = _raw_thumbnail(320, 240)
    persona = json.dumps(
        {
            "returnValue": 0,
            "imageDataB64": base64.b64encode(payload).decode(),
        }
    )
    fake = FakeScriptedPS(
        [
            # one folded capture (issue #18): metadata ahead of the payload
            PSResult(
                stdout="VMID=" + GUID + "\n"
                + "HEAD=1024x768" + "\n" + "SIZES=320x240" + "\n"
                + "USED=320x240" + "\n" + persona,
                returncode=0,
            ),
        ]
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    result = asyncio.run(
        mod.get_mcp().call_tool(
            "hyperv_console_screenshot",
            {"vm_name": "test-vm-1", "width": 320, "height": 240},
        )
    )
    from conftest import content_blocks as _blocks

    content = _blocks(result)
    image_blocks = [c for c in content if getattr(c, "type", "") == "image"]
    assert image_blocks, f"AC11: no image content in {[type(c).__name__ for c in content]}"
    block = image_blocks[0]
    assert isinstance(block, ImageContent), (
        f"AC11: image block is {type(block).__name__}, expected ImageContent"
    )
    mime = getattr(block, "mimeType", None) or getattr(block, "mime_type", None)
    assert mime == "image/png", f"AC11: image block mime {mime!r} != 'image/png'"
    img = PILImage.open(io.BytesIO(base64.b64decode(block.data)))
    assert img.size == (320, 240), f"AC11: decoded image size {img.size} != (320, 240)"
    text_blocks = [c for c in content if getattr(c, "type", "") == "text"]
    assert text_blocks, "AC11: metadata text block missing"
    assert "e953c649" in text_blocks[0].text and "frame_hash" in text_blocks[0].text, (
        f"AC11: metadata block lacks vm_id/frame_hash: {text_blocks[0].text[:120]!r}"
    )


def test_ac12_tool_inventory_per_credential_mode(tmp_path, fresh_server):
    """AC12: tools listed register the same 57-name inventory with the same
    parameters per credential mode (inline mode only adds username/password
    to the credential tools)."""
    mod = fresh_server({})
    base_schemas = {t.name: _schema_of(t) for t in asyncio.run(mod.get_mcp().list_tools())}
    assert set(base_schemas) == TOOL_NAMES, (
        f"AC12: registered tool names drifted: "
        f"extra={sorted(set(base_schemas) - TOOL_NAMES)}, "
        f"missing={sorted(TOOL_NAMES - set(base_schemas))}"
    )
    assert len(base_schemas) == len(TOOL_NAMES) == 68, (
        f"AC12: tool count {len(base_schemas)} != 68 "
        f"(66 through issue #24; 67 with issue #27's settle wait; "
        f"68 with issue #28's hyperv_console_sequence)"
    )
    doc = {"allow_inline_credentials": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod2 = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    cred_schemas = {t.name: _schema_of(t) for t in asyncio.run(mod2.get_mcp().list_tools())}
    assert set(cred_schemas) == set(base_schemas), "AC12: names differ per mode"
    for name in sorted(base_schemas):
        base_props = set(base_schemas[name].get("properties", {}))
        cred_props = set(cred_schemas[name].get("properties", {}))
        expected_gain = {"username", "password"} if name in CRED_TOOLS else set()
        assert (cred_props - base_props, base_props - cred_props) == (
            expected_gain,
            set(),
        ), f"AC12: {name} parameter set drifted across credential modes"
