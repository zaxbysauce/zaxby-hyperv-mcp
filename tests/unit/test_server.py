"""Server-level tests: tool schemas per credential mode, entry points."""

import asyncio
import importlib
import json

import pytest

import hyperv_mcp.server as server_module

CRED_TOOLS = {
    "hyperv_configure_kdnet", "hyperv_configure_kdcom",
    "hyperv_guest_run", "hyperv_guest_run_ps",
    "hyperv_guest_put", "hyperv_guest_get",
    "hyperv_guest_read_file", "hyperv_guest_list_dir",
}
TOOL_NAMES = {
    "hyperv_list_vms", "hyperv_get_vm_info", "hyperv_start_vm", "hyperv_stop_vm",
    "hyperv_reset_vm", "hyperv_checkpoint_create", "hyperv_checkpoint_list",
    "hyperv_checkpoint_restore", "hyperv_checkpoint_remove",
    "hyperv_configure_kdnet", "hyperv_configure_kdcom",
    "hyperv_guest_run", "hyperv_guest_run_ps", "hyperv_guest_put",
    "hyperv_guest_get", "hyperv_guest_read_file", "hyperv_guest_list_dir",
    "hyperv_victim_run", "hyperv_victim_run_ps",
    # console (WMI screenshot / keyboard / mouse)
    "hyperv_console_screenshot", "hyperv_console_get_display_info",
    "hyperv_console_type_text", "hyperv_console_press_key",
    "hyperv_console_key_combo", "hyperv_console_type_scancodes",
    "hyperv_console_mouse_move", "hyperv_console_click",
    "hyperv_console_button", "hyperv_console_scroll",
    "hyperv_console_wait_frame_change", "hyperv_console_capture_sequence",
    # VM / media preparation
    "hyperv_vm_create", "hyperv_vm_disk_add", "hyperv_vm_disk_list",
    "hyperv_vm_media_attach", "hyperv_vm_media_detach", "hyperv_vm_media_list",
    "hyperv_vm_firmware_get", "hyperv_vm_firmware_set_boot_order",
    "hyperv_vm_tpm_set", "hyperv_vm_secureboot_set", "hyperv_vm_network_set",
    # orchestration
    "hyperv_wait_vm_state",
}
CONFIRM_TOOLS = {
    "hyperv_stop_vm", "hyperv_reset_vm", "hyperv_checkpoint_restore",
    "hyperv_checkpoint_remove", "hyperv_configure_kdnet",
    "hyperv_configure_kdcom", "hyperv_guest_run_ps", "hyperv_guest_run",
    "hyperv_guest_put",
    "hyperv_vm_create", "hyperv_vm_disk_add",
    "hyperv_vm_firmware_set_boot_order", "hyperv_vm_tpm_set",
    "hyperv_vm_secureboot_set",
}


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod
    yield make
    importlib.reload(server_module)


def _schemas(mod):
    mcp = mod.get_mcp()
    tools = asyncio.run(mcp.list_tools())
    return {t.name: t.inputSchema for t in tools}


def test_43_tools_registered(fresh_server):
    mod = fresh_server({})
    schemas = _schemas(mod)
    assert set(schemas) == TOOL_NAMES
    assert len(schemas) == 43


def test_no_password_params_by_default(fresh_server):
    """F4 regression: username/password must be absent from tool schemas."""
    mod = fresh_server({})
    for name, schema in _schemas(mod).items():
        props = schema.get("properties", {})
        assert "username" not in props, name
        assert "password" not in props, name


def test_inline_credential_mode_exposes_params(tmp_path, fresh_server):
    doc = {"allow_inline_credentials": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    schemas = _schemas(mod)
    for name in CRED_TOOLS:
        props = schemas[name].get("properties", {})
        assert "username" in props, name
        assert "password" in props, name
    # non-cred tools never gain them
    props = schemas["hyperv_list_vms"].get("properties", {})
    assert "password" not in props


def test_destructive_tools_have_confirm_param(fresh_server):
    mod = fresh_server({})
    schemas = _schemas(mod)
    confirmed = {n for n, sch in schemas.items() if "confirm" in sch.get("properties", {})}
    assert confirmed == CONFIRM_TOOLS, (
        f"confirm-param set drifted: extra={confirmed - CONFIRM_TOOLS}, missing={CONFIRM_TOOLS - confirmed}"
    )


def test_interactive_tools_have_no_confirm_param(fresh_server):
    """Console input + reversible media ops must NOT force a human prompt."""
    mod = fresh_server({})
    for name in ("hyperv_console_type_text", "hyperv_console_press_key",
                 "hyperv_console_mouse_move", "hyperv_console_click",
                 "hyperv_vm_media_attach", "hyperv_vm_media_detach",
                 "hyperv_vm_network_set"):
        props = _schemas(mod)[name].get("properties", {})
        assert "confirm" not in props, name


def test_mdt_config_still_loads(tmp_path, fresh_server):
    """The user's existing 7-category config (schema_version 1) must keep
    loading unchanged after the additive category extension."""
    doc = {
        "schema_version": 1,
        "allowed_vm_patterns": ["Deployment Test", "Deployment Test 2"],
        "guest_read_roots": ["C:\\", "D:\\"],
        "destructive": {
            "stop": True, "reset": True, "checkpoint_restore": True,
            "checkpoint_remove": True, "kd_reboot": True,
            "elevated_exec": True, "guest_write": True,
            "require_confirm": True,
        },
        "allow_inline_credentials": False,
    }
    p = tmp_path / "hyperv-mcp-mdt.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    cfg = mod.CFG
    assert cfg.destructive.stop is True
    assert cfg.destructive.console_input is False  # new fields default safely
    assert cfg.destructive.media is False
    assert cfg.destructive.vm_provision is False


def test_mdt_config_with_new_categories(tmp_path, fresh_server):
    doc = {
        "schema_version": 1,
        "allowed_vm_patterns": ["Deployment Test", "Deployment Test 2", "ZAC"],
        "destructive": {
            "console_input": True, "media": True, "vm_provision": True,
            "require_confirm": True,
        },
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    assert mod.CFG.destructive.console_input is True


def test_check_env_exit_zero(fresh_server, capsys):
    mod = fresh_server({})
    rc = mod.main(["--check-env"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "hyperv-mcp 0.2.0" in out
    assert "DENY ALL" in out


def test_check_env_config_error_exit_two(tmp_path, monkeypatch, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{broken", encoding="utf-8")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(p))
    mod = importlib.reload(server_module)
    rc = mod.main(["--check-env"])
    assert rc == 2
    assert "CONFIG ERROR" in capsys.readouterr().err
    importlib.reload(server_module)


def test_version_flag(fresh_server, capsys):
    mod = fresh_server({})
    with pytest.raises(SystemExit) as exc:
        mod.main(["--version"])
    assert exc.value.code == 0
    assert "0.2.0" in capsys.readouterr().out


def test_mcp_compat_import_bootstraps(fresh_server):
    mod = fresh_server({})
    # PEP 562 module getattr used by `from hyperv_mcp.server import mcp`
    mcp = mod.mcp
    assert mcp is mod.get_mcp()


def test_unknown_attr_raises(fresh_server):
    mod = fresh_server({})
    name = "mcp_does_not_exist"
    with pytest.raises(AttributeError):
        getattr(mod, name)  # exercises PEP 562 module __getattr__


def test_state_enum_single_source():
    """Review PRR-020 pin: the Hyper-V state enum lives only in lifecycle.py;
    server.py validates against lifecycle.VALID_STATES and console's dead
    duplicate is gone."""
    from hyperv_mcp import console, lifecycle

    assert lifecycle.VALID_STATES == (
        "Off", "Running", "Saved", "Paused", "Starting", "Stopping", "Resuming", "Pausing",
    )
    assert lifecycle._VALID_STATES is lifecycle.VALID_STATES
    assert not hasattr(console, "_STATE_ENUM")
