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


def test_19_tools_registered(fresh_server):
    mod = fresh_server({})
    schemas = _schemas(mod)
    assert set(schemas) == TOOL_NAMES
    assert len(schemas) == 19


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
    for name in ("hyperv_stop_vm", "hyperv_reset_vm", "hyperv_checkpoint_restore",
                 "hyperv_checkpoint_remove", "hyperv_configure_kdnet",
                 "hyperv_configure_kdcom", "hyperv_guest_run_ps"):
        props = _schemas(mod)[name].get("properties", {})
        assert "confirm" in props, name


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
