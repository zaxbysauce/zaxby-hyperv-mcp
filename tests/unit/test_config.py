"""Config schema tests: secure defaults, strict parsing, failure modes."""

import json

import pytest

from hyperv_mcp.config import Config, ConfigError


def test_defaults_deny_every_axis():
    cfg = Config()
    assert cfg.allowed_vm_patterns == []
    assert cfg.host_read_roots == []
    assert not cfg.unrestricted
    assert not cfg.destructive.stop
    assert not cfg.destructive.reset
    assert not cfg.destructive.checkpoint_restore
    assert not cfg.destructive.checkpoint_remove
    assert not cfg.destructive.kd_reboot
    assert not cfg.destructive.elevated_exec
    assert not cfg.destructive.guest_write
    assert not cfg.destructive.console_input
    assert not cfg.destructive.media
    assert not cfg.destructive.vm_provision
    assert cfg.destructive.require_confirm
    assert not cfg.allow_inline_credentials


def test_no_config_file_loads_deny_all():
    cfg = Config.load(environ={})
    assert not cfg.unrestricted
    assert cfg.allowed_vm_patterns == []


def test_missing_config_file_is_defaults():
    cfg = Config.load(environ={"HYPERV_MCP_CONFIG": r"Z:\definitely\missing.json"})
    assert cfg.allowed_vm_patterns == []


def test_malformed_config_aborts(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        Config.load(environ={"HYPERV_MCP_CONFIG": str(bad)})


def test_unreadable_config_aborts(tmp_path):
    # A directory in place of the file raises PermissionError, not FileNotFoundError.
    with pytest.raises(ConfigError, match="unreadable"):
        Config.load(environ={"HYPERV_MCP_CONFIG": str(tmp_path)})


def test_unknown_keys_rejected():
    with pytest.raises(ConfigError, match="unknown config key"):
        Config.from_dict({"allowed_vm_paturns": ["*"]})


def test_wrong_type_rejected():
    with pytest.raises(ConfigError):
        Config.from_dict({"allowed_vm_patterns": "not-a-list"})
    with pytest.raises(ConfigError):
        Config.from_dict({"allow_inline_credentials": "yes"})
    with pytest.raises(ConfigError):
        Config.from_dict({"max_output_bytes": True})


def test_destructive_subdict_validated():
    cfg = Config.from_dict({"destructive": {"stop": True}})
    assert cfg.destructive.stop
    with pytest.raises(ConfigError, match="unknown destructive"):
        Config.from_dict({"destructive": {"nuke": True}})
    with pytest.raises(ConfigError):
        Config.from_dict({"destructive": {"stop": "yes"}})


def test_unrestricted_env_opt_in():
    cfg = Config.load(environ={"HYPERV_MCP_UNRESTRICTED": "1"})
    assert cfg.unrestricted
    cfg2 = Config.load(environ={"HYPERV_MCP_UNRESTRICTED": "0"})
    assert not cfg2.unrestricted


def test_full_config_file(tmp_path):
    doc = {
        "schema_version": 1,
        "allowed_vm_patterns": ["test-vm-*"],
        "host_write_roots": ["C:\\lab\\out"],
        "destructive": {"stop": True, "require_confirm": False},
        "verify_sha256": True,
    }
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    cfg = Config.load(environ={"HYPERV_MCP_CONFIG": str(p)})
    assert cfg.allowed_vm_patterns == ["test-vm-*"]
    assert cfg.destructive.stop and not cfg.destructive.reset
    assert cfg.verify_sha256


def test_wrong_schema_version_rejected(tmp_path):
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
    with pytest.raises(ConfigError, match="schema_version"):
        Config.load(environ={"HYPERV_MCP_CONFIG": str(p)})


def test_configured_axes_reporting():
    unrestricted = Config(unrestricted=True)
    assert set(unrestricted.configured_axes()) == {"vm", "host_read", "host_write", "guest_read", "guest_write"}
    restrictive = Config(allowed_vm_patterns=["*"], host_read_roots=["C:\\r"])
    assert set(restrictive.configured_axes()) == {"vm", "host_read"}
    assert Config().configured_axes() == []


def test_policy_summary_mentions_deny_all():
    assert "DENY ALL" in Config().policy_summary()


def test_empty_string_root_rejected():
    with pytest.raises(ConfigError):
        Config.from_dict({"host_read_roots": ["  "]})


def test_ps_bounds_validated():
    with pytest.raises(ConfigError):
        Config.from_dict({"max_output_bytes": 10})
    with pytest.raises(ConfigError):
        Config.from_dict({"ps_timeout_s": 1})
