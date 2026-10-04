"""Config schema tests: secure defaults, strict parsing, failure modes."""

import hashlib
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
    assert not cfg.destructive.guest_repair
    assert not cfg.destructive.relay
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


# ---------------------------------------------------------------------------
# provenance fields (config_path / config_sha256) — ENH-16
# ---------------------------------------------------------------------------

def test_bom_prefixed_config_loads_with_real_digest(tmp_path):
    """F-008: a UTF-8 BOM is tolerated and config_sha256 covers the raw
    stored bytes (BOM included)."""
    p = tmp_path / "bom.json"
    p.write_text(json.dumps({"allowed_vm_patterns": ["bom-vm"]}), encoding="utf-8-sig")
    cfg = Config.load(environ={"HYPERV_MCP_CONFIG": str(p)})
    assert cfg.allowed_vm_patterns == ["bom-vm"]
    assert cfg.config_sha256 == hashlib.sha256(p.read_bytes()).hexdigest()
    assert cfg.config_path == str(p)


def test_load_digest_is_real_file_hash(tmp_path):
    """F-008/F-037: config_sha256 is the digest of the actual file bytes, so
    a mutation returning a constant default digest fails here."""
    p = tmp_path / "cfg.json"
    payload = b'{"verify_sha256": true}'
    p.write_bytes(payload)
    cfg = Config.load(environ={"HYPERV_MCP_CONFIG": str(p)})
    assert cfg.config_sha256 == hashlib.sha256(payload).hexdigest()
    assert cfg.config_path == str(p)


def test_missing_config_records_path_and_empty_digest():
    """F-026/F-029: the missing-file branch records the requested path and
    the documented sha256(b"") sentinel (config_path disambiguates)."""
    cfg = Config.load(environ={"HYPERV_MCP_CONFIG": r"Z:\definitely\missing.json"})
    assert cfg.config_path == r"Z:\definitely\missing.json"
    assert cfg.config_sha256 == hashlib.sha256(b"").hexdigest()


def test_no_config_records_empty_path_and_empty_digest():
    """F-029: the no-config bootstrap branch is pinned too."""
    cfg = Config.load(environ={})
    assert cfg.config_path == ""
    assert cfg.config_sha256 == hashlib.sha256(b"").hexdigest()


def test_json_cannot_set_provenance_fields():
    """F-043: config_path/config_sha256 stay out of _FIELD_MAP — JSON
    attempts are rejected as unknown keys so a config file cannot dictate the
    reported provenance."""
    with pytest.raises(ConfigError, match="unknown config key"):
        Config.from_dict({"config_sha256": "deadbeef"})
    with pytest.raises(ConfigError, match="unknown config key"):
        Config.from_dict({"config_path": r"C:\x.json"})


def test_padded_token_env_stored_trimmed():
    """F-017: padding around http.token_env must not defeat exact-name
    matching downstream (child_env strips by exact case-insensitive name)."""
    cfg = Config.from_dict({"http": {"token_env": "  HYPERV_MCP_HTTP_TOKEN  "}})
    assert cfg.http.token_env == "HYPERV_MCP_HTTP_TOKEN"


def test_token_env_reserved_names_rejected():
    """F-035: naming a functional variable as token_env would make child_env
    strip that variable from every spawned child — reject at load time."""
    with pytest.raises(ConfigError, match="token_env"):
        Config.from_dict({"http": {"token_env": "PATH"}})
    with pytest.raises(ConfigError, match="token_env"):
        Config.from_dict({"http": {"token_env": "SystemRoot"}})
    with pytest.raises(ConfigError, match="token_env"):
        Config.from_dict({"http": {"token_env": "PSModulePath"}})
