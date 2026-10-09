"""AC1 acceptance checks: the optional top-level "hyperv" config section.

Contract (remote Hyper-V host mode):
  * {"hyperv": {"host": "nuc01"}} parses via Config.from_dict and the host is
    readable on the resulting Config (remote mode).
  * An empty host string is rejected with ConfigError.
  * Unknown keys inside "hyperv" are rejected with ConfigError (house style:
    config.py raises, typos never silently disable a control).
  * An absent section leaves a default local-mode value: hyperv host None.
  * The section is additive: schema_version stays 1.

Every check here is RED on a tree without the feature: from_dict rejects the
unknown "hyperv" key outright, and Config() has no hyperv attribute at all.
"""

import json

import pytest

from hyperv_mcp.config import Config, ConfigError


def test_hyperv_host_section_round_trips():
    """{"hyperv": {"host": "nuc01"}} loads and the field is readable."""
    cfg = Config.from_dict({"hyperv": {"host": "nuc01"}})
    assert cfg.hyperv.host == "nuc01"


def test_hyperv_host_section_via_load(tmp_path):
    """The section works through the JSON-file load path (schema stays 1)."""
    p = tmp_path / "remote.json"
    p.write_text(
        json.dumps({"schema_version": 1, "hyperv": {"host": "nuc01"}}),
        encoding="utf-8",
    )
    cfg = Config.load(environ={"HYPERV_MCP_CONFIG": str(p)})
    assert cfg.hyperv.host == "nuc01"


def test_hyperv_empty_host_rejected():
    """host must be a non-empty string (the wrap targets a real hostname)."""
    with pytest.raises(ConfigError, match="non-empty"):
        Config.from_dict({"hyperv": {"host": ""}})


def test_hyperv_unknown_key_rejected():
    """Unknown keys inside the section are rejected, naming the offender."""
    with pytest.raises(ConfigError, match="typo"):
        Config.from_dict({"hyperv": {"typo": 1}})


def test_absent_section_defaults_to_local_mode():
    """No "hyperv" section => hyperv host is None => local mode (today's
    behavior, byte for byte)."""
    cfg = Config()
    assert cfg.hyperv.host is None
    cfg2 = Config.from_dict({"allowed_vm_patterns": ["test-*"]})
    assert cfg2.hyperv.host is None
