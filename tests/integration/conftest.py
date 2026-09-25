"""Fixtures for real-Hyper-V integration tests.

These tests drive a DISPOSABLE test VM through the real Hyper-V stack and
PowerShell Direct. They NEVER run accidentally:

  pytest tests/integration          # explicit invocation required

and they skip with an actionable reason unless ALL of the following hold:
  - HYPERV_MCP_INTEGRATION=1
  - HYPERV_MCP_TEST_VM names an existing disposable VM
  - guest credentials configured (HYPERV_GUEST_USERNAME + PASSWORD/FILE)

Every test module that uses the `it` fixture runs the empirical protocol:
record start state, checkpoint, exercise, restore. Credentials must come from
the environment; placeholder values are never baked into this repo.
"""

import os

import pytest

from hyperv_mcp.config import Config


def _integration_ready() -> tuple[bool, str]:
    if os.environ.get("HYPERV_MCP_INTEGRATION", "") != "1":
        return False, "HYPERV_MCP_INTEGRATION is not set to 1 (real Hyper-V tests stay skipped)"
    if not os.environ.get("HYPERV_MCP_TEST_VM", "").strip():
        return False, "HYPERV_MCP_TEST_VM is not set (name a disposable test VM)"
    have_creds = (
        os.environ.get("HYPERV_GUEST_USERNAME", "")
        and (
            os.environ.get("HYPERV_GUEST_PASSWORD", "")
            or os.environ.get("HYPERV_GUEST_PASSWORD_FILE", "")
        )
    )
    if not have_creds:
        return False, "guest credentials missing (HYPERV_GUEST_USERNAME + PASSWORD/FILE)"
    return True, ""


READY, SKIP_REASON = _integration_ready()

# Real restores can merge deep checkpoint subtrees (600s waits); the repo
# default pytest timeout (120s) kills them. Give every integration test 900s.
INTEGRATION_TIMEOUT_S = 900


def pytest_collection_modifyitems(config, items):
    """Skip the whole real-Hyper-V suite unless explicitly enabled, and give
    surviving tests a timeout that accommodates real checkpoint merges."""
    for item in items:
        item.add_marker(pytest.mark.timeout(INTEGRATION_TIMEOUT_S))
        if not READY:
            item.add_marker(pytest.mark.skip(reason=SKIP_REASON))


@pytest.fixture(scope="module")
def it_tmp(tmp_path_factory):
    return tmp_path_factory.mktemp("hyperv-it")


@pytest.fixture()
def cfg(it_tmp):
    """Unrestricted research config bound to the disposable test VM."""
    return Config(
        unrestricted=True,
        audit_log_path=str(it_tmp / "audit.jsonl"),
        verify_sha256=True,
    )


@pytest.fixture()
def it(cfg):
    """Bundle everything a real-Hyper-V test needs."""
    import hyperv_mcp.credentials as credentials
    from hyperv_mcp import auditlog, pswindows

    credentials.init(cfg)
    pswindows.init(cfg, credentials.redact)
    auditlog.init(cfg)
    return type(
        "IT",
        (),
        {
            "cfg": cfg,
            "vm": os.environ["HYPERV_MCP_TEST_VM"],
            "creds": credentials.resolve_guest(os.environ.get("HYPERV_GUEST_USERNAME", ""),
                                              os.environ.get("HYPERV_GUEST_PASSWORD", "")),
        },
    )()
