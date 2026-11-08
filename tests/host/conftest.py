"""Fixtures for the live-host VM-agent-isolation legs (issue #31 AC16).

These tests drive the cleanup-provider seam against REAL Hyper-V objects on
a disposable, self-minted lab. They never run accidentally:

  pytest tests/host            # explicit invocation required

and they skip with an actionable reason unless ALL of the following hold:
  - HYPERV_MCP_INTEGRATION=1
  - HYPERV_MCP_TEST_GOLDEN_VHD names an existing golden .vhdx the tests may
    clone from (mint one with New-VHD -Dynamic + Set-ItemProperty
    IsReadOnly $true; the tests restore the attribute on their golden-scoped
    paths only)

No guest credentials are required: the seam leg needs no guest OS.

The lab config is deliberately NOT unrestricted: VM names must match
host-iso-* and the golden/child disks must live under the golden's
directory (host_read_roots/host_write_roots). Provisioning, stopping,
and removal pass their destructive categories with confirm=True on every
call. Console input is NOT needed by these tests.

The scoping of this conftest's collection hook is pinned by
tests/unit/test_host_conftest_scope.py (the issue #115 pattern): only
items under tests/host receive these markers.
"""

import os
from pathlib import Path

import pytest

from hyperv_mcp.config import Config, DestructivePolicy


def _host_ready() -> tuple[bool, str]:
    if os.environ.get("HYPERV_MCP_INTEGRATION", "") != "1":
        return False, "HYPERV_MCP_INTEGRATION is not set to 1 (real Hyper-V tests stay skipped)"
    golden = os.environ.get("HYPERV_MCP_TEST_GOLDEN_VHD", "").strip()
    if not golden or not os.path.isfile(golden):
        return False, (
            "HYPERV_MCP_TEST_GOLDEN_VHD is not set to an existing read-only "
            "golden .vhdx (mint one with New-VHD -Dynamic + Set-ItemProperty "
            "IsReadOnly $true)")
    return True, ""


READY, SKIP_REASON = _host_ready()

# Real clone lifecycle legs can wait out boot and removal merges; the repo
# default pytest timeout (120s) kills them. Give every host test 900s.
HOST_TIMEOUT_S = 900


def pytest_collection_modifyitems(config, items):
    """Skip the real-host suite unless explicitly enabled, and give
    surviving tests a timeout that accommodates real boot/removal waits.
    Scoped by item path (issue #115 pattern): only items living under this
    conftest's directory are touched; unit items keep the repo's own
    timeout and run normally."""
    host_root = Path(__file__).resolve().parent
    for item in items:
        item_path = Path(str(getattr(item, "path", None) or item.fspath)).resolve()
        if not item_path.is_relative_to(host_root):
            continue
        item.add_marker(pytest.mark.timeout(HOST_TIMEOUT_S))
        if not READY:
            item.add_marker(pytest.mark.skip(reason=SKIP_REASON))


@pytest.fixture(scope="module")
def host_tmp(tmp_path_factory):
    return tmp_path_factory.mktemp("hyperv-host")


def _lab_config(golden: str, host_tmp: Path) -> Config:
    scratch = str(Path(golden).resolve().parent)
    return Config(
        allowed_vm_patterns=["host-iso-*"],
        host_read_roots=[scratch],
        host_write_roots=[scratch],
        audit_log_path=str(host_tmp / "audit.jsonl"),
        verify_sha256=True,
        destructive=DestructivePolicy(stop=True, vm_provision=True, vm_remove=True),
    )


@pytest.fixture()
def host(host_tmp):
    """Bundle the live-host leg needs: least-privilege lab config bound to
    the golden's scratch directory, initialized transports, the golden
    path, and the assertion-result record path (plan v3 transcript
    contract; markers come from OBSERVED assertions)."""
    import hyperv_mcp.credentials as credentials
    from hyperv_mcp import auditlog, pswindows

    golden = os.environ["HYPERV_MCP_TEST_GOLDEN_VHD"].strip()
    cfg = _lab_config(golden, host_tmp)
    credentials.init(cfg)
    pswindows.init(cfg, credentials.redact)
    auditlog.init(cfg)
    record = os.environ.get("HYPERV_MCP_HOST_RESULT_RECORD", "").strip()
    return type(
        "Host",
        (),
        {
            "cfg": cfg,
            "golden": golden,
            "scratch": str(Path(golden).resolve().parent),
            "record": record,
            "note": lambda self, line: _note(self.record, line),
        },
    )()


def _note(record: str, line: str) -> None:
    """Append one observed assertion-result line to the record file when
    the wave's transcript harness named one (no-op otherwise)."""
    if not record:
        return
    with open(record, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(f"assert: {line}\n")
