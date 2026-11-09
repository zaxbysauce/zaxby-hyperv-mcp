"""Fixtures for the live-host VM-agent-isolation legs (issue #31 AC16).

These tests drive the cleanup-provider seam against REAL Hyper-V objects on
a disposable, self-minted lab. They never run accidentally:

  pytest tests/host            # explicit invocation required

and they skip with an actionable reason unless ALL of the following hold:
  - HYPERV_MCP_INTEGRATION=1
  - HYPERV_MCP_TEST_GOLDEN_VHD names an existing READ-ONLY golden .vhdx the
    tests may clone from (mint a dedicated disposable one with
    `New-VHD -Path <scratch>/golden.vhdx -SizeBytes 1GB -Dynamic` then
    `Set-ItemProperty -LiteralPath <path> -Name IsReadOnly -Value $true`;
    see docs/validation/capability-plan/test_vm_agent_isolation_host-evidence.json
    for the recorded procedure)

Read-only matters: media.vm_clone locks a WRITABLE parent read-only and,
on success, deliberately keeps it locked (src/hyperv_mcp/media.py M8 note —
the attribute restore exists only on its failure path), and the digest
guard cannot observe a DOS-attribute change. A dedicated disposable golden
keeps that one-way lock harmless.

Timeout derivation: HOST_TIMEOUT_S (5700s) dominates the NAIVE
fully-bounded envelope (every listed leg at its cap, no redundant-wait
discount). Body per clone: vm_clone 315 + resolve legs 360 (5-6 resolves
x 60s on the real call graph) + start 75 + start's internal Running wait
105 + the test's Running re-wait 195 + turnoff 75 + stop's internal Off
wait 135 + the test's Off re-wait 195 + refusal remove 75 + clean remove
570 (resolve 60 + state gate 75 + removal 315 + usage audit 120; the
600s merge envelope has NO reachable share in this lab — a fresh clone
owns no checkpoint, so no .avhdx candidate ever exists) + absence probe
135 = 2235s; two clones = 4470s. Finally cleanup (failure path only; the
tracked list holds at most one entry sequentially): stop 75 + stop's
resolve/internal wait 135 + remove 570 + up to 3 absence probes 405 =
1185s. Body + one finally entry = 4470 + 1185 = 5655s < 5700s. (The
realistic path is far lower — start_vm's internal wait and the test's
re-wait cannot both max on a healthy state machine; observed 63s.)
NOTE: pytest-timeout's
thread method (this repo's timeout_method, the only one available on
Windows) kills via os._exit(1) — it does NOT run finally blocks — so a
test that times out despite this budget can still orphan its tracked
clones; the operator sweep for that residual is recorded in
docs/validation/live-host/vm-agent-isolation-lab-cleanup.md
(`Get-VM | Where-Object Name -like 'host-iso-*'` then Remove-VM + disk
delete).

No guest credentials are required: the seam leg needs no guest OS.

The lab config is deliberately NOT unrestricted: VM names must match
host-iso-* and the golden must live under the operator's dedicated scratch
directory (host_read_roots); clone child disks are confined to the
clone-disks subdirectory (host_write_roots). Provisioning, stopping, and
removal pass their destructive categories with confirm=True on every call.
Console input is NOT needed by these tests.

The scoping of this conftest's collection hook is pinned by
tests/unit/test_host_conftest_scope.py (the issue #115 pattern): only
items under tests/host receive these markers.
"""

import os
import stat
from pathlib import Path

import pytest

from hyperv_mcp.config import Config, DestructivePolicy


def _golden_ready(golden: str) -> tuple[bool, str]:
    if not golden.lower().endswith((".vhdx", ".vhd")):
        return False, (
            "HYPERV_MCP_TEST_GOLDEN_VHD does not name a .vhdx/.vhd file "
            "(mint a dedicated disposable golden: New-VHD -Dynamic + "
            "Set-ItemProperty IsReadOnly $true)")
    try:
        st = os.stat(golden)
    except OSError:
        return False, (
            "HYPERV_MCP_TEST_GOLDEN_VHD names a path that does not exist "
            "(mint a dedicated disposable golden: New-VHD -Dynamic + "
            "Set-ItemProperty IsReadOnly $true)")
    if not (st.st_file_attributes & stat.FILE_ATTRIBUTE_READONLY):
        return False, (
            "HYPERV_MCP_TEST_GOLDEN_VHD names an existing VHDX that is NOT "
            "read-only (Set-ItemProperty -LiteralPath <path> -Name "
            "IsReadOnly -Value $true first — vm_clone permanently locks a "
            "writable parent, and the digest guard cannot observe a "
            "DOS-attribute change)")
    return True, ""


def _host_ready() -> tuple[bool, str]:
    if os.environ.get("HYPERV_MCP_INTEGRATION", "") != "1":
        return False, "HYPERV_MCP_INTEGRATION is not set to 1 (real Hyper-V tests stay skipped)"
    golden = os.environ.get("HYPERV_MCP_TEST_GOLDEN_VHD", "").strip()
    if not golden:
        return False, (
            "HYPERV_MCP_TEST_GOLDEN_VHD is not set (mint a dedicated "
            "disposable read-only golden: New-VHD -Dynamic + Set-ItemProperty "
            "IsReadOnly $true)")
    ok, why = _golden_ready(golden)
    if not ok:
        return False, why
    return True, ""


READY, SKIP_REASON = _host_ready()

# Derived from the legs' own bounded waits (see the module docstring); the
# previous 900s value could be tripped mid-body by a slow-but-healthy host,
# and pytest-timeout's thread method kills via os._exit(1) — the test's
# finally-based fail-closed cleanup never runs on expiry.
HOST_TIMEOUT_S = 5700


def pytest_collection_modifyitems(config, items):
    """Skip the real-host suite unless explicitly enabled, and give
    surviving tests a timeout derived from the legs' bounded-wait budget.
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
    clone_disks = str(Path(scratch) / "clone-disks")
    os.makedirs(clone_disks, exist_ok=True)
    return Config(
        allowed_vm_patterns=["host-iso-*"],
        host_read_roots=[scratch],
        host_write_roots=[clone_disks],
        audit_log_path=str(host_tmp / "audit.jsonl"),
        verify_sha256=True,
        destructive=DestructivePolicy(stop=True, vm_provision=True, vm_remove=True),
    )


@pytest.fixture()
def host(host_tmp):
    """Bundle the live-host leg needs: least-privilege lab config (reads
    bound to the golden's scratch dir; writes confined to its clone-disks
    subdirectory), initialized transports, the golden path, and the
    assertion-result record path (plan v3 transcript contract; markers come
    from OBSERVED assertions)."""
    import hyperv_mcp.credentials as credentials
    from hyperv_mcp import auditlog, pswindows

    golden = os.environ["HYPERV_MCP_TEST_GOLDEN_VHD"].strip()
    cfg = _lab_config(golden, host_tmp)
    credentials.init(cfg)
    pswindows.init(cfg, credentials.redact)
    auditlog.init(cfg)
    record = os.environ.get("HYPERV_MCP_HOST_RESULT_RECORD", "").strip()
    scratch = str(Path(golden).resolve().parent)
    return type(
        "Host",
        (),
        {
            "cfg": cfg,
            "golden": golden,
            "scratch": scratch,
            "clone_disks": str(Path(scratch) / "clone-disks"),
            "record": record,
            "note": lambda self, line, kind="assert": _note(self.record, line, kind=kind),
        },
    )()


def _note(record: str, line: str, kind: str = "assert") -> None:
    """Append one line to the result record when the wave's transcript
    harness named one (no-op otherwise). `kind` selects the prefix:
    "assert" for observed assertion results, "report" for cleanup
    outcome/inventory lines (PRR-007: failures must not be filed as
    observed assertions). The write is guarded (PRR-008): a failing record
    path degrades to a stderr note and NEVER masks an in-flight primary
    exception."""
    if not record:
        return
    try:
        with open(record, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(f"{kind}: {line}\n")
    except OSError as exc:
        import sys
        sys.stderr.write(f"result-record write failed ({exc}); line: {kind}: {line}\n")
