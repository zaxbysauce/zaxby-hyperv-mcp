"""Scoping pin for tests/host/conftest.py (the issue #115 pattern, sibling
of test_conftest_collection_scope.py): the host conftest's
pytest_collection_modifyitems hook must only mark items that live under
tests/host — never unit items — so a whole-tree run (pytest tests) cannot
silently turn the unit suite into skips when the host gate is unset.

Deterministic: loads the host conftest by file path under a unique name
with the gate FORCED off, builds two fake items (a host-path one and a
unit-path one), and drives the hook directly. No subprocess, no real
collection, no env mutation beyond the forced-off delenv.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO = Path(__file__).resolve().parents[2]
_HOST_CONFTEST = _REPO / "tests" / "host" / "conftest.py"


def _load_host_conftest(monkeypatch: pytest.MonkeyPatch):
    """Import tests/host/conftest.py by path under a unique name so the
    unit suite never registers its fixtures (only its functions run). The
    host gate is FORCED off for the import (the module computes READY at
    import time), so the check's environment is deterministic on every box."""
    monkeypatch.delenv("HYPERV_MCP_INTEGRATION", raising=False)
    monkeypatch.delenv("HYPERV_MCP_TEST_GOLDEN_VHD", raising=False)
    spec = importlib.util.spec_from_file_location(
        "host_conftest_under_test_ac16", _HOST_CONFTEST
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeItem(SimpleNamespace):
    def __init__(self, fspath: str, nodeid: str) -> None:
        super().__init__(fspath=fspath, path=Path(fspath), nodeid=nodeid)
        self.markers: list[str] = []

    def add_marker(self, marker) -> None:
        self.markers.append(getattr(marker, "name", str(marker)))


def test_host_conftest_marks_only_host_items(monkeypatch):
    module = _load_host_conftest(monkeypatch)
    host_item = _FakeItem(
        str(_REPO / "tests" / "host" / "test_vm_agent_isolation_host.py"),
        "tests/host/test_vm_agent_isolation_host.py::test_x",
    )
    unit_item = _FakeItem(
        str(_REPO / "tests" / "unit" / "test_config.py"),
        "tests/unit/test_config.py::test_y",
    )
    module.pytest_collection_modifyitems(config=None, items=[host_item, unit_item])
    # the host item is gated (skip) and timed for real-host waits
    assert "skip" in host_item.markers, host_item.markers
    assert "timeout" in host_item.markers, host_item.markers
    # the unit item is untouched — the whole-tree silent-skip regression
    # class stays dead for the new conftest
    assert unit_item.markers == [], unit_item.markers
