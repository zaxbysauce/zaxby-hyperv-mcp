"""Issue #115 acceptance check: the pytest_collection_modifyitems hook in
tests/integration/conftest.py must only mark items that live under
tests/integration.

At base 92854d9 the hook iterates EVERY session item, so a collection run
whose args span both directories (``pytest tests``) takes the integration
skip/timeout markers onto the UNIT items too: the whole unit suite silently
reports as skipped while HYPERV_MCP_INTEGRATION is unset. Empirically, base
``pytest tests/unit/test_config.py tests/integration/test_c01_locks_real.py``
collects 27 skipped unit tests and zero run ones.

RED at base 92854d9: the hook marks every session item, so the fake unit
item below receives both markers. GREEN after the scoping fix: the hook
filters by item location and only items under tests/integration are marked.

The check is deterministic: it loads the integration conftest by file path,
builds two fake items (an integration-path one and a unit-path one), and
drives the hook directly -- no subprocess, no real collection, no env
mutation. The fake items carry fspath (str), path (pathlib.Path) and nodeid
so the scoping fix may key on any of the conventional item attributes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO = Path(__file__).resolve().parents[2]
_INTEGRATION_CONFTEST = _REPO / "tests" / "integration" / "conftest.py"


def _load_integration_conftest(monkeypatch: pytest.MonkeyPatch):
    """Import tests/integration/conftest.py by path under a unique name so
    the unit suite never registers its fixtures (only its functions run).

    The integration gate is FORCED off for the import (the module computes
    READY at import time), so the check's environment is deterministic on
    every box, including one with a complete integration setup."""
    monkeypatch.delenv("HYPERV_MCP_INTEGRATION", raising=False)
    spec = importlib.util.spec_from_file_location(
        "integration_conftest_under_test_115", _INTEGRATION_CONFTEST
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeItem(SimpleNamespace):
    """Duck-typed pytest item: records add_marker calls by marker name."""

    def __init__(self, fspath: str, nodeid: str) -> None:
        super().__init__(fspath=fspath, path=Path(fspath), nodeid=nodeid)
        self.markers: list[str] = []

    def add_marker(self, marker) -> None:
        self.markers.append(getattr(marker, "name", str(marker)))


def test_hook_marks_only_integration_items(monkeypatch: pytest.MonkeyPatch):
    """The hook must add skip+timeout to the integration item and neither
    marker to the unit item (issue #115). The integration gate is forced
    off for the conftest import, so this holds on every box."""
    module = _load_integration_conftest(monkeypatch)
    assert module.READY is False

    integration_item = _FakeItem(
        str(_REPO / "tests" / "integration" / "test_c01_locks_real.py"),
        "tests/integration/test_c01_locks_real.py::test_probe",
    )
    unit_item = _FakeItem(
        str(_REPO / "tests" / "unit" / "test_config.py"),
        "tests/unit/test_config.py::test_probe",
    )

    module.pytest_collection_modifyitems(config=None, items=[integration_item, unit_item])

    assert "timeout" in integration_item.markers, (
        "the scoped hook must still give integration items the 900s timeout"
    )
    assert "skip" in integration_item.markers, (
        "the scoped hook must still skip integration items while "
        f"HYPERV_MCP_INTEGRATION is unset (reason: {module.SKIP_REASON!r})"
    )
    leaked = {"timeout", "skip"} & set(unit_item.markers)
    assert not leaked, (
        "issue #115: pytest_collection_modifyitems marked a test OUTSIDE "
        f"tests/integration ({unit_item.fspath}) with {sorted(leaked)}; "
        "the hook must scope its markers to items under tests/integration"
    )
