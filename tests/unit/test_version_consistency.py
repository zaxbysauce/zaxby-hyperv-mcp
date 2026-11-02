"""Version-consistency regression checks (issue #108; trace
55-108-31-32-33-collated, arm's-length acceptance-check authoring, tier L).

At base the version lives in three independent literals with no pin between
them — ``src/hyperv_mcp/server.py`` ``VERSION = "0.4.0"`` (the source of the
CLI banner/``--version``/``--check-env`` strings AND of the MCP initialize
``serverInfo.version`` via ``MCPServer(..., version=VERSION)``),
``src/hyperv_mcp/__init__.py`` ``__version__ = "0.8.0"``, and
``pyproject.toml`` ``version = "0.8.0"`` — so every release bump desyncs the
user-visible strings from the installed package. These checks are
import-level and deterministic (no CLI subprocess, no network): they pin
every user-visible version source to the installed distribution metadata
``importlib.metadata.version("hyperv-mcp")``.
"""

import importlib.metadata
from pathlib import Path

import hyperv_mcp
import hyperv_mcp.server as server_module

REPO_ROOT = Path(__file__).resolve().parents[2]


def _metadata_version() -> str:
    """The installed distribution's version (the single source of truth)."""
    return importlib.metadata.version("hyperv-mcp")


def _pyproject_version() -> str:
    """The ``[project] version`` literal from pyproject.toml (tomllib on
    3.11+, a targeted literal fallback on the 3.10 floor)."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - py3.10 floor
        import re

        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert match, "pyproject.toml carries no `version = \"...\"` literal"
        return match.group(1)
    with open(REPO_ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_version_consistency_cli():
    """AC1 (#108): the CLI ``--version`` / banner / ``--check-env`` version
    source (``server.VERSION``) must equal the installed distribution
    metadata version."""
    meta = _metadata_version()
    assert server_module.VERSION == meta, (
        f"CLI version source desync: server.VERSION={server_module.VERSION!r} "
        f"while importlib.metadata.version('hyperv-mcp')={meta!r} — the CLI "
        "banner/--version/--check-env strings drift from the installed package"
    )


def test_version_consistency_handshake(monkeypatch):
    """AC2 (#108): the MCP ``initialize`` ``serverInfo.version`` is the
    value bound at MCPServer construction (``bootstrap()`` builds
    ``MCPServer(..., version=VERSION)``); the construction-bound value must
    equal the installed distribution metadata version."""
    import importlib

    meta = _metadata_version()
    monkeypatch.delenv("HYPERV_MCP_CONFIG", raising=False)
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    mod = importlib.reload(server_module)
    try:
        mod.bootstrap()
        mcp = mod.get_mcp()
        bound = getattr(mcp, "version", None)
        if bound is None:
            # SDK shim spelling guard: the low-level server owns serverInfo.
            lowlevel = getattr(mcp, "_lowlevel_server", None)
            bound = getattr(lowlevel, "server_info", None)
            bound = getattr(bound, "version", None)
        assert bound == meta, (
            f"handshake serverInfo version desync: the constructed server "
            f"reports {bound!r} while importlib.metadata.version("
            f"'hyperv-mcp')={meta!r}"
        )
    finally:
        importlib.reload(server_module)


def test_version_consistency_literals():
    """AC3 (#108): ``server.py`` ``VERSION``, ``__init__`` ``__version__``
    and ``pyproject.toml`` ``version`` must all agree."""
    pyproject = _pyproject_version()
    assert hyperv_mcp.__version__ == server_module.VERSION == pyproject, (
        f"version literals disagree: __version__={hyperv_mcp.__version__!r} "
        f"server.VERSION={server_module.VERSION!r} "
        f"pyproject.version={pyproject!r}"
    )
