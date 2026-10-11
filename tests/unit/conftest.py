"""Shared unit-test fixtures. No real Hyper-V is touched."""

import pytest

from hyperv_mcp.config import Config


@pytest.fixture(autouse=True)
def _ps_transport_default(monkeypatch):
    """Unit tests default to the PowerShell console transport: no real
    Hyper-V through EITHER transport (the suite stubs run_ps; the
    in-process WMI backend is likewise never real here — on boxes with
    pywin32 AND a live namespace it would otherwise serve silently).
    Tests that exercise the WMI path install their own fake backend
    explicitly and re-enable it via wmiconsole.COM_AVAILABLE (issue #45).
    The backend/negative-cache state is reset per test so no test inherits
    another test's fake service (review F3-C/P24)."""
    from hyperv_mcp import wmiconsole

    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", False)
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})


@pytest.fixture()
def deny_all_cfg() -> Config:
    return Config()


@pytest.fixture()
def unrestricted_cfg() -> Config:
    return Config(unrestricted=True)


@pytest.fixture()
def lab_cfg(tmp_path) -> Config:
    """A realistic restrictive lab config: one VM pattern, tmp roots."""
    return Config(
        allowed_vm_patterns=["test-vm-*"],
        host_read_roots=[str(tmp_path / "host-read")],
        host_write_roots=[str(tmp_path / "host-write")],
        guest_read_roots=["C:\\guest-read"],
        guest_write_roots=["C:\\guest-write"],
    )


def content_blocks(result):
    """Content blocks from any mcp call_tool return shape.

    Handles the historical tuple form, the converted list form, and the
    CallToolResult object that in-process call_tool returns when a tool
    returns one (issue #9 envelope delivery)."""
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    return content if isinstance(content, list) else [content]


def envelope_from_result(result, label: str) -> dict:
    """Parse the first text block of a failure result into the envelope."""
    import json

    blocks = content_blocks(result)
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {label}"
    return json.loads(texts[0].text)
