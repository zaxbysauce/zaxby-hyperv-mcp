"""Shared unit-test fixtures. No real Hyper-V is touched."""

import pytest

from hyperv_mcp.config import Config


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
