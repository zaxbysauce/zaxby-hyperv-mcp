"""Issue #86 acceptance checks (AC1 + AC2): every declared tool parameter
carries a non-empty description in the published input schema, and the
description text is the tool docstring's Args: entry for that parameter.

The schema is the surface clients see, so these checks import the real
server and read the real list_tools() output (no reimplementation of the
registration path). Measured at base 92854d9: 80 tools publish 434
properties, ZERO properties carry any description, and 28 of the published
descriptions already contain an Args: section whose text never reaches the
schema -- the enrichment pipeline simply does not exist.

Both registration variants (default + inline credentials) are scanned, so a
variant-only gap (e.g. the creds_allowed username/password parameters) fails
the suite too.

RED at base 92854d9: test_every_declared_parameter_is_described fails with
the issue's signature (every property of every tool is in the undescribed
set), and test_docstring_args_reach_the_schema fails its non-vacuity oracle
(zero descriptions exist anywhere). GREEN after the docstring-to-schema
enrichment plus Args authoring lands: every property described, and every
description equal (whitespace-normalized) to its docstring Args text.

Deterministic: list_tools() is pure registration output (the unit-suite
conftest already redirects the state store and profile paths to tmp), and
the Args parser below is indentation-relative so the raw docstring's source
indentation never matters.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]

_TOOLS: list | None = None
_INLINE_TOOLS: list | None = None


def _tools() -> list:
    """The published tool list of the DEFAULT registration, built once per
    test session (memoized)."""
    global _TOOLS
    if _TOOLS is None:
        from hyperv_mcp import server

        _TOOLS = list(asyncio.run(server.get_mcp().list_tools()))
    return _TOOLS


def _inline_tools() -> list:
    """The published tool list of the INLINE-CREDENTIALS registration
    variant (plan-critic round 2: the creds_allowed block registers extra
    username/password parameters that exist only in this variant), built
    once per test session (memoized). Mirrors bootstrap()'s registration
    shape on a throwaway MCPServer instance."""
    global _INLINE_TOOLS
    if _INLINE_TOOLS is None:
        import tempfile

        from mcp.server.mcpserver import MCPServer

        from hyperv_mcp import server
        from hyperv_mcp.config import Config

        audit_tmp = Path(tempfile.mkdtemp(prefix="d04-inline-variant-"))
        cfg = Config(
            unrestricted=True,
            audit_log_path=str(audit_tmp / "audit-variant.jsonl"),
            allow_inline_credentials=True,
        )
        mcp = MCPServer("hyperv_mcp_inline_variant", version="0.0.0-test")
        server._register_tools(cfg, mcp)
        _INLINE_TOOLS = list(asyncio.run(mcp.list_tools()))
    return _INLINE_TOOLS


def _all_variants() -> list:
    """Both registration variants: default + inline credentials."""
    return _tools() + _inline_tools()


def _schema_of(tool) -> dict:
    """The tool's input schema across SDK generations (mcp 1.x: inputSchema,
    2.x: input_schema)."""
    return getattr(tool, "input_schema", None) or tool.inputSchema


def _properties_of(tool) -> dict:
    schema = _schema_of(tool)
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties", {})
    return props if isinstance(props, dict) else {}


def _described(tool, name: str) -> str | None:
    """The property's description when it is a non-empty string, else None."""
    spec = _properties_of(tool).get(name)
    if not isinstance(spec, dict):
        return None
    description = spec.get("description")
    if isinstance(description, str) and description.strip():
        return description
    return None


def _normalize(text: str) -> str:
    return " ".join(text.split())


#: Section headers that end an Args: block when they appear at the param
#: indent (a header indented like a parameter name is still a header).
_STOP_HEADERS = {
    "returns",
    "failure",
    "policy",
    "notes",
    "raises",
    "examples",
    "example",
    "yields",
}


def _parse_args_section(description: str) -> dict[str, str]:
    """Parse Google-style ``Args:`` blocks out of a published tool
    description.

    Indentation-tolerant: a line matching ``^\\s*Args:\\s*$`` opens a block;
    the first indented ``name:`` line fixes the block indent; later lines at
    that indent starting ``name:`` open the next parameter, deeper-indented
    lines (and blanks) continue the current one, a dedent or a stop-header
    (Returns:/Policy/Notes/...) closes the block. Returns param name ->
    whitespace-joined text.
    """
    params: dict[str, str] = {}
    lines = description.splitlines()
    i = 0
    while i < len(lines):
        if not re.match(r"^\s*Args:\s*$", lines[i]):
            i += 1
            continue
        i += 1
        while i < len(lines) and not lines[i].strip():
            i += 1
        block_indent: int | None = None
        current: str | None = None
        while i < len(lines):
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            indent = len(line) - len(line.lstrip())
            if block_indent is None:
                block_indent = indent
            matched = re.match(r"^\s+([A-Za-z_][A-Za-z0-9_]*):\s?(.*)$", line)
            name = matched.group(1) if matched else None
            if indent == block_indent and name is not None:
                if name.lower() in _STOP_HEADERS:
                    break
                current = name
                params[current] = matched.group(2).strip()
            elif current is not None and indent > block_indent:
                params[current] = (params[current] + " " + line.strip()).strip()
            else:
                break
            i += 1
    return params


def test_every_declared_parameter_is_described():
    """AC1: every property of every tool's input schema carries a non-empty
    string description (issue #86)."""
    undescribed: dict[str, set[str]] = {}
    for tool in _all_variants():
        missing = {
            name
            for name in _properties_of(tool)
            if _described(tool, name) is None
        }
        if missing:
            undescribed[tool.name] = missing
    assert undescribed == {}, (
        "issue #86: tool parameters published without any schema "
        "description:\n"
        + "\n".join(
            f"  {name}: {sorted(props)}" for name, props in sorted(undescribed.items())
        )
    )


def test_docstring_args_reach_the_schema():
    """AC2: every description that exists equals its docstring Args text
    (whitespace-normalized), and at least one description exists at all.

    The vacuity oracle is load-bearing: at base zero descriptions exist, so
    without it this check would pass vacuously before the enrichment lands.
    """
    described_pairs = 0
    mismatches: list[str] = []
    for tool in _all_variants():
        parsed = _parse_args_section(tool.description or "")
        for name in _properties_of(tool):
            description = _described(tool, name)
            if description is None:
                continue
            described_pairs += 1
            if name not in parsed:
                mismatches.append(
                    f"  {tool.name}.{name}: schema description "
                    f"{_normalize(description)!r} has no matching "
                    "docstring Args entry"
                )
            elif _normalize(description) != _normalize(parsed[name]):
                mismatches.append(
                    f"  {tool.name}.{name}: schema says "
                    f"{_normalize(description)!r}, docstring Args says "
                    f"{_normalize(parsed[name])!r}"
                )
    assert described_pairs > 0, (
        "issue #86 non-vacuity oracle: zero tool parameters carry a schema "
        "description, so no Args text has reached the schema -- the "
        "docstring-to-schema enrichment has not landed"
    )
    assert mismatches == [], (
        "issue #86: schema descriptions that disagree with their docstring "
        "Args text:\n" + "\n".join(mismatches)
    )
