"""Docstring→schema description enrichment (issue #86).

mcp 2.x builds every tool's inputSchema from the function signature alone;
the Google-style ``Args:`` sections this repo documents are never parsed by
the SDK, so the published schema carried ZERO parameter descriptions (434
properties across 78 tools at base 92854d9). This module closes that gap
with one rule: THE DOCSTRING IS THE SOURCE OF TRUTH. After registration,
every schema property without a description is stamped with the tool
docstring's ``Args:`` text for that parameter (whitespace-normalized).

Design notes:
- Indentation-tolerant parsing identical in shape to the acceptance check's
  parser (tests/unit/test_d04_tool_param_descriptions.py): ``Args:`` opens a
  block, the first indented ``name:`` line fixes the block indent, wrapped
  continuation lines (deeper indent) join with a single space, and a
  Returns:/Failure:/Policy:/Notes:/Raises: header closes the block.
- Existing descriptions are NEVER overwritten: an explicit Field/
  Annotated description wins.
- A parameter documented in prose but missing from ``Args:`` simply stays
  undescribed here — and the suite-wide pin (C3) fails on it, so authoring
  gaps surface in CI instead of drifting silently.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

#: Headers that end an Args: block (case-insensitive) when they appear at
#: the block's parameter indent.
_STOP_HEADERS = {"returns", "failure", "policy", "notes", "raises", "examples"}

_ARGS_HEADER = re.compile(r"^\s*Args:\s*$")
_PARAM_LINE = re.compile(r"^\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s?(.*)$")


def parse_args_section(description: str | None) -> dict[str, str]:
    """Parse a tool description's ``Args:`` block into {param: text}.

    Wrapped continuation lines join with single spaces; the block indent is
    fixed by the first ``name:`` line so the raw docstring indentation never
    matters.
    """
    params: dict[str, str] = {}
    if not description:
        return params
    lines = description.splitlines()
    i = 0
    while i < len(lines):
        if not _ARGS_HEADER.match(lines[i]):
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
            matched = _PARAM_LINE.match(line)
            name = matched.group(1) if matched is not None else None
            if indent == block_indent and name is not None:
                if name.lower() in _STOP_HEADERS:
                    break
                current = name
                assert matched is not None  # name is not None implies a match
                params[current] = matched.group(2).strip()
            elif current is not None and indent > block_indent:
                params[current] = (params[current] + " " + line.strip()).strip()
            else:
                break
            i += 1
    return params


def apply_docstring_descriptions(tools: Iterable) -> int:
    """Stamp docstring ``Args:`` text onto undescribed schema properties.

    `tools` is any iterable of mcp Tool objects (mcp 2.x: ``input_schema``;
    1.x: ``inputSchema``). Returns the number of properties described.
    Existing descriptions are never overwritten.
    """
    described = 0
    for tool in tools:
        # The registry's Tool objects carry the schema as `parameters`
        # (the attribute _harden_tools stamps); the list_tools DTOs use
        # input_schema/inputSchema. Accept all three shapes.
        schema = (
            getattr(tool, "parameters", None)
            or getattr(tool, "input_schema", None)
            or getattr(tool, "inputSchema", None)
        )
        if not isinstance(schema, dict):
            continue
        props = schema.get("properties")
        if not isinstance(props, dict):
            continue
        args = parse_args_section(getattr(tool, "description", None))
        if not args:
            continue
        for name, spec in props.items():
            if not isinstance(spec, dict) or spec.get("description"):
                continue
            text = args.get(name)
            if text:
                spec["description"] = text
                described += 1
    return described
