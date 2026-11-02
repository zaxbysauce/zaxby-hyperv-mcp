"""Frozen doc-pin checks for issue #56: the README's "Connecting to MCP
clients" section must document the controller token environment variable
(HYPERV_MCP_HTTP_TOKEN) in the .mcp.json snippet and alongside the
`claude mcp add` one-liner, and the README's `setx` guidance must be
paste-safe (no angle-bracket placeholder).

Token -> AC map:
  test_connect_snippet_documents_controller_token
      AC1: the fenced .mcp.json snippet's env object lists
      HYPERV_MCP_HTTP_TOKEN among its keys.
  test_connect_oneliner_documents_controller_token
      AC2: the connect section's text (the fenced block plus its
      surrounding prose) names HYPERV_MCP_HTTP_TOKEN.
  test_setx_guidance_is_paste_safe
      AC3: the line carrying `setx HYPERV_MCP_HTTP_TOKEN` contains no
      "<" or ">" anywhere (paste-safe into cmd/PowerShell).

All three read the live README.md (never this file), so they stay red
until the documentation edit lands.
"""

import json
import re
from pathlib import Path

README = Path(__file__).resolve().parents[2] / "README.md"
SECTION_HEADING = "## Connecting to MCP clients"


def _readme_text() -> str:
    assert README.is_file(), f"README.md not found at {README}"
    return README.read_text(encoding="utf-8")


def _connect_section() -> str:
    """The section body between the heading and the next '## ' heading."""
    text = _readme_text()
    start = text.find(SECTION_HEADING)
    assert start != -1, f"README has no {SECTION_HEADING!r} section"
    rest = text[start + len(SECTION_HEADING):]
    nxt = rest.find("\n## ")
    return rest if nxt == -1 else rest[:nxt]


def _find_env_objects(node):
    """Every dict stored under an 'env' key, at any depth of the snippet."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "env" and isinstance(value, dict):
                yield value
            yield from _find_env_objects(value)
    elif isinstance(node, list):
        for item in node:
            yield from _find_env_objects(item)


def test_connect_snippet_documents_controller_token():
    section = _connect_section()
    blocks = re.findall(r"```json\s*\n(.*?)```", section, re.DOTALL)
    with_config = [b for b in blocks if "HYPERV_MCP_CONFIG" in b]
    assert with_config, (
        "connect section has no fenced json snippet carrying HYPERV_MCP_CONFIG"
    )
    for block in with_config:
        snippet = json.loads(block)
        envs = list(_find_env_objects(snippet))
        assert envs, "the .mcp.json snippet carries no env object"
        assert any("HYPERV_MCP_HTTP_TOKEN" in env for env in envs), (
            "connect-section .mcp.json env block does not document "
            "HYPERV_MCP_HTTP_TOKEN: " + json.dumps(envs)
        )


def test_connect_oneliner_documents_controller_token():
    section = _connect_section()
    # Plan-critic round-1 blocker 3 (isolation): the assertion reads ONLY
    # the one-liner's fenced block plus its immediately adjacent prose
    # (8 lines either side), so the section's OTHER json snippet or the
    # shared-controller guidance cannot satisfy it in the one-liner's
    # place.
    blocks = list(re.finditer(r"```[a-z]*\s*\n(.*?)```", section, re.DOTALL))
    oneliner_blocks = [
        m for m in blocks if "claude mcp add" in m.group(1)
    ]
    assert oneliner_blocks, (
        "connect section carries no fenced block containing the "
        "'claude mcp add' one-liner"
    )
    lines = section.splitlines()
    for m in oneliner_blocks:
        start_line = section[: m.start()].count("\n")
        end_line = section[: m.end()].count("\n")
        lo = max(0, start_line - 8)
        hi = min(len(lines), end_line + 8)
        window = "\n".join(lines[lo:hi])
        assert "HYPERV_MCP_HTTP_TOKEN" in window or (
            "HYPERV_MCP_HTTP_TOKEN" in m.group(1)
        ), (
            "the 'claude mcp add' one-liner and its adjacent prose never "
            "name HYPERV_MCP_HTTP_TOKEN (a documented supply mechanism is "
            "required next to the one-liner itself)"
        )


def test_setx_guidance_is_paste_safe():
    for line in _readme_text().splitlines():
        if "setx HYPERV_MCP_HTTP_TOKEN" in line:
            assert "<" not in line and ">" not in line, (
                f"setx guidance is not paste-safe (angle-bracket "
                f"placeholder): {line!r}"
            )
            return
    raise AssertionError(
        "README carries no 'setx HYPERV_MCP_HTTP_TOKEN' guidance line"
    )
