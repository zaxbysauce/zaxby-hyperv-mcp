"""Frozen acceptance checks for issue #57: every line the http controller
emits on its serve path must carry an ISO-8601 UTC timestamp prefix, and
no emitted line may ever contain the token value.

Token -> AC map:
  test_log_lines_carry_iso8601_timestamps
      AC1: the controller's line-emission helper prefixes each emitted
      line with YYYY-MM-DDTHH:MM:SSZ (ISO-8601 UTC).
  test_log_lines_never_carry_the_token_value
      AC2: with a non-blank token value in the environment, two
      refusal-style emissions never echo that value into the output.

The seam is probed arm's-length because the issue binds the OUTPUT shape,
not the implementation: the fix may name its helper controller_log, _log
or _emit (probed in that order via getattr on hyperv_mcp.http_entry; the
helper may print and/or return the formatted line — both are captured).
At base none of those names exists, so both checks fail by naming the
missing seam — the intended red while the timestamping work is
unimplemented.
"""

import ast
import re
from pathlib import Path

from hyperv_mcp import http_entry

SEAM_NAMES = ("controller_log", "_log", "_emit")
TIMESTAMP_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

HTTP_ENTRY_SOURCE = Path(http_entry.__file__).read_text(encoding="utf-8")


def _emission_seam():
    for name in SEAM_NAMES:
        seam = getattr(http_entry, name, None)
        if callable(seam):
            return seam
    raise AssertionError(
        "hyperv_mcp.http_entry exposes no controller log-line emission seam "
        f"(probed {', '.join(SEAM_NAMES)}); issue #57 requires the "
        "controller's serve-path lines to be emitted through a helper that "
        "prefixes ISO-8601 UTC timestamps"
    )


def _assert_serve_path_routes_through_seam(seam_name: str) -> None:
    """Plan-critic round-1 blocker 3 + round-2 blocker 3 (wiring): the serve
    entry point and EVERY module function it transitively calls must emit
    through the timestamped seam — a bare `print()` in any serve-path
    helper (e.g. the per-agent token resolver) would bypass the prefix on
    exactly the lines the issue binds. Structural pin via AST call-graph
    walk (driving a real uvicorn serve needs a live host)."""
    tree = ast.parse(HTTP_ENTRY_SOURCE)
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "main" in functions, "http_entry.main not found"

    def _called_names(node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                if isinstance(sub.func, ast.Name):
                    yield sub.func.id
                elif isinstance(sub.func, ast.Attribute):
                    yield sub.func.attr

    # Transitive closure over same-module calls, starting at main().
    # Plan-critic round-3 blocker: the interactive --install-logon-task path
    # (its own helper subtree) prints to the OPERATOR'S SHELL, not the
    # redirected per-user log, and the issue's scope explicitly leaves those
    # lines unprefixed (05-fix-plan Fix 5). Exclude that subtree from the
    # serve-path closure: reachable-from-main MINUS everything reachable
    # only through the install helper.
    INSTALL_ONLY = {"_handle_logon_task"}

    def _reachable(skip: set) -> set:
        seen_local = {"main"}
        frontier_local = ["main"]
        while frontier_local:
            current = frontier_local.pop()
            for name in _called_names(functions[current]):
                if name in functions and name not in seen_local and name not in skip:
                    seen_local.add(name)
                    frontier_local.append(name)
        return seen_local

    seen = _reachable(set())
    serve_only = _reachable(INSTALL_ONLY)
    seen = serve_only

    bare_prints = []
    for fname in sorted(seen):
        if fname == seam_name:
            # The seam itself is the sanctioned emitter (plan-critic round-4
            # follow-up: its own print() IS the timestamped mechanism the
            # issue binds; scanning it is self-referential).
            continue
        for sub in ast.walk(functions[fname]):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == "print"
            ):
                bare_prints.append((fname, sub.lineno))
    assert not bare_prints, (
        f"serve-path functions still make direct print() call(s): "
        f"{bare_prints!r}; serve-path output must route through {seam_name} "
        "so every emitted line carries the ISO-8601 UTC prefix"
    )
    seam_refs = [
        fname
        for fname in sorted(seen)
        for sub in ast.walk(functions[fname])
        if isinstance(sub, ast.Name) and sub.id == seam_name
    ]
    assert seam_refs, (
        f"the serve path (main + {len(seen) - 1} transitive callees) never "
        f"references the emission seam {seam_name!r}; it is not wired through"
    )


def test_log_lines_carry_iso8601_timestamps(capsys):
    seam = _emission_seam()
    seam_name = next(
        name for name in SEAM_NAMES if getattr(http_entry, name, None) is seam
    )
    _assert_serve_path_routes_through_seam(seam_name)
    returned = seam("controller refused to start: no token is set")
    captured = capsys.readouterr()
    text = returned if isinstance(returned, str) else (captured.out + captured.err)
    lines = [line for line in text.splitlines() if line.strip()]
    assert lines, "emission seam produced no observable line"
    assert TIMESTAMP_PREFIX.match(lines[0]), (
        f"controller log line carries no ISO-8601 UTC timestamp prefix: {lines[0]!r}"
    )
    # Implementation-review round 1: the PREFIX SHAPE alone is not UTC --
    # a local-time stamp suffixed "Z" matches the same regex. Parse the
    # emitted stamp as UTC and compare it with the real UTC clock.
    from datetime import datetime, timezone

    stamp = lines[0].split(" ", 1)[0]
    parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    now = datetime.now(timezone.utc)
    drift = abs((now - parsed).total_seconds())
    assert drift <= 120, (
        f"controller log timestamp {stamp!r} is not UTC (drift {drift:.0f}s "
        f"from {now.isoformat()}); local time suffixed 'Z' matches the shape "
        "but is the wrong clock"
    )


def test_log_lines_never_carry_the_token_value(monkeypatch, capsys):
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "sup3rs3cret-sentinel-value")
    seam = _emission_seam()
    seam_name = next(
        name for name in SEAM_NAMES if getattr(http_entry, name, None) is seam
    )
    _assert_serve_path_routes_through_seam(seam_name)
    returned: list = []
    for _ in range(2):
        out = seam("ERROR: HYPERV_MCP_HTTP_TOKEN is not set (refusal)")
        if isinstance(out, str):
            returned.append(out)
    captured = capsys.readouterr()
    blob = "".join(returned) + captured.out + captured.err
    assert "sup3rs3cret-sentinel-value" not in blob, (
        "controller log output leaked the token value"
    )


def test_refusal_paths_never_carry_the_token_value(monkeypatch, capsys):
    """Implementation-review round 1+2: the seam-level no-leak floor does
    not prove the REAL refusal sites are safe. Drive the serve-path
    refusals that could echo a value and assert EVERY involved token
    value is absent — the reviewer's falsifier (the refusal echoing
    {value!r}) must be caught, so each value in the refusal's scope is
    asserted absent, not just the first one."""
    sentinel_a = "sup3rs3cret-refusal-sentinel-a"
    sentinel_b = "sup3rs3cret-refusal-sentinel-b"
    non_ascii = "not-ascii-\u00e9"
    # (a) a RESOLVED agent emits nothing; its value must not appear.
    monkeypatch.setenv("HYPERV_MCP_TOKEN_AGENT_A", sentinel_a)
    rc, pairs = http_entry._resolve_agent_tokens(
        {"agent-a": "HYPERV_MCP_TOKEN_AGENT_A"}, ""
    )
    assert rc == 0 and pairs, pairs
    captured = capsys.readouterr()
    assert sentinel_a not in (captured.out + captured.err), (
        "the agent-token resolver echoed the token value"
    )
    # (b) the non-ASCII refusal: the REFUSED value (non_ascii) AND the
    # already-resolved sibling value (sentinel_a) must both be absent —
    # asserting only the sibling's absence left the falsifier alive.
    monkeypatch.setenv("HYPERV_MCP_TOKEN_AGENT_B", non_ascii)
    rc, _ = http_entry._resolve_agent_tokens(
        {
            "agent-a": "HYPERV_MCP_TOKEN_AGENT_A",
            "agent-b": "HYPERV_MCP_TOKEN_AGENT_B",
        },
        "",
    )
    assert rc == 2, rc
    captured = capsys.readouterr()
    blob = captured.out + captured.err
    assert non_ascii not in blob, (
        "the refusal echoed the refused token value"
    )
    assert sentinel_a not in blob, (
        "the refusal echoed another agent's token value"
    )
    assert "agent-b" in blob, (
        f"the refusal must name the offending agent, not its value: {blob!r}"
    )
    assert "never printed" in blob, (
        f"the refusal must state that values are never printed: {blob!r}"
    )
    # (c) the MISSING-variable refusal names the variable, never a value.
    monkeypatch.delenv("HYPERV_MCP_TOKEN_AGENT_B", raising=False)
    rc, _ = http_entry._resolve_agent_tokens(
        {
            "agent-a": "HYPERV_MCP_TOKEN_AGENT_A",
            "agent-b": "HYPERV_MCP_TOKEN_AGENT_B",
        },
        "",
    )
    assert rc == 2, rc
    captured = capsys.readouterr()
    blob = captured.out + captured.err
    assert sentinel_a not in blob, "the missing-variable refusal echoed a value"
    assert "HYPERV_MCP_TOKEN_AGENT_B" in blob, (
        f"the missing-variable refusal must name the variable: {blob!r}"
    )
