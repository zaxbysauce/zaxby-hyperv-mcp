"""Issue #60 Part A acceptance check: the failure-envelope docstring sweep
under the LOCK-TAKING-ONLY convention (plan critic round 1, blocker B5).

Every server.py tool docstring that advertises the failure envelope shape

    {ok: false, error, error_class, retryable, retry_after_ms}

must carry the '(+ holder on busy)' note within 40 characters IFF the tool
can actually take a VM lock (and therefore emit a busy envelope with holder
metadata). One exception is pinned explicitly: hyperv_vm_get_video is
lock-free (media.vm_get_video takes no vm_lock, so it can never emit
holder), and its docstring must NOT advertise holder metadata.

RED at base 92854d9: 17 lock-capable mentions are uncovered (hyperv_ui_*
via dual registration + hyperv_vm_secureboot_set) and the lock-free
hyperv_vm_get_video docstring is the honest plain shape. GREEN after the
docstring sweep: the same scan yields zero uncovered lock-capable mentions
and get_video stays plain.

Deterministic: pure source-text analysis of src/hyperv_mcp/server.py with
the issue's own regex and 40-character window; no import, no server build.
"""

from __future__ import annotations

import re
from pathlib import Path

_SERVER_PY = Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp" / "server.py"

_ENVELOPE = re.compile(r"\{ok: false, error, error_class, retryable,\s*retry_after_ms\}")

_TOOL_DEF = re.compile(r"^\s*def (hyperv_[A-Za-z0-9_]+)", re.MULTILINE)

#: The one registered tool that never takes a VM lock and therefore never
#: emits a busy envelope with holder metadata (verified: media.vm_get_video
#: contains no vm_lock). Its failure-shape docstring must stay PLAIN.
LOCK_FREE_TOOLS = {"hyperv_vm_get_video"}


def _enclosing_tool(source: str, pos: int) -> str:
    """Name of the nearest `def hyperv_<name>` above pos ('?' when none)."""
    best = "?"
    for match in _TOOL_DEF.finditer(source):
        if match.start() >= pos:
            break
        best = match.group(1)
    return best


def test_every_lock_capable_envelope_docstring_names_the_busy_holder():
    """Every failure-envelope mention in a lock-capable tool's docstring
    carries the holder note within the 40-char window (issue #60 Part A),
    and the lock-free tools stay honest and plain."""
    source = _SERVER_PY.read_text(encoding="utf-8")
    uncovered = []
    overcovered = []
    for match in _ENVELOPE.finditer(source):
        tool = _enclosing_tool(source, match.start())
        has_note = "holder on busy" in source[match.end() : match.end() + 40]
        if tool in LOCK_FREE_TOOLS:
            if has_note:
                overcovered.append((tool, match.start()))
        elif not has_note:
            uncovered.append((tool, match.start()))
    assert not uncovered, (
        "issue #60: lock-capable failure-envelope docstrings without the "
        f"'(+ holder on busy)' note ({len(uncovered)} mentions): "
        + ", ".join(sorted({tool for tool, _ in uncovered}))
    )
    assert not overcovered, (
        "issue #60 convention: the lock-free tool(s) "
        f"{sorted(set(t for t, _ in overcovered))} must NOT advertise "
        "holder metadata they can never emit"
    )
