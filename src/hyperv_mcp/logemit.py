"""Timestamped emission for the controller's redirected output (issue #57).

The controller process writes its stdout/stderr into a per-user log file
(stdio_proxy spawns it with stdout=log, stderr=STDOUT). Every line that
lands there therefore needs an emit-time timestamp: spawn/refusal history
is only diagnosable from the log alone when the LINES carry the time,
instead of being reconstructed from filesystem mtimes.

This module is the single emitter for that surface, shared by the HTTP
controller entry point (http_entry), the server bootstrap banner
(server._startup_banner) and the audit stream (auditlog._emit) — a
per-module helper would let the banner keep writing unprefixed lines
into the same file.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any

__all__ = ["log_line", "timestamp_prefix"]


def timestamp_prefix() -> str:
    """The ISO-8601 UTC prefix every controller log line carries."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_line(*parts: Any, file: Any = None) -> None:
    """Emit one controller log line with an ISO-8601 UTC prefix.

    ``file`` resolves LATE (None -> the current sys.stderr) so test capture
    and runtime redirection both see the line — a ``file=sys.stderr``
    default would bind the original stream object at import time and
    bypass any later swap. Token VALUES must never be passed here: the
    emission sites print variable NAMES, never values.
    """
    print(
        f"{timestamp_prefix()} " + " ".join(str(part) for part in parts),
        file=file or sys.stderr,
    )
