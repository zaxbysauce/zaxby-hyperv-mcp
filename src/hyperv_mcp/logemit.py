"""Timestamped emission for the controller's redirected output (issue #57).

The controller process writes its stdout/stderr into a per-user log file
(stdio_proxy spawns it with stdout=log, stderr=STDOUT). Every line that
lands there therefore needs an emit-time timestamp: spawn/refusal history
is only diagnosable from the log alone when the LINES carry the time,
instead of being reconstructed from filesystem mtimes.

This module is the single emitter for that surface, shared by the HTTP
controller entry point (http_entry), the server bootstrap banner
(server._startup_banner), the audit stream (auditlog._emit) and the
PowerShell slot-pool warnings (pswindows) — a per-module helper lets a
sibling module keep writing unprefixed lines into the same file.

Two properties hold for EVERY physical line this module writes:

* it carries the ISO-8601 UTC prefix (embedded newlines in a payload are
  split so a continuation line is prefixed too);
* a write failure NEVER propagates to the caller — logging must not be
  able to break the error path it is reporting on.
"""

from __future__ import annotations

import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "log_line",
    "log_exception",
    "timestamp_prefix",
    "install_log_prefix",
]


def timestamp_prefix() -> str:
    """The ISO-8601 UTC prefix every controller log line carries."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write(text: str, file: Any = None) -> None:
    """Write one already-formatted line; a write error is swallowed.

    The controller's stderr IS the shared per-user log volume, so a full
    or closed log must not turn a tool's failure into an unstructured
    I/O error (the previous logging handler could not raise: logging
    swallows handler write errors)."""
    try:
        print(text, file=file or sys.stderr)
    except Exception:  # noqa: BLE001 - logging must never break the caller
        pass


def log_line(*parts: Any, file: Any = None) -> None:
    """Emit one controller log line with an ISO-8601 UTC prefix.

    A payload containing embedded newlines is split so that EVERY
    physical line carries the prefix — an operator (and any log reader)
    can rely on line N starting with the timestamp.

    ``file`` resolves LATE (None -> the current sys.stderr) so test
    capture and runtime redirection both see the line — a
    ``file=sys.stderr`` default would bind the original stream object
    at import time and bypass any later swap. Token VALUES must never
    be passed here: the emission sites print variable NAMES, never
    values.
    """
    stamp = timestamp_prefix()
    text = " ".join(str(part) for part in parts)
    for line in text.splitlines() or [""]:
        _write(f"{stamp} {line}" if line else f"{stamp}", file)


def log_exception(*parts: Any, file: Any = None) -> None:
    """Emit one controller log line plus the current exception's traceback.

    Every traceback line carries the SAME prefix: the controller log is
    read line by line, and an unprefixed continuation line would break
    the "every line is timestamped" property the log is built for. The
    summary line is split the same way log_line splits its payload, so a
    multi-part summary cannot leak an unprefixed continuation either.
    """
    import traceback

    stamp = timestamp_prefix()
    stream = file or sys.stderr
    summary = " ".join(str(part) for part in parts)
    for line in summary.splitlines() or [""]:
        _write(f"{stamp} {line}" if line else f"{stamp}", stream)
    for line in traceback.format_exc().splitlines():
        if line.strip():
            _write(f"{stamp} {line}", stream)


_PREFIXED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z(\s|$)")
# Marker set on the installed factory: the guard is "is the CURRENT
# factory ours?", not "did we ever install one?" - a caller that
# REPLACES the factory (a test restoring the previous one) must be able
# to install again without a second stamp stacking on every record.
_FACTORY_MARKER = "_hyperv_log_prefix_factory"


def _prefix_record(record: logging.LogRecord) -> None:
    """Stamp one log record with the ISO-8601 UTC prefix.

    Two record shapes have to be handled differently:

    * an ordinary record (the SDK's, uvicorn.error's) renders as
      ``record.msg % record.args``, so the stamp is put in front of the
      MESSAGE and the args are left in place - a formatter that uses
      ``%(message)s`` then renders "STAMP <text>";
    * uvicorn's ACCESS records are composed by uvicorn's own
      ``AccessFormatter`` from a FIVE-element args tuple (client address,
      method, path, http version, status code) - the message is not used
      at all. Clearing or reshaping those args would make the formatter
      raise ("not enough values to unpack") and print a logging error
      INTO the controller log, so the stamp goes into the client address
      instead and the tuple contract is preserved.
    """
    rendered = True
    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 - never break the log call
        # The message cannot be rendered (a stray "%" with no args, a
        # broken format tuple). The record must still be stamped: fall
        # back to the raw message and CONSUME the args (they are what
        # broke the rendering).
        rendered = False
        message = record.msg if isinstance(record.msg, str) else ""
    if not isinstance(message, str) or _PREFIXED_RE.match(message):
        return
    try:
        stamp = timestamp_prefix()
        if record.name.startswith("uvicorn.access") and isinstance(
            record.args, tuple
        ) and len(record.args) == 5:
            client = record.args[0]
            if isinstance(client, tuple) and len(client) == 2:
                # The client address renders as the FIRST field of the
                # access line, so the stamp goes there; the ARGS TUPLE
                # keeps its five-element shape (uvicorn's formatter
                # unpacks exactly five) and only the address itself
                # becomes the stamped "host:port" string.
                record.args = (
                    f"{stamp} {client[0]}:{client[1]}",
                ) + record.args[1:]
            elif isinstance(client, str):
                record.args = (f"{stamp} {client}",) + record.args[1:]
            return
        if "\n" in message or not rendered:
            # A multi-line payload (or an unrenderable one): embed the
            # RENDERED text so that every physical line carries the prefix
            # (the args are consumed).
            record.msg = "\n".join(
                f"{stamp} {line}" if line else stamp for line in message.splitlines()
            )
            record.args = ()
        else:
            # Keep the args: the formatter still needs them to render the
            # message, and the stamp lands in front of it.
            record.msg = f"{stamp} {record.msg}"
    except Exception:  # noqa: BLE001 - never break the log call
        pass


def install_log_prefix() -> None:
    """Prefix EVERY record the process logs with the ISO-8601 UTC stamp.

    The controller's redirected streams also carry the SDK's own records
    (mcp calls configure_logging) and uvicorn's access lines. Those are
    not hyperv-mcp emissions, but they land in the SAME per-user log, so
    an operator reading it line by line needs them prefixed too.

    A filter attached to a LOGGER does not see the records of its
    CHILDREN (the SDK logs under "mcp.*", uvicorn under "uvicorn.*"), and
    a filter attached to a HANDLER is lost when the SDK's
    configure_logging() replaces the root handlers at startup. The global
    RECORD FACTORY is the one hook that sees every record the process
    creates, whichever logger and handler it ends up in."""
    base = logging.getLogRecordFactory()
    if getattr(base, _FACTORY_MARKER, False):
        # Already installed (the controller calls this once per start); a
        # second call must not STACK a second prefix on every record.
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = base(*args, **kwargs)
        _prefix_record(record)
        return record

    setattr(factory, _FACTORY_MARKER, True)
    logging.setLogRecordFactory(factory)
