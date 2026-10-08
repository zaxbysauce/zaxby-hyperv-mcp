"""Structured, secret-safe audit logging for hyperv-mcp.

One JSON object per operation: timestamp, tool, vm_name, category, ok,
duration_ms, exit_code, error_class, plus the correlation keys added by
issue #10 — agent_id (the authenticated caller's client_id, null on
stdio/anonymous), request_id (server-generated per audited call), and
job_id/relay_id when the operation addressed a guest job or relay. Command
content, file content and credentials are NEVER logged; all string fields
pass the redaction filter.

Sink: audit_log_path from config (JSONL, appended). When unset, a compact
one-line summary goes to stderr. When the server runs in unrestricted mode,
the stderr line is forced on so the bypass stays visible.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Literal

from mcp.server.auth.middleware.auth_context import get_access_token

from . import credentials
from .config import Config

_lock = threading.Lock()
_config: Config | None = None

# Sentinel for "no agent_id supplied — resolve it from the auth context at
# write time". Distinguishes an explicit None (anonymous: serialize null)
# from an unset value (direct/out-of-band callers: resolve).
_UNSET_AGENT = object()


def current_agent_id() -> str | None:
    """The authenticated caller's client_id, or None outside a request.

    Public since issue #11: the job/relay tool layer passes this down as
    the ownership principal for registry entries (None = the unattributed
    local principal on stdio/anonymous/direct-module paths).
    """
    token = get_access_token()
    if token is not None and token.client_id:
        return str(token.client_id)
    return None


def init(cfg: Config) -> None:
    global _config
    _config = cfg


def _emit(line: str) -> None:
    path = _config.audit_log_path if _config else None
    if path:
        with _lock:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if _config is not None and _config.unrestricted:
            # Unrestricted bypass stays visible even when a file sink is set.
            print(f"[hyperv-mcp audit] {line}", file=sys.stderr)
    else:
        print(f"[hyperv-mcp audit] {line}", file=sys.stderr)


def log_operation(
    *,
    tool: str,
    vm_name: str = "",
    category: str,
    ok: bool,
    duration_ms: int = 0,
    exit_code: int | None = None,
    error_class: str = "",
    agent_id: object = _UNSET_AGENT,
    request_id: str | None = None,
    job_id: str | None = None,
    relay_id: str | None = None,
) -> None:
    if _config is None:
        return
    r = credentials.redact
    if agent_id is _UNSET_AGENT:
        # Direct/out-of-band callers (e.g. the pre-tool rejection writer) get
        # the same identity resolution as context-managed operations.
        agent_value: str | None = current_agent_id()
    else:
        agent_value = agent_id  # type: ignore[assignment]
    if request_id is None:
        # Generated per call, inside the body — never once per process.
        request_id = uuid.uuid4().hex
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "tool": r(tool),
        "vm_name": r(vm_name),
        "category": r(category),
        "ok": ok,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "error_class": r(error_class),
        "agent_id": agent_value if agent_value is None else r(str(agent_value)),
        "request_id": r(str(request_id)),
        "job_id": job_id if job_id is None else r(str(job_id)),
        "relay_id": relay_id if relay_id is None else r(str(relay_id)),
    }
    _emit(json.dumps(record, ensure_ascii=False))


# The error_class taxonomy lives in errors.classify (isinstance-based) and is
# shared with the tool envelopes, so an audit record's error_class always
# equals the envelope's (issue #9). The former exact-name _TAXONOMY table
# audited subclasses under their verbatim names (e.g. ConsoleError), which
# disagreed with the envelope's "transport".


class operation:  # noqa: N801 - context manager reads like a decorator
    """Context manager that audits a tool operation end to end.

    Guest/transfer tools attach the result outcome before returning:
        op = auditlog.operation(...)
        with op as op:
            result = fn(...)
            op.exit_code = result.get("exit_code")
            op.ok = bool(result.get("ok", True))
            op.error_class = result.get("error_class") or ""

    Correlation (issue #10): pass job_id=/relay_id= at CONSTRUCTION when the
    call addresses a known handle (follow-up tools) — __enter__ never
    overwrites them; start tools instead adopt the ids from the tool result
    after entry. agent_id (authenticated caller, null on stdio/anonymous) and
    request_id (server-generated per call) are resolved inside __enter__ so
    they are per-call, never per-process.
    """

    def __init__(
        self,
        *,
        tool: str,
        vm_name: str = "",
        category: str,
        job_id: str | None = None,
        relay_id: str | None = None,
    ) -> None:
        self.tool = tool
        self.vm_name = vm_name
        self.category = category
        self.start = 0.0
        self.exit_code: int | None = None
        self.ok = True
        self.error_class = ""
        self.job_id = job_id
        self.relay_id = relay_id
        self.agent_id: str | None = None
        self.request_id: str = ""

    def __enter__(self) -> operation:
        self.start = time.monotonic()
        self.agent_id = current_agent_id()
        self.request_id = uuid.uuid4().hex
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        duration_ms = int((time.monotonic() - self.start) * 1000)
        if exc is not None:
            from . import errors  # late import: errors imports policy/media modules

            self.error_class = errors.classify(exc)
        log_operation(
            tool=self.tool,
            vm_name=self.vm_name,
            category=self.category,
            ok=self.ok and exc is None,
            duration_ms=duration_ms,
            exit_code=self.exit_code,
            error_class=self.error_class,
            agent_id=self.agent_id,
            request_id=self.request_id,
            job_id=self.job_id,
            relay_id=self.relay_id,
        )
        return False  # never swallow
