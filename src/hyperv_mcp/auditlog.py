"""Structured, secret-safe audit logging for hyperv-mcp.

One JSON object per operation: timestamp, tool, vm_name, category, ok,
duration_ms, exit_code, error_class. Command content, file content and
credentials are NEVER logged; all string fields pass the redaction filter.

Sink: audit_log_path from config (JSONL, appended). When unset, a compact
one-line summary goes to stderr. When the server runs in unrestricted mode,
the stderr line is forced on so the bypass stays visible.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Literal

from . import credentials
from .config import Config

_lock = threading.Lock()
_config: Config | None = None


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
) -> None:
    if _config is None:
        return
    r = credentials.redact
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "tool": r(tool),
        "vm_name": r(vm_name),
        "category": r(category),
        "ok": ok,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "error_class": r(error_class),
    }
    _emit(json.dumps(record, ensure_ascii=False))


# Documented error_class taxonomy. Exception class names not listed here pass
# through unchanged (they indicate a bug worth surfacing verbatim).
_TAXONOMY = {
    "PolicyDenied": "policy",
    "CredentialError": "credential",
    "VMBusy": "busy",
    "ValueError": "invalid",
    "TimeoutError": "timeout",
    "RuntimeError": "transport",
}


class operation:  # noqa: N801 - context manager reads like a decorator
    """Context manager that audits a tool operation end to end.

    Guest/transfer tools attach the result outcome before returning:
        op = auditlog.operation(...)
        with op as op:
            result = fn(...)
            op.exit_code = result.get("exit_code")
            op.ok = bool(result.get("ok", True))
            op.error_class = result.get("error_class") or ""
    """

    def __init__(self, *, tool: str, vm_name: str = "", category: str) -> None:
        self.tool = tool
        self.vm_name = vm_name
        self.category = category
        self.start = 0.0
        self.exit_code: int | None = None
        self.ok = True
        self.error_class = ""

    def __enter__(self) -> operation:
        self.start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        duration_ms = int((time.monotonic() - self.start) * 1000)
        if exc is not None:
            self.error_class = _TAXONOMY.get(
                type(exc).__name__, type(exc).__name__
            )
        log_operation(
            tool=self.tool,
            vm_name=self.vm_name,
            category=self.category,
            ok=self.ok and exc is None,
            duration_ms=duration_ms,
            exit_code=self.exit_code,
            error_class=self.error_class,
        )
        return False  # never swallow
