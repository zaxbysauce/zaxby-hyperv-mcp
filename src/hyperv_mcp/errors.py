"""One error taxonomy shared by tool envelopes and the audit log.

Issue #9: every tool failure returns one envelope
{ok: false, error, error_class, retryable, retry_after_ms} delivered as a
CallToolResult with isError=true, classified by the SAME isinstance-based
function the audit log uses, so the audit record and the envelope can never
disagree.

Most-specific first. MediaError maps to "invalid" explicitly (PRR-020: its
faults are caller/vm-state faults — missing ISO, Gen1 VM, verify mismatch —
not transport); that is a documented divergence from the issue's taxonomy
sketch, pinned by tests/unit/test_errors_taxonomy.py.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.types import CallToolResult, TextContent

from . import policy
from .credentials import CredentialError
from .media import MediaError
from .vmlocks import VMBusy

__all__ = [
    "BUSY_RETRY_MS",
    "classify",
    "enrich_failure",
    "envelope",
    "failure_result",
    "retry_fields",
    "success_result",
]

# Fixed guidance until [Workstream C] PR 1 replaces it with holder-derived
# retry_after_ms. `timeout` is deliberately NOT retryable for guest
# execution: the host killed its process tree but the guest-side child may
# still be running (README "Timeout semantics").
BUSY_RETRY_MS = 2000


def classify(exc: BaseException) -> str:
    """Map an exception to the documented error_class taxonomy.

    isinstance-based, most-specific first. Unknown exception types default
    to "transport" (generic failure) so the catch-all envelope and the
    audit record always agree.
    """
    if isinstance(exc, policy.PolicyDenied):
        return "policy"
    if isinstance(exc, CredentialError):
        return "credential"
    if isinstance(exc, VMBusy):
        return "busy"
    if isinstance(exc, MediaError):
        # PRR-020: caller/vm-state faults, not transport — matches the
        # shipped envelope contract (test_media_error_envelope_maps_invalid).
        return "invalid"
    if isinstance(exc, ValueError):
        return "invalid"
    if isinstance(exc, TimeoutError):
        return "timeout"
    return "transport"


def retry_fields(error_class: str) -> tuple[bool, int | None]:
    """Retry guidance for an error class: (retryable, retry_after_ms)."""
    if error_class == "busy":
        return True, BUSY_RETRY_MS
    return False, None


def _redact(text: str) -> str:
    from . import pswindows  # late import: avoids import-order coupling

    return pswindows.redact(text)


def envelope(exc: BaseException) -> dict[str, Any]:
    """Build the failure envelope for a raised exception."""
    error_class = classify(exc)
    retryable, retry_after_ms = retry_fields(error_class)
    return {
        "ok": False,
        "error": _redact(str(exc)),
        "error_class": error_class,
        "retryable": retryable,
        "retry_after_ms": retry_after_ms,
    }


def enrich_failure(env: dict[str, Any]) -> dict[str, Any]:
    """Add retry guidance to a module-built ok:false result dict.

    Module-level envelopes keep their own error_class (never reclassified);
    a dict missing one defaults to "transport". The five envelope keys are
    the minimum set — module diagnostics (timed_out, stopped, ...) ride
    along unchanged.
    """
    out = dict(env)
    error_class = str(out.get("error_class") or "transport")
    out["error_class"] = error_class
    retryable, retry_after_ms = retry_fields(error_class)
    out["retryable"] = retryable
    out["retry_after_ms"] = retry_after_ms
    return out


def failure_result(env: dict[str, Any]) -> CallToolResult:
    """Deliver a failure envelope with isError=true.

    FastMCP passes a returned CallToolResult through verbatim
    (func_metadata.convert_result), so this is the only mechanism by which
    a failure is visible at the protocol level.
    """
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(env))],
        structuredContent=env,
        isError=True,
    )


def success_result(blocks: list[Any]) -> CallToolResult:
    """Wrap a success payload's content blocks (isError=false).

    Blocks already carrying content types (ImageContent/TextContent) pass
    through; plain dicts (metadata sidecars, VM rows) each become one
    TextContent serialized with the same pydantic_core.to_json form
    func_metadata._convert_to_content uses, so the wire content is
    byte-identical to the converted-list delivery on every interpreter.
    """
    from pydantic_core import to_json

    content: list[Any] = []
    for block in blocks:
        if isinstance(block, dict):
            content.append(
                TextContent(
                    type="text",
                    text=to_json(block, fallback=str, indent=2).decode(),
                )
            )
        else:
            content.append(block)
    return CallToolResult(content=content, structuredContent=None, isError=False)
