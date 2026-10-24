"""Durable operation handles for long-running tools (issue #24).

The problem this module closes: the slow tools (checkpoint restore: up to
300 s restore + 600 s state wait; stop; guest waits; VM create) returned
their result only as the return value of one blocking MCP call — a client
that timed out, disconnected, or restarted lost the result, a retried call
re-executed the operation, and nothing could answer "what happened since I
last looked". Here every long tool gains `detach` and `idempotency_key`,
durable op rows in the E-01 store back both, the `hyperv_op_status` /
`hyperv_op_result` / `hyperv_op_cancel` / `hyperv_op_list` tools serve the
rows, an append-only `events` table is read through `hyperv_events`, and the
SEP-2663 tasks extension (`io.modelcontextprotocol/tasks`) is served from
the SAME store rows via the mcp 2.3 SDK's Extension framework.

Design invariants (see the trace's 05-fix-plan.md for the reviewed plan):

- Policy, confirm and lease gates run synchronously BEFORE any op row is
  written: a denied call never yields an `op_id` (the guard consult below is
  positioned after the lease gate; the tasks interceptor runs the same gate
  itself before creating a row).
- Secret-free at rest: arguments are stored only as an HMAC-SHA256
  fingerprint (keyed by a key minted once into the store's `meta` table, or
  an operator-supplied env key via `cfg.operations.key_env`); stored results
  pass `credentials.redact` before they are written. No column name carries
  a guardrail-forbidden fragment (`params_hmac` / `idem_key`, mirroring the
  `fencing_seq` rename precedent).
- Crash recovery classifies at READ time through the resolving store's own
  clock: an open-time sweep cannot discriminate stale from fresh heartbeats
  written under a different time base (plan-critic F1), so every read path
  lazily transitions a `working` row whose heartbeat lapsed to
  `failed` / `interrupted` and reports that the VM-side outcome is unknown.
- Agent scoping: rows store the caller identity with an empty-string
  sentinel for an unattributed (stdio) caller, so plain-equality scoping is
  NULL-safe by construction and no caller is exempt from another's
  ownership (a foreign id answers exactly like an unknown id).
- A detached runner holds the VM lock and lease exactly as the synchronous
  call would: it runs the tool body inside a copy of the caller's context
  (auth identity + presented lease ride along), and the body enters
  `auditlog.operation` like any synchronous call, so `vm_lock`'s scope
  resolver and call-row adoption behave identically.
- Cancellation is cooperative: the runner checks `cancel_requested` between
  its phases and the long-running bodies consult `raise_if_cancelled()` at
  their leg boundaries (lifecycle.checkpoint_restore's restore leg and the
  state-wait entry). Killing an in-flight PowerShell child remains
  [Workstream C] PR 2's mechanism, out of scope here.
"""

from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from . import auditlog, errors, leases, pswindows, statestore
from .config import Config

#: The detachable set: every tool whose body can run for minutes. The two
#: wait_* tools have no TOOL_SCOPES entry (no lease gate) but are detachable.
DETACHABLE_TOOLS = frozenset({
    "hyperv_start_vm", "hyperv_stop_vm", "hyperv_reset_vm",
    "hyperv_checkpoint_create", "hyperv_checkpoint_restore",
    "hyperv_checkpoint_remove", "hyperv_wait_vm_state",
    "hyperv_wait_guest_recovery", "hyperv_vm_create",
    "hyperv_guest_run", "hyperv_guest_run_ps",
    "hyperv_guest_put", "hyperv_guest_get",
})

_META_FINGERPRINT_KEY = "ops_fingerprint_key"
_PAGE_CHARS = 16000  # <=64 KiB even at 4 bytes/char (frozen AC6 ceiling)
def store_for(cfg: Config, environ: dict[str, str] | None = None) -> statestore.Store:
    """The store seam. Resolved through the statestore MODULE ATTRIBUTE at
    call time (the leases._store precedent): a test patching
    statestore.store_for reaches every operations call, and the frozen e03
    checks may also rebind this name directly. Binding the function OBJECT
    instead was a real defect: the first emit from a fake-clock test opened a
    real-clock Store on the same database and its first-open lease sweep
    deleted the fake-clock rows."""
    return statestore.store_for(cfg, environ)

#: ContextVars set INSIDE the runner's copied context before the body runs:
#: the cancel hook and nothing else reads them. A synchronous call has none
#: of them set and pays a single .get("") for the check.
_current_op_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "hyperv_current_op_id", default=""
)
_current_ops_cfg: contextvars.ContextVar[object] = contextvars.ContextVar(
    "hyperv_current_ops_cfg", default=None
)


class OperationCancelled(BaseException):
    """Raised inside a tool body when its detached op was cancel-requested.

    Deliberately BaseException (the anyio/asyncio cancellation precedent):
    the body's leg boundaries sit under several `except Exception` envelope
    wrappers (`_run_guest_tool`, per-module error translation), and a
    RuntimeError-derived cancellation would be swallowed into an error
    envelope and reported as a COMPLETED op carrying the refusal. The runner
    catches this class explicitly and transitions the row to cancelled."""

    def __init__(self, op_id: str) -> None:
        super().__init__(f"operation {op_id} was cancelled")
        self.op_id = op_id


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------


def emit(
    cfg: Config,
    kind: str,
    ref_id: str = "",
    vm_id: str = "",
    agent: str | None = None,
    data: dict[str, Any] | None = None,
    store: statestore.Store | None = None,
) -> None:
    """Append one event row. Best-effort and never raising: an event-log
    failure must never break the state transition that emitted it. One call
    per state transition — the append unit the frozen AC9 counts on. The
    payload carries metadata only, never arguments or results."""
    try:
        (store if store is not None else store_for(cfg)).event_append(
            datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            agent if agent is not None else "",
            kind,
            ref_id,
            vm_id,
            json.dumps(data or {}, separators=(",", ":")),
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# fingerprints
# ---------------------------------------------------------------------------

_FINGERPRINT_EXCLUDED = frozenset({
    "username", "password", "lease_id", "fencing_token",
    "idempotency_key", "detach",
})
_key_cache: dict[str, bytes] = {}
_key_cache_lock = threading.Lock()
# Live detached-runner registry (conftest drains it at teardown so a slow
# runner cannot outlive its test's monkeypatches — implementation-review R9).
_runners: dict[str, threading.Thread] = {}
_runners_lock = threading.Lock()


def _fingerprint_key(cfg: Config, store: statestore.Store) -> bytes:
    """The restart-stable HMAC key. `cfg.operations.key_env` names an env var
    carrying operator-supplied key material (wins when set); otherwise a
    token_urlsafe(32) key is minted once into the store's meta table
    (INSERT .. ON CONFLICT DO NOTHING then read, so concurrent first-openers
    converge on one key). Never logged."""
    env_name = (cfg.operations.key_env or "").strip()
    if env_name:
        material = os.environ.get(env_name, "")
        if material:
            return material.encode("utf-8")
    path = store.path
    with _key_cache_lock:
        cached = _key_cache.get(path)
        if cached is not None:
            return cached
    store.meta_put(_META_FINGERPRINT_KEY, secrets.token_urlsafe(32))
    material = store.meta_get(_META_FINGERPRINT_KEY) or ""
    key = material.encode("utf-8")
    with _key_cache_lock:
        _key_cache[path] = key
    return key


def arguments_fingerprint(cfg: Config, store: statestore.Store, arguments: dict) -> str:
    """HMAC-SHA256 over the canonical form of the arguments minus the
    excluded coordination/credential keys."""
    canonical = {
        k: v for k, v in (arguments or {}).items() if k not in _FINGERPRINT_EXCLUDED
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    key = _fingerprint_key(cfg, store)
    return hmac.new(key, blob.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


# ---------------------------------------------------------------------------
# read-time staleness (critic F1)
# ---------------------------------------------------------------------------


def _classify_stale(store: statestore.Store, row: statestore.OpRow, cfg: Config) -> statestore.OpRow:
    """Lazily transition a `working` op whose runner heartbeat lapsed past
    `operations.heartbeat_ttl_s` to failed/interrupted (write-through), and
    return the fresh row. Runs through the RESOLVING store's clock, so it is
    correct under an injected clock and across restarts; a fresh heartbeat
    (another live process) keeps its op working."""
    if row.status != statestore.OP_WORKING or row.heartbeat_at <= 0:
        return row
    if not row.runner:
        # Sync (non-detach) keyed rows have no runner thread to heartbeat:
        # the only process that can complete them is the one serving this
        # read, so a lapsed heartbeat cannot mean "the runner is gone"
        # (implementation-review R6). Their crash residue is retired by the
        # consult-time idempotency-TTL expiry instead.
        return row
    ttl = int(cfg.operations.heartbeat_ttl_s or 60)
    if row.heartbeat_at >= store.now() - ttl:
        return row
    store.op_transition(
        row.op_id, (statestore.OP_WORKING,), statestore.OP_FAILED,
        error_class=statestore.OP_INTERRUPTED, updated_at=store.now(),
    )
    emit(cfg, "op.failed", row.op_id, row.vm_id, row.agent,
         {"error_class": statestore.OP_INTERRUPTED, "reason": "heartbeat_lapsed"})
    fresh = store.op_get(row.op_id)
    return fresh if fresh is not None else row


def _stale_view(row: statestore.OpRow) -> dict[str, Any]:
    """The interrupted payload must note that the VM-side outcome is unknown
    (frozen AC5 asserts a literal 'unknown' marker)."""
    if row.status == statestore.OP_FAILED and row.error_class == statestore.OP_INTERRUPTED:
        return {"vm_outcome": "unknown", "note": "runner heartbeat lapsed; VM-side outcome is unknown"}
    return {}


# ---------------------------------------------------------------------------
# the guard consult (server.py's guard calls this after its gates)
# ---------------------------------------------------------------------------


def guard_consult(
    cfg: Config,
    name: str,
    arguments: dict[str, Any],
    tool_fn: Callable[..., Any],
    runner_slots: Callable[[], threading.BoundedSemaphore],
    preflight: Callable[[], None] | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Idempotency + detach interception for one dispatchable call.

    Returns (response, op_ctx):
    - (None, None): proceed with the synchronous call unchanged.
    - (payload, None): the guard returns `payload` instead of running the
      body — a replay, an idempotency_conflict refusal, a busy refusal, or a
      detach handle.
    - (None, op_ctx): a SYNC call carrying an idempotency_key recorded its op
      row; the guard runs the body and then calls complete_inline/fail_inline
      with the context.

    The caller has already run the unknown-argument guard, the policy gate
    and the lease gate; `preflight` (when given) runs the remaining
    synchronous body gates — SDK argument validation, the destructive
    confirm/category screen, and the VM policy screen for tools outside
    TOOL_SCOPES — BEFORE any op row exists, so a denied call never mints an
    `op_id` (issue constraint; implementation-review R2/R13). A preflight
    refusal propagates to the guard's envelope path. The presented-lease
    ContextVar (if any) is captured into the runner's copied context BEFORE
    the guard's finally resets it.
    """
    if not cfg.operations.enabled or name not in DETACHABLE_TOOLS:
        return None, None
    detach = bool(arguments.get("detach"))
    idem_key = str(arguments.get("idempotency_key") or "")
    if not detach and not idem_key:
        return None, None
    if preflight is not None:
        preflight()

    agent = auditlog.current_agent_id() or ""
    store = store_for(cfg)
    now = store.now()
    fingerprint = arguments_fingerprint(cfg, store, arguments) if idem_key else ""

    # Idempotency consult + record insert run inside ONE transaction so a
    # concurrent retry cannot pass the consult and lose the insert race.
    with store.transaction():
        existing = store.op_find_idem(agent, name, idem_key) if idem_key else None
        if existing is not None:
            # Idempotency-window expiry (operations.idempotency_ttl_s): a
            # working record older than the window cannot belong to any live
            # caller — the creating request or runner is long gone — so it is
            # retired (failed/interrupted semantics would be a lie; the row
            # is simply forgotten) and the retry executes fresh.
            ttl = int(cfg.operations.idempotency_ttl_s or 86400)
            if existing.created_at > 0 and existing.created_at < now - ttl:
                store.op_delete(existing.op_id)
                emit(cfg, "op.expired", existing.op_id, "", agent,
                     {"reason": "idempotency_ttl_lapsed"}, store=store)
                existing = None
        if existing is not None:
            existing = _classify_stale(store, existing, cfg)
            if existing.params_hmac and existing.params_hmac != fingerprint:
                return _conflict_envelope(name, idem_key), None
            return _replay_response(store, existing), None
        if detach:
            slots = runner_slots()
            if not slots.acquire(blocking=False):
                return _busy_envelope(name), None
            row = statestore.OpRow(
                op_id=secrets.token_urlsafe(16),
                tool=name,
                agent=agent,
                vm_name=str(arguments.get("vm_name") or ""),
                status=statestore.OP_WORKING,
                created_at=now,
                updated_at=now,
                runner=secrets.token_hex(8),
                heartbeat_at=now,
                params_hmac=fingerprint,
                idem_key=idem_key,
                poll_interval_ms=2000,
            )
            store.op_insert(row)
            emit(cfg, "op.created", row.op_id, "", agent, {"tool": name, "detached": True})
            _start_runner(cfg, row, dict(arguments), tool_fn, slots)
            return _handle_payload(row), None
        if idem_key:
            row = statestore.OpRow(
                op_id=secrets.token_urlsafe(16),
                tool=name,
                agent=agent,
                vm_name=str(arguments.get("vm_name") or ""),
                status=statestore.OP_WORKING,
                created_at=now,
                updated_at=now,
                runner="",
                heartbeat_at=now,
                params_hmac=fingerprint,
                idem_key=idem_key,
                poll_interval_ms=2000,
            )
            store.op_insert(row)
            emit(cfg, "op.created", row.op_id, "", agent, {"tool": name, "detached": False})
            return None, {"op_id": row.op_id, "cfg": cfg, "agent": agent}
    return None, None


def _replay_response(store: statestore.Store, row: statestore.OpRow) -> dict[str, Any]:
    """The stored result marked `replayed: true` — or, for an op still in
    flight, its live handle marked `replayed: true` (a non-detach retry of a
    detached op re-attaches instead of re-executing; terminal results are
    retrieved through hyperv_op_result)."""
    if row.status == statestore.OP_WORKING:
        return {**_handle_payload(row), "replayed": True}
    stored = row.result_json or ""
    try:
        payload = json.loads(stored)
        if not isinstance(payload, dict):
            payload = {"result": payload}
    except (TypeError, ValueError):
        payload = {"result_text": stored}
    payload["replayed"] = True
    return payload


def _handle_payload(row: statestore.OpRow) -> dict[str, Any]:
    return {
        "op_id": row.op_id,
        "status": row.status,
        "poll_interval_ms": row.poll_interval_ms,
    }


def _conflict_envelope(name: str, idem_key: str) -> dict[str, Any]:
    return errors.enrich_failure({
        "ok": False,
        "error": (
            f"idempotency_key {idem_key!r} was already used for {name} with "
            f"different arguments"
        ),
        "error_class": "idempotency_conflict",
    })


def _busy_envelope(name: str) -> dict[str, Any]:
    env = errors.enrich_failure({
        "ok": False,
        "error": f"{name}: too many detached operations are running",
        "error_class": "busy",
    })
    env["retryable"] = True
    env["retry_after_ms"] = errors.BUSY_RETRY_MS
    return env


def _unknown_op_envelope(op_id: str) -> dict[str, Any]:
    """The refusal for a foreign OR unknown id — identical text for both, so
    ids cannot be confirmed by probing (frozen AC8 compares the signatures)."""
    return errors.enrich_failure({
        "ok": False,
        "error": f"unknown op_id: {op_id}",
        "error_class": "invalid",
    })


def complete_inline(op_ctx: dict[str, Any], result: Any) -> None:
    """Store the synchronous result of a keyed (non-detach) call and close
    its op row. The transition also repairs a row that read-time staleness
    flipped to failed/interrupted mid-call (the finishing request is the
    proof the process lived). Best-effort: a store failure must not alter
    the tool's outcome."""
    try:
        cfg: Config = op_ctx["cfg"]
        agent = str(op_ctx.get("agent") or "")
        store = store_for(cfg)
        text = _result_text(result)
        # Same classification rule as the detached path (review round-2 Q1):
        # a tool-level ok:false envelope is a FAILED op, not a completed one
        # carrying a refusal.
        error_class = ""
        try:
            parsed = json.loads(text) if text.startswith("{") else None
            if isinstance(parsed, dict) and parsed.get("ok") is False:
                error_class = str(parsed.get("error_class") or "transport")
        except ValueError:
            parsed = None
        if error_class:
            store.op_transition(
                op_ctx["op_id"], (statestore.OP_WORKING, statestore.OP_FAILED),
                statestore.OP_FAILED,
                error_class=error_class,
                result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
                updated_at=store.now(),
            )
            emit(cfg, "op.failed", op_ctx["op_id"], "", agent,
                 {"error_class": error_class, "mode": "inline"})
        else:
            store.op_transition(
                op_ctx["op_id"], (statestore.OP_WORKING, statestore.OP_FAILED),
                statestore.OP_COMPLETED,
                result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
                updated_at=store.now(),
            )
            emit(cfg, "op.completed", op_ctx["op_id"], "", agent, {"mode": "inline"})
    except Exception:
        pass


def fail_inline(op_ctx: dict[str, Any], exc: BaseException) -> None:
    try:
        cfg: Config = op_ctx["cfg"]
        agent = str(op_ctx.get("agent") or "")
        store = store_for(cfg)
        env = errors.envelope(exc)
        text = json.dumps(env, separators=(",", ":"))
        store.op_transition(
            op_ctx["op_id"], (statestore.OP_WORKING, statestore.OP_FAILED),
            statestore.OP_FAILED,
            error_class=str(env.get("error_class") or "transport"),
            result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
            updated_at=store.now(),
        )
        emit(cfg, "op.failed", op_ctx["op_id"], "", agent,
             {"error_class": env.get("error_class")})
    except Exception:
        pass


def _result_text(result: Any) -> str:
    """The serialized body of one tool result (CallToolResult or dict)."""
    content = getattr(result, "content", None)
    if content:
        texts = [getattr(block, "text", "") for block in content if getattr(block, "type", "") == "text"]
        if texts:
            return texts[0]
    if isinstance(result, dict):
        return json.dumps(result, separators=(",", ":"), default=str)
    return str(result)


# ---------------------------------------------------------------------------
# the detached runner
# ---------------------------------------------------------------------------


def _start_runner(
    cfg: Config,
    row: statestore.OpRow,
    arguments: dict[str, Any],
    tool_fn: Callable[..., Any],
    runner_slots: threading.BoundedSemaphore,
    store: statestore.Store | None = None,
) -> None:
    """Start one daemon runner thread for a detached op. The caller's context
    is COPIED now (the guard resets the presented-lease ContextVar in its
    finally) so the runner sees the same auth identity and presented lease a
    synchronous call would; the body still enters auditlog.operation, so
    vm_lock's scope resolver and call-row adoption behave identically."""
    captured = contextvars.copy_context()
    body_args = {k: v for k, v in arguments.items() if k not in ("detach", "idempotency_key")}
    presented = ""
    agent = row.agent
    try:
        presented = leases.presented_lease_id()
    except Exception:
        presented = ""
    thread = threading.Thread(
        target=_run_detached,
        args=(captured, cfg, store if store is not None else store_for(cfg),
              row.op_id, tool_fn, body_args, agent, presented, runner_slots),
        name=f"hyperv-op-{row.op_id[:8]}",
        daemon=True,
    )
    with _runners_lock:
        _runners[row.op_id] = thread
    thread.start()


def _run_detached(
    captured: contextvars.Context,
    cfg: Config,
    store: statestore.Store,
    op_id: str,
    tool_fn: Callable[..., Any],
    body_args: dict[str, Any],
    agent: str,
    presented_lease: str,
    runner_slots: threading.BoundedSemaphore,
) -> None:
    # `store` is BOUND AT DETACH TIME on purpose: a runner that outlives its
    # caller (its test's seam rebinds, its process restarts against the same
    # db) must write its completion to the store row it was created against,
    # never re-resolve into whatever store is currently mounted. Writes to a
    # closed store fail and are swallowed by the transition helpers.
    stop = threading.Event()

    def _beat() -> None:
        try:
            store.op_heartbeat(op_id, store.now())
            if presented_lease:
                try:
                    leases.renew(cfg, presented_lease, agent or None)
                except Exception:
                    pass  # a lapsed lease is the lease layer's refusal to give
        except Exception:
            pass  # a missed beat is retried on the next interval
        if not stop.is_set():
            timer = threading.Timer(max(1.0, int(cfg.operations.heartbeat_ttl_s or 60) / 3.0), _beat)
            timer.daemon = True
            timer.start()

    beat_timer = threading.Timer(max(1.0, int(cfg.operations.heartbeat_ttl_s or 60) / 3.0), _beat)
    beat_timer.daemon = True
    beat_timer.start()
    try:
        captured.run(_execute_body, cfg, op_id, tool_fn, body_args, agent, store, stop)
    finally:
        stop.set()
        beat_timer.cancel()
        with _runners_lock:
            _runners.pop(op_id, None)
        try:
            runner_slots.release()
        except ValueError:
            pass


def _safe_transition(
    store: statestore.Store, op_id: str, to_status: str, agent: str, cfg: Config,
    kind: str, *, error_class: str = "", result_json: str | None = None,
    result_size: int = 0,
) -> None:
    """One terminal transition + its event, swallowed when the bound store is
    closed (a runner that outlived its caller) — never resurrects a row that
    recovery already failed, and never raises into the runner's epilogue."""
    try:
        moved = store.op_transition(
            op_id, (statestore.OP_WORKING,), to_status,
            error_class=error_class, result_json=result_json,
            result_size=result_size, updated_at=store.now(),
        )
        if moved:
            emit(cfg, kind, op_id, "", agent,
                 {"error_class": error_class} if error_class else {}, store=store)
    except Exception:
        pass


def _execute_body(
    cfg: Config,
    op_id: str,
    tool_fn: Callable[..., Any],
    body_args: dict[str, Any],
    agent: str,
    store: statestore.Store,
    stop: threading.Event,
) -> None:
    """Runs inside the copied context: sets the cancel-hook ContextVars, then
    drives the body and the terminal transition."""
    _current_op_id.set(op_id)
    _current_ops_cfg.set(cfg)
    try:
        _raise_if_cancelled_locked(cfg, op_id, store)
        result = tool_fn(**body_args)
        text = _result_text(result)
        # A tool-level failure leaves as a NORMAL return carrying the one
        # envelope ({ok: false, error, error_class}) - recording that as
        # `completed` would book a refusal as a success (R11). Any envelope
        # with ok=false is a FAILED op whose stored result is the envelope.
        error_class = ""
        try:
            parsed = json.loads(text) if text.startswith("{") else None
            if isinstance(parsed, dict) and parsed.get("ok") is False:
                error_class = str(parsed.get("error_class") or "transport")
        except ValueError:
            parsed = None
        if error_class:
            _safe_transition(
                store, op_id, statestore.OP_FAILED, agent, cfg, "op.failed",
                error_class=error_class,
                result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
            )
        else:
            _safe_transition(
                store, op_id, statestore.OP_COMPLETED, agent, cfg, "op.completed",
                result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
            )
    except OperationCancelled:
        _safe_transition(store, op_id, statestore.OP_CANCELLED, agent, cfg,
                         "op.cancelled")
    except BaseException as exc:  # noqa: BLE001 — the runner classifies everything
        env = errors.envelope(exc)
        text = json.dumps(env, separators=(",", ":"), default=str)
        _safe_transition(
            store, op_id, statestore.OP_FAILED, agent, cfg, "op.failed",
            error_class=str(env.get("error_class") or "transport"),
            result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
        )


def _raise_if_cancelled_locked(cfg: Config, op_id: str, store: statestore.Store) -> None:
    row = store.op_get(op_id)
    if row is not None and row.cancel_requested and row.status == statestore.OP_WORKING:
        raise OperationCancelled(op_id)


def cfg_config(value: object) -> Config:
    """Narrow the ops ContextVar payload (typed object to avoid a config
    import cycle in the annotation) back to Config."""
    return value  # type: ignore[return-value]


def raise_if_cancelled() -> None:
    """The cooperative-cancel hook long-running bodies call between legs.
    A synchronous call has no op context and returns immediately; a detached
    body raises OperationCancelled at the next leg boundary when its op was
    cancel-requested (the runner transitions the row)."""
    op_id = _current_op_id.get("")
    cfg = _current_ops_cfg.get()
    if not op_id or cfg is None:
        return
    try:
        row = store_for(cfg_config(cfg)).op_get(op_id)
        if row is not None and row.cancel_requested and row.status == statestore.OP_WORKING:
            raise OperationCancelled(op_id)
    except OperationCancelled:
        raise
    except Exception:
        pass


# ---------------------------------------------------------------------------
# the op_* / hyperv_events tool backends
# ---------------------------------------------------------------------------


def _scoped_row(cfg: Config, op_id: str, agent: str) -> statestore.OpRow | None:
    store = store_for(cfg)
    row = store.op_get_scoped(op_id, agent)
    if row is None:
        return None
    return _classify_stale(store, row, cfg)


def op_status(cfg: Config, op_id: str, agent: str) -> dict[str, Any]:
    row = _scoped_row(cfg, op_id, agent)
    if row is None:
        return _unknown_op_envelope(op_id)
    payload = _handle_payload(row)
    payload.update({
        "ok": True,
        "tool": row.tool,
        "error_class": row.error_class,
        "vm_id": row.vm_id,
        "vm_name": row.vm_name,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    })
    payload.update(_stale_view(row))
    return payload


def op_result(cfg: Config, op_id: str, agent: str, cursor: str) -> dict[str, Any]:
    row = _scoped_row(cfg, op_id, agent)
    if row is None:
        return _unknown_op_envelope(op_id)
    if row.status == statestore.OP_WORKING:
        return errors.enrich_failure({
            "ok": False,
            "error": f"op {op_id} is still working; poll hyperv_op_status",
            "error_class": "invalid",
        })
    data = row.result_json or ""
    try:
        offset = (
            int.from_bytes(base64.urlsafe_b64decode(
                cursor.encode("ascii") + b"=" * (-len(cursor) % 4)
            ), "big")
            if cursor else 0
        )
    except Exception:
        return errors.enrich_failure({
            "ok": False, "error": f"invalid cursor: {cursor[:32]}", "error_class": "invalid",
        })
    offset = max(0, min(offset, len(data)))
    chunk = data[offset:offset + _PAGE_CHARS]
    next_offset = offset + len(chunk)
    done = next_offset >= len(data)
    payload: dict[str, Any] = {
        "ok": True,
        "op_id": row.op_id,
        "status": row.status,
        "chunk": chunk,
        "done": done,
    }
    if not done:
        payload["next_cursor"] = base64.urlsafe_b64encode(
            next_offset.to_bytes(8, "big")
        ).decode("ascii").rstrip("=")
    payload.update(_stale_view(row))
    return payload


def op_cancel(cfg: Config, op_id: str, agent: str) -> dict[str, Any]:
    store = store_for(cfg)
    row = _scoped_row(cfg, op_id, agent)
    if row is None:
        return _unknown_op_envelope(op_id)
    if row.status in statestore.OP_TERMINAL_STATES:
        return {
            "ok": True, "op_id": op_id, "status": row.status,
            "error_class": row.error_class if row.status == statestore.OP_FAILED else "",
            "cancel_requested": bool(row.cancel_requested),
        }
    store.op_request_cancel(op_id, agent, store.now())
    fresh = store.op_get_scoped(op_id, agent)
    status = fresh.status if fresh is not None else row.status
    return {"ok": True, "op_id": op_id, "status": status, "cancel_requested": True}


def op_list(cfg: Config, agent: str, include_terminal: bool = False) -> dict[str, Any]:
    store = store_for(cfg)
    rows = [
        _classify_stale(store, row, cfg)
        for row in store.op_rows_by_agent(agent, include_terminal=include_terminal)
    ]
    return {
        "ok": True,
        "ops": [
            {**_handle_payload(row), "tool": row.tool, "error_class": row.error_class,
             "created_at": row.created_at}
            for row in rows
        ],
    }


def _cursor_to_seq(cursor: str) -> int | None:
    if not cursor:
        return 0
    try:
        raw = base64.urlsafe_b64decode(
            cursor.encode("ascii") + b"=" * (-len(cursor) % 4)
        )
        return int.from_bytes(raw, "big")
    except Exception:
        return None


def _seq_to_cursor(seq: int) -> str:
    return base64.urlsafe_b64encode(int(seq).to_bytes(8, "big")).decode("ascii").rstrip("=")


def events_read(cfg: Config, agent: str, after: str, limit: int = 100) -> dict[str, Any]:
    store = store_for(cfg)
    after_seq = _cursor_to_seq(after)
    if after_seq is None:
        return errors.enrich_failure({
            "ok": False, "error": f"invalid cursor: {after[:32]}", "error_class": "invalid",
        })
    oldest = store.events_oldest(agent)
    if after_seq > 0 and oldest is not None and after_seq < oldest:
        return {
            "ok": True,
            "cursor_expired": True,
            "oldest_cursor": _seq_to_cursor(oldest),
        }
    rows = store.events_after(agent, after_seq, limit=max(1, min(int(limit), 1000)))
    parsed = []
    for row in rows:
        try:
            data = json.loads(row["data_json"])
        except (TypeError, ValueError):
            data = {}
        parsed.append({
            "seq": row["seq"], "ts": row["ts"], "kind": row["kind"],
            "ref_id": row["ref_id"], "vm_id": row["vm_id"], "data": data,
        })
    last_seq = rows[-1]["seq"] if rows else after_seq
    return {
        "ok": True,
        "events": parsed,
        "next_cursor": _seq_to_cursor(last_seq),
    }


# ---------------------------------------------------------------------------
# the SEP-2663 tasks bridge (mcp 2.3 Extension framework)
# ---------------------------------------------------------------------------

_TASKS_IDENTIFIER = "io.modelcontextprotocol/tasks"


def _build_task_models() -> tuple[Any, Any, Any, Any, Any]:
    """The flat SEP-2663 wire models. mcp 2.3's own mcp_types task types are
    the removed 2025-11-25 nested shape (types-only, never dispatched), so
    these are hand-built to the extension's wire contract: a tools/call
    answer carrying resultType "task" survives the modern-wire claimed-shape
    carve-out, and tasks/get|cancel return the flat task view with the tool's
    CallToolResult embedded once terminal."""
    from typing import Literal

    from mcp.shared.exceptions import MCPError
    from mcp_types import CallToolResult, RequestParams, Result
    from mcp_types.jsonrpc import INVALID_PARAMS
    from pydantic import Field

    class TaskHandleResult(Result):
        """tools/call answer to a capable client (CreateTaskResult)."""

        result_type: Literal["task"] = "task"
        task_id: str = Field(alias="taskId")
        status: str = statestore.OP_WORKING
        ttl_ms: int | None = Field(default=None, alias="ttlMs")
        poll_interval_ms: int | None = Field(default=None, alias="pollIntervalMs")

    class TaskParams(RequestParams):
        task_id: str = Field(alias="taskId")

    class TaskViewResult(Result):
        """tasks/get | tasks/cancel answer: the live status, with the tool's
        CallToolResult embedded once terminal."""

        task_id: str = Field(alias="taskId")
        status: str = statestore.OP_WORKING
        status_message: str | None = None
        created_at: str | None = None
        last_updated_at: str | None = None
        ttl_ms: int | None = Field(default=None, alias="ttlMs")
        poll_interval_ms: int | None = Field(default=None, alias="pollIntervalMs")
        result: CallToolResult | None = None

    return TaskHandleResult, TaskParams, TaskViewResult, MCPError, INVALID_PARAMS


def tasks_extension(
    cfg: Config,
    gate_fn: Callable[[str, dict], tuple[dict[str, Any] | None, Any]],
    tool_fn_resolver: Callable[[str], Callable[..., Any]],
    runner_slots: Callable[[], threading.BoundedSemaphore],
    preflight_fn: Callable[[str, dict], None] | None = None,
) -> Any:
    """Build the Extension instance the server passes to MCPServer(...).

    `gate_fn` is the server's lease gate (policy + confirm + lease checks run
    synchronously BEFORE any op row is written, exactly as for detach);
    `tool_fn_resolver` returns the raw tool function for the runner. A soft
    per-request capability check decides the task path — never
    require_client_extension, whose -32021 would answer a client that simply
    did not ask for tasks (frozen AC13)."""
    from mcp.server.extension import Extension, MethodBinding
    from mcp.types import TextContent
    from mcp_types import CallToolResult

    TaskHandleResult, TaskParams, TaskViewResult, MCPError, INVALID_PARAMS = _build_task_models()

    class TasksExtension(Extension):
        identifier = _TASKS_IDENTIFIER

        def settings(self) -> dict[str, Any]:
            return {}

        def _capable(self, ctx: Any) -> bool:
            try:
                caps = ctx.session.client_capabilities
                return bool(caps and getattr(caps, "extensions", None)
                            and _TASKS_IDENTIFIER in caps.extensions)
            except Exception:
                return False

        async def intercept_tool_call(self, params: Any, ctx: Any, call_next: Any) -> Any:
            if not cfg.operations.enabled or params.name not in DETACHABLE_TOOLS:
                return await call_next(ctx)
            if not self._capable(ctx):
                return await call_next(ctx)
            arguments = dict(params.arguments or {})
            env, reset = gate_fn(params.name, arguments)
            if env is not None:
                # Gate refusal is an ordinary tool-envelope answer, never -32021.
                return errors.failure_result(env)
            if preflight_fn is not None:
                try:
                    preflight_fn(params.name, arguments)
                except Exception as exc:
                    # Synchronous body-gate refusal BEFORE any op row
                    # (implementation-review R2/R13) - an ordinary envelope.
                    return errors.failure_result(errors.envelope(exc))
            # Runner admission (R4): symmetric with the guard path - excess
            # detached calls are refused retryable-busy, never queued.
            slots = runner_slots()
            if not slots.acquire(blocking=False):
                return errors.failure_result(_busy_envelope(params.name))
            released = False
            try:
                agent = auditlog.current_agent_id() or ""
                store = store_for(cfg)
                now = store.now()
                idem_key = str(arguments.get("idempotency_key") or "")
                fingerprint = (
                    arguments_fingerprint(cfg, store, arguments) if idem_key else ""
                )
                # Idempotency consult + insert in one transaction (R5): a
                # keyed retry re-attaches to the live task instead of
                # re-executing the mutation.
                with store.transaction():
                    existing = (
                        store.op_find_idem(agent, params.name, idem_key)
                        if idem_key else None
                    )
                    if existing is not None:
                        ttl = int(cfg.operations.idempotency_ttl_s or 86400)
                        if existing.created_at > 0 and existing.created_at < now - ttl:
                            store.op_delete(existing.op_id)
                            emit(cfg, "op.expired", existing.op_id, "", agent,
                                 {"reason": "idempotency_ttl_lapsed"}, store=store)
                            existing = None
                    if existing is not None:
                        existing = _classify_stale(store, existing, cfg)
                        if existing.params_hmac and existing.params_hmac != fingerprint:
                            # Release the admission slot BEFORE the refusal:
                            # the conflict path starts no runner, and a leaked
                            # permit erodes BOTH routes forever (review F1).
                            slots.release()
                            released = True
                            return errors.failure_result(
                                _conflict_envelope(params.name, idem_key))
                        slots.release()
                        released = True
                        return TaskHandleResult(
                            task_id=existing.op_id,
                            status=existing.status,
                            ttl_ms=int(cfg.operations.retention_s) * 1000,
                            poll_interval_ms=existing.poll_interval_ms,
                        )
                    row = statestore.OpRow(
                        op_id=secrets.token_urlsafe(16),
                        tool=params.name,
                        agent=agent,
                        vm_name=str(arguments.get("vm_name") or ""),
                        status=statestore.OP_WORKING,
                        created_at=now,
                        updated_at=now,
                        runner=secrets.token_hex(8),
                        heartbeat_at=now,
                        params_hmac=fingerprint,
                        idem_key=idem_key,
                        poll_interval_ms=2000,
                    )
                    # Durable creation BEFORE the response (SEP-2663: MUST NOT
                    # return CreateTaskResult until the task is durably created).
                    store.op_insert(row)
                emit(cfg, "op.created", row.op_id, "", agent,
                     {"tool": params.name, "detached": True, "tasks": True})
                _start_runner(cfg, row, arguments, tool_fn_resolver(params.name), slots)
                return TaskHandleResult(
                    task_id=row.op_id,
                    status=statestore.OP_WORKING,
                    ttl_ms=int(cfg.operations.retention_s) * 1000,
                    poll_interval_ms=row.poll_interval_ms,
                )
            except Exception:
                if not released:
                    try:
                        slots.release()
                    except ValueError:
                        pass
                raise
            finally:
                if reset is not None:
                    leases.reset_presented_lease(reset)

        def _view(self, ctx: Any, task_id: str, embed_result: bool) -> Any:
            agent = auditlog.current_agent_id() or ""
            store = store_for(cfg)
            row = store.op_get_scoped(task_id, agent)
            if row is not None:
                row = _classify_stale(store, row, cfg)
            if row is None:
                # A foreign id answers exactly like an unknown id (AC15).
                raise MCPError(
                    code=INVALID_PARAMS,
                    message=f"unknown taskId: {task_id}",
                )
            view = TaskViewResult(
                task_id=row.op_id,
                status=row.status,
                created_at=datetime.fromtimestamp(row.created_at, tz=timezone.utc).isoformat(timespec="milliseconds")
                if row.created_at else None,
                last_updated_at=datetime.fromtimestamp(row.updated_at, tz=timezone.utc).isoformat(timespec="milliseconds")
                if row.updated_at else None,
                ttl_ms=int(cfg.operations.retention_s) * 1000,
                poll_interval_ms=row.poll_interval_ms,
            )
            if row.status == statestore.OP_FAILED and row.error_class == statestore.OP_INTERRUPTED:
                view.status_message = "interrupted: runner heartbeat lapsed; VM-side outcome is unknown"
            elif row.error_class:
                view.status_message = row.error_class
            if embed_result and row.result_json:
                view.result = CallToolResult(
                    content=[TextContent(text=row.result_json)],
                    is_error=row.status == statestore.OP_FAILED,
                )
            return view

        def methods(self) -> list[Any]:
            async def get_task(ctx: Any, params: Any) -> Any:
                return self._view(ctx, params.task_id, embed_result=True)

            async def cancel_task(ctx: Any, params: Any) -> Any:
                agent = auditlog.current_agent_id() or ""
                store = store_for(cfg)
                row = store.op_get_scoped(params.task_id, agent)
                if row is not None:
                    row = _classify_stale(store, row, cfg)
                if row is None:
                    raise MCPError(code=INVALID_PARAMS, message=f"unknown taskId: {params.task_id}")
                if row.status in statestore.OP_TERMINAL_STATES:
                    return self._view(ctx, params.task_id, embed_result=True)
                store.op_request_cancel(params.task_id, agent, store.now())
                return self._view(ctx, params.task_id, embed_result=False)

            async def update_task(ctx: Any, params: Any) -> Any:
                # This server never enters input_required; any update is a
                # JSON-RPC invalid-params error (frozen AC14).
                raise MCPError(code=INVALID_PARAMS, message="tasks/update is not supported for this server's tasks")

            return [
                MethodBinding(method="tasks/get", params_type=TaskParams, handler=get_task,
                              protocol_versions=frozenset({"2026-07-28"})),
                MethodBinding(method="tasks/cancel", params_type=TaskParams, handler=cancel_task,
                              protocol_versions=frozenset({"2026-07-28"})),
                MethodBinding(method="tasks/update", params_type=TaskParams, handler=update_task,
                              protocol_versions=frozenset({"2026-07-28"})),
            ]

    return TasksExtension()


def drain_for_tests(timeout_s: float = 5.0) -> int:
    """Wait (bounded) for live detached runners so a test teardown never
    races one past its own monkeypatches. Returns the number still running
    after the timeout — a runner blocked on a real child cannot be forced;
    the test's own gating Events remain the authoritative release."""
    with _runners_lock:
        threads = list(_runners.values())
    deadline = time.monotonic() + timeout_s
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    with _runners_lock:
        return len(_runners)


def reset_for_tests() -> None:
    """Drop every process-local cache (the conftest bootstrap-restore fixture
    calls this so one test's fingerprint key never serves another's store)."""
    with _key_cache_lock:
        _key_cache.clear()
