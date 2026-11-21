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

from . import admission, auditlog, errors, evidencejournal, leases, pswindows, statestore
from .config import Config

#: The detachable set: every tool whose body can run for minutes. The two
#: wait_* tools have no TOOL_SCOPES entry (no lease gate) but are detachable.
DETACHABLE_TOOLS = frozenset({
    "hyperv_start_vm", "hyperv_stop_vm", "hyperv_reset_vm",
    "hyperv_checkpoint_create", "hyperv_checkpoint_restore",
    "hyperv_checkpoint_remove", "hyperv_wait_vm_state",
    "hyperv_wait_guest_recovery", "hyperv_vm_create", "hyperv_vm_remove",
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
# Issue #157: the executor generation captured IMMUTABLY at row creation and
# threaded through the runner / inline dispatch; every generation-validated
# store write (terminal transitions, heartbeats, send marks, idem releases,
# the pre-send commit) reads THIS value, never the row's current generation
# (a re-read would let a fenced executor borrow its replacement's authority).
# Default 0 = the legacy/direct shape (a row with generation 0 validates).
_current_op_generation: contextvars.ContextVar[int] = contextvars.ContextVar(
    "hyperv_current_op_generation", default=0
)

# The per-resource send gate (issue #157, plan rounds 2-4): route-layer-owned,
# one canonical order (send gate -> VM lock -> provider submission). Keyed by
# the casefolded first-present identity argument (vm_name / name / vm_id) so
# a different resource always progresses; the inline (async) route acquires
# NON-blocking and answers a retryable busy envelope on contention, runner
# threads acquire blocking.
_SEND_GATES: dict[str, threading.Lock] = {}
_SEND_GATES_LOCK = threading.Lock()


def _send_gate_key(arguments: dict[str, Any]) -> str:
    for k in ("vm_name", "name", "vm_id"):
        value = str(arguments.get(k) or "")
        if value:
            return value.casefold()
    return ""


def _send_gate_acquire(arguments: dict[str, Any], blocking: bool = False) -> bool:
    """True = acquired; False = contended (non-blocking callers answer busy).

    Runner threads pass blocking=True (the plan's canonical order holds the
    gate until the pre-send commit completes; a same-VM runner waits its turn
    instead of failing); the async keyed-inline caller passes blocking=False
    and answers the retryable busy envelope on contention, never blocking the
    event loop."""
    key = _send_gate_key(arguments)
    with _SEND_GATES_LOCK:
        lock = _SEND_GATES.get(key)
        if lock is None:
            lock = threading.Lock()
            _SEND_GATES[key] = lock
    return lock.acquire(blocking=blocking)


def _send_gate_release(arguments: dict[str, Any]) -> None:
    key = _send_gate_key(arguments)
    with _SEND_GATES_LOCK:
        lock = _SEND_GATES.get(key)
    if lock is not None:
        try:
            lock.release()
        except RuntimeError:
            pass


def commit_send_intent(cfg: Config, vm_key: str = "") -> None:
    """The durable pre-send commit (issue #157). ONE transaction: when an op
    context exists, generation-validates and sets send_state='possibly_sent'
    (fail-closed on fence movement); with no op context this is the unkeyed
    epoch-only commit. A VM key turns the commit into the restore barrier's
    atomic possibly_sent + dirty-epoch pair. Raises before any provider
    submission when the commit fails — keyed AND unkeyed alike (the
    epoch-only barrier of a direct restore is equally mandatory)."""
    op_id = _current_op_id.get("")
    if not op_id:
        if vm_key:
            # Issue #157 fail-closed (impl-review round-2): the unkeyed
            # restore barrier commits the dirty epoch with NO suppression —
            # a failed epoch write propagates so the provider submission
            # (Restore-VMSnapshot) never runs without its durable barrier.
            store_for(cfg).epoch_bump(vm_key)
        return
    generation = _current_op_generation.get(0)
    try:
        store = store_for(cfg)
        if vm_key:
            moved = store.op_mark_send_and_dirty_epoch(op_id, generation, vm_key)
        else:
            moved = store.op_mark_send(op_id, generation)
        if not moved:
            raise RuntimeError(
                f"operation {op_id} lost send authority (generation fence moved)"
            )
    except RuntimeError:
        raise
    # Issue #157 fail-closed (impl-review F1): ANY inability to durably commit
    # the mark or epoch propagates — a provider submission never follows an
    # unrecorded send intent.


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
    (another live process) keeps its op working.

    Issue #157: a possibly_sent row whose heartbeat lapsed is the lost-reply
    case — it transitions to failed with error_class `unknown` (the protected,
    attachable unresolved identity), NOT `interrupted`. A `sync-` prefixed
    runner (a keyed inline row) is exempt ONLY while it is not possibly_sent:
    its serving request was its heartbeat (design decision R6), but once the
    send commit landed a lapsed heartbeat genuinely means the executor is gone."""
    if row.status != statestore.OP_WORKING or row.heartbeat_at <= 0:
        return row
    possibly_sent = (getattr(row, "send_state", "") or "") == "possibly_sent"
    if not row.runner and not possibly_sent:
        # Sync (non-detach) keyed rows with no send commit have no runner
        # thread to heartbeat: the only process that can complete them is the
        # one serving this read, so a lapsed heartbeat cannot mean "the runner
        # is gone" (implementation-review R6). Their crash residue is retired
        # by the consult-time idempotency-TTL expiry instead.
        return row
    if row.runner.startswith("sync-") and not possibly_sent:
        # Issue #157: a keyed inline row records an execution owner but its
        # inline beat keeps the heartbeat fresh while the request lives; the
        # lapsed case is the crashed-inline arm handled below. Unmarked
        # sync- rows keep the R6 exemption.
        return row
    ttl = int(cfg.operations.heartbeat_ttl_s or 60)
    if row.heartbeat_at >= store.now() - ttl:
        return row
    if possibly_sent:
        error_class = statestore.OP_UNKNOWN
        reason = "send_committed_lost_reply"
    else:
        error_class = statestore.OP_INTERRUPTED
        reason = "heartbeat_lapsed"
    store.op_transition(
        row.op_id, (statestore.OP_WORKING,), statestore.OP_FAILED,
        error_class=error_class, updated_at=store.now(),
    )
    emit(cfg, "op.failed", row.op_id, row.vm_id, row.agent,
         {"error_class": error_class, "reason": reason})
    fresh = store.op_get(row.op_id)
    return fresh if fresh is not None else row


def _stale_view(row: statestore.OpRow) -> dict[str, Any]:
    """The interrupted payload must note that the VM-side outcome is unknown
    (frozen AC5 asserts a literal 'unknown' marker)."""
    if row.status == statestore.OP_FAILED and row.error_class == statestore.OP_INTERRUPTED:
        return {"vm_outcome": "unknown", "note": "runner heartbeat lapsed; VM-side outcome is unknown"}
    if row.status == statestore.OP_FAILED and (
        row.error_class == statestore.OP_UNKNOWN
        or (getattr(row, "send_state", "") or "") == "possibly_sent"
    ):
        # Issue #157 (final critic F1/PB): ANY failed row still carrying the
        # send mark is a post-send ambiguity - the provider may have committed
        # before the failure - so the view discloses the unknown outcome.
        return {"vm_outcome": "unknown",
                "note": ("send committed; reply lost; outcome unknown; the "
                         "identity stays protected until trusted reconciliation")}
    if row.status == statestore.OP_CANCELLED and (
        getattr(row, "send_state", "") or ""
    ) == "possibly_sent":
        return {"vm_outcome": "unknown",
                "note": ("cancel honored after the send commit; VM-side "
                         "outcome unknown; the send mark stays set")}
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
    journal_token: Any = None,
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
            # Idempotency-window expiry (operations.idempotency_ttl_s), with
            # the issue #157 retention arms: a possibly_sent row is NEVER
            # age-deleted (it is classified — the lost-reply unknown — and
            # answered as a protected attach), and a row with a FRESH
            # heartbeat is answered live regardless of age (a live handle is
            # kept through completion "regardless of replay age"). Only a
            # resolved row past the window is forgotten so the retry executes
            # fresh — the documented window end.
            ttl = int(cfg.operations.idempotency_ttl_s or 86400)
            heartbeat_fresh = (
                existing.heartbeat_at > 0
                and existing.heartbeat_at >= now - int(
                    cfg.operations.heartbeat_ttl_s or 60
                )
            )
            possibly_sent = (
                getattr(existing, "send_state", "") or ""
            ) == "possibly_sent"
            protected_class = existing.error_class in (
                statestore.OP_INTERRUPTED, statestore.OP_UNKNOWN
            )
            if (
                existing.created_at > 0
                and existing.created_at < now - ttl
                and not possibly_sent
                and not heartbeat_fresh
                and not protected_class
            ):
                existing = _classify_stale(store, existing, cfg)
                if existing.status == statestore.OP_WORKING:
                    # Still working (a no-runner exempt row): fence it before
                    # the replacement so the retired executor's late writes
                    # become no-ops (issue #157 authority transfer).
                    try:
                        store.op_fence(existing.op_id)
                    except Exception:
                        pass
                store.op_delete(existing.op_id)
                emit(cfg, "op.expired", existing.op_id, "", agent,
                     {"reason": "idempotency_ttl_lapsed"}, store=store)
                existing = None
        if existing is not None:
            existing = _classify_stale(store, existing, cfg)
            if existing.params_hmac and existing.params_hmac != fingerprint:
                return _conflict_envelope(name, idem_key), None
            if not existing.params_hmac and fingerprint:
                # Issue #157 (C8b): a legacy row with a BLANK fingerprint and
                # different arguments is protected reconciliation — a disclosed
                # refusal naming the original handle, never a silent reattach,
                # never a re-dispatch.
                return errors.enrich_failure({
                    "ok": False,
                    "error": (
                        f"idempotency_key {idem_key!r} matches a legacy record "
                        f"(handle {existing.op_id}) whose argument fingerprint "
                        f"predates fingerprinting; reconciliation is required "
                        f"before reuse — re-run with a new idempotency_key"
                    ),
                    "error_class": "idempotency_conflict",
                    "reconciliation": True,
                    "op_id": existing.op_id,
                }), None
            if (
                existing.status == statestore.OP_FAILED
                and existing.error_class == statestore.OP_UNKNOWN
            ):
                # Protected recovery of an unresolved identity (issue #157):
                # fence the lost executor before answering so its late writes
                # cannot re-authorize (the replacement demonstrably fences).
                try:
                    store.op_fence(existing.op_id)
                except Exception:
                    pass
            return _replay_response(store, existing), None
        if detach:
            slots = runner_slots()
            if not slots.acquire(blocking=False):
                return _busy_envelope(name), None
            row = None
            try:
                # Issue #157 (impl-review F6): everything after the acquire —
                # INCLUDING generation minting — sits inside the protected
                # region, so any failure releases the slot exactly once.
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
                    generation=store.op_next_generation(),
                )
                store.op_insert(row)
                emit(cfg, "op.created", row.op_id, "", agent,
                     {"tool": name, "detached": True})
                _start_runner(cfg, row, dict(arguments), tool_fn, slots,
                              journal_token=journal_token)
            except Exception:
                # Issue #157 (C1/C10): the reservation is exception-safe — the
                # slot is released exactly once, the stranded working row is
                # removed (the transaction rolled the insert back on insert
                # failure; a start failure deletes the inserted row), and the
                # guard answers the classified refusal envelope instead of
                # letting a raw store/transport exception escape.
                slots.release()
                if row is not None:
                    try:
                        store.op_delete(row.op_id)
                    except Exception:
                        pass
                env = errors.enrich_failure({
                    "ok": False,
                    "error": (
                        f"{name}: the detached operation could not be recorded "
                        f"or started; no dispatch authority was left behind — "
                        f"retry after fixing the durable-state fault"
                    ),
                    "error_class": "transport",
                })
                env["retryable"] = True
                env["retry_after_ms"] = errors.BUSY_RETRY_MS
                return env, None
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
                # Issue #157 (C2): the inline route records a non-empty
                # execution owner (the sync- prefix keeps the R6 staleness
                # exemption for unmarked rows) and a minted generation.
                runner="sync-" + secrets.token_hex(8),
                heartbeat_at=now,
                params_hmac=fingerprint,
                idem_key=idem_key,
                poll_interval_ms=2000,
                generation=store.op_next_generation(),
            )
            store.op_insert(row)
            emit(cfg, "op.created", row.op_id, "", agent, {"tool": name, "detached": False})
            return None, {
                "op_id": row.op_id,
                "cfg": cfg,
                "agent": agent,
                "generation": row.generation,
            }
    return None, None


def _replay_response(store: statestore.Store, row: statestore.OpRow) -> dict[str, Any]:
    """The stored result marked `replayed: true` — or, for an op still in
    flight, its live handle marked `replayed: true` (a non-detach retry of a
    detached op re-attaches instead of re-executing; terminal results are
    retrieved through hyperv_op_result).

    Issue #157 branch ORDER: an unknown (lost-reply) row is answered with the
    unknown disclosure FIRST — it is never mislabeled as an ordinary payload
    expiry; a terminal row whose payload was pruned (identity tombstone) is
    answered with the ORIGINAL handle plus the explicit result-expired
    disclosure instead of a fresh dispatch."""
    if row.status == statestore.OP_WORKING:
        return {**_handle_payload(row), "replayed": True}
    if row.error_class == statestore.OP_UNKNOWN or (
        row.status == statestore.OP_CANCELLED
        and (getattr(row, "send_state", "") or "") == "possibly_sent"
    ):
        # Issue #157 (final critic F5): a cancelled possibly_sent row keeps
        # its unknown disclosure on the replay view - never mislabeled as an
        # ordinary payload expiry.
        payload = {
            **_handle_payload(row),
            "replayed": True,
            "vm_outcome": "unknown",
            "note": ("send committed; reply lost; outcome unknown; the identity "
                     "stays protected until trusted reconciliation"),
        }
        return payload
    stored = row.result_json or ""
    if not stored:
        return {
            **_handle_payload(row),
            "replayed": True,
            "result_expired": True,
            "note": ("result payload pruned within the replay window; the "
                     "original handle stays addressable"),
        }
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
    the tool's outcome. Issue #157: the completion carries the captured
    generation (a fenced executor's write is a no-op) and — because a
    successful result is a definitive outcome — the COMPLETED move clears
    send_state in the store."""
    try:
        cfg: Config = op_ctx["cfg"]
        agent = str(op_ctx.get("agent") or "")
        generation = int(op_ctx.get("generation") or 0) or None
        store = store_for(cfg)
        text = _result_text(result)
        # Same classification rule as the detached path (review round-2 Q1):
        # a tool-level ok:false envelope is a FAILED op, not a completed one
        # carrying a refusal. Issue #157: this is a DEFINITIVE outcome with
        # its envelope in hand, so the failed move clears send_state via
        # pre_body_terminal (the result proves what happened — this is not a
        # post-send ambiguity).
        error_class = ""
        try:
            parsed = json.loads(text) if text.startswith("{") else None
            if isinstance(parsed, dict) and parsed.get("ok") is False:
                error_class = str(parsed.get("error_class") or "transport")
        except ValueError:
            parsed = None
        if error_class:
            # Issue #157 (impl-review F8 + final critic F1/PB): a tool-level
            # ok:false envelope is a BODY outcome — in-body provenance RETAINS
            # the send mark (an envelope does not prove the provider never
            # acted), and the stored envelope discloses the unknown VM-side
            # outcome so retries/replays carry it.
            row = store.op_get(op_ctx["op_id"])
            if row is not None and (getattr(row, "send_state", "") or "") == "possibly_sent":
                try:
                    parsed_env = json.loads(text) if text.startswith("{") else None
                    if isinstance(parsed_env, dict) and "vm_outcome" not in parsed_env:
                        parsed_env["vm_outcome"] = "unknown"
                        parsed_env["note"] = (
                            "send committed before the failure; outcome unknown; "
                            "the identity stays protected"
                        )
                        text = json.dumps(parsed_env, separators=(",", ":"),
                                          default=str, ensure_ascii=False)
                except ValueError:
                    pass
            store.op_transition(
                op_ctx["op_id"], (statestore.OP_WORKING, statestore.OP_FAILED),
                statestore.OP_FAILED,
                error_class=error_class,
                result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
                updated_at=store.now(), generation=generation,
            )
            emit(cfg, "op.failed", op_ctx["op_id"], "", agent,
                 {"error_class": error_class, "mode": "inline"})
        else:
            store.op_transition(
                op_ctx["op_id"], (statestore.OP_WORKING, statestore.OP_FAILED),
                statestore.OP_COMPLETED,
                result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
                updated_at=store.now(), generation=generation,
            )
            emit(cfg, "op.completed", op_ctx["op_id"], "", agent, {"mode": "inline"})
    except Exception:
        pass


def reconcile_interrupted_commit(op_ctx: dict[str, Any], exc: BaseException) -> None:
    """Issue #157 (delta review R8-1): a BaseException escaping the route's
    pre-send commit window reconciles the attempt according to its durable
    send provenance before the interruption propagates. The keyed commit is
    the pre-send boundary: if the possibly_sent mark did NOT land, nothing
    was dispatched — the definitive pre-send refusal (terminal failed,
    interrupted). If the mark DID land (the crash came after the commit),
    the row keeps the protected unknown identity and self-reconciles at
    read time via the lapsed-heartbeat arm. Best-effort: a store failure
    must never mask the in-flight interruption."""
    try:
        cfg: Config = op_ctx["cfg"]
        store = store_for(cfg)
        row = store.op_get(op_ctx["op_id"])
        if row is None or row.status != statestore.OP_WORKING:
            return
        if (getattr(row, "send_state", "") or "") == "possibly_sent":
            return
        env = errors.envelope(exc)
        env["note"] = "interrupted before the send commit; nothing was dispatched"
        text = json.dumps(env, separators=(",", ":"))
        store.op_transition(
            op_ctx["op_id"], (statestore.OP_WORKING,), statestore.OP_FAILED,
            error_class=statestore.OP_INTERRUPTED,
            result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
            updated_at=store.now(),
            generation=int(op_ctx.get("generation") or 0) or None,
            pre_body_terminal=True,
        )
        emit(cfg, "op.failed", op_ctx["op_id"], "",
             str(op_ctx.get("agent") or ""),
             {"error_class": statestore.OP_INTERRUPTED})
    except Exception:
        pass


def fail_inline(op_ctx: dict[str, Any], exc: BaseException) -> None:
    """Issue #157: the failing arm's outcome carries its send-state
    provenance. A raise BEFORE the body started (send_state still empty) is
    the definitive pre-send refusal — it clears the mark. A raise AFTER the
    pre-send commit (send_state == possibly_sent) is a post-send ambiguity
    even though errors.envelope serializes a result payload — the row keeps
    its mark and carries error_class unknown, staying a protected attachable
    identity."""
    try:
        cfg: Config = op_ctx["cfg"]
        agent = str(op_ctx.get("agent") or "")
        generation = int(op_ctx.get("generation") or 0) or None
        store = store_for(cfg)
        row = store.op_get(op_ctx["op_id"])
        post_send = bool(
            row is not None and (getattr(row, "send_state", "") or "") == "possibly_sent"
        )
        env = errors.envelope(exc)
        if post_send:
            env["vm_outcome"] = "unknown"
            env["note"] = (
                "send committed before the failure; outcome unknown; the "
                "identity stays protected until trusted reconciliation"
            )
            error_class = statestore.OP_UNKNOWN
        else:
            error_class = str(env.get("error_class") or "transport")
        text = json.dumps(env, separators=(",", ":"))
        store.op_transition(
            op_ctx["op_id"], (statestore.OP_WORKING, statestore.OP_FAILED),
            statestore.OP_FAILED,
            error_class=error_class,
            result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
            updated_at=store.now(), generation=generation,
            pre_body_terminal=not post_send,
        )
        emit(cfg, "op.failed", op_ctx["op_id"], "", agent,
             {"error_class": env.get("error_class")})
    except Exception:
        pass


def release_busy_idem(op_ctx: dict[str, Any]) -> None:
    """The guard-side twin of the runner's post-busy idem release (PR #123
    review PRR-001, F1): call AFTER fail_inline stored the busy envelope on
    a keyed sync row — the refusal is RETRYABLE, so the row's idem_key is
    cleared (statestore.op_release_idem; the partial UNIQUE index ignores
    empty keys) and a same-key retry mints a FRESH row and executes instead
    of replaying the refusal for the idempotency TTL. The caller keeps the
    busy envelope fail_inline just wrote. Best-effort like fail_inline: a
    store failure degrades to the replayable refusal this closes, never
    into a raw exception on the response path."""
    try:
        store_for(op_ctx["cfg"]).op_release_idem(
            op_ctx["op_id"],
            generation=int(op_ctx.get("generation") or 0) or None,
        )
    except Exception:
        pass


def busy_inline(op_ctx: dict[str, Any], name: str) -> None:
    """The keyed-INLINE route's gate-contention twin of the runner's
    admission-refusal epilogue (issue #157): the row closes failed/busy
    (provably pre-body, so the send mark clears) and the caller frees the
    idem_key (retryable per PRR-001) via release_busy_idem. Best-effort."""
    try:
        store = store_for(op_ctx["cfg"])
        env = _busy_envelope(name)
        text = json.dumps(env, separators=(",", ":"), default=str)
        store.op_transition(
            op_ctx["op_id"], (statestore.OP_WORKING,), statestore.OP_FAILED,
            error_class="busy",
            result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
            updated_at=store.now(),
            generation=int(op_ctx.get("generation") or 0) or None,
            pre_body_terminal=True,
        )
        emit(op_ctx["cfg"], "op.failed", op_ctx["op_id"], "",
             str(op_ctx.get("agent") or ""),
             {"error_class": "busy", "mode": "inline"})
    except Exception:
        pass


def start_inline_heartbeat(op_ctx: dict[str, Any]) -> Callable[[], None]:
    """The keyed-inline body's generation-fenced beat timer (issue #157,
    plan round-5 blocker 1): keeps the row's heartbeat fresh for the whole
    inline body lifetime so a LIVE inline call past the heartbeat TTL is
    never classified unknown, while a CRASHED inline body (timer dead with
    the mark set) lapses into the unknown reconciliation identity. Returns
    the stop callable; the dispatch's finally MUST call it."""
    cfg: Config = op_ctx["cfg"]
    op_id = str(op_ctx["op_id"])
    generation = int(op_ctx.get("generation") or 0)
    # The store is BOUND AT DISPATCH like the detached runner's: a body that
    # outlives its caller writes to the row's own store, never re-resolves.
    store = store_for(cfg)
    stop = threading.Event()

    def _beat() -> None:
        try:
            store.op_heartbeat(op_id, store.now(), generation=generation or None)
        except Exception:
            pass  # a missed beat is retried on the next interval
        if not stop.is_set():
            t = threading.Timer(
                max(1.0, int(cfg.operations.heartbeat_ttl_s or 60) / 3.0), _beat)
            t.daemon = True
            t.start()

    first = threading.Timer(
        max(1.0, int(cfg.operations.heartbeat_ttl_s or 60) / 3.0), _beat)
    first.daemon = True
    first.start()

    def _stop() -> None:
        stop.set()
        first.cancel()

    return _stop


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

#: Issue #68 supplement (review round 1, MAJOR 3): per-op stop events
#: registered by a detached runner WHILE its admission park is in flight.
#: The cancel path (op_cancel / tasks cancel) sets cancel_requested in the
#: store AND fires the registered event, so a runner parked in
#: admission.admit_sync observes the cancel at its next tick (raises
#: AdmissionStopped -> the cancelled transition) instead of running out its
#: full wait_s and closing as a busy refusal. Entries live only for the
#: park window: the runner deregisters as soon as admit_sync returns.
_ADMIT_STOPS: dict[str, threading.Event] = {}
_ADMIT_STOPS_LOCK = threading.Lock()


def _signal_admit_stop(op_id: str) -> None:
    """Fire a parked runner's admission stop event (never raises).

    The set() runs INSIDE the registry lock (PR #123 review PRR-002):
    releasing the lock between the lookup and the set let the runner's
    park-window pop (same lock) interleave, so the signal landed on the
    shared heartbeat-teardown event AFTER the body had started — a live
    runner's beat chain killed by a park-window cancel (the D12 defect
    class). Signal-and-pop now serialize on the lock: either the cancel
    fires while the entry is still registered (the park wakes into
    AdmissionStopped) or the pop wins and the cancel finds no event (the
    body-time cooperative path takes over)."""
    with _ADMIT_STOPS_LOCK:
        event = _ADMIT_STOPS.get(op_id)
        if event is not None:
            event.set()


def _start_runner(
    cfg: Config,
    row: statestore.OpRow,
    arguments: dict[str, Any],
    tool_fn: Callable[..., Any],
    runner_slots: threading.BoundedSemaphore,
    store: statestore.Store | None = None,
    journal_token: Any = None,
) -> None:
    """Start one daemon runner thread for a detached op. The caller's context
    is COPIED now (the guard resets the presented-lease ContextVar in its
    finally) so the runner sees the same auth identity and presented lease a
    synchronous call would; the body still enters auditlog.operation, so
    vm_lock's scope resolver and call-row adoption behave identically."""
    captured = contextvars.copy_context()
    # issue #131: the runner owns this call's journal token (guard's
    # finally must not resolve it); the body resolves it at completion.
    # handed_off is set ONLY immediately before thread.start() (review
    # F-003 round-2): every setup failure before that point leaves the
    # token unmarked so the caller's finish_if_unowned resolves it.
    body_args = {k: v for k, v in arguments.items() if k not in ("detach", "idempotency_key")}
    presented = ""
    agent = row.agent
    generation = int(getattr(row, "generation", 0) or 0)
    try:
        presented = leases.presented_lease_id()
    except Exception:
        presented = ""
    thread = threading.Thread(
        target=_run_detached,
        args=(captured, cfg, store if store is not None else store_for(cfg),
              row.op_id, row.tool, tool_fn, body_args, agent, presented,
              runner_slots, journal_token, generation),
        name=f"hyperv-op-{row.op_id[:8]}",
        daemon=True,
    )
    with _runners_lock:
        _runners[row.op_id] = thread
    try:
        if journal_token is not None:
            journal_token.handed_off = True
        thread.start()
    except BaseException:
        # issue #152 review F-003 (round-2 residual): a failed start leaves
        # no runner to own the token; un-mark it and let the caller's
        # cleanup (finish_if_unowned in the tasks except path) resolve it.
        if journal_token is not None:
            journal_token.handed_off = False
        with _runners_lock:
            _runners.pop(row.op_id, None)
        raise


def _run_detached(
    captured: contextvars.Context,
    cfg: Config,
    store: statestore.Store,
    op_id: str,
    tool_name: str,
    tool_fn: Callable[..., Any],
    body_args: dict[str, Any],
    agent: str,
    presented_lease: str,
    runner_slots: threading.BoundedSemaphore,
    journal_token: Any = None,
    generation: int = 0,
) -> None:
    # `store` is BOUND AT DETACH TIME on purpose: a runner that outlives its
    # caller (its test's seam rebinds, its process restarts against the same
    # db) must write its completion to the store row it was created against,
    # never re-resolve into whatever store is currently mounted. Writes to a
    # closed store fail and are swallowed by the transition helpers.
    stop = threading.Event()

    def _beat() -> None:
        try:
            store.op_heartbeat(op_id, store.now(), generation=generation or None)
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
        captured.run(
            _execute_body, cfg, op_id, tool_name, tool_fn, body_args, agent,
            store, stop, journal_token, generation,
        )
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
    result_size: int = 0, generation: int | None = None,
    pre_body_terminal: bool = False,
) -> None:
    """One terminal transition + its event, swallowed when the bound store is
    closed (a runner that outlived its caller) — never resurrects a row that
    recovery already failed, and never raises into the runner's epilogue.
    Issue #157: the captured generation and the pre-body provenance flag ride
    through to the store (a fenced executor's write is a no-op; a provably
    pre-body terminal clears the send mark)."""
    try:
        moved = store.op_transition(
            op_id, (statestore.OP_WORKING,), to_status,
            error_class=error_class, result_json=result_json,
            result_size=result_size, updated_at=store.now(),
            generation=generation, pre_body_terminal=pre_body_terminal,
        )
        if moved:
            emit(cfg, kind, op_id, "", agent,
                 {"error_class": error_class} if error_class else {}, store=store)
    except Exception:
        pass


def _execute_body(
    cfg: Config,
    op_id: str,
    tool_name: str,
    tool_fn: Callable[..., Any],
    body_args: dict[str, Any],
    agent: str,
    store: statestore.Store,
    stop: threading.Event,
    journal_token: Any = None,
    generation: int = 0,
) -> None:
    """Runs inside the copied context: sets the cancel-hook ContextVars,
    admits the call through the classed-admission core (issue #68
    supplement — the runner-side twin of the request-loop guard), then
    drives the body and the terminal transition.

    Issue #157: the captured generation rides this whole run (immutable —
    never re-read from a fenced row); the per-resource send gate serializes
    provider submissions for this VM outside the replaceable worker, and the
    attempt-level pre-send commit (commit_send_intent) lands under that gate
    BEFORE tool_fn. The pre-body arms (admission busy / stop-valve /
    park-window cancellations) are PROVABLY pre-send: their transitions pass
    pre_body_terminal=True (clearing an inherited mark). Every in-body
    terminal — any exception, cancellation included once the body started —
    is post-send provenance and retains the mark (mapped to OP_UNKNOWN when
    the row was marked)."""
    _current_op_id.set(op_id)
    _current_ops_cfg.set(cfg)
    _current_op_generation.set(int(generation or 0))
    # Issue #68 supplement (workstream C): the detached/task runner
    # admits BEFORE tool_fn via the same fair/reserve core the guard
    # uses, driven synchronously on the runner thread (per-tick
    # stop-event checks). The agent comes from the copied context (the
    # same identity resolution a synchronous call sees); the actor key
    # follows the console raw-input rule. admit_sync installs the
    # admission ContextVar INSIDE this copied-context run, so the
    # body's auditlog.operation reads the class/wait when it writes
    # the row. The runner's stop event is REGISTERED BEFORE the
    # cancelled pre-check (review round 2): a cancel landing between
    # the pre-check and a later registration would otherwise find no
    # event to signal and leave the park timing out into busy; with the
    # event already visible, such a cancel signals it and the
    # AdmissionStopped arm below closes the op as cancelled.
    with _ADMIT_STOPS_LOCK:
        _ADMIT_STOPS[op_id] = stop
    try:
        # The outer finally (below) pops the registry entry on EVERY exit
        # path from here, including the cancelled pre-check raising before
        # the park — an entry stranded there would be memory-only but would
        # also let a later cancel signal a dead event (review r3).
        _raise_if_cancelled_locked(cfg, op_id, store)
        was_stopped = False
        try:
            ticket = admission.admit_sync(
                tool_name,
                auditlog.current_agent_id() or "unattributed",
                cfg.admission.wait_s,
                actor_key=admission.actor_key_for(tool_name, body_args),
                stop_event=stop,
            )
        except admission.AdmissionBusy as busy:
            _admission_refusal(store, cfg, op_id, tool_name, agent, body_args, busy,
                         generation=generation)
            return
        except admission.AdmissionStopped:
            # The stop valve fired mid-park (a cancel of the parked op, or
            # runner teardown): the waiter reclaimed every stage, so the op
            # closes as cancelled. Provably pre-body (issue #157): the
            # transition clears any inherited send mark.
            _safe_transition(store, op_id, statestore.OP_CANCELLED, agent, cfg,
                             "op.cancelled", pre_body_terminal=True)
            return
        finally:
            # The PARK-WINDOW pop (review round 5) + the ATOMIC stop
            # re-read (review round 2, R2): the registry entry must be gone
            # BEFORE the body starts, and the pop and the stop re-read run
            # under ONE _ADMIT_STOPS_LOCK hold — the same lock
            # _signal_admit_stop holds for its lookup+set. That closes the
            # grant-to-pop window: a park-window cancel either wins the
            # lock while the entry is still registered (its set() lands,
            # the re-read observes it, and the granted-but-unused ticket is
            # released below — the body NEVER starts with the shared
            # heartbeat-teardown stop already set) or loses the race to
            # the pop (the signal finds no entry, and body-time
            # cancellation stays with the cooperative leg-boundary hook).
            # The registered event IS the runner's shared
            # heartbeat-teardown `stop` — an entry left live through the
            # body turns a body-time hyperv_op_cancel into a beat-chain
            # kill of a LIVE runner: the heartbeats stop, read-time
            # staleness misclassifies the row failed/interrupted while the
            # body still runs, and the body's own cancelled transition is
            # dropped by the stale flip.
            with _ADMIT_STOPS_LOCK:
                _ADMIT_STOPS.pop(op_id, None)
                was_stopped = stop.is_set()
        if was_stopped:
            # A cancel signalled inside the grant-to-pop window: the ticket
            # was granted but never used — release it (the retire path
            # reclaims the permit) and close the op with the AdmissionStopped
            # terminal, exactly as a stop observed mid-park would. Provably
            # pre-body (issue #157): the mark clears.
            admission.release_sync(ticket)
            _safe_transition(store, op_id, statestore.OP_CANCELLED, agent, cfg,
                             "op.cancelled", pre_body_terminal=True)
            return
        # Issue #157: the send gate serializes the per-resource PRE-SEND
        # COMMIT window outside this replaceable worker (route-layer owned;
        # the canonical order is gate -> commit -> submission; the VM write /
        # read locks already serialize the submissions themselves). The gate
        # covers the commit only, NOT the whole body: a body legitimately runs
        # for minutes, and holding a per-VM lock for its whole lifetime would
        # wedge every queued same-VM attempt behind it (found by the e03
        # interceptor schedules — a parked body deadlocked later borrows; a
        # disclosed deviation from the plan's whole-body hold that preserves
        # every gate property the plan required). A runner thread acquires
        # blocking; the async inline route acquires non-blocking (server.py).
        gate_held = _send_gate_acquire(body_args, blocking=True)
        try:
            if not gate_held:
                env = _busy_envelope(tool_name)
                text = json.dumps(env, separators=(",", ":"), default=str)
                _safe_transition(
                    store, op_id, statestore.OP_FAILED, agent, cfg, "op.busy",
                    error_class="busy",
                    result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
                    pre_body_terminal=True,
                )
                # Issue #157 (final critic F2): the busy refusal is RETRYABLE
                # (PRR-001) — free the (agent, tool, idem_key) slot so a
                # same-key retry mints a fresh dispatch instead of replaying
                # this busy envelope for the whole idempotency TTL.
                try:
                    store.op_release_idem(op_id, generation=generation or None)
                except Exception:
                    pass
                admission.release_sync(ticket)
                return
            try:
                # Attempt-level pre-send commit: mark only. The dirty-epoch
                # bump is the restore boundary's commit (lifecycle passes the
                # vm_key); a generic body must never dirty an epoch.
                commit_send_intent(cfg)
            except Exception as exc:
                env = errors.envelope(exc)
                text = json.dumps(env, separators=(",", ":"), default=str)
                _safe_transition(
                    store, op_id, statestore.OP_FAILED, agent, cfg, "op.failed",
                    error_class=str(env.get("error_class") or "transport"),
                    result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
                    pre_body_terminal=True,
                )
                admission.release_sync(ticket)
                return
        finally:
            if gate_held:
                _send_gate_release(body_args)
        try:
            evidencejournal.arm(journal_token)
            result = tool_fn(**body_args)
        finally:
            admission.release_sync(ticket)
        evidencejournal.finish(journal_token, result, outcome="body")
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
            # Issue #157 (impl-review F8): a tool-level ok:false envelope is a
            # BODY outcome — in-body provenance RETAINS the send mark (an
            # envelope does not prove the provider never acted).
            _safe_transition(
                store, op_id, statestore.OP_FAILED, agent, cfg, "op.failed",
                error_class=error_class,
                result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
                generation=generation or None,
            )
        else:
            _safe_transition(
                store, op_id, statestore.OP_COMPLETED, agent, cfg, "op.completed",
                result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
                generation=generation or None,
            )
    except OperationCancelled:
        # Issue #157: the cooperative cancel is honored by a LIVE runner — the
        # attempt terminal is definitively `cancelled` even when the send
        # commit already landed (the plan's acknowledgment rule: post-send
        # cancellation retains possibly_sent, so the row stays protected; the
        # views disclose the uncertain VM-side outcome via _stale_view).
        # Status stays cancelled on both arms; only the mark's fate differs.
        row = None
        try:
            row = store.op_get(op_id)
        except Exception:
            pass
        post_send = bool(
            row is not None and (getattr(row, "send_state", "") or "") == "possibly_sent"
        )
        _safe_transition(
            store, op_id, statestore.OP_CANCELLED,
            agent, cfg, "op.cancelled",
            generation=generation or None,
        )
        if post_send:
            emit(cfg, "op.cancelled", op_id, "", agent,
                 {"vm_outcome": "unknown",
                  "note": "cancel honored after the send commit; VM-side outcome unknown"})
    except BaseException as exc:  # noqa: BLE001 — the runner classifies everything
        # Issue #157 (round-5 blocker 2): provenance is the execution phase,
        # not the error_class string — a raise AFTER the pre-send commit is a
        # post-send ambiguity even though errors.envelope serializes a result
        # payload; the row keeps its mark and carries error_class unknown.
        marked = False
        try:
            row = store.op_get(op_id)
            marked = bool(
                row is not None
                and (getattr(row, "send_state", "") or "") == "possibly_sent"
            )
        except Exception:
            pass
        env = errors.envelope(exc)
        if marked:
            env["vm_outcome"] = "unknown"
            env["note"] = (
                "send committed before the failure; outcome unknown; the "
                "identity stays protected until trusted reconciliation"
            )
        text = json.dumps(env, separators=(",", ":"), default=str)
        _safe_transition(
            store, op_id, statestore.OP_FAILED, agent, cfg, "op.failed",
            error_class=statestore.OP_UNKNOWN if marked else str(
                env.get("error_class") or "transport"),
            result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
            generation=generation or None,
        )
    finally:
        # issue #131 (PC4-1): every runner terminal outcome that skipped
        # an explicit finish (admission refusal, cancelled pre-check,
        # OperationCancelled, BaseException) still resolves exactly one
        # journal line here; body-finished/handed-off tokens no-op.
        evidencejournal.finish(journal_token, None, outcome="terminal")
        # The BACKSTOP pop (review r3/r5): idempotent safety net for the
        # exits that never reach the park-window pop above — the cancelled
        # pre-check raising before the park (and any future early return).
        # During the body this is a no-op: the inner pop already removed
        # the entry precisely so a body-time cancel cannot reach the
        # runner's shared teardown event.
        with _ADMIT_STOPS_LOCK:
            _ADMIT_STOPS.pop(op_id, None)


def _admission_refusal(
    store: statestore.Store,
    cfg: Config,
    op_id: str,
    tool_name: str,
    agent: str,
    body_args: dict[str, Any],
    busy: admission.AdmissionBusy,
    generation: int = 0,
) -> None:
    """The runner-side pre-body admission refusal (issue #68 supplement):
    the op row transitions to failed carrying the busy envelope (whose
    retry_after_ms errors.envelope preserved from the exception), and an
    auditable rejection row records tool, agent, error_class, the
    exception's retry hint, and the admission class — the same fields the
    guard's _audited_rejection writes, which is not reachable from this
    thread. The busy-vs-cancel tick race below is intended: a cancel
    signal racing the park deadline may lose — the deadline outcome is
    authoritative, and a same-key resubmit executes fresh (the idem
    release below frees the key either way).
    Best-effort on the audit sink: a broken sink must not raise
    into the runner's epilogue."""
    env = errors.envelope(busy)
    text = json.dumps(env, separators=(",", ":"), default=str)
    _safe_transition(
        store, op_id, statestore.OP_FAILED, agent, cfg, "op.failed",
        generation=int(generation or 0) or None,
        error_class="busy",
        result_json=pswindows.redact(text), result_size=len(text.encode("utf-8")),
    )
    # AFTER the terminal busy write: free the row's idem_key (PR #123
    # review PRR-001, F1). The busy refusal is RETRYABLE — this caller's
    # submitted handle keeps polling the stored busy envelope above, but
    # the (agent, tool, idem_key) UNIQUE slot must not hold the key for
    # the idempotency TTL: a same-key resubmit mints a FRESH row and
    # executes instead of replaying the refusal. The cancel path (the
    # AdmissionStopped arm) deliberately does NOT do this: a cancelled op
    # is terminal and its retry answers from the row (D9's pin).
    try:
        store.op_release_idem(op_id, generation=int(generation or 0) or None)
    except Exception:
        pass  # best-effort: a store failure degrades to the replayable
        # refusal this closes, never into a runner-crash
    try:
        auditlog.log_operation(
            tool=tool_name,
            vm_name=str(body_args.get("vm_name") or ""),
            category="",
            ok=False,
            error_class="busy",
            agent_id=agent or None,
            admission_class=str(admission.classify_tool(tool_name)),
            retry_after_ms=busy.retry_after_ms,
        )
    except Exception:
        pass


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
    # Review round 1, MAJOR 3: wake a runner still parked in admission —
    # the store flag alone is invisible to a parked admit_sync, which would
    # run out its full wait_s and close the op as a busy refusal instead of
    # the cancellation the caller asked for.
    _signal_admit_stop(op_id)
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
            # issue #131 (PC4-1): the tasks route bypasses guard entirely —
            # bind its own journal token at entry so gate/preflight/slot
            # refusals, reattach, and accepted-start all resolve exactly
            # one line (begin no-ops with no runs open).
            jtok = (evidencejournal.begin(params.name, arguments)
                    if evidencejournal.has_any_open_run() else None)
            try:
                env, reset = gate_fn(params.name, arguments)
            except Exception:
                # issue #152 review F-003 (round-2 residual): a gate raise
                # before the main try must resolve the token or stop_run
                # wedges on journal_drain_timeout forever.
                evidencejournal.finish_if_unowned(jtok, None, outcome="error")
                raise
            if env is not None:
                # Gate refusal is an ordinary tool-envelope answer, never -32021.
                evidencejournal.finish(jtok, env, outcome="refusal")
                return errors.failure_result(env)
            if preflight_fn is not None:
                try:
                    preflight_fn(params.name, arguments)
                except Exception as exc:
                    # Synchronous body-gate refusal BEFORE any op row
                    # (implementation-review R2/R13) - an ordinary envelope.
                    _penv = errors.envelope(exc)
                    evidencejournal.finish(jtok, _penv, outcome="refusal")
                    return errors.failure_result(_penv)
            # Issue #157 (plan round-2 blocker 6): the idempotency consult is
            # answered BEFORE the runner-slot acquisition on the tasks route
            # too — a reattach/conflict/reconciliation response never consumes
            # capacity. Reservation + fresh-row creation stays atomic for NEW
            # dispatch (the consult below and the insert share one
            # transaction; the slot is taken only on the fresh-dispatch arm).
            try:
                agent = auditlog.current_agent_id() or ""
                store = store_for(cfg)
                now = store.now()
                idem_key = str(arguments.get("idempotency_key") or "")
                fingerprint = (
                    arguments_fingerprint(cfg, store, arguments) if idem_key else ""
                )
                with store.transaction():
                    existing = (
                        store.op_find_idem(agent, params.name, idem_key)
                        if idem_key else None
                    )
                    consult_answer: Any = None
                    consult_op_id = ""
                    if existing is not None:
                        consult_op_id = existing.op_id
                        ttl = int(cfg.operations.idempotency_ttl_s or 86400)
                        heartbeat_fresh = (
                            existing.heartbeat_at > 0
                            and existing.heartbeat_at >= now - int(
                                cfg.operations.heartbeat_ttl_s or 60
                            )
                        )
                        possibly_sent = (
                            getattr(existing, "send_state", "") or ""
                        ) == "possibly_sent"
                        protected_class = existing.error_class in (
                            statestore.OP_INTERRUPTED, statestore.OP_UNKNOWN
                        )
                        if (
                            existing.created_at > 0
                            and existing.created_at < now - ttl
                            and not possibly_sent
                            and not heartbeat_fresh
                            and not protected_class
                        ):
                            existing = _classify_stale(store, existing, cfg)
                            if existing.status == statestore.OP_WORKING:
                                try:
                                    store.op_fence(existing.op_id)
                                except Exception:
                                    pass
                            store.op_delete(existing.op_id)
                            emit(cfg, "op.expired", existing.op_id, "", agent,
                                 {"reason": "idempotency_ttl_lapsed"}, store=store)
                            existing = None
                    if existing is not None:
                        existing = _classify_stale(store, existing, cfg)
                        if existing.params_hmac and existing.params_hmac != fingerprint:
                            consult_answer = errors.failure_result(
                                _conflict_envelope(params.name, idem_key))
                        elif not existing.params_hmac and fingerprint:
                            consult_answer = errors.failure_result(
                                errors.enrich_failure({
                                    "ok": False,
                                    "error": (
                                        f"idempotency_key {idem_key!r} matches a "
                                        f"legacy record (handle {existing.op_id}) "
                                        f"whose argument fingerprint predates "
                                        f"fingerprinting; reconciliation is "
                                        f"required before reuse — re-run with a "
                                        f"new idempotency_key"
                                    ),
                                    "error_class": "idempotency_conflict",
                                    "reconciliation": True,
                                    "op_id": existing.op_id,
                                }))
                        else:
                            if (
                                existing.status == statestore.OP_FAILED
                                and existing.error_class == statestore.OP_UNKNOWN
                            ):
                                try:
                                    store.op_fence(existing.op_id)
                                except Exception:
                                    pass
                            consult_answer = TaskHandleResult(
                                task_id=existing.op_id,
                                status=existing.status,
                                ttl_ms=int(cfg.operations.retention_s) * 1000,
                                poll_interval_ms=existing.poll_interval_ms,
                            )
                    if consult_answer is not None:
                        evidencejournal.finish(jtok,
                                               {"task_id": consult_op_id,
                                                "consulted": True},
                                               outcome="reattach")
                        return consult_answer
                # Fresh dispatch: NOW take the runner slot (R4), then insert.
                slots = runner_slots()
                if not slots.acquire(blocking=False):
                    _benv = _busy_envelope(params.name)
                    evidencejournal.finish(jtok, _benv, outcome="busy")
                    return errors.failure_result(_benv)
                row = None
                try:
                    # Issue #157 (impl-review F6): minting sits inside the
                    # protected region so a generation failure releases the slot.
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
                        generation=store.op_next_generation(),
                    )
                except Exception:
                    # Issue #157 (impl-review F6): a generation-mint failure
                    # releases the slot exactly once and answers the classified
                    # refusal envelope.
                    slots.release()
                    evidencejournal.finish_if_unowned(jtok, None, outcome="error")
                    env = errors.enrich_failure({
                        "ok": False,
                        "error": (
                            f"{params.name}: the detached operation could not "
                            f"be recorded; no dispatch authority was left "
                            f"behind — retry after fixing the durable-state fault"
                        ),
                        "error_class": "transport",
                    })
                    env["retryable"] = True
                    env["retry_after_ms"] = errors.BUSY_RETRY_MS
                    return errors.failure_result(env)
                # Durable creation BEFORE the response (SEP-2663: MUST NOT
                # return CreateTaskResult until the task is durably created).
                try:
                    store.op_insert(row)
                except Exception:
                    # Issue #157 (impl-review F3): a concurrent identical tasks
                    # call may have won the insert race between this call's
                    # consult and insert (the two are deliberately split so the
                    # consult answers before capacity). RE-CONSULT: the winner
                    # is answered as a reattach (the same handle the guard
                    # route would return); a true durable-state failure still
                    # releases the slot and answers the classified refusal.
                    # Issue #157 (impl-review round 4): the re-consult is
                    # KEYED-ONLY (an unkeyed insert has no race winner to
                    # find - op_find_idem with an empty key would match an
                    # unrelated unkeyed row). Issue #157 (impl-review round
                    # 5): the slot ownership flag makes the release
                    # EXACTLY-ONCE on every path - a journal/response
                    # construction failure after an inner release falls to
                    # the degraded refusal WITHOUT a second release.
                    winner = None
                    slot_released = False
                    if idem_key:
                        try:
                            with store.transaction():
                                # Issue #157 (impl-review round 3): the re-consult
                                # winner gets the SAME fingerprint/reconciliation/
                                # protected-identity checks an ordinary consult
                                # applies - the key identifies the slot, not the args.
                                winner = store.op_find_idem(agent, params.name, idem_key)
                            if winner is not None and winner.op_id != row.op_id:
                                winner = _classify_stale(store, winner, cfg)
                                if winner.params_hmac and winner.params_hmac != fingerprint:
                                    slots.release()
                                    slot_released = True
                                    _cenv2 = _conflict_envelope(params.name, idem_key)
                                    evidencejournal.finish(
                                        jtok, _cenv2, outcome="conflict")
                                    return errors.failure_result(_cenv2)
                                if not winner.params_hmac and fingerprint:
                                    slots.release()
                                    slot_released = True
                                    _renv = errors.enrich_failure({
                                        "ok": False,
                                        "error": (
                                            f"idempotency_key {idem_key!r} matches a "
                                            f"legacy record (handle {winner.op_id}) "
                                            f"whose argument fingerprint predates "
                                            f"fingerprinting; reconciliation is "
                                            f"required before reuse"
                                        ),
                                        "error_class": "idempotency_conflict",
                                        "reconciliation": True,
                                        "op_id": winner.op_id,
                                    })
                                    evidencejournal.finish(jtok, _renv, outcome="conflict")
                                    return errors.failure_result(_renv)
                                if (
                                    winner.status == statestore.OP_FAILED
                                    and winner.error_class == statestore.OP_UNKNOWN
                                ):
                                    try:
                                        store.op_fence(winner.op_id)
                                    except Exception:
                                        pass
                                _handle = TaskHandleResult(
                                    task_id=winner.op_id,
                                    status=winner.status,
                                    ttl_ms=int(cfg.operations.retention_s) * 1000,
                                    poll_interval_ms=winner.poll_interval_ms,
                                )
                                slots.release()
                                slot_released = True
                                evidencejournal.finish(
                                    jtok, {"task_id": winner.op_id, "consulted": True},
                                    outcome="reattach")
                                return _handle
                        except Exception:
                            # Issue #157 (impl-review rounds 4-5): a re-consult
                            # failure falls through to the single exactly-once
                            # release + classified refusal below - the permit
                            # is never leaked NOR double-released by the
                            # recovery path itself.
                            winner = None
                    if not slot_released:
                        slots.release()
                        slot_released = True
                    evidencejournal.finish_if_unowned(jtok, None, outcome="error")
                    env = errors.enrich_failure({
                        "ok": False,
                        "error": (
                            f"{params.name}: the detached operation could not "
                            f"be recorded; no dispatch authority was left "
                            f"behind — retry after fixing the durable-state fault"
                        ),
                        "error_class": "transport",
                    })
                    env["retryable"] = True
                    env["retry_after_ms"] = errors.BUSY_RETRY_MS
                    return errors.failure_result(env)
                emit(cfg, "op.created", row.op_id, "", agent,
                     {"tool": params.name, "detached": True, "tasks": True})
                try:
                    _start_runner(cfg, row, arguments, tool_fn_resolver(params.name),
                                  slots, journal_token=jtok)
                except Exception:
                    # Issue #157 (C1's tasks twin): a failed start releases the
                    # slot exactly once, removes the stranded row, and answers
                    # the classified refusal envelope — never a leaked permit
                    # or a raw escape.
                    slots.release()
                    try:
                        store.op_delete(row.op_id)
                    except Exception:
                        pass
                    evidencejournal.finish_if_unowned(jtok, None, outcome="error")
                    env = errors.enrich_failure({
                        "ok": False,
                        "error": (
                            f"{params.name}: the detached operation could not "
                            f"be started; no dispatch authority was left "
                            f"behind — retry after fixing the fault"
                        ),
                        "error_class": "transport",
                    })
                    env["retryable"] = True
                    env["retry_after_ms"] = errors.BUSY_RETRY_MS
                    return errors.failure_result(env)
                return TaskHandleResult(
                    task_id=row.op_id,
                    status=statestore.OP_WORKING,
                    ttl_ms=int(cfg.operations.retention_s) * 1000,
                    poll_interval_ms=row.poll_interval_ms,
                )
            except Exception:
                # issue #152 review F-003: a pre-handoff failure must resolve
                # the journal token or stop_run wedges on journal_drain_timeout
                # forever (the runner never owned it, nothing else finalizes).
                evidencejournal.finish_if_unowned(jtok, None, outcome="error")
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
            # Issue #157: the tasks view carries the SAME outcome disclosures
            # the guard route's _stale_view carries (impl-review F9).
            stale = _stale_view(row)
            if stale:
                view.status_message = str(stale.get("note") or stale.get("vm_outcome"))
            elif row.error_class:
                view.status_message = row.error_class
            if (
                embed_result
                and row.status in statestore.OP_TERMINAL_STATES
                and not row.result_json
                and row.error_class != statestore.OP_UNKNOWN
            ):
                # A terminal tombstone (identity retained, payload pruned)
                # discloses result-expired explicitly; unknown rows keep their
                # own reconciliation disclosure above.
                view.status_message = (
                    "result expired: the payload was pruned within the replay "
                    "window; the original handle stays addressable"
                )
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
                # Review round 1, MAJOR 3: wake a parked runner's admission
                # (same wiring as op_cancel — the store flag alone is
                # invisible to a parked admit_sync).
                _signal_admit_stop(params.task_id)
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
    with _ADMIT_STOPS_LOCK:
        _ADMIT_STOPS.clear()
