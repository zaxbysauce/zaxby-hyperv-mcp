"""Classed admission fairness layer (issue #68 supplement, workstream C).

The tool-limiter lifespan sizes anyio's default thread limiter to
2 x max_host_powershell but reserves no class for the light/status tools,
so lock-queued GENERAL callers can delay them up to vm_lock_wait_s (the
documented bound in the README concurrency section). This module is the
fairness reserve that closes it, interposed by the server's pre-Tool.run
guard (event-loop side) and by the detached-operation runner (worker-thread
side, admit_sync) — registered tool fns stay sync and the anyio default
limiter remains THE thread bound.

Surfaces:

  - AdmissionClass: LIGHT (the light/status lane — the
    status/readiness/list/info/jobs-status registry reserved at the
    thread-limiter axis; a CLASS reservation, not a claim that these tools
    never touch PowerShell) and GENERAL (everything else); str() gives the
    name. classify_tool is the ONE classification source of truth.
  - configure(total_tokens, light_reserve, wait_s, light_wait_s=None): the
    token budget (bootstrap passes 2 x max_host_powershell, mirroring the
    limiter sizing). GENERAL admits are bounded to total - light_reserve
    tokens; LIGHT admits may use the full total (the reserved lane).
    light_reserve omitted (None) resolves to min(2, total_tokens - 1); a
    SUPPLIED value is validated 0 <= light_reserve < total_tokens with
    ValueError — never clamped (an explicit misconfiguration fails loudly
    at startup, the OperationsPolicy convention).
  - admit(tool_name, agent_id, wait_s, actor_key=None) -> AdmissionTicket
    (.cls, .wait_ms, .agent_id). SINGLE-STAGE without actor_key (the light
    lane or a general permit directly). TWO-STAGE with actor_key (the
    console actor shape): stage 1 waits in a per-actor-key fair queue of
    capacity 1 (actor eligibility BEFORE token acquisition, per the issue
    #68 supplement: K agents fanning in on one VM must not occupy every
    token and starve unrelated light/status traffic), and ONLY THEN stage 2
    acquires the token — an actor-queued caller NEVER holds a token while
    queued. GENERAL-stage waiters queue per-agent round-robin (a plain
    FIFO would serve one agent's whole backlog first and starve the
    other); the same per-agent fairness orders a contended actor queue.
    Raises AdmissionBusy(retry_after_ms) on exhaustion — the retry
    precedent is operations._busy_envelope / errors.BUSY_RETRY_MS.
  - admit_sync(tool_name, agent_id, wait_s, actor_key=None,
    stop_event=None) + release_sync: the same core driven synchronously by
    the detached runner (per-tick stop-event checks, the vmlocks
    cancellation-tick precedent).
  - snapshot(): the telemetry seam (in_flight_general, in_flight_light,
    reserved, total_tokens, fair_queue_depth — every parked admit across
    both stages — plus actor_queue_depth); reset(): the test seam.
  - current_admission(): (admission_class, wait_ms) for the call in
    flight, carried on a ContextVar set by a successful admit and reset
    when the ticket releases (auditlog reads it when it writes the row;
    no cross-call bleed).

Waits are bounded and cancellation-safe: both admit flavors poll on a
small tick, observe host-task cancellation every tick (async) / the stop
event every tick (sync), and a try/except reclaims every partial stage —
a cancelled admit leaves no permit, actor slot, or queue entry. All
counter and queue mutations happen under one threading.Lock (the state is
shared by the event loop and the runner threads), and snapshot() reads a
consistent copy of it. No secrets flow through this module: agent ids and
tool names only, counts in the snapshot.
"""

from __future__ import annotations

import contextvars
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import anyio

__all__ = [
    "AdmissionBusy",
    "AdmissionClass",
    "AdmissionStopped",
    "AdmissionTicket",
    "admit",
    "admit_sync",
    "actor_key_for",
    "classify_tool",
    "configure",
    "current_admission",
    "release",
    "release_sync",
    "reset",
    "snapshot",
]

#: The LIGHT registry (issue #68 supplement): the light/status lane — the
#: status/readiness/list/info/jobs-status surfaces whose admission must
#: survive GENERAL callers saturating the budget. The reserve is a CLASS
#: reservation at the thread-limiter axis, not a PS-freeness guarantee
#: (several of these bodies DO spawn PowerShell or guest work; the
#: class is what the layer enforces). Internal to this module — there is
#: no second classification source of truth.
_LIGHT_TOOLS = frozenset({
    "hyperv_list_vms",
    "hyperv_server_info",
    "hyperv_get_vm_info",
    "hyperv_guest_job_status",
})

#: The console raw-input surface (the mouse/keyboard/text-input tools):
#: the only tools whose calls key a per-VM actor stage. Unrelated VM tools
#: are never actor-keyed — they are classed GENERAL and go straight to the
#: token lane.
_ACTOR_KEYED_TOOLS = frozenset({
    "hyperv_console_type_text",
    "hyperv_console_press_key",
    "hyperv_console_key_combo",
    "hyperv_console_type_scancodes",
    "hyperv_console_mouse_move",
    "hyperv_console_click",
    "hyperv_console_button",
    "hyperv_console_scroll",
    "hyperv_console_sequence",
})

#: Park-tick for both admit flavors: small enough that cancellation and
#: stop events surface promptly (observed per tick), large enough that a
#: saturated budget is not a spin loop.
_TICK_S = 0.005


class AdmissionClass(str, Enum):
    """The two admission classes; str() gives the name (LIGHT/GENERAL)."""

    LIGHT = "LIGHT"
    GENERAL = "GENERAL"

    def __str__(self) -> str:
        return self.value


def classify_tool(tool_name: str) -> AdmissionClass:
    """LIGHT for the light/status registry, GENERAL for everything else."""
    if tool_name in _LIGHT_TOOLS:
        return AdmissionClass.LIGHT
    return AdmissionClass.GENERAL


@dataclass
class AdmissionTicket:
    """One granted admit: the class, the measured park wait, the agent."""

    cls: AdmissionClass
    wait_ms: int
    agent_id: str
    # Bookkeeping for release() (never part of the documented surface):
    # the internal waiter and the ContextVar token the admit installed.
    _waiter: Any = field(default=None, repr=False, compare=False)
    _ctx_token: Any = field(default=None, repr=False, compare=False)


class AdmissionBusy(RuntimeError):
    """A bounded admit refused on a saturated budget (retryable).

    retry_after_ms is the positive hint carried into the busy envelope
    (errors.envelope preserves it over the fixed BUSY_RETRY_MS, the
    lease_conflict precedent)."""

    def __init__(self, retry_after_ms: float) -> None:
        super().__init__(
            f"admission budget saturated; retry after {retry_after_ms:g} ms"
        )
        self.retry_after_ms = retry_after_ms


class AdmissionStopped(RuntimeError):
    """admit_sync observed its stop_event mid-wait (the runner valve).

    The waiter reclaimed every partial stage before raising: no permit,
    actor slot, or queue entry leaks. The detached runner maps this onto
    its cancelled transition."""

    def __init__(self) -> None:
        super().__init__("admission wait stopped before a ticket was granted")


def _retry_after_ms(bound_s: float) -> float:
    """The retry hint for a refused admit, in ms: half the caller's bound,
    at least 1 ms — long enough to matter, never above the bound itself."""
    return max(1.0, float(bound_s) * 500.0)


def actor_key_for(tool_name: str, arguments: dict[str, Any] | None) -> str | None:
    """The hinted-canonical console actor identity for admission stage 1.

    Only the console raw-input surface is actor-keyed. By-id calls key the
    GUID; by-name calls key console._hint_for(name) — the canonical GUID
    once the host-side hint map knows the name (issue #77) — falling back
    to the raw caller-supplied name, casefolded so both addressing aliases
    of one VM share ONE actor queue. Returns None for every other tool
    (single-stage) and for calls with no identity argument.
    """
    if tool_name not in _ACTOR_KEYED_TOOLS:
        return None
    args = arguments or {}
    vm_id = str(args.get("vm_id") or "").strip()
    if vm_id:
        return vm_id.casefold()
    vm_name = str(args.get("vm_name") or "").strip()
    if not vm_name:
        return None
    from . import console  # late import: keeps this module import-cycle-free

    hinted = console._hint_for(vm_name)
    return (hinted if hinted is not None else vm_name).casefold()


# ---------------------------------------------------------------------------
# core state — one lock guards every counter, queue, and actor record
# ---------------------------------------------------------------------------

_LOCK = threading.Lock()

_TOTAL_TOKENS = 0
_LIGHT_RESERVE = 0
_WAIT_S = 30.0
_LIGHT_WAIT_S: float | None = None
_CONFIGURED = False

_IN_FLIGHT_GENERAL = 0
_IN_FLIGHT_LIGHT = 0

#: Parked token-lane waiters (stage 2, or single-stage admits), in arrival
#: order; the agent turn deque orders grants per-agent round-robin.
_LANE: list[_Waiter] = []
_LANE_AGENTS: deque[str] = deque()


class _Waiter:
    """One in-flight admit attempt, shared by both admit flavors."""

    __slots__ = ("agent_id", "cls", "actor_key", "granted", "retired", "stage")

    def __init__(self, agent_id: str, cls: AdmissionClass, actor_key: str | None):
        self.agent_id = agent_id
        self.cls = cls
        self.actor_key = actor_key
        self.stage = 0  # 1 = parked in the actor queue, 2 = parked in the lane
        self.granted = False
        self.retired = False


class _Actor:
    """Per-actor-key stage-1 state: capacity 1 plus its own fair queue."""

    __slots__ = ("holder", "waiters", "agents")

    def __init__(self) -> None:
        self.holder: _Waiter | None = None
        self.waiters: list[_Waiter] = []
        self.agents: deque[str] = deque()


_ACTORS: dict[str, _Actor] = {}

#: (admission_class, wait_ms) for the call in flight — set by a successful
#: admit BEFORE the body dispatch, reset when the ticket releases, read by
#: auditlog at row-write time (the lease_ref field precedent).
_ADMISSION_CTX: contextvars.ContextVar[tuple[str, int] | None] = (
    contextvars.ContextVar("hyperv_admission", default=None)
)


def current_admission() -> tuple[str, int] | None:
    """(admission_class, wait_ms) for the current call, or None when no
    admit is in flight (rows then serialize the fields as null)."""
    return _ADMISSION_CTX.get()


def _require_configured() -> None:
    if not _CONFIGURED:
        raise RuntimeError(
            "admission.configure() has not run (bootstrap sizes the budget)"
        )


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _general_capacity() -> int:
    return max(0, _TOTAL_TOKENS - _LIGHT_RESERVE)


def _headroom() -> int:
    return _TOTAL_TOKENS - _IN_FLIGHT_GENERAL - _IN_FLIGHT_LIGHT


def _pick_fair(candidates: list[_Waiter], agents: deque[str]) -> _Waiter | None:
    """Per-agent round-robin pick over arrival-ordered candidates.

    The turn deque holds agent ids least-recently-served first; the pick
    grants the OLDEST waiter of the front agent, then rotates that agent
    to the back — so two parked agents alternate grants and neither can
    starve the other (a plain FIFO serves the first agent's whole backlog
    before the second's). Agents with no parked waiter drop out of the
    deque; newly parking agents join at the back in arrival order.
    """
    if not candidates:
        return None
    oldest_by_agent: dict[str, _Waiter] = {}
    for waiter in candidates:
        oldest_by_agent.setdefault(waiter.agent_id, waiter)
    for agent in oldest_by_agent:
        if agent not in agents:
            agents.append(agent)
    for agent in [a for a in agents if a not in oldest_by_agent]:
        agents.remove(agent)
    if not agents:
        return None
    front = agents[0]
    agents.rotate(-1)
    return oldest_by_agent[front]


def _grant_pass() -> None:
    """Admit every waiter the freed capacity can serve (caller holds the
    lock): stage 1 first (actor eligibility, capacity 1 per key), then the
    token lane — LIGHT waiters on any overall headroom, GENERAL waiters
    per-agent fair below total - light_reserve. A stage-1 grant moves the
    waiter to the lane WITHOUT a token, so an actor-queued caller never
    holds a token while queued."""
    global _IN_FLIGHT_GENERAL, _IN_FLIGHT_LIGHT
    for actor in list(_ACTORS.values()):
        if actor.holder is not None:
            continue
        waiter = _pick_fair(actor.waiters, actor.agents)
        if waiter is None:
            continue
        actor.waiters.remove(waiter)
        actor.holder = waiter
        waiter.stage = 2
        _LANE.append(waiter)
    while _headroom() > 0:
        waiter = next(
            (w for w in _LANE if w.cls is AdmissionClass.LIGHT and not w.retired),
            None,
        )
        if waiter is None:
            break
        _LANE.remove(waiter)
        _IN_FLIGHT_LIGHT += 1
        waiter.granted = True
    while _IN_FLIGHT_GENERAL < _general_capacity() and _headroom() > 0:
        # The shared-budget gate: in-flight GENERAL + LIGHT never exceeds
        # total_tokens. The capacity clause alone would oversell the budget
        # when LIGHT holds MORE than the reserve (e.g. total 4, reserve 2,
        # 3 LIGHT + 1 GENERAL in flight leaves headroom 0 — a GENERAL grant
        # on capacity alone would push the sum to 5), so the general lane
        # also waits for overall headroom (review round 1, MAJOR 1).
        waiter = _pick_fair(
            [w for w in _LANE if w.cls is AdmissionClass.GENERAL], _LANE_AGENTS
        )
        if waiter is None:
            break
        _LANE.remove(waiter)
        _IN_FLIGHT_GENERAL += 1
        waiter.granted = True


def _retire(waiter: _Waiter) -> None:
    """Reclaim every stage a waiter holds or queues in (caller holds the
    lock): the actor slot it owns (a two-stage waiter holds it from its
    stage-1 grant whether or not the token ever issued), the granted
    permit, or the one queue entry it parks in. Idempotent, then re-runs
    the grant pass so freed capacity serves the next waiter immediately."""
    global _IN_FLIGHT_GENERAL, _IN_FLIGHT_LIGHT
    if waiter.retired:
        return
    waiter.retired = True
    actor = _ACTORS.get(waiter.actor_key) if waiter.actor_key is not None else None
    if waiter.granted:
        waiter.granted = False
        if waiter.cls is AdmissionClass.LIGHT:
            _IN_FLIGHT_LIGHT -= 1
        else:
            _IN_FLIGHT_GENERAL -= 1
    elif waiter.stage == 1 and actor is not None:
        try:
            actor.waiters.remove(waiter)
        except ValueError:
            pass
    else:
        try:
            _LANE.remove(waiter)
        except ValueError:
            pass
    if actor is not None:
        if actor.holder is waiter:
            actor.holder = None
        if actor.holder is None and not actor.waiters:
            # CI mypy (arg-type): actor is not None implies the lookup key was
            # a present str key; narrow it for the del.
            key = waiter.actor_key
            assert key is not None
            del _ACTORS[key]
    _grant_pass()


def _enter(
    tool_name: str, agent_id: str, wait_s: float, actor_key: str | None
) -> tuple[_Waiter, float]:
    """Validate, park the waiter in its first-stage queue, and run one
    grant pass (an uncontended admit is granted inside this call)."""
    _require_configured()
    cls = classify_tool(tool_name)
    bound = float(wait_s)
    if cls is AdmissionClass.LIGHT and _LIGHT_WAIT_S is not None:
        # The configured light bound caps the caller's ask, so the reserved
        # lane never inherits a GENERAL-sized park.
        bound = min(bound, _LIGHT_WAIT_S)
    waiter = _Waiter(str(agent_id), cls, actor_key)
    with _LOCK:
        if actor_key is None:
            waiter.stage = 2
            _LANE.append(waiter)
        else:
            waiter.stage = 1
            _ACTORS.setdefault(actor_key, _Actor()).waiters.append(waiter)
        _grant_pass()
    return waiter, bound


def _issue(waiter: _Waiter, started: float) -> AdmissionTicket:
    """Build the ticket for a granted waiter and install the audit
    ContextVar (caller holds the lock; the token rides the ticket so the
    matching release resets exactly this set)."""
    wait_ms = max(0, int((time.monotonic() - started) * 1000))
    token = _ADMISSION_CTX.set((str(waiter.cls), wait_ms))
    ticket = AdmissionTicket(
        cls=waiter.cls, wait_ms=wait_ms, agent_id=waiter.agent_id
    )
    ticket._waiter = waiter
    ticket._ctx_token = token
    return ticket


async def admit(
    tool_name: str,
    agent_id: str,
    wait_s: float,
    actor_key: str | None = None,
) -> AdmissionTicket:
    """Bounded, cancellation-safe async admit (the request-loop guard).

    Parks on small anyio-friendly sleeps; host-task cancellation surfaces
    at the next tick and the except arm reclaims every partial stage — a
    cancelled admit leaves no permit, actor slot, or queue entry.
    """
    waiter, bound = _enter(tool_name, agent_id, wait_s, actor_key)
    started = time.monotonic()
    deadline = started + bound
    try:
        while True:
            with _LOCK:
                if waiter.granted:
                    return _issue(waiter, started)
                if time.monotonic() >= deadline:
                    raise AdmissionBusy(_retry_after_ms(bound))
            await anyio.sleep(_TICK_S)
    except BaseException:
        with _LOCK:
            _retire(waiter)
        raise


def admit_sync(
    tool_name: str,
    agent_id: str,
    wait_s: float,
    actor_key: str | None = None,
    stop_event: threading.Event | None = None,
) -> AdmissionTicket:
    """The synchronous twin of admit() (the detached runner's flavor):
    the same core, tick-bounded, observing `stop_event` every tick — a
    set event aborts the wait as AdmissionStopped with every stage
    reclaimed."""
    waiter, bound = _enter(tool_name, agent_id, wait_s, actor_key)
    started = time.monotonic()
    deadline = started + bound
    try:
        while True:
            with _LOCK:
                if waiter.granted:
                    return _issue(waiter, started)
                if time.monotonic() >= deadline:
                    raise AdmissionBusy(_retry_after_ms(bound))
            if stop_event is not None and stop_event.is_set():
                raise AdmissionStopped
            time.sleep(_TICK_S)
    except BaseException:
        with _LOCK:
            _retire(waiter)
        raise


def release_sync(ticket: AdmissionTicket) -> None:
    """Free both stages an admit acquired and reset the audit ContextVar
    (the token discipline means a sequential call never reads the previous
    call's class/wait)."""
    waiter = ticket._waiter
    with _LOCK:
        if waiter is not None:
            _retire(waiter)
    token = ticket._ctx_token
    if token is not None:
        try:
            _ADMISSION_CTX.reset(token)
        except ValueError:
            # The ticket was issued in a DIFFERENT context (a caller driving
            # admit/release across event-loop boundaries): reset cannot
            # cross contexts, so clear this context's value instead — the
            # issuing context already ended, so no telemetry can bleed from
            # it either way.
            _ADMISSION_CTX.set(None)


async def release(ticket: AdmissionTicket) -> None:
    """Async release (the guard's finally): same core as release_sync."""
    release_sync(ticket)


def configure(
    *,
    total_tokens: int,
    light_reserve: int | None,
    wait_s: float,
    light_wait_s: float | None = None,
) -> None:
    """Size the budget (bootstrap: total = 2 x max_host_powershell).

    light_reserve omitted (None) resolves to min(2, total_tokens - 1) —
    the bootstrap-valid default at every cap including 1. A SUPPLIED value
    is validated 0 <= light_reserve < total_tokens (a reserve at or above
    the budget leaves zero general capacity) and REJECTED with ValueError
    — never clamped. Validation happens before any state moves, so a
    refused configure leaves the running budget untouched.
    """
    global _TOTAL_TOKENS, _LIGHT_RESERVE, _WAIT_S, _LIGHT_WAIT_S, _CONFIGURED
    if isinstance(total_tokens, bool) or not isinstance(total_tokens, int):
        raise ValueError("admission total_tokens must be an integer >= 1")
    if total_tokens < 1:
        raise ValueError("admission total_tokens must be an integer >= 1")
    if not _is_number(wait_s) or wait_s < 0:
        raise ValueError("admission wait_s must be a number >= 0")
    if light_wait_s is not None and (not _is_number(light_wait_s) or light_wait_s < 0):
        raise ValueError("admission light_wait_s must be a number >= 0 or None")
    if light_reserve is None:
        resolved = min(2, total_tokens - 1)
    else:
        if isinstance(light_reserve, bool) or not isinstance(light_reserve, int):
            raise ValueError(
                "admission light_reserve must be an integer or None (omitted)"
            )
        if not 0 <= light_reserve < total_tokens:
            raise ValueError(
                f"admission light_reserve {light_reserve} must satisfy "
                f"0 <= light_reserve < total_tokens ({total_tokens}): a reserve "
                f"at or above the budget leaves zero general capacity"
            )
        resolved = light_reserve
    with _LOCK:
        _reset_core()
        _TOTAL_TOKENS = total_tokens
        _LIGHT_RESERVE = resolved
        _WAIT_S = float(wait_s)
        _LIGHT_WAIT_S = None if light_wait_s is None else float(light_wait_s)
        _CONFIGURED = True


def snapshot() -> dict[str, int]:
    """A consistent telemetry copy: in-flight counts per lane, the
    resolved reserve, the budget, and the parked-waiter depths
    (fair_queue_depth counts every parked admit across both stages;
    actor_queue_depth the stage-1 parks)."""
    with _LOCK:
        actor_parked = sum(len(actor.waiters) for actor in _ACTORS.values())
        return {
            "in_flight_general": _IN_FLIGHT_GENERAL,
            "in_flight_light": _IN_FLIGHT_LIGHT,
            "reserved": _LIGHT_RESERVE,
            "total_tokens": _TOTAL_TOKENS,
            "fair_queue_depth": len(_LANE) + actor_parked,
            "actor_queue_depth": actor_parked,
        }


def _reset_core() -> None:
    """Drop every queue and counter (caller holds the lock)."""
    global _IN_FLIGHT_GENERAL, _IN_FLIGHT_LIGHT
    _IN_FLIGHT_GENERAL = 0
    _IN_FLIGHT_LIGHT = 0
    _LANE.clear()
    _LANE_AGENTS.clear()
    _ACTORS.clear()


def reset() -> None:
    """Test seam: unconfigure and clear every queue/counter."""
    global _TOTAL_TOKENS, _LIGHT_RESERVE, _WAIT_S, _LIGHT_WAIT_S, _CONFIGURED
    with _LOCK:
        _reset_core()
        _TOTAL_TOKENS = 0
        _LIGHT_RESERVE = 0
        _WAIT_S = 30.0
        _LIGHT_WAIT_S = None
        _CONFIGURED = False
