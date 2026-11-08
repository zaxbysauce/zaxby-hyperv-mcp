"""Issue #68 supplement (workstream C) — admission fairness reserve checks.

Phase 4 adds src/hyperv_mcp/admission.py: a TWO-STAGE admission layer in
front of the tool-limiter resize (_make_tool_limiter_lifespan sizes
anyio's default thread limiter to 2 x max_host_powershell but reserves no
class for PS-free tools, so lock-queued GENERAL callers can delay them up
to vm_lock_wait_s — the documented bound this layer closes). The module
API these checks encode (arm's-length: the module does not exist at base,
so this file's RED signature at base is the import itself):

  - AdmissionClass: LIGHT and GENERAL (StrEnum-like; str() gives the name);
  - classify_tool(tool_name): status/readiness/list/info/jobs-status
    surfaces are LIGHT, everything else GENERAL;
  - configure(total_tokens, light_reserve, wait_s, light_wait_s=None):
    the token budget (total_tokens = 2 x max_host_powershell, mirroring
    the lifespan sizing) with a light reserve — every knob bounds an
    admission axis (the OperationsPolicy convention), and the cross-field
    rule light_reserve < total_tokens is validated at configure time with
    ValueError (a reserve equal to or above the budget leaves zero
    general capacity);
  - admit(tool_name, agent_id, wait_s, actor_key=None) -> ticket (.cls,
    .wait_ms, .agent_id). TWO-STAGE when actor_key is given (the console
    actor shape): stage 1 waits in a per-actor-key fair queue of capacity
    1 (bounded wait, cancellation observed, per-agent fairness inside the
    actor queue), and ONLY THEN stage 2 acquires the general permit — an
    actor-queued caller NEVER holds a general permit while queued
    (actor eligibility BEFORE token acquisition, per the issue #68
    supplement: K agents fanning in on one VM must not occupy every
    token and starve unrelated PS-free traffic — the exact starvation the
    layer exists to close). actor_key=None is single-stage: the light
    lane or a general permit directly. Raises
    AdmissionBusy(retry_after_ms) on exhaustion — the retry_after_ms
    precedent is operations._busy_envelope;
  - release(ticket): frees BOTH stages an admit acquired;
  - snapshot() (telemetry seam: in_flight_general, in_flight_light,
    reserved, total_tokens, fair_queue_depth — fair_queue_depth counts
    every parked admit across both stages; an implementation may
    additionally expose actor_queue_depth), reset() (test seam).

Semantics pinned here:

  A1  reserved light lane — when total_tokens - light_reserve general
      permits are all held, a LIGHT admit still succeeds within
      light_wait_s while a GENERAL admit raises AdmissionBusy;
  A2  agent fairness — GENERAL admits queue per-agent round-robin on the
      general lane (a plain FIFO that serves one agent's whole backlog
      first starves the other agent) AND inside a contended actor queue;
  A3  cancellation — an admit cancelled while waiting (EITHER stage)
      re-raises the cancellation promptly (observed per wait tick, not
      after the full bound) and never half-issues a ticket: no permit,
      actor-slot, or queue leak;
  A4  bounded wait — admit against a saturated budget raises
      AdmissionBusy with retry_after_ms > 0 inside wait_s on the general
      lane AND on the actor stage, never unbounded;
  A5  two-stage ordering — a waiter queued for a held actor key holds NO
      general permit: in_flight_general during the actor-queue park is
      the holders only, and the AC8 fan-in peak stays at or below
      general capacity - 1;
  AC8 canonical-actor integration — K agents fanning raw-input admits
      onto one VM serialize through console._input_lock semantics (both
      addressing aliases key the canonical GUID, one-at-a-time), a LIGHT
      admit completes while the actor queue is parked, general tokens
      are never exhausted by actor-waiting callers, and the actor queue
      drains to zero (no queue leak).

All legs are hermetic: no PowerShell spawn, no host, no network; each
test runs well under 5 s. The console actor seam is driven directly (a
counting _input_lock replacement) — no live VM.
"""

import asyncio
import threading
import time
from contextlib import contextmanager

import anyio

# `import hyperv_mcp.admission` (not `from hyperv_mcp import admission`) so
# the base-leg RED signature is exactly
# ModuleNotFoundError: No module named 'hyperv_mcp.admission'.
import hyperv_mcp.admission as admission
import pytest

from hyperv_mcp import console, vmident

_LIGHT_TOOLS = (
    "hyperv_list_vms",
    "hyperv_server_info",
    "hyperv_get_vm_info",
    "hyperv_guest_job_status",
)
_GENERAL_TOOLS = (
    "hyperv_start_vm",
    "hyperv_console_type_text",
    "hyperv_guest_run",
)
_RAW_INPUT_TOOL = "hyperv_console_type_text"
_LIGHT_TOOL = "hyperv_list_vms"


async def _wait_until(predicate, timeout_s: float, what: str) -> None:
    """Poll an async-observable predicate until true or fail naming it."""
    deadline = time.monotonic() + timeout_s
    while not predicate():
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        await asyncio.sleep(0.005)


def _queue_depth() -> int:
    """Parked-admit depth: the actor-stage seam when the implementation
    exposes one (actor_queue_depth), else fair_queue_depth (which must
    then count every parked admit across both stages)."""
    snap = admission.snapshot()
    return int(snap.get("actor_queue_depth", snap["fair_queue_depth"]))


def test_classify_and_budget_snapshot():
    """The module surface: classification registry + budget snapshot seam.

    LIGHT is exactly the status/readiness/list/info/jobs-status surfaces;
    every other tool (mutating, guest-exec, console input) is GENERAL.
    str() of a class gives its name; snapshot() carries the telemetry keys
    and reflects the configured budget on a clean (reset) state; and
    configure() validates the cross-field rule light_reserve <
    total_tokens (light_wait_s optional).
    """

    async def _main():
        admission.reset()
        # light_wait_s omitted: the single-stage default must be accepted.
        admission.configure(total_tokens=4, light_reserve=2, wait_s=1.0)
        snap = admission.snapshot()
        for key in (
            "in_flight_general", "in_flight_light", "reserved",
            "total_tokens", "fair_queue_depth",
        ):
            assert key in snap, f"snapshot must carry the seam key {key!r}: {snap}"
        assert snap["total_tokens"] == 4
        assert snap["reserved"] == 2
        assert snap["in_flight_general"] == 0
        assert snap["in_flight_light"] == 0
        assert snap["fair_queue_depth"] == 0

        # Cross-field validation: a reserve that leaves no general
        # capacity (equal to or above the budget) fails at configure time.
        with pytest.raises(ValueError):
            admission.configure(
                total_tokens=4, light_reserve=4, wait_s=1.0, light_wait_s=0.5
            )
        with pytest.raises(ValueError):
            admission.configure(total_tokens=4, light_reserve=5, wait_s=1.0)

    asyncio.run(_main())
    assert str(admission.AdmissionClass.LIGHT) == "LIGHT"
    assert str(admission.AdmissionClass.GENERAL) == "GENERAL"
    for name in _LIGHT_TOOLS:
        assert admission.classify_tool(name) is admission.AdmissionClass.LIGHT, (
            f"{name} is a status/readiness/list/info/jobs-status surface"
        )
    for name in _GENERAL_TOOLS:
        assert admission.classify_tool(name) is admission.AdmissionClass.GENERAL, (
            f"{name} must classify GENERAL (everything non-LIGHT is GENERAL)"
        )


def test_light_lane_reserved_while_general_saturated():
    """A1: with total_tokens - light_reserve general permits held, LIGHT
    admits still flow through the reserved capacity (within light_wait_s)
    while a GENERAL admit inside wait_s raises AdmissionBusy carrying a
    retry hint."""

    async def _main():
        admission.reset()
        admission.configure(
            total_tokens=4, light_reserve=2, wait_s=0.5, light_wait_s=0.5
        )
        general_capacity = 4 - 2  # total_tokens - light_reserve
        held = []
        for _ in range(general_capacity):
            ticket = await admission.admit(
                "hyperv_start_vm", "holder", wait_s=0.5
            )
            assert ticket.cls == admission.AdmissionClass.GENERAL
            assert ticket.agent_id == "holder"
            assert ticket.wait_ms >= 0
            held.append(ticket)
        assert admission.snapshot()["in_flight_general"] == general_capacity

        # The reserved lane: both light admits succeed promptly while the
        # general lane is saturated.
        lights = []
        for reader in ("reader-a", "reader-b"):
            started = time.monotonic()
            ticket = await admission.admit(_LIGHT_TOOL, reader, wait_s=0.5)
            assert ticket.cls == admission.AdmissionClass.LIGHT
            assert ticket.agent_id == reader
            assert time.monotonic() - started <= 0.5
            lights.append(ticket)
        assert admission.snapshot()["in_flight_light"] == 2

        # The budget is now fully held (2 general + 2 light): a further
        # LIGHT admit is bounded by light_wait_s and refuses with a hint.
        with pytest.raises(admission.AdmissionBusy) as busy_light:
            await admission.admit(_LIGHT_TOOL, "reader-c", wait_s=0.05)
        assert busy_light.value.retry_after_ms > 0

        # The GENERAL lane cannot reach the reserve: bounded refusal.
        with pytest.raises(admission.AdmissionBusy) as busy_general:
            await admission.admit("hyperv_start_vm", "blocked", wait_s=0.05)
        assert busy_general.value.retry_after_ms > 0

        for ticket in held:
            await admission.release(ticket)
        for ticket in lights:
            await admission.release(ticket)
        snap = admission.snapshot()
        assert snap["in_flight_general"] == 0
        assert snap["in_flight_light"] == 0
        assert snap["fair_queue_depth"] == 0

    asyncio.run(_main())


def test_agent_fair_queue_no_starvation():
    """A2 (both stages): GENERAL admits queue per-agent round-robin.

    General lane: both general permits are harness-held; agent-a parks K
    admits first, then agent-b parks K — a plain FIFO queue (or any
    priority that reorders by arrival) serves agent-a's whole backlog
    first, so the first two grants must go to DIFFERENT agents.

    Actor stage: one actor key is harness-held; agent-x then agent-y park
    two TWO-STAGE admits each — the same first-two-grants alternation
    applies inside the actor queue, the queued waiters hold NO general
    permit (A5), and afterwards both agents drain all their admits inside
    the bounded window (no starvation across it)."""

    K = 3  # general-lane admits per agent
    AK = 2  # actor-stage admits per agent

    async def _main():
        admission.reset()
        admission.configure(
            total_tokens=4, light_reserve=2, wait_s=5.0, light_wait_s=1.0
        )

        # ---- phase 1: the general lane (single-stage admits) ----
        harness = [
            await admission.admit("hyperv_start_vm", f"harness-{i}", wait_s=0.5)
            for i in range(2)  # general capacity = 4 - 2
        ]
        assert admission.snapshot()["in_flight_general"] == 2

        completions: list[str] = []  # agent ids in grant order
        depth_peak = {"n": 0}

        async def _queued_admit(agent_id: str) -> None:
            ticket = await admission.admit("hyperv_start_vm", agent_id, wait_s=5.0)
            completions.append(agent_id)
            await admission.release(ticket)

        async def _agent(agent_id: str) -> None:
            async with anyio.create_task_group() as tg:
                for _ in range(K):
                    tg.start_soon(_queued_admit, agent_id)

        async def _sampler(stop: asyncio.Event) -> None:
            while not stop.is_set():
                depth_peak["n"] = max(
                    depth_peak["n"], admission.snapshot()["fair_queue_depth"]
                )
                await asyncio.sleep(0.005)

        stop = asyncio.Event()
        sampler = asyncio.create_task(_sampler(stop))

        agent_a = asyncio.create_task(_agent("agent-a"))
        await _wait_until(
            lambda: admission.snapshot()["fair_queue_depth"] >= K,
            timeout_s=2.0, what="agent-a admits to park",
        )
        agent_b = asyncio.create_task(_agent("agent-b"))
        await _wait_until(
            lambda: admission.snapshot()["fair_queue_depth"] >= 2 * K,
            timeout_s=2.0, what="agent-b admits to park",
        )

        # Release ONE permit at a time: the fair window must alternate
        # agents, so the first two grants land on different agents.
        await admission.release(harness[0])
        await _wait_until(
            lambda: len(completions) >= 1, timeout_s=2.0, what="first grant",
        )
        await admission.release(harness[1])
        await _wait_until(
            lambda: len(completions) >= 2, timeout_s=2.0, what="second grant",
        )
        assert set(completions[:2]) == {"agent-a", "agent-b"}, (
            f"the fair queue must alternate agents (per-agent round robin); "
            f"grant order was {completions}"
        )

        # Drain: both agents complete ALL K admits inside the window —
        # each agent's ticket count reaches K (well over half of K).
        await asyncio.wait_for(agent_a, timeout=5.0)
        await asyncio.wait_for(agent_b, timeout=5.0)
        stop.set()
        await asyncio.wait_for(sampler, timeout=2.0)

        assert completions.count("agent-a") == K
        assert completions.count("agent-b") == K
        assert depth_peak["n"] <= 2 * K, (
            f"queued depth exceeded the submitted admits: {depth_peak['n']}"
        )
        snap = admission.snapshot()
        assert snap["in_flight_general"] == 0
        assert snap["fair_queue_depth"] == 0

        # ---- phase 2: the actor stage (two-stage admits, one actor key) --
        actor_key = "fair-actor-key"
        actor = await admission.admit(
            "hyperv_start_vm", "actor", wait_s=0.5, actor_key=actor_key
        )
        assert admission.snapshot()["in_flight_general"] == 1

        actor_completions: list[str] = []  # agent ids in actor-grant order

        async def _actor_admit(agent_id: str) -> None:
            ticket = await admission.admit(
                "hyperv_start_vm", agent_id, wait_s=5.0, actor_key=actor_key
            )
            actor_completions.append(agent_id)
            await admission.release(ticket)

        async def _actor_agent(agent_id: str) -> None:
            async with anyio.create_task_group() as tg:
                for _ in range(AK):
                    tg.start_soon(_actor_admit, agent_id)

        agent_x = asyncio.create_task(_actor_agent("agent-x"))
        await _wait_until(
            lambda: _queue_depth() >= AK, timeout_s=2.0,
            what="agent-x actor admits to park",
        )
        agent_y = asyncio.create_task(_actor_agent("agent-y"))
        await _wait_until(
            lambda: _queue_depth() >= 2 * AK, timeout_s=2.0,
            what="agent-y actor admits to park",
        )
        # A5, directly: the actor-queued waiters hold NO general permit —
        # the only in-flight general token is the actor holder's.
        assert admission.snapshot()["in_flight_general"] == 1, (
            "an actor-queued waiter must not hold a general permit while "
            f"queued: {admission.snapshot()}"
        )

        # Freeing the actor (both stages) starts the drain; capacity 1
        # serializes grants, so the first two completions are the first
        # two actor grants and must come from DIFFERENT agents.
        await admission.release(actor)
        await _wait_until(
            lambda: len(actor_completions) >= 2, timeout_s=3.0,
            what="the first two actor-stage grants",
        )
        assert set(actor_completions[:2]) == {"agent-x", "agent-y"}, (
            f"the actor queue must alternate agents (per-agent round robin); "
            f"grant order was {actor_completions}"
        )
        await asyncio.wait_for(agent_x, timeout=5.0)
        await asyncio.wait_for(agent_y, timeout=5.0)
        assert actor_completions.count("agent-x") == AK
        assert actor_completions.count("agent-y") == AK
        snap2 = admission.snapshot()
        assert snap2["in_flight_general"] == 0
        assert snap2["fair_queue_depth"] == 0
        if "actor_queue_depth" in snap2:
            assert snap2["actor_queue_depth"] == 0

    asyncio.run(_main())


def test_admit_cancellation_observed_and_no_permit_leak():
    """A3 (both stages): an admit cancelled while parked re-raises the
    cancellation promptly (each wait tick observes it — not after the full
    10 s bound) and never half-issues a ticket: in_flight_general returns
    to just the held permit, the queue drains, and the budget closes
    cleanly. Pinned for the general lane AND for the actor stage."""

    async def _main():
        cancelled_cls = anyio.get_cancelled_exc_class()
        admission.reset()
        admission.configure(
            total_tokens=2, light_reserve=1, wait_s=10.0, light_wait_s=1.0
        )

        # ---- stage: the general lane ----
        held = await admission.admit("hyperv_start_vm", "holder", wait_s=0.5)
        # general capacity = 2 - 1 = 1: the waiter below must park.
        assert admission.snapshot()["in_flight_general"] == 1

        task = asyncio.create_task(
            admission.admit("hyperv_start_vm", "waiter", wait_s=10.0)
        )
        await _wait_until(
            lambda: admission.snapshot()["fair_queue_depth"] >= 1,
            timeout_s=2.0, what="the waiter to park in the fair queue",
        )

        started = time.monotonic()
        task.cancel()
        with pytest.raises(cancelled_cls):
            await asyncio.wait_for(task, timeout=2.0)
        cancelled_elapsed = time.monotonic() - started
        assert cancelled_elapsed < 2.0, (
            f"cancellation must surface at the next wait tick, not after "
            f"the 10 s bound (took {cancelled_elapsed:.2f}s)"
        )

        # No permit leak: the cancelled admit issued no ticket.
        snap = admission.snapshot()
        assert snap["in_flight_general"] == 1, (
            f"a cancelled admit leaked a general permit: {snap}"
        )
        assert snap["fair_queue_depth"] == 0
        await admission.release(held)
        snap_lane = admission.snapshot()
        assert snap_lane["in_flight_general"] == 0
        assert snap_lane["fair_queue_depth"] == 0

        # ---- stage: the actor queue (two-stage admit) ----
        actor_key = "cancel-actor-key"
        actor = await admission.admit(
            "hyperv_start_vm", "actor-holder", wait_s=0.5, actor_key=actor_key
        )
        assert admission.snapshot()["in_flight_general"] == 1

        actor_task = asyncio.create_task(
            admission.admit(
                "hyperv_start_vm", "actor-waiter", wait_s=10.0,
                actor_key=actor_key,
            )
        )
        await _wait_until(
            lambda: _queue_depth() >= 1, timeout_s=2.0,
            what="the actor waiter to park in the actor queue",
        )
        # A5: the parked actor waiter holds NO general permit.
        assert admission.snapshot()["in_flight_general"] == 1

        started_actor = time.monotonic()
        actor_task.cancel()
        with pytest.raises(cancelled_cls):
            await asyncio.wait_for(actor_task, timeout=2.0)
        actor_elapsed = time.monotonic() - started_actor
        assert actor_elapsed < 2.0, (
            f"actor-stage cancellation must surface at the next wait tick "
            f"(took {actor_elapsed:.2f}s)"
        )

        # No leak on EITHER stage: the cancelled waiter released its actor
        # queue entry (no ghost waiter) and never held a permit.
        snap_actor = admission.snapshot()
        assert snap_actor["in_flight_general"] == 1
        assert snap_actor["fair_queue_depth"] == 0
        if "actor_queue_depth" in snap_actor:
            assert snap_actor["actor_queue_depth"] == 0
        await admission.release(actor)
        snap_final = admission.snapshot()
        assert snap_final["in_flight_general"] == 0
        assert snap_final["fair_queue_depth"] == 0

    asyncio.run(_main())


def test_bounded_wait_raises_admission_busy():
    """A4 (both stages): admit against a saturated budget with wait_s=0.05
    raises AdmissionBusy with retry_after_ms > 0 inside the bound — the
    wait is never unbounded and the accounting stays clean, on the general
    lane AND on the actor stage (a held actor key refuses the second
    caller without ever issuing a permit)."""

    async def _main():
        admission.reset()
        admission.configure(
            total_tokens=2, light_reserve=1, wait_s=0.05, light_wait_s=0.05
        )

        # ---- the general lane ----
        held = await admission.admit("hyperv_start_vm", "holder", wait_s=0.5)
        assert admission.snapshot()["in_flight_general"] == 1

        started = time.monotonic()
        with pytest.raises(admission.AdmissionBusy) as busy:
            await admission.admit("hyperv_start_vm", "starved", wait_s=0.05)
        elapsed = time.monotonic() - started
        assert busy.value.retry_after_ms > 0
        assert elapsed < 1.0, (
            f"the wait must be bounded by wait_s (waited {elapsed:.2f}s)"
        )
        snap = admission.snapshot()
        assert snap["in_flight_general"] == 1
        assert snap["fair_queue_depth"] == 0
        await admission.release(held)
        assert admission.snapshot()["in_flight_general"] == 0

        # ---- the actor stage ----
        actor_key = "busy-actor-key"
        actor = await admission.admit(
            "hyperv_start_vm", "actor-holder", wait_s=0.5, actor_key=actor_key
        )
        assert admission.snapshot()["in_flight_general"] == 1

        started_actor = time.monotonic()
        with pytest.raises(admission.AdmissionBusy) as actor_busy:
            await admission.admit(
                "hyperv_start_vm", "actor-blocked", wait_s=0.05,
                actor_key=actor_key,
            )
        actor_elapsed = time.monotonic() - started_actor
        assert actor_busy.value.retry_after_ms > 0
        assert actor_elapsed < 1.0, (
            f"the actor-stage wait must be bounded by wait_s "
            f"(waited {actor_elapsed:.2f}s)"
        )
        # The refused actor waiter never held a permit and left no queue
        # entry behind.
        snap_actor = admission.snapshot()
        assert snap_actor["in_flight_general"] == 1
        assert snap_actor["fair_queue_depth"] == 0
        await admission.release(actor)
        snap_final = admission.snapshot()
        assert snap_final["in_flight_general"] == 0
        assert snap_final["fair_queue_depth"] == 0

    asyncio.run(_main())


def test_shared_vm_actor_serialization_under_agent_fan_in(monkeypatch):
    """AC8 (C09): the canonical console actor under K-agent fan-in, driven
    through the TWO-STAGE admission shape. One actor holds the actor key
    (stage 1), one general permit (stage 2), and the console input lock
    for the VM; K agents (alternating the two addressing aliases) submit
    raw-input admits with the SAME actor key — they queue actor-first and
    hold NO general permit while queued. Asserted:

      1. both aliases (by-name through the issue-#77 hint, and by-GUID)
         derive the SAME lock key and serialize exactly one-at-a-time
         (the counting _input_lock replacement never observes overlap);
      2. a LIGHT admit completes while the actor queue is parked (the
         read/status reservation is preserved under fan-in);
      3. general tokens are never exhausted by actor-waiting callers: the
         sampled in_flight_general peak stays at or below GENERAL
         capacity - 1 (total_tokens - light_reserve - 1), because the
         only general holders are the actor itself and, after it drains,
         one admitted waiter at a time;
      4. the actor queue drains to zero after the run (no queue leak).
    """
    guid = "ac8e0000-0000-4000-8000-000000000001"
    vm_name = "ac8-vm"
    K = 4

    # The canonical actor seam, counted: every entry serializes on ONE
    # threading.Lock (exactly one-at-a-time) and records the derived key
    # (ref.id) plus the addressing alias that produced it.
    entries: list[tuple[str, str]] = []
    overlap = {"now": 0, "max": 0}
    serialize = threading.Lock()

    @contextmanager
    def _counting_input_lock(ref):
        with serialize:
            overlap["now"] += 1
            overlap["max"] = max(overlap["max"], overlap["now"])
            entries.append((ref.id, ref.name))
            try:
                yield
            finally:
                overlap["now"] -= 1

    monkeypatch.setattr(console, "_input_lock", _counting_input_lock)

    # The two addressing aliases of the SAME VM: by-name (the issue-#77
    # hinted path keys the canonical GUID) and by-GUID.
    console.note_name_guid_hint(vm_name, guid)
    hinted = console._hint_for(vm_name)
    assert hinted == guid, "the hint must carry the canonical GUID"
    ref_by_name = vmident.VMRef(id=hinted, name=vm_name)
    ref_by_guid = vmident.VMRef(id=guid, name=guid)
    assert ref_by_name.id == ref_by_guid.id == guid

    async def _main():
        admission.reset()
        admission.configure(
            total_tokens=4, light_reserve=2, wait_s=4.0, light_wait_s=1.0
        )
        budget = admission.snapshot()
        general_capacity = budget["total_tokens"] - budget["reserved"]
        assert general_capacity == 2, (
            f"scenario arithmetic needs general capacity 2: {budget}"
        )
        # The actor takes the actor key (stage 1) and then one general
        # permit (stage 2); the K agents below queue actor-first and hold
        # NO general permit while queued (A5).
        actor_lock_held = threading.Event()
        actor_release = threading.Event()

        actor_ticket = await admission.admit(
            _RAW_INPUT_TOOL, "actor", wait_s=1.0, actor_key=guid
        )
        assert actor_ticket.cls == admission.AdmissionClass.GENERAL
        assert admission.snapshot()["in_flight_general"] == 1

        def _actor_hold():
            with console._input_lock(ref_by_name):
                actor_lock_held.set()
                actor_release.wait(timeout=10)

        actor_task = asyncio.create_task(
            anyio.to_thread.run_sync(_actor_hold)
        )
        await _wait_until(
            actor_lock_held.is_set, timeout_s=2.0,
            what="the actor to take the console lock",
        )

        in_flight_peak = {"n": 0}

        async def _sampler(stop: asyncio.Event) -> None:
            while not stop.is_set():
                in_flight_peak["n"] = max(
                    in_flight_peak["n"],
                    admission.snapshot()["in_flight_general"],
                )
                await asyncio.sleep(0.004)

        stop = asyncio.Event()
        sampler = asyncio.create_task(_sampler(stop))

        async def _fan_in_agent(i: int) -> None:
            ref = ref_by_name if i % 2 == 0 else ref_by_guid
            ticket = await admission.admit(
                _RAW_INPUT_TOOL, f"agent-{i}", wait_s=4.0, actor_key=guid
            )
            try:
                def _type_under_actor():
                    with console._input_lock(ref):
                        time.sleep(0.01)
                await anyio.to_thread.run_sync(_type_under_actor)
            finally:
                await admission.release(ticket)

        agents = [asyncio.create_task(_fan_in_agent(i)) for i in range(K)]
        await _wait_until(
            lambda: _queue_depth() >= K, timeout_s=2.0,
            what="the fan-in agents to park in the actor queue",
        )
        # A5, directly: all K waiters are parked for the actor key and the
        # ONLY in-flight general token is the actor's own.
        parked = admission.snapshot()
        assert parked["in_flight_general"] == 1, (
            f"actor-queued waiters must hold no general permit: {parked}"
        )

        # (2) the LIGHT lane still admits while the actor queue is parked.
        started = time.monotonic()
        light_ticket = await admission.admit(
            _LIGHT_TOOL, "read-probe", wait_s=1.0
        )
        assert light_ticket.cls == admission.AdmissionClass.LIGHT
        assert time.monotonic() - started <= 1.0
        await admission.release(light_ticket)

        # Release the actor (console lock first, then both admission
        # stages); the fan-in drains through the single lock.
        actor_release.set()
        await asyncio.wait_for(actor_task, timeout=5.0)
        await admission.release(actor_ticket)
        for agent in agents:
            await asyncio.wait_for(agent, timeout=5.0)
        stop.set()
        await asyncio.wait_for(sampler, timeout=2.0)

        # (1) both aliases serialized through the same lock, one at a time.
        assert overlap["max"] == 1, (
            f"console submissions overlapped across aliases: "
            f"max concurrent {overlap['max']}"
        )
        assert len(entries) == K + 1, (
            f"the actor plus every agent must enter the lock: {entries}"
        )
        keys = {key for key, _ in entries}
        assert keys == {guid}, (
            f"both addressing aliases must key the canonical GUID: {keys}"
        )
        aliases = {alias for _, alias in entries}
        assert aliases == {vm_name, guid}, (
            f"the fan-in must exercise both addressing spellings: {aliases}"
        )

        # (3) general tokens were never exhausted by actor-waiting callers:
        # the peak sits at or below general capacity - 1 (the actor's own
        # token is the only holder while the queue is parked, and at most
        # one admitted waiter at a time after the drain begins).
        assert 1 <= in_flight_peak["n"] <= general_capacity - 1, (
            f"in_flight_general peaked at {in_flight_peak['n']} against "
            f"general capacity {general_capacity} (actor-waiting callers "
            f"must never hold the lane's last token)"
        )

        # (4) no queue leak: the actor queue (and the fair queue seam)
        # drains to zero, and both token lanes close cleanly.
        snap = admission.snapshot()
        assert snap["in_flight_general"] == 0
        assert snap["in_flight_light"] == 0
        assert snap["fair_queue_depth"] == 0, (
            f"actor queue did not drain after the fan-in: {snap}"
        )
        if "actor_queue_depth" in snap:
            assert snap["actor_queue_depth"] == 0

    asyncio.run(_main())
