"""Issue #68 supplement (workstream C) — production dispatch coverage.

The frozen fairness checks (tests/unit/test_admission_fairness.py) pin the
admission module's semantics at arm's length; this unfrozen census drives
the REAL dispatch surfaces that interpose it — the server's pre-Tool.run
guard for body-bound calls and the detached/task runner's admit_sync leg —
so the wiring itself stays pinned against regressions the module tests
cannot see:

  D1  a normal tool call through the REAL guard admits exactly once,
      releases on every exit, and the audit row carries the admit's class
      and measured wait;
  D2  the detach:true path admits exactly once (runner-side; the guard
      never admits a diverted call) and the runner's operation row carries
      the admission fields;
  D3  two distinct authenticated agents alternating the two addressing
      aliases (by-name through the issue-#77 hint, by-GUID) of one VM hit
      ONE canonical actor queue: raw-input bodies never overlap, a LIGHT
      call progresses while the actor queue is parked, and
      in_flight_general stays below general capacity the whole time;
  D4  stage-2 companion legs — stage 1 granted + stage 2 saturated ->
      cancel AND timeout separately free the actor slot and every queue
      depth returns to zero; the sync runner path honors its stop event;
  D5  cap-1 bootstrap: the omitted default (total 2, reserve 1) is valid
      and an explicit light_reserve=2 at total 2 is REJECTED at bootstrap;
  D6  a NON-default retry hint (1234.0) survives EXACTLY through the
      normal, detached, and task paths — client envelope, stored op
      envelope, and audit rows;
  D7  sequential calls never bleed admission telemetry: each row's class
      is its own call's, never the previous call's.

Hermetic: no PowerShell spawn (content-dispatched run_ps fakes), no host,
no network; every wait is a bounded poll. Whole-file runtime is well under
60 s.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import threading
import time
from pathlib import Path
from typing import Literal

import anyio
import pytest
from mcp import ClientSession
from mcp.client._memory import InMemoryTransport
from mcp.client.extension import ResultClaim
from mcp.server.auth.middleware.auth_context import (
    AccessToken,
    AuthenticatedUser,
    auth_context_var,
)
from mcp.types import CallToolResult
from mcp_types import Request, RequestParams, Result

import hyperv_mcp.server as server_module
from hyperv_mcp import admission, console, operations, pswindows

GUID = "d4d1d1d1-0000-4000-8000-0000000000aa"
TASKS_ID = "io.modelcontextprotocol/tasks"
NONDEFAULT_RETRY_MS = 1234.0

RAW_INPUT_TOOL = "hyperv_console_type_text"
LIGHT_TOOL = "hyperv_list_vms"
GENERAL_TOOL = "hyperv_relay_status"
RESTORE_ARGS = {"vm_name": "test-vm", "checkpoint_name": "snap", "confirm": True}


class GatedFakePS:
    """Content-dispatched, thread-safe run_ps fake (the e03 tasks-bridge
    pattern): the by-name resolver leg answers the stable GUID, restore
    legs succeed, and the console type-text leg is COUNTED and (for the
    first call only) gated so the choreography can park the actor queue."""

    def __init__(self) -> None:
        self.gate = threading.Event()
        self._lock = threading.Lock()
        self.type_calls = 0
        self.type_overlap_now = 0
        self.type_overlap_max = 0

    def __call__(self, script, **kwargs):
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if "MethodName TypeText" in script:
            with self._lock:
                self.type_calls += 1
                self.type_overlap_now += 1
                self.type_overlap_max = max(
                    self.type_overlap_max, self.type_overlap_now)
                first = self.type_calls == 1
            try:
                if first:
                    # The choreography releases this only after asserting the
                    # parked state; bounded so a broken test cannot hang.
                    self.gate.wait(timeout=15.0)
                else:
                    time.sleep(0.01)
                return pswindows.PSResult(stdout="", returncode=0)
            finally:
                with self._lock:
                    self.type_overlap_now -= 1
        if "final_state" in script:
            return pswindows.PSResult(stdout='{"final_state": "Off"}', returncode=0)
        return pswindows.PSResult(stdout="{}", returncode=0)


def _as_agent(client_id: str):
    return auth_context_var.set(
        AuthenticatedUser(AccessToken(token="t", client_id=client_id, scopes=[]))
    )


def _payload(result, label: str) -> dict:
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    assert texts, f"expected a JSON text payload for {label}"
    payload = json.loads(texts[0].text)
    assert isinstance(payload, dict), f"{label}: payload is not an object"
    return payload


def _rows(audit_path: Path) -> list[dict]:
    if not audit_path.exists():
        return []
    return [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _wait_until(predicate, timeout_s: float, what: str) -> None:
    deadline = time.monotonic() + timeout_s
    while not predicate():
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        time.sleep(0.005)


@pytest.fixture()
def fresh_server(tmp_path):
    def make(doc: dict):
        cfg_path = tmp_path / "dispatch-config.json"
        cfg_path.write_text(json.dumps(doc), encoding="utf-8")
        mod = importlib.reload(server_module)
        mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_path)})
        return mod

    yield make
    importlib.reload(server_module)


class TaskHandleResult(Result):
    result_type: Literal["task"] = "task"
    task_id: str
    status: str
    ttl_ms: int | None = None
    poll_interval_ms: int | None = None


class TasksGetParams(RequestParams):
    task_id: str


class TasksGetRequest(Request[TasksGetParams, Literal["tasks/get"]]):
    method: Literal["tasks/get"] = "tasks/get"
    params: TasksGetParams
    name_param = "taskId"


class GetTaskResult(Result):
    task_id: str
    status: str
    status_message: str | None = None
    result: CallToolResult | None = None


def _task_claim() -> ResultClaim:
    async def _resolve(value, ctx):  # pragma: no cover - never invoked
        return CallToolResult(content=[])

    return ResultClaim(
        result_type="task", model=TaskHandleResult, resolve=_resolve)


def _drive_task_route(server, agent: str, args: dict):
    """Call hyperv_checkpoint_restore as a tasks-capable client and poll the
    task to a terminal status; returns (task_id, embedded result text)."""

    async def _run():
        async with InMemoryTransport(server) as (read, write):
            async with ClientSession(
                read, write,
                extensions={TASKS_ID: {}},
                result_claims={TASKS_ID: (_task_claim(),)},
            ) as session:
                await session.discover()
                handle = await session.call_tool(
                    "hyperv_checkpoint_restore", dict(args), allow_claimed=True
                )
                assert isinstance(handle, TaskHandleResult), (
                    f"the capable client must get a task handle; got "
                    f"{type(handle).__name__}"
                )
                deadline = time.monotonic() + 10.0
                while True:
                    view = await session.send_request(
                        TasksGetRequest(
                            params=TasksGetParams(task_id=handle.task_id)
                        ),
                        GetTaskResult,
                    )
                    if view.status != "working":
                        break
                    assert time.monotonic() < deadline, "task never left working"
                    await asyncio.sleep(0.02)
                return handle.task_id, view

    token = _as_agent(agent)
    try:
        return asyncio.run(_run())
    finally:
        auth_context_var.reset(token)


# ---------------------------------------------------------------------------
# D1 — the real guard admits once, releases, and audits the admit
# ---------------------------------------------------------------------------


def test_normal_call_admits_once_and_releases(tmp_path, fresh_server, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    fresh_server({
        "unrestricted": True,
        "max_host_powershell": 2,
        "audit_log_path": str(audit),
    })
    mcp = server_module.get_mcp()
    monkeypatch.setattr(pswindows, "run_ps", GatedFakePS())

    counts = {"admit": 0, "release": 0}
    real_admit, real_release = admission.admit, admission.release

    async def counting_admit(*args, **kwargs):
        counts["admit"] += 1
        return await real_admit(*args, **kwargs)

    async def counting_release(ticket):
        counts["release"] += 1
        await real_release(ticket)

    monkeypatch.setattr(admission, "admit", counting_admit)
    monkeypatch.setattr(admission, "release", counting_release)

    asyncio.run(mcp.call_tool(LIGHT_TOOL, {}))

    assert counts["admit"] == 1, (
        f"a body-bound call must admit exactly once: {counts}"
    )
    assert counts["release"] == 1, "the guard must release on the success exit"
    snap = admission.snapshot()
    assert snap["in_flight_general"] == 0 and snap["in_flight_light"] == 0
    assert snap["fair_queue_depth"] == 0 and snap["actor_queue_depth"] == 0

    rows = [r for r in _rows(audit) if r["tool"] == LIGHT_TOOL and r["ok"]]
    assert rows, "the LIGHT body must leave an audited operation row"
    assert rows[-1]["admission_class"] == "LIGHT"
    assert isinstance(rows[-1]["admission_wait_ms"], int)
    assert rows[-1]["admission_wait_ms"] >= 0
    assert rows[-1]["retry_after_ms"] is None


# ---------------------------------------------------------------------------
# D2 — detach:true admits once, runner-side, with audit fields on the row
# ---------------------------------------------------------------------------


def test_detached_call_admits_once_on_the_runner(tmp_path, fresh_server, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    mod = fresh_server({
        "allowed_vm_patterns": ["test-*"],
        "unrestricted": True,
        "max_host_powershell": 2,
        "audit_log_path": str(audit),
    })
    mcp = mod.get_mcp()
    monkeypatch.setattr(pswindows, "run_ps", GatedFakePS())

    counts = {"admit": 0, "admit_sync": 0, "release_sync": 0}
    real_admit, real_sync, real_release_sync = (
        admission.admit, admission.admit_sync, admission.release_sync)

    async def counting_admit(*args, **kwargs):
        counts["admit"] += 1
        return await real_admit(*args, **kwargs)

    def counting_sync(*args, **kwargs):
        counts["admit_sync"] += 1
        return real_sync(*args, **kwargs)

    def counting_release(ticket):
        counts["release_sync"] += 1
        real_release_sync(ticket)

    monkeypatch.setattr(admission, "admit", counting_admit)
    monkeypatch.setattr(admission, "admit_sync", counting_sync)
    monkeypatch.setattr(admission, "release_sync", counting_release)

    token = _as_agent("agent-a")
    try:
        handle = _payload(asyncio.run(mcp.call_tool(
            "hyperv_checkpoint_restore", {**RESTORE_ARGS, "detach": True}
        )), "detach handle")
    finally:
        auth_context_var.reset(token)
    op_id = handle["op_id"]
    assert op_id, f"the detach answer must carry an op_id: {handle}"

    _wait_until(
        lambda: operations.op_status(mod.CFG, op_id, "agent-a").get("status")
        == "completed",
        timeout_s=10.0, what="the detached op to complete",
    )
    operations.drain_for_tests(timeout_s=5.0)

    assert counts["admit"] == 0, "the guard must NOT admit a diverted call"
    assert counts["admit_sync"] == 1, (
        f"the runner must admit exactly once: {counts}"
    )
    assert counts["release_sync"] == 1
    snap = admission.snapshot()
    assert snap["in_flight_general"] == 0 and snap["in_flight_light"] == 0
    assert snap["fair_queue_depth"] == 0

    rows = [
        r for r in _rows(audit)
        if r["tool"] == "hyperv_checkpoint_restore" and r["ok"]
    ]
    assert rows, "the detached body must leave an audited operation row"
    assert rows[-1]["admission_class"] == "GENERAL"
    assert isinstance(rows[-1]["admission_wait_ms"], int)
    assert rows[-1]["admission_wait_ms"] >= 0
    assert rows[-1]["agent_id"] == "agent-a"


# ---------------------------------------------------------------------------
# D3 — two agents, two addressing aliases, ONE canonical actor queue
# ---------------------------------------------------------------------------


def test_actor_fan_in_two_agents_one_canonical_queue(tmp_path, fresh_server, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    vm_name = "ac-vm"
    mod = fresh_server({
        "allowed_vm_patterns": ["ac-*"],
        "unrestricted": True,
        "destructive": {"console_input": True},
        # total 4, reserve 2 -> general capacity 2; the actor stage must
        # keep in_flight_general strictly below it while the queue parks.
        "max_host_powershell": 2,
        "admission": {"wait_s": 6.0},
        "audit_log_path": str(audit),
    })
    mcp = mod.get_mcp()
    fake = GatedFakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)

    console.note_name_guid_hint(vm_name, GUID)
    assert console._hint_for(vm_name) == GUID
    # The hinted-canonical rule both addressing aliases key: by-name through
    # the hint, by-GUID directly.
    assert admission.actor_key_for(
        RAW_INPUT_TOOL, {"vm_name": vm_name, "text": "x"}) == GUID.casefold()
    assert admission.actor_key_for(
        RAW_INPUT_TOOL, {"vm_id": GUID, "text": "x"}) == GUID.casefold()

    K = 4
    peak = {"n": 0}
    peak_lock = threading.Lock()

    async def _call(i: int):
        token = _as_agent("agent-a" if i % 2 == 0 else "agent-b")
        try:
            args = (
                {"vm_name": vm_name, "text": "x"}
                if i % 2 == 0 else {"vm_id": GUID, "text": "x"}
            )
            await mcp.call_tool(RAW_INPUT_TOOL, args)
        finally:
            auth_context_var.reset(token)

    async def _sampler(stop: asyncio.Event):
        while not stop.is_set():
            with peak_lock:
                peak["n"] = max(
                    peak["n"], admission.snapshot()["in_flight_general"])
            await asyncio.sleep(0.004)

    async def _await_until(predicate, timeout_s: float, what: str) -> None:
        deadline = time.monotonic() + timeout_s
        while not predicate():
            assert time.monotonic() < deadline, f"timed out waiting for {what}"
            await asyncio.sleep(0.005)

    async def _main():
        stop = asyncio.Event()
        sampler = asyncio.create_task(_sampler(stop))
        agents = [asyncio.create_task(_call(i)) for i in range(K)]
        await _await_until(
            lambda: admission.snapshot()["actor_queue_depth"] >= K - 1,
            timeout_s=5.0, what="the fan-in calls to park in the actor queue",
        )
        parked = admission.snapshot()
        assert parked["in_flight_general"] == 1, (
            f"actor-queued waiters must hold no general permit: {parked}"
        )

        # A LIGHT call progresses while the actor queue is parked (the
        # reserved lane survives the fan-in).
        light_done = asyncio.Event()

        async def _light():
            await mcp.call_tool(LIGHT_TOOL, {})
            light_done.set()

        light_task = asyncio.create_task(_light())
        try:
            await asyncio.wait_for(light_done.wait(), timeout=5.0)
        finally:
            light_task.cancel()

        fake.gate.set()
        for agent in agents:
            await asyncio.wait_for(agent, timeout=10.0)
        stop.set()
        await asyncio.wait_for(sampler, timeout=5.0)

    asyncio.run(_main())

    assert fake.type_calls == K, (
        f"every fan-in call must reach the body: {fake.type_calls}/{K}"
    )
    assert fake.type_overlap_max == 1, (
        f"raw-input bodies overlapped across the two addressing aliases: "
        f"max concurrent {fake.type_overlap_max}"
    )
    assert 1 <= peak["n"] < 2, (
        f"in_flight_general peaked at {peak['n']} against general capacity 2 "
        f"(actor-waiting callers must never hold the lane's last token)"
    )
    snap = admission.snapshot()
    assert snap["in_flight_general"] == 0 and snap["in_flight_light"] == 0
    assert snap["fair_queue_depth"] == 0 and snap["actor_queue_depth"] == 0
    rows = [r for r in _rows(audit) if r["tool"] == LIGHT_TOOL and r["ok"]]
    assert rows and rows[-1]["admission_class"] == "LIGHT"


# ---------------------------------------------------------------------------
# D4 — stage-2 companion legs: cancel, timeout, and the sync stop valve
# ---------------------------------------------------------------------------


def test_stage2_companion_cancel_and_timeout_free_the_actor_slot():
    async def _leg(refuse: str) -> None:
        cancelled_cls = anyio.get_cancelled_exc_class()
        admission.reset()
        admission.configure(
            total_tokens=4, light_reserve=2, wait_s=0.5, light_wait_s=0.5
        )
        harness = [
            await admission.admit("hyperv_start_vm", f"h{i}", wait_s=0.5)
            for i in range(2)  # general capacity = 4 - 2
        ]
        assert admission.snapshot()["in_flight_general"] == 2

        waiter = asyncio.create_task(admission.admit(
            "hyperv_start_vm", "w", wait_s=2.0, actor_key="k"))
        # Stage 1 granted, stage 2 saturated: the waiter parks in the LANE
        # (fair_queue_depth 1, actor queue empty — the slot is HELD by it).
        for _ in range(400):
            snap = admission.snapshot()
            if snap["fair_queue_depth"] == 1 and snap["actor_queue_depth"] == 0:
                break
            await asyncio.sleep(0.005)
        assert admission.snapshot()["fair_queue_depth"] == 1

        if refuse == "cancel":
            waiter.cancel()
            try:
                # Outer margins stay generous (6 s) so the outer timeout can
                # never race the admit's own 2.0 s bound under load; the
                # assertions below still discriminate the inner refusal.
                await asyncio.wait_for(waiter, timeout=6.0)
                raise AssertionError("the cancelled admit must not return")
            except cancelled_cls:
                pass
        else:
            with pytest.raises(admission.AdmissionBusy):
                await asyncio.wait_for(waiter, timeout=6.0)

        snap = admission.snapshot()
        assert snap["in_flight_general"] == 2, f"no permit may issue: {snap}"
        assert snap["fair_queue_depth"] == 0 and snap["actor_queue_depth"] == 0

        # The actor slot was freed with the refusal: a fresh two-stage
        # waiter reaches STAGE 2 (parks in the lane), it does not queue
        # behind a ghost holder (which would park at stage 1 and show
        # actor_queue_depth 1).
        probe = asyncio.create_task(admission.admit(
            "hyperv_start_vm", "p", wait_s=2.0, actor_key="k"))
        for _ in range(400):
            snap = admission.snapshot()
            if snap["fair_queue_depth"] == 1:
                break
            await asyncio.sleep(0.005)
        assert admission.snapshot()["actor_queue_depth"] == 0, (
            f"the actor slot leaked to the refused waiter: "
            f"{admission.snapshot()}"
        )
        probe.cancel()
        try:
            await asyncio.wait_for(probe, timeout=6.0)
        except cancelled_cls:
            pass
        for ticket in harness:
            await admission.release(ticket)
        snap = admission.snapshot()
        assert snap["in_flight_general"] == 0
        assert snap["fair_queue_depth"] == 0 and snap["actor_queue_depth"] == 0

    asyncio.run(_leg("cancel"))
    asyncio.run(_leg("timeout"))


def test_admit_sync_honors_stop_event_mid_wait():
    admission.reset()
    admission.configure(total_tokens=2, light_reserve=1, wait_s=0.5, light_wait_s=0.5)
    held = admission.admit_sync("hyperv_start_vm", "holder", wait_s=0.5)
    assert admission.snapshot()["in_flight_general"] == 1  # capacity 1

    stop = threading.Event()
    outcome: dict = {}

    def _waiter():
        try:
            admission.admit_sync(
                "hyperv_start_vm", "w", wait_s=30.0, stop_event=stop)
        except BaseException as exc:  # noqa: BLE001 - recorded, asserted below
            outcome["error"] = exc

    waiter = threading.Thread(target=_waiter, daemon=True)
    waiter.start()
    _wait_until(
        lambda: admission.snapshot()["fair_queue_depth"] >= 1,
        timeout_s=2.0, what="the sync waiter to park",
    )
    started = time.monotonic()
    stop.set()
    waiter.join(timeout=5.0)
    assert not waiter.is_alive(), "the stop valve must end the sync wait"
    assert time.monotonic() - started < 5.0
    assert isinstance(outcome.get("error"), admission.AdmissionStopped), (
        f"admit_sync must raise AdmissionStopped on the stop event; got "
        f"{outcome!r}"
    )
    snap = admission.snapshot()
    assert snap["in_flight_general"] == 1, (
        f"the stopped waiter must leave no permit: {snap}"
    )
    assert snap["fair_queue_depth"] == 0 and snap["actor_queue_depth"] == 0
    admission.release_sync(held)
    assert admission.snapshot()["in_flight_general"] == 0


# ---------------------------------------------------------------------------
# D5 — cap-1 bootstrap reserve semantics
# ---------------------------------------------------------------------------


def test_cap1_bootstrap_omitted_default_valid_and_explicit_invalid_rejected(
    tmp_path, fresh_server,
):
    mod = fresh_server({
        "unrestricted": True,
        "max_host_powershell": 1,  # total_tokens = 2
    })
    snap = admission.snapshot()
    assert snap["total_tokens"] == 2
    assert snap["reserved"] == 1, (
        f"the omitted default at cap 1 must resolve to min(2, total-1)=1: {snap}"
    )
    assert mod.CFG.admission.light_reserve is None

    with pytest.raises(ValueError) as refused:
        fresh_server({
            "unrestricted": True,
            "max_host_powershell": 1,
            "admission": {"light_reserve": 2},
        })
    assert "light_reserve" in str(refused.value), (
        f"the refusal must name light_reserve: {refused.value}"
    )


# ---------------------------------------------------------------------------
# D6 — a NON-default retry hint survives exactly through every dispatch path
# ---------------------------------------------------------------------------


def test_nondefault_retry_after_ms_flows_exact(tmp_path, fresh_server, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    mod = fresh_server({
        "allowed_vm_patterns": ["test-*"],
        "unrestricted": True,
        # total 2, reserve 1 -> general capacity 1, held by the harness below.
        "max_host_powershell": 1,
        "admission": {"wait_s": 0.05},
        "audit_log_path": str(audit),
    })
    mcp = mod.get_mcp()
    monkeypatch.setattr(pswindows, "run_ps", GatedFakePS())
    monkeypatch.setattr(
        admission, "_retry_after_ms", lambda bound_s: NONDEFAULT_RETRY_MS)

    held = asyncio.run(admission.admit("hyperv_start_vm", "holder", wait_s=0.5))
    try:
        assert admission.snapshot()["in_flight_general"] == 1

        # -- normal path: the guard's refusal envelope + audit row --------
        token = _as_agent("agent-a")
        try:
            env = _payload(asyncio.run(mcp.call_tool(
                "hyperv_start_vm", {"vm_name": "test-vm"}
            )), "the busy envelope")
        finally:
            auth_context_var.reset(token)
        assert env["ok"] is False and env["error_class"] == "busy"
        assert env["retryable"] is True
        assert env["retry_after_ms"] == NONDEFAULT_RETRY_MS, (
            f"the normal-path envelope must carry the measured hint "
            f"exactly: {env['retry_after_ms']!r}"
        )
        busy_rows = [
            r for r in _rows(audit)
            if r["tool"] == "hyperv_start_vm" and r["error_class"] == "busy"
        ]
        assert busy_rows, "the busy refusal must leave an audit row"
        assert busy_rows[-1]["retry_after_ms"] == NONDEFAULT_RETRY_MS
        assert busy_rows[-1]["admission_class"] == "GENERAL"
        assert busy_rows[-1]["agent_id"] == "agent-a"

        # -- detached path: the runner's stored envelope + rejection row ---
        token = _as_agent("agent-a")
        try:
            handle = _payload(asyncio.run(mcp.call_tool(
                "hyperv_checkpoint_restore", {**RESTORE_ARGS, "detach": True}
            )), "the detach handle")
        finally:
            auth_context_var.reset(token)
        op_id = handle["op_id"]

        def _failed() -> bool:
            row = operations.op_status(mod.CFG, op_id, "agent-a")
            return row.get("status") == "failed"

        _wait_until(_failed, timeout_s=10.0, what="the detached op to fail busy")
        operations.drain_for_tests(timeout_s=5.0)
        result = operations.op_result(mod.CFG, op_id, "agent-a", "")
        stored = json.loads(result["chunk"])
        assert stored["error_class"] == "busy"
        assert stored["retry_after_ms"] == NONDEFAULT_RETRY_MS, (
            f"the stored detached envelope must carry the hint exactly: "
            f"{stored!r}"
        )
        runner_rows = [
            r for r in _rows(audit)
            if r["tool"] == "hyperv_checkpoint_restore"
            and r["error_class"] == "busy"
        ]
        assert runner_rows, "the runner must write its own rejection row"
        assert runner_rows[-1]["retry_after_ms"] == NONDEFAULT_RETRY_MS
        assert runner_rows[-1]["admission_class"] == "GENERAL"

        # -- task path: the tasks-extension runner stores the same envelope -
        task_id, view = _drive_task_route(mcp, "agent-b", RESTORE_ARGS)
        assert view.status == "failed", (
            f"the saturated task must fail busy; got {view.status}"
        )
        assert view.result is not None and view.result.content, (
            "the failed task must embed the stored result envelope"
        )
        task_env = json.loads(view.result.content[0].text)
        assert task_env["error_class"] == "busy"
        assert task_env["retry_after_ms"] == NONDEFAULT_RETRY_MS
        assert task_id
        operations.drain_for_tests(timeout_s=5.0)
    finally:
        asyncio.run(admission.release(held))
    snap = admission.snapshot()
    assert snap["in_flight_general"] == 0 and snap["fair_queue_depth"] == 0


# ---------------------------------------------------------------------------
# D7 — sequential calls never bleed admission telemetry
# ---------------------------------------------------------------------------


def test_sequential_calls_no_admission_class_bleed(tmp_path, fresh_server, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    fresh_server({
        "unrestricted": True,
        "max_host_powershell": 2,
        "audit_log_path": str(audit),
    })
    mcp = server_module.get_mcp()
    monkeypatch.setattr(pswindows, "run_ps", GatedFakePS())

    order = [LIGHT_TOOL, GENERAL_TOOL, LIGHT_TOOL, GENERAL_TOOL]
    for tool in order:
        args = {"relay_id": ""} if tool == GENERAL_TOOL else {}
        asyncio.run(mcp.call_tool(tool, args))

    rows = [r for r in _rows(audit) if r["tool"] in order and r["ok"]]
    assert len(rows) >= 4, f"expected one row per call, got {len(rows)}"
    for row in rows[-4:]:
        expected = str(admission.classify_tool(row["tool"]))
        assert row["admission_class"] == expected, (
            f"{row['tool']}'s row carries {row['admission_class']!r} — the "
            f"previous call's class bled ({expected} expected)"
        )
        assert isinstance(row["admission_wait_ms"], int)
        assert row["admission_wait_ms"] >= 0
    classes = [r["admission_class"] for r in rows[-4:]]
    assert classes == ["LIGHT", "GENERAL", "LIGHT", "GENERAL"], classes
