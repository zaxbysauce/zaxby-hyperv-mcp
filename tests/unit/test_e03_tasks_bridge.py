"""Issue #24 acceptance checks, part 3 (trace 24-durable-operation-handles):
the SEP-2663 tasks bridge (io.modelcontextprotocol/tasks) over the mcp 2.3
SDK — CreateTaskResult on tools/call for a capable client, plain
CallToolResult for everyone else, the tasks/get / tasks/cancel /
tasks/update lifecycle, and per-agent + restart durability of taskIds.

ACs carried (01-issue-summary.md):
  AC12 test_capable_client_gets_task_result
  AC13 test_non_capable_client_gets_plain_result
  AC14 test_tasks_get_cancel_update_lifecycle
  AC15 test_task_ids_authorized_and_durable

RED at base, GREEN after the fix — the RED signature for this whole file is
the module-level import: at base 55da0d3 there IS no hyperv_mcp.operations,
so collection fails with `ImportError: cannot import name 'operations'`
(the issue's documented expect for AC12-AC15). The import is otherwise an
anchor only: every check below drives the REAL server surface — a real
mcp ClientSession over InMemoryTransport against the bootstrapped
server.get_mcp() — and asserts WIRE behavior only (what a client sees), so
the checks stay valid regardless of how the bridge is structured
internally.

Harness facts this file relies on (verified against mcp 2.3.0):
  - `ClientSession.discover()` adopts the 2026-07-28 modern protocol; from
    then on every request carries `_meta["io.modelcontextprotocol/
    clientCapabilities"].extensions` — a capable client is constructed with
    `extensions={"io.modelcontextprotocol/tasks": {}}` plus a ResultClaim
    for resultType "task", so the per-request capability rides every call
    and a task-shaped result PARSES instead of tripping the core union.
  - mcp 2.3 ships no runtime tasks support; its mcp_types task types are
    the removed 2025-11-25 nested shape. The flat SEP-2663 wire shapes
    below are therefore defined TEST-SIDE (taskId/status/ttlMs/
    pollIntervalMs on the tools/call result; taskId/status/result on
    tasks/get) — they are the contract the fix must serve on the wire.
  - Agent identity: `auth_context_var` set around a transport connection is
    inherited by that connection's server tasks (probe-verified: audit rows
    carry the set client_id), so agent a and agent b are two connections.

What is faked: PowerShell only (content-dispatched run_ps with a gating
Event for "runner mid-leg"), and TIME on the store (FakeClock through the
statestore.store_for seam, the frozen test_e02_lease_store pattern) for the
AC15 restart. No network, no real PowerShell; real sleeps only in bounded
polls (asyncio.sleep 0.02 s steps, 5 s deadline).
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import threading
import time
from typing import Literal

import pytest
from mcp import ClientSession
from mcp.client._memory import InMemoryTransport
from mcp.client.extension import ResultClaim
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken
from mcp.shared.exceptions import MCPError
from mcp_types import CallToolResult, Request, RequestParams, Result
from mcp_types.jsonrpc import INVALID_PARAMS

import hyperv_mcp.server as server_module
from hyperv_mcp import operations, pswindows, statestore  # noqa: F401 — `operations` is the RED anchor

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
TASKS_ID = "io.modelcontextprotocol/tasks"

# A runner heartbeat TTL must sit far below the store's other horizons —
# advancing the injected clock by 2 h is stale for any sane heartbeat TTL.
RESTART_CLOCK_ADVANCE_S = 7200


class FakeClock:
    """Deterministic wall clock for Store(path, clock=...)."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


class ClockStoreMount:
    """Bind statestore.store_for (and operations' own reference, if any) to
    one clock-injected Store — the frozen test_e02_lease_store._clock_store
    pattern, reused so the AC15 restart is time-deterministic."""

    def __init__(self, monkeypatch, db: str, clock: FakeClock) -> None:
        self._monkeypatch = monkeypatch
        self.db = str(db)
        self.clock = clock
        self.store = None
        self.mount()

    def mount(self) -> ClockStoreMount:
        statestore.open(self.db).close()
        self.store = statestore.Store(self.db, clock=self.clock)
        store = self.store

        def _fake_store_for(cfg, environ=None):
            return store

        self._monkeypatch.setattr(statestore, "store_for", _fake_store_for)
        if hasattr(operations, "store_for"):
            self._monkeypatch.setattr(operations, "store_for", _fake_store_for, raising=False)
        return self

    def reopen(self) -> ClockStoreMount:
        """Close and re-open the same database through the same seam — the
        store reopen half of the AC15 simulated restart."""
        if self.store is not None:
            self.store.close()
        return self.mount()

    def close(self) -> None:
        if self.store is not None:
            self.store.close()
            self.store = None


class GatedFakePS:
    """Content-dispatched, thread-safe run_ps fake. The by-name resolution
    leg answers the stable GUID; restore and state-wait legs succeed. The
    restore leg blocks for every call at index >= `pass_first` — index 0 is
    the poll-to-completed task, index 1+ are the cancel/durability targets
    that must stay `working` until the gate is released."""

    def __init__(self, pass_first: int = 0):
        self.gate = threading.Event()
        self._lock = threading.Lock()
        self.restore_legs = 0
        self.pass_first = pass_first

    def __call__(self, script, **kwargs):
        if "Restore-VMSnapshot" in script:
            with self._lock:
                index = self.restore_legs
                self.restore_legs += 1
            if index >= self.pass_first:
                self.gate.wait(timeout=30.0)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if "Restore-VMSnapshot" in script:
            return pswindows.PSResult(stdout="", returncode=0)
        if "final_state" in script:
            return pswindows.PSResult(stdout='{"final_state": "Off"}', returncode=0)
        return pswindows.PSResult(stdout="{}", returncode=0)


# ---------------------------------------------------------------------------
# test-side wire shapes (the flat SEP-2663 contract the server must serve)
# ---------------------------------------------------------------------------


class TaskHandleResult(Result):
    """tools/call answer to a capable client: the flat CreateTaskResult."""

    result_type: Literal["task"] = "task"
    task_id: str                      # taskId
    status: str
    ttl_ms: int | None = None         # ttlMs
    poll_interval_ms: int | None = None  # pollIntervalMs


class TasksGetParams(RequestParams):
    task_id: str                      # taskId


class TasksGetRequest(Request[TasksGetParams, Literal["tasks/get"]]):
    method: Literal["tasks/get"] = "tasks/get"
    params: TasksGetParams
    name_param = "taskId"  # SEP-2663 mirrors taskId into Mcp-Name


class TasksCancelParams(RequestParams):
    task_id: str


class TasksCancelRequest(Request[TasksCancelParams, Literal["tasks/cancel"]]):
    method: Literal["tasks/cancel"] = "tasks/cancel"
    params: TasksCancelParams
    name_param = "taskId"


class TasksUpdateParams(RequestParams):
    task_id: str
    status: str | None = None


class TasksUpdateRequest(Request[TasksUpdateParams, Literal["tasks/update"]]):
    method: Literal["tasks/update"] = "tasks/update"
    params: TasksUpdateParams
    name_param = "taskId"


class GetTaskResult(Result):
    """tasks/get / tasks/cancel answer: the task's live status, with the
    tool's CallToolResult embedded once completed."""

    task_id: str
    status: str
    status_message: str | None = None
    created_at: str | None = None
    last_updated_at: str | None = None
    ttl_ms: int | None = None
    poll_interval_ms: int | None = None
    result: CallToolResult | None = None


def _task_claim() -> ResultClaim:
    """The client-side claim for resultType "task" so a task-shaped
    tools/call result parses (resolve itself is never invoked by
    ClientSession.call_tool with allow_claimed=True)."""

    async def _resolve(value, ctx):  # pragma: no cover - ClientSession never calls it
        return CallToolResult(content=[])

    return ResultClaim(result_type="task", model=TaskHandleResult, resolve=_resolve)


def _entropy_bytes(task_id: str) -> int:
    """Decoded byte length of the id in the practical encodings (0 when the
    id decodes in none of them)."""
    sizes = []
    for decoder in (
        lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)),
        lambda s: base64.b64decode(s + "=" * (-len(s) % 4)),
        lambda s: bytes.fromhex(s),
    ):
        try:
            raw = decoder(task_id)
        except Exception:
            continue
        if raw:
            sizes.append(len(raw))
    return max(sizes) if sizes else 0


def _as_agent(client_id: str):
    return auth_context_var.set(
        AuthenticatedUser(AccessToken(token="t", client_id=client_id, scopes=[]))
    )


def _drive(server, agent: str, capable: bool, coro_fn, *args):
    """Run `coro_fn(session, *args)` inside one real ClientSession over
    InMemoryTransport against `server`, as `agent`, discovering (not
    initializing — the 2026-07-28 path has no initialize handshake)."""
    token = _as_agent(agent)

    async def _run():
        async with InMemoryTransport(server) as (read, write):
            kwargs = (
                {"extensions": {TASKS_ID: {}}, "result_claims": {TASKS_ID: (_task_claim(),)}}
                if capable else {}
            )
            async with ClientSession(read, write, **kwargs) as session:
                await session.discover()
                return await coro_fn(session, *args)

    try:
        return asyncio.run(_run())
    finally:
        auth_context_var.reset(token)


async def _get_task(session, task_id: str) -> GetTaskResult:
    return await session.send_request(
        TasksGetRequest(params=TasksGetParams(task_id=task_id)), GetTaskResult
    )


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


UNRESTRICTED_DOC = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}

RESTORE_ARGS = {"vm_name": "test-vm", "checkpoint_name": "snap", "confirm": True}


def _boot(tmp_path, fresh_server, doc: dict) -> type(server_module):
    p = tmp_path / "e03-tasks-config.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return fresh_server({"HYPERV_MCP_CONFIG": str(p)})


def _payload(result, label: str) -> dict:
    from conftest import content_blocks

    texts = [c for c in content_blocks(result) if getattr(c, "type", "") == "text"]
    assert texts, f"expected a JSON text payload for {label}"
    payload = json.loads(texts[0].text)
    assert isinstance(payload, dict), f"{label}: payload is not an object: {payload!r}"
    return payload


# ---------------------------------------------------------------------------
# AC12 — a capable client's tools/call answers CreateTaskResult
# ---------------------------------------------------------------------------


def test_capable_client_gets_task_result(tmp_path, fresh_server, monkeypatch):
    """AC12: a client whose per-request capabilities include
    io.modelcontextprotocol/tasks calls hyperv_checkpoint_restore and gets a
    CreateTaskResult — resultType "task", a taskId of at least 128 bits,
    status "working", ttlMs and pollIntervalMs — and server/discover
    advertises the extension. Receiving a taskId at all proves the op row
    was committed before the response (AC15 exercises the restart side of
    that durability), and hyperv_op_status answering for the SAME id as
    op_id proves tasks and op_* are two views of one store row. RED at base
    (module absent), GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    mount = ClockStoreMount(monkeypatch, str(tmp_path / "state.db"), FakeClock())
    fake = GatedFakePS(pass_first=1)  # this task runs to completion
    monkeypatch.setattr(pswindows, "run_ps", fake)
    server = mod.get_mcp()

    async def scenario(session):
        discover = await session.discover()
        extensions = (discover.capabilities.extensions if discover.capabilities else None) or {}
        assert TASKS_ID in extensions, (
            f"AC12: server/discover must advertise {TASKS_ID} in the "
            f"server's extension capabilities; got {extensions!r}"
        )
        handle = await session.call_tool(
            "hyperv_checkpoint_restore", dict(RESTORE_ARGS), allow_claimed=True
        )
        assert isinstance(handle, TaskHandleResult), (
            f"AC12: a capable client's detachable tools/call must answer "
            f"CreateTaskResult (resultType 'task'); got {type(handle).__name__}"
        )
        assert handle.result_type == "task"
        assert handle.status == "working", (
            f"AC12: the fresh task must report status 'working'; got {handle.status!r}"
        )
        entropy = _entropy_bytes(handle.task_id)
        assert entropy >= 16 or len(handle.task_id) >= 22, (
            f"AC12: the taskId must carry at least 128 bits of entropy "
            f"({handle.task_id!r}: {entropy} decodable bytes, "
            f"{len(handle.task_id)} chars)"
        )
        assert isinstance(handle.ttl_ms, int) and handle.ttl_ms >= 0, (
            f"AC12: CreateTaskResult must carry ttlMs; got {handle.ttl_ms!r}"
        )
        assert isinstance(handle.poll_interval_ms, int) and handle.poll_interval_ms > 0, (
            f"AC12: CreateTaskResult must carry pollIntervalMs; got "
            f"{handle.poll_interval_ms!r}"
        )
        return handle.task_id

    try:
        task_id = _drive(server, "agent-a", True, scenario)

        # taskId == op_id: the op tools serve the same store row.
        token = _as_agent("agent-a")
        try:
            st = _payload(asyncio.run(mod.get_mcp().call_tool(
                "hyperv_op_status", {"op_id": task_id}
            )), "AC12 op_status")
        finally:
            auth_context_var.reset(token)
        assert not st.get("error_class"), (
            f"AC12: hyperv_op_status must know the taskId as an op_id; got "
            f"{json.dumps(st)[:300]}"
        )
        assert st.get("status") in ("working", "completed"), (
            f"AC12: the op behind the task must be known; got {json.dumps(st)[:300]}"
        )
    finally:
        fake.gate.set()
        mount.close()


# ---------------------------------------------------------------------------
# AC13 — a non-capable client gets an ordinary CallToolResult, never -32021
# ---------------------------------------------------------------------------


def test_non_capable_client_gets_plain_result(tmp_path, fresh_server, monkeypatch):
    """AC13: the same hyperv_checkpoint_restore call from a client that did
    NOT include the tasks capability on its request returns an ordinary
    synchronous CallToolResult — never a CreateTaskResult and never the
    -32021 missing-capability error (a JSON-RPC error would surface here as
    a raised MCPError). RED at base, GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    fake = GatedFakePS(pass_first=1)  # the call runs synchronously to completion
    monkeypatch.setattr(pswindows, "run_ps", fake)
    server = mod.get_mcp()

    async def scenario(session):
        result = await session.call_tool("hyperv_checkpoint_restore", dict(RESTORE_ARGS))
        assert isinstance(result, CallToolResult), (
            f"AC13: a non-capable client must get an ordinary CallToolResult; "
            f"got {type(result).__name__}"
        )
        assert "taskId" not in json.dumps(result.model_dump(by_alias=True)), (
            "AC13: the non-capable answer must not be a task result"
        )
        texts = [
            block.text
            for block in (result.content or [])
            if getattr(block, "type", "") == "text"
        ]
        assert texts and "restored" in texts[0], (
            f"AC13: the synchronous result must be the tool's ordinary "
            f"restore payload; got {texts[:1]!r}"
        )
        return None

    try:
        _drive(server, "agent-a", False, scenario)
    finally:
        fake.gate.set()


# ---------------------------------------------------------------------------
# AC14 — tasks/get polls to completed, tasks/cancel cooperatively cancels a
# second running task, tasks/update off input_required is invalid-params
# ---------------------------------------------------------------------------


def test_tasks_get_cancel_update_lifecycle(tmp_path, fresh_server, monkeypatch):
    """AC14: the capable client polls tasks/get on task 1 to completed with
    the tool's CallToolResult embedded; tasks/cancel on a second RUNNING
    task moves it to cancelled at the runner's next cooperative check (the
    restore leg is gated, the state-wait leg ahead of it is the check
    point); tasks/update on the completed (never input_required) task
    yields a JSON-RPC invalid-params error. RED at base, GREEN after the
    fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    mount = ClockStoreMount(monkeypatch, str(tmp_path / "state.db"), FakeClock())
    fake = GatedFakePS(pass_first=1)  # task 1 completes; task 2's leg gates
    monkeypatch.setattr(pswindows, "run_ps", fake)
    server = mod.get_mcp()

    async def scenario(session):
        handle1 = await session.call_tool(
            "hyperv_checkpoint_restore", dict(RESTORE_ARGS), allow_claimed=True
        )
        assert isinstance(handle1, TaskHandleResult), (
            f"AC14: expected a task handle for the first restore; got "
            f"{type(handle1).__name__}"
        )
        deadline = time.monotonic() + 5.0
        task1 = None
        while time.monotonic() < deadline:
            task1 = await _get_task(session, handle1.task_id)
            if task1.status in ("completed", "failed", "cancelled"):
                break
            await asyncio.sleep(0.02)
        assert task1 is not None and task1.status == "completed", (
            f"AC14: tasks/get must poll task 1 to completed; got "
            f"{task1.status if task1 else None!r}"
        )
        assert task1.result is not None, (
            "AC14: the completed task must embed the tool's CallToolResult"
        )
        texts = [
            block.text
            for block in (task1.result.content or [])
            if getattr(block, "type", "") == "text"
        ]
        assert texts and "restored" in texts[0], (
            f"AC14: the embedded result must be the tool's restore payload; "
            f"got {texts[:1]!r}"
        )

        handle2 = await session.call_tool(
            "hyperv_checkpoint_restore",
            {**RESTORE_ARGS, "checkpoint_name": "snap-b"},
            allow_claimed=True,
        )
        assert isinstance(handle2, TaskHandleResult)
        cancel = await session.send_request(
            TasksCancelRequest(params=TasksCancelParams(task_id=handle2.task_id)),
            GetTaskResult,
        )
        assert cancel.status in ("working", "cancelled"), (
            f"AC14: tasks/cancel must record the cooperative cancel; got "
            f"{cancel.status!r}"
        )

        fake.gate.set()  # the runner proceeds to its next cooperative check
        deadline = time.monotonic() + 5.0
        task2 = None
        while time.monotonic() < deadline:
            task2 = await _get_task(session, handle2.task_id)
            if task2.status in ("completed", "failed", "cancelled"):
                break
            await asyncio.sleep(0.02)
        assert task2 is not None and task2.status == "cancelled", (
            f"AC14: the cancelled task must reach cancelled at the runner's "
            f"next cooperative check; got {task2.status if task2 else None!r}"
        )

        # tasks/update on a task that is not input_required (this server
        # never enters it) is a JSON-RPC invalid-params error.
        with pytest.raises(MCPError) as raised:
            await session.send_request(
                TasksUpdateRequest(params=TasksUpdateParams(task_id=handle1.task_id)),
                GetTaskResult,
            )
        assert raised.value.code == INVALID_PARAMS, (
            f"AC14: tasks/update off input_required must answer "
            f"invalid-params ({INVALID_PARAMS}); got {raised.value.code}"
        )

    try:
        _drive(server, "agent-a", True, scenario)
    finally:
        fake.gate.set()
        mount.close()


# ---------------------------------------------------------------------------
# AC15 — taskIds are per-agent authorized and restart-durable
# ---------------------------------------------------------------------------


def test_task_ids_authorized_and_durable(tmp_path, fresh_server, monkeypatch):
    """AC15: agent b's tasks/get with agent a's taskId answers EXACTLY as
    for an unknown id (same code, id-normalized message). After a simulated
    server restart (heartbeat clock advanced past its TTL, cached stores
    closed, server module rebuilt), agent a's pre-restart taskId is served
    from the durable store as failed / interrupted — never as unknown. RED
    at base, GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    clock = FakeClock()
    mount = ClockStoreMount(monkeypatch, str(tmp_path / "state.db"), clock)
    fake = GatedFakePS(pass_first=0)  # the pre-restart task stays working
    monkeypatch.setattr(pswindows, "run_ps", fake)
    server = mod.get_mcp()

    async def create(session):
        handle = await session.call_tool(
            "hyperv_checkpoint_restore", dict(RESTORE_ARGS), allow_claimed=True
        )
        assert isinstance(handle, TaskHandleResult), (
            f"AC15: expected a task handle; got {type(handle).__name__}"
        )
        return handle.task_id

    unknown_id = "task-that-does-not-exist-0001"

    async def probe(session, task_id: str):
        try:
            result = await _get_task(session, task_id)
        except MCPError as exc:
            return (exc.code, exc.message.replace(task_id, "<taskId>"))
        return ("ok", result.status)

    try:
        task_id = _drive(server, "agent-a", True, create)

        foreign = _drive(server, "agent-b", True, probe, task_id)
        unknown = _drive(server, "agent-b", True, probe, unknown_id)
        assert foreign == unknown and foreign != ("ok", None), (
            f"AC15: agent b touching agent a's taskId must answer exactly as "
            f"for an unknown id; foreign={foreign!r} unknown={unknown!r}"
        )

        # Simulated restart: the gated runner's heartbeat goes stale on the
        # injected clock, every cached Store closes, the clock store itself
        # reopens on the same database, and the server rebuilds.
        clock.advance(RESTART_CLOCK_ADVANCE_S)
        statestore.clear_store_cache_for_tests()
        mount.reopen()
        mod2 = importlib.reload(server_module)
        mod2.bootstrap({"HYPERV_MCP_CONFIG": str(tmp_path / "e03-tasks-config.json")})

        async def resume(session):
            return await _get_task(session, task_id)

        resumed = _drive(mod2.get_mcp(), "agent-a", True, resume)
        assert resumed.status == "failed", (
            f"AC15: after the restart the owner must be served the "
            f"pre-restart task as failed (interrupted); got {resumed.status!r}"
        )
        assert "interrupted" in json.dumps(resumed.model_dump(by_alias=True)).lower(), (
            f"AC15: the pre-restart task must report failed / interrupted "
            f"for its owner; got {resumed.model_dump(by_alias=True)}"
        )
    finally:
        fake.gate.set()
        mount.close()
