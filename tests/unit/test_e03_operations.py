"""Issue #24 acceptance checks, part 1 (trace 24-durable-operation-handles):
the detachable-tool surface itself — idempotency-key replay, replay across a
simulated server restart, the detach operation handle, and the op/event tool
inventory.

ACs carried (01-issue-summary.md):
  AC1 test_idempotency_key_replays_checkpoint_create
  AC2 test_idempotency_key_replays_across_restart
  AC3 test_detach_returns_operation_handle
  AC4 test_op_tools_registered  (+ the mirrored inventory edits in
      tests/unit/test_server.py and tests/unit/test_c03_tool_surface.py)

RED at base, GREEN after the fix. RED at the base tree for AC1-AC3 because
`hyperv_checkpoint_create` declares no `idempotency_key`/`detach`, so the
repo's unknown-argument guard (server.py `_harden_tools.guard`) refuses those
calls with an {ok: false, error_class: "invalid"} envelope before the tool
body runs — the checkpoint legs therefore never execute and the replay/handle
assertions fail. (The issue text was authored against mcp 1.x, where the
argument was silently DROPPED and the body ran twice; the observable RED line
here is `assert 0 == 1` rather than `assert 2 == 1`, same discriminator.)
AC4 is RED at base because the five op/event tools do not exist.

What is faked: PowerShell only. `pswindows.run_ps` answers the by-name VM
resolution leg with a stable GUID and every action leg with success; the
RECORDING is the oracle for "Checkpoint-VM ran exactly once" and "no
synchronous run before the detach handle returned". No sleeps except the
bounded op_status poll in AC3 (0.02 s steps, 5 s deadline).
"""

import asyncio
import importlib
import json
import threading
import time

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows, statestore

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

OP_TOOLS = {
    "hyperv_op_status", "hyperv_op_result", "hyperv_op_cancel",
    "hyperv_op_list", "hyperv_events",
}


class GatedFakePS:
    """Content-dispatched run_ps fake (thread-safe: detached runners call
    from worker threads).

    The by-name resolution leg answers the stable GUID; every other leg
    succeeds. Legs whose script contains a marker in `gates` BLOCK on that
    Event until the test releases it, which keeps "the runner is mid-leg"
    deterministic. Records every script so counting legs is the oracle.
    """

    def __init__(self, gates: dict[str, threading.Event] | None = None):
        self.scripts: list[str] = []
        self._lock = threading.Lock()
        self.gates = dict(gates or {})

    def __call__(self, script, **kwargs):
        for marker, event in self.gates.items():
            if marker in script:
                event.wait(timeout=30.0)
                break
        with self._lock:
            self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if "Checkpoint-VM" in script or "Restore-VMSnapshot" in script:
            return pswindows.PSResult(stdout="", returncode=0)
        if "final_state" in script:
            return pswindows.PSResult(stdout='{"final_state": "Off"}', returncode=0)
        return pswindows.PSResult(stdout="{}", returncode=0)

    def count(self, marker: str) -> int:
        with self._lock:
            return sum(1 for s in self.scripts if marker in s)

    def total(self) -> int:
        with self._lock:
            return len(self.scripts)


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def _boot(tmp_path, fresh_server, doc: dict) -> type(server_module):
    """Bootstrapped server whose config file is `doc`; the durable state DB
    is the conftest-pinned per-test tmp path (HYPERV_MCP_STATE_DB), so a
    simulated restart against the same DB is just a store-cache drop plus a
    module reload + re-bootstrap."""
    p = tmp_path / "e03-ops-config.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return fresh_server({"HYPERV_MCP_CONFIG": str(p)})


def _payload(result, label: str) -> dict:
    """First JSON text block of a call_tool return, as a dict."""
    from conftest import content_blocks

    texts = [c for c in content_blocks(result) if getattr(c, "type", "") == "text"]
    assert texts, f"expected a JSON text payload for {label}"
    payload = json.loads(texts[0].text)
    assert isinstance(payload, dict), f"{label}: payload is not an object: {payload!r}"
    return payload


def _call(mcp, tool: str, args: dict) -> dict:
    return _payload(asyncio.run(mcp.call_tool(tool, args)), tool)


UNRESTRICTED_DOC = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}


# ---------------------------------------------------------------------------
# AC1 — same idempotency_key twice: Checkpoint-VM runs exactly once, the
# second call replays the stored result marked replayed: true
# ---------------------------------------------------------------------------


def test_idempotency_key_replays_checkpoint_create(tmp_path, fresh_server, monkeypatch):
    """AC1: two hyperv_checkpoint_create calls carrying the same
    idempotency_key run Checkpoint-VM exactly once; the second response is
    the stored result of the first, marked replayed: true. RED at base
    (unknown-argument guard rejects idempotency_key, zero runs), GREEN after
    the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    fake = GatedFakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    args = {"vm_name": "test-vm", "checkpoint_name": "baseline", "idempotency_key": "k-0001"}

    first = _call(mcp, "hyperv_checkpoint_create", args)
    second = _call(mcp, "hyperv_checkpoint_create", args)

    runs = fake.count("Checkpoint-VM")
    assert runs == 1, (
        f"AC1: two idempotency-keyed calls must run Checkpoint-VM exactly "
        f"once; ran {runs} (first={json.dumps(first)[:200]}, "
        f"second={json.dumps(second)[:200]})"
    )
    assert second.get("replayed") is True, (
        f"AC1: the second idempotent call must return the stored result "
        f"marked replayed: true; got {json.dumps(second)[:300]}"
    )
    assert second.get("status") == "created" and second.get("checkpoint_name") == "baseline", (
        f"AC1: the replayed response must be the STORED result of the first "
        f"call (status/checkpoint_name); got {json.dumps(second)[:300]}"
    )


# ---------------------------------------------------------------------------
# AC2 — the replay survives a simulated server restart on the same state DB
# ---------------------------------------------------------------------------


def test_idempotency_key_replays_across_restart(tmp_path, fresh_server, monkeypatch):
    """AC2: call once with idempotency_key k-0002, simulate a server restart
    (drop the cached store, reload the server module, re-bootstrap against
    the same HYPERV_MCP_STATE_DB), repeat the identical call — Checkpoint-VM
    still ran exactly once. RED at base (same guard refusal), GREEN after
    the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    fake = GatedFakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    args = {"vm_name": "test-vm", "checkpoint_name": "baseline", "idempotency_key": "k-0002"}

    _call(mod.get_mcp(), "hyperv_checkpoint_create", args)

    # Simulated restart: close every cached Store, rebuild the server module
    # against the same environment (the conftest fixture pins
    # HYPERV_MCP_STATE_DB to this test's tmp path for the whole test).
    statestore.clear_store_cache_for_tests()
    mod2 = importlib.reload(server_module)
    mod2.bootstrap({"HYPERV_MCP_CONFIG": str(tmp_path / "e03-ops-config.json")})

    replay = _call(mod2.get_mcp(), "hyperv_checkpoint_create", args)

    runs = fake.count("Checkpoint-VM")
    assert runs == 1, (
        f"AC2: after a simulated restart the identical idempotent call must "
        f"still be a replay — Checkpoint-VM ran {runs} times "
        f"(replay={json.dumps(replay)[:200]})"
    )
    assert replay.get("replayed") is True, (
        f"AC2: the post-restart response must be the stored result marked "
        f"replayed: true; got {json.dumps(replay)[:300]}"
    )


# ---------------------------------------------------------------------------
# AC3 — detach: true returns a committed operation handle, not the result
# ---------------------------------------------------------------------------


def test_detach_returns_operation_handle(tmp_path, fresh_server, monkeypatch):
    """AC3: hyperv_checkpoint_create with detach: true returns
    {op_id, status: "working", poll_interval_ms} instead of the checkpoint
    result, with NO synchronous Checkpoint-VM run before the return (the
    action leg is gated); polling hyperv_op_status reaches completed and the
    stored result carries the checkpoint payload. RED at base (detach is an
    unknown argument, so the guard's invalid envelope comes back and the
    op_id assertion fails), GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    gate = threading.Event()
    fake = GatedFakePS(gates={"Checkpoint-VM": gate})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    handle = _call(mcp, "hyperv_checkpoint_create",
                   {"vm_name": "test-vm", "checkpoint_name": "b2", "detach": True})

    assert "op_id" in handle, (
        f"AC3: detach: true must return an operation handle with op_id; "
        f"got {json.dumps(handle)[:300]}"
    )
    op_id = handle["op_id"]
    assert isinstance(op_id, str) and op_id, f"AC3: op_id must be a non-empty string: {op_id!r}"
    assert handle.get("status") == "working", (
        f"AC3: the handle must report status 'working'; got {handle.get('status')!r}"
    )
    poll_ms = handle.get("poll_interval_ms")
    assert isinstance(poll_ms, int) and poll_ms > 0, (
        f"AC3: the handle must carry a positive poll_interval_ms; got {poll_ms!r}"
    )
    assert fake.count("Checkpoint-VM") == 0, (
        "AC3: the tool body must not run synchronously before the detach "
        "handle is returned (the action leg is gated, so any run here is a "
        "synchronous execution)"
    )

    # Let the detached runner proceed, then poll op_status to completion.
    gate.set()
    deadline = time.monotonic() + 5.0
    status = None
    while time.monotonic() < deadline:
        status = _call(mcp, "hyperv_op_status", {"op_id": op_id})
        if status.get("status") in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.02)
    assert status is not None and status.get("status") == "completed", (
        f"AC3: the detached op must reach completed; last status "
        f"{json.dumps(status)[:300]}"
    )
    result = _call(mcp, "hyperv_op_result", {"op_id": op_id})
    dumped = json.dumps(result)
    assert "created" in dumped and "b2" in dumped, (
        f"AC3: the stored result must carry the checkpoint payload "
        f"(status 'created', checkpoint_name 'b2'); got {dumped[:300]}"
    )


# ---------------------------------------------------------------------------
# AC4 — the op/event tools are in the inventory (mirrored in test_server.py
# and test_c03_tool_surface.py, both updated to the 66-tool count)
# ---------------------------------------------------------------------------


def test_op_tools_registered(tmp_path, fresh_server):
    """AC4: the tool list must include hyperv_op_status, hyperv_op_result,
    hyperv_op_cancel, hyperv_op_list and hyperv_events. RED at base (none of
    the five exist), GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    tools = asyncio.run(mod.get_mcp().list_tools())
    names = {t.name for t in tools}
    missing = OP_TOOLS - names
    assert not missing, (
        f"AC4: the durable-operation/event tool surface is missing from the "
        f"inventory: {sorted(missing)} (registered: {len(names)} tools)"
    )
