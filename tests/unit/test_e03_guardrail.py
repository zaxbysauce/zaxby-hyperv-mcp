"""Issue #24 Phase-4.2 guardrail (NOT part of the frozen checkpoint set —
this file is additive hardening authored after the red checkpoint, per the
amendment-avoidance rule for frozen files).

The defect class the frozen checks close is "coordination state that lives
only in the request lifecycle": a long-running tool whose result/progress
dies with one blocking call, and coordination arguments that never reach the
mechanism that must honour them. The single guardrail for the class: every
tool registered in `operations.DETACHABLE_TOOLS` must DECLARE both
`detach` and `idempotency_key` on its schema — a future tool added to the
detachable set without the parameters would silently re-create the original
defect (the coordination argument refused as unknown) while every other test
stays green.

The remaining tests close the coverage gaps the Phase-4.5 implementation
reviewer's own probes survived (round 1, R10-R12/R14): runner-bound busy
refusal, detached-body crash classification, the v2->v3 migration content,
and the shipped events/ops retention sweeps.
"""

import asyncio
import importlib
import json
import sqlite3
import threading

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import operations, pswindows, statestore

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


def test_every_detachable_tool_declares_the_coordination_params(tmp_path):
    """Schema-level guardrail for the issue-#24 defect class: each member of
    operations.DETACHABLE_TOOLS carries detach AND idempotency_key in its
    input schema. RED on the pre-fix base (the schema check ran against a
    server whose detachable tools declared neither), GREEN after the fix —
    and GREEN means zero drift between the detachable set and the declared
    parameters forever after."""
    p = tmp_path / "e03-guardrail-config.json"
    p.write_text(json.dumps({"allowed_vm_patterns": ["test-*"], "unrestricted": True}),
                 encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    tools = {t.name: t for t in asyncio.run(mod.get_mcp().list_tools())}

    assert len(operations.DETACHABLE_TOOLS) == 13
    missing = []
    for name in sorted(operations.DETACHABLE_TOOLS):
        props = (getattr(tools[name], "input_schema", None) or {}).get("properties", {})
        for param in ("detach", "idempotency_key"):
            if param not in props:
                missing.append(f"{name}.{param}")
    assert not missing, (
        "defect-class guardrail: every detachable tool must declare both "
        f"coordination parameters; missing {missing}"
    )


class _FakePS:
    """Content-dispatched run_ps fake with an optional raising marker."""

    def __init__(self, raise_on: str | None = None, gate: threading.Event | None = None):
        self.scripts: list[str] = []
        self._lock = threading.Lock()
        self._raise_on = raise_on
        self._gate = gate

    def __call__(self, script, **kwargs):
        if self._gate is not None:
            for marker in ("Checkpoint-VM", "Restore-VMSnapshot"):
                if marker in script:
                    self._gate.wait(timeout=10.0)
                    break
        with self._lock:
            self.scripts.append(script)
        if self._raise_on and self._raise_on in script:
            raise pswindows.PowerShellTransportError("guardrail: scripted leg failure")
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if "Checkpoint-VM" in script or "Restore-VMSnapshot" in script:
            return pswindows.PSResult(stdout="", returncode=0)
        return pswindows.PSResult(stdout="{}", returncode=0)

    def count(self, marker: str) -> int:
        with self._lock:
            return sum(1 for s in self.scripts if marker in s)


def _boot(tmp_path, doc: dict):
    p = tmp_path / "e03-guardrail-boot.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    return mod


def _payload(result, label: str) -> dict:
    from conftest import content_blocks

    texts = [c for c in content_blocks(result) if getattr(c, "type", "") == "text"]
    assert texts, f"expected a JSON text payload for {label}"
    payload = json.loads(texts[0].text)
    assert isinstance(payload, dict), f"{label}: payload is not an object"
    return payload


def _call(mcp, tool: str, args: dict) -> dict:
    return _payload(asyncio.run(mcp.call_tool(tool, args)), tool)


UNRESTRICTED = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}


def test_runner_bound_exhaustion_refuses_retryable_busy(tmp_path, monkeypatch):
    """R10: with operations.runner_bound=1, a second detached call while the
    first is gated is refused with a retryable busy envelope, runs no
    PowerShell, and mints no op row; releasing the gate lets the first finish
    and the next detach succeeds."""
    mod = _boot(tmp_path, {**UNRESTRICTED, "operations": {"runner_bound": 1}})
    gate = threading.Event()
    fake = _FakePS(gate=gate)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    first = _call(mcp, "hyperv_checkpoint_create",
                  {"vm_name": "test-vm", "checkpoint_name": "one", "detach": True})
    assert first.get("status") == "working", json.dumps(first)[:200]
    busy = _call(mcp, "hyperv_checkpoint_create",
                 {"vm_name": "test-vm", "checkpoint_name": "two", "detach": True})
    assert busy.get("ok") is False and busy.get("error_class") == "busy", (
        f"R10: the second detached call must be refused busy; got {json.dumps(busy)[:300]}"
    )
    assert busy.get("retryable") is True, (
        f"R10: the busy envelope must be retryable; got {json.dumps(busy)[:200]}"
    )
    # the first op's runner may still be inside its gated leg (the fake
    # records after the gate), so only an upper bound is deterministic here
    assert fake.count("Checkpoint-VM") <= 1
    gate.set()
    import time

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        st = _call(mcp, "hyperv_op_status", {"op_id": first["op_id"]})
        if st.get("status") in ("completed", "failed"):
            break
        time.sleep(0.02)
    third = _call(mcp, "hyperv_checkpoint_create",
                  {"vm_name": "test-vm", "checkpoint_name": "three", "detach": True})
    assert third.get("status") == "working", json.dumps(third)[:200]
    operations.drain_for_tests(timeout_s=5.0)


def test_detached_body_crash_records_failed_envelope(tmp_path, monkeypatch):
    """R11: a detached body whose leg raises is recorded failed with the
    classified error envelope stored (never completed), and a later
    tasks/get-style embed would carry it as an error result."""
    mod = _boot(tmp_path, UNRESTRICTED)
    fake = _FakePS(raise_on="Checkpoint-VM")
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    handle = _call(mcp, "hyperv_checkpoint_create",
                   {"vm_name": "test-vm", "checkpoint_name": "boom", "detach": True})
    assert handle.get("op_id")
    import time

    deadline = time.monotonic() + 5.0
    status = {}
    while time.monotonic() < deadline:
        status = _call(mcp, "hyperv_op_status", {"op_id": handle["op_id"]})
        if status.get("status") in ("completed", "failed"):
            break
        time.sleep(0.02)
    assert status.get("status") == "failed", (
        f"R11: a crashing detached body must record failed; got {json.dumps(status)[:300]}"
    )
    assert status.get("error_class") not in ("", None), (
        f"R11: the failed op must carry an error_class; got {json.dumps(status)[:200]}"
    )
    result = _call(mcp, "hyperv_op_result", {"op_id": handle["op_id"]})
    assert result.get("chunk") and json.loads(result["chunk"]).get("ok") is False, (
        f"R11: the stored result must be the error envelope; got {json.dumps(result)[:300]}"
    )
    operations.drain_for_tests(timeout_s=5.0)


def test_v2_store_migrates_forward_to_v3_with_all_tables(tmp_path):
    """R12: a hand-built v2 store (jobs/relays/leases/indexes/fence_counters,
    user_version=2) migrates to version 3 with ops/events/meta PRESENT and
    reopens cleanly — the forward migration's content is asserted, so a
    truncated migration slice cannot brick an upgraded store."""

    db = tmp_path / "v2.db"
    con = sqlite3.connect(str(db))
    try:
        con.executescript(
            """
            CREATE TABLE jobs (job_id TEXT PRIMARY KEY, vm_name TEXT NOT NULL DEFAULT '',
                vm_id TEXT NOT NULL DEFAULT '', pid INTEGER NOT NULL DEFAULT 0,
                start_time_ticks INTEGER, job_dir TEXT NOT NULL DEFAULT '',
                out_path TEXT NOT NULL DEFAULT '', err_path TEXT NOT NULL DEFAULT '',
                exit_path TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'starting', cred_ref TEXT NOT NULL DEFAULT 'inline',
                owner TEXT);
            CREATE TABLE relays (relay_id TEXT PRIMARY KEY, vm_name TEXT NOT NULL DEFAULT '',
                vm_id TEXT NOT NULL DEFAULT '', guest_port INTEGER NOT NULL DEFAULT 0,
                bind TEXT NOT NULL DEFAULT '127.0.0.1', host_port INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'active',
                cred_ref TEXT NOT NULL DEFAULT 'inline', owner TEXT);
            CREATE TABLE leases (row_key TEXT PRIMARY KEY, lease_id TEXT NOT NULL,
                vm_key TEXT NOT NULL, vm_name TEXT NOT NULL DEFAULT '', scope TEXT NOT NULL,
                holder_agent TEXT, fencing_seq INTEGER NOT NULL DEFAULT 0,
                acquired_at REAL NOT NULL DEFAULT 0, ttl_s INTEGER NOT NULL DEFAULT 0,
                expires_at REAL NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT 'explicit',
                write_lock INTEGER NOT NULL DEFAULT 1);
            CREATE INDEX leases_active ON leases(vm_key, expires_at);
            CREATE INDEX leases_by_id ON leases(lease_id);
            CREATE INDEX leases_by_name ON leases(vm_name COLLATE NOCASE);
            CREATE TABLE fence_counters (vm_key TEXT NOT NULL, scope TEXT NOT NULL,
                last_seq INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (vm_key, scope));
            INSERT INTO jobs (job_id, state) VALUES ('legacy-1', 'stopped');
            PRAGMA user_version = 2;
            """
        )
        con.commit()
    finally:
        con.close()

    store = statestore.open(str(db))
    try:
        version = sqlite3.connect(str(db)).execute("PRAGMA user_version").fetchone()[0]
        assert version == statestore.SCHEMA_VERSION == 3, version
        names = {
            row[0] for row in sqlite3.connect(str(db)).execute(
                "SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"ops", "events", "meta"} <= names, sorted(names)
        # the migrated store is immediately usable in both directions

        store.op_insert(statestore.OpRow(
            op_id="op-post-v3", tool="t", agent="a",
            created_at=1.0, updated_at=1.0, idem_key="",
        ))
        assert store.op_get("op-post-v3") is not None
    finally:
        store.close()
    # a genuine reopen (not cache) also succeeds
    reopened = statestore.open(str(db))
    try:
        assert reopened.op_get("op-post-v3") is not None
    finally:
        reopened.close()


def test_events_and_ops_retention_sweeps(tmp_path):
    """R14: the SHIPPED sweep functions execute — events_prune honours the
    age cutoff and the row cap with AUTOINCREMENT seqs never reused, and
    ops_prune removes only TERMINAL rows past retention."""

    db = tmp_path / "retention.db"
    store = statestore.open(str(db))
    try:
        old_ts = "2000-01-01T00:00:00.000+00:00"
        new_ts = "2100-01-01T00:00:00.000+00:00"
        for i in range(5):
            store.event_append(old_ts if i < 3 else new_ts, "agent-a", "op.created",
                               f"op-{i}", "", "{}")
        removed = store.events_prune(new_ts, 100)
        assert removed == 3, removed
        remaining = store.events_after("agent-a", 0, 100)
        assert [r["seq"] for r in remaining] == [4, 5], remaining
        # row cap: keep only the 1 newest
        removed = store.events_prune(new_ts, 1)
        assert removed == 1, removed
        assert len(store.events_after("agent-a", 0, 100)) == 1
        new_seq = store.event_append(new_ts, "agent-a", "op.completed", "op-x", "", "{}")
        assert new_seq == 6, "AUTOINCREMENT must never reuse a pruned seq"

        now = store.now()
        for i in range(3):
            store.op_insert(statestore.OpRow(
                op_id=f"op-old-{i}", tool="t", agent="a", status=statestore.OP_COMPLETED,
                created_at=now - 100000, updated_at=now - 100000, result_json="{}",
            ))
        store.op_insert(statestore.OpRow(
            op_id="op-old-working", tool="t", agent="a", status=statestore.OP_WORKING,
            created_at=now - 100000, updated_at=now - 100000,
        ))
        removed = store.ops_prune(now - 86400)
        assert removed == 3, removed
        assert store.op_get("op-old-working") is not None, "working rows are never swept"
        assert store.op_get("op-old-0") is None
    finally:
        store.close()


def test_interceptor_slot_accounting_across_create_reattach_conflict(tmp_path):
    """Review F1: the tasks interceptor's admission slot is restored on EVERY
    no-runner exit — re-attach AND idempotency_conflict — so one conflict can
    never permanently erode the runner bound. Drives the SHIPPED extension
    instance with a fabricated per-request-capability context (the same
    object bootstrap installed), not a lookalike."""
    from types import SimpleNamespace

    mod = _boot(tmp_path, {**UNRESTRICTED, "operations": {"runner_bound": 2}})
    gate = threading.Event()
    fake = _FakePS(gate=gate)
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(pswindows, "run_ps", fake)
        mcp = mod.get_mcp()
        ext = next(e for e in mcp._extensions
                   if getattr(e, "identifier", "") == "io.modelcontextprotocol/tasks")
        caps = SimpleNamespace(extensions={"io.modelcontextprotocol/tasks": {}})
        ctx = SimpleNamespace(session=SimpleNamespace(client_capabilities=caps))

        async def run_intercept(name, arguments):
            params = SimpleNamespace(name=name, arguments=arguments)
            return await ext.intercept_tool_call(params, ctx, None)

        def slots_free() -> int:
            return server_module._runner_slots()._value

        assert slots_free() == 2
        a = asyncio.run(run_intercept(
            "hyperv_checkpoint_create",
            {"vm_name": "test-vm", "checkpoint_name": "k1", "idempotency_key": "kap"}))
        assert getattr(a, "task_id", ""), "A: expected a task handle"
        assert slots_free() == 1, f"A: one gated runner holds one slot; free={slots_free()}"

        b = asyncio.run(run_intercept(
            "hyperv_checkpoint_create",
            {"vm_name": "test-vm", "checkpoint_name": "k1", "idempotency_key": "kap"}))
        assert b.task_id == a.task_id, "B: keyed repeat re-attaches"
        # B acquired then released on the re-attach path: back to A's level
        assert slots_free() == 1, f"B: re-attach restores the slot; free={slots_free()}"

        c = asyncio.run(run_intercept(
            "hyperv_checkpoint_create",
            {"vm_name": "test-vm", "checkpoint_name": "DIFFERENT", "idempotency_key": "kap"}))
        payload = json.loads(c.content[0].text)
        assert payload.get("error_class") == "idempotency_conflict", json.dumps(payload)[:200]
        assert slots_free() == 1, (
            f"F1: a conflict refusal must restore the admission slot; free={slots_free()}"
        )

        d = asyncio.run(run_intercept(
            "hyperv_checkpoint_create",
            {"vm_name": "test-vm", "checkpoint_name": "k2", "detach": True}))
        assert getattr(d, "task_id", ""), "D: a fresh detach is still admitted after the conflict"
        assert slots_free() == 0, "D: the fresh gated runner holds the last slot"
    finally:
        gate.set()
        monkey.undo()
        operations.drain_for_tests(timeout_s=5.0)


def test_preflight_refusal_answers_audited_envelope_both_param_shapes(tmp_path):
    """Review F2: a DETACHED call refused by the synchronous preflight answers
    the ordinary ok:false envelope (error_class policy for a missing confirm,
    invalid for a mistyped confirm) with ZERO op rows - never a raw escape -
    and leaves the same audit record every other guard refusal writes (the
    audit_log_path file is read back and the two error_class values are
    asserted). Both calls carry detach:true so the preflight seam
    (operations.guard_consult's preflight hook) is ON the call path: this test
    FAILS if the F2 handler in server.py is reverted to a re-raise."""
    audit_log = tmp_path / "guardrail-audit.jsonl"
    mod = _boot(tmp_path, {**UNRESTRICTED,
                           "audit_log_path": str(audit_log)})
    fake = _FakePS()
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(pswindows, "run_ps", fake)
        mcp = mod.get_mcp()

        refused = _call(mcp, "hyperv_checkpoint_restore",
                        {"vm_name": "test-vm", "checkpoint_name": "snap",
                         "detach": True})
        assert refused.get("ok") is False and refused.get("error_class") == "policy", (
            f"F2: detach without confirm must answer the policy envelope; "
            f"got {json.dumps(refused)[:300]}"
        )
        mistyped = _call(mcp, "hyperv_checkpoint_restore",
                         {"vm_name": "test-vm", "checkpoint_name": "snap",
                          "confirm": "banana", "detach": True})
        assert mistyped.get("ok") is False and mistyped.get("error_class") == "invalid", (
            f"F2: a mistyped confirm must answer invalid; got {json.dumps(mistyped)[:300]}"
        )
        assert fake.count("Restore-VMSnapshot") == 0
        statestore.clear_store_cache_for_tests()
        store = statestore.store_for(mod.CFG)
        try:
            assert store.op_rows_by_agent("", include_terminal=True) == [], (
                "F2: a refused detached call must mint no op row"
            )
        finally:
            statestore.clear_store_cache_for_tests()
        # The audit record the docstring promises: one audited rejection per
        # refusal, carrying the same error_class as the envelope.
        records = [json.loads(line) for line in
                   audit_log.read_text(encoding="utf-8").splitlines() if line.strip()]
        restores = [r for r in records if r.get("tool") == "hyperv_checkpoint_restore"]
        assert sorted(r.get("error_class") for r in restores) == ["invalid", "policy"], (
            f"F2: both preflight refusals must leave audit records with their "
            f"error_class; got {restores}"
        )
    finally:
        monkey.undo()


def test_sync_keyed_envelope_refusal_records_failed_with_event(tmp_path):
    """Review F4 (Q1 pin): a keyed SYNC call whose body returns a tool-level
    ok:false envelope is recorded FAILED with the envelope's error_class and
    an op.failed event carrying mode:inline - symmetric with the detached path
    (operations.complete_inline) - while a succeeding keyed call stays
    completed. FAILS when the ok:false classification in complete_inline is
    reverted."""
    mod = _boot(tmp_path, UNRESTRICTED)

    class LegFailurePS(_FakePS):
        def __call__(self, script, **kwargs):
            result = super().__call__(script, **kwargs)
            # fail ONLY the second create's action leg: the fake's gate-free
            # fake answers every leg, so keying the two calls apart by
            # checkpoint name keeps the control (good) succeeding
            if "Checkpoint-VM" in script and "fail" in script and "good" not in script:
                return pswindows.PSResult(
                    stdout="", stderr="simulated leg failure", returncode=1)
            return result

    fake = LegFailurePS()
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(pswindows, "run_ps", fake)
        mcp = mod.get_mcp()
        refused = _call(mcp, "hyperv_checkpoint_create",
                        {"vm_name": "test-vm", "checkpoint_name": "fail",
                         "idempotency_key": "q1-fail"})
        assert refused.get("ok") is False, json.dumps(refused)[:200]
        # locate the row via the idempotency record
        store = statestore.store_for(mod.CFG)
        row = store.op_find_idem("", "hyperv_checkpoint_create", "q1-fail")
        assert row is not None and row.status == statestore.OP_FAILED, (
            f"F4: a sync keyed refusal must record failed; got "
            f"{(row.status, row.error_class) if row else None}"
        )
        assert row.error_class == "transport", row.error_class
        events = [json.loads(r["data_json"]) for r in
                  store.events_after(row.agent or "", 0, 100)
                  if r["ref_id"] == row.op_id]
        assert any(e.get("mode") == "inline" and e.get("error_class") == "transport"
                   for e in events), (
            f"F4: the op.failed event must carry mode:inline; got {events}"
        )

        ok = _call(mcp, "hyperv_checkpoint_create",
                   {"vm_name": "test-vm", "checkpoint_name": "good",
                    "idempotency_key": "q1-ok"})
        assert ok.get("status") == "created", json.dumps(ok)[:200]
        row_ok = store.op_find_idem("", "hyperv_checkpoint_create", "q1-ok")
        assert row_ok is not None and row_ok.status == statestore.OP_COMPLETED
    finally:
        monkey.undo()
