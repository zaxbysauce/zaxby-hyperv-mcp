"""Issue #24 acceptance checks, part 2 (trace 24-durable-operation-handles):
the durable operation store behind the op_* / hyperv_events tools — crash
recovery, cursor-paged results, cooperative cancel, per-agent scoping, the
event cursor across restarts and pruning, idempotency conflicts, and
secret-free persistence.

ACs carried (01-issue-summary.md):
  AC5  test_working_op_after_restart_reports_interrupted
  AC6  test_op_result_cursor_pages_large_result
  AC7  test_op_cancel_is_cooperative_and_terminal
  AC8  test_ops_and_events_scoped_to_caller_agent
  AC9  test_event_cursor_resumes_after_restart
  AC10 test_idempotency_key_reuse_with_different_args_conflicts
  AC11 test_persisted_operation_rows_hold_no_secrets

RED at base, GREEN after the fix — the RED signature for this whole file is
the module-level import: at base 55da0d3 there IS no hyperv_mcp.operations,
so collection fails with `ImportError: cannot import name 'operations'`.
That is the expected new-surface signature the issue documents, not an
authoring bug; after the fix lands, every check in this file must pass as
written.

Surface driven: the REAL tool surface (get_mcp().call_tool against the
bootstrapped server) plus the E-01 store seams the issue names — tmp-path
state DB, an injected clock through statestore.Store(path, clock=...) rebound
at the statestore.store_for seam (the frozen test_e02_lease_store._clock_store
pattern), a genuine store reopen (close cached stores, remount, or reload the
server module), and direct sqlite reads only where the issue speaks of file
bytes (AC11) or of pruning rows (AC9, the issue's AUTOINCREMENT note). What
is faked: PowerShell only (content-dispatched run_ps with gating Events for
"runner mid-leg" determinism) and TIME (FakeClock). No network, no real
PowerShell; the only real sleeps are bounded op_status polls (0.02 s steps,
5 s deadline).

DECLARED GUESSES a correct fix must honor (same standing as the frozen e02
file's guesses): the operations layer resolves its store through
statestore.store_for(cfg) (re-bound on hyperv_mcp.operations too if it holds
its own reference); event rows live in the issue-documented `events` table
keyed by an AUTOINCREMENT seq (AC9 prunes by deleting the oldest rows, which
is what retention pruning does); the op_result page carries its payload under
"chunk" / "data" / "page" / "result" in that preference order (AC6's
byte-identity holds for whichever key the server uses consistently).
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

import hyperv_mcp.server as server_module
from hyperv_mcp import (  # noqa: F401 — `operations` is the RED anchor
    leases,
    operations,
    pswindows,
    statestore,
)

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

# A runner heartbeat TTL must sit far below the store's other horizons
# (leases max_ttl_s=3600, the proposed 24 h idempotency expiry) — advancing
# the injected clock by 2 h is stale for any sane heartbeat TTL and fresh
# for nothing else this file depends on.
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
    """Owns the statestore.store_for seam across remounts.

    A remount closes the current clock-injected Store and opens a fresh one
    on the same database — a genuine store reopen, so wherever the stale
    heartbeat is classified (at reopen or at read) the reopen really
    happened. DECLARED GUESS: the production operations API resolves its
    store through statestore.store_for(cfg) — the repo's established cached
    path — and re-binds its own reference if it holds one (the frozen e02
    _clock_store pattern).
    """

    def __init__(self, monkeypatch, db: str, clock: FakeClock) -> None:
        self._monkeypatch = monkeypatch
        self.db = str(db)
        self.clock = clock
        self.store: statestore.Store | None = None
        self.mount()

    def _bind(self) -> None:
        store = self.store
        assert store is not None

        def _fake_store_for(cfg, environ=None):
            return store

        self._monkeypatch.setattr(statestore, "store_for", _fake_store_for)
        if hasattr(operations, "store_for"):
            self._monkeypatch.setattr(operations, "store_for", _fake_store_for, raising=False)

    def mount(self) -> ClockStoreMount:
        statestore.open(self.db).close()  # ensure schema exists via the real open()
        self.store = statestore.Store(self.db, clock=self.clock)
        self._bind()
        return self

    def reopen(self) -> ClockStoreMount:
        """Close and re-open the same database through the same seam."""
        if self.store is not None:
            self.store.close()
        return self.mount()

    def close(self) -> None:
        if self.store is not None:
            self.store.close()
            self.store = None


class GatedFakePS:
    """Content-dispatched, thread-safe run_ps fake.

    The by-name resolution leg answers the stable GUID; the checkpoint /
    restore legs succeed; the guest leg answers benign JSON. Legs matching a
    marker in `gates` block on that Event until released ("the runner is
    mid-leg", deterministically).
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
        if "Invoke-Command -VMId" in script:
            return pswindows.PSResult(
                stdout=json.dumps({"exit_code": 0, "stdout": "guest-ok", "stderr": ""}),
                returncode=0,
            )
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


UNRESTRICTED_DOC = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}
INLINE_CRED_DOC = {
    "allowed_vm_patterns": ["test-*"],
    "unrestricted": True,
    "allow_inline_credentials": True,
}


def _boot(tmp_path, fresh_server, doc: dict) -> type(server_module):
    p = tmp_path / "e03-store-config.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return fresh_server({"HYPERV_MCP_CONFIG": str(p)})


def _payload(result, label: str) -> dict:
    from conftest import content_blocks

    texts = [c for c in content_blocks(result) if getattr(c, "type", "") == "text"]
    assert texts, f"expected a JSON text payload for {label}"
    payload = json.loads(texts[0].text)
    assert isinstance(payload, dict), f"{label}: payload is not an object: {payload!r}"
    return payload


def _call(mcp, tool: str, args: dict) -> dict:
    return _payload(asyncio.run(mcp.call_tool(tool, args)), tool)


def _as_agent(client_id: str):
    """Set the auth context exactly as AuthContextMiddleware does."""
    return auth_context_var.set(
        AuthenticatedUser(AccessToken(token="t", client_id=client_id, scopes=[]))
    )


def _poll_status(mcp, op_id: str, want: set[str], label: str) -> dict:
    """Poll hyperv_op_status until status is in `want` (bounded; 0.02 s steps)."""
    deadline = time.monotonic() + 5.0
    status = {}
    while time.monotonic() < deadline:
        status = _call(mcp, "hyperv_op_status", {"op_id": op_id})
        if status.get("status") in want:
            return status
        time.sleep(0.02)
    raise AssertionError(
        f"{label}: op {op_id} never reached {sorted(want)}; last status "
        f"{json.dumps(status)[:300]}"
    )


def _detach(mcp, tool: str, args: dict, label: str) -> str:
    """Detach-call a tool and return its op_id."""
    handle = _call(mcp, tool, args)
    assert isinstance(handle.get("op_id"), str) and handle["op_id"], (
        f"{label}: expected an operation handle with op_id; got {json.dumps(handle)[:300]}"
    )
    return handle["op_id"]


def _page_text(page: dict) -> str:
    """The paged payload text of one op_result page.

    DECLARED GUESS: the payload rides under "chunk" / "data" / "page" /
    "result" in that preference order; the fallback is the longest string
    value, which is stable across reads of the same page so AC6's
    byte-identity assertions hold for whichever key the server uses.
    """
    for key in ("chunk", "data", "page", "result"):
        value = page.get(key)
        if isinstance(value, str):
            return value
    strings = [v for v in page.values() if isinstance(v, str)]
    assert strings, f"op_result page carries no text payload: {sorted(page)}"
    return max(strings, key=len)


# ---------------------------------------------------------------------------
# AC5 — a stale-heartbeat working op reports failed/interrupted at reopen;
# a fresh-heartbeat op (another live runner) stays working
# ---------------------------------------------------------------------------


def test_working_op_after_restart_reports_interrupted(tmp_path, fresh_server, monkeypatch):
    """AC5: op A's runner heartbeat is older than its TTL when the store
    reopens (injected clock advanced 2 h; the runner is blocked mid-leg, the
    process is 'gone') -> op_status reports status 'failed' with error_class
    'interrupted' and notes the VM-side outcome is unknown. Op B, created at
    the advanced clock time (a live runner's fresh heartbeat), stays
    'working' after the same reopen. RED at base (module absent), GREEN
    after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    db = str(tmp_path / "state.db")
    clock = FakeClock()
    mount = ClockStoreMount(monkeypatch, db, clock)
    # One gate serializes BOTH ops' Checkpoint-VM legs: op A blocks in its
    # action leg (heartbeat frozen at clock T0), and op B — created at the
    # ADVANCED clock time — blocks in its own action leg with a fresh row.
    gate = threading.Event()
    fake = GatedFakePS(gates={"Checkpoint-VM": gate})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    token = _as_agent("agent-a")
    try:
        op_a = _detach(mcp, "hyperv_checkpoint_create",
                       {"vm_name": "test-vm", "checkpoint_name": "stale", "detach": True},
                       "AC5 op-a")
        # The runner is gated mid action-leg: heartbeat written at clock T0.
        clock.advance(RESTART_CLOCK_ADVANCE_S)
        # Op B is created NOW, at the advanced clock: its row is fresh, the
        # shape a second live runner process would keep heartbeating.
        op_b = _detach(mcp, "hyperv_checkpoint_create",
                       {"vm_name": "test-vm", "checkpoint_name": "fresh", "detach": True},
                       "AC5 op-b")

        mount.reopen()  # the store reopen the AC names

        staled = _call(mcp, "hyperv_op_status", {"op_id": op_a})
        assert staled.get("status") == "failed", (
            f"AC5: a working op whose runner heartbeat is older than its TTL "
            f"must report failed at reopen; got {json.dumps(staled)[:300]}"
        )
        assert staled.get("error_class") == "interrupted", (
            f"AC5: the crash-recovered op must carry error_class "
            f"'interrupted'; got {staled.get('error_class')!r}"
        )
        assert "unknown" in json.dumps(staled).lower(), (
            f"AC5: the recovered op must note that the VM-side outcome is "
            f"unknown; got {json.dumps(staled)[:300]}"
        )

        fresh = _call(mcp, "hyperv_op_status", {"op_id": op_b})
        assert fresh.get("status") == "working", (
            f"AC5: an op whose runner heartbeat is still fresh (another live "
            f"process) must stay working at reopen; got {json.dumps(fresh)[:300]}"
        )
    finally:
        auth_context_var.reset(token)
        gate.set()
        mount.close()


# ---------------------------------------------------------------------------
# AC6 — a 300 KiB stored result pages from op_result in <=64 KiB chunks
# ---------------------------------------------------------------------------


def test_op_result_cursor_pages_large_result(tmp_path, fresh_server, monkeypatch):
    """AC6: a completed detached hyperv_guest_run_ps whose stored result is
    300 KiB pages from hyperv_op_result(op_id, cursor='') in chunks of at
    most 64 KiB, each page carrying next_cursor, the last page done: true;
    re-reading from an earlier cursor — including after a store reopen —
    returns identical bytes. RED at base, GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, INLINE_CRED_DOC)
    db = str(tmp_path / "state.db")
    mount = ClockStoreMount(monkeypatch, db, FakeClock())

    big_stdout = "Q" * (300 * 1024)

    class BigGuestPS(GatedFakePS):
        def __call__(self, script, **kwargs):
            result = super().__call__(script, **kwargs)
            if "Invoke-Command -VMId" in script:
                return pswindows.PSResult(
                    stdout=json.dumps(
                        {"exit_code": 0, "stdout": big_stdout, "stderr": ""}
                    ),
                    returncode=0,
                )
            return result

    fake = BigGuestPS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    op_id = _detach(
        mcp, "hyperv_guest_run_ps",
        {"vm_name": "test-vm", "script": "Write-Output big", "username": "Administrator",
         "password": "unit-pass", "detach": True},
        "AC6",
    )
    _poll_status(mcp, op_id, {"completed"}, "AC6")

    def read_all(cursor: str) -> tuple[str, list[dict]]:
        pages = []
        text = ""
        seen = 0
        while True:
            page = _call(mcp, "hyperv_op_result", {"op_id": op_id, "cursor": cursor})
            chunk = _page_text(page)
            assert len(chunk.encode("utf-8")) <= 64 * 1024, (
                f"AC6: page {seen} is {len(chunk.encode('utf-8'))} bytes; every "
                f"page must be at most 64 KiB"
            )
            text += chunk
            pages.append(page)
            cursor = page.get("next_cursor")
            if page.get("done") is True:
                assert not cursor, (
                    f"AC6: the done page must not offer next_cursor; got {cursor!r}"
                )
                return text, pages
            assert isinstance(cursor, str) and cursor, (
                f"AC6: a non-terminal page must carry next_cursor; got {page!r}"
            )
            seen += 1
            assert seen < 64, "AC6: page chain did not terminate"

    full, pages = read_all("")
    assert len(full.encode("utf-8")) >= 300 * 1024, (
        f"AC6: the paged read must reconstruct the >=300 KiB stored result; "
        f"got {len(full.encode('utf-8'))} bytes over {len(pages)} pages"
    )
    assert len(pages) >= 2, (
        "AC6: a 300 KiB result cannot fit one 64 KiB page; expected a chain"
    )

    early_cursor = pages[0].get("next_cursor")
    assert isinstance(early_cursor, str) and early_cursor, "AC6: no early cursor to resume from"

    tail, _tail_pages = read_all(early_cursor)
    assert tail == full[len(_page_text(pages[0])):], (
        "AC6: resuming from the first page's cursor must return the exact "
        "remaining bytes"
    )

    mount.reopen()  # the store reopen the AC names
    tail2, _p2 = read_all(early_cursor)
    assert tail2 == tail, (
        "AC6: after a store reopen, resuming from the same earlier cursor "
        "must return byte-identical pages"
    )
    mount.close()


# ---------------------------------------------------------------------------
# AC7 — cooperative cancel between legs; cancel on a terminal op is a no-op
# ---------------------------------------------------------------------------


def test_op_cancel_is_cooperative_and_terminal(tmp_path, fresh_server, monkeypatch):
    """AC7: op_cancel on a working op records cancel_requested and returns
    the current status; the runner (gated mid restore-leg, with the state
    wait leg still ahead) moves the op to cancelled at its next cooperative
    check. op_cancel on the now-terminal op is a no-op reporting the
    terminal status. RED at base, GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    mount = ClockStoreMount(monkeypatch, str(tmp_path / "state.db"), FakeClock())
    gate = threading.Event()
    fake = GatedFakePS(gates={"Restore-VMSnapshot": gate})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    token = _as_agent("agent-a")
    try:
        op_id = _detach(
            mcp, "hyperv_checkpoint_restore",
            {"vm_name": "test-vm", "checkpoint_name": "snap", "confirm": True, "detach": True},
            "AC7",
        )
        cancel_resp = _call(mcp, "hyperv_op_cancel", {"op_id": op_id})
        assert cancel_resp.get("cancel_requested") is True, (
            f"AC7: op_cancel must record cancel_requested; got "
            f"{json.dumps(cancel_resp)[:300]}"
        )
        assert cancel_resp.get("status") == "working", (
            f"AC7: op_cancel must return the current status 'working'; got "
            f"{cancel_resp.get('status')!r}"
        )

        gate.set()  # the runner proceeds past the restore leg...
        final = _poll_status(mcp, op_id, {"cancelled", "completed"}, "AC7 runner check")
        assert final.get("status") == "cancelled", (
            f"AC7: the runner must honor the cancel flag at its next "
            f"cooperative check (the state-wait leg ahead of it); got "
            f"{json.dumps(final)[:300]}"
        )

        # Cancel on a terminal op: a no-op that reports the terminal status.
        again = _call(mcp, "hyperv_op_cancel", {"op_id": op_id})
        assert again.get("status") == "cancelled", (
            f"AC7: cancelling a terminal op must report its terminal status; "
            f"got {json.dumps(again)[:300]}"
        )
        assert not again.get("error_class"), (
            f"AC7: cancelling a terminal op is a no-op, not an error; got "
            f"{json.dumps(again)[:300]}"
        )
    finally:
        auth_context_var.reset(token)
        gate.set()
        mount.close()


# ---------------------------------------------------------------------------
# AC8 — ops and events are scoped to the calling agent
# ---------------------------------------------------------------------------


def test_ops_and_events_scoped_to_caller_agent(tmp_path, fresh_server, monkeypatch):
    """AC8: agent b touching agent a's op_id through op_status, op_result
    and op_cancel gets EXACTLY the unknown-id answer (same error_class and
    id-normalized error text), and b's op_list / hyperv_events list none of
    a's rows; a's op row is untouched. RED at base, GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    mount = ClockStoreMount(monkeypatch, str(tmp_path / "state.db"), FakeClock())
    gate = threading.Event()
    fake = GatedFakePS(gates={"Checkpoint-VM": gate})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    unknown_id = "op-that-does-not-exist-0001"

    token = _as_agent("agent-a")
    op_id = _detach(mcp, "hyperv_checkpoint_create",
                    {"vm_name": "test-vm", "checkpoint_name": "scoped", "detach": True},
                    "AC8 a")
    auth_context_var.reset(token)

    def refusal_signature(env: dict, op_id: str) -> tuple:
        """error_class plus the error text with the probed id normalized out,
        so an id-echoing message compares equal while a foreign-vs-unknown
        wording difference does not."""
        return (
            env.get("error_class"),
            str(env.get("error", "")).replace(op_id, "<op_id>"),
        )

    token = _as_agent("agent-b")
    try:
        for tool, extra in (
            ("hyperv_op_status", {}),
            ("hyperv_op_result", {"cursor": ""}),
            ("hyperv_op_cancel", {}),
        ):
            foreign = _call(mcp, tool, {"op_id": op_id, **extra})
            unknown = _call(mcp, tool, {"op_id": unknown_id, **extra})
            assert foreign.get("ok") is False and unknown.get("ok") is False, (
                f"AC8: {tool} must refuse both a foreign and an unknown id; "
                f"foreign={json.dumps(foreign)[:200]} unknown={json.dumps(unknown)[:200]}"
            )
            assert refusal_signature(foreign, op_id) == refusal_signature(unknown, unknown_id), (
                f"AC8: {tool} answering agent b for agent a's op must be "
                f"indistinguishable from an unknown id; foreign="
                f"{json.dumps(foreign)[:200]} unknown={json.dumps(unknown)[:200]}"
            )

        listing = _call(mcp, "hyperv_op_list", {})
        events = _call(mcp, "hyperv_events", {"after": ""})
        assert op_id not in json.dumps(listing), (
            f"AC8: agent b's op_list must not list agent a's ops; got "
            f"{json.dumps(listing)[:300]}"
        )
        assert op_id not in json.dumps(events), (
            f"AC8: agent b's hyperv_events must not list agent a's events; "
            f"got {json.dumps(events)[:300]}"
        )
    finally:
        auth_context_var.reset(token)

    # b's probes changed nothing: a still sees the op working.
    token = _as_agent("agent-a")
    try:
        status = _call(mcp, "hyperv_op_status", {"op_id": op_id})
        assert status.get("status") == "working", (
            f"AC8: agent b's foreign probes must not change a's op; got "
            f"{json.dumps(status)[:300]}"
        )
    finally:
        auth_context_var.reset(token)
        gate.set()
        mount.close()


# ---------------------------------------------------------------------------
# AC9 — the event cursor resumes across a restart and pruning
# ---------------------------------------------------------------------------


def _event_key(row: dict):
    """Stable identity of one event row: its sequence/id field when exposed,
    else the canonical JSON of the row (deterministic for identical rows)."""
    for key in ("seq", "id", "event_id", "cursor"):
        value = row.get(key)
        if isinstance(value, int):
            return ("seq", value)
        if isinstance(value, str) and value:
            return ("seq", value)
    return ("json", json.dumps(row, sort_keys=True))


def test_event_cursor_resumes_after_restart(tmp_path, fresh_server, monkeypatch):
    """AC9: lease transitions append events 1..8 (ONE event per transition:
    a _transition call is an acquire plus a release, so it appends two);
    a client reads hyperv_events(after='') and captures a mid cursor after
    the first _transition; three more _transition calls bring the total to
    eight; the store is reopened, three more _transition calls append
    events 9..14, and the two oldest rows are pruned (the retention sweep's
    own DELETE — AUTOINCREMENT keeps seqs monotonic). Resuming from the kept
    cursor returns exactly the six new events in order with no repeats; the
    too-old mid cursor returns cursor_expired: true with oldest_cursor.

    One event per lease transition is the counted append unit (the issue's
    plan emits one lease.* event per transition). RED at base, GREEN after
    the fix. AMENDED (CHECK_WRONG): the original freeze asserted call-counts
    (2/5/3) under a per-transition append unit — an arithmetic slip caught by
    the plan critic; corrected to transition-counts (2/8/6)."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    mcp = mod.get_mcp()
    cfg = mod.CFG
    db = str(tmp_path / "state.db")

    def _transition(vm: str) -> None:
        lease = leases.acquire(cfg, vm, ["console"], "agent-a")[0]
        leases.release(cfg, lease.lease_id, "agent-a")

    def _events(cursor: str) -> dict:
        token = _as_agent("agent-a")
        try:
            return _call(mcp, "hyperv_events", {"after": cursor})
        finally:
            auth_context_var.reset(token)

    def _rows(payload: dict) -> list:
        rows = payload.get("events") or payload.get("rows") or payload.get("items")
        if rows is None:
            for value in payload.values():
                if isinstance(value, list) and value and isinstance(value[0], dict):
                    rows = value
                    break
        assert isinstance(rows, list), (
            f"AC9: hyperv_events must return an event list; got "
            f"{json.dumps(payload)[:300]}"
        )
        return rows

    _transition("cursor-vm-1")
    mid = _events("")
    mid_rows = _rows(mid)
    assert len(mid_rows) == 2, (
        f"AC9: two lease transitions must append two events; got "
        f"{len(mid_rows)} ({json.dumps(mid_rows)[:300]})"
    )
    mid_cursor = mid.get("next_cursor")
    assert isinstance(mid_cursor, str) and mid_cursor, (
        f"AC9: hyperv_events must hand back next_cursor; got {mid_cursor!r}"
    )

    _transition("cursor-vm-2")
    _transition("cursor-vm-3")
    _transition("cursor-vm-4")
    full = _events("")
    full_rows = _rows(full)
    assert len(full_rows) == 8, (
        f"AC9: eight lease transitions must total eight events (one per "
        f"acquire and per release); got {len(full_rows)}"
    )
    kept_cursor = full.get("next_cursor")
    assert isinstance(kept_cursor, str) and kept_cursor, (
        f"AC9: the full read must hand back next_cursor; got {kept_cursor!r}"
    )

    # Simulated restart: close every cached Store so the next access reopens.
    statestore.clear_store_cache_for_tests()
    _transition("cursor-vm-5")
    _transition("cursor-vm-6")
    _transition("cursor-vm-7")

    # Retention pruning: delete the two oldest event rows — what the sweep
    # does; AUTOINCREMENT never reuses their seqs.
    con = sqlite3.connect(db)
    try:
        con.execute(
            "DELETE FROM events WHERE rowid IN "
            "(SELECT rowid FROM events ORDER BY rowid LIMIT 2)"
        )
        con.commit()
    finally:
        con.close()

    resumed = _events(kept_cursor)
    resumed_rows = _rows(resumed)
    assert len(resumed_rows) == 6, (
        f"AC9: resuming from the kept cursor must return exactly the six "
        f"new events (three post-restart _transition calls x two "
        f"transitions); got {len(resumed_rows)} "
        f"({json.dumps(resumed_rows)[:300]})"
    )
    resumed_keys = [_event_key(r) for r in resumed_rows]
    seen_keys = [_event_key(r) for r in mid_rows] + [_event_key(r) for r in full_rows]
    assert not (set(resumed_keys) & set(seen_keys)), (
        "AC9: the resumed read must not repeat any pre-restart event"
    )
    seqs = [k[1] for k in resumed_keys if k[0] == "seq" and isinstance(k[1], int)]
    assert not seqs or seqs == sorted(seqs), (
        f"AC9: the resumed events must arrive in sequence order; got {seqs}"
    )

    expired = _events(mid_cursor)
    assert expired.get("cursor_expired") is True, (
        f"AC9: a cursor older than the retention window must answer "
        f"cursor_expired: true; got {json.dumps(expired)[:300]}"
    )
    oldest = expired.get("oldest_cursor")
    assert isinstance(oldest, str) and oldest, (
        f"AC9: the expired answer must carry oldest_cursor; got {oldest!r}"
    )


# ---------------------------------------------------------------------------
# AC10 — same agent, same key, different args: idempotency_conflict
# ---------------------------------------------------------------------------


def test_idempotency_key_reuse_with_different_args_conflicts(tmp_path, fresh_server, monkeypatch):
    """AC10: agent a reuses idempotency_key k-1 on
    hyperv_checkpoint_create with different arguments -> refused with
    error_class 'idempotency_conflict' and NO PowerShell run for the refused
    call. Agent b using the same key k-1 is an independent key: the call
    runs. RED at base, GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, UNRESTRICTED_DOC)
    mount = ClockStoreMount(monkeypatch, str(tmp_path / "state.db"), FakeClock())
    fake = GatedFakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    token = _as_agent("agent-a")
    try:
        first = _call(mcp, "hyperv_checkpoint_create",
                      {"vm_name": "test-vm", "checkpoint_name": "alpha",
                       "idempotency_key": "k-1"})
        assert first.get("status") == "created", (
            f"AC10: the first keyed call must succeed; got {json.dumps(first)[:300]}"
        )
        runs_before = fake.total()

        conflict = _call(mcp, "hyperv_checkpoint_create",
                         {"vm_name": "test-vm", "checkpoint_name": "bravo",
                          "idempotency_key": "k-1"})
        assert conflict.get("error_class") == "idempotency_conflict", (
            f"AC10: reusing the key with different arguments must refuse with "
            f"error_class 'idempotency_conflict'; got {json.dumps(conflict)[:300]}"
        )
        assert fake.total() == runs_before, (
            "AC10: the refused call must run no PowerShell"
        )
        assert fake.count("Checkpoint-VM") == 1, (
            f"AC10: exactly one Checkpoint-VM (the first call's) may have "
            f"run; got {fake.count('Checkpoint-VM')}"
        )
    finally:
        auth_context_var.reset(token)

    token = _as_agent("agent-b")
    try:
        independent = _call(mcp, "hyperv_checkpoint_create",
                            {"vm_name": "test-vm", "checkpoint_name": "charlie",
                             "idempotency_key": "k-1"})
        assert independent.get("status") == "created", (
            f"AC10: the same key under a different agent is an independent "
            f"key and must run; got {json.dumps(independent)[:300]}"
        )
        assert fake.count("Checkpoint-VM") == 2, (
            f"AC10: agent b's keyed call must have run its own Checkpoint-VM; "
            f"total runs {fake.count('Checkpoint-VM')}"
        )
    finally:
        auth_context_var.reset(token)
        mount.close()


# ---------------------------------------------------------------------------
# AC11 — no credential or script canaries at rest, in any db sibling file
# ---------------------------------------------------------------------------


PASSWORD_CANARY = "S3cret-canary-pass"
SCRIPT_CANARY = "Arg-canary-77"


def test_persisted_operation_rows_hold_no_secrets(tmp_path, fresh_server, monkeypatch):
    """AC11: a detached hyperv_guest_run_ps in inline-credential mode with
    password 'S3cret-canary-pass' and a script containing 'Arg-canary-77'
    completes; neither canary (UTF-8 or UTF-16-LE) appears in the database
    file or its -wal / -shm siblings. RED at base, GREEN after the fix."""
    mod = _boot(tmp_path, fresh_server, INLINE_CRED_DOC)
    mount = ClockStoreMount(monkeypatch, str(tmp_path / "state.db"), FakeClock())
    fake = GatedFakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    token = _as_agent("agent-a")
    try:
        op_id = _detach(
            mcp, "hyperv_guest_run_ps",
            {"vm_name": "test-vm", "script": f"Write-Output {SCRIPT_CANARY}",
             "username": "Administrator", "password": PASSWORD_CANARY,
             "detach": True},
            "AC11",
        )
        _poll_status(mcp, op_id, {"completed"}, "AC11")
    finally:
        auth_context_var.reset(token)

    # Flush WAL content into the scan regardless of checkpoint timing: close
    # every handle, then read the db and every sibling as raw bytes.
    statestore.clear_store_cache_for_tests()
    mount.close()
    db = Path(tmp_path) / "state.db"
    blobs = {}
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = Path(str(db) + suffix)
        if path.exists():
            blobs[suffix or ".db"] = path.read_bytes()
    assert blobs, "AC11: no state database file was found to scan"
    for name, blob in blobs.items():
        for canary in (PASSWORD_CANARY, SCRIPT_CANARY):
            for encoding in ("utf-8", "utf-16-le"):
                assert canary.encode(encoding) not in blob, (
                    f"AC11: the {encoding} {canary[:12]}... canary is "
                    f"readable in the store file {name}"
                )
