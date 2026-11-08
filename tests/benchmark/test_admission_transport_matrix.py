"""Issue #68 supplement AC6 (workstream C) — admission transport matrix.

HOST_ONLY, UNEXECUTED by default: this is the named harness the issue's
approval row reserves for the live transport leg (the plan-critic round-1
finding-8 substitution; the companion evidence placeholder is
docs/validation/capability-plan/test_admission_transport_matrix-evidence.json).
It never presents as a live pass: without the env gates below the test
SKIPS at its first line (the gate check runs INSIDE the test, not at
collection — a default run reports the skip, never a pass), the
issue-#29 AC18 HOST_ONLY precedent.

What the harness measures once an operator points it at a configured,
disposable lab over the CONFIGURED MCP TRANSPORT (the streamable-http
endpoint the deployment actually runs):

  - topology axis — SHARED-VM fan-in (concurrent callers interleaving
    raw-input and read calls on ONE VM, the actor-stage shape) vs
    INDEPENDENT-VM fan-out (each caller on its own VM, the general-lane
    plus per-VM actor shape);
  - latency — p50/p95 per tool call, measured client-side from
    tools/call dispatch to the result;
  - queue wait — the server-reported admission park wait per call
    (audit ``admission_wait_ms``, read from the audit sink the operator
    names; each summary row carries the per-tool ``queue_wait_ms.<tool>``
    lists PLUS the bare ``queue_wait_ms`` aggregate — the max across
    tools — so the value pastes straight into the evidence file's field);
  - throughput — completed calls per second at the configured
    concurrency;
  - busy-refusal rate — the share of calls answered with a retryable
    ``busy`` envelope;
  - per-VM fairness — per-VM completion counts and mean client latency
    under saturation (a starved VM shows ~0 completions while another
    drains).

Running it (operator, disposable host only):

    HYPERV_MCP_ADMISSION_MATRIX=1 \
    HYPERV_MCP_MATRIX_URL=http://127.0.0.1:8787/mcp \
    HYPERV_MCP_MATRIX_SHARED_VM=matrix-shared \
    HYPERV_MCP_MATRIX_VMS=matrix-a,matrix-b \
    HYPERV_MCP_MATRIX_AUDIT=C:/lab/audit.jsonl \
    ./.venv/Scripts/python.exe -m pytest tests/benchmark/test_admission_transport_matrix.py -q

Setting the gate env var is the operator's assertion that the target host
is disposable and the run is sanctioned (raw input is typed into the named
VMs' consoles). Summary rows append to the JSONL sink named by
HYPERV_MCP_MATRIX_SINK so the numbers paste straight into the evidence
file's required-when-run fields.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

#: The HOST_ONLY gate (the issue-#29 AC18 env-gated-skip precedent): the
#: named lab flag. Absent -> every leg here skips; nothing in CI or a
#: default checkout can present this harness's numbers as a live pass.
GATE_ENV = "HYPERV_MCP_ADMISSION_MATRIX"
#: The configured MCP transport endpoint (streamable-http URL).
URL_ENV = "HYPERV_MCP_MATRIX_URL"
#: The ONE VM the shared-vm topology fans raw input onto.
SHARED_VM_ENV = "HYPERV_MCP_MATRIX_SHARED_VM"
#: The comma-separated per-caller VMs of the independent-vm topology.
VMS_ENV = "HYPERV_MCP_MATRIX_VMS"
#: The server's JSONL audit sink, for the server-side queue-wait axis.
AUDIT_ENV = "HYPERV_MCP_MATRIX_AUDIT"
#: Optional JSONL sink for the collected summary rows (stdout otherwise).
SINK_ENV = "HYPERV_MCP_MATRIX_SINK"

#: Scenario axes the matrix covers (plan F7): the shared-VM fan-in shape
#: exercises the actor stage (raw-input serialization plus LIGHT reads
#: progressing while the actor queue parks); the independent-VM fan-out
#: shape exercises the general lane, the fair queue, and per-VM actor keys.
TOPOLOGIES = ("shared-vm", "independent-vm")

RAW_INPUT_TOOL = "hyperv_console_type_text"
LIGHT_TOOL = "hyperv_list_vms"


def _gate() -> None:
    """The HOST_ONLY gate (the issue-#29 AC18 env-gated-skip precedent) —
    validates EVERY matrix env before the run can start: the two topology
    legs share one test, so a malformed independent-VM list discovered
    only at its leg would arrive AFTER the shared-VM leg had already
    driven raw input for the full duration (PR #123 review PRR-017)."""
    if not os.environ.get(GATE_ENV, "").strip():
        pytest.skip(
            f"HOST_ONLY: set {GATE_ENV}=1 against a configured, disposable, "
            "operator-approved lab to run the admission transport matrix "
            "(issue #68 supplement AC6; never a live pass by default)"
        )
    if not os.environ.get(URL_ENV, "").strip():
        pytest.skip(
            f"HOST_ONLY: {GATE_ENV} is set but {URL_ENV} does not name the "
            "configured MCP transport endpoint"
        )
    if not os.environ.get(SHARED_VM_ENV, "").strip():
        pytest.skip(
            f"HOST_ONLY: {GATE_ENV} is set but {SHARED_VM_ENV} does not name "
            "the one disposable VM the shared-vm topology fans raw input onto"
        )
    vms_raw = os.environ.get(VMS_ENV, "")
    vms = [name.strip() for name in vms_raw.split(",")]
    if not vms_raw.strip() or any(not name for name in vms):
        pytest.skip(
            f"HOST_ONLY: {GATE_ENV} is set but {VMS_ENV} is not a non-empty "
            f"comma-separated list of disposable VM names with no blank "
            f"entry (got {vms_raw!r})"
        )


@dataclass
class CallRecord:
    """One measured client-side call."""

    vm: str
    tool: str
    started_s: float
    ended_s: float
    ok: bool
    error_class: str = ""


@dataclass
class MatrixRun:
    """The collector for one matrix leg: every axis the evidence file's
    required-when-run fields name (p50/p95, queue wait, throughput,
    busy-refusal rate, per-VM fairness)."""

    topology: str
    concurrency: int
    duration_s: float
    records: list[CallRecord] = field(default_factory=list)

    def latencies_ms(self) -> list[float]:
        return sorted((r.ended_s - r.started_s) * 1000.0 for r in self.records)

    def percentile(self, fraction: float) -> float:
        latencies = self.latencies_ms()
        if not latencies:
            return float("nan")
        return latencies[min(len(latencies) - 1, int(fraction * len(latencies)))]

    def p50_ms(self) -> float:
        return self.percentile(0.50)

    def p95_ms(self) -> float:
        return self.percentile(0.95)

    def throughput_per_s(self) -> float:
        return len(self.records) / self.duration_s if self.duration_s else 0.0

    def busy_refusal_rate(self) -> float:
        """The share of calls the bounded admit refused retryable-busy
        (named for what it counts — the driver never cancels anything;
        PR #123 review PRR-014)."""
        if not self.records:
            return float("nan")
        refused = sum(1 for r in self.records if r.error_class == "busy")
        return refused / len(self.records)

    def per_vm_fairness(self) -> dict[str, dict[str, float]]:
        """Per-VM completion counts and mean client latency: the spread a
        starved lane would show (one VM at ~0 completions while another
        drains)."""
        by_vm: dict[str, list[CallRecord]] = {}
        for record in self.records:
            if record.ok:
                by_vm.setdefault(record.vm, []).append(record)
        spread: dict[str, dict[str, float]] = {}
        for vm, rows in by_vm.items():
            spread[vm] = {
                "completed": float(len(rows)),
                "mean_latency_ms": sum(
                    (r.ended_s - r.started_s) * 1000.0 for r in rows
                ) / len(rows),
            }
        return spread

    def summary(self) -> dict[str, object]:
        return {
            "topology": self.topology,
            "concurrency": self.concurrency,
            "duration_s": self.duration_s,
            "calls": len(self.records),
            "p50_ms": self.p50_ms(),
            "p95_ms": self.p95_ms(),
            "throughput_per_s": self.throughput_per_s(),
            "busy_refusal_rate": self.busy_refusal_rate(),
            "per_vm_fairness": self.per_vm_fairness(),
        }


def audit_queue_waits_ms(audit_path: Path, tool: str) -> list[float]:
    """The server-reported admission park waits (audit admission_wait_ms)
    for one tool, from the controller's JSONL audit sink: the queue-wait
    axis of the matrix."""
    if not audit_path.exists():
        return []
    waits: list[float] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or tool not in line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        wait = row.get("admission_wait_ms")
        if isinstance(wait, (int, float)):
            waits.append(float(wait))
    return waits


def emit_row(row: dict[str, object]) -> None:
    """Append one summary to the operator's sink (or stdout) so a run's
    numbers paste into the evidence file's required-when-run fields
    without transcription."""
    line = json.dumps(row, default=str)
    sink = os.environ.get(SINK_ENV, "").strip()
    if sink:
        with open(sink, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    else:
        print(line)


def _result_envelope(result) -> dict:
    """The first JSON text block of a CallToolResult ({} when absent)."""
    texts = [
        block.text
        for block in (result.content or [])
        if getattr(block, "type", "") == "text"
    ]
    if not texts:
        return {}
    try:
        payload = json.loads(texts[0])
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _shared_vms() -> tuple[str, ...]:
    shared = os.environ.get(SHARED_VM_ENV, "").strip()
    if shared:
        return (shared,)
    pytest.skip(
        f"HOST_ONLY: the shared-vm topology needs {SHARED_VM_ENV} naming "
        "the one disposable VM every caller fans raw input onto"
    )


def _independent_vms() -> tuple[str, ...]:
    names = tuple(
        name.strip()
        for name in os.environ.get(VMS_ENV, "").split(",")
        if name.strip()
    )
    if not names:
        pytest.skip(
            f"HOST_ONLY: the independent-vm topology needs {VMS_ENV} naming "
            "one disposable VM per concurrent caller"
        )
    return names


async def _call_once(session, tool: str, args: dict, vm: str, run: MatrixRun):
    started = time.monotonic()
    ok = False
    error_class = ""
    try:
        result = await asyncio.wait_for(
            session.call_tool(tool, dict(args)), timeout=120.0
        )
        envelope = _result_envelope(result)
        ok = bool(envelope.get("ok", not getattr(result, "is_error", False)))
        error_class = str(envelope.get("error_class") or "")
    except Exception as exc:  # noqa: BLE001 - one failed call is a record
        error_class = type(exc).__name__
    finally:
        run.records.append(CallRecord(
            vm=vm, tool=tool, started_s=started, ended_s=time.monotonic(),
            ok=ok, error_class=error_class,
        ))


async def _drive(session, run: MatrixRun, vms: tuple[str, ...]) -> None:
    """One matrix leg: concurrent callers alternate the raw-input tool on
    their topology's VM(s) with LIGHT reads until the duration elapses."""
    deadline = time.monotonic() + run.duration_s

    async def _caller(slot: int) -> None:
        flip = 0
        while time.monotonic() < deadline:
            vm = vms[slot % len(vms)]
            if flip % 2 == 0:
                await _call_once(
                    session, RAW_INPUT_TOOL,
                    {"vm_name": vm, "text": "m"}, vm, run)
            else:
                await _call_once(session, LIGHT_TOOL, {}, "", run)
            flip += 1

    # anyio task group (not asyncio.TaskGroup) so the harness also runs on
    # the 3.10 floor the package declares.
    async with anyio.create_task_group() as group:
        for slot in range(run.concurrency):
            group.start_soon(_caller, slot)


def test_admission_transport_matrix_host_only():
    """The matrix driver (issue #68 supplement AC6): shared-VM vs
    independent-VM topology at the configured concurrency, collecting
    p50/p95 latency, throughput, busy-refusal rate, and per-VM fairness
    over the configured MCP transport, plus the server-side queue-wait
    axis from the audit sink (per-tool lists + the bare max aggregate, so
    a run's rows paste straight into the evidence file's fields). SKIPS
    unless the named lab env gates are set — this harness's numbers are
    never produced by a default run."""
    _gate()
    url = os.environ[URL_ENV].strip()
    concurrency = int(os.environ.get("HYPERV_MCP_MATRIX_CONCURRENCY", "4"))
    duration_s = float(os.environ.get("HYPERV_MCP_MATRIX_DURATION_S", "30"))
    audit_path = Path(os.environ.get(AUDIT_ENV, "").strip())

    async def _matrix() -> None:
        async with streamable_http_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for topology in TOPOLOGIES:
                    vms = (
                        _shared_vms()
                        if topology == "shared-vm"
                        else _independent_vms()
                    )
                    run = MatrixRun(
                        topology=topology,
                        concurrency=concurrency,
                        duration_s=duration_s,
                    )
                    await _drive(session, run, vms)
                    row = run.summary()
                    if audit_path != Path(""):
                        per_tool_waits = {
                            tool: audit_queue_waits_ms(audit_path, tool)
                            for tool in (RAW_INPUT_TOOL, LIGHT_TOOL)
                        }
                        for tool, waits in per_tool_waits.items():
                            if waits:
                                row[f"queue_wait_ms.{tool}"] = waits
                        # The BARE aggregate (PR #123 review PRR-013): the
                        # worst observed park wait across tools, so the
                        # evidence file's queue_wait_ms field pastes
                        # straight from this row.
                        flat = [w for waits in per_tool_waits.values() for w in waits]
                        if flat:
                            row["queue_wait_ms"] = max(flat)
                    emit_row(row)

    asyncio.run(_matrix())
