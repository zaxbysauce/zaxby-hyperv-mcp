"""Frozen acceptance checks for trace D-04: the per-call timing breakdown.

The contract under check: a contextvar-held per-call collector in
``hyperv_mcp.timing`` gives every audit record (and the screenshot metadata
sidecar) a ``timing`` object — ``lock_wait_ms`` / ``ps_ms`` / ``ps_spawns`` /
``total_ms`` everywhere, plus ``ps_startup_ms`` / ``psdirect_session_ms`` /
``guest_ms`` on guest-tool records (None when the script emitted no marker);
each concurrent call keeps its own collector, sequential calls never
accumulate, failed and rejected operations still write their timing, the
PowerShell ``__MCP_TIMING=`` marker is stripped from stdout and numeric-only,
and ``scripts/soak_bench.py`` summarizes samples off the same nearest-rank
engine ``consolebench.pct`` uses.

RED at base 454efde1356c3bafa9d47a2d3c8f07282d8e84cd, GREEN after the fix.
No real PowerShell child, Hyper-V host, network or credential is touched:
every PowerShell leg is served by a fake (a counting ``run_ps`` stand-in, or
a scripted fake child under the real ``run_ps`` for the marker-protocol
checks).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import importlib
import io
import json
import sys
import threading
import time
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import auditlog, consolebench, pswindows
from hyperv_mcp.config import Config

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
BASE_TIMING_KEYS = {"lock_wait_ms", "ps_ms", "ps_spawns", "total_ms"}
MARKER_KEYS = ("ps_startup_ms", "psdirect_session_ms", "guest_ms")


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


def _capture_payload(w: int, h: int) -> str:
    """A size-correct GetVirtualSystemThumbnailImage JSON payload."""
    raw = b"\x00" * (w * h * 2 + 4)
    return json.dumps({"returnValue": 0, "imageDataB64": base64.b64encode(raw).decode()})


class FakeTimingPS:
    """pswindows.run_ps stand-in.

    Classifies each leg by script shape (by-id resolver, by-name resolver,
    PowerShell-Direct guest leg, folded screenshot, console input op, or the
    generic read leg), serves that leg's protocol response with a KNOWN
    duration_ms, and records — globally and per calling thread — the call
    count and the summed duration it actually served. Those counters are the
    oracle the timing assertions below derive their expected values from;
    no expected spawn count is hardcoded anywhere in this file.
    """

    DEFAULT_MS = 10

    def __init__(self, durations: dict[str, int] | None = None, sleep_s: float = 0.0):
        self.durations = dict(durations or {})
        self.sleep_s = sleep_s
        self.calls = 0
        self.total_ms = 0
        self.by_thread: dict[int, dict] = {}
        self._lock = threading.Lock()

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        leg = self._classify(script)
        duration = int(self.durations.get(leg, self.DEFAULT_MS))
        if self.sleep_s:
            time.sleep(self.sleep_s)
        ident = threading.get_ident()
        with self._lock:
            self.calls += 1
            self.total_ms += duration
            bucket = self.by_thread.setdefault(ident, {"calls": 0, "ms": 0, "legs": []})
            bucket["calls"] = bucket["calls"] + 1
            bucket["ms"] = bucket["ms"] + duration
            bucket["legs"].append(leg)
        return self._serve(leg, duration)

    def _classify(self, script: str) -> str:
        s = script.strip()
        if "Get-VM -Id $vmTarget" in s and s.endswith("$vm.Name"):
            return "resolve_id"
        if "Msvm_ComputerSystem" in s and s.endswith("$vmTarget"):
            return "resolve_name"
        if "Invoke-Command -VMId" in s:
            return "guest"
        if "GetVirtualSystemThumbnailImage" in s:
            return "capture"
        if any(
            marker in s
            for marker in (
                "SetScrollPosition", "SetButtonState", "SetAbsolutePosition",
                "ClickButton", "TypeText", "TypeScancodes",
            )
        ):
            return "input"
        return "list"

    def _serve(self, leg: str, duration: int) -> pswindows.PSResult:
        if leg == "resolve_id":
            stdout = "test-vm-a"
        elif leg == "resolve_name":
            stdout = GUID
        elif leg == "guest":
            stdout = json.dumps({"exit_code": 0, "stdout": "guest-ok", "stderr": ""})
        elif leg == "capture":
            stdout = (
                f"VMID={GUID}\nSIZES=160x160,640x480,320x240\nUSED=160x160\n"
                + _capture_payload(160, 160)
            )
        elif leg == "input":
            stdout = "RC=0"
        else:
            stdout = ""
        return pswindows.PSResult(stdout=stdout, returncode=0, duration_ms=duration)


class _ScriptedChild:
    """subprocess.Popen stand-in (the test_a01 fake-child pattern): serves one
    scripted stdout payload; nothing really executes."""

    pid = 4242
    _handle = 0
    returncode = 0

    def __init__(self, stdout_b: bytes) -> None:
        self._stdout_b = stdout_b

    def communicate(self, input=None, timeout=None):
        return self._stdout_b, b""

    def kill(self):
        return None


def _serve_child_stdout(monkeypatch, payloads: list[bytes]) -> None:
    """Run the REAL pswindows.run_ps against scripted child stdout: each spawn
    pops the next payload, so the __MCP_TIMING marker protocol flows through
    run_ps exactly the way a real PowerShell child's output would."""
    queue = list(payloads)

    def fake_popen(argv, *args, **kwargs):
        assert queue, "unexpected extra PowerShell spawn"
        return _ScriptedChild(queue.pop(0))

    monkeypatch.setattr(pswindows.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(pswindows, "_make_kill_on_close_job", lambda: None)
    monkeypatch.setattr(pswindows, "_resume_process", lambda pid: True)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


@pytest.fixture()
def audited_server(tmp_path, fresh_server):
    """A bootstrapped server whose audit sink is a tmp JSONL file: test-* VMs
    allowed, console_input destructive category enabled."""
    log = tmp_path / "audit-d04.jsonl"
    doc = {
        "allowed_vm_patterns": ["test-*"],
        "audit_log_path": str(log),
        "destructive": {"console_input": True},
    }
    p = tmp_path / "d04-config.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    return mod, log


def _rows(log) -> list[dict]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _newest(rows, tool: str) -> dict:
    matching = [r for r in rows if r.get("tool") == tool]
    assert matching, f"no audit row was written for {tool}"
    return matching[-1]


def _texts(result) -> list[str]:
    from conftest import content_blocks

    return [c.text for c in content_blocks(result) if getattr(c, "type", "") == "text"]


def _envelope(result) -> dict:
    texts = _texts(result)
    assert texts, "expected a JSON text envelope"
    return json.loads(texts[0])


def _guest_env(monkeypatch):
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "d04-unit-pass")


# ---------------------------------------------------------------------------
# AC1: screenshot metadata timing breakdown
# ---------------------------------------------------------------------------


def test_screenshot_meta_reports_timing_breakdown(audited_server, monkeypatch):
    """AC1: the screenshot metadata sidecar carries a timing breakdown whose
    ps_spawns/ps_ms equal the run_ps call count and duration sum the transport
    actually served. RED at base, GREEN after the fix."""
    mod, _log = audited_server
    fake = FakeTimingPS(durations={"resolve_id": 400, "capture": 500})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    result = asyncio.run(mcp.call_tool(
        "hyperv_console_screenshot", {"vm_id": GUID, "width": 160, "height": 160},
    ))
    assert fake.calls == 2, (
        f"expected the by-id resolve leg plus the capture leg, got {fake.calls} run_ps calls"
    )
    meta = json.loads(_texts(result)[0])
    assert "timing" in meta, "AC1: screenshot metadata carries no timing breakdown"
    timing = meta["timing"]
    assert timing["ps_spawns"] == fake.calls, (
        f"timing.ps_spawns {timing.get('ps_spawns')!r} != the {fake.calls} run_ps calls "
        f"the transport served"
    )
    assert timing["ps_ms"] == fake.total_ms, (
        f"timing.ps_ms {timing.get('ps_ms')!r} != the {fake.total_ms} ms the transport served"
    )


# ---------------------------------------------------------------------------
# AC2/AC3: audit rows carry the per-call counters
# ---------------------------------------------------------------------------


def test_audit_record_carries_timing_for_console_tool(audited_server, monkeypatch):
    """AC2: the console input tool's audit row carries timing.ps_spawns equal
    to the run_ps call count the transport served. RED at base, GREEN after
    the fix."""
    mod, log = audited_server
    fake = FakeTimingPS(durations={"input": 220})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    envelope = _envelope(asyncio.run(mcp.call_tool(
        "hyperv_console_scroll", {"vm_name": "test-vm-a", "delta": 1},
    )))
    assert envelope.get("ok") is True, f"console scroll failed: {envelope}"
    row = _newest(_rows(log), "hyperv_console_scroll")
    timing = row.get("timing")
    assert isinstance(timing, dict) and "ps_spawns" in timing, (
        "AC2: no timing.ps_spawns in the audit record"
    )
    assert timing["ps_spawns"] == fake.calls, (
        f"audit timing.ps_spawns {timing['ps_spawns']!r} != the {fake.calls} run_ps calls "
        f"the transport served"
    )


def test_audit_record_carries_timing_for_guest_tool(audited_server, monkeypatch):
    """AC3: the guest tool's audit row carries timing.ps_ms equal to the sum
    of the run_ps durations the transport served. RED at base, GREEN after
    the fix."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    fake = FakeTimingPS(durations={"resolve_name": 300, "guest": 2500})
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    envelope = _envelope(asyncio.run(mcp.call_tool(
        "hyperv_guest_run_ps", {"vm_name": "test-vm-a", "script": "Write-Output ok"},
    )))
    assert envelope.get("ok") is True, f"guest run failed: {envelope}"
    assert fake.calls == 2, (
        f"expected the resolve leg plus the guest leg, got {fake.calls} run_ps calls"
    )
    row = _newest(_rows(log), "hyperv_guest_run_ps")
    timing = row.get("timing")
    assert isinstance(timing, dict) and "ps_ms" in timing, (
        "AC3: no timing.ps_ms in the audit record"
    )
    assert timing["ps_ms"] == fake.total_ms, (
        f"audit timing.ps_ms {timing['ps_ms']!r} != the {fake.total_ms} ms the transport served"
    )


# ---------------------------------------------------------------------------
# AC4: lock_wait_ms / total_ms on every row
# ---------------------------------------------------------------------------


def test_audit_timing_has_lock_wait_and_total(audited_server, monkeypatch):
    """AC4: an audit row's timing carries lock_wait_ms, ps_ms, ps_spawns and
    total_ms; an uncontended call reports lock_wait_ms == 0 and total_ms an
    int >= 0. RED at base, GREEN after the fix."""
    mod, log = audited_server
    monkeypatch.setattr(pswindows, "run_ps", FakeTimingPS())
    mcp = mod.get_mcp()

    asyncio.run(mcp.call_tool("hyperv_list_vms", {}))
    row = _newest(_rows(log), "hyperv_list_vms")
    missing = BASE_TIMING_KEYS - set(row.get("timing") or {})
    assert missing == set(), (
        "AC4: audit timing is missing " + ", ".join(sorted(missing))
    )
    timing = row["timing"]
    assert timing["lock_wait_ms"] == 0, (
        f"an uncontended read reported lock_wait_ms {timing['lock_wait_ms']!r}"
    )
    assert type(timing["total_ms"]) is int, (
        f"total_ms must be an int, got {timing['total_ms']!r}"
    )
    assert timing["total_ms"] >= 0


# ---------------------------------------------------------------------------
# AC5: the guest marker trio, present with markers and None without
# ---------------------------------------------------------------------------


def test_guest_timing_separates_psdirect_session_setup(audited_server, monkeypatch):
    """AC5: a guest-leg script that emits the __MCP_TIMING marker gets its
    ps_startup_ms/psdirect_session_ms/guest_ms into the audit timing with the
    marker's numeric values; a marker-less script reports all three as None.
    The marker rides the REAL run_ps (a scripted fake child under a patched
    Popen), so it reaches the collector the way the real protocol does.
    RED at base, GREEN after the fix."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    marker = '__MCP_TIMING={"ps_startup_ms":120,"psdirect_session_ms":340,"guest_ms":900}'
    guest_with_marker = (
        b'{"exit_code":0,"stdout":"marker-leg","stderr":""}\n' + marker.encode() + b"\n"
    )
    guest_plain = b'{"exit_code":0,"stdout":"plain-leg","stderr":""}\n'
    _serve_child_stdout(
        monkeypatch,
        [GUID.encode(), guest_with_marker, GUID.encode(), guest_plain],
    )
    mcp = mod.get_mcp()

    first = asyncio.run(mcp.call_tool(
        "hyperv_guest_run_ps", {"vm_name": "test-vm-a", "script": "Write-Output one"},
    ))
    row1 = _newest(_rows(log), "hyperv_guest_run_ps")
    timing = row1.get("timing") or {}
    assert all(key in timing for key in MARKER_KEYS), (
        "AC5: audit timing is missing guest_ms, ps_startup_ms, psdirect_session_ms"
    )
    assert (
        timing["ps_startup_ms"], timing["psdirect_session_ms"], timing["guest_ms"]
    ) == (120, 340, 900), f"marker values did not reach the audit timing: {timing}"
    assert _envelope(first).get("ok") is True, (
        "the marker line was not stripped before the tool saw its guest stdout"
    )

    asyncio.run(mcp.call_tool(
        "hyperv_guest_run_ps", {"vm_name": "test-vm-a", "script": "Write-Output two"},
    ))
    row2 = _newest(_rows(log), "hyperv_guest_run_ps")
    timing2 = row2.get("timing") or {}
    for key in MARKER_KEYS:
        assert key in timing2 and timing2[key] is None, (
            f"a marker-less script must report {key}=None, got {timing2.get(key)!r}"
        )


# ---------------------------------------------------------------------------
# AC6: concurrent calls each get their own collector
# ---------------------------------------------------------------------------


def test_concurrent_calls_get_their_own_timing(audited_server, monkeypatch):
    """AC6: two REAL threads driving different VMs' tools through one server
    object each get an audit row whose timing.ps_spawns/ps_ms equal the calls
    and durations the fake run_ps recorded FOR THAT THREAD. RED at base,
    GREEN after the fix."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    fake = FakeTimingPS(
        durations={"input": 250, "resolve_name": 250, "guest": 250}, sleep_s=0.2,
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    outcomes: dict[str, object] = {}

    def console_call() -> None:
        try:
            outcomes["scroll"] = asyncio.run(mcp.call_tool(
                "hyperv_console_scroll", {"vm_name": "test-vm-a", "delta": 1},
            ))
        except Exception as exc:  # recorded and asserted below
            outcomes["scroll"] = exc

    def guest_call() -> None:
        try:
            outcomes["guest"] = asyncio.run(mcp.call_tool(
                "hyperv_guest_run_ps", {"vm_name": "test-vm-b", "script": "Write-Output ok"},
            ))
        except Exception as exc:  # recorded and asserted below
            outcomes["guest"] = exc

    threads = [
        threading.Thread(target=console_call, name="d04-console"),
        threading.Thread(target=guest_call, name="d04-guest"),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), (
        "a concurrent tool call did not finish within 30 s"
    )
    for name, value in outcomes.items():
        assert not isinstance(value, Exception), f"the {name} thread raised: {value!r}"

    rows = _rows(log)
    scroll_row = _newest(rows, "hyperv_console_scroll")
    guest_row = _newest(rows, "hyperv_guest_run_ps")
    assert isinstance(scroll_row.get("timing"), dict) and isinstance(
        guest_row.get("timing"), dict
    ), "AC6: concurrent calls did not get their own timing"

    scroll_idents = [i for i, b in fake.by_thread.items() if "input" in b["legs"]]
    guest_idents = [i for i, b in fake.by_thread.items() if "guest" in b["legs"]]
    assert len(scroll_idents) == 1 and len(guest_idents) == 1, (
        f"thread leg bookkeeping is ambiguous: {fake.by_thread}"
    )
    assert scroll_idents[0] != guest_idents[0], (
        "the two concurrent calls serialized onto one thread"
    )
    scroll_bucket = fake.by_thread[scroll_idents[0]]
    guest_bucket = fake.by_thread[guest_idents[0]]
    assert scroll_row["timing"]["ps_spawns"] == scroll_bucket["calls"], (
        f"console row timing.ps_spawns {scroll_row['timing']['ps_spawns']!r} != that "
        f"thread's {scroll_bucket['calls']} served calls"
    )
    assert scroll_row["timing"]["ps_ms"] == scroll_bucket["ms"], (
        f"console row timing.ps_ms {scroll_row['timing']['ps_ms']!r} != that "
        f"thread's {scroll_bucket['ms']} served ms"
    )
    assert guest_row["timing"]["ps_spawns"] == guest_bucket["calls"], (
        f"guest row timing.ps_spawns {guest_row['timing']['ps_spawns']!r} != that "
        f"thread's {guest_bucket['calls']} served calls"
    )
    assert guest_row["timing"]["ps_ms"] == guest_bucket["ms"], (
        f"guest row timing.ps_ms {guest_row['timing']['ps_ms']!r} != that "
        f"thread's {guest_bucket['ms']} served ms"
    )


# ---------------------------------------------------------------------------
# AC7/AC8: scripts/soak_bench.py
# ---------------------------------------------------------------------------


def _import_soak_bench():
    """Insert the repo's scripts/ dir on sys.path and import soak_bench.
    At base the module does not exist and the ModuleNotFoundError IS the
    frozen signature — it is never caught here (the finally only un-does the
    sys.path edit)."""
    scripts_dir = str(Path(__file__).resolve().parents[2] / "scripts")
    sys.path.insert(0, scripts_dir)
    try:
        import soak_bench
    finally:
        sys.path.remove(scripts_dir)
    return soak_bench


def test_soak_bench_summarizes_percentiles():
    """AC7: summarize() reports nearest-rank p50/p95/p99 over the ok samples
    only, busy_rate/incorrect_rate over ALL samples, agreeing with
    consolebench.pct. RED at base, GREEN after the fix."""
    soak_bench = _import_soak_bench()

    samples = [{"ok": True, "ms": float(ms)} for ms in range(1, 101)]
    samples.append({"ok": False, "busy": True, "ms": 1.0})
    samples.append({"ok": False, "incorrect": True, "ms": 1.0})
    summary = soak_bench.summarize(samples)
    assert summary["p50_ms"] == 50.0, f"p50_ms {summary.get('p50_ms')!r} != 50.0"
    assert summary["p95_ms"] == 95.0, f"p95_ms {summary.get('p95_ms')!r} != 95.0"
    assert summary["p99_ms"] == 99.0, f"p99_ms {summary.get('p99_ms')!r} != 99.0"
    assert summary["busy_rate"] == 1 / 102, (
        f"busy_rate {summary.get('busy_rate')!r} != 1/102 (counted over ALL samples)"
    )
    assert summary["incorrect_rate"] == 1 / 102, (
        f"incorrect_rate {summary.get('incorrect_rate')!r} != 1/102 (counted over ALL samples)"
    )
    pool = [float(ms) for ms in range(1, 101)]
    for q, key in ((0.50, "p50_ms"), (0.95, "p95_ms"), (0.99, "p99_ms")):
        assert summary[key] == consolebench.pct(pool, q), (
            f"{key} drifted from the shared nearest-rank engine consolebench.pct"
        )


def test_soak_bench_fake_mode_reports_each_agent_count():
    """AC8: soak_bench --fake --agents 1,4,8 --iterations 3 --json exits 0 and
    prints exactly one JSON row per agent count, each carrying p50_ms/p95_ms/
    p99_ms/busy_rate/incorrect_rate. RED at base, GREEN after the fix."""
    soak_bench = _import_soak_bench()

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = soak_bench.main(
            ["--fake", "--agents", "1,4,8", "--iterations", "3", "--json"]
        )
    assert rc == 0, f"soak_bench --fake exited {rc}"
    rows = [
        json.loads(line)
        for line in buffer.getvalue().splitlines()
        if line.strip().startswith("{")
    ]
    assert len(rows) == 3, (
        f"expected one JSON row per agent count, got {len(rows)}: {buffer.getvalue()!r}"
    )
    assert sorted(row["agents"] for row in rows) == [1, 4, 8], (
        f"agent counts {sorted(row['agents'] for row in rows)} != [1, 4, 8]"
    )
    for row in rows:
        for key in ("p50_ms", "p95_ms", "p99_ms", "busy_rate", "incorrect_rate"):
            assert key in row, f"the agents={row.get('agents')} row omits {key}"


# ---------------------------------------------------------------------------
# AC13/AC14: the audit-schema guardrail knows the new key and stays green
# ---------------------------------------------------------------------------


def test_audit_schema_guardrail_includes_timing():
    """AC13: the B01 audit-schema guardrail's expected key set includes the
    new timing key, so the class guardrail keeps pinning the full row shape.
    RED at base, GREEN after the fix."""
    import test_b01_audit_correlation_guardrail as b01

    assert "timing" in b01.AUDIT_KEYS, (
        "AC13: the audit schema guardrail's expected key set omits timing"
    )


def test_b01_guardrail_stays_green():
    """AC14: the B01 audit-schema guardrail test itself still passes over its
    four audited paths (anonymous read, two authenticated agents, pre-body
    rejection). It is DRIVEN as a child pytest process rather than frozen into
    this manifest, because the fix legitimately adds the new key to that file's
    expected set — freezing it would force a post-freeze AMEND for a
    strengthening edit. The key set itself is pinned by AC13 from this frozen
    file, so nothing about the guardrail escapes verification. GREEN at base,
    GREEN after the fix."""
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[2]
    node = (
        "tests/unit/test_b01_audit_correlation_guardrail.py"
        "::test_guardrail_every_audit_row_carries_full_correlation_key_set"
    )
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", node, "-q", "-p", "no:cacheprovider"],
        cwd=str(root),
        capture_output=True,
        text=True,
        # 90 s, not 300 (PRR-042): the suite-wide budget is 120 s (pyproject
        # timeout), so a 300 s child deadline was dead code — the parent test
        # would be killed first and this timeout could never fire. The child
        # deadline must sit strictly inside the parent's budget.
        timeout=90,
    )
    assert proc.returncode == 0, (
        f"AC14: the B01 audit-schema guardrail regressed\n"
        f"--- stdout ---\n{proc.stdout[-3000:]}\n--- stderr ---\n{proc.stderr[-3000:]}"
    )


# ---------------------------------------------------------------------------
# AC15: the marker is stripped from stdout and numeric-only
# ---------------------------------------------------------------------------


def test_timing_marker_is_stripped_and_numeric_only(monkeypatch, tmp_path):
    """AC15: run_ps strips the trailing __MCP_TIMING marker from the stdout
    any tool sees (the real output survives), and a NON-NUMERIC marker value
    never enters the timing object. Chosen behaviour, stated for the
    implementer: a non-numeric value is rejected — the field stays None in
    the audit record (not coerced, not carried as text) — so script text can
    never ride the marker into the audit log. RED at base, GREEN after the
    fix."""
    # (a) the marker never survives into the stdout a tool would parse
    pswindows.init(Config(max_output_bytes=1024 * 1024), lambda text: text)
    marker = '__MCP_TIMING={"ps_startup_ms":1,"psdirect_session_ms":2,"guest_ms":3}'
    _serve_child_stdout(
        monkeypatch, [b"some real output\n" + marker.encode() + b"\n"]
    )
    result = pswindows.run_ps("Write-Output 'marker-strip-probe'", timeout_s=30)
    assert result.ok(), result.stderr
    assert "__MCP_TIMING" not in result.stdout, (
        "AC15: the timing marker was not stripped from stdout"
    )
    assert "some real output" in result.stdout, "stripping ate the real stdout"

    # (b) a string marker value is rejected before it can reach the audit row
    log = tmp_path / "audit-d04-marker.jsonl"
    doc = {"allowed_vm_patterns": ["test-*"], "audit_log_path": str(log)}
    p = tmp_path / "d04-marker-config.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    try:
        _guest_env(monkeypatch)
        evil = (
            '__MCP_TIMING={"ps_startup_ms":"evil-script-text",'
            '"psdirect_session_ms":2,"guest_ms":3}'
        )
        guest = (
            b'{"exit_code":0,"stdout":"leg","stderr":""}\n' + evil.encode() + b"\n"
        )
        _serve_child_stdout(monkeypatch, [GUID.encode(), guest])
        mcp = mod.get_mcp()
        asyncio.run(mcp.call_tool(
            "hyperv_guest_run_ps", {"vm_name": "test-vm-a", "script": "probe"},
        ))
        rows = [r for r in _rows(log) if r["tool"] == "hyperv_guest_run_ps"]
        assert rows, "no audit row was written for the marker-injection probe"
        row = rows[-1]
        assert "evil-script-text" not in json.dumps(row), (
            "non-numeric marker text reached the audit record"
        )
        timing = row.get("timing") or {}
        assert timing.get("ps_startup_ms") is None, (
            f"a string marker value was accepted into the timing object: "
            f"{timing.get('ps_startup_ms')!r}"
        )
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC16: sequential calls never accumulate
# ---------------------------------------------------------------------------


def test_sequential_calls_do_not_accumulate(audited_server, monkeypatch):
    """AC16: a second audited operation's timing reflects only ITS OWN run_ps
    spawns and durations — never the sum of both operations. RED at base,
    GREEN after the fix."""
    mod, log = audited_server
    mcp = mod.get_mcp()

    first = FakeTimingPS(durations={"input": 400})
    monkeypatch.setattr(pswindows, "run_ps", first)
    asyncio.run(mcp.call_tool(
        "hyperv_console_scroll", {"vm_name": "test-vm-a", "delta": 1},
    ))

    second = FakeTimingPS(durations={"resolve_id": 100, "input": 150})
    monkeypatch.setattr(pswindows, "run_ps", second)
    asyncio.run(mcp.call_tool(
        "hyperv_console_scroll", {"vm_id": GUID, "delta": 1},
    ))

    scroll_rows = [r for r in _rows(log) if r["tool"] == "hyperv_console_scroll"]
    assert len(scroll_rows) == 2, f"expected two scroll rows, got {len(scroll_rows)}"
    row = scroll_rows[-1]
    timing = row.get("timing")
    assert isinstance(timing, dict) and "ps_spawns" in timing, (
        "AC16: the second operation inherited the first operation's timing"
    )
    assert timing["ps_spawns"] == second.calls, (
        f"the second operation's timing.ps_spawns {timing['ps_spawns']!r} counted earlier "
        f"operations (expected only this call's {second.calls} spawns)"
    )
    assert timing["ps_ms"] == second.total_ms, (
        f"the second operation's timing.ps_ms {timing['ps_ms']!r} accumulated earlier "
        f"operations (expected only this call's {second.total_ms} ms)"
    )


# ---------------------------------------------------------------------------
# AC17: a failed operation still writes its timing
# ---------------------------------------------------------------------------


def test_failed_operation_still_writes_timing(tmp_path, monkeypatch):
    """AC17: an operation whose body raises after a run_ps leg still writes
    its audit row — ok False — with the complete timing object. RED at base,
    GREEN after the fix."""
    log = tmp_path / "audit-d04-fail.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    fake = FakeTimingPS(durations={"list": 77})
    monkeypatch.setattr(pswindows, "run_ps", fake)

    with pytest.raises(RuntimeError, match="d04 boom"):
        with auditlog.operation(
            tool="d04-failure-probe", vm_name="d04-vm", category="read"
        ):
            pswindows.run_ps("Write-Output 'leg'", timeout_s=5)
            raise RuntimeError("d04 boom")

    rows = _rows(log)
    assert rows, "the failed operation wrote no audit row at all"
    row = rows[-1]
    timing = row.get("timing")
    assert isinstance(timing, dict) and BASE_TIMING_KEYS <= set(timing), (
        "AC17: a failed operation wrote no timing"
    )
    assert row["ok"] is False, "the operation must audit as failed"
    assert timing["ps_spawns"] == fake.calls == 1, (
        f"failed-op timing.ps_spawns {timing['ps_spawns']!r} != the 1 run_ps call served"
    )
    assert timing["ps_ms"] == fake.total_ms, (
        f"failed-op timing.ps_ms {timing['ps_ms']!r} != the {fake.total_ms} ms served"
    )


# ---------------------------------------------------------------------------
# AC18: a pre-body rejection writes zeroed timing
# ---------------------------------------------------------------------------


def test_rejection_record_carries_zero_timing(audited_server, monkeypatch):
    """AC18: a call rejected by the unknown-argument guard before any tool
    body runs still audits a timing object — ps_spawns 0, lock_wait_ms 0.
    RED at base, GREEN after the fix."""
    mod, log = audited_server
    fake = FakeTimingPS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()

    envelope = _envelope(asyncio.run(mcp.call_tool(
        "hyperv_list_vms", {"no_such_argument_d04": 1},
    )))
    assert envelope.get("ok") is False and envelope.get("error_class") == "invalid", (
        f"expected an invalid rejection envelope, got {envelope}"
    )
    rows = [r for r in _rows(log) if r["tool"] == "hyperv_list_vms" and r["ok"] is False]
    assert rows, "the rejected call wrote no audit row"
    row = rows[-1]
    timing = row.get("timing")
    assert isinstance(timing, dict) and BASE_TIMING_KEYS <= set(timing), (
        "AC18: a rejected call wrote no timing"
    )
    assert fake.calls == 0, "a rejected call must not have spawned anything"
    assert timing["ps_spawns"] == 0, (
        f"rejected-call timing.ps_spawns {timing['ps_spawns']!r} != 0"
    )
    assert timing["lock_wait_ms"] == 0, (
        f"rejected-call timing.lock_wait_ms {timing['lock_wait_ms']!r} != 0"
    )
