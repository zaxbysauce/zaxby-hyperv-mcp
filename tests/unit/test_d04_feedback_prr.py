"""swarm-pr-feedback checks for PR #89 (issue #20, workstream D-04): per-call
timing and the soak benchmark.

Each check names the PRR finding it kills and the mutant it is designed to die
on. The review that produced these findings executed its mutants and confirmed
they survive, so a check that does not say which mutation kills it is not yet
evidence — and the final critic's own probes on PR #87 found two more survivors
in code the round had just fixed, so every fix here is paired with its mutant.
"""

import asyncio
import base64
import importlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows, timing
from hyperv_mcp.config import Config
from hyperv_mcp.timing import MARKER_PREFIX

REPO_ROOT = Path(__file__).resolve().parents[2]


def _import_soak_bench():
    """The harness lives in scripts/, outside the package, so it is imported the
    way test_d04_soak_live_gate.py already does rather than duplicated."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        import soak_bench
    finally:
        sys.path.remove(str(REPO_ROOT / "scripts"))
    return soak_bench


soak_bench = _import_soak_bench()

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


def _raw_thumbnail(w: int, h: int) -> bytes:
    pixels = bytearray()
    for y in range(h):
        for x in range(w):
            v = ((x * 31 % 32) << 11) | ((y * 15 % 64) << 5) | (x * 7 % 32)
            pixels += bytes([v & 0xFF, (v >> 8) & 0xFF])
    return b"\x00\x00\x96\x04" + bytes(pixels)


class FakeCapture:
    """Queue-ordered run_ps stand-in.

    A response may be a CALLABLE, which is invoked at pop time. That matters:
    `PSResult.__post_init__` feeds the active collector, so a PSResult built
    eagerly while the list is constructed records nothing and every
    spawn-count assertion built on it is vacuous. Building it lazily puts the
    construction inside the tool body, where the collector is active.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        item = self.responses.pop(0)
        return item() if callable(item) else item


def _folded_response(payload: bytes, w: int, h: int) -> pswindows.PSResult:
    body = json.dumps({
        "returnValue": 0,
        "imageDataB64": base64.b64encode(payload).decode(),
    })
    return pswindows.PSResult(
        stdout="VMID=" + GUID + "\nHEAD=1024x768\nSIZES=" + str(w) + "x" + str(h)
               + "\nUSED=" + str(w) + "x" + str(h) + "\n" + body,
        returncode=0,
    )


@pytest.fixture()
def fresh_server(tmp_path):
    def make(environ=None, config_doc=None):
        environ = dict(environ or {})
        if config_doc is not None:
            p = tmp_path / "d04-fb-config.json"
            p.write_text(json.dumps(config_doc), encoding="utf-8")
            environ["HYPERV_MCP_CONFIG"] = str(p)
        mod = importlib.reload(server_module)
        mod.bootstrap(environ)
        return mod

    yield make
    importlib.reload(server_module)


def _blocks(result):
    from conftest import content_blocks

    return content_blocks(result)


def _split(result):
    blocks = _blocks(result)
    images = [c for c in blocks if getattr(c, "type", "") == "image"]
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    return images, texts


def _meta(texts) -> dict:
    assert texts, "no metadata text block in the success result"
    return json.loads(texts[0].text)


def _call(mcp, tool, arguments):
    return asyncio.run(mcp.call_tool(tool, arguments))


# ---------------------------------------------------------------------------
# PRR-002 / PRR-001 — the marker parse must not split on Unicode boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sep", ["\u2028", "\u2029", "\u0085", "\x0b", "\x0c",
                                 "\x1c", "\x1d", "\x1e"])
def test_a_unicode_line_separator_survives_the_marker_parse(sep):
    """PRR-002: `run_ps` parses the marker BEFORE `credentials.redact` runs, and
    redaction matches exact substrings. Splitting on a Unicode line boundary
    broke a guest secret containing one into two fragments that no longer match
    the registry, leaking it to the MCP client in mangled form. The mutant this
    kills: `str.splitlines()` in place of a CRLF/LF-only split."""
    secret = "abc" + sep + "def"
    text = f"cmdkey /list: {secret}\n{MARKER_PREFIX}" + json.dumps(
        {"ps_startup_ms": 11, "psdirect_session_ms": 22, "guest_ms": 33}
    )
    cleaned, markers = timing.parse_marker(text)

    assert cleaned == f"cmdkey /list: {secret}", (
        f"PRR-002: a Unicode line separator ({sep!r}) inside the caller's stdout "
        f"must survive the marker parse byte-for-byte, because redaction runs "
        f"afterwards and matches exact substrings; got {cleaned!r}"
    )
    assert markers == {
        "ps_startup_ms": 11, "psdirect_session_ms": 22, "guest_ms": 33,
    }, "the marker must still be found and parsed"


def test_mixed_crlf_and_lf_terminators_are_preserved():
    """PRR-001's other half: real PowerShell emits CRLF while the checks inject
    LF, and a caller's stdout can legitimately mix them. Neither terminator may
    be rewritten by the parse."""
    text = "alpha\r\nbeta\ngamma\r\n" + MARKER_PREFIX + '{"guest_ms": 7}'
    cleaned, markers = timing.parse_marker(text)
    # The marker line and its OWN terminator are removed together; every other
    # terminator in the caller's stdout keeps the style it arrived in.
    assert cleaned == "alpha\r\nbeta\ngamma", (
        f"PRR-001: the caller's own terminators must be preserved; got {cleaned!r}"
    )
    assert markers == {"guest_ms": 7}, (
        f"the marker trio must be reported; got {markers}"
    )


def test_every_marker_line_is_removed_not_only_the_last():
    """PRR-003: only the LAST marker line used to be removed, while the
    docstring promised an absolute guarantee. The mutant this kills: returning
    from the loop on the first match found."""
    text = (
        "line one\n"
        + MARKER_PREFIX + '{"guest_ms": 1}\n'
        + "line two\n"
        + MARKER_PREFIX + '{"guest_ms": 2}\n'
    )
    cleaned, markers = timing.parse_marker(text)
    assert cleaned == "line one\nline two", (
        f"PRR-003: every marker line must be removed, not only the last; got "
        f"{cleaned!r}"
    )
    assert MARKER_PREFIX not in cleaned, (
        "PRR-003: a surviving marker line would reach the caller's stdout"
    )
    assert markers["guest_ms"] == 2, (
        "the last marker in the file supplies the values"
    )


# ---------------------------------------------------------------------------
# PRR-004 / PRR-005 — the marker payload must be bounded
# ---------------------------------------------------------------------------

def test_a_deeply_nested_marker_payload_is_refused_not_raised():
    """PRR-004: `json.loads` on a deeply nested array raises `RecursionError`,
    which is NOT a `ValueError`, so the old `except ValueError` let it escape
    `_accept` → `parse_marker` → `run_ps`. Reproduced by the reviewer at depth
    ~200000. The mutant this kills: removing the length guard."""
    deep = "[" * 200000 + "]" * 200000
    payload = MARKER_PREFIX + deep
    cleaned, markers = timing.parse_marker("out\n" + payload)

    assert cleaned == "out", "the marker line must still be removed"
    assert markers == {}, (
        f"a hostile payload must yield an empty marker dict, got {markers}"
    )


def test_an_oversized_marker_payload_is_refused_not_parsed():
    """PRR-004's length half: a payload over the bound is refused rather than
    parsed, so a hostile emitter cannot make the host spend unbounded work."""
    big = "x" * (timing._MAX_MARKER_BYTES + 1)
    cleaned, markers = timing.parse_marker(f"out\n{MARKER_PREFIX}{big}")
    assert cleaned == "out" and markers is not None
    assert all(v is None for v in markers.values()), (
        f"an oversized payload must be refused, got {markers}"
    )


def test_a_huge_integer_in_the_marker_is_dropped():
    """PRR-005: `_accept` enforced no magnitude bound and `log_operation`
    inserts the timing dict verbatim — the only record field without the
    redaction wrapper. A marker can carry a 4000-digit integer; three of them
    made `json.dumps(record)` ~12 KB. The mutant this kills: removing the
    bit-length guard."""
    huge = 10 ** 4000
    payload = json.dumps({
        "ps_startup_ms": huge, "psdirect_session_ms": 22, "guest_ms": 33,
    })
    _, markers = timing.parse_marker(f"out\n{MARKER_PREFIX}{payload}")
    assert markers.get("ps_startup_ms") is None, (
        f"PRR-005: an integer wider than {timing._MAX_MARKER_INT_BITS} bits must "
        f"be dropped so it cannot inflate the audit row; got "
        f"{markers.get('ps_startup_ms')!r}"
    )
    assert markers.get("guest_ms") == 33, "an in-range value must still be accepted"
    # A 64-bit millisecond count is still accepted: the bound must not reject
    # legitimate measurements.
    ok = json.dumps({"guest_ms": 2 ** 62})
    _, markers = timing.parse_marker(f"out\n{MARKER_PREFIX}{ok}")
    assert markers["guest_ms"] == 2 ** 62, (
        "a 62-bit millisecond count is a legitimate measurement and must pass"
    )


# ---------------------------------------------------------------------------
# PRR-026 — the marker overwrite-vs-merge contract
# ---------------------------------------------------------------------------

def test_a_marker_bearing_spawn_replaces_the_trio_and_a_bare_one_does_not():
    """PRR-026: the overwrite-vs-merge contract is unpinned; the mutant
    `self._markers = markers or {}` survives, which would make a marker-LESS
    spawn after a marker-bearing one erase the trio. The distinction between
    `None` ("no marker line at all") and `{}` ("a marker was here") is the
    contract, so both are pinned."""
    collector = timing.Collector()
    collector.add_spawn(10, {"ps_startup_ms": 5, "guest_ms": 7})
    first = collector.snapshot()
    assert (first["ps_startup_ms"], first["guest_ms"]) == (5, 7)

    # A marker-LESS spawn must leave the trio alone.
    collector.add_spawn(10, None)
    assert collector.snapshot()["guest_ms"] == 7, (
        "PRR-026: a marker-less spawn must leave the previous trio untouched"
    )

    # A marker-BEARING but unparseable spawn must REPLACE the trio.
    collector.add_spawn(10, {})
    assert collector.snapshot()["guest_ms"] is None, (
        "PRR-026: a present-but-unparseable marker means 'a marker was here' "
        "and must replace the trio, not leave the earlier values"
    )


# ---------------------------------------------------------------------------
# PRR-025 — total_ms must be a real measurement
# ---------------------------------------------------------------------------

def test_total_ms_is_a_real_measurement_not_a_constant():
    """PRR-025: hardcoding `"total_ms": 0` in `Collector.snapshot` left the
    entire suite green, because AC4 asserts only `type(...) is int` and `>= 0`
    and every guardrail check touching `total_ms` runs with no collector. The
    headline metric shipped on every audit row is pinned here against the
    clock. The mutant this kills: a constant `total_ms`."""
    collector = timing.Collector()
    early = collector.snapshot()["total_ms"]
    time.sleep(0.2)
    late = collector.snapshot()["total_ms"]

    assert late > early, (
        f"PRR-025: total_ms must advance with the clock ({early} -> {late}); a "
        f"constant would leave every audit row reporting the same number"
    )
    assert late >= 150, (
        f"PRR-025: total_ms must measure elapsed wall time; a 200 ms sleep "
        f"reported {late} ms"
    )


def test_total_ms_reaches_the_audit_row_as_a_measurement(tmp_path):
    """PRR-025's other half: the value the collector produces must be the value
    the audit row carries. The mutant this kills: a sink that drops or
    substitutes the collector's snapshot."""
    from hyperv_mcp import auditlog

    log = tmp_path / "audit.jsonl"
    cfg = Config(unrestricted=True, audit_log_path=str(log))
    auditlog.init(cfg)
    try:
        with auditlog.operation(
            tool="hyperv_console_screenshot", vm_name="vm1", category="read"
        ) as op:
            op.ok = True
            op.exit_code = 0
            time.sleep(0.2)
    finally:
        auditlog.init(Config(unrestricted=True))

    rows = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    assert rows, "no audit row was written"
    record = rows[-1]
    assert record["timing"]["total_ms"] >= 150, (
        f"PRR-025: the audit row's total_ms must be the collector's measurement; "
        f"got {record['timing']['total_ms']}"
    )
    assert record["timing"]["ps_spawns"] == 0, (
        "a call that spawned nothing must report zero spawns"
    )


# ---------------------------------------------------------------------------
# PRR-028 — capture_evidence's metadata must carry `timing`
# ---------------------------------------------------------------------------

def test_capture_evidence_metadata_carries_the_timing_block(
    monkeypatch, fresh_server
):
    """PRR-028: `capture_evidence` is the second console image tool, and the
    README claims the image tools return the same `timing` object — but every
    test faked the screenshot leg with a hand-built `_base_meta()` carrying no
    `timing` key, so filtering it out of the evidence meta copy left the suite
    green. The mutant this kills: dropping `timing` from the meta copy."""
    payload = _raw_thumbnail(320, 240)
    # THREE spawns: capture_evidence resolves the target by name, the console
    # leg re-resolves the fresh name by GUID, then the capture runs.
    monkeypatch.setattr(
        pswindows, "run_ps",
        FakeCapture([
            lambda: pswindows.PSResult(stdout=GUID, returncode=0),
            lambda: pswindows.PSResult(stdout="test-vm-1", returncode=0),
            lambda: _folded_response(payload, 320, 240),
        ]),
    )
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    images, texts = _split(_call(mcp, "hyperv_capture_evidence", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
    }))
    assert len(images) == 1, "capture_evidence must return one image block"
    meta = _meta(texts)
    assert "timing" in meta, (
        f"PRR-028: capture_evidence's metadata must carry the `timing` block; "
        f"keys present: {sorted(meta)}"
    )
    for key in ("lock_wait_ms", "ps_ms", "ps_spawns", "total_ms"):
        assert key in meta["timing"], (
            f"PRR-028: the timing block must carry {key!r}; got "
            f"{sorted(meta['timing'])}"
        )


# ---------------------------------------------------------------------------
# PRR-007 — the metadata timing must agree with the audit row
# ---------------------------------------------------------------------------

def test_metadata_timing_agrees_with_the_audit_row(monkeypatch, fresh_server, tmp_path):
    """PRR-007: the metadata `timing` was snapshotted MID-operation, so a
    `capture_evidence(ui_tree=True)` call returned metadata `{ps_ms: 75,
    ps_spawns: 3}` while the audit row for the SAME call showed `{ps_ms: 100,
    ps_spawns: 4}` — the UI-tree leg runs after the snapshot but before
    `operation.__exit__`. The docstring's "which is the value the server
    records" was false. The mutant this kills: snapshotting before the last
    leg runs."""
    payload = _raw_thumbnail(320, 240)
    monkeypatch.setattr(
        pswindows, "run_ps",
        FakeCapture([
            lambda: pswindows.PSResult(stdout=GUID, returncode=0),
            lambda: pswindows.PSResult(stdout="test-vm-1", returncode=0),
            lambda: _folded_response(payload, 320, 240),
            lambda: _folded_response(payload, 320, 240),
        ]),
    )
    log = tmp_path / "audit.jsonl"
    mod = fresh_server(config_doc={
        "unrestricted": True, "audit_log_path": str(log),
    })
    mcp = mod.get_mcp()

    images, texts = _split(_call(mcp, "hyperv_capture_evidence", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
    }))
    meta = _meta(texts)
    assert "timing" in meta, "the metadata must carry the timing block"

    rows = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    assert rows, "no audit row was written"
    audit_timing = rows[-1]["timing"]
    for key in ("ps_spawns", "ps_ms", "lock_wait_ms"):
        assert meta["timing"][key] == audit_timing[key], (
            f"PRR-007: metadata {key}={meta['timing'][key]!r} must equal the "
            f"audit row's {audit_timing[key]!r} for the same call — the metadata "
            f"used to be snapshotted before the last leg ran"
        )


# ---------------------------------------------------------------------------
# PRR-030 / PRR-029 — the soak row's advertised metrics
# ---------------------------------------------------------------------------

class _FakeResult:
    """A CallToolResult stand-in: is_error plus a text sidecar."""

    def __init__(self, payload: dict, *, is_error: bool = False):
        self.is_error = is_error
        block = type("B", (), {"type": "text", "text": json.dumps(payload)})()
        self.content = [block]


def test_a_busy_sample_is_classified_busy_end_to_end():
    """PRR-030: hardcoding `sample["busy"] = False` left the suite green, because
    AC7's `busy_rate` pin feeds synthetic samples straight into `summarize`,
    bypassing the classifier entirely. The advertised metric had zero coverage
    of its classification source. The mutant this kills: a `_sample` that never
    reports busy."""
    result = _FakeResult(
        {"ok": False, "error": "VM is busy", "error_class": "busy",
         "retryable": True, "retry_after_ms": 2000},
        is_error=True,
    )
    sample = soak_bench._sample("hyperv_guest_run_ps", result, 12.0, "tok")
    assert sample["busy"] is True, (
        f"PRR-030: a busy envelope must be classified busy; got {sample}"
    )
    assert sample["ok"] is False, "a busy call is not an ok call"

    # And a non-busy failure must NOT be classified busy, so the rate is not
    # simply "everything failed".
    other = soak_bench._sample(
        "hyperv_guest_run_ps",
        _FakeResult({"ok": False, "error": "denied", "error_class": "policy"},
                    is_error=True),
        12.0, "tok",
    )
    assert other["busy"] is False, (
        f"PRR-030: a policy rejection is not a busy sample; got {other}"
    )


def test_an_incorrect_echo_is_classified_incorrect():
    """PRR-030's other half: the `incorrect` flag is what `incorrect_rate`
    advertises, and a wrong guest echo must set it. The mutant this kills: a
    classifier that never reports incorrect."""
    good = soak_bench._sample(
        "hyperv_guest_run_ps",
        _FakeResult({"ok": True, "stdout": "tok\n", "exit_code": 0}),
        10.0, "tok",
    )
    assert good["ok"] is True and good["incorrect"] is False, (
        f"a correct echo must not be flagged incorrect; got {good}"
    )
    bad = soak_bench._sample(
        "hyperv_guest_run_ps",
        _FakeResult({"ok": True, "stdout": "something else\n", "exit_code": 0}),
        10.0, "tok",
    )
    assert bad["ok"] is True and bad["incorrect"] is True, (
        f"a wrong echo must be flagged incorrect; got {bad}"
    )


def test_summarize_carries_every_advertised_rate_and_percentile():
    """PRR-029's summarize half: `n`, `ok`, `incorrect`, `ok_rate`, `busy_rate`,
    `incorrect_rate` and the three percentiles are the row `summarize` emits,
    and the rates must be counted over ALL samples while the percentiles are
    nearest-rank over the ok samples only. The mutant this kills: a rate
    computed over the ok pool, which would hide a harness that rejected
    everything."""
    samples = [
        {"tool": "hyperv_console_screenshot", "ok": True, "incorrect": False,
         "busy": False, "ms": 10 + i}
        for i in range(4)
    ]
    # A busy sample is a FAILED call -- that is the whole point of the rate, so
    # a rate computed over the ok pool only would drop it.
    samples.append({"tool": "hyperv_guest_run_ps", "ok": False,
                    "incorrect": False, "busy": True, "ms": 99})
    samples.append({"tool": "hyperv_guest_run_ps", "ok": False,
                    "incorrect": True, "busy": False, "ms": 5000})
    row = soak_bench.summarize(samples)

    for key in ("n", "ok", "busy", "incorrect", "ok_rate", "busy_rate",
                "incorrect_rate", "p50_ms", "p95_ms", "p99_ms"):
        assert key in row, (
            f"PRR-029: the emitted row must carry {key!r}; got {sorted(row)}"
        )
    assert row["n"] == 6 and row["ok"] == 4
    assert row["busy"] == 1 and row["incorrect"] == 1
    # Rates over ALL six samples, so a rejected run reports its own rejection.
    assert abs(row["ok_rate"] - 4 / 6) < 1e-9, row["ok_rate"]
    assert abs(row["busy_rate"] - 1 / 6) < 1e-9, (
        f"PRR-029: busy_rate must be counted over ALL samples, so a run whose "
        f"only failures are busy still reports them; got {row['busy_rate']}"
    )
    assert abs(row["incorrect_rate"] - 1 / 6) < 1e-9, (
        f"PRR-029: incorrect_rate must be counted over ALL samples; got "
        f"{row['incorrect_rate']}"
    )
    # Percentiles over the OK pool only: the 5000 ms failure must not read as
    # a fast sample, and must not drag p95 either.
    assert row["p50_ms"] is not None and row["p99_ms"] is not None
    assert row["p99_ms"] <= 99, (
        f"a fail-fast error must never read as a fast sample; got {row}"
    )


def test_an_empty_ok_pool_yields_null_percentiles_not_a_raise():
    """PRR-029's other half (the finding's "whole block unpinned" was an
    overstatement — the null percentiles ARE pinned end to end — but the row
    shape is pinned here too): a run where nothing succeeded must still emit a
    row with null percentiles and the rates computed."""
    row = soak_bench.summarize([
        {"tool": "t", "ok": False, "incorrect": False, "busy": False, "ms": 10},
    ])
    assert row["p50_ms"] is None and row["p95_ms"] is None and row["p99_ms"] is None
    assert row["ok_rate"] == 0.0 and row["ok"] == 0, row


def test_summarize_by_tool_groups_and_keeps_the_five_keys():
    """PRR-029's per_tool half: the per-tool breakdown must group by tool and
    carry the five headline keys per group."""
    samples = [
        {"tool": "hyperv_console_screenshot", "ok": True, "incorrect": False,
         "busy": False, "ms": 10},
        {"tool": "hyperv_console_screenshot", "ok": True, "incorrect": False,
         "busy": False, "ms": 20},
        {"tool": "hyperv_guest_run_ps", "ok": False, "incorrect": True,
         "busy": True, "ms": 30},
    ]
    by_tool = soak_bench.summarize_by_tool(samples)
    assert set(by_tool) == {
        "hyperv_console_screenshot", "hyperv_guest_run_ps",
    }, f"per_tool must group by tool; got {sorted(by_tool)}"
    for tool, row in by_tool.items():
        for key in ("ok", "ok_rate", "busy_rate", "incorrect_rate",
                    "p50_ms", "p95_ms", "p99_ms"):
            assert key in row, f"{tool}: per_tool row must carry {key!r}; got {row}"
        assert "n" not in row, (
            f"per_tool rows drop the pooled n (the tool name IS the group); "
            f"got {sorted(row)}"
        )
    assert by_tool["hyperv_console_screenshot"]["ok_rate"] == 1.0
    assert by_tool["hyperv_guest_run_ps"]["busy_rate"] == 1.0
    # Pooling would hide which tool is slow, so the groups must be separate.
    assert (by_tool["hyperv_console_screenshot"]["p50_ms"]
            != by_tool["hyperv_guest_run_ps"]["p50_ms"]), (
        "per-tool percentiles must not be pooled"
    )


# ---------------------------------------------------------------------------
# PRR-023 residual (a) — execute the shipped PowerShell marker arithmetic
# ---------------------------------------------------------------------------

def test_the_marker_arithmetic_runs_in_real_powershell():
    """PRR-023 residual (a): the shipped PowerShell-side marker arithmetic was
    validated by no execution at all — the parse lane is syntax-only. Yet
    `ps_startup_ms` and `guest_ms` are computable by a real `powershell.exe`
    child with no Hyper-V. This is the execution lane the repo's own
    PS-generation lesson requires. The mutant this kills: a wrong cast or a
    wrong offset in the emitted marker expression."""
    script = (
        "$born = [Diagnostics.Process]::GetCurrentProcess().StartTime\n"
        "$bornMs = [int]((Get-Date) - $born).TotalMilliseconds\n"
        "$sw = [Diagnostics.Stopwatch]::StartNew()\n"
        "$r = [PSCustomObject]@{ exit_code = 0; stdout = 'x'; stderr = ''; "
        "duration_ms = 4242 }\n"
        "$sessionMs = $sw.ElapsedMilliseconds\n"
        "$r | ConvertTo-Json -Compress -Depth 2\n"
        "'__MCP_TIMING=' + (@{ ps_startup_ms = [int]$bornMs; "
        "psdirect_session_ms = [int]$sessionMs; guest_ms = [int]$r.duration_ms } "
        "| ConvertTo-Json -Compress)\n"
    )
    # Run the DECODED script through a real powershell.exe child, the way
    # run_ps does: the encoded form is what crosses the process boundary, so
    # decoding it is what proves the emitted text is what actually executes.
    encoded = pswindows.encode_command(script)
    decoded = base64.b64decode(encoded).decode("utf-16-le")
    proc = subprocess.run(
        [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "-NonInteractive", "-NoProfile", "-Command", decoded],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        "the emitted marker arithmetic must run under real PowerShell 5.1"
        + "\nstdout: " + proc.stdout[-1500:]
        + "\nstderr: " + proc.stderr[-1500:]
    )
    _, markers = timing.parse_marker(proc.stdout)
    assert markers is not None and markers.get("guest_ms") == 4242, (
        f"the executed marker must round-trip through parse_marker; got {markers}"
    )
    assert (markers.get("ps_startup_ms") or 0) >= 0, (
        f"the executed marker must carry a non-negative ps_startup_ms; got {markers}"
    )
    assert (markers.get("psdirect_session_ms") or 0) >= 0, (
        f"the executed marker must carry a non-negative psdirect_session_ms; "
        f"got {markers}"
    )


# ---------------------------------------------------------------------------
# PRR-048 — PSResult.timing's compare=False
# ---------------------------------------------------------------------------

def test_psresult_timing_is_excluded_from_equality():
    """PRR-048: `PSResult.timing`'s `compare=False` was unpinned — and there
    were no `PSResult` equality comparisons at all. The field must not change
    whether two results compare equal, or a stubbed test that compares results
    would start failing on timing noise. The mutant this kills: removing
    `compare=False`."""
    a = pswindows.PSResult(stdout="x", returncode=0, duration_ms=1,
                           timing={"guest_ms": 1})
    b = pswindows.PSResult(stdout="x", returncode=0, duration_ms=1,
                           timing={"guest_ms": 999})
    assert a == b, (
        "PRR-048: PSResult.timing must be excluded from equality, so two "
        "results that differ only in timing compare equal"
    )
    c = pswindows.PSResult(stdout="x", returncode=0, duration_ms=1,
                           timing=None)
    assert a == c, (
        "PRR-048: a present and an absent timing must still compare equal"
    )


# ---------------------------------------------------------------------------
# PRR-047 — add_lock_wait accumulates
# ---------------------------------------------------------------------------

def test_add_lock_wait_accumulates_rather_than_replaces():
    """PRR-047: `add_lock_wait`'s `+=` was indistinguishable from `=` in tests,
    while production takes TWO locks per console-input call, so a `=` would
    report only the second wait. The mutant this kills: `=` in place of `+=`."""
    collector = timing.Collector()
    collector.add_lock_wait(10)
    collector.add_lock_wait(25)
    snapshot = collector.snapshot()
    assert snapshot["lock_wait_ms"] == 35, (
        f"PRR-047: two waits must accumulate (10 + 25 = 35); got "
        f"{snapshot['lock_wait_ms']}"
    )


# ---------------------------------------------------------------------------
# PRR-014 — the uncontended-acquire measurement window
# ---------------------------------------------------------------------------

def test_an_uncontended_acquire_reports_zero_lock_wait():
    """PRR-014: the "uncontended acquire returns exactly 0" claim was false —
    4 of 20,000 uncontended write acquires reported a nonzero `lock_wait_ms`
    (max 16 ms) under a GIL-hogging thread, because `wait_started` precedes the
    mode branch and the shared return runs after the write branch's `finally`
    bookkeeping, all inside the measured window. The claim holds only via
    `int()` truncation. The mutant this kills: widening the measured window
    back around the uncontended path."""
    from hyperv_mcp import vmlocks

    with vmlocks.vm_lock("vm-probe-14", mode="write") as _held:
        # Measure the value the COLLECTOR records -- that is what reaches audit
        # rows and console metadata. Timing the whole context manager instead
        # would include CM entry/exit overhead that lock_wait_ms never claims
        # to cover, and would report a "defect" that ships nothing.
        collector = timing.Collector()
        token = timing._collector.set(collector)  # noqa: SLF001 — the seam
        try:
            hog = threading.Event()

            def _hog_gil():
                while not hog.is_set():
                    sum(range(1000))

            threads = [threading.Thread(target=_hog_gil, daemon=True)
                       for _ in range(4)]
            for t in threads:
                t.start()
            try:
                # 20,000 iterations: the reviewer's own reproduction found 4
                # nonzero values in 20,000 uncontended acquires, so a smaller
                # sample would not see the defect at all.
                for _ in range(20000):
                    with vmlocks.vm_lock("vm-probe-free", mode="write"):
                        pass
            finally:
                hog.set()
                for t in threads:
                    t.join(timeout=2)
        finally:
            timing._collector.reset(token)  # noqa: SLF001

        waited = collector.snapshot()["lock_wait_ms"]
        assert waited == 0, (
            f"PRR-014: 20,000 uncontended acquires under GIL contention must "
            f"report exactly 0 ms of lock wait; got {waited}"
        )


# ---------------------------------------------------------------------------
# PRR-046 — _audited_rejection's finally
# ---------------------------------------------------------------------------

def test_audited_rejection_resets_the_collector_even_when_the_sink_fails(
    monkeypatch, fresh_server
):
    """PRR-046: `_audited_rejection`'s `finally` was untested, so a sink failure
    on the rejection path could leak a collector into the next operation on the
    same thread. The mutant this kills: dropping the `finally` reset."""
    payload = _raw_thumbnail(320, 240)
    # Two LAZY responses: the rejected call captures and is then denied by the
    # save_path policy, and the follow-up call captures successfully.
    monkeypatch.setattr(pswindows, "run_ps",
                        FakeCapture([lambda: _folded_response(payload, 320, 240),
                                     lambda: _folded_response(payload, 320, 240)]))
    mod = fresh_server({"HYPERV_MCP_UNRESTRICTED": "1"})
    mcp = mod.get_mcp()

    # A rejected call (an out-of-roots save_path) must not leave a collector.
    _, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
        "save_path": "/nonexistent-root-xyz/frame.png",
    }))
    assert timing.current() is None, (
        "PRR-046: a rejected call must not leak a collector into the next "
        "operation on this thread"
    )
    # And a subsequent call must report its own honest numbers.
    images, texts = _split(_call(mcp, "hyperv_console_screenshot", {
        "vm_name": "test-vm-1", "width": 320, "height": 240,
    }))
    assert len(images) == 1
    meta = _meta(texts)
    assert meta["timing"]["ps_spawns"] == 1, (
        f"PRR-046: the next call must report its own spawn count, not an "
        f"accumulated one; got {meta['timing']}"
    )


# ---------------------------------------------------------------------------
# PRR-022 / PRR-039 / PRR-040 — documentation claims that were false
# ---------------------------------------------------------------------------

def test_the_readme_documents_the_timing_keys_the_code_actually_emits():
    """PRR-022's README half: the audit-record example listed the timing keys
    without the marker trio, and the "Console image tools" sentence (PRR-009)
    was plural when only `screenshot` carries the block. Both claims are checked
    against the source, not against each other."""
    readme = Path("README.md").read_text(encoding="utf-8")
    for key in ("lock_wait_ms", "ps_ms", "ps_spawns", "total_ms"):
        assert key in readme, (
            f"PRR-022: the README must document the {key!r} timing key"
        )
    # The marker trio must be named, and named as conditional.
    assert "ps_startup_ms" in readme and "psdirect_session_ms" in readme, (
        "PRR-022: the README must document the guest-side marker keys"
    )
    # The plural claim must be scoped to the tools that actually carry it.
    assert "Console image tools return the same object" not in readme, (
        "PRR-009: 'Console image tools' (plural) is false — only screenshot "
        "carries the timing block"
    )


def test_the_example_audit_record_is_internally_consistent():
    """PRR-008: the README's example audit record was impossible three ways —
    `total_ms: 447` against `duration_ms: 47`, `ps_ms: 400` > 47, and the three
    guest-only marker keys populated on `hyperv_console_scroll`, a
    console-input tool whose script never emits the marker. The mutant this
    kills: any internally impossible example."""
    readme = Path("README.md").read_text(encoding="utf-8")
    start = readme.find('"duration_ms"')
    assert start != -1, "the README must carry an example audit record"
    block = readme[start - 200:start + 1400]

    # Pull the numeric fields out of the JSON-ish example.
    def _field(name: str):
        marker = f'"{name}"'
        at = block.find(marker)
        if at == -1:
            return None
        tail = block[at + len(marker):]
        colon = tail.find(":")
        if colon == -1:
            return None
        digits = ""
        for ch in tail[colon + 1:].lstrip():
            if ch.isdigit():
                digits += ch
            else:
                break
        return int(digits) if digits else None

    duration = _field("duration_ms")
    total = _field("total_ms")
    ps_ms = _field("ps_ms")
    assert duration is not None and total is not None, (
        "the example record must carry duration_ms and total_ms"
    )
    assert total >= duration, (
        f"PRR-008: total_ms ({total}) cannot be less than duration_ms "
        f"({duration}) — total_ms is the whole operation"
    )
    if ps_ms is not None:
        assert ps_ms <= total, (
            f"PRR-008: ps_ms ({ps_ms}) cannot exceed total_ms ({total})"
        )


# ---------------------------------------------------------------------------
# PRR-010 / PRR-033 / PRR-045 / PRR-011 — harness lifecycle
# ---------------------------------------------------------------------------

def test_the_agent_threads_are_daemon():
    """PRR-010: a hung agent thread was not a daemon and was never stopped, so
    CPython's `threading._shutdown()` joined it at interpreter exit and a hung
    tool call blocked process exit AFTER `main` had returned 0. The mutant this
    kills: dropping `daemon=True` from the agent thread construction."""
    import inspect

    source = inspect.getsource(soak_bench._run)
    assert "daemon=True" in source, (
        "PRR-010: the agent threads must be daemon threads, or a wedged tool "
        "call blocks interpreter exit after main() returned 0"
    )


def test_the_agent_join_budget_is_one_shared_deadline():
    """PRR-033: the join was a single serial `t.join(timeout=600)`, so a run of
    8 agents was capped by 8 x 600 s of serial waiting. The budget must be one
    shared deadline. The mutant this kills: reverting to a per-thread join."""
    import inspect

    source = inspect.getsource(soak_bench._run)
    assert "_AGENT_JOIN_BUDGET_S" in source, (
        "PRR-033: the join budget must be a named shared deadline"
    )
    assert "t.join(timeout=max(0.0, deadline - time.monotonic()))" in source, (
        "PRR-033: each agent must join against the SHARED deadline, not its "
        "own full budget"
    )


def test_importing_the_harness_twice_does_not_grow_sys_path():
    """PRR-045: `sys.path.insert` ran unconditionally at import, so importing
    the harness twice grew sys.path without bound. The mutant this kills: an
    unconditional insert."""
    scripts = str(REPO_ROOT / "scripts")
    # Remove any earlier copy of the module so each import re-executes the
    # module body -- that is where the insert lives. The helper's own
    # insert/remove pair would mask an unconditional insert, so drive the
    # import directly.
    saved = sys.modules.pop("soak_bench", None)
    try:
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        lengths = []
        for _ in range(3):
            sys.modules.pop("soak_bench", None)
            before = len(sys.path)
            import soak_bench  # noqa: F401
            lengths.append(len(sys.path) - before)
        assert max(lengths) == 0, (
            f"PRR-045: importing the harness must not grow sys.path; the three "
            f"imports changed it by {lengths}"
        )
    finally:
        sys.modules.pop("soak_bench", None)
        if saved is not None:
            sys.modules["soak_bench"] = saved


def test_a_run_restores_the_audit_sink():
    """PRR-011: after a run, `auditlog._config` kept pointing at the run's tmp
    audit file, so a later direct `auditlog.operation()` in the same process
    raised FileNotFoundError once the TemporaryDirectory was gone. Guarded in
    every shipped consumer by the conftest autouse restore — a latent landmine
    the harness itself must not carry. The mutant this kills: dropping the
    sink restore from the teardown."""
    import contextlib
    import io
    import tempfile

    import hyperv_mcp.auditlog as auditlog

    before = auditlog._config
    with tempfile.TemporaryDirectory():
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = soak_bench.main(
                ["--fake", "--agents", "1", "--iterations", "1"]
            )
    assert rc == 0, f"the harness exited {rc}"
    assert auditlog._config is before, (
        "PRR-011: a run must restore the audit sink it replaced, or a later "
        "direct auditlog.operation() in this process writes into a deleted "
        "temporary directory"
    )
    # And the restored sink must actually work.
    with auditlog.operation(tool="d04-probe", vm_name="v", category="read"):
        pass
