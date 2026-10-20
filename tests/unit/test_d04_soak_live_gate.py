"""Non-frozen companions for the issue-#20 trace (D-04).

These live outside `test_d04_timing.py` because that file's bytes are pinned by
the checkpoint manifest, and each of these needs to sit somewhere the fix is
free to grow. Three things are covered here:

  - the soak harness's live-mode env gate, which is AC9's substitute evidence;
  - the B01 audit-schema guardrail's *strictness*, which AC13 pins only the key
    set of and C13 verifies only the outcome of;
  - the soak harness's ok-guarantee, because AC8 is shape-only and cannot tell a
    working stub from a harness that rejects everything.

No real PowerShell, Hyper-V, network or credential is touched.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _import_soak_bench():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        import soak_bench
    finally:
        sys.path.remove(str(REPO_ROOT / "scripts"))
    return soak_bench


def test_soak_bench_live_mode_refuses_without_env(monkeypatch):
    """AC9 substitute evidence (a): the live mode refuses to start unless
    HYPERV_MCP_INTEGRATION=1, HYPERV_MCP_SOAK=1 and HYPERV_MCP_TEST_VM are all
    set and guest credentials resolve. Same disposable-VM discipline as
    tests/integration/conftest.py."""
    soak_bench = _import_soak_bench()
    for name in (
        "HYPERV_MCP_INTEGRATION", "HYPERV_MCP_SOAK", "HYPERV_MCP_TEST_VM",
        "HYPERV_GUEST_USERNAME", "HYPERV_GUEST_PASSWORD",
        "HYPERV_GUEST_PASSWORD_FILE",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(SystemExit) as excinfo:
        soak_bench.main(["--agents", "1", "--iterations", "1"])
    message = str(excinfo.value)
    assert "live mode refused" in message, message
    assert "HYPERV_MCP_INTEGRATION" in message, message


def test_soak_bench_live_mode_refuses_without_soak_flag(monkeypatch):
    """The gate is all three variables, not any one of them: setting the
    integration flag alone must still refuse, and must name HYPERV_MCP_SOAK."""
    soak_bench = _import_soak_bench()
    for name in (
        "HYPERV_MCP_SOAK", "HYPERV_MCP_TEST_VM",
        "HYPERV_GUEST_USERNAME", "HYPERV_GUEST_PASSWORD",
        "HYPERV_GUEST_PASSWORD_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HYPERV_MCP_INTEGRATION", "1")

    with pytest.raises(SystemExit) as excinfo:
        soak_bench.main(["--agents", "1", "--iterations", "1"])
    assert "HYPERV_MCP_SOAK" in str(excinfo.value)


def test_soak_bench_fake_mode_reports_non_null_percentiles():
    """The ok-guarantee, made executable.

    AC8 asserts only that the fake mode exits 0 and prints three rows with the
    five keys present, so a harness whose every sample is a policy or credential
    rejection would still pass it. This is the check that distinguishes a
    working stub from that: with the stub serving the real tool layer, the ok
    pool is non-empty and the percentiles are real numbers.
    """
    soak_bench = _import_soak_bench()
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = soak_bench.main(
            ["--fake", "--agents", "1", "--iterations", "1", "--json"]
        )
    assert rc == 0, f"soak_bench --fake exited {rc}"
    rows = [
        json.loads(line)
        for line in buffer.getvalue().splitlines()
        if line.strip().startswith("{")
    ]
    assert len(rows) == 1, f"expected one row, got {len(rows)}: {buffer.getvalue()!r}"
    row = rows[0]
    assert row["ok"] > 0, (
        "the fake-mode run produced no successful sample, so its percentiles "
        f"measure nothing: {row}"
    )
    for key in ("p50_ms", "p95_ms", "p99_ms"):
        assert isinstance(row[key], (int, float)), (
            f"{key} is {row[key]!r}: the ok pool was empty, which means the "
            "stub did not serve the tool layer (check the tmp config allows "
            "test-* VMs and console_input, and that guest credentials resolve)"
        )
    assert row["incorrect"] == 0, (
        f"the fake-mode run misclassified {row['incorrect']} sample(s) as "
        "incorrect; the guest stub must echo the calling agent's token"
    )


def test_soak_bench_fake_mode_reports_a_rejection_only_run_as_such(monkeypatch):
    """The other half of the ok-guarantee.

    `test_soak_bench_fake_mode_reports_non_null_percentiles` proves a working
    stub produces real percentiles. This proves the sampler READS the result
    rather than assuming success: pointed at a config that denies every VM,
    every sample must come back `ok: false` with a non-zero busy-or-incorrect
    rate, so a harness that silently labelled rejections as successes cannot
    pass. Without this, `ok = True` hardcoded in the sampler would survive."""
    soak_bench = _import_soak_bench()
    import contextlib
    import importlib
    import io
    import tempfile

    import hyperv_mcp.server as server_module

    def denying_server(mode, audit_log, session_reuse=None):
        """A server whose policy matches no VM name at all.

        Returns the (module, teardown) pair `_run` unpacks; the teardown
        restores the audit sink the way the real one does (feedback PRR-011).
        """
        import hyperv_mcp.auditlog as auditlog

        cfg = audit_log.parent / "deny.json"
        cfg.write_text(
            json.dumps({"allowed_vm_patterns": ["nothing-matches-*"]}),
            encoding="utf-8",
        )
        saved_config = auditlog._config
        mod = importlib.reload(server_module)
        mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg)})

        def _teardown():
            auditlog._config = saved_config
            importlib.reload(server_module)

        return mod, _teardown

    monkeypatch.setattr(soak_bench, "_server_for", denying_server)
    with tempfile.TemporaryDirectory():
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = soak_bench.main(
                ["--fake", "--agents", "1", "--iterations", "1", "--json"]
            )
    assert rc == 0, f"soak_bench --fake exited {rc}"
    rows = [
        json.loads(line)
        for line in buffer.getvalue().splitlines()
        if line.strip().startswith("{")
    ]
    assert len(rows) == 1, f"expected one row: {buffer.getvalue()!r}"
    row = rows[0]
    assert row["ok"] == 0, (
        f"a deny-all config produced {row['ok']} successful sample(s): the "
        f"sampler is not reading the result: {row}"
    )
    assert row["ok_rate"] == 0.0 and row["n"] > 0, (
        f"a deny-all run must be visible as zero successes over a non-empty "
        f"sample set: {row}"
    )
    assert row["p50_ms"] is None, (
        f"a run with no ok sample reported percentiles: {row}"
    )


def test_guardrail_assertion_stays_strict():
    """The B01 audit-schema guardrail's *strictness*, checked behaviourally
    (feedback PRR-041).

    AC13 pins that `timing` is in `AUDIT_KEYS`, and C13 verifies the guardrail
    test still passes. Neither pins HOW it asserts: weakening
    `assert set(row) == AUDIT_KEYS` to `<=` would keep both green while
    letting a row silently lose a key. The old version of this check pinned
    the literal source substring — brittle to reformatting and satisfiable
    by moving the string into a comment. This one parses the guardrail
    module's AST, finds the key-set comparison, and EXECUTES the found
    expression against a row that lost a key: the operator must be `==`, and
    the guard's own comparison must answer False for the deficient row.
    """
    import ast

    source = (REPO_ROOT / "tests" / "unit" / "test_b01_audit_correlation_guardrail.py")
    text = source.read_text(encoding="utf-8")
    guard = None
    for node in ast.walk(ast.parse(text)):
        if not isinstance(node, ast.Compare):
            continue
        left = node.left
        if not (isinstance(left, ast.Call) and isinstance(left.func, ast.Name)
                and left.func.id == "set" and len(left.args) == 1):
            continue
        if any(isinstance(c, ast.Name) and c.id == "AUDIT_KEYS"
               for c in node.comparators):
            guard = node
            break
    assert guard is not None, (
        "the B01 audit-schema guardrail no longer compares set(row) against "
        "AUDIT_KEYS at all"
    )
    ops = [type(op).__name__ for op in guard.ops]
    assert ops == ["Eq"], (
        f"the audit-schema comparison is not strict set equality: {ops} — a "
        "subset/superset check would let a row lose or gain a key undetected"
    )
    sys.path.insert(0, str(REPO_ROOT / "tests" / "unit"))
    try:
        import test_b01_audit_correlation_guardrail as b01
    finally:
        sys.path.remove(str(REPO_ROOT / "tests" / "unit"))
    # Execute the FOUND comparison (not a lookalike) on a deficient row: the
    # guard itself must reject a row that lost a key.
    row_missing_key = {key: 0 for key in b01.AUDIT_KEYS if key != "timing"}
    verdict = eval(
        compile(ast.Expression(guard), "<b01-audit-schema-guard>", "eval"),
        {"set": set, "row": row_missing_key, "AUDIT_KEYS": b01.AUDIT_KEYS},
    )
    assert verdict is False, (
        "the audit-schema guardrail's own comparison admitted a row missing "
        "the timing key — it is no longer strict"
    )


def test_guardrail_key_set_includes_timing():
    """AC13's other half, restated here so the two halves of the guardrail's
    contract (which keys, and how strictly) sit together."""
    sys.path.insert(0, str(REPO_ROOT / "tests" / "unit"))
    try:
        import test_b01_audit_correlation_guardrail as b01
    finally:
        sys.path.remove(str(REPO_ROOT / "tests" / "unit"))
    assert "timing" in b01.AUDIT_KEYS


def test_timing_marker_is_absent_from_stdout_by_default():
    """A PowerShell leg that emits no marker must leave stdout byte-identical,
    so the parse step is invisible to every existing consumer of run_ps."""
    from hyperv_mcp import timing

    text = "line one\nline two\n"
    cleaned, markers = timing.parse_marker(text)
    assert cleaned == text
    assert markers is None


def test_timing_marker_crlf_is_recognised():
    """Real PowerShell emits CRLF; the frozen checks inject LF. Both must be
    recognised, so the split is on universal newlines.

    The marker line and its terminator are removed together (it is the last
    line), and the separator between the SURVIVING lines keeps the caller's
    own style, so a stdout that arrived CRLF leaves CRLF and nothing else
    about it changes.
    """
    from hyperv_mcp import timing

    crlf = chr(13) + chr(10)
    lf = chr(10)
    payload = '{"ps_startup_ms":11,"psdirect_session_ms":22,"guest_ms":33}'
    wanted = {"ps_startup_ms": 11, "psdirect_session_ms": 22, "guest_ms": 33}

    cleaned, markers = timing.parse_marker(
        "line one" + crlf + "line two" + crlf + "__MCP_TIMING=" + payload + crlf
    )
    assert markers == wanted
    assert cleaned == "line one" + crlf + "line two", repr(cleaned)
    assert "__MCP_TIMING" not in cleaned

    # The LF form is recognised identically, so the parse is
    # terminator-agnostic and an existing consumer cannot tell it ran.
    cleaned_lf, markers_lf = timing.parse_marker(
        "line one" + lf + "line two" + lf + "__MCP_TIMING=" + payload + lf
    )
    assert markers_lf == wanted
    assert cleaned_lf == "line one" + lf + "line two", repr(cleaned_lf)

    # A stdout with no marker is returned byte-identical.
    plain = "line one" + crlf + "line two" + crlf
    assert timing.parse_marker(plain) == (plain, None)


def test_timing_marker_rejects_non_numeric_and_unknown_keys():
    """A hostile or malformed marker must not become a channel for script text:
    non-numeric values and unknown keys are dropped, the line is removed either
    way, and the marker still counts as present (a dict, not None)."""
    from hyperv_mcp import timing

    hostile = '__MCP_TIMING={"ps_startup_ms":"evil-script-text","nope":1,"guest_ms":true}'
    cleaned, markers = timing.parse_marker(f"out\n{hostile}\n")
    assert "evil-script-text" not in cleaned
    assert markers is not None, "a present marker must read as a dict, not None"
    assert markers == {}, f"only the three known int keys may survive: {markers}"


def _fake_result(tool: str, payload: dict, image: bool = False):
    """Build the shape mcp.call_tool returns, for driving _sample directly."""
    import types

    blocks = []
    if image:
        blocks.append(types.SimpleNamespace(type="image"))
    blocks.append(types.SimpleNamespace(type="text", text=json.dumps(payload)))
    return types.SimpleNamespace(content=blocks, is_error=False)


def test_soak_bench_sample_compares_the_echo_stripped():
    """The guest echo comparison must strip.

    The guest child's stdout keeps its trailing newline -- _normal_body captures
    it with ReadAllText and _result_ok never strips -- so an exact comparison
    counts every CORRECT live echo as incorrect, and a live AC9 run reports
    incorrect_rate 1.0 no matter how the system behaves. The fake stub echoes the
    bare token, which is exactly why this was invisible until the final critic
    drove _sample with realistic stdout.
    """
    soak_bench = _import_soak_bench()
    correct = soak_bench._sample(
        "hyperv_guest_run_ps",
        _fake_result("hyperv_guest_run_ps",
                     {"ok": True, "exit_code": 0, "stdout": "soak-token-1\r\n"}),
        1.0,
        "soak-token-1",
    )
    assert correct["ok"] is True
    assert correct["incorrect"] is False, (
        f"a correct guest echo with its trailing newline was counted incorrect: "
        f"{correct}"
    )
    wrong = soak_bench._sample(
        "hyperv_guest_run_ps",
        _fake_result("hyperv_guest_run_ps",
                     {"ok": True, "exit_code": 0, "stdout": "someone-else\r\n"}),
        1.0,
        "soak-token-1",
    )
    assert wrong["incorrect"] is True, (
        f"a mismatched token was not counted incorrect: {wrong}"
    )


def test_soak_bench_summarize_by_tool_groups_and_keeps_the_five_keys():
    """summarize_by_tool, pinned directly.

    AC9 asks for percentiles PER TOOL. Nothing else in the suite reads this
    function, so a mutant that dropped the grouping, renamed a key, or returned
    an empty dict survived every other check.
    """
    soak_bench = _import_soak_bench()
    samples = []
    for tool in soak_bench.TOOLS:
        for ms in (10.0, 20.0, 30.0, 40.0):
            samples.append({"tool": tool, "ok": True, "ms": ms,
                            "busy": False, "incorrect": False})
    per_tool = soak_bench.summarize_by_tool(samples)
    assert set(per_tool) == set(soak_bench.TOOLS), (
        f"per-tool grouping lost a tool: {sorted(per_tool)}"
    )
    for tool, entry in per_tool.items():
        for key in ("p50_ms", "p95_ms", "p99_ms", "busy_rate", "incorrect_rate"):
            assert key in entry, f"{tool} omits {key}: {entry}"
        assert entry["p50_ms"] == 20.0, f"{tool} p50 wrong: {entry}"
        assert entry["p95_ms"] == 40.0, f"{tool} p95 wrong: {entry}"
        assert entry["ok"] == 4, f"{tool} ok count wrong: {entry}"


def test_soak_bench_guest_timing_median_is_a_median():
    """_guest_timing_median, pinned directly -- and specifically as a MEDIAN.

    Workstream D PR 5's before/after session-reuse baseline reads these numbers.
    Swapping statistics.median for statistics.mean changes them on any skewed
    sample and survived every other check in the suite, so the semantics get
    their own assertion.
    """
    soak_bench = _import_soak_bench()
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.jsonl"
        rows = [
            {"tool": "hyperv_guest_run_ps",
             "timing": {"ps_startup_ms": 10, "psdirect_session_ms": 100,
                        "guest_ms": 1}},
            {"tool": "hyperv_guest_run_ps",
             "timing": {"ps_startup_ms": 20, "psdirect_session_ms": 200,
                        "guest_ms": 2}},
            {"tool": "hyperv_guest_run_ps",
             "timing": {"ps_startup_ms": 900, "psdirect_session_ms": 300,
                        "guest_ms": 3}},
            {"tool": "hyperv_console_screenshot",
             "timing": {"ps_startup_ms": 5, "psdirect_session_ms": 5,
                        "guest_ms": 5}},
        ]
        log.write_text(
            chr(10).join(json.dumps(r) for r in rows) + chr(10), encoding="utf-8"
        )
        medians = soak_bench._guest_timing_median(log)
    assert medians["ps_startup_ms"] == 20.0, (
        f"the median of 10/20/900 is 20, not {medians['ps_startup_ms']} "
        "(a mean would give 310)"
    )
    assert medians["psdirect_session_ms"] == 200.0
    assert medians["guest_ms"] == 2.0


def test_soak_bench_guest_timing_median_is_null_without_markers():
    """No marker values means nulls, not zeroes -- the honest answer in fake
    mode, where no real PowerShell ever ran."""
    soak_bench = _import_soak_bench()
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.jsonl"
        log.write_text(
            json.dumps({"tool": "hyperv_guest_run_ps",
                        "timing": {"ps_startup_ms": None,
                                   "psdirect_session_ms": None,
                                   "guest_ms": None}}) + chr(10),
            encoding="utf-8",
        )
        medians = soak_bench._guest_timing_median(log)
    assert medians == {"ps_startup_ms": None, "psdirect_session_ms": None,
                       "guest_ms": None}, medians


def test_soak_bench_guest_timing_median_is_null_when_the_log_is_unreadable():
    """PRR-035: `read_text` was unguarded, so an audit log that exists but
    cannot be read (non-UTF-8 bytes, a directory left at the path, a
    permissions failure) raised instead of answering "no guest timing". The
    mutant this kills: removing the read guard."""
    soak_bench = _import_soak_bench()
    import tempfile

    nulls = {"ps_startup_ms": None, "psdirect_session_ms": None,
             "guest_ms": None}
    with tempfile.TemporaryDirectory() as td:
        broken = Path(td) / "broken.jsonl"
        broken.write_bytes(b"\xff\xfe\x00 not utf-8 \xff")
        assert soak_bench._guest_timing_median(broken) == nulls, (
            "a non-decodable audit log must yield the no-guest-timing answer"
        )
        # A DIRECTORY at the path: exists() is True and read_text raises
        # IsADirectoryError (an OSError) -- still nulls, not a raise.
        assert soak_bench._guest_timing_median(Path(td)) == nulls, (
            "an unreadable audit log path must yield the no-guest-timing answer"
        )


def test_a_cancelled_agent_call_is_recorded_as_a_sample():
    """PRR-034: `_agent_loop`'s `except Exception` could not catch
    asyncio.CancelledError (a BaseException since Python 3.8), so a
    cancelled agent thread escaped the handler and its sample vanished
    instead of being recorded. The mutant this kills: `except Exception` in
    place of `except BaseException`."""
    soak_bench = _import_soak_bench()
    import asyncio
    import threading

    class CancellingMcp:
        async def call_tool(self, tool, args):
            raise asyncio.CancelledError()

    samples: list[dict] = []
    lock = threading.Lock()
    soak_bench._agent_loop(CancellingMcp(), None, "tok", 1, "vm", samples, lock)
    assert len(samples) == len(soak_bench.TOOLS), (
        f"a cancelled call must still produce one sample per tool; got "
        f"{samples}"
    )
    for sample in samples:
        assert sample["ok"] is False and sample["error"] == "CancelledError", (
            f"PRR-034: the cancellation was not recorded as a sample: {sample}"
        )
        assert sample["busy"] is False and sample["incorrect"] is False


def test_a_fake_run_withdraws_its_fake_password_from_the_redaction_registry():
    """PRR-037: fake mode's `soak-agent-pass` was registered in the
    process-global, append-only redaction registry by every credential
    resolution during the run, and the teardown never withdrew it -- so the
    fake password kept scrubbing unrelated text in every later redaction
    this process performed. The mutant this kills: dropping the unregister
    call from the harness teardown."""
    soak_bench = _import_soak_bench()
    import contextlib
    import io

    from hyperv_mcp import credentials

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = soak_bench.main(["--fake", "--agents", "1", "--iterations", "1"])
    assert rc == 0, f"soak_bench --fake exited {rc}"
    fake = soak_bench._FAKE_GUEST_PASSWORD
    assert fake not in credentials.registry().all(), (
        "PRR-037: the fake-mode password stayed in the process-global "
        "redaction registry after the run"
    )
    assert credentials.redact(f"x {fake} x") == f"x {fake} x", (
        "PRR-037: a later redaction still scrubs the fake password out of "
        "unrelated text"
    )
