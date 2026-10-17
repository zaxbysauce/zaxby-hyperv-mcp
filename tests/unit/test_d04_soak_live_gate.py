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


def test_guardrail_assertion_stays_strict():
    """The B01 audit-schema guardrail's *strictness*.

    AC13 pins that `timing` is in `AUDIT_KEYS`, and C13 verifies the guardrail
    test still passes. Neither pins HOW it asserts: weakening
    `assert set(row) == AUDIT_KEYS` to `<=` would keep both green while letting
    a row silently lose a key. This pins the literal in the source.
    """
    source = (REPO_ROOT / "tests" / "unit" / "test_b01_audit_correlation_guardrail.py")
    text = source.read_text(encoding="utf-8")
    assert "set(row) == AUDIT_KEYS" in text, (
        "the B01 audit-schema guardrail no longer asserts the exact key set; "
        "a superset check would let a row lose a key undetected"
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
    recognised, so the split is on universal newlines rather than on "\\n"."""
    from hyperv_mcp import timing

    payload = '{"ps_startup_ms":11,"psdirect_session_ms":22,"guest_ms":33}'
    cleaned, markers = timing.parse_marker(f"real output\r\n__MCP_TIMING={payload}\r\n")
    assert markers == {"ps_startup_ms": 11, "psdirect_session_ms": 22, "guest_ms": 33}
    assert cleaned == "real output"
    assert "__MCP_TIMING" not in cleaned


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
