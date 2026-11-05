"""Acceptance checks for issue #81 (trace 75-76-78-81-83-84-collated): no
console composer may grow the spawned command line past the Windows
CreateProcess limit for any schema-allowed input shape.

Measured constants (02-reproduction.md, real subprocess.Popen at base):
  * CreateProcess command-line limit: 32767 characters.
  * Composed argv = ~385 fixed characters (powershell.exe path + the three
    flags + "-EncodedCommand ") plus 8/3 (2.667) argv characters per script
    character (UTF-16LE bytes, base64-encoded at 4/3).
  * type_scancodes cliff: 2472 codes (vm1) -> 32777 -> WinError 206; the
    cliff moves with the VM-name prelude.
  * remote type_text cliff: 163 chunks -> 32793 (~165 argv characters per
    chunk: the $__pN stdin read + the param() entry + the -ArgumentList
    entry + the $payloads entry).
  * run_sequence step cliff: 2400 codes/step -> cmdline 32609.
  * fix-round rejection shapes (implementation review of the collated fix):
    a 50-step type_text plan (50 x 512-char steps) composes a 34028-char
    script -> a 91125-character command line, and a single 20000-code
    scancode step stays over even compacted (26668-char base64 seed ->
    29231-char script -> 78333-character command line) — both must be
    refused BEFORE any spawn, never launched into WinError 206.

Frozen-docstring wording note: the discriminating checks below are RED at
the pre-fix tree (single oversized composed command) and GREEN after the
split/cap fix; the small-shape legs are GREEN at both ends. Every check
measures the command line EXACTLY as pswindows.run_ps spawns it
(pswindows.py:651: ``[_ps_path, "-NonInteractive", "-NoProfile",
"-EncodedCommand", encode_command(_PS_PIN + script)]``)."""

from __future__ import annotations

import base64
import re

import pytest

from hyperv_mcp import console, credentials, pswindows
from hyperv_mcp.config import Config

# CUB2-3: the sweep bound is the PRR-103 PRODUCT ceiling — the largest
# SPAWNABLE command line is 32766 characters (console._CMDLINE_CHAR_LIMIT;
# the OS's raw 32767 buffer includes the terminating null, cited once in the
# module docstring above). The product gate now refuses a composed 32767-char
# line pre-spawn, so a sweep shape composing exactly 32767 is
# refused-not-delivered and must read as OVER this bound, not at it.
CMDLINE_LIMIT = 32766


@pytest.fixture(autouse=True)
def _transport_gate():
    """run_ps's argv composition needs a resolved _ps_path (the same gate the
    folded-protocol pack uses before executing scripts)."""
    pswindows.init(Config(unrestricted=True))


class _CapturingRunner:
    """pswindows.run_ps replacement: records every (script, stdin_b64) pair
    the module composes and answers an empty success (returncode 0 — every
    folded input op only checks the exit code; chunk counts are derived from
    the emitted script/stdin text, never from this stub's own values)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def __call__(self, script, timeout_s=None, stdin_b64=None):
        self.calls.append((script, stdin_b64))
        return pswindows.PSResult(stdout="", returncode=0, duration_ms=0.0)


def _install(monkeypatch, runner: _CapturingRunner) -> _CapturingRunner:
    monkeypatch.setattr(pswindows, "run_ps", runner)
    return runner


def _argv_len(script: str) -> int:
    """The composed command line run_ps spawns for this script — the exact
    argv pswindows.py:651 builds (path + flags + base64 of PIN+script)."""
    return len(
        pswindows._ps_path + " -NonInteractive -NoProfile -EncodedCommand "
        + pswindows.encode_command(pswindows._PS_PIN + script)
    )


def _seed_codes(script: str) -> list[int]:
    """The scancode codes delivered by one emitted script: the folded
    `$chunks = @(...)` seed line (the D-02 AC19-pinned shape)."""
    m = re.search(r"^\$chunks = @\((\d+(?:,\d+)*)\)$", script, re.M)
    assert m, "no $chunks seed array found in the emitted scancode script"
    return [int(x) for x in m.group(1).split(",")]


def _sequence_codes(script: str, expected: list[int] | None = None) -> list[int]:
    """The scancode codes one emitted sequence script embeds: the unrolled
    step's literal `ScanCodes = [byte[]]@(...)` argument, or — for a codes
    step the composer had to compact — its base64 seed (`$__scB64`, decoded
    in-script to the same delivered array)."""
    # R2-A sanctioned amendment (issue #84 coordination, plan Round-2 R2-A):
    # production compact-encodes OVERSIZED sequence codes steps (issue #81) —
    # the codes ride the `$__scB64` base64 seed instead of the literal array,
    # so this helper deliberately accepts BOTH shapes. Ordinary steps keep
    # the literal extraction exactly as before; the compact branch decodes
    # the seed in Python and, when `expected` (the codes the test drove) is
    # given, asserts the bytes round-trip to them exactly and in order.
    m = re.search(r"ScanCodes = \[byte\[\]\]@\((\d+(?:,\d+)*)\)", script)
    if m:
        return [int(x) for x in m.group(1).split(",")]
    seed = re.search(r"^\s*\$__scB64 = '([A-Za-z0-9+/=]+)'", script, re.M)
    assert seed, "no ScanCodes step array found in the emitted sequence script"
    assert "$__sc = [byte[]][Convert]::FromBase64String($__scB64)" in script, (
        "the compact $__scB64 seed is not decoded into the delivered ScanCodes array"
    )
    codes = list(base64.b64decode(seed.group(1)))
    if expected is not None:
        assert codes == expected, (
            "the compact seed did not round-trip to the exact ordered step codes"
        )
    return codes


def _delivered_text(calls: list[tuple[str, str | None]]) -> str:
    """The text chunks actually handed to the transport, decoded from the
    base64 stdin payload lines in delivery order."""
    parts: list[str] = []
    for _script, stdin_b64 in calls:
        if not stdin_b64:
            continue
        for line in stdin_b64.split("\n"):
            if line.strip():
                parts.append(base64.b64decode(line).decode("utf-8"))
    return "".join(parts)


def _argv_problems(runner: _CapturingRunner) -> list[str]:
    return [
        f"composed command line {length} > {CMDLINE_LIMIT} (script #{i})"
        for i, (script, _stdin) in enumerate(runner.calls)
        if (length := _argv_len(script)) > CMDLINE_LIMIT
    ]


def test_scancodes_beyond_the_command_line_limit_deliver_every_code(
    monkeypatch, unrestricted_cfg
):
    """AC10: 4000 scancode codes (past the measured 2472-code cliff) must
    deliver EVERY code: whatever scripts the module spawns, each composed
    command line stays <= 32767 and the concatenated delivered chunks
    reproduce the input exactly, in order. RED at base (one script -> one
    ~35k+ command line -> the limit assert fails), GREEN after the split."""
    codes = [123] * 4000
    runner = _install(monkeypatch, _CapturingRunner())

    out = console.type_scancodes(unrestricted_cfg, "vm1abc", codes)
    assert runner.calls, "the PowerShell transport spawned nothing"

    problems = _argv_problems(runner)
    for script, _stdin in runner.calls:
        assert "TypeScancodes" in script, "a split leg lost the op's WMI method"

    delivered = [code for script, _stdin in runner.calls for code in _seed_codes(script)]
    assert problems == [], (
        "AC10: oversized composed command line(s): " + "; ".join(problems)
    )
    assert delivered == codes, (
        f"AC10: delivered {len(delivered)} codes (in order) for {len(codes)} input codes"
    )
    assert out["ok"] is True and out["scancodes_sent"] == len(codes)


def test_remote_type_text_beyond_the_command_line_limit_delivers_every_chunk(
    monkeypatch,
):
    """AC11: remote type_text sized to 200 chunks (past the measured
    163-chunk cliff) must deliver EVERY chunk: the composition goes through
    the REAL pswindows.compose_remote (the WS-Man hop), and every composed
    command line stays <= 32767 with the concatenated decoded payload equal
    to the input text. RED at base (one composed command ~38.9k chars),
    GREEN after the chunks-per-command cap."""
    cfg = Config.from_dict({"hyperv": {"host": "nuc01"}, "unrestricted": True})
    # Implicit-auth remote (no HYPERV_HOST_* pair): the hop carries no
    # -Credential, deterministically independent of this process's env.
    monkeypatch.setattr(credentials, "resolve_host", lambda environ=None: None)
    text = "a" * 102400  # 200 x 512-char chunks
    runner = _install(monkeypatch, _CapturingRunner())

    out = console.type_text(cfg, "vm1", text)
    assert runner.calls, "the remote PowerShell transport spawned nothing"
    for script, _stdin in runner.calls:
        assert "Invoke-Command -ComputerName 'nuc01'" in script, (
            "the remote composition did not go through the real compose_remote hop"
        )

    problems = _argv_problems(runner)
    delivered = _delivered_text(runner.calls)
    assert problems == [], (
        "AC11: oversized composed command line(s): " + "; ".join(problems)
    )
    assert delivered == text, (
        f"AC11: delivered {len(delivered)} chunk characters for {len(text)} input "
        "characters (every chunk must arrive, in order)"
    )
    assert out["ok"] is True and out["chunks"] == 200 and out["chars"] == len(text)


def test_command_line_stays_under_the_limit_for_schema_allowed_shapes(
    monkeypatch, unrestricted_cfg
):
    """AC13: a sweep of realistic schema-allowed shapes — 5000 scancodes,
    a 200-chunk local type_text, a run_sequence step carrying 2500 scancode
    codes, and one short ordinary call. EVERY composed command line must
    stay <= 32767 and the delivery invariants must hold (all codes / all
    text / all step codes / the short call's two codes). RED at base (the
    5000-code and 2500-code-step shapes overflow), GREEN after the fix.

    Fix-round amendment (same procedure as the R2-A one above): the
    implementation review of the collated fix found run_sequence could still
    compose an over-limit script for schema-allowed plans the codes-step
    compaction loop cannot shrink — a 50-step type_text plan and a single
    20000-code step — so those two shapes are now pinned as PRE-SPAWN
    rejections (structured ConsoleError naming the budget, ZERO PowerShell
    spawn attempts) instead of launches into WinError 206."""
    shapes: list[tuple[str, list[str]]] = []

    # (1) 5000 scancodes — past the cliff, must split and deliver everything.
    codes = [123] * 5000
    runner = _install(monkeypatch, _CapturingRunner())
    console.type_scancodes(unrestricted_cfg, "vm1abc", codes)
    problems = _argv_problems(runner)
    delivered = [c for script, _ in runner.calls for c in _seed_codes(script)]
    if delivered != codes:
        problems.append(f"delivered {len(delivered)} of {len(codes)} codes in order")
    shapes.append(("type_scancodes 5000 codes", problems))

    # (2) 200-chunk LOCAL type_text — already argv-safe (chunks ride stdin);
    # pins that the fix does not regress the safe shape.
    text = "a" * 102400
    runner = _install(monkeypatch, _CapturingRunner())
    console.type_text(unrestricted_cfg, "vm1", text)
    problems = _argv_problems(runner)
    if _delivered_text(runner.calls) != text:
        problems.append("the 200-chunk local text did not arrive complete")
    shapes.append(("type_text 200 chunks local", problems))

    # (3) one run_sequence step carrying 2500 scancode codes — the unrolled
    # step block shares the overflow class (measured 2400 -> 32609).
    step_codes = [123] * 2500
    runner = _install(monkeypatch, _CapturingRunner())
    console.run_sequence(
        unrestricted_cfg, "vm1",
        steps=[{"action": "type_scancodes", "scancodes": step_codes}],
    )
    problems = _argv_problems(runner)
    delivered = [c for script, _ in runner.calls for c in _sequence_codes(script, step_codes)]
    if delivered != step_codes:
        problems.append(
            f"sequence delivered {len(delivered)} of {len(step_codes)} step codes"
        )
    shapes.append(("run_sequence step 2500 codes", problems))

    # (4) a short ordinary call — under the limit before and after.
    short = [0x1C, 0x9C]
    runner = _install(monkeypatch, _CapturingRunner())
    out = console.type_scancodes(unrestricted_cfg, "vm1abc", short)
    problems = _argv_problems(runner)
    if not runner.calls or _seed_codes(runner.calls[0][0]) != short:
        problems.append("the short call's codes did not ride the script seed")
    if not out["ok"] or out["scancodes_sent"] != 2:
        problems.append("the short call did not report both codes sent")
    shapes.append(("short type_scancodes call", problems))

    # (5) fix-round legs closing the implementation-review finding: the
    # codes-step compaction loop cannot shrink a plan whose size rides the
    # UNROLLED BLOCKS (50 type_text steps -> a 34028-char script -> a
    # 91125-character command line), nor a single codes step whose compact
    # base64 seed alone busts the budget (20000 codes -> a 78333-character
    # command line). Both must be refused BEFORE any spawn: a structured
    # ConsoleError naming the 32766-char command-line budget (PRR-103: the
    # ceiling is 32766 SPAWNABLE characters — CreateProcess's 32767 includes
    # the terminating null), with the captured transport proving ZERO spawn
    # attempts (fail-closed, not launched into WinError 206).
    for label, steps in [
        ("type_text", [{"action": "type_text", "text": "a" * 512} for _ in range(50)]),
        ("codes", [{"action": "type_scancodes", "scancodes": [123] * 20000}]),
    ]:
        runner = _install(monkeypatch, _CapturingRunner())
        with pytest.raises(console.ConsoleError) as excinfo:
            console.run_sequence(unrestricted_cfg, "vm1", steps=steps)
        message = str(excinfo.value)
        assert runner.calls == [], (
            f"the over-limit {label} plan spawned {len(runner.calls)} PowerShell "
            "process(es) before the rejection — the refusal must be pre-spawn"
        )
        assert "32766" in message and "command" in message, (
            f"the {label} rejection must name the command-line budget: {message!r}"
        )
        shapes.append((f"run_sequence {label} plan rejected pre-spawn", []))

    failures = {label: probs for label, probs in shapes if probs}
    assert failures == {}, (
        "AC13: shapes whose composed command line exceeds "
        f"{CMDLINE_LIMIT} or drops delivery: {failures}"
    )
