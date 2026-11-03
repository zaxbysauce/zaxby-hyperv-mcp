"""Issue #71 AC1 acceptance check: the stdio->controller auto-start budget
is derived from measurement, and the timeout message names what the operator
needs (the controller log PATH and the wait that elapsed).

Budget derivation (measured on the dev box, issue #71): a spawned
streamable-HTTP controller accepts connections in ~1.1 s idle and 2.2-3.9 s
under load, and the Windows spawn path can additionally route through the
WMI/CIM breakaway fallback. The frozen AUTOSTART_WAIT_S = 15.0 at base
leaves under 4x margin over the loaded worst case; 30.0 s restores ~8x
margin, so the check pins >= 30.0.

Message contract: after the fix, _autostart_timeout_message includes the
observed wait (a waited_s parameter), the budget, and interpolates
_controller_log_path(port) so the operator gets the exact file. RED at base
92854d9: AUTOSTART_WAIT_S is 15.0 (assert 15.0 >= 30.0 fails) and the
timeout message names neither a log path nor the budget (it says only "check
the controller log for this port"). GREEN after the fix: budget >= 30 s and
the message carries host:port, a seconds figure, the word "budget", and a
path-like token (or the phrase "controller log path").

test_refusal_precedes_the_wait_deadline is a keep-green structural guard
(green at base by design): the tokenless-spawn refusal CONTRACT is already
runtime-tested in tests/unit/test_b03_feedback_fixes.py (fail-fast tests
for the agents/shared-token/whitespace/custom-env variants), so this file
does not duplicate it -- it only pins the source order (fail-fast refusal
before the port-wait deadline) so the budget/message work cannot silently
reorder it.

Deterministic: constant comparison plus pure string/inspect work; no
controller is spawned, no socket touched, no wall clock read.
"""

from __future__ import annotations

import inspect
import os
import re
from pathlib import Path

from hyperv_mcp import stdio_proxy


def test_budget_derived_from_measurement():
    """AC1: AUTOSTART_WAIT_S is at least 30 s (~8x the measured loaded
    controller-ready time of 2.2-3.9 s; the base 15 s is under 4x)."""
    assert stdio_proxy.AUTOSTART_WAIT_S >= 30.0, (
        f"issue #71: AUTOSTART_WAIT_S={stdio_proxy.AUTOSTART_WAIT_S} is not "
        "derived from the measured controller-ready times (idle ~1.1 s, "
        "loaded 2.2-3.9 s); the budget must be >= 30.0 s"
    )


def _timeout_message(waited_s: float, log_path: str) -> str:
    """The timeout message for 127.0.0.1:55999, adapted to the function's
    arity: the fix adds observed-wait and log-path parameters; at base only
    the (host, port) form exists. The RED/GREEN signal lives in the message
    text, never in the call shape."""
    function = stdio_proxy._autostart_timeout_message
    positional = [
        parameter
        for parameter in inspect.signature(function).parameters.values()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 4:
        return function("127.0.0.1", "55999", waited_s, log_path)
    if len(positional) == 3:
        return function("127.0.0.1", "55999", waited_s)
    return function("127.0.0.1", "55999")


def test_timeout_message_names_log_path_and_wait():
    """AC1 (message): the auto-start timeout message interpolates the OBSERVED
    wait (distinct from the budget), the budget, and the EXACT controller log
    path it hands the operator (issue #71; plan-critic round 1 blocker B1:
    any-seconds-figure + any-path-token pins passed without the contract)."""
    observed_log = str(
        Path(os.environ.get("LOCALAPPDATA", os.getcwd())) / "hyperv-mcp"
        / "http-controller-55999.log"
    )
    message = _timeout_message(3.0, observed_log)
    assert "controller log" in message, (
        f"issue #71: the timeout message lost the controller-log pointer: {message!r}"
    )
    assert "127.0.0.1:55999" in message, (
        f"issue #71: the timeout message lost the host:port: {message!r}"
    )
    # The OBSERVED wait (3 s) must be distinguishable from the BUDGET (>= 30 s):
    # a message that prints only the budget passes the old any-figure pin while
    # telling the operator nothing about how long the attempt actually ran.
    assert re.search(r"\b3(?:\.0)?s\b", message), (
        "issue #71: the timeout message does not report the OBSERVED wait "
        f"(waited_s=3.0 was injected); got: {message!r}"
    )
    assert "budget" in message.lower(), (
        "issue #71: the timeout message does not name the auto-start budget "
        f"(AUTOSTART_WAIT_S); operators cannot tell a wait from a ceiling: {message!r}"
    )
    assert observed_log in message, (
        "issue #71: the timeout message does not interpolate the EXACT "
        f"controller log path ({observed_log}); got: {message!r}"
    )


def test_every_budget_expiry_site_routes_through_the_message():
    """AC1 (coverage, plan-critic round 1 blocker B1): every budget-expiry
    exit in ensure_controller -- the POSIX port-wait expiry, the spawner
    subprocess.TimeoutExpired branch, and the Windows port-wait expiry --
    must route through _autostart_timeout_message with the observed wait
    and the controller log path, so none of them can retain the old
    bare-timeout diagnostic. Source-order pin (the branches are not
    drivable without a hung spawner). The spawner's own failure exit (a
    bad marker) keeps its distinct diagnostic; it is not a budget
    expiry."""
    source = inspect.getsource(stdio_proxy.ensure_controller)
    calls = len(re.findall(r"_autostart_timeout_message\(", source))
    assert calls == 3, (
        "issue #71: ensure_controller's three budget-expiry exits (the "
        "POSIX port-wait expiry, the spawner subprocess.TimeoutExpired "
        "branch, and the Windows port-wait expiry) must all route through "
        f"_autostart_timeout_message; found {calls} call sites (expected "
        "exactly 3 — the spawner's own marker-failure exit keeps its "
        "distinct diagnostic and is not a budget expiry)"
    )
    observed_wait_uses = len(re.findall(
        r"time\.monotonic\(\) - wait_started, log_path",
        source,
    ))
    assert observed_wait_uses >= 2, (
        "issue #71: both port-wait expiry sites must report the OBSERVED "
        f"wait (time.monotonic() - wait_started); found {observed_wait_uses}"
    )
    expired_branch = re.search(
        r"except subprocess\.TimeoutExpired.*?raise ProxyRefused",
        source,
        re.DOTALL,
    )
    assert expired_branch is not None, (
        "the spawner subprocess.TimeoutExpired branch moved or vanished; "
        "update this coverage pin alongside it"
    )
    assert "_autostart_timeout_message" in expired_branch.group(0), (
        "issue #71: the spawner TimeoutExpired branch does not route through "
        "_autostart_timeout_message; it must carry the observed wait and the "
        "controller log path like every other budget-expiry exit"
    )


def test_refusal_precedes_the_wait_deadline():
    """Keep-green source-order guard (issue #71 AC3 context): the
    tokenless-spawn ProxyRefused refusal is raised BEFORE the port-wait
    deadline is set, so a tokenless environment fails fast instead of
    sitting out the whole budget. The runtime contract is pinned by
    tests/unit/test_b03_stdio_proxy.py; this pins only the ordering."""
    source = inspect.getsource(stdio_proxy.ensure_controller)
    guard = source.find("not os.environ.get(cfg.http.token_env")
    assert guard != -1, (
        "the tokenless-spawn guard moved: ensure_controller no longer checks "
        "cfg.http.token_env in this environment"
    )
    raise_site = source.find("raise ProxyRefused", guard)
    assert raise_site != -1, (
        "the tokenless-spawn guard no longer raises ProxyRefused"
    )
    deadline = source.find("deadline = time.monotonic() + AUTOSTART_WAIT_S")
    assert deadline != -1, (
        "the port-wait deadline line moved in ensure_controller; update "
        "this order pin alongside it"
    )
    assert raise_site < deadline, (
        "issue #71: the fail-fast tokenless-spawn refusal must run BEFORE "
        "the AUTOSTART_WAIT_S deadline is set, or tokenless environments "
        "wait out the whole budget per spawn attempt"
    )
