"""Phase 4.2 guardrail (issue #43, trace 12): choke census + ReadLine census.

Defect class: implicitly-local Hyper-V addressing in generated PowerShell.
The load-bearing rule is call-flow: every ``pswindows.run_ps(`` reference in
``src/`` must live in the sanctioned choke set (the per-module ``_run``
helpers + the transport itself + the two deliberate exemptions). A generator
that calls run_ps directly composes no remote hop and silently re-introduces
the class. The ReadLine census pins the stdin-read surface: outside the
composer preamble and the two pinned local-mode emissions, a stray
``[Console]::In.ReadLine()`` inside a remote block would hang every remote
call (a remote scriptblock cannot read local stdin).

RED on the pre-fix tree by construction: generators call run_ps directly
(enclosing functions outside the allowlist) and the ReadLine reads live at
guestexec.py:72 / console.py:503 outside any sanctioned form.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp"

# (file, function) pairs allowed to reference run_ps. Everything else must
# route through a choke so the remote hop composes above the spawn boundary.
RUN_PS_ALLOWLIST = {
    ("pswindows.py", "run_ps"),            # the transport itself
    ("pswindows.py", "compose_remote"),    # calls the transport
    ("lifecycle.py", "_run"),
    ("console.py", "_run"),
    ("vmident.py", "_run"),
    ("media.py", "_run"),
    ("diagnostics.py", "_run"),
    ("filetransfer.py", "_run"),
    ("filetransfer.py", "_run_transfer"),
    ("guestexec.py", "_run_inner"),
    ("relay.py", "_run_forward"),
    ("server.py", "_powershell_provenance"),  # deliberate: probes the LOCAL interpreter
    ("server.py", "main"),                    # deliberate: --check-env reachability probe
}

# [Console]::In.ReadLine() may appear only inside these functions.
READLINE_ALLOWLIST = {
    ("pswindows.py", "_remote_parts"),     # composer preamble emission
    ("guestexec.py", "psdirect_prefix"),   # pinned local-mode emission
    ("console.py", "type_text"),           # pinned local-mode inline emission
}


def _enclosing_function(lines: list[str], idx: int) -> str:
    for j in range(idx, -1, -1):
        m = re.match(r"\s*def (\w+)\(", lines[j])
        if m:
            return m.group(1)
    return "<module>"


def census_run_ps() -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for py in sorted(SRC.glob("*.py")):
        if py.name == "__init__":
            continue
        lines = py.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if "run_ps(" in line and "def run_ps" not in line:
                if re.search(r"\bpswindows\.run_ps\(", line) or (
                    py.name == "pswindows.py" and re.search(r"(?<!\w)run_ps\(", line)
                ):
                    out.append((py.name, _enclosing_function(lines, i), i + 1))
    return out


def census_readline() -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for py in sorted(SRC.glob("*.py")):
        lines = py.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if "[Console]::In.ReadLine()" in line:
                out.append((py.name, _enclosing_function(lines, i), i + 1))
    return out


def census_run_ps_from_imports() -> list[tuple[str, int]]:
    """Modules that import run_ps directly (bypasses the pswindows.run_ps(
    reference the main census counts — MA-7/cubic C19 blind spot)."""
    out: list[tuple[str, int]] = []
    for py in sorted(SRC.glob("*.py")):
        if py.name == "pswindows.py":
            continue
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines()):
            if re.search(r"from\s+\.?pswindows\s+import[^#]*run_ps", line):
                out.append((py.name, i + 1))
    return out


def test_every_run_ps_reference_is_choked():
    rows = census_run_ps()
    assert rows, "census must find the transport references"
    offenders = [r for r in rows if (r[0], r[1]) not in RUN_PS_ALLOWLIST]
    assert offenders == [], (
        "pswindows.run_ps referenced outside the sanctioned choke set "
        "(implicitly-local Hyper-V addressing class): "
        f"{offenders}"
    )
    importers = census_run_ps_from_imports()
    assert importers == [], (
        "run_ps imported directly (the main census cannot see bare "
        f"run_ps( call sites in these modules): {importers}"
    )


# Exact per-function ReadLine budgets: a NEW read added to a remote branch
# of an allowlisted function would hang every remote call (a remote
# scriptblock cannot read local stdin), so function-level membership alone
# is not enough (cubic C18).
READLINE_BUDGETS = {
    ("pswindows.py", "_remote_parts"): 2,      # hostpw line + param-loop f-string
    ("guestexec.py", "psdirect_prefix"): 1,    # pinned local-mode emission
    ("console.py", "type_text"): 1,            # pinned local-mode inline emission
}


def test_readline_surface_is_pinned():
    rows = census_readline()
    offenders = [r for r in rows if (r[0], r[1]) not in READLINE_BUDGETS]
    assert offenders == [], (
        "[Console]::In.ReadLine() outside the composer preamble / pinned "
        f"local-mode emissions: {offenders}"
    )
    counts: dict[tuple[str, str], int] = {}
    for fname, fn, _line in rows:
        counts[(fname, fn)] = counts.get((fname, fn), 0) + 1
    for key, budget in READLINE_BUDGETS.items():
        actual = counts.get(key, 0)
        assert actual == budget, (
            f"{key}: expected exactly {budget} ReadLine emission(s), found "
            f"{actual} — a new read in a remote branch would hang remote calls"
        )
