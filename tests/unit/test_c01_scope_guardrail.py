"""Issue #59 AC1 — AST guardrail over the issue-#14 VM-lock scope table.

The PR #58 review found that a revert probe flipping two scope-table mode
assignments back to write scope left the suite fully green: only two sites
were behaviorally pinned. This guardrail freezes the table so the sites
cannot silently drift:

  1. every read-scope site named by the issue-#14 scope table still passes
     an explicit ``mode="read"`` to ``vm_lock`` (direct sites) or to
     ``run_guest_inner`` (job/evidence legs), and
  2. the write-default modules (lifecycle, media, harvest, repair) contain
     NO ``mode="read"`` argument anywhere — a write-scope module can never
     silently downgrade to read scope.

The guardrail asserts CURRENT compliance, so it is GREEN at the fix head
(the file itself is NEW-SURFACE: absent at base, exit-4 RED signature at
base; discrimination is demonstrated by the Phase 4.5 revert probe, which
flips one assignment and must be killed by this guardrail).
"""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp"

# issue-#14 scope table: read-scope sites. (module, function) -> minimum
# number of vm_lock / run_guest_inner calls inside that function that carry
# the literal kwarg mode="read".
READ_TABLE: dict[tuple[str, str], int] = {
    ("filetransfer", "guest_put"): 1,
    ("filetransfer", "guest_get"): 1,
    ("filetransfer", "guest_read_file"): 1,
    ("filetransfer", "guest_list_dir"): 1,
    ("guestexec", "guest_run_ps"): 1,
    ("guestexec", "guest_run"): 1,
    ("guestexec", "victim_run_ps"): 1,
    ("diagnostics", "diagnose_report"): 2,
    ("diagnostics", "wait_guest_recovery"): 1,
    ("guestjobs", "job_start"): 1,
    ("guestjobs", "job_status"): 1,
    ("guestjobs", "job_output"): 1,
    ("guestjobs", "job_stop"): 1,
    ("evidence", "capture_evidence"): 1,
}

# write-default modules: no mode="read" may appear anywhere in the file.
WRITE_DEFAULT_MODULES = ("lifecycle.py", "media.py", "harvest.py", "repair.py")


def _read_kwargs_in_function(path: Path, func_name: str) -> int:
    """Count vm_lock / run_guest_inner calls carrying a literal mode="read"
    kwarg inside the named top-level function of the module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    count = 0
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                func = sub.func
                callee = (
                    func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                )
                if callee not in ("vm_lock", "run_guest_inner"):
                    continue
                for kw in sub.keywords:
                    if (
                        kw.arg == "mode"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value == "read"
                    ):
                        count += 1
    return count


def test_read_scope_sites_pass_read_mode():
    """Every issue-#14 read-scope site still passes mode="read" (AST pin of
    the scope table)."""
    for (module, func), minimum in READ_TABLE.items():
        path = SRC / f"{module}.py"
        assert path.exists(), f"missing module {module}.py"
        count = _read_kwargs_in_function(path, func)
        assert count >= minimum, (
            f"{module}.{func}: found {count} mode=read lock legs (need {minimum})"
        )


def test_write_default_modules_have_no_read_mode():
    """The write-default modules carry no mode="read" argument anywhere —
    a write-scope module can never silently downgrade to read scope."""
    for filename in WRITE_DEFAULT_MODULES:
        path = SRC / filename
        assert path.exists(), f"missing module {filename}"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.keyword)
                and node.arg == "mode"
                and isinstance(node.value, ast.Constant)
                and node.value.value == "read"
            ):
                pytest.fail(
                    f"{filename} contains a mode=read kwarg near ast line {node.lineno}"
                )
