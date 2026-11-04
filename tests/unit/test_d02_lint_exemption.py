"""Issue #75 AC1: the frozen d01 check file is lint-clean and unexempted.

RED at base b1ed4f7, GREEN after the #75 amendment. Two halves:

* ``ruff check --isolated --select I001,F401,B905`` — invoked as a subprocess
  against the venv's own ruff executable so the verdict is independent of
  whatever config the surrounding project carries — reports ZERO violations
  for tests/unit/test_d01_screenshot_decode.py once the frozen file is
  amended: sorted imports (I001), no unused ``io`` import (F401), and an
  explicit ``strict=`` on the all-65,536-values equivalence ``zip`` (B905 —
  without it the byte comparison truncates to the shorter operand, so a
  decode with the wrong pixel count could still report zero mismatches).
* pyproject.toml carries NO ``[tool.ruff.lint.per-file-ignores]`` entry whose
  path is tests/unit/test_d01_screenshot_decode.py — the permanent blanket
  exemption (base pyproject.toml:141) is removed rather than widened.

The fix amends the frozen file under the sanctioned CHECK_WRONG procedure;
these checks pin the post-amendment state.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
D01_REL = "tests/unit/test_d01_screenshot_decode.py"


def _ruff_exe() -> Path:
    for candidate in (ROOT / ".venv" / "Scripts" / "ruff.exe", ROOT / ".venv" / "bin" / "ruff"):
        if candidate.exists():
            return candidate
    raise AssertionError(
        "AC1: no ruff executable found under .venv (dev extras missing?); the "
        "config-independent lint check cannot run"
    )


def test_d01_file_has_no_lint_violations_under_isolated_ruff():
    """AC1a: config-independent ruff run on the frozen d01 file reports nothing."""
    proc = subprocess.run(
        [str(_ruff_exe()), "check", "--isolated", "--select", "I001,F401,B905", D01_REL],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        "AC1: isolated ruff still reports violations in the frozen d01 file "
        f"(exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
    )


def _per_file_ignore_keys() -> set[str]:
    """Every key of [tool.ruff.lint.per-file-ignores], posix-normalized."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if sys.version_info >= (3, 11):
        import tomllib

        data = tomllib.loads(text)
        section = data.get("tool", {}).get("ruff", {}).get("lint", {})
        return {k.replace("\\", "/") for k in section.get("per-file-ignores", {})}
    # Python 3.10 fallback (tomllib is 3.11+): scan the section body between
    # the [tool.ruff.lint.per-file-ignores] header and the next header for
    # quoted key paths.
    keys: set[str] = set()
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped == "[tool.ruff.lint.per-file-ignores]"
            continue
        if in_section and stripped.startswith('"'):
            keys.add(stripped.split('"')[1].replace("\\", "/"))
    return keys


def test_pyproject_has_no_per_file_ignore_entry_for_d01():
    """AC1b: the permanent per-file-ignores exemption for the d01 file is gone."""
    keys = _per_file_ignore_keys()
    assert D01_REL not in keys, (
        "AC1: pyproject.toml still carries a per-file-ignores entry for the "
        f"frozen d01 file (current keys: {sorted(keys)})"
    )
