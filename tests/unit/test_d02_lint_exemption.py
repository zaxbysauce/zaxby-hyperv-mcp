"""Issue #75 AC1: the frozen d01 check file is lint-clean and unexempted.

RED at base b1ed4f7, GREEN after the #75 amendment. Two halves:

* ``ruff check --isolated --select I001,F401,B905 --target-version py310`` —
  invoked as a subprocess against the repo .venv's own ruff executable
  (preferred; PATH is the fallback when no repo .venv exists, per CUB-lint-37)
  so the verdict is independent of whatever config the surrounding project
  carries — reports ZERO violations
  for tests/unit/test_d01_screenshot_decode.py once the frozen file is
  amended: sorted imports (I001), no unused ``io`` import (F401), and an
  explicit ``strict=`` on the all-65,536-values equivalence ``zip`` (B905 —
  without it the byte comparison truncates to the shorter operand, so a
  decode with the wrong pixel count could still report zero mismatches;
  ``--target-version py310`` because an isolated run otherwise defaults to
  py39, where B905 does not fire at all — CUB-lint-42).
* pyproject.toml carries NO ``[tool.ruff.lint.per-file-ignores]`` entry that
  matches tests/unit/test_d01_screenshot_decode.py — the permanent blanket
  exemption (base pyproject.toml:141) is removed rather than widened, and no
  glob-form key may re-silence the file (PRR-107/CUB-lint-80: every key is
  fnmatch-tested against the d01 path, not compared for exact equality).

The fix amends the frozen file under the sanctioned CHECK_WRONG procedure;
these checks pin the post-amendment state.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
D01_REL = "tests/unit/test_d01_screenshot_decode.py"


def _ruff_exe() -> Path:
    # The repo .venv is the first choice, but CI installs dev extras into the
    # runner environment (no repo .venv), where ruff resolves from PATH.
    import shutil

    for candidate in (ROOT / ".venv" / "Scripts" / "ruff.exe", ROOT / ".venv" / "bin" / "ruff"):
        if candidate.exists():
            return candidate
    found = shutil.which("ruff")
    if found:
        return Path(found)
    raise AssertionError(
        "AC1: no ruff executable found (repo .venv or PATH; dev extras missing?); "
        "the config-independent lint check cannot run"
    )


def test_d01_file_has_no_lint_violations_under_isolated_ruff():
    """AC1a: config-independent ruff run on the frozen d01 file reports nothing."""
    # CUB-lint-42: --target-version py310 — with --isolated the target
    # defaults to py39, where B905 does not fire, so a strict=-removed zip
    # would pass unnoticed.
    proc = subprocess.run(
        [
            str(_ruff_exe()), "check", "--isolated",
            "--select", "I001,F401,B905", "--target-version", "py310", D01_REL,
        ],
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
    # PRR-107/CUB-lint-80: exact-key equality misses a glob-form entry that
    # re-silences the file — EVERY key is fnmatch-tested against the d01
    # path (tomllib already normalizes quote styles on the 3.11+ path).
    from fnmatch import fnmatch

    keys = _per_file_ignore_keys()
    matching = sorted(k for k in keys if fnmatch(D01_REL, k))
    assert not matching, (
        "AC1: pyproject.toml carries a per-file-ignores entry matching the "
        f"frozen d01 file (exact or glob form; matching keys: {matching}, "
        f"all keys: {sorted(keys)})"
    )
