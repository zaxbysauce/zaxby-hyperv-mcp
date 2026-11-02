"""Frozen acceptance checks for issue #110: the built wheel must ship the
in-session UIA helper (hyperv_mcp/guest/uia_helper.ps1), and the check
must read the BUILT ARTIFACT — a wheel deliberately built with the guest
package excluded must FAIL it while the source tree stays intact.

Token -> AC map:
  test_wheel_ships_the_uia_helper
      AC1: hatchling's PEP 517 build_wheel run over a copy of the project
      produces a wheel whose archive listing contains
      hyperv_mcp/guest/uia_helper.ps1 with nonzero size.
  test_helper_check_discriminates_a_wheel_missing_the_entry
      AC2: rebuilding the copy after adding
      exclude = ["src/hyperv_mcp/guest/**"] to
      [tool.hatch.build.targets.wheel] drops the entry from the archive,
      and the AC1 assertion fails on that mutated wheel — proving the
      check is fed by the wheel listing, not by a source-tree is_file()
      pass-through.

The builds run inside tmp_path over a COPY of pyproject.toml + src/ (+ the
files the build references), so the repository tree is never written to
and the discriminating leg's mutated pyproject never leaks anywhere.
Skips when hatchling is not importable (CI installs the dev dependencies,
which carry hatchling as the build backend once the issue lands).
"""

import os
import shutil
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER_ENTRY = "hyperv_mcp/guest/uia_helper.ps1"


@contextmanager
def _chdir(target: Path):
    """contextlib.chdir() equivalent for Python 3.10 (chdir landed in
    3.11; CI runs the 3.10 matrix leg, plan-critic round-1 blocker 2)."""
    previous = os.getcwd()
    os.chdir(target)
    try:
        yield
    finally:
        os.chdir(previous)


def _copy_project(dst: Path) -> None:
    """A buildable copy of the project (no __pycache__, nothing mutated)."""
    shutil.copy2(REPO_ROOT / "pyproject.toml", dst / "pyproject.toml")
    shutil.copytree(
        REPO_ROOT / "src", dst / "src", ignore=shutil.ignore_patterns("__pycache__")
    )
    # Everything the build references: [project] readme and license-files,
    # plus the wheel target's force-include of scripts/soak_bench.py.
    for name in ("README.md", "LICENSE", "NOTICE"):
        source = REPO_ROOT / name
        if source.is_file():
            shutil.copy2(source, dst / name)
    if (REPO_ROOT / "scripts").is_dir():
        shutil.copytree(
            REPO_ROOT / "scripts",
            dst / "scripts",
            ignore=shutil.ignore_patterns("__pycache__"),
        )


def build_wheel_into(dest: Path) -> Path:
    """Build the wheel with hatchling's PEP 517 hook from a copied tree.

    chdir's into the copy for the build (hatchling resolves the project
    from the working directory) and returns the built wheel's path.
    """
    try:
        from hatchling.build import build_wheel
    except ImportError:
        pytest.skip("hatchling not available")
    src_tree = dest / "project"
    src_tree.mkdir(parents=True)
    _copy_project(src_tree)
    with _chdir(src_tree):
        name = build_wheel(str(dest), None, None)
    return dest / name


def assert_helper_ships(wheel_path: Path) -> None:
    """The AC1 assertion, shared by both legs of the pair: the archive
    listing carries the helper entry with nonzero size."""
    with zipfile.ZipFile(wheel_path) as wheel:
        infos = {info.filename: info for info in wheel.infolist()}
        assert HELPER_ENTRY in infos, (
            f"{wheel_path.name} does not ship {HELPER_ENTRY} "
            f"({len(infos)} archive entries)"
        )
        assert infos[HELPER_ENTRY].file_size > 0


def test_wheel_ships_the_uia_helper(tmp_path):
    wheel = build_wheel_into(tmp_path)
    assert_helper_ships(wheel)


def test_helper_check_discriminates_a_wheel_missing_the_entry(tmp_path):
    try:
        from hatchling.build import build_wheel
    except ImportError:
        pytest.skip("hatchling not available")
    project = tmp_path / "project"
    project.mkdir()
    _copy_project(project)
    # The discriminating mutation: the wheel target stops packaging the
    # guest package while the source tree stays intact.
    pyproject = project / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    marker = 'packages = ["src/hyperv_mcp"]'
    assert marker in text, "wheel target's packages line moved; update the pin"
    pyproject.write_text(
        text.replace(
            marker,
            marker + '\nexclude = ["src/hyperv_mcp/guest/**"]',
            1,
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    out.mkdir()
    with _chdir(project):
        name = build_wheel(str(out), None, None)
    mutated_wheel = out / name
    with zipfile.ZipFile(mutated_wheel) as wheel:
        assert HELPER_ENTRY not in wheel.namelist(), (
            "the exclude mutation failed to drop the helper from the wheel; "
            "the discrimination leg no longer discriminates"
        )
    with pytest.raises(AssertionError):
        assert_helper_ships(mutated_wheel)
