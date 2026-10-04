"""Phase 4.2 defect-class guardrail for issue #5 (FND-03).

Defect class: a child process spawned with ambient inheritance anywhere under
``src/`` — a subprocess/os spawn call whose ``env=`` is missing, ``None``, a
raw ``os.environ`` reference, or any expression other than a ``child_env()``
invocation. Mere keyword presence is not enough: ``env=None`` and
``env=os.environ`` reproduce the exact channel this issue closes.

The census is AST-based (multi-line calls are covered by construction) and
recursive over every ``.py`` file under ``src/``, so any future spawn site —
bare ``child_env()``, module-qualified ``pswindows.child_env()``, or an
unsanitized spelling — is enforced by the unit suite. The archived census
script ``repro/census_spawn_env.py`` imports this module's predicate, so the
08a sweep counts and this guardrail can never drift apart.
"""

import ast
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src"

# The predicate's class definition (07-approved-plan "Anticipated Defect-Class
# Sweep"): qualified calls only. Direct imports of these names, os.exec*,
# and asyncio subprocess helpers do not occur anywhere under src/ (grep-
# verified at the sweep; add them here if they are ever introduced).
_SUBPROCESS_CALLS = frozenset({"Popen", "run", "call", "check_call", "check_output"})
_OS_CALLS = frozenset({"system", "popen"})


def _spawn_call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id == "subprocess" and func.attr in _SUBPROCESS_CALLS:
            return f"subprocess.{func.attr}"
        if func.value.id == "os" and (func.attr in _OS_CALLS or func.attr.startswith("spawn")):
            return f"os.{func.attr}"
    return None


def _is_child_env_call(value: ast.expr) -> bool:
    return (
        isinstance(value, ast.Call)
        and (
            (isinstance(value.func, ast.Name) and value.func.id == "child_env")
            or (isinstance(value.func, ast.Attribute) and value.func.attr == "child_env")
        )
    )


def _env_status(call: ast.Call) -> str:
    for kw in call.keywords:
        if kw.arg == "env":
            if _is_child_env_call(kw.value):
                return "child_env"
            return f"non-compliant:{type(kw.value).__name__}"
    return "missing"


def spawn_sites(src_root: Path = _SRC_ROOT) -> list[tuple[str, int, str, str]]:
    """One row per spawn call: (path relative to src parent, line, name, env status)."""
    sites: list[tuple[str, int, str, str]] = []
    for path in sorted(src_root.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:  # pragma: no cover - src/ always parses
            raise AssertionError(f"census cannot parse {path}: {exc}") from exc
        rel = path.relative_to(src_root.parent).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _spawn_call_name(node)
                if name is not None:
                    sites.append((rel, node.lineno, name, _env_status(node)))
    return sorted(sites, key=lambda row: (row[0], row[1]))


def _violations() -> list[tuple[str, int, str, str]]:
    return [row for row in spawn_sites() if row[3] != "child_env"]


def test_spawn_census_is_populated() -> None:
    """Non-vacuity: the predicate must actually find spawn sites."""
    sites = spawn_sites()
    assert sites, "spawn-site census matched nothing under src/ — guardrail is vacuous"


def test_every_spawn_site_passes_child_env() -> None:
    bad = _violations()
    assert not bad, "spawn sites with ambient inheritance (missing/unsanitized env=):\n" + "\n".join(
        f"{rel}:{line} {name} env={status}" for rel, line, name, status in bad
    )
