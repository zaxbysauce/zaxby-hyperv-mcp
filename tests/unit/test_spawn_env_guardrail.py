"""Phase 4.2 defect-class guardrail for issue #5 (FND-03).

Defect class: a child process spawned with ambient inheritance anywhere under
``src/`` — a subprocess/os/asyncio spawn call whose ``env=`` is missing,
``None``, a raw ``os.environ`` reference, or any expression other than an
invocation of the real ``child_env()`` sanitizer. Mere keyword presence is not
enough: ``env=None`` and ``env=os.environ`` reproduce the exact channel this
issue closes.

Census scope (extended after the PR review): the census is AST-based
(multi-line calls are covered by construction), recursive over every ``.py``
file under ``src/``, and resolves per-module imports, so aliased spawns
(``import subprocess as sp``), from-imported functions (``from subprocess
import run``), ``os.exec*``/``os.spawn*``, and
``asyncio.create_subprocess_*`` are all counted. A ``child_env(...)``
argument counts as sanitized only when it names the real sanitizer: an
attribute call must be ``pswindows.child_env(...)`` (``leaky.child_env()``
is flagged), and a bare name must be the sanitizer itself (``pswindows.py``)
or imported from it without a shadowing module-local ``def child_env``.

Known remaining blind spots (accepted, documented): dynamic forms an AST
census cannot see — ``getattr(subprocess, "run")(...)``, ``importlib``-driven
spawn modules, or a sanitizer-shaped helper that does not name ``child_env``.
Grep for new spawn spellings when introducing any of those.
"""

import ast
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src"

# The predicate's class definition (07-approved-plan "Anticipated Defect-Class
# Sweep"): subprocess.run/call/check_call/check_output/Popen, os.system/popen
# plus the full os.spawn*/os.exec* families, and the asyncio subprocess
# helpers. Aliased and from-imported spellings are resolved per module.
_SUBPROCESS_CALLS = frozenset({"Popen", "run", "call", "check_call", "check_output"})
_OS_CALLS = frozenset({"system", "popen"})
_ASYNCIO_CALLS = frozenset({"create_subprocess_exec", "create_subprocess_shell"})

# Known live spawn sites — the census must keep finding at least these, so
# coverage cannot silently shrink to zero (non-vacuity with a lower bound).
_KNOWN_SITES = {
    ("src/hyperv_mcp/pswindows.py", "subprocess.Popen"),
    ("src/hyperv_mcp/pswindows.py", "subprocess.run"),
    ("src/hyperv_mcp/server.py", "subprocess.run"),
}


def _import_map(tree: ast.AST) -> tuple[dict[str, str], dict[str, str], bool, bool]:
    """Per-module spawn-relevant import bindings.

    Returns (aliases, froms, child_env_imported, local_child_env_def):
    aliases maps a local name to its source module (``import subprocess as
    sp`` -> {"sp": "subprocess"}), froms maps a local name to
    "module.func" (``from subprocess import run as r`` -> {"r":
    "subprocess.run"}), child_env_imported says whether ``child_env`` was
    imported from a pswindows module, and local_child_env_def says whether
    this module defines its own ``child_env`` function (a shadowing def)."""
    aliases: dict[str, str] = {}
    froms: dict[str, str] = {}
    child_env_imported = False
    local_child_env_def = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in ("subprocess", "os", "asyncio"):
                    aliases[a.asname or a.name] = a.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for a in node.names:
                if module == "subprocess" and a.name in _SUBPROCESS_CALLS:
                    froms[a.asname or a.name] = f"subprocess.{a.name}"
                elif module == "os" and (
                    a.name in _OS_CALLS or a.name.startswith(("spawn", "exec"))
                ):
                    froms[a.asname or a.name] = f"os.{a.name}"
                elif module == "asyncio" and a.name in _ASYNCIO_CALLS:
                    froms[a.asname or a.name] = f"asyncio.{a.name}"
                elif module.endswith("pswindows") and a.name == "child_env":
                    child_env_imported = True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "child_env":
                local_child_env_def = True
    return aliases, froms, child_env_imported, local_child_env_def


def _module_ctx(tree: ast.AST, path: Path) -> dict:
    aliases, froms, child_env_imported, local_def = _import_map(tree)
    return {
        "aliases": aliases,
        "froms": froms,
        "child_env_imported": child_env_imported,
        "local_child_env_def": local_def,
        "is_pswindows_module": path.name == "pswindows.py",
    }


def _spawn_call_name(node: ast.Call, aliases: dict, froms: dict) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        mod = aliases.get(func.value.id, func.value.id)
        if mod == "subprocess" and func.attr in _SUBPROCESS_CALLS:
            return f"subprocess.{func.attr}"
        if mod == "os" and (
            func.attr in _OS_CALLS or func.attr.startswith(("spawn", "exec"))
        ):
            return f"os.{func.attr}"
        if mod == "asyncio" and func.attr in _ASYNCIO_CALLS:
            return f"asyncio.{func.attr}"
        return None
    if isinstance(func, ast.Name):
        return froms.get(func.id)
    return None


def _is_child_env_call(value: ast.expr, module_ctx: dict) -> bool:
    """True only for calls to the real sanitizer: module-qualified
    ``pswindows.child_env(...)``, or a bare ``child_env(...)`` in a module
    that either defines the sanitizer itself (pswindows.py) or imports it
    from pswindows without a shadowing local def."""
    if not isinstance(value, ast.Call):
        return False
    func = value.func
    if isinstance(func, ast.Attribute):
        return (
            isinstance(func.value, ast.Name)
            and func.value.id == "pswindows"
            and func.attr == "child_env"
        )
    if isinstance(func, ast.Name) and func.id == "child_env":
        if module_ctx["is_pswindows_module"]:
            return True
        return module_ctx["child_env_imported"] and not module_ctx["local_child_env_def"]
    return False


def _env_status(call: ast.Call, module_ctx: dict) -> str:
    for kw in call.keywords:
        if kw.arg == "env":
            if _is_child_env_call(kw.value, module_ctx):
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
        module_ctx = _module_ctx(tree, path)
        rel = path.relative_to(src_root.parent).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _spawn_call_name(node, module_ctx["aliases"], module_ctx["froms"])
                if name is not None:
                    sites.append((rel, node.lineno, name, _env_status(node, module_ctx)))
    return sorted(sites, key=lambda row: (row[0], row[1]))


def _violations() -> list[tuple[str, int, str, str]]:
    return [row for row in spawn_sites() if row[3] != "child_env"]


def _synthetic_root(tmp_path: Path, name: str, body: str) -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "mod.py").write_text(body, encoding="utf-8")
    return root


def test_spawn_census_is_populated() -> None:
    """Non-vacuity with a lower bound: the predicate must keep finding the
    three known spawn sites, so coverage cannot silently shrink to zero."""
    sites = spawn_sites()
    assert len(sites) >= len(_KNOWN_SITES), f"spawn-site census too small: {sites!r}"
    found = {(rel, name) for rel, _line, name, _status in sites}
    missing = _KNOWN_SITES - found
    assert not missing, f"known spawn sites missing from the census: {missing}"


def test_every_spawn_site_passes_child_env() -> None:
    bad = _violations()
    assert not bad, "spawn sites with ambient inheritance (missing/unsanitized env=):\n" + "\n".join(
        f"{rel}:{line} {name} env={status}" for rel, line, name, status in bad
    )


def test_synthetic_bad_spawn_is_flagged(tmp_path: Path) -> None:
    """Negative self-test: detection rot must fail loudly. A synthetic tree
    holding a spawn without env= has to be flagged."""
    body = "import subprocess\ndef bad():\n    subprocess.run(['x'])\n"
    rows = [r for r in spawn_sites(_synthetic_root(tmp_path, "neg", body)) if r[3] != "child_env"]
    assert rows, "synthetic env=-less spawn was NOT flagged — guardrail detection is rotten"


def test_env_status_classifications() -> None:
    """Direct _env_status checks for the missing/None/os.environ spellings."""
    ctx = {
        "aliases": {}, "froms": {}, "child_env_imported": False,
        "local_child_env_def": False, "is_pswindows_module": False,
    }

    def status(snippet: str) -> str:
        tree = ast.parse(snippet)
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        return _env_status(call, ctx)

    assert status("subprocess.run(['x'])") == "missing"
    assert status("subprocess.run(['x'], env=None)") == "non-compliant:Constant"
    assert status("subprocess.run(['x'], env=os.environ)") == "non-compliant:Attribute"
    assert status("subprocess.Popen(['x'], env=pswindows.child_env())") == "child_env"


def test_aliased_and_from_imported_spawns_are_counted(tmp_path: Path) -> None:
    """Alias resolution: sp.run, os.execl, from-imported run and asyncio
    spawns must all land in the census, not slip through as unknown names."""
    body = (
        "import subprocess as sp\n"
        "import os as o\n"
        "from subprocess import run as r1\n"
        "import asyncio\n"
        "def a():\n    sp.run(['x'])\n"
        "def b():\n    o.execl('x', 'x')\n"
        "def c():\n    r1(['x'])\n"
        "def d():\n    asyncio.create_subprocess_exec('x')\n"
    )
    rows = spawn_sites(_synthetic_root(tmp_path, "al", body))
    names = sorted(r[2] for r in rows)
    assert names == [
        "asyncio.create_subprocess_exec", "os.execl", "subprocess.run", "subprocess.run",
    ], names
    assert all(r[3] == "missing" for r in rows), rows


def test_shadowed_and_foreign_child_env_calls_not_compliant(tmp_path: Path) -> None:
    """A module-local ``def child_env`` shadowing the sanitizer, and a
    foreign receiver (``leaky.child_env()``), must both be flagged."""
    shadowed = (
        "import subprocess\n"
        "def child_env():\n    return {}\n"
        "def f():\n    subprocess.run(['x'], env=child_env())\n"
    )
    rows = [r for r in spawn_sites(_synthetic_root(tmp_path, "sh", shadowed)) if r[3] != "child_env"]
    assert rows, "shadowed local child_env was treated as the sanitizer"

    foreign = (
        "import subprocess\n"
        "import leaky\n"
        "def f():\n    subprocess.run(['x'], env=leaky.child_env())\n"
    )
    rows = [r for r in spawn_sites(_synthetic_root(tmp_path, "fr", foreign)) if r[3] != "child_env"]
    assert rows, "foreign leaky.child_env() receiver was treated as the sanitizer"


def test_sanitized_spellings_count_as_compliant(tmp_path: Path) -> None:
    """The compliant spellings (bare imported child_env, pswindows-qualified)
    must still classify as child_env — the hardening must not over-flag."""
    good = (
        "import subprocess\n"
        "from hyperv_mcp.pswindows import child_env\n"
        "def ok1():\n    subprocess.run(['x'], env=child_env())\n"
        "def ok2():\n    subprocess.Popen(['x'], env=pswindows.child_env())\n"
    )
    rows = spawn_sites(_synthetic_root(tmp_path, "ok", good))
    assert rows, "census matched nothing in the synthetic compliant tree"
    assert all(r[3] == "child_env" for r in rows), rows
