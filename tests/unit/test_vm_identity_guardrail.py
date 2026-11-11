"""Defect-class guardrail for the GUID-identity fix (issue #8, Phase 4.2).

Class: identity by a non-unique, mutable label. PR #4 fixed the targeting
half (-VMId everywhere); this fix closes the exclusion and late-binding
halves. These AST predicates keep them closed: a future name-keyed lock, a
stored-name follow-up leg, or a second name-resolution site fails here.

Every predicate fails against the base tree (37f9cd0, pre-fix) and passes
post-fix; the census style follows test_transfer_defect_class_guardrail.py.
"""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp"

# vm_lock keys that are NOT a resolved VM identity, with the reason each is
# safe (vm_create locks the not-yet-existing name; the in-script guard makes
# duplicates unreachable). Anything else must be a GUID.
# vm_create/vm_clone lock the not-yet-existing name; the shared in-script
# duplicate-name guard makes name collisions unreachable (issue #31 carries
# the same disclosed residual as vm_create).
# uia._read_console_exclusion (issue #140) locks (name, "console") — the
# CALLER-NAME spelling of the console-input exclusion key — deliberately and
# ONLY as the second identity of the same resolved VM: a cold (unhinted)
# console input keys _input_lock on the caller's name (console.py:477
# derives it from ref.id, which by-name paths set to the name), so the read
# must hold the name spelling too or an in-flight cold input can bump
# between the read's observation and its receipt stamp (plan critic Round 2,
# AC15). It is a console-namespace suffix key, not a VM-identity lock, and
# the function below is pinned to that exact shape by
# test_read_console_exclusion_lock_shape.
ALLOWED_LOCK_KEYS = {"vm_create", "vm_clone", "_read_console_exclusion"}


def test_read_console_exclusion_lock_shape():
    """The #140 allowlist entry above is narrowly earned: _read_console_
    exclusion must contain ONLY vm_lock calls keyed on a (x, "console")
    tuple in READ mode — never a bare-name VM key, never write mode. If this
    pin goes red the dual-identity exclusion has drifted out of the console
    namespace and the allowlist exemption is no longer justified."""
    tree = _tree(SRC / "uia.py")
    func = next((n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef)
                 and n.name == "_read_console_exclusion"), None)
    assert func is not None, "_read_console_exclusion vanished from uia.py"
    calls = [n for n in ast.walk(func)
             if isinstance(n, ast.Call) and _call_name(n) == "vm_lock"]
    assert calls, "the exclusion helper must take the console keys itself"
    for node in calls:
        assert node.args and isinstance(node.args[0], ast.Tuple), (
            "vm_lock here must be the (identity, 'console') tuple — a bare "
            "name key would re-open the #140 cold-input race under a "
            "VM-identity lock")
        elts = node.args[0].elts
        assert (len(elts) == 2
                and isinstance(elts[1], ast.Constant)
                and elts[1].value == "console"), (
            "the second tuple element must be the console namespace "
            "constant")
        modes = [kw for kw in node.keywords if kw.arg == "mode"]
        assert any(isinstance(kw.value, ast.Constant)
                   and kw.value.value == "read" for kw in modes), (
            "the exclusion holds the console key in READ mode (writers are "
            "the inputs it excludes)")



def _module_files():
    return sorted(SRC.glob("*.py"))


def _tree(path: Path):
    return ast.parse(path.read_text(encoding="utf-8"))


def _build_parents(tree):
    # Every node -> its immediate parent. The comprehension must iterate the
    # PARENT's children (ast.iter_child_nodes(parent)), not the module's —
    # the original form keyed only module-level children, so every nested
    # call resolved to "<module>" and the vm_create exemption was dead.
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _func_name_of(node, parents):
    scope = node
    while scope is not None and not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        scope = parents.get(scope)
    return scope.name if scope is not None else "<module>"


def _call_name(node):
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


# vm_lock first-argument expressions that ARE resolved identities (or are
# statically verifiable GUID keys). Anything else must sit inside a function
# listed in ALLOWED_LOCK_KEYS.
_ALLOWED_KEY_EXPRS = ("ref.id", "vm_id", "entry", "ctx")


def _lock_key_source(arg) -> str | None:
    """Render the vm_lock key expression's identity-bearing source, or None
    when the expression is not a simple identity form we can static-check."""
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
        return f"{arg.value.id}.{arg.attr}"
    if isinstance(arg, ast.Name):
        return arg.id
    if isinstance(arg, ast.Subscript) and isinstance(arg.slice, ast.Constant):
        return f"{ast.unparse(arg.value)}[{arg.slice.value!r}]"
    return None


@pytest.mark.parametrize("path", _module_files(), ids=lambda p: p.name)
def test_no_name_keyed_vm_locks(path):
    """vm_lock must never be keyed on a caller-supplied VM name.

    The predicate is GUID-shape-based, not spelling-based: any first argument
    that is not a recognized identity expression (ref.id / vm_id /
    entry["vm_id"] / ctx["vm_id"]) must sit inside an explicitly allowlisted
    function (vm_create locks the not-yet-existing VM's name).
    """
    tree = _tree(path)
    parents = _build_parents(tree)
    bad = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _call_name(node) == "vm_lock"):
            continue
        if not node.args:
            continue
        arg0 = node.args[0]
        # Issue #14 console dual-key: a tuple whose FIRST element is a
        # recognized resolved identity (the rest are constant suffixes like
        # "console") is still identity-keyed, not name-keyed.
        if isinstance(arg0, ast.Tuple) and arg0.elts:
            key_src = _lock_key_source(arg0.elts[0])
            if key_src is not None and all(
                isinstance(e, ast.Constant) for e in arg0.elts[1:]
            ) and any(
                key_src == allowed or key_src.startswith(allowed + "[")
                for allowed in _ALLOWED_KEY_EXPRS
            ):
                continue
        source = _lock_key_source(arg0)
        if source is not None and any(
            source == allowed or source.startswith(allowed + "[")
            for allowed in _ALLOWED_KEY_EXPRS
        ):
            # A recognized resolved-identity expression (ref.id / vm_id /
            # entry["vm_id"] / ctx["vm_id"]).
            continue
        # Anything else — a plain local (e.g. vm_create's `name`) or an
        # unrecognized expression — is a name-keyed lock unless this exact
        # function is allowlisted.
        func = _func_name_of(node, parents)
        if func not in ALLOWED_LOCK_KEYS:
            bad.append(f"{func}({ast.unparse(node.args[0])})")
    assert not bad, f"{path.name}: non-identity-keyed vm_lock calls: {bad}"


def test_guest_registry_legs_never_address_by_stored_name():
    """guestjobs/relay follow-up legs must target the stored GUID, never the
    stored (mutable) name — a rename between start and stop must not
    retarget the leg."""
    offenders = []
    for mod in ("guestjobs.py", "relay.py"):
        tree = _tree(SRC / mod)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _call_name(node) in ("run_guest_inner", "build_guest_script")):
                continue
            for arg in node.args:
                if (isinstance(arg, ast.Subscript) and isinstance(arg.slice, ast.Constant)
                        and arg.slice.value == "vm_name"):
                    offenders.append(f"{mod}:{_call_name(node)}")
    assert not offenders, f"follow-up legs addressing by stored name: {offenders}"


def test_psdirect_vm_target_runs_only_inside_vmident():
    """The shared name resolver must run in exactly one place (vmident.resolve);
    action scripts receive the pre-resolved GUID preamble instead."""
    callers = {}
    for path in _module_files():
        tree = _tree(path)
        parents = _build_parents(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in ("psdirect_vm_target", "psdirect_vm_target_id"):
                callers.setdefault(path.name, set()).add(_func_name_of(node, parents))
    allowed = {"guestexec.py", "vmident.py"}
    stray = {mod: fns for mod, fns in callers.items() if mod not in allowed}
    assert not stray, f"name resolver called outside guestexec/vmident: {stray}"


def test_vm_lock_module_importers_exist():
    """The exclusion registry stays importable and its VMBusy contract is the
    fail-fast one: a second acquisition of the SAME key raises."""
    from hyperv_mcp import vmlocks

    with pytest.raises(vmlocks.VMBusy):
        with vmlocks.vm_lock("guardrail-dup-key"):
            with vmlocks.vm_lock("Guardrail-Dup-Key"):
                pass
