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
ALLOWED_LOCK_KEYS = {"vm_create"}



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
        source = _lock_key_source(node.args[0])
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
