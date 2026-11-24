"""Issue #167 AC1 - the generation write-form guard.

RED at base, GREEN after the fix: at the base commit the fail-open write
sites carry no disclosure tag, so the tag assertions below fail with the AC1
marker; once each disclosed site is tagged (and the sets are still exactly
the disclosed ones), every assertion passes.

Five properties are pinned, and each is a property of the SEMANTICS of a
site rather than of a line number, so the pins survive line drift, insertion
and reordering:

1. IDENTITY of the keyword-local fail-open set. A write whose ``generation``
   argument is a boolean-or expression that can yield ``None`` is
   fail-open: the store treats ``generation=None`` as "no ownership
   predicate", so the write lands on whichever executor owns the row. The
   four disclosed sites are identified by (enclosing function, called
   method, transition event): the inline heartbeat, the detached
   heartbeat, the post-body failed terminal and the post-body completed
   terminal. The set must equal those four, with one site each - a count
   alone would accept a different tagged site in place of a disclosed one.

2. IDENTITY of the ALIASED fail-open set. A write whose ``generation``
   argument is a local name is fail-open when that local can hold ``None``,
   which the classifier decides by tracing the local's assignments through
   the enclosing scopes. The disclosed alias is ``complete_inline``'s
   captured generation, which reaches two transition writes. Its assignment
   must carry the alias disclosure tag.

3. IDENTITY of the PARAMETER pass-through set, pinned in two layers. A
   write whose ``generation`` argument is a bare name that resolves to a
   FUNCTION PARAMETER of the enclosing function (not to a local
   assignment) is invisible to both classes above: they only see the local
   shape at the write site, and a parameter's value arrives from callers
   the write site knows nothing about (the independent critic's executed
   bypass). The guard therefore pins, separately:
   - the ADMITTING set: parameter sites whose signature can carry ``None``
     (an annotation that admits ``None`` - ``int | None``,
     ``Optional[...]``, any union containing ``None`` - or a ``None``
     default value). Pinned: the write inside
     ``_reconcile_interrupted_commit_core`` (parameter
     ``generation: int | None``) and the write inside ``_safe_transition``
     (parameter ``generation: int | None = None``).
   - the REACHABLE set: admitting sites for which some in-module call site
     of the enclosing function binds a ``None``-capable expression to that
     parameter - positional index AND keyword binding are both resolved,
     and an unbound no-default parameter, a ``*args``/``**kwargs`` spread
     or a bare reference to the function (passed around as a value) is
     treated conservatively as ``None``-capable. Pinned: the
     ``_safe_transition`` write alone - the two disclosed post-body
     terminals in ``_execute_body`` feed it ``generation or None``.
     ``_reconcile_interrupted_commit_core``'s two callers pass the
     fail-closed ``int(... or 0)`` form, so its site is admitting but NOT
     reachable today; the critic's mutant (the wrapper feeding bare
     ``op_ctx.get("generation")``) moves it into the reachable set and the
     pinned-identity assertion fires.

4. DISCLOSURE. Every keyword-local fail-open site carries the
   ``generation-write-form: fail-open-disclosed`` tag on its own line, the
   aliased assignment carries ``generation-write-form: fail-open-aliased``,
   every REACHABLE parameter site carries
   ``generation-write-form: fail-open-parameter`` and every
   admitting-but-unreachable parameter site carries the weaker
   ``generation-write-form: fail-open-parameter-admits-none`` (so the two
   cases stay distinguishable in the source).

Mutation that must kill this check: an untagged fifth fail-open site added
to ``operations.py`` (the identity set check fires); a fifth site added
WITH the tag (the identity set check fires - it is not one of the four
disclosed identities); one disclosed site converted while a different
tagged fail-open line replaces it (the identity check fires - the count
stays at four); the aliased capture re-introduced as a plain
``generation or None`` assignment (the alias set check fires); a caller of
an admitting parameter switched to a ``None``-capable feed such as
``op_ctx.get("generation")`` (the parameter reachable-set check fires).

Note on the reachability of the class: production row constructors mint
positive generations, but legacy generation zero is an explicitly modelled
failure shape and the private execution APIs default to zero, so these
sites are a drift-prevention gap rather than a purely theoretical one.

Note on conservatism: ``_can_be_none`` treats an unrecognized construct
(an unknown call - including ``.get(...)``, which surfaces a stored
``None`` with or without a default - or an unbound name) as
``None``-CAPABLE, because the guard must never certify a feed as closed
that it cannot actually resolve. The only expressions certified closed
are ``int(...)``/``float(...)``/``bool(...)`` calls, names resolved to
non-``None`` locals or non-admitting parameters, and literal non-``None``
constants.
"""

import ast
from pathlib import Path

_OPERATIONS = (
    Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp" / "operations.py"
)
_LOCAL_TAG = "generation-write-form: fail-open-disclosed"
_ALIAS_TAG = "generation-write-form: fail-open-aliased"
_PARAM_TAG = "generation-write-form: fail-open-parameter"
_PARAM_ADMITS_TAG = "generation-write-form: fail-open-parameter-admits-none"
_NO_DEFAULT = object()

# (enclosing function, called method, transition event) -> number of sites.
_EXPECTED_LOCAL = {
    ("start_inline_heartbeat", "op_heartbeat", None): 1,
    ("_run_detached", "op_heartbeat", None): 1,
    ("_execute_body", "_safe_transition", "OP_FAILED"): 1,
    ("_execute_body", "_safe_transition", "OP_COMPLETED"): 1,
}
_EXPECTED_ALIASED = {
    ("complete_inline", "op_transition", "OP_FAILED"): 1,
    ("complete_inline", "op_transition", "OP_COMPLETED"): 1,
}
_EXPECTED_PARAM_ADMITTING = {
    ("_reconcile_interrupted_commit_core", "op_transition", "OP_FAILED"): 1,
    ("_safe_transition", "op_transition", None): 1,
}
_EXPECTED_PARAM_REACHABLE = {
    ("_safe_transition", "op_transition", None): 1,
}
# The disclosed fail-open FORM of the aliased capture. The set pin fixes WHICH
# sites are aliased; this pins WHAT each one says, so a rewrite of an
# already-pinned site's value form cannot pass unnoticed while it keeps its
# disclosure tag.
_DISCLOSED_ALIAS_FORM = 'generation = int(op_ctx.get("generation") or 0) or None'
_EVENT_SUFFIXES = ("OP_FAILED", "OP_COMPLETED", "OP_WORKING", "OP_CANCELLED")


def _can_be_none(node, scopes, seen):
    """True when `node` can evaluate to None.

    `scopes` is the enclosing scope chain, INNERMOST first; each scope maps
    ``assignments`` (name -> assigned value nodes) and ``params`` (name ->
    parameter table entry with an ``admits_none`` verdict). A name is
    resolved against the innermost scope that binds it. CONSERVATIVE by
    design: an unknown construct is None-capable, never certified closed.
    """
    if isinstance(node, ast.Constant):
        return node.value is None
    if isinstance(node, ast.BoolOp):
        # `a or b` / `a and b` evaluate to one of the operands.
        return any(_can_be_none(value, scopes, seen) for value in node.values)
    if isinstance(node, ast.IfExp):
        return _can_be_none(node.orelse, scopes, seen) or _can_be_none(node.body, scopes, seen)
    if isinstance(node, ast.Call):
        # int()/float()/bool(...) never return None. Everything else may:
        # a `.get(...)` surfaces a stored None with or without a default,
        # and an arbitrary call's return is unknown to a static walk.
        return not (
            isinstance(node.func, ast.Name) and node.func.id in ("int", "float", "bool")
        )
    if isinstance(node, ast.Name):
        if node.id in seen:
            return False
        for scope in scopes:
            if node.id in scope["assignments"]:
                return any(
                    _can_be_none(value, scopes, seen | {node.id})
                    for value in scope["assignments"][node.id]
                )
            if node.id in scope["params"]:
                return scope["params"][node.id]["admits_none"]
        return True  # unbound here: module-level or foreign - conservative
    return True  # unrecognized construct - conservative


def _owners(tree):
    """Map every node to the innermost function that contains it."""
    owner = {}

    def visit(node, current):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner[child] = current
                visit(child, child)
            else:
                owner.setdefault(child, current)
                visit(child, current)

    visit(tree, None)
    return owner


def _chain_of(owner, node):
    """The enclosing function chain of `node`, innermost first."""
    chain = []
    current = owner.get(node)
    while current is not None:
        chain.append(current)
        current = owner.get(current)
    return chain


def _bound_names(target):
    """The names a binding TARGET rebinds."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _bound_names(element)
    elif isinstance(target, ast.Starred):
        yield from _bound_names(target.value)


def _local_assignments(func):
    """name -> the value nodes assigned to it anywhere in `func`.

    EVERY binding form is collected, not just `name = value`: a tuple
    target (`generation, = (None,)`), a walrus (`(generation := None)`), a
    for-target, a with-target and an except-handler name all rebind the
    name. Missing one of them lets a value reach a write behind the
    classifier's back — the plan critic's M9 and M10 mutants.
    """
    env = {}

    def bind(target, value):
        for name in _bound_names(target):
            env.setdefault(name, []).append(value)

    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        elif isinstance(node, ast.AnnAssign):
            bind(node.target, node.value)
        elif isinstance(node, ast.NamedExpr):
            # A walrus rebinds the name inside an expression.
            bind(node.target, node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            bind(node.target, node.iter)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    bind(item.optional_vars, item.context_expr)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            # `except E as name` binds the name to None.
            env.setdefault(node.name, []).append(ast.Constant(value=None))
    return env


def _annotation_admits_none(annotation):
    """True for `int | None`, `Optional[...]`, any union containing None."""
    if annotation is None:
        return False
    for node in ast.walk(annotation):
        if isinstance(node, ast.Constant) and node.value is None:
            return True
        if isinstance(node, ast.Name) and node.id == "Optional":
            return True
    return False


def _param_table(func):
    """param name -> {index, kwonly, default, admits_none} for one function."""
    args = func.args
    table = {}
    positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
    for index, arg in enumerate(positional):
        table[arg.arg] = {
            "index": index,
            "kwonly": False,
            "default": _NO_DEFAULT,
            "admits_none": _annotation_admits_none(arg.annotation),
        }
    for arg in args.kwonlyargs:
        table[arg.arg] = {
            "index": None,
            "kwonly": True,
            "default": _NO_DEFAULT,
            "admits_none": _annotation_admits_none(arg.annotation),
        }
    # positional defaults align to the TAIL of the positional list;
    # kw_defaults align index-by-index (None = no default at all).
    lead = len(positional) - len(args.defaults)
    for offset, default in enumerate(args.defaults):
        table[positional[lead + offset].arg]["default"] = default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        if default is not None:
            table[arg.arg]["default"] = default
    for entry in table.values():
        if entry["default"] is not _NO_DEFAULT and _can_be_none(
            entry["default"], [], set()
        ):
            entry["admits_none"] = True
    return table


def _event_of(call):
    """The transition event a call carries, if any."""
    for argument in call.args:
        if isinstance(argument, ast.Attribute) and argument.attr in _EVENT_SUFFIXES:
            return argument.attr
        if isinstance(argument, ast.Name) and argument.id in _EVENT_SUFFIXES:
            return argument.id
    for argument in call.args:
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            return argument.value
    return None


def _method_of(call):
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ast.unparse(func)


def _call_binds_none(call, scope_of, param_name, entry):
    """True when this call site binds a None-capable value to the parameter."""
    if any(keyword.arg is None for keyword in call.keywords):
        return True  # a **spread may bind anything
    for keyword in call.keywords:
        if keyword.arg == param_name:
            return _can_be_none(keyword.value, scope_of(call), set())
    if any(isinstance(argument, ast.Starred) for argument in call.args):
        return True  # a *spread may shift every positional binding
    if not entry["kwonly"] and len(call.args) > entry["index"]:
        return _can_be_none(call.args[entry["index"]], scope_of(call), set())
    # Not bound by this call: the parameter's default applies - and an
    # omitted no-default parameter is a runtime TypeError, conservatively
    # None-capable rather than certified closed.
    if entry["default"] is not _NO_DEFAULT:
        return _can_be_none(entry["default"], [], set())
    return True


def _reachable_with_none(tree, scope_of, func, param_name, entry):
    """True when any in-module call of `func` can bind None to the parameter.

    Direct calls are resolved by positional index OR keyword. A bare
    reference to the function (its name passed around as a value, so the
    binding site is unknowable from this module) is None-capable.
    """
    called = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == func.name
        ):
            called.add(id(node.func))
            if _call_binds_none(node, scope_of, param_name, entry):
                return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == func.name and id(node) not in called:
            return True
    return False


def _classify():
    """Return (local, aliased, parameter) site lists.

    Local and aliased entries are (identity, line, text); parameter entries
    are (identity, line, text, reachable) and cover the ADMITTING parameter
    pass-through sites only (a parameter whose signature cannot carry None
    is a contract, not a fail-open feed).
    """
    text = _OPERATIONS.read_text(encoding="utf-8")
    tree = ast.parse(text)
    lines = text.split("\n")
    owner = _owners(tree)
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    envs = {func: _local_assignments(func) for func in functions}
    tables = {func: _param_table(func) for func in functions}

    def scope_of(node):
        """The `_can_be_none` scope chain (innermost first) for `node`."""
        return [
            {"assignments": envs[func], "params": tables[func]}
            for func in _chain_of(owner, node)
        ]

    local_sites = []
    aliased_sites = []
    parameter_sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "generation":
                continue
            chain = _chain_of(owner, node)
            identity = (
                chain[-1].name if chain else "<module>",
                _method_of(node),
                _event_of(node),
            )
            line = getattr(keyword.value, "lineno", node.lineno)
            if isinstance(keyword.value, ast.BoolOp):
                local_sites.append((identity, line, lines[line - 1]))
            elif isinstance(keyword.value, ast.Name):
                name = keyword.value.id
                binding = None
                for func in chain:
                    if name in envs[func]:
                        binding = ("local", func)
                        break
                    if name in tables[func]:
                        binding = ("param", func)
                        break
                if binding is None:
                    continue
                if binding[0] == "local":
                    assigned = envs[binding[1]][name]
                    if any(
                        _can_be_none(value, scope_of(node), {name})
                        for value in assigned
                    ):
                        # EVERY assignment that can feed this write is kept,
                        # not just the earliest one. Collapsing them onto
                        # `min(...)` let a LATER reassignment change the
                        # runtime value while the set, tag and form
                        # assertions kept inspecting the original line -
                        # an executed bypass (the plan critic's M8).
                        alias_lines = sorted({
                            getattr(value, "lineno", line) for value in assigned
                        })
                        aliased_sites.append((
                            identity,
                            alias_lines,
                            [lines[alias - 1] for alias in alias_lines],
                        ))
                    continue
                func = binding[1]
                entry = tables[func][name]
                if not entry["admits_none"]:
                    continue
                reachable = _reachable_with_none(tree, scope_of, func, name, entry)
                parameter_sites.append((identity, line, lines[line - 1], reachable))
    return local_sites, aliased_sites, parameter_sites


def _identity_counts(sites):
    counts = {}
    for site in sites:
        counts[site[0]] = counts.get(site[0], 0) + 1
    return counts


def test_keyword_local_fail_open_sites_are_exactly_the_four_disclosed():
    """The keyword-local fail-open set equals the four disclosed identities."""
    local_sites, _aliased, _parameter = _classify()
    counts = _identity_counts(local_sites)
    assert counts == _EXPECTED_LOCAL, (
        f"AC1: fail-open write sites mismatch: expected exactly "
        f"{sorted(_EXPECTED_LOCAL)} with counts {sorted(_EXPECTED_LOCAL.values())}, "
        f"found {sorted(counts)} with counts {sorted(counts.values())}"
    )


def test_every_fail_open_site_carries_the_disclosure_tag():
    """Each keyword-local fail-open site carries the same-line disclosure tag."""
    local_sites, _aliased, _parameter = _classify()
    untagged = [line for _identity, line, text in local_sites if _LOCAL_TAG not in text]
    assert not untagged, (
        f"AC1: fail-open write sites missing the '{_LOCAL_TAG}' tag at lines {untagged}"
    )


def test_aliased_fail_open_writes_are_exactly_the_disclosed_pair():
    """The aliased fail-open set equals the disclosed captured-generation pair."""
    _local, aliased_sites, _parameter = _classify()
    counts = _identity_counts(aliased_sites)
    assert counts == _EXPECTED_ALIASED, (
        f"AC1: aliased fail-open writes mismatch: expected exactly "
        f"{sorted(_EXPECTED_ALIASED)}, found {sorted(counts)}"
    )


def test_the_aliased_capture_carries_its_disclosure_tag():
    """EVERY assignment that can feed an aliased write is disclosed.

    Not just the first one: a later reassignment of the same local feeds
    the write just as much, and an undisclosed one would change the
    runtime value while the set pin kept looking at the original line.
    """
    _local, aliased_sites, _parameter = _classify()
    untagged = [
        line
        for _identity, alias_lines, texts in aliased_sites
        for line, text in zip(alias_lines, texts)
        if _ALIAS_TAG not in text
    ]
    assert not untagged, (
        f"AC1: aliased fail-open capture missing the '{_ALIAS_TAG}' tag at lines {untagged}"
    )


def test_the_aliased_capture_keeps_its_disclosed_fail_open_form():
    """EVERY assignment that can feed an aliased write keeps the disclosed FORM.

    The set pin fixes WHICH sites are aliased; this pins what each one SAYS.
    Without it, rewriting an already-pinned site's value form (e.g. dropping
    the fail-closed `int(...)` coercion) while keeping its disclosure tag
    leaves every other assertion passing: the site stays disclosed, but the
    shape the disclosure describes can change silently. An executed mutant
    (M6 in the mutation probe) shows exactly that bypass.

    The same applies to a REASSIGNMENT: an ADDED assignment to the same
    local (M8) drops the coercion just as effectively, so every assignment
    is checked, not only the earliest one.
    """
    _local, aliased_sites, _parameter = _classify()
    forms = {
        text.split("#", 1)[0].strip()
        for _identity, _alias_lines, texts in aliased_sites
        for text in texts
    }
    assert forms == {_DISCLOSED_ALIAS_FORM}, (
        f"AC1: aliased fail-open capture form mismatch: expected exactly "
        f"{[_DISCLOSED_ALIAS_FORM]!r}, found {sorted(forms)!r}"
    )


def test_parameter_admitting_sites_are_exactly_the_two_disclosed():
    """The parameter pass-through ADMITTING set equals the two disclosed identities."""
    _local, _aliased, parameter_sites = _classify()
    counts = _identity_counts(parameter_sites)
    assert counts == _EXPECTED_PARAM_ADMITTING, (
        f"AC1: parameter pass-through admitting sites mismatch: expected exactly "
        f"{sorted(_EXPECTED_PARAM_ADMITTING)}, found {sorted(counts)} - a write whose "
        f"generation argument is a bare function parameter appeared or changed"
    )


def test_parameter_reachable_sites_are_exactly_the_disclosed_one():
    """Only the _safe_transition write is reachable with None today.

    This is the pin that kills the parameter-feed bypass: if a caller of an
    admitting parameter starts binding a None-capable expression to it
    (positional or keyword), the site moves into the reachable set and this
    identity assertion fires.
    """
    _local, _aliased, parameter_sites = _classify()
    reachable = [site for site in parameter_sites if site[3]]
    counts = _identity_counts(reachable)
    assert counts == _EXPECTED_PARAM_REACHABLE, (
        f"AC1: parameter pass-through sites REACHABLE with None mismatch: expected "
        f"exactly {sorted(_EXPECTED_PARAM_REACHABLE)}, found {sorted(counts)} - "
        f"a caller started feeding a None-capable value into an admitting parameter"
    )


def test_reachable_parameter_sites_carry_the_parameter_tag():
    """Each None-reachable parameter site carries the strong disclosure tag."""
    _local, _aliased, parameter_sites = _classify()
    untagged = [
        line for _identity, line, text, reachable in parameter_sites
        # the admits tag CONTAINS the strong tag as a prefix, so a line
        # carrying only the weaker tag must be rejected explicitly
        if reachable and (_PARAM_TAG not in text or _PARAM_ADMITS_TAG in text)
    ]
    assert not untagged, (
        f"AC1: reachable parameter pass-through sites missing the "
        f"'{_PARAM_TAG}' tag at lines {untagged}"
    )


def test_admitting_but_unreachable_parameter_sites_carry_the_admits_tag():
    """Admitting-but-currently-closed parameter sites carry the weaker tag."""
    _local, _aliased, parameter_sites = _classify()
    untagged = [
        line for _identity, line, text, reachable in parameter_sites
        if not reachable and _PARAM_ADMITS_TAG not in text
    ]
    assert not untagged, (
        f"AC1: admitting-but-unreachable parameter pass-through sites missing the "
        f"'{_PARAM_ADMITS_TAG}' tag at lines {untagged}"
    )
