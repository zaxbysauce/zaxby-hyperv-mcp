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

5. RESOLUTION of the classes that are not write forms. Two further
   classes are pinned so that the guard cannot be widened by a blind
   spot:

   - the DIRECT EXPRESSION class (a ``generation=`` argument that is a
     call or a conditional expression rather than a boolean-or
     expression or a bare name). Every such form must be on the
     REVIEWED closed list - the ``int(...)`` coercions and the store's
     positive generation counter - or the guard fails. An unreviewed
     form is a new feed that must earn its pin.
   - the ANNOTATION and DECLARATION resolution rules behind the
     parameter class: a parameter annotated with a name that admits
     ``None`` (``int | None``, ``Optional[...]``, ``Any``, ``object``,
     or any unresolved alias) is admitting, and a ``global``/
     ``nonlocal`` declaration applies to the whole function scope, so
     one nested inside a conditional block is found too.

Mutation that must kill this check: an untagged fifth fail-open site added
to ``operations.py`` (the identity set check fires); a fifth site added
WITH the tag (the identity set check fires - it is not one of the four
disclosed identities); one disclosed site converted while a different
tagged fail-open line replaces it (the identity check fires - the count
stays at four); the aliased capture re-introduced as a plain
``generation or None`` assignment (the alias set check fires); a caller of
an admitting parameter switched to a ``None``-capable feed such as
``op_ctx.get("generation")`` (the parameter reachable-set check fires); a
direct expression feed that is not on the reviewed closed list (the
unresolved-direct-form check fires).

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
constants. The same rule governs the direct expression class: a form that
is not on the reviewed closed list is reported, not assumed closed.
"""

import ast
import pathlib
import re
import tokenize
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
        # int()/float()/bool(...) never return None - but only when the
        # name still resolves to the BUILTIN. A rebound `int` (a local
        # or a module-level `int = ...`) is a call to something else
        # that CAN return None, so the spelling is not enough: a
        # shadowed coercion is classified conservatively (the round-17
        # implementation reviewer's finding).
        if isinstance(node.func, ast.Name) and node.func.id in _COERCION_NAMES:
            return any(
                node.func.id in scope["shadowed"] for scope in scopes
            )
        return True
    if isinstance(node, ast.Name):
        if node.id in seen:
            # A RESOLUTION CYCLE (`generation = generation`) does not
            # resolve to a closed value: the name still holds whatever the
            # enclosing binding supplied, so it can be None. Certifying a
            # cycle closed is how a parameter's own value was lost - the
            # plan critic's executed parameter-self-assignment probe.
            return True
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


def _scope_shadowed_names(tree) -> set[str]:
    """The names a LAMBDA or a COMPREHENSION binds anywhere in the module.

    A lambda parameter and a comprehension iteration variable each create a
    scope of their own, so a `generation=` write inside one resolves to THAT
    binding and not to the enclosing function's local. The classifier does
    not model those scopes, so a name they bind is treated as UNRESOLVED -
    conservatively, which is the fail-closed direction for a guard.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Lambda):
            args = node.args
            for group in (args.posonlyargs, args.args, args.kwonlyargs):
                for arg in group:
                    names.add(arg.arg)
            if args.vararg:
                names.add(args.vararg.arg)
            if args.kwarg:
                names.add(args.kwarg.arg)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp,
                               ast.GeneratorExp)):
            for generator in node.generators:
                names.update(_bound_names(generator.target))
    return names


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


def _pattern_names(pattern):
    """The names a MATCH pattern binds."""
    if isinstance(pattern, ast.MatchAs):
        if pattern.name:
            yield pattern.name
        # `case (generation, _) as pair:` binds BOTH the inner name and the
        # outer one, so the nested pattern is walked too.
        if pattern.pattern is not None:
            yield from _pattern_names(pattern.pattern)
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name:
            yield pattern.name
    elif isinstance(pattern, ast.MatchMapping):
        if pattern.rest:
            yield pattern.rest
        for value in pattern.patterns:
            yield from _pattern_names(value)
    elif isinstance(pattern, ast.MatchSequence):
        for element in pattern.patterns:
            yield from _pattern_names(element)
    elif isinstance(pattern, ast.MatchClass):
        for element in pattern.patterns:
            yield from _pattern_names(element)
        for element in pattern.kwd_patterns:
            yield from _pattern_names(element)
    elif isinstance(pattern, ast.MatchOr):
        for element in pattern.patterns:
            yield from _pattern_names(element)


def _own_scope_nodes(func):
    """Every node in `func`'s OWN scope, in source order.

    A function's own scope is its body and every compound statement
    nested in it - but NOT a nested function's or class's body, which has a
    scope of its own. A `global`/`nonlocal` declaration applies to the
    WHOLE function scope, so it must be found wherever it sits in that
    scope: searching only the function's immediate children missed the
    conditional form (`if ...: global generation`), which then let the
    name be treated as a local (the plan critic's executed probe).
    """
    stack = list(getattr(func, "body", []))
    while stack:
        node = stack.pop(0)
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)):
            continue  # a scope of its own
        stack.extend(ast.iter_child_nodes(node))


def _local_assignments(func):
    """name -> the value nodes assigned to it anywhere in `func`.

    EVERY binding form is collected, not just `name = value`: a tuple
    target (`generation, = (None,)`), a walrus (`(generation := None)`), a
    for-target, a with-target, an except-handler name, an IMPORT binding and
    a MATCH pattern capture all rebind the name. Missing one of them lets a
    value reach a write behind the classifier's back — the plan critic's M9
    and M10 mutants, the implementation reviewer's pattern-capture finding
    and the plan critic's import and global probes.

    A name declared `global`/`nonlocal` in this function does NOT become a
    local here: the binding lives in the enclosing scope, so the assignment
    is not collected as a local binding (the name stays unresolved for this
    function, which the classifier treats conservatively).
    """
    env = {}
    declared_elsewhere: set[str] = set()
    # The function's OWN declarations only: an unrestricted walk would also
    # collect a NESTED function's `nonlocal x`, and suppressing the outer
    # function's binding of `x` on that basis would let a nested rebinding
    # slip past the census.
    for node in _own_scope_nodes(func):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            declared_elsewhere.update(node.names)
    # A nested function that declares `nonlocal x` (or `global x`) rebinds
    # the name in THIS scope, so this scope's binding of it is no longer
    # the only one - an unknown value is added for it. The nested
    # function's own declarations are searched in ITS own scope, so a
    # conditional declaration inside it counts too.
    for node in _own_scope_nodes(func):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for statement in _own_scope_nodes(node):
                if isinstance(statement, (ast.Global, ast.Nonlocal)):
                    for name in statement.names:
                        env.setdefault(name, []).append(
                            ast.Constant(value=None, lineno=statement.lineno,
                                          col_offset=0)
                        )

    def bind(target, value):
        for name in _bound_names(target):
            if name in declared_elsewhere:
                continue  # the binding lives in an enclosing scope
            env.setdefault(name, []).append(value)

    def bind_name(name, value):
        """Bind a NAME directly (a definition's name is a string, not a node)."""
        if name in declared_elsewhere:
            return
        env.setdefault(name, []).append(value)

    dynamic_scope = False
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
            # A dynamic EXEC of a LITERAL source rebinds the names that
            # source mentions, in the executing scope. A static walk can
            # see that, so it is collected like any other binding form
            # rather than left to the declared boundary.
            for dynamic_name in _exec_rebound_names(node.value):
                bind_name(dynamic_name, ast.Constant(value=None,
                                                      lineno=node.lineno,
                                                      col_offset=0))
            if _is_computed_exec(node.value):
                dynamic_scope = True
        elif isinstance(node, ast.Expr):
            # The same dynamic rebinding as a STATEMENT (`exec("generation
            # = None")`), which is the shape it takes in practice.
            for dynamic_name in _exec_rebound_names(node.value):
                bind_name(dynamic_name, ast.Constant(value=None,
                                                      lineno=node.lineno,
                                                      col_offset=0))
            if _is_computed_exec(node.value):
                dynamic_scope = True
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
            env.setdefault(node.name, []).append(
                ast.Constant(value=None, lineno=node.lineno, col_offset=0)
            )
        elif isinstance(node, ast.Match):
            # A match case's capture patterns bind names to the matched
            # subject (conservatively: the subject expression).
            for case in node.cases:
                for name in _pattern_names(case.pattern):
                    if name in declared_elsewhere:
                        continue
                    env.setdefault(name, []).append(node.subject)
        elif isinstance(node, ast.ImportFrom):
            # `from x import generation` binds the name to an imported
            # value, which is unknown here - conservatively None-capable.
            for alias in node.names:
                bound = alias.asname or alias.name
                if bound in declared_elsewhere:
                    continue
                env.setdefault(bound, []).append(
                    ast.Constant(value=None, lineno=node.lineno, col_offset=0)
                )
        elif isinstance(node, ast.Import):
            # Python's binding rule: `import x as y` binds `y`, `import x`
            # binds `x`, and `import a.b` binds `a` - the FIRST component.
            for alias in node.names:
                if alias.asname:
                    bound = alias.asname
                else:
                    bound = alias.name.split(".", 1)[0]
                if bound in declared_elsewhere:
                    continue
                env.setdefault(bound, []).append(
                    ast.Constant(value=None, lineno=node.lineno, col_offset=0)
                )
        elif isinstance(node, ast.AugAssign):
            # `generation += x` REBINDS the name through the target's
            # `__iadd__`, so the result is an unknown value: conservatively
            # None-capable.
            bind(node.target, ast.Constant(value=None, lineno=node.lineno,
                                           col_offset=0))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                               ast.ClassDef)):
            # `def generation(): ...` / `class generation: ...` binds the
            # name in the enclosing scope, so a later definition of that
            # name REBINDS the local before the writes. The bound value is
            # a function or class object - never None - but the binding
            # still shadows the disclosed assignment, so it is collected as
            # an unknown value (conservatively).
            bind_name(node.name, ast.Constant(value=None, lineno=node.lineno,
                                              col_offset=0))
    if dynamic_scope:
        # An EXEC of a COMPUTED source can touch ANY name in this scope,
        # so every name it binds is UNRESOLVED: the value that reaches a
        # write cannot be established by a walk, and the guard reports it
        # (the fail-closed direction).
        for name in list(env):
            env[name].append(ast.Constant(value=None, lineno=0, col_offset=0))
    return env



# The annotation names the analysis can certify as NOT admitting None. Every
# other name is treated as admitting None (see `_annotation_admits_none`).
#
# `Any` and `object` are NOT on this list, and that is deliberate: `Any`
# includes `NoneType`, and `None` is an instance of `object`, so a
# parameter annotated with either can carry None. Certifying them closed
# would let a None-capable feed into a parameter site that the reachable
# set then reports as closed (the plan critic's executed `Any` and
# `object` probes).
_CLOSED_ANNOTATION_NAMES = frozenset({
    "int", "float", "bool", "str", "bytes",
})


def _annotation_admits_none(annotation, shadowed=frozenset()):
    """True for `int | None`, `Optional[...]`, any union containing None.

    A QUOTED annotation ("int | None") is parsed first: a postponed
    annotation written by hand is a string literal, and reading only the
    AST of the literal would miss the None inside it.

    A CLOSED annotation name is closed only while it still resolves to
    the BUILTIN: a rebound `str` (`str = type(None)`) makes a
    `str`-annotated parameter admit None, so the spelling alone is not
    enough (the plan gate's executed probe).
    """
    if annotation is None:
        return False
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        try:
            annotation = ast.parse(annotation.value, mode="eval").body
        except SyntaxError:
            return True  # unparsable: conservative
    for node in ast.walk(annotation):
        if isinstance(node, ast.Constant) and node.value is None:
            return True
        if isinstance(node, ast.Name) and node.id == "Optional":
            return True
        # An annotation NAME the analysis cannot resolve (a module-level type
        # ALIAS such as `OptionalGeneration = int | None`, or any custom
        # alias) is treated as admitting None: a guard that skips what it
        # cannot resolve has a hole.
        if isinstance(node, ast.Name):
            if node.id in _CLOSED_ANNOTATION_NAMES:
                if node.id in shadowed:
                    # A REBOUND name: the annotation no longer excludes
                    # None.
                    return True
                continue
            return True
        # `typing.Optional[...]` is an attribute, not a name.
        if isinstance(node, ast.Attribute) and node.attr == "Optional":
            return True
        # `types.NoneType` IS `type(None)`, so it admits None.
        if isinstance(node, ast.Attribute) and node.attr == "NoneType":
            return True
        if isinstance(node, ast.Name) and node.id == "NoneType":
            return True
    return False


def _param_table(func, annotation_shadow=frozenset()):
    """param name -> {index, kwonly, default, admits_none} for one function.

    `annotation_shadow` is the set of names the ENCLOSING scopes rebind:
    an annotation is evaluated where the function is DEFINED, so the
    function's own locals do not shadow it.
    """
    args = func.args
    table = {}
    shadowed = set(annotation_shadow)
    positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
    for index, arg in enumerate(positional):
        table[arg.arg] = {
            "index": index,
            "kwonly": False,
            "default": _NO_DEFAULT,
            # An UNANNOTATED parameter can receive anything, so it admits
            # None: a signature that cannot exclude None must not be read
            # as one that excludes it.
            "admits_none": (arg.annotation is None
                            or _annotation_admits_none(arg.annotation, shadowed)),
        }
    for arg in args.kwonlyargs:
        table[arg.arg] = {
            "index": None,
            "kwonly": True,
            "default": _NO_DEFAULT,
            "admits_none": (arg.annotation is None
                            or _annotation_admits_none(arg.annotation, shadowed)),
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
    if _has_computed_exec(func):
        # An EXEC of a COMPUTED source can rebind a PARAMETER too, so no
        # parameter's value can be established by a walk: every one of
        # them admits None.
        for entry in table.values():
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


def _reachable_with_none(tree, scope_of, func, param_name, entry,
                         unknown_is_reachable=True):
    """True when any in-module call of `func` can bind None to the parameter.

    Direct calls are resolved by positional index OR keyword. A bare
    reference to the function (its name passed around as a value, so the
    binding site is unknowable from this module) is None-capable - for
    an ADMITTING signature. `unknown_is_reachable` is False for a CLOSED
    signature, where an unknowable binding is not reported: the codebase's
    own contract excludes None there, and only a DEFINITE None feed is a
    real fail-open (the plan gate's probe).
    """
    called = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == func.name
        ):
            # An ATTRIBUTE-style call of the tracked function (through a
            # module object, a class attribute, a `sys.modules[...]` lookup)
            # is not a bare name, so it must be resolved conservatively: the
            # site is treated as REACHABLE rather than skipped.
            called.add(id(node.func))
            if _call_binds_none(node, scope_of, param_name, entry):
                return True
            continue
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
            if unknown_is_reachable:
                return True
    return False


# The REVIEWED closed forms for a DIRECT EXPRESSION argument. AC1 pins the
# `generation or None` write form, but a direct expression form still feeds
# the same write, so the guard must decide whether it can carry None. Two
# certifications are accepted, and each is explicit:
#
#   * `int(...)` (and `float`/`bool`): the coercion RAISES TypeError on a
#     None argument rather than returning it, so its result is never None;
#   * `store.op_next_generation()`: the store's own generation counter,
#     whose contract is a POSITIVE value.
#
# Every other direct expression form is UNRESOLVED: the guard never
# certifies what it cannot resolve, so the site is reported and the guard
# FAILS until the form is reviewed and pinned here. That is the fail-closed
# direction - a new feed cannot enter the tree unnoticed - and it is what
# turns the class from a hole into a PIN.
_CLOSED_DIRECT_CALLS = frozenset({"int", "float", "bool"})

# The coercion names whose call result can never be None - as long as the
# name still resolves to the BUILTIN.
_COERCION_NAMES = ("int", "float", "bool")

# Every name the analysis certifies CLOSED: the coercions (a call cannot
# return None) and the closed annotation names. A REBINDING of any of them
# - at module level or in the analysed scope - removes the certification,
# so the shadow census must cover all of them (the plan gate's `str =
# type(None)` probe).
_CERTIFIED_CLOSED_NAMES = frozenset({
    "int", "float", "bool", "str", "bytes",
})
_CLOSED_DIRECT_EXACT = frozenset({"store.op_next_generation()"})


def _direct_form_is_closed(node, shadowed=frozenset()) -> bool:
    """True when a direct expression form is a REVIEWED non-None form.

    A coercion name that is SHADOWED in the scope under analysis is not
    the builtin, so the form is not closed.
    """
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in _CLOSED_DIRECT_CALLS:
            return node.func.id not in shadowed
        return ast.unparse(node) in _CLOSED_DIRECT_EXACT
    return False




def _is_store_write(node) -> bool:
    """True when the call writes through the store.

    The store's write methods take the generation as their last
    argument, and it may be POSITIONAL - so the keyword-only scan would
    miss a positional fail-open feed.
    """
    func = node.func
    return isinstance(func, ast.Attribute) and func.attr.startswith("op_")



def _spread_generation_value(node):
    """The generation value carried by a `**` SPREAD, if any.

    `**{"generation": generation or None}` reaches the receiving write
    with the same keyword the named form would - but the keyword is not
    named in the call, so the named-keyword scan skips it. A COMPUTED
    spread (`**body_args`) carries keys that are not statically visible;
    that form is the census's remaining declared boundary.
    """
    if not isinstance(node, ast.Dict):
        return None
    found = None
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and key.value == "generation":
            # The LAST duplicate wins in a dict literal, so the last
            # matching value is the one that reaches the write.
            found = value
    return found


def _comment_tokens(path: pathlib.Path) -> dict[int, str]:
    """The real COMMENT tokens of a source file, keyed by line number.

    The disclosure tag must be in a COMMENT. A line scan cannot tell a
    comment from a `#` inside a string - and a MULTI-LINE string's
    content lines look like comments to a line scan. `tokenize` reports
    the real comments.
    """
    comments: dict[int, str] = {}
    try:
        with path.open("rb") as handle:
            for token in tokenize.tokenize(handle.readline):
                if token.type == tokenize.COMMENT:
                    comments[token.start[0]] = token.string
    except (tokenize.TokenError, IndentationError, SyntaxError, OSError):
        return {}
    return comments


def _comment_text(line: str) -> str:
    """The COMMENT part of a source line (fallback scan).

    The disclosure tag must be a COMMENT: a string literal that happens
    to contain the tag text satisfied the same-line scan, so a site could
    lose its disclosure comment and keep the text. The authoritative
    source is `_comment_tokens`; this fallback is used when the file
    cannot be tokenized.
    """
    quote = None
    index = 0
    while index < len(line):
        character = line[index]
        if quote is not None:
            if character == "\\":
                index += 2
                continue
            if character == quote:
                quote = None
        elif character in ("'", '"'):
            quote = character
        elif character == "#":
            return line[index:]
        index += 1
    return ""


# The real COMMENT tokens of the analysed source, by line. The
# disclosure tag must be in one of them.
_COMMENTS = _comment_tokens(_OPERATIONS)

def _reads_only_its_own_name(values, name) -> bool:
    """True when EVERY assignment of the name only READS the name.

    `generation = generation` does not rebind the name with a new value:
    it copies the enclosing binding into the local. When that enclosing
    binding is a PARAMETER, the value that reaches the write is the
    CALLER's value - so the site belongs in the parameter class, not in
    the local class, and the local must not shadow the parameter.

    EVERY assignment must be a self-read for that to hold: a local that
    reads itself once and is later assigned something else (`generation =
    generation` followed by `generation = None`) takes that OTHER value,
    so the local must be assessed on its own - and the other assignment
    must not be hidden behind the parameter's (possibly closed)
    annotation (the round-15 implementation reviewer's finding).
    """
    if not values:
        return False
    for value in values:
        if not (isinstance(value, ast.Name) and value.id == name):
            return False
    return True


def _exec_rebound_names(node) -> list[str]:
    """The names a dynamic EXEC of a LITERAL source can rebind.

    `exec("generation = None")` names the names that source touches, so
    a static walk CAN see them and collects them like any other binding
    form.
    """
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return []
    if node.func.id != "exec" or not node.args:
        return []
    source = node.args[0]
    if not (isinstance(source, ast.Constant) and isinstance(source.value, str)):
        return []
    return sorted(set(re.findall(r"[A-Za-z_][A-Za-z_0-9]*", source.value)))


def _is_computed_exec(node) -> bool:
    """True for an EXEC whose source is not a literal.

    A computed source names nothing a walk can resolve, and it can touch
    ANY name in the scope - so the census treats every name in that scope
    as UNRESOLVED (conservatively, the fail-closed direction) rather
    than leaving a hole.

    The runtime observation behind this rule is recorded in the mutation
    transcript: on CPython 3.11 a function's local is NOT rebound by an
    `exec` (the executed code writes a locals snapshot), so the pure-
    Python forms of this class are closed by the runtime as well. The
    census does not rely on that: it reports what it cannot resolve.
    """
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id != "exec" or not node.args:
        return False
    source = node.args[0]
    return not (isinstance(source, ast.Constant)
                and isinstance(source.value, str))


def _has_computed_exec(func) -> bool:
    """True when the function contains an EXEC of a computed source."""
    for node in ast.walk(func):
        if isinstance(node, ast.Expr) and _is_computed_exec(node.value):
            return True
        if isinstance(node, ast.Assign) and _is_computed_exec(node.value):
            return True
    return False



def _statement_bindings(node) -> set[str]:
    """The names a single statement binds."""
    names: set[str] = set()
    if isinstance(node, ast.Assign):
        for target in node.targets:
            names |= set(_bound_names(target))
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        names |= set(_bound_names(node.target))
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        names |= set(_bound_names(node.target))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                names |= set(_bound_names(item.optional_vars))
    elif isinstance(node, ast.ExceptHandler) and node.name:
        names.add(node.name)
    elif isinstance(node, ast.Match):
        for case in node.cases:
            for name in _pattern_names(case.pattern):
                names.add(name)
    elif isinstance(node, ast.NamedExpr):
        # A WALRUS binds a name in the enclosing scope.
        names |= set(_bound_names(node.target))
    elif isinstance(node, ast.Import):
        for alias in node.names:
            names.add(alias.asname or alias.name.split(".", 1)[0])
    elif isinstance(node, ast.ImportFrom):
        for alias in node.names:
            names.add(alias.asname or alias.name)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.add(node.name)
    return names


def _module_scope_nodes(tree):
    """The module's OWN scope: its body and the compound statements in it.

    A nested function's or class's body is a scope of its own, so it is
    NOT walked: a local `int` in another function does not shadow the
    module's name, and treating it as shadowed would report the closed
    sites as fail-open.
    """
    stack = list(tree.body)
    while stack:
        node = stack.pop(0)
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _module_shadowed_coercions(tree) -> set[str]:
    """The coercion names the MODULE rebinds.

    A module-level `int = ...` - or an IMPORT that binds `int`, or a
    binding nested in a module-level compound statement - shadows the
    builtin for the whole module, so every `int(...)` in it calls
    something else, which can return None.
    """
    shadowed: set[str] = set()
    for node in _module_scope_nodes(tree):
        for name in _statement_bindings(node):
            if name in _CERTIFIED_CLOSED_NAMES:
                shadowed.add(name)
    return shadowed


def _function_shadowed_coercions(func, env, table) -> set[str]:
    """The coercion names bound in a function's own scope.

    A local or a parameter named `int` shadows the builtin for that
    function, so its `int(...)` calls are calls to something else.
    """
    shadowed = {name for name in env if name in _CERTIFIED_CLOSED_NAMES}
    shadowed |= {name for name in table if name in _CERTIFIED_CLOSED_NAMES}
    return shadowed


def _classify():
    """Return (local, aliased, parameter, direct) site lists.

    Local and aliased entries are (identity, line, text); parameter entries
    are (identity, line, text, reachable) and cover the ADMITTING parameter
    pass-through sites only (a parameter whose signature cannot carry None
    is a contract, not a fail-open feed); direct entries are
    (identity, line, text) and cover the direct expression forms that are
    NOT on the reviewed closed list.
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
    module_shadowed = _module_shadowed_coercions(tree)

    def _param_names(func) -> set[str]:
        """The names a function's SIGNATURE binds."""
        args = func.args
        names: set[str] = set()
        for group in (getattr(args, "posonlyargs", []), args.args, args.kwonlyargs):
            names |= {arg.arg for arg in group}
        return names

    def _annotation_shadow(func) -> set[str]:
        """The certified-closed names the ENCLOSING scopes rebind."""
        names = set(module_shadowed)
        for outer in _chain_of(owner, func)[:-1]:
            names |= {
                name for name in envs[outer] if name in _CERTIFIED_CLOSED_NAMES
            }
            names |= {
                name for name in _param_names(outer)
                if name in _CERTIFIED_CLOSED_NAMES
            }
        return names

    tables = {
        func: _param_table(func, _annotation_shadow(func))
        for func in functions
    }
    shadowed = _scope_shadowed_names(tree)

    shadowed_by_func = {
        func: module_shadowed | _function_shadowed_coercions(
            func, envs[func], tables[func]
        )
        for func in functions
    }

    def scope_of(node):
        """The `_can_be_none` scope chain (innermost first) for `node`."""
        return [
            {
                "assignments": envs[func],
                "params": tables[func],
                "shadowed": shadowed_by_func[func],
            }
            for func in _chain_of(owner, node)
        ]

    local_sites = []
    aliased_sites = []
    parameter_sites = []
    direct_sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _is_store_write(node):
            # A POSITIONAL generation feed is invisible to the keyword
            # scan: a store write's third positional argument can carry
            # the fail-open form (`store.op_heartbeat(op_id, now,
            # generation or None)`). Every positional argument of a store
            # write is therefore checked for the fail-open form too.
            for argument in node.args:
                if (
                    isinstance(argument, ast.BoolOp)
                    and isinstance(argument.op, ast.Or)
                    and _can_be_none(argument, scope_of(node), set())
                ):
                    chain = _chain_of(owner, node)
                    identity = (
                        chain[-1].name if chain else "<module>",
                        _method_of(node),
                        None,
                    )
                    position = getattr(argument, "lineno", node.lineno)
                    local_sites.append(
                        (identity, position, lines[position - 1])
                    )
        for keyword in node.keywords:
            if keyword.arg is None:
                # A `**` SPREAD can carry the generation keyword:
                # `**{"generation": generation or None}` reaches the
                # receiving write with the same keyword the named form
                # would, and the keyword is not NAMED in the call - so
                # the named-keyword scan skipped it and the value
                # reached the write unpredicated (the plan gate's
                # executed probe).
                value = _spread_generation_value(keyword.value)
                if value is None:
                    continue
            elif keyword.arg == "generation":
                value = keyword.value
            else:
                continue
            chain = _chain_of(owner, node)
            identity = (
                chain[-1].name if chain else "<module>",
                _method_of(node),
                _event_of(node),
            )
            line = getattr(value, "lineno", node.lineno)
            if isinstance(value, ast.BoolOp) and isinstance(value.op, ast.Or):
                # The fail-open FORM is a boolean-OR that can yield None.
                # A different boolean expression (`generation or 0`) is
                # fail-CLOSED, and counting it as a fail-open site would
                # let a disclosed site be rewritten into a closed one
                # while the pin still passed (the plan gate's executed
                # probe). An `and` form is not the disclosed form
                # either: it keeps the None-capability and the comment,
                # so accepting it would let the pinned FORM change
                # unnoticed (the round-19 reviewer's finding) - it falls
                # through to the direct-expression class below and is
                # reported there.
                if _can_be_none(value, scope_of(node), set()):
                    local_sites.append((identity, line, lines[line - 1]))
            elif not isinstance(value, ast.Name):
                # A DIRECT EXPRESSION form (a call, a conditional
                # expression) is not the boolean-or write form AC1 pins,
                # but it still feeds the write - so it is checked against
                # the REVIEWED closed forms. A form that is not on that
                # list is UNRESOLVED: the guard never certifies what it
                # cannot resolve, so the site is reported here and the
                # guard FAILS until the form is reviewed and pinned. The
                # shipped tree's forms - the `int(...)` coercions and the
                # store's positive generation counter - are on the list;
                # anything else is a new feed that must earn its pin.
                coercion_shadowed = set()
                for func in chain:
                    coercion_shadowed |= shadowed_by_func[func]
                # A lambda parameter or a comprehension target binds the
                # name in a scope of its own, so a coercion call through
                # it is not the builtin.
                coercion_shadowed |= {
                    name for name in shadowed if name in _COERCION_NAMES
                }
                if not _direct_form_is_closed(value, coercion_shadowed):
                    direct_sites.append((identity, line, lines[line - 1]))
            else:
                name = value.id
                if name in shadowed:
                    # A lambda parameter or a comprehension target binds
                    # this name in a scope of its own, so the enclosing
                    # function's local is NOT what reaches the write.
                    # The scope is not modelled, so the site is treated as
                    # unresolved - conservatively.
                    aliased_sites.append((identity, [line], [lines[line - 1]]))
                    continue
                binding = None
                for func in chain:
                    if name in envs[func]:
                        # A local that only READS its own name
                        # (`generation = generation`) does not rebind it:
                        # the value that reaches the write is the
                        # enclosing binding's, so the PARAMETER table is
                        # consulted first and the site stays in the
                        # parameter class (the plan critic's executed
                        # parameter-self-assignment probe).
                        if (
                            name in tables[func]
                            and _reads_only_its_own_name(envs[func][name], name)
                        ):
                            binding = ("param", func)
                            break
                        binding = ("local", func)
                        break
                    if name in tables[func]:
                        binding = ("param", func)
                        break
                if binding is None:
                    # The name resolves to NEITHER a local nor a parameter of
                    # any enclosing function: it is a module-level (or
                    # otherwise foreign) binding - a `global` declaration,
                    # a module constant, an import. The conservative reading
                    # is that it can be None, so the site is classified as
                    # aliased and the pin demands that it be disclosed.
                    # Skipping it (the earlier behaviour) let an
                    # unpredicated bare-generation write through unseen -
                    # the plan critic's executed global probe.
                    aliased_sites.append((identity, [line], [lines[line - 1]]))
                    continue
                if binding[0] == "local":
                    assigned = envs[binding[1]][name]
                    # The value is analysed in the scope where the
                    # ASSIGNMENT is evaluated - not the scope of the
                    # write. A name assigned in an outer scope and
                    # read in an inner one resolves against the INNER
                    # scope's bindings, which is the wrong lexical
                    # scope (the plan gate's executed probe).
                    if any(
                        _can_be_none(value, scope_of(value), {name})
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
                reachable = _reachable_with_none(
                    tree, scope_of, func, name, entry,
                    unknown_is_reachable=entry["admits_none"],
                )
                if not entry["admits_none"] and not reachable:
                    # A closed signature that no caller feeds None with
                    # is a contract, not a fail-open feed.
                    continue
                parameter_sites.append(
                    (identity, line, lines[line - 1], entry["admits_none"], reachable)
                )
    return local_sites, aliased_sites, parameter_sites, direct_sites


def _identity_counts(sites):
    counts = {}
    for site in sites:
        counts[site[0]] = counts.get(site[0], 0) + 1
    return counts


def test_keyword_local_fail_open_sites_are_exactly_the_four_disclosed():
    """The keyword-local fail-open set equals the four disclosed identities."""
    local_sites, _aliased, _parameter, _direct = _classify()
    counts = _identity_counts(local_sites)
    assert counts == _EXPECTED_LOCAL, (
        f"AC1: fail-open write sites mismatch: expected exactly "
        f"{sorted(_EXPECTED_LOCAL)} with counts {sorted(_EXPECTED_LOCAL.values())}, "
        f"found {sorted(counts)} with counts {sorted(counts.values())}"
    )


def test_every_fail_open_site_carries_the_disclosure_tag():
    """Each keyword-local fail-open site carries the same-line disclosure tag."""
    local_sites, _aliased, _parameter, _direct = _classify()
    untagged = [
        line
        for _identity, line, text in local_sites
        if _LOCAL_TAG not in _COMMENTS.get(line, "")
    ]
    assert not untagged, (
        f"AC1: fail-open write sites missing the '{_LOCAL_TAG}' tag at lines {untagged}"
    )


def test_aliased_fail_open_writes_are_exactly_the_disclosed_pair():
    """The aliased fail-open set equals the disclosed captured-generation pair."""
    _local, aliased_sites, _parameter, _direct = _classify()
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
    _local, aliased_sites, _parameter, _direct = _classify()
    untagged = [
        line
        for _identity, alias_lines, texts in aliased_sites
        for line, text in zip(alias_lines, texts, strict=True)
        if _ALIAS_TAG not in _COMMENTS.get(line, "")
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
    _local, aliased_sites, _parameter, _direct = _classify()
    forms = {
        text.split("#", 1)[0].strip()
        for _identity, _alias_lines, texts in aliased_sites
        for text in texts
    }
    assert forms == {_DISCLOSED_ALIAS_FORM}, (
        f"AC1: aliased fail-open capture form mismatch: expected exactly "
        f"{[_DISCLOSED_ALIAS_FORM]!r}, found {sorted(forms)!r}"
    )


def test_no_direct_generation_form_is_unresolved():
    """Every direct expression feed is on the reviewed closed list.

    A direct expression form (a call, a conditional expression) is not
    the boolean-or write form AC1 pins, but it feeds the same write. The
    guard never certifies a form it cannot resolve, so an UNREVIEWED form
    is reported here and this assertion fires - a new feed must earn its
    pin instead of arriving unnoticed.
    """
    _local, _aliased, _parameter, direct_sites = _classify()
    assert not direct_sites, (
        f"AC1: unresolved direct expression generation feed(s) at "
        f"{[(site[1], site[2].strip()) for site in direct_sites]} - a direct "
        f"expression form must be reviewed and pinned as a closed form"
    )


def test_the_direct_form_closure_rule_certifies_only_the_reviewed_forms():
    """The closed-form rule is a pin, not a rubber stamp.

    Without this, a classifier that certified EVERY direct expression
    form would leave the unresolved set empty and every other assertion
    passing - the same false green that the direct-form site list is
    meant to prevent.
    """
    for text in (
        "store.op_next_generation()",
        "int(row.generation or 0)",
        "int(op_ctx.get('generation') or 0)",
    ):
        node = ast.parse(text, mode="eval").body
        assert _direct_form_is_closed(node), (
            f"the closure rule must certify the reviewed form {text!r}"
        )
    for text in (
        "_maybe_none()",
        "op_ctx.get('generation')",
        "1 if flag else None",
        "None",
    ):
        node = ast.parse(text, mode="eval").body
        assert not _direct_form_is_closed(node), (
            f"the closure rule must NOT certify {text!r} as a closed form"
        )


def test_parameter_admitting_sites_are_exactly_the_two_disclosed():
    """The parameter pass-through ADMITTING set equals the two disclosed identities."""
    _local, _aliased, parameter_sites, _direct = _classify()
    counts = _identity_counts([site for site in parameter_sites if site[3]])
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
    _local, _aliased, parameter_sites, _direct = _classify()
    reachable = [site for site in parameter_sites if site[4]]
    counts = _identity_counts(reachable)
    assert counts == _EXPECTED_PARAM_REACHABLE, (
        f"AC1: parameter pass-through sites REACHABLE with None mismatch: expected "
        f"exactly {sorted(_EXPECTED_PARAM_REACHABLE)}, found {sorted(counts)} - "
        f"a caller started feeding a None-capable value into an admitting parameter"
    )


def test_reachable_parameter_sites_carry_the_parameter_tag():
    """Each None-reachable parameter site carries the strong disclosure tag."""
    _local, _aliased, parameter_sites, _direct = _classify()
    untagged = [
        line for _identity, line, text, _admits, reachable in parameter_sites
        # the admits tag CONTAINS the strong tag as a prefix, so a line
        # carrying only the weaker tag must be rejected explicitly
        if reachable and (
            _PARAM_TAG not in _COMMENTS.get(line, "")
            or _PARAM_ADMITS_TAG in _COMMENTS.get(line, "")
        )
    ]
    assert not untagged, (
        f"AC1: reachable parameter pass-through sites missing the "
        f"'{_PARAM_TAG}' tag at lines {untagged}"
    )


def test_admitting_but_unreachable_parameter_sites_carry_the_admits_tag():
    """Admitting-but-currently-closed parameter sites carry the weaker tag."""
    _local, _aliased, parameter_sites, _direct = _classify()
    untagged = [
        line for _identity, line, text, admits, reachable in parameter_sites
        if not reachable and _PARAM_ADMITS_TAG not in _COMMENTS.get(line, "")
    ]
    assert not untagged, (
        f"AC1: admitting-but-unreachable parameter pass-through sites missing the "
        f"'{_PARAM_ADMITS_TAG}' tag at lines {untagged}"
    )
