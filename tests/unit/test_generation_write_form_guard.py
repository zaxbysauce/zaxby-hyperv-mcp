"""Issue #167 AC1 - the generation write-form guard.

RED at base, GREEN after the fix: at the base commit the fail-open write
sites carry no disclosure tag, so the tag assertions below fail with the AC1
marker; once each disclosed site is tagged (and the sets are still exactly
the disclosed ones), every assertion passes.

Three properties are pinned, and each is a property of the SEMANTICS of a
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

3. DISCLOSURE. Every keyword-local fail-open site carries the
   ``generation-write-form: fail-open-disclosed`` tag on its own line, and
   the aliased assignment carries
   ``generation-write-form: fail-open-aliased``.

Mutation that must kill this check: an untagged fifth fail-open site added
to ``operations.py`` (the identity set check fires); a fifth site added
WITH the tag (the identity set check fires - it is not one of the four
disclosed identities); one disclosed site converted while a different
tagged fail-open line replaces it (the identity check fires - the count
stays at four); the aliased capture re-introduced as a plain
``generation or None`` assignment (the alias set check fires).

Note on the reachability of the class: production row constructors mint
positive generations, but legacy generation zero is an explicitly modelled
failure shape and the private execution APIs default to zero, so these
sites are a drift-prevention gap rather than a purely theoretical one.
"""

import ast
from pathlib import Path

_OPERATIONS = (
    Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp" / "operations.py"
)
_LOCAL_TAG = "generation-write-form: fail-open-disclosed"
_ALIAS_TAG = "generation-write-form: fail-open-aliased"

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
_EVENT_SUFFIXES = ("OP_FAILED", "OP_COMPLETED", "OP_WORKING", "OP_CANCELLED")


def _can_be_none(node, scopes, seen):
    """True when `node` can evaluate to None.

    `scopes` is the enclosing scope chain, innermost first; a name is
    resolved against the innermost scope that binds it.
    """
    if isinstance(node, ast.Constant):
        return node.value is None
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.Or):
            return any(_can_be_none(value, scopes, seen) for value in node.values)
        return False
    if isinstance(node, ast.IfExp):
        return _can_be_none(node.orelse, scopes, seen) or _can_be_none(node.body, scopes, seen)
    if isinstance(node, ast.Name):
        if node.id in seen:
            return False
        for scope in scopes:
            for assigned in scope.get(node.id, []):
                if _can_be_none(assigned, scopes, seen | {node.id}):
                    return True
            if node.id in scope:
                break
        return False
    return False


def _scopes(tree):
    """Return (innermost-owner map, scope chain per function).

    The owner map gives each node the innermost function that contains it;
    the chain lists a function's enclosing scopes from outermost to
    innermost.
    """
    owner = {}
    parent = {}
    chain = {}

    def visit(node, current, stack):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner[child] = current
                parent[child] = current
                chain[child] = stack + [child]
                visit(child, child, stack + [child])
            else:
                owner.setdefault(child, current)
                visit(child, current, stack)

    visit(tree, None, [])
    return owner, parent, chain


def _local_assignments(func):
    env = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            env.setdefault(node.target.id, []).append(node.value)
    return env


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


def _classify():
    """Return (local sites, aliased sites) as lists of (identity, line, text)."""
    text = _OPERATIONS.read_text(encoding="utf-8")
    tree = ast.parse(text)
    lines = text.split("\n")
    owner, _parent, chain = _scopes(tree)
    envs = {
        node.name: _local_assignments(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    def scopes_for(node):
        """The scope chain (outermost first) that encloses `node`."""
        current = owner.get(node)
        if current is None:
            return []
        names = []
        walker = current
        while walker is not None:
            names.append(walker.name)
            walker = owner.get(walker)
        return list(reversed(names))

    def env_chain(node):
        current = owner.get(node)
        scopes = []
        while current is not None:
            scopes.append(envs.get(current.name, {}))
            current = owner.get(current)
        return list(reversed(scopes))

    local_sites = []
    aliased_sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "generation":
                continue
            names = scopes_for(node)
            identity = (
                names[0] if names else "<module>",
                _method_of(node),
                _event_of(node),
            )
            line = getattr(keyword.value, "lineno", node.lineno)
            if isinstance(keyword.value, ast.BoolOp):
                local_sites.append((identity, line, lines[line - 1]))
            elif isinstance(keyword.value, ast.Name):
                scopes = env_chain(node)
                assigned = []
                for scope in scopes:
                    if keyword.value.id in scope:
                        assigned = scope[keyword.value.id]
                        break
                if assigned and any(
                    _can_be_none(value, scopes, {keyword.value.id}) for value in assigned
                ):
                    alias_line = min(getattr(value, "lineno", line) for value in assigned)
                    aliased_sites.append((identity, alias_line, lines[alias_line - 1]))
    return local_sites, aliased_sites


def _identity_counts(sites):
    counts = {}
    for identity, _line, _text in sites:
        counts[identity] = counts.get(identity, 0) + 1
    return counts


def test_keyword_local_fail_open_sites_are_exactly_the_four_disclosed():
    """The keyword-local fail-open set equals the four disclosed identities."""
    local_sites, _aliased = _classify()
    counts = _identity_counts(local_sites)
    assert counts == _EXPECTED_LOCAL, (
        f"AC1: fail-open write sites mismatch: expected exactly "
        f"{sorted(_EXPECTED_LOCAL)} with counts {sorted(_EXPECTED_LOCAL.values())}, "
        f"found {sorted(counts)} with counts {sorted(counts.values())}"
    )


def test_every_fail_open_site_carries_the_disclosure_tag():
    """Each keyword-local fail-open site carries the same-line disclosure tag."""
    local_sites, _aliased = _classify()
    untagged = [line for _identity, line, text in local_sites if _LOCAL_TAG not in text]
    assert not untagged, (
        f"AC1: fail-open write sites missing the '{_LOCAL_TAG}' tag at lines {untagged}"
    )


def test_aliased_fail_open_writes_are_exactly_the_disclosed_pair():
    """The aliased fail-open set equals the disclosed captured-generation pair."""
    _local, aliased_sites = _classify()
    counts = _identity_counts(aliased_sites)
    assert counts == _EXPECTED_ALIASED, (
        f"AC1: aliased fail-open writes mismatch: expected exactly "
        f"{sorted(_EXPECTED_ALIASED)}, found {sorted(counts)}"
    )


def test_the_aliased_capture_carries_its_disclosure_tag():
    """The assignment that mints the absent generation is disclosed."""
    _local, aliased_sites = _classify()
    untagged = [line for _identity, line, text in aliased_sites if _ALIAS_TAG not in text]
    assert not untagged, (
        f"AC1: aliased fail-open capture missing the '{_ALIAS_TAG}' tag at lines {untagged}"
    )
