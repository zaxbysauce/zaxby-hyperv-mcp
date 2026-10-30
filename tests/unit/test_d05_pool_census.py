"""Frozen acceptance check for issue #21, AC30 — the recurrence guardrail.

The defect class this PR closes is "per-call connection setup with no pooling":
a guest leg that opens its own PowerShell Direct session inside a freshly
spawned host process, when the same session could have been reused. The 27
behavioural checks prove the three named chokes are pooled; this census is what
stops the class coming back. It enumerates every place in `src/hyperv_mcp/`
that EMITS a session-establishing command and requires each one to be either

  * the pool's own establishment (`psdsessions._worker_loop`), or
  * an explicitly enumerated per-call-by-design site, with the reason recorded
    beside it.

A new, unlisted emission fails the suite, so a future contributor cannot add a
fourth unpooled per-call session without either pooling it or amending this
allow-list with a reason.

RED at base 9434636cb035ebdb91415c5e4809ba6db20b05c5 (the module does not exist,
so `psdsessions._worker_loop` is absent from the census and the guardrail's own
allow-list is unsatisfiable); GREEN after the fix.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

#: The unpooled tree the guardrail must reject.
BASE_REV = "9434636"

SRC = Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp"

#: Every emission that is deliberately NOT pooled, with the reason. The pool's
#: own establishment is added separately because it is the fix, not an exemption.
PER_CALL_BY_DESIGN: dict[tuple[str, str], str] = {
    # issue #29: the UIA helper surface is per-call by design - the pooled
    # worker stdin frame protocol cannot carry the second framed payload
    # line, and helper liveness must not be coupled to pool lifetime.
    ("uia.py", "_uia_guest_script"): "framed two-line pipe/leg wrapper",
    ("uia.py", "_ps_guest_text"): "quser/LogonUI/whoami discovery legs",
    # The per-call wrapper. Still the path of record for flag-off, no-pool,
    # remote-host mode and every direct module call in unit tests.
    ("guestexec.py", "_host_script"): "the per-call path the pooled branch falls back to",
    # The per-call leg wrapper, reached through build_guest_script by the relay,
    # which deliberately skips vm_lock and must not borrow tool-call sessions.
    ("diagnostics.py", "_guest_leg_script"): (
        "the per-call guest leg: the relay's per-request legs, diagnose_report's "
        "probe leg, and run_guest_inner's own per-call fallback"
    ),
    # wait_guest_recovery exists to detect a guest coming back, so it must open
    # fresh sessions and observe a real failure.
    ("diagnostics.py", "_recovery_script"): "wait_guest_recovery must observe a fresh session",
    # The local per-call transfer wrapper, plus the remote-mode session legs,
    # which run inside the -ComputerName hop and are never pooled.
    ("filetransfer.py", "_session_body"): "the per-call transfer wrapper",
    ("filetransfer.py", "_remote_put_script"): "remote-host mode is never pooled",
    ("filetransfer.py", "_remote_get_script"): "remote-host mode is never pooled",
    # The per-call bodies for read_file/list_dir, kept for the fallback path.
    ("filetransfer.py", "guest_read_file"): "the per-call body the pooled branch falls back to",
    ("filetransfer.py", "guest_list_dir"): "the per-call body the pooled branch falls back to",
    # The KD tools configure kernel debugging and then REBOOT the guest, which
    # invalidates the session they would have opened. One-shot, so pooling buys
    # nothing and the reboot leg needs a fresh session anyway.
    ("lifecycle.py", "configure_kdnet"): "a one-shot operation that ends in a guest reboot",
    ("lifecycle.py", "configure_kdcom"): "a one-shot operation that ends in a guest reboot",
}

#: The pool's own establishment — the fix, not an exemption.
POOLED_SITE = ("psdsessions.py", "_worker_loop")

#: How many session-establishing emissions each site may contain.
#:
#: The allow-list is keyed by (file, function), so on its own it cannot see a
#: SECOND emission added inside a function it already excuses — which is
#: exactly the regression PRR-028 named. The budget closes that: a site that
#: emits more than its budget has grown a new session establishment, and the
#: guardrail fails. Raise a budget deliberately, with a reason, never to make
#: a failure go away.
SITE_BUDGETS: dict[tuple[str, str], int] = {
    ("diagnostics.py", "_guest_leg_script"): 1,
    ("diagnostics.py", "_recovery_script"): 2,
    ("filetransfer.py", "_remote_get_script"): 1,
    ("filetransfer.py", "_remote_put_script"): 1,
    ("filetransfer.py", "_session_body"): 1,
    ("filetransfer.py", "guest_list_dir"): 1,
    ("filetransfer.py", "guest_read_file"): 1,
    ("guestexec.py", "_host_script"): 1,
    ("lifecycle.py", "configure_kdcom"): 2,
    ("lifecycle.py", "configure_kdnet"): 2,
    ("psdsessions.py", "_worker_loop"): 1,
    # issue #29: the UIA surface's two per-call-by-design sites (each emits
    # exactly one establishment — its leg wrapper / discovery command).
    ("uia.py", "_uia_guest_script"): 1,
    ("uia.py", "_ps_guest_text"): 1,
}

#: A session-establishing emission, not a prose mention of one.
#:
#: The pattern has to survive the spellings a contributor will actually type,
#: which the first revision of this guardrail did not: it missed
#: `Invoke-Command  -VMId` (two spaces), a tab, a backtick line continuation,
#: the `icm` alias, lowercase, and every `-VMName` form. Each of those was
#: verified to evade the old pattern, so the emission is now detected by the
#: COMMAND plus a VM-binding parameter, with whitespace and casing normalised
#: and the alias table spelled out.
_EMISSION_RE = re.compile(
    r"(?<![-\w])(?:Invoke-Command|New-PSSession|icm)\b[^\n]*?-VM(?:Id|Name)\b",
    re.IGNORECASE,
)


def _enclosing_function(lines: list[str], index: int) -> str:
    for j in range(index, -1, -1):
        m = re.match(r"^(?:async )?def (\w+)", lines[j])
        if m:
            return m.group(1)
    return "<module>"


def _docstring_lines(source: str) -> set[int]:
    """Line numbers occupied by docstrings, so a prose mention of a command is
    never counted as an emission.

    Computed with `ast` rather than a heuristic, because the widened emission
    pattern deliberately catches `-VMName` spellings that appear in docstrings
    explaining the old binding (`guestexec.psdirect_vm_target` documents exactly
    that migration).
    """
    import ast

    out: set[int] = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            for ln in range(first.lineno, (first.end_lineno or first.lineno) + 1):
                out.add(ln)
    return out


def _is_emission(line: str) -> bool:
    """True when `line` emits a session-establishing command.

    Comment and docstring mentions are excluded, because the defect this
    guardrail exists to catch is an emitted command, not a mention of one.
    """
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return False
    return bool(_EMISSION_RE.search(line))


def census(root: Path | None = None) -> list[tuple[str, str, int]]:
    """Every session-establishing emission under `root` (default: the package),
    as (file, enclosing function, line)."""
    out: list[tuple[str, str, int]] = []
    base = SRC if root is None else root
    for py in sorted(base.glob("*.py")):
        source = py.read_text(encoding="utf-8")
        skip = _docstring_lines(source)
        lines = source.splitlines()
        for i, line in enumerate(lines):
            if (i + 1) in skip:
                continue
            if _is_emission(line):
                out.append((py.name, _enclosing_function(lines, i), i + 1))
    return out


def violations(hits: list[tuple[str, str, int]]) -> list[str]:
    """Every way `hits` breaks the AC30 contract, as human-readable strings.

    Two rules, because the allow-list alone is blind to the regression that
    matters most: an emission inside a function it already excuses. A third rule
    makes the whole thing DISCRIMINATING rather than a description of the
    current tree:

      1. every site is the pool's own or an enumerated per-call-by-design one;
      2. no site emits MORE than its `SITE_BUDGETS` budget;
      3. the pool's own establishment site EXISTS.

    Rule 3 is what fails on the unpooled base tree, where every emission happens
    to sit inside an allow-listed function — the case that made the first
    revision's headline test GREEN on the defect-bearing base.
    """
    out: list[str] = []
    allowed = set(PER_CALL_BY_DESIGN) | {POOLED_SITE}
    for hit in hits:
        if (hit[0], hit[1]) not in allowed:
            out.append(
                f"unlisted site {hit[0]}:{hit[1]} at line {hit[2]}; either "
                f"route it through psdsessions or add it to "
                f"PER_CALL_BY_DESIGN with a reason"
            )
    if POOLED_SITE not in {(h[0], h[1]) for h in hits}:
        out.append(
            f"the pooled worker's establishment site {POOLED_SITE} is absent, so "
            f"this tree has no session reuse for the guardrail to protect"
        )
    counts: dict[tuple[str, str], int] = {}
    for hit in hits:
        counts[(hit[0], hit[1])] = counts.get((hit[0], hit[1]), 0) + 1
    for site, budget in SITE_BUDGETS.items():
        seen = counts.get(site, 0)
        if seen > budget:
            out.append(
                f"{site[0]}:{site[1]} emits {seen} session-establishing "
                f"commands, over its budget of {budget}; a new emission "
                f"inside an allow-listed function is still a new session "
                f"establishment"
            )
    return out


def test_every_session_establishment_site_is_dispositioned():
    """AC30: every emission of a PS Direct session-establishing command is
    either the pool's own establishment or an enumerated per-call-by-design
    site, and no site has grown past its emission budget."""
    hits = census()
    assert hits, "the census found no session-establishing emissions at all"
    found = violations(hits)
    assert found == [], "\n".join(found)


def test_the_pooled_establishment_site_exists():
    """AC30: the pool's own establishment is present, so the guardrail is not
    vacuously satisfied. Without this the census would pass on a tree with no
    session reuse at all — which is precisely the base tree."""
    sites = {(f, fn) for f, fn, _ in census()}
    assert POOLED_SITE in sites, (
        f"the pooled worker's establishment site {POOLED_SITE} is gone; the "
        "guardrail would then be checking a codebase with no session reuse"
    )


def test_every_budgeted_site_is_real_and_at_its_budget():
    """AC30: the budget table names sites that exist and counts that match, so
    a stale row cannot silently widen a site's allowance."""
    counts: dict[tuple[str, str], int] = {}
    for f, fn, _ in census():
        counts[(f, fn)] = counts.get((f, fn), 0) + 1
    for site, budget in SITE_BUDGETS.items():
        seen = counts.get(site, 0)
        assert seen == budget, (
            f"{site[0]}:{site[1]} is budgeted at {budget} but emits {seen}; "
            f"update SITE_BUDGETS deliberately, with a reason, when the site "
            f"legitimately changes"
        )


def test_a_new_emission_inside_an_allow_listed_function_is_seen(tmp_path):
    """AC30: the guardrail is NOT blind to a new emission added inside a function
    the allow-list already excuses.

    The first revision keyed hits by (file, enclosing function) and asserted
    only that a new emission is LISTED, so a second `Invoke-Command -VMId
    $vmTarget` inside `guestexec._host_script` passed the suite. This probe runs
    the real `violations()` against a synthetic tree and asserts BOTH directions:
    one emission is accepted (the positive control — without it a census that
    rejected everything would also pass), two are rejected.
    """
    pooled = (
        "def _worker_loop():\n"
        "    return \"New-PSSession -VMId $vmTarget -Credential $cred\"\n"
    )
    one = (
        "def _host_script():\n"
        "    return \"Invoke-Command  -VMId $vmTarget -Credential $cred\"\n"
    )
    two = one + "    return \"Invoke-Command  -VMId $vmTarget -Credential $cred\"\n"

    # A COMPLETE tree: the pooled site plus one allow-listed emission. Without
    # the pooled site the positive control would fail on rule 3, not rule 1.
    (tmp_path / "psdsessions.py").write_text(pooled, encoding="utf-8")
    (tmp_path / "guestexec.py").write_text(one, encoding="utf-8")
    assert violations(census(tmp_path)) == [], (
        "the guardrail rejected a single, allow-listed emission; the positive "
        "control failed, so the negative assertion below would prove nothing"
    )

    (tmp_path / "guestexec.py").write_text(two, encoding="utf-8")
    found = violations(census(tmp_path))
    assert found, (
        "a SECOND session-establishing emission inside an allow-listed function "
        "was accepted; the guardrail is still blind to the regression PRR-028 "
        "named"
    )
    assert any("over its budget" in f for f in found), (
        f"the second emission was rejected for the wrong reason: {found}"
    )


def _census_of_commit(rev: str) -> list[tuple[str, str, int]] | None:
    """The census as it would read `rev`, or None when `rev` is not in this
    clone.

    CI checks out with `fetch-depth: 1`, so the base commit — which lives on
    main, not on the PR branch — is simply absent there. Returning None lets the
    caller skip rather than fail on an environment that cannot answer.

    The whole walk is guarded, not just a probe: a shallow clone answers
    `cat-file -e` for a revision it then refuses to walk, so probing first would
    pass and the walk would still raise.
    """
    import subprocess

    try:
        listing = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", rev, "src/hyperv_mcp"],
            capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        hits: list[tuple[str, str, int]] = []
        for path in listing:
            if not path.endswith(".py"):
                continue
            blob = subprocess.run(
                ["git", "show", f"{rev}:{path}"], capture_output=True, text=True,
                check=True,
            ).stdout
            skip = _docstring_lines(blob)
            body = blob.splitlines()
            for i, line in enumerate(body):
                if (i + 1) in skip:
                    continue
                if _is_emission(line):
                    hits.append(
                        (Path(path).name, _enclosing_function(body, i), i + 1)
                    )
        return hits
    except subprocess.CalledProcessError:
        # The revision is not walkable in this clone.
        return None


def test_the_guardrail_is_red_on_the_unpooled_base():
    """AC30: the guardrail DISCRIMINATES — it fails on the base tree.

    The first revision's headline test was GREEN at the defect-bearing base,
    because the base tree's 13 emissions all happened to sit inside allow-listed
    functions and the pooled site was never required to exist. This runs the
    REAL `violations()` over the base commit's blobs and asserts it is non-empty,
    which is what makes the guardrail a guardrail rather than a description of
    the current tree.

    Skipped when the base commit is not in this clone (CI checks out with
    `fetch-depth: 1`, and the base lives on main rather than on the branch). The
    property it proves is ALSO pinned directly and locally, so the skip costs no
    coverage of the contract itself: `violations()` rule 3 requires the pooled
    establishment site to exist, and `test_the_pooled_establishment_site_exists`
    asserts that on the current tree.
    """
    base = _census_of_commit(BASE_REV)
    if base is None:
        pytest.skip(f"{BASE_REV} is not present in this clone (shallow checkout)")
    assert base, "the base tree emitted no session-establishing commands"
    found = violations(base)
    assert found, (
        "the guardrail is GREEN on the unpooled base tree, so it cannot tell a "
        "tree with session reuse from one without it"
    )
    assert any("psdsessions.py" in f for f in found), (
        f"the base tree was rejected, but not for the reason that matters "
        f"(no pooled establishment site): {found}"
    )



def test_every_per_call_by_design_site_is_real():
    """AC30: the allow-list names sites that actually exist. An entry that
    rotted away is a lie in the guardrail, and a guardrail that over-states its
    exemptions hides exactly the regression it exists to catch."""
    sites = {(f, fn) for f, fn, _ in census()}
    stale = sorted(set(PER_CALL_BY_DESIGN) - sites)
    assert stale == [], (
        f"PER_CALL_BY_DESIGN names site(s) that emit nothing any more: {stale}. "
        "Remove them, or the exemption outlives the code it excused."
    )
