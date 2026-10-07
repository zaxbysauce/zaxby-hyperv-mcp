"""Defect-class guardrail for the guest-transfer fix (issue #6, Phase 4.2).

Predicates 1-4 from the fix plan's Anticipated Defect-Class Sweep: a shared
helper or parameterization written once for the first axis/caller and never
specialized. Each test here fails against the base tree (pre-fix) and passes
post-fix; together they keep the class closed — a new axis-inverting
canonicalize, a new hardcoded transport class, a new destination-derived
staging name, or a fragment moved back outside its guest -ScriptBlock all
break the unit suite.
"""

import ast
import json
import os
from pathlib import Path

import pytest

# rooted_cfg is re-exported so pytest can discover it as a fixture of THIS
# module; the placement test requests it by parameter name.
from test_a02_guest_transfer import (  # noqa: F401
    CRED,
    FakePS,
    _is_resolution_leg,
    assertion_placement,
    rooted_cfg,
)

from hyperv_mcp import filetransfer, policy, pswindows
from hyperv_mcp.config import Config


def _action_scripts(fake):
    """Legs after the content-served vmident resolution leg (issue #8)."""
    return [sc for sc in fake.scripts if not _is_resolution_leg(sc)]


def test_realpath_authority_census(monkeypatch):
    """Predicate 1: guest axes must never consult host realpath (host axes must).

    The check_* census is discovered from policy.py source, so a NEW policy
    check added later fails here until it is classified below — an
    unclassified axis must not silently inherit the wrong filesystem
    authority.
    """
    seam_calls = []
    real_realpath = os.path.realpath

    def spy(path):
        seam_calls.append(os.fspath(path))
        return real_realpath(path)

    monkeypatch.setattr(policy.os.path, "realpath", spy)

    host_root = os.path.abspath(os.getcwd())
    guest_cfg = Config(guest_read_roots=["C:\\g-read"], guest_write_roots=["C:\\g-write"])
    host_cfg = Config(host_read_roots=[host_root], host_write_roots=[host_root])
    probe = os.path.join(host_root, "guardrail-probe.bin")

    guest_axes = {
        "check_guest_read": (policy.check_guest_read, guest_cfg, r"C:\g-read\x.bin"),
        "check_guest_write": (policy.check_guest_write, guest_cfg, r"C:\g-write\x.bin"),
    }
    host_axes = {
        "check_host_read": (policy.check_host_read, host_cfg, probe),
        "check_host_write": (policy.check_host_write, host_cfg, probe),
    }

    tree = ast.parse(Path(policy.__file__).read_text(encoding="utf-8"))
    discovered = {
        n.name
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name.startswith("check_")
    }
    classified = set(guest_axes) | set(host_axes)
    unclassified = discovered - classified
    stale = classified - discovered
    assert not unclassified, f"new policy check(s) not classified: {sorted(unclassified)}"
    assert not stale, f"classified check(s) no longer exist: {sorted(stale)}"

    hit_axes = []
    for name, (check, cfg, path) in guest_axes.items():
        seam_calls.clear()
        try:
            check(cfg, path)
        except policy.PolicyDenied:
            pass
        if seam_calls:
            hit_axes.append(name)
    assert not hit_axes, f"guest axes consulting host realpath: {hit_axes}"

    # Positive control per host axis: realpath must still be consulted, so
    # "remove realpath everywhere" cannot satisfy this predicate.
    for name, (check, cfg, path) in host_axes.items():
        seam_calls.clear()
        check(cfg, path)
        assert seam_calls, f"host axis {name} no longer consults realpath (positive control broken)"


def test_transport_literal_single_source():
    """Predicate 2: exactly one "transport" string constant, inside _failure_class.

    AST-based: a docstring that merely mentions transport cannot count, and
    an implicit concatenation ("trans" "port"), which folds to the same
    string at runtime, cannot slip past a raw text count.
    """
    text = Path(filetransfer.__file__).read_text(encoding="utf-8")
    tree = ast.parse(text)
    hits = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value == "transport"
    ]
    assert len(hits) == 1, f'"transport" string constant occurs {len(hits)} times; must be single-sourced'
    helper = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_failure_class"),
        None,
    )
    assert helper is not None, "_failure_class helper missing"
    hit = hits[0]
    assert helper.lineno <= hit.lineno <= helper.end_lineno, (
        f'"transport" constant at line {hit.lineno} outside _failure_class'
    )


def test_staging_suffix_single_constructor():
    """Predicate 3: staging names are built only inside _staging_path.

    Pins the suffix VALUE (so a "harmless" rename cannot change the probe
    glob contract), every Load of _STAGING_SUFFIX, and every string
    constant containing the suffix marker — AST-based so implicit
    concatenation counts too.
    """
    assert filetransfer._STAGING_SUFFIX == ".mcptmp"
    text = Path(filetransfer.__file__).read_text(encoding="utf-8")
    tree = ast.parse(text)
    loads = sorted(
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.Name) and n.id == "_STAGING_SUFFIX" and isinstance(n.ctx, ast.Load)
    )
    helper = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_staging_path"),
        None,
    )
    if helper is None:
        pytest.fail(f"_staging_path helper missing; _STAGING_SUFFIX Load refs at lines {loads}")
    outside = [ln for ln in loads if not (helper.lineno <= ln <= helper.end_lineno)]
    assert loads, "expected at least one Load of _STAGING_SUFFIX"
    assert not outside, f"_STAGING_SUFFIX loaded outside _staging_path at lines {outside}"

    # Every string constant carrying the suffix marker must be the suffix
    # definition itself or live inside _staging_path.
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str) and "mcptmp" in node.value):
            continue
        scope = node
        while scope is not None and not isinstance(scope, (ast.FunctionDef, ast.Assign)):
            scope = parents.get(scope)
        ok = scope is helper or (
            isinstance(scope, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_STAGING_SUFFIX" for t in scope.targets)
        )
        assert ok, f'staging-suffix constant {node.value!r} at line {node.lineno} outside _staging_path'
    # Plain-text cross-check: no destination + suffix construction outside the helper.
    helper_src = ast.get_source_segment(text, helper) or ""
    residual = text.replace(helper_src, "", 1)
    assert '+ ".mcptmp"' not in residual and "+ '.mcptmp'" not in residual, (
        "staging suffix concatenated outside _staging_path"
    )


# Expected (outside, inside) assertion-marker counts per tool. put = (0, 2)
# is load-bearing: initial assertion + re-walk immediately before Move-Item.
EXPECTED_INSIDE = {
    "guest_put": (0, 2),
    "guest_get": (0, 1),
    "guest_read_file": (0, 1),
    "guest_list_dir": (0, 1),
}


def test_placement_census_all_four_tools(monkeypatch, tmp_path, rooted_cfg):  # noqa: F811
    """Predicate 4: the root-assertion fragment sits inside a guest -ScriptBlock in every tool.

    The census is expectation-driven (per-tool counts) and cross-checked
    against the AST call sites of _guest_root_assertion: a fifth tool (or a
    helper) that starts embedding the fragment fails here until it is
    added to EXPECTED_INSIDE deliberately.
    """
    cfg = rooted_cfg
    vm = "test-vm-a"
    placements = {}

    src = tmp_path / "host-src" / "census.bin"
    src.write_bytes(b"x")
    put_payload = json.dumps(
        {
            "ok": True,
            "bytes_copied": 1,
            "bytes_local": 1,
            "bytes_remote": 1,
            "sha256_local": None,
            "sha256_remote": None,
        }
    )
    fake = FakePS([pswindows.PSResult(stdout=put_payload, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        cfg, vm, str(src), r"C:\g-write\census.bin", confirm=True, verify=False, cred=CRED
    )
    placements["guest_put"] = assertion_placement(_action_scripts(fake)[0])

    dest = tmp_path / "host-dst" / "census-back.bin"
    get_payload = json.dumps(
        {"ok": True, "bytes_copied": 1, "bytes_remote": 1, "sha256_local": "S", "sha256_remote": "S"}
    )
    fake = FakePS([pswindows.PSResult(stdout=get_payload, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_get(cfg, vm, r"C:\g-read\census.bin", str(dest), verify=True, cred=CRED)
    placements["guest_get"] = assertion_placement(_action_scripts(fake)[0])

    read_payload = json.dumps({"content_b64": "eA==", "bytes_read": 1, "truncated": False})
    fake = FakePS([pswindows.PSResult(stdout=read_payload, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_read_file(cfg, vm, r"C:\g-read\census.bin", cred=CRED)
    placements["guest_read_file"] = assertion_placement(_action_scripts(fake)[0])

    fake = FakePS([pswindows.PSResult(stdout="[]", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_list_dir(cfg, vm, r"C:\g-read", cred=CRED)
    placements["guest_list_dir"] = assertion_placement(_action_scripts(fake)[0])

    bad = {name: plc for name, plc in placements.items() if EXPECTED_INSIDE.get(name) != plc}
    assert not bad, f"assertion placement violations (expected, got): {bad}"
    assert set(placements) == set(EXPECTED_INSIDE), (
        f"census tools drifted: missing {sorted(set(EXPECTED_INSIDE) - set(placements))}, "
        f"unexpected {sorted(set(placements) - set(EXPECTED_INSIDE))}"
    )

    # AST cross-check: every _guest_root_assertion call site must live in a
    # census tool — a new embedder cannot hide behind an unchanged census.
    tree = ast.parse(Path(filetransfer.__file__).read_text(encoding="utf-8"))
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    callers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_guest_root_assertion":
            scope = node
            while scope is not None and not isinstance(scope, ast.FunctionDef):
                scope = parents.get(scope)
            assert scope is not None, "_guest_root_assertion call outside any function"
            callers.add(scope.name)
    assert callers == set(EXPECTED_INSIDE), (
        f"_guest_root_assertion callers drifted: "
        f"{sorted(callers ^ set(EXPECTED_INSIDE))}"
    )
