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
from test_a02_guest_transfer import CRED, FakePS, assertion_placement, rooted_cfg  # noqa: F401

from hyperv_mcp import filetransfer, policy, pswindows
from hyperv_mcp.config import Config


def test_realpath_authority_census(monkeypatch):
    """Predicate 1: guest axes must never consult host realpath (host axis must)."""
    seam_calls = []
    real_realpath = os.path.realpath

    def spy(path):
        seam_calls.append(os.fspath(path))
        return real_realpath(path)

    monkeypatch.setattr(policy.os.path, "realpath", spy)

    guest_cfg = Config(guest_read_roots=["C:\\g-read"], guest_write_roots=["C:\\g-write"])
    hit_axes = []
    for name, check, path in (
        ("check_guest_read", policy.check_guest_read, r"C:\g-read\x.bin"),
        ("check_guest_write", policy.check_guest_write, r"C:\g-write\x.bin"),
    ):
        seam_calls.clear()
        try:
            check(guest_cfg, path)
        except policy.PolicyDenied:
            pass
        if seam_calls:
            hit_axes.append(name)
    assert not hit_axes, f"guest axes consulting host realpath: {hit_axes}"

    # Positive control: the host axis still resolves through realpath, so
    # "remove realpath everywhere" cannot satisfy this predicate.
    host_root = os.path.abspath(os.getcwd())
    host_cfg = Config(host_write_roots=[host_root])
    seam_calls.clear()
    policy.check_host_write(host_cfg, os.path.join(host_root, "guardrail-probe.bin"))
    assert seam_calls, "host axis no longer consults realpath (positive control broken)"


def test_transport_literal_single_source():
    """Predicate 2: the "transport" literal lives only inside _failure_class."""
    text = Path(filetransfer.__file__).read_text(encoding="utf-8")
    count = text.count('"transport"') + text.count("'transport'")
    assert count == 1, f'"transport" literal occurs {count} times; must be single-sourced'
    tree = ast.parse(text)
    helper = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_failure_class"),
        None,
    )
    assert helper is not None, "_failure_class helper missing"
    pos = text.find('"transport"')
    if pos < 0:
        pos = text.find("'transport'")
    line = text.count("\n", 0, pos) + 1
    assert helper.lineno <= line <= helper.end_lineno, f'"transport" literal at line {line} outside _failure_class'


def test_staging_suffix_single_constructor():
    """Predicate 3: every Load of _STAGING_SUFFIX occurs inside _staging_path only."""
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
    # Plain-text cross-check: no destination + suffix construction outside the helper.
    helper_src = ast.get_source_segment(text, helper) or ""
    residual = text.replace(helper_src, "", 1)
    assert '+ ".mcptmp"' not in residual and "+ '.mcptmp'" not in residual, (
        "staging suffix concatenated outside _staging_path"
    )


def test_placement_census_all_four_tools(monkeypatch, tmp_path, rooted_cfg):  # noqa: F811
    """Predicate 4: the root-assertion fragment sits inside a guest -ScriptBlock in all four tools."""
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
    placements["guest_put"] = assertion_placement(fake.scripts[0])

    dest = tmp_path / "host-dst" / "census-back.bin"
    get_payload = json.dumps(
        {"ok": True, "bytes_copied": 1, "bytes_remote": 1, "sha256_local": "S", "sha256_remote": "S"}
    )
    fake = FakePS([pswindows.PSResult(stdout=get_payload, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_get(cfg, vm, r"C:\g-read\census.bin", str(dest), verify=True, cred=CRED)
    placements["guest_get"] = assertion_placement(fake.scripts[0])

    read_payload = json.dumps({"content_b64": "eA==", "bytes_read": 1, "truncated": False})
    fake = FakePS([pswindows.PSResult(stdout=read_payload, returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_read_file(cfg, vm, r"C:\g-read\census.bin", cred=CRED)
    placements["guest_read_file"] = assertion_placement(fake.scripts[0])

    fake = FakePS([pswindows.PSResult(stdout="[]", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_list_dir(cfg, vm, r"C:\g-read", cred=CRED)
    placements["guest_list_dir"] = assertion_placement(fake.scripts[0])

    bad = {name: plc for name, plc in placements.items() if plc != (0, 1)}
    assert not bad, f"assertion placement violations (outside, inside): {bad}"
