"""Issue #132 acceptance checks: coordinated multi-VM console sequences.

RED at base, GREEN after the fix. Five checks, one per acceptance criterion:
  AC1 test_barrier_holds_until_all_arrive — no step after a barrier starts
      on ANY VM until every VM has reached it (the dispatched fake scripts
      are the ordering oracle).
  AC2 test_every_step_has_host_timestamps — every step result carries a
      host monotonic AND a wall-clock timestamp.
  AC3 test_failure_stops_all_vms — a step failure on one VM stops every VM
      at its next step, remaining steps reported skipped.
  AC4 test_lease_failure_refuses_whole_plan — a lease-check failure on any
      plan VM refuses the whole plan before input is sent to any VM.
  AC5 test_single_vm_sequence_unchanged — the single-VM tool keeps its
      current envelope and validation (PRESERVING floor for #28 callers).

Surface reconciliation (the issue leaves these free; the observables here
are the contract): hyperv_console_sequence_multi takes `plans` — a list of
per-VM plan dicts {vm_name, steps, lease_id?, fencing_token?} — and
`barriers`, the list of barrier names; a barrier point is a marker step
{"action": "barrier", "name": <barrier>} inside a plan's steps, composed
from the existing single-VM step grammar (server.py's hyperv_console_sequence
docstring). Timestamp fields are discovered by name shape (a key containing
"monoton"; a key containing "wall"/"utc" with a numeric or ISO-8601 value).

What is faked: every PowerShell leg. Conftest pins the folded console
transport (COM_AVAILABLE False); pswindows.run_ps is stubbed with the
SeqPS pattern from tests/unit/test_console_commit_guard_sequence.py —
per-name GUID resolution legs, then folded sequence legs answering the
frozen VMID/EPOCH/STEP protocol with one STEP line per TypeScancodes step
block the script carries. Scancode literals in the recorded scripts are the
per-step, per-VM dispatch oracle (a=30,158 enter=28,156 space=57,185). The
ledger is reset around every test.
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import re
import uuid
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import console, pswindows

VM_A = "race-vm-a"
VM_B = "race-vm-b"


def _guid_for(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_OID, name))


def _vm_name_in(script: str) -> str:
    """The VM name a folded script's embedded resolver carries — by-name
    console scripts embed the resolver, so the NAME literal (not a GUID)
    is the per-VM dispatch marker."""
    m = re.search(r"ElementName -eq '([^']*)'", script)
    return m.group(1) if m else ""


# press_key scancode literals inside a folded sequence script (make,break).
PRE_CODES = "(30,158)"    # press_key "a"      — the pre-barrier phase
POST_CODES = "(28,156)"   # press_key "enter"  — the post-barrier phase
TAIL_CODES = "(57,185)"   # press_key "space"  — the after-second-barrier tail


class MultiPS:
    """Recording run_ps stub serving the multi-VM legs: per-name by-name
    resolution, folded display/capture legs, and folded sequence legs that
    answer the frozen VMID/EPOCH/STEP protocol (one STEP line per
    TypeScancodes step block the script carries). `fail_b_post` makes every
    vm-B leg carrying POST_CODES report a failed step (issue #132 AC3)."""

    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.fail_b_post = False

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=_guid_for(_vm_name_in(script)),
                                      returncode=0)
        if "GetVirtualSystemThumbnailImage" in script:
            return pswindows.PSResult(stdout="{}", returncode=0)
        if "EnabledState" in script:
            body = json.dumps({
                "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
                "keyboard_present": True, "keyboard_enabled": 2,
                "mouse_present": True, "mouse_enabled": 2,
            })
            return pswindows.PSResult(stdout="VMID=" + _guid_for(_vm_name_in(script))
                                      + "\n" + body, returncode=0)
        if "Msvm_VideoHead" in script:
            return pswindows.PSResult(
                stdout='{"horizontal": 1024, "vertical": 768}', returncode=0)
        if "MethodName TypeScancodes" in script:
            name = _vm_name_in(script)
            steps = script.count("MethodName TypeScancodes")
            if self.fail_b_post and name == VM_B and POST_CODES in script:
                err = base64.b64encode(
                    b"synthetic step failure (issue #132 AC3)").decode("ascii")
                lines = ["VMID=" + _guid_for(VM_B), "EPOCH=7",
                         "STEP=0 OK=0 ERR=" + err]
                lines += [f"STEP={j} SKIPPED=1 STOP=failure"
                          for j in range(1, steps)]
                return pswindows.PSResult(stdout="\n".join(lines) + "\n",
                                          returncode=0)
            lines = ["VMID=" + _guid_for(name or VM_A), "EPOCH=4242"]
            lines += [f"STEP={j} OK=1" for j in range(steps)]
            return pswindows.PSResult(stdout="\n".join(lines) + "\n",
                                      returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)


@pytest.fixture(autouse=True)
def _clean_console_state(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)
    console.reset_input_ledger()
    yield
    console.reset_input_ledger()


def _boot(tmp_path: Path):
    cfg_file = tmp_path / "multi-cfg.json"
    cfg_file.write_text(json.dumps({
        "unrestricted": True,
        "audit_log_path": str(tmp_path / "audit.jsonl"),
    }), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_file)})
    return mod


def _call(mcp, tool: str, args: dict) -> dict:
    result = asyncio.run(mcp.call_tool(tool, args))
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {tool}"
    return json.loads(texts[0].text)


def _step_entries(node, inside_steps: bool = False) -> list[dict]:
    """Every step-result dict in a multi-VM envelope: dicts nested under a
    *step*-shaped key, or dicts carrying the single-VM step markers
    (index / skipped)."""
    out: list[dict] = []
    if isinstance(node, dict):
        if inside_steps or "index" in node or "skipped" in node:
            out.append(node)
        for k, v in node.items():
            out += _step_entries(v, "step" in str(k).lower())
    elif isinstance(node, list):
        for v in node:
            out += _step_entries(v, inside_steps)
    return out


def _vm_result_dicts(node) -> list[dict]:
    """Every per-VM result dict in a multi-VM envelope (a dict holding both
    an `ok` and a `steps` key, at any nesting depth)."""
    out: list[dict] = []
    if isinstance(node, dict):
        if "steps" in node and "ok" in node:
            out.append(node)
        for v in node.values():
            out += _vm_result_dicts(v)
    elif isinstance(node, list):
        for v in node:
            out += _vm_result_dicts(v)
    return out


def _two_vm_plans(post_action: str = "enter") -> list[dict]:
    """Two one-step-before / one-step-after plans sharing one barrier."""
    steps = [
        {"action": "press_key", "key": "a"},
        {"action": "barrier", "name": "sync-1"},
        {"action": "press_key", "key": post_action},
    ]
    return [
        {"vm_name": VM_A, "steps": [dict(s) for s in steps]},
        {"vm_name": VM_B, "steps": [dict(s) for s in steps]},
    ]


# ---------------------------------------------------------------------------
# AC1 — no step after the barrier starts on ANY VM until every VM reached it
# ---------------------------------------------------------------------------

def test_barrier_holds_until_all_arrive(tmp_path, monkeypatch):
    """AC1: with a shared barrier between a pre and a post phase, every
    dispatched pre-barrier script completes before any post-barrier script
    starts — expressed over the recorded fake dispatches, which carry the
    per-step scancode literals and the per-VM GUIDs. A plan not split at
    the barrier (one script carrying both phases) fails the same
    separation assert.

    RED at base: hyperv_console_sequence_multi does not exist."""
    mod = _boot(tmp_path)
    try:
        stub = MultiPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()
        out = _call(mcp, "hyperv_console_sequence_multi",
                    {"plans": _two_vm_plans(), "barriers": ["sync-1"]})
        assert out.get("ok") is True, (
            "AC1: the two-VM barrier plan must succeed against the fake "
            f"transport (envelope: {json.dumps(out)[:400]})")

        pre_idx = [i for i, s in enumerate(stub.scripts) if PRE_CODES in s]
        post_idx = [i for i, s in enumerate(stub.scripts) if POST_CODES in s]
        assert pre_idx and post_idx, (
            "AC1: both barrier phases must have dispatched "
            f"(scripts: {len(stub.scripts)})")
        assert max(pre_idx) < min(post_idx), (
            "AC1: a post-barrier step dispatched before every VM reached "
            "the barrier — dispatch order was "
            + str([("pre" if PRE_CODES in s
                    else "post" if POST_CODES in s else "other")
                   for s in stub.scripts]))
        # and BOTH VMs ran the pre phase (the barrier needs every arrival)
        assert any(f"ElementName -eq '{VM_A}'" in s
                   for s in stub.scripts if PRE_CODES in s), (
            "AC1: vm A never dispatched its pre-barrier step")
        assert any(f"ElementName -eq '{VM_B}'" in s
                   for s in stub.scripts if PRE_CODES in s), (
            "AC1: vm B never dispatched its pre-barrier step")
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC2 — host monotonic and wall-clock timestamps on every step
# ---------------------------------------------------------------------------

def test_every_step_has_host_timestamps(tmp_path, monkeypatch):
    """AC2: every step result in the multi-VM envelope carries a host
    monotonic timestamp and a wall-clock timestamp (numeric epoch or
    ISO-8601), and the monotonic values never decrease within a VM — the
    recorded ordering a race reproduction needs.

    RED at base: hyperv_console_sequence_multi does not exist."""
    mod = _boot(tmp_path)
    try:
        stub = MultiPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()
        plans = [{
            "vm_name": VM_A,
            "steps": [
                {"action": "press_key", "key": "a"},
                {"action": "press_key", "key": "enter"},
            ],
        }]
        out = _call(mcp, "hyperv_console_sequence_multi", {"plans": plans})
        assert out.get("ok") is True, (
            "AC2: the single-plan multi call must succeed "
            f"(envelope: {json.dumps(out)[:400]})")
        entries = _step_entries(out)
        assert len(entries) >= 2, (
            f"AC2: expected both step results in the envelope (got "
            f"{len(entries)}: {json.dumps(out)[:400]})")
        monos: list[float] = []
        for entry in entries:
            mono = [v for k, v in entry.items()
                    if "monoton" in k.lower() and isinstance(v, (int, float))]
            wall = [v for k, v in entry.items()
                    if ("wall" in k.lower() or "utc" in k.lower())]
            assert mono, (
                f"AC2: step {entry.get('index', '?')} carries no host "
                f"monotonic timestamp (entry: {json.dumps(entry)[:200]})")
            assert wall and (
                isinstance(wall[0], (int, float))
                or (isinstance(wall[0], str)
                    and re.match(r"\d{4}-\d{2}-\d{2}", wall[0]))), (
                f"AC2: step {entry.get('index', '?')} carries no wall-clock "
                f"timestamp (entry: {json.dumps(entry)[:200]})")
            monos.append(float(mono[0]))
        assert monos == sorted(monos), (
            "AC2: monotonic timestamps must not decrease across the plan's "
            f"steps (saw {monos})")
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC3 — a step failure on one VM stops every VM at its next step
# ---------------------------------------------------------------------------

def test_failure_stops_all_vms(tmp_path, monkeypatch):
    """AC3: vm B's post-barrier step fails; the tail step after the SECOND
    barrier is unreachable for both VMs (vm B never arrives at it), so a
    conforming coordinator must stop every VM and report the remaining
    steps as skipped — never dispatch them.

    RED at base: hyperv_console_sequence_multi does not exist."""
    steps = [
        {"action": "press_key", "key": "a"},
        {"action": "barrier", "name": "sync-1"},
        {"action": "press_key", "key": "enter"},
        {"action": "barrier", "name": "sync-2"},
        {"action": "press_key", "key": "space"},
    ]
    mod = _boot(tmp_path)
    try:
        stub = MultiPS()
        stub.fail_b_post = True
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()
        plans = [
            {"vm_name": VM_A, "steps": [dict(s) for s in steps]},
            {"vm_name": VM_B, "steps": [dict(s) for s in steps]},
        ]
        out = _call(mcp, "hyperv_console_sequence_multi",
                    {"plans": plans, "barriers": ["sync-1", "sync-2"]})

        entries = _step_entries(out)
        failure_surfaced = (
            any(e.get("ok") is False for e in entries)
            or any(vm.get("ok") is False for vm in _vm_result_dicts(out))
            or out.get("ok") is False
        )
        assert failure_surfaced, (
            "AC3: the vm-B step failure must surface in the result "
            f"(envelope: {json.dumps(out)[:400]})")
        skipped = [e for e in entries if e.get("skipped")]
        assert len(skipped) >= 2, (
            "AC3: the remaining steps on BOTH VMs must be reported skipped "
            f"(skipped entries: {len(skipped)}, envelope: "
            f"{json.dumps(out)[:400]})")
        assert not any(TAIL_CODES in s for s in stub.scripts), (
            "AC3: input was dispatched for a step after the failure — every "
            "VM must stop at its next step "
            f"(scripts: {[s[:60] for s in stub.scripts]})")
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC4 — a lease-check failure on any plan VM refuses the whole plan
# ---------------------------------------------------------------------------

def test_lease_failure_refuses_whole_plan(tmp_path, monkeypatch):
    """AC4: vm B's plan cites a lease that does not exist; the whole plan
    is refused (the single-VM lease_unknown class) with zero input
    dispatched to ANY VM — vm A's clean plan must not run either.

    RED at base: hyperv_console_sequence_multi does not exist."""
    mod = _boot(tmp_path)
    try:
        stub = MultiPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()
        plans = [
            {"vm_name": VM_A,
             "steps": [{"action": "press_key", "key": "a"}]},
            {"vm_name": VM_B,
             "lease_id": "lease-does-not-exist-132ac4", "fencing_token": 1,
             "steps": [{"action": "press_key", "key": "a"}]},
        ]
        out = _call(mcp, "hyperv_console_sequence_multi",
                    {"plans": plans, "barriers": []})
        assert out.get("ok") is False, (
            "AC4: a plan citing an unknown lease must be refused "
            f"(envelope: {json.dumps(out)[:400]})")
        assert out.get("error_class") == "lease_unknown", (
            "AC4: the refusal must carry the single-VM lease gate's "
            f"lease_unknown class (got {out.get('error_class')!r})")
        input_scripts = [
            s for s in stub.scripts
            if "TypeScancodes" in s or "TypeText" in s or "ClickButton" in s
            or "SetButtonState" in s
        ]
        assert input_scripts == [], (
            "AC4: input was dispatched before the whole-plan lease refusal "
            f"({len(input_scripts)} input scripts ran)")
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC5 — single-VM console sequences unchanged (PRESERVING floor)
# ---------------------------------------------------------------------------

def test_single_vm_sequence_unchanged(tmp_path, monkeypatch):
    """AC5: hyperv_console_sequence keeps its current envelope and
    validation: a one-step plan succeeds with per-step results, and an
    invalid step is still the step-indexed invalid envelope (the #28
    callers' floor; the multi-VM surface must not move it).

    GREEN-preserving at base by design."""
    mod = _boot(tmp_path)
    try:
        stub = MultiPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()
        out = _call(mcp, "hyperv_console_sequence", {
            "steps": [{"action": "press_key", "key": "enter"}],
            "vm_name": VM_A,
        })
        assert out.get("ok") is True, (
            "AC5: the single-VM sequence must keep succeeding "
            f"(envelope: {json.dumps(out)[:400]})")
        steps = out.get("steps", [])
        assert len(steps) == 1 and steps[0].get("ok") is True, (
            "AC5: the single-VM sequence must keep its per-step results "
            f"(steps: {json.dumps(steps)[:300]})")

        refused = _call(mcp, "hyperv_console_sequence", {
            "steps": [{"action": "no-such-action"}],
            "vm_name": VM_A,
        })
        assert refused.get("ok") is False, (
            "AC5: an invalid step must still be refused")
        assert refused.get("error_class") == "invalid", (
            "AC5: an invalid step must keep the invalid error class (got "
            f"{refused.get('error_class')!r})")
        assert "step 0" in refused.get("error", ""), (
            "AC5: the refusal must keep naming the step index "
            f"(error: {refused.get('error', '')[:200]})")
    finally:
        importlib.reload(server_module)
