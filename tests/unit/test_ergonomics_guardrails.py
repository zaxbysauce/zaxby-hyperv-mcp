"""Companion guardrails for the collated 131/132/133 PR (final-critic C4/C5).

These are NON-FROZEN tests (the 15 acceptance checks stay byte-frozen). Each
kills a mutant the frozen spec alone let survive:

* REG-1: an asymmetric-VM barrier probe — removing the rendezvous in
  run_sequence_multi lets VM A's post step dispatch before VM B's slow pre
  step completes; the frozen C6 uses symmetric timing and passed that mutant
  10/10.
* REG-2: bind-time inflight reservation — dropping the counter reservation in
  evidencejournal.begin let stop certify an empty manifest while a journal
  line was still to be written; none of C1-C5 referenced inflight.
"""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from pathlib import Path

from hyperv_mcp import evidencejournal, pswindows, wmiconsole
from hyperv_mcp.config import Config

wmiconsole.COM_AVAILABLE = False

GUID_A = str(uuid.uuid5(uuid.NAMESPACE_OID, "guard-vm-a"))
GUID_B = str(uuid.uuid5(uuid.NAMESPACE_OID, "guard-vm-b"))


class _AsymPS:
    """Folded console transport; VM B's pre step is delayed 0.4 s."""

    def __init__(self) -> None:
        self.scripts: list[str] = []
        # Keyed by (vm, step-kind): call ORDER changes when the barrier is
        # removed, so positional timestamps cannot detect it (R2-C2).
        self.starts: dict[tuple[str, str], float] = {}
        self.ends: dict[tuple[str, str], float] = {}

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        self.scripts.append(script)
        m = re.search(r"ElementName -eq '([^']*)'", script)
        name = m.group(1) if m else ""
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            guid = GUID_A if name == "guard-vm-a" else GUID_B
            return pswindows.PSResult(stdout=guid, returncode=0)
        if "MethodName TypeScancodes" in script:
            kind = "pre" if "(30,158)" in script else "post"
            key = (name, kind)
            self.starts[key] = time.monotonic()
            if name == "guard-vm-b" and kind == "pre":
                time.sleep(0.4)
            self.ends[key] = time.monotonic()
            return pswindows.PSResult(
                stdout=f"VMID={GUID_A if name == 'guard-vm-a' else GUID_B}\n"
                       "EPOCH=7\nSTEP=0 OK=1\n", returncode=0)
        if "EnabledState" in script or "Msvm_VideoHead" in script:
            return pswindows.PSResult(stdout="{}", returncode=0)
        return pswindows.PSResult(stdout="RC=1 CHUNK=1/1", returncode=0)


def test_reg1_barrier_holds_with_asymmetric_vm_timing(monkeypatch, tmp_path):
    import importlib

    import hyperv_mcp.server as server

    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({"unrestricted": True}), encoding="utf-8")
    mod = importlib.reload(server)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_file)})
    stub = _AsymPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    plans = [
        {"vm_name": "guard-vm-a",
         "steps": [{"action": "press_key", "key": "a"},
                   {"action": "barrier", "name": "s"},
                   {"action": "press_key", "key": "enter"}]},
        {"vm_name": "guard-vm-b",
         "steps": [{"action": "press_key", "key": "a"},
                   {"action": "barrier", "name": "s"},
                   {"action": "press_key", "key": "enter"}]},
    ]
    out = mod.get_mcp()
    import asyncio

    result = asyncio.run(out.call_tool("hyperv_console_sequence_multi",
                                       {"plans": plans, "barriers": ["s"]}))
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    text = next(c.text for c in content if getattr(c, "type", "") == "text")
    payload = json.loads(text)
    assert payload.get("ok") is True, payload
    pre_idx = [i for i, s in enumerate(stub.scripts) if "(30,158)" in s]
    post_idx = [i for i, s in enumerate(stub.scripts) if "(28,156)" in s]
    assert len(pre_idx) == 2 and len(post_idx) == 2, stub.scripts
    assert max(pre_idx) < min(post_idx), (
        "REG-1: a post-barrier step dispatched before BOTH VMs' pre steps "
        f"(barrier rendezvous removed?) indices={pre_idx}/{post_idx}")
    # B's slow pre step is the last of the two arrivals; its completion
    # timestamp must precede the first post step's dispatch time.
    b_pre_end = stub.ends[("guard-vm-b", "pre")]
    for vm in ("guard-vm-a", "guard-vm-b"):
        post_start = stub.starts[(vm, "post")]
        assert post_start >= b_pre_end, (
            f"REG-1: {vm}'s post step began before the slow VM's pre step "
            f"COMPLETED (post={post_start:.3f}, b_pre_end={b_pre_end:.3f})")


def test_reg2_stop_manifest_waits_for_bound_token(tmp_path):
    """A token bound BEFORE stop must be drained and journalled before the
    manifest digest is computed (mutant: remove inflight reservation)."""
    evidencejournal.reset_for_tests()
    cfg = Config(unrestricted=True)
    evidencejournal.install(get_config=lambda: cfg,
                            is_mutating=lambda n: n == "hyperv_console_press_key",
                            screenshot=lambda *a, **k: {})
    start = evidencejournal.start_run(str(tmp_path / "reg2"), ["vm-x"])
    assert start.get("ok") is True
    run_id = start["run_id"]
    token = evidencejournal.begin("hyperv_console_press_key",
                                  {"vm_name": "vm-x"})
    assert token is not None
    stopped: dict = {}

    def _stop() -> None:
        stopped.update(evidencejournal.stop_run(run_id))

    th = threading.Thread(target=_stop)
    th.start()
    time.sleep(0.05)
    evidencejournal.finish(token, {"ok": True}, outcome="body")
    th.join(10)
    assert stopped.get("ok") is True, stopped
    manifest = json.loads(Path(stopped["manifest"]).read_text(encoding="utf-8"))
    digest = __import__("hashlib").sha256(
        (tmp_path / "reg2" / "journal.jsonl").read_bytes()).hexdigest()
    assert manifest["entries"].get("journal.jsonl") == digest, (
        "REG-2: manifest digest does not cover the token's journal line")


def test_reg3_heartbeat_disable_owner_only(monkeypatch, tmp_path):
    """The owner can stop its own heartbeat; a foreign caller cannot
    (final-critic R2-C1). The disable path uses the heartbeat's bound
    fencing token, not 0."""
    import importlib

    from hyperv_mcp import console, leases

    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({"unrestricted": True}), encoding="utf-8")
    mod = importlib.reload(importlib.import_module("hyperv_mcp.server"))
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_file)})
    cfg = mod._cfg()
    console.reset_input_ledger()
    leases.clear_registry_for_tests() if hasattr(leases, "clear_registry_for_tests") else None
    rows = leases.acquire(cfg, "guard-hb-vm", ["console"], "owner-agent",
                          vm_name="guard-hb-vm")
    lease = next(r for r in rows if r.scope == "console")
    hb = console.heartbeat_enable(
        cfg, vm_name="guard-hb-vm", vm_id=lease.vm_id, key="shift",
        interval_s=5.0, lease_id=lease.lease_id,
        fencing_token=lease.fencing_token, agent="owner-agent")
    assert hb.get("ok") is True, hb
    foreign = console.heartbeat_disable(
        cfg, vm_name="guard-hb-vm", vm_id=lease.vm_id, agent="other-agent",
        lease_id=lease.lease_id)
    assert foreign.get("ok") is False, foreign
    assert console.heartbeat_status(cfg, vm_name="guard-hb-vm")["enabled"] is True
    owner = console.heartbeat_disable(
        cfg, vm_name="guard-hb-vm", vm_id=lease.vm_id, agent="owner-agent",
        lease_id=lease.lease_id)
    assert owner.get("ok") is True, owner
    assert console.heartbeat_status(cfg, vm_name="guard-hb-vm")["enabled"] is False
    console.reset_input_ledger()
