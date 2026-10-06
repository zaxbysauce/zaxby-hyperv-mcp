"""By-id policy runs on the RESOLVED name (issue #8 reviewer round-1 falsifier).

C6 pins the deny direction (resolved name outside the pattern is refused).
These tests pin the complementary, equally load-bearing direction: a GUID
whose resolved name IS allowed must be ADMITTED under restricted patterns —
so a lazy predicate keyed on the raw vm_id string (which never matches a
name pattern) or on an empty name cannot pass here — and a both-given
mismatch is still rejected before any script runs.
"""

import json

from hyperv_mcp import lifecycle, pswindows, vmident
from hyperv_mcp.config import Config
from hyperv_mcp.policy import PolicyDenied

PROD_ID = "0f6e6a8a-1d3c-4a52-9a43-6f0b2f0c1a11"
TEST_ID = "e953c649-dcab-438d-9a54-3af74a82b624"


class _ByIdFake:
    """Serves the by-id leg (Get-VM -Id ... emits the bare resolved name),
    then canned responses for the action legs; records every script."""

    def __init__(self, resolved_name, actions=()):
        self.resolved_name = resolved_name
        self.responses = list(actions)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Get-VM -Id $vmTarget" in script and script.rstrip().endswith("$vm.Name"):
            return pswindows.PSResult(stdout=self.resolved_name, returncode=0)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_by_id_admitted_when_resolved_name_matches_pattern(monkeypatch):
    cfg = Config(allowed_vm_patterns=["test-*"])
    fake = _ByIdFake(
        "test-vm-1",
        [
            pswindows.PSResult(stdout=json.dumps({"initial_state": "Stopped"}), returncode=0),
            pswindows.PSResult(stdout=json.dumps({"final_state": "Running"}), returncode=0),
        ],
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    ref = vmident.resolve(cfg, vm_id=TEST_ID)
    assert ref.name == "test-vm-1" and ref.id == TEST_ID
    result = lifecycle.start_vm(cfg, vm_id=TEST_ID)
    assert result["status"] == "started"
    # the action scripts must have run (a lazy raw-vm_id-keyed policy would
    # have denied BEFORE them), and they address the GUID, not the raw string
    action = fake.scripts[-2]
    assert "$vmTarget = 'e953c649-dcab-438d-9a54-3af74a82b624'" in action


def test_by_id_denied_after_only_the_readonly_leg(monkeypatch):
    cfg = Config(allowed_vm_patterns=["test-*"])
    fake = _ByIdFake("prod-db")
    monkeypatch.setattr(pswindows, "run_ps", fake)
    try:
        lifecycle.start_vm(cfg, vm_id=PROD_ID)
    except PolicyDenied:
        pass
    else:
        raise AssertionError("out-of-pattern resolved name must be denied")
    # exactly one read-only leg (the Get-VM -Id resolution); no action script
    assert len(fake.scripts) == 1
    assert "Get-VM -Id $vmTarget" in fake.scripts[0]
    assert not any(m in fake.scripts[0] for m in ("Start-VM", "Stop-VM", "Invoke-Command", "New-VM"))


def test_both_given_mismatch_rejected_before_action(monkeypatch):
    cfg = Config(unrestricted=True)
    fake = _ByIdFake("prod-db")
    monkeypatch.setattr(pswindows, "run_ps", fake)
    try:
        vmident.resolve(cfg, vm_name="test-vm-1", vm_id=PROD_ID)
    except ValueError as exc:
        assert "different VMs" in str(exc)
    else:
        raise AssertionError("name/id mismatch must raise")
    assert fake.scripts == [fake.scripts[0]], "no action leg after mismatch"
