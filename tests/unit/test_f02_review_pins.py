"""Issue #26 non-frozen review pins (the PR #99 pattern).

The frozen pack in tests/unit/test_f02_checkpoint_type.py pins the issue's
acceptance criteria; this file pins the semantics the frozen checks
underconstrain (review-plan-critic Rounds 1-3): MCP forwarding, result-field
contracts, script-placement precision, the enum map, the real-PowerShell
error matrix of the standard variant, exact restore notes, the default-path
shape, the idempotency fingerprint, and positional-vm_id compatibility.

Every pin here is written to FAIL on a mutant that weakens the corresponding
semantics (the mutation probes are recorded in the issue trace).
"""

import asyncio
import importlib
import json
import os

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import lifecycle, pswindows
from hyperv_mcp.config import Config

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
RESOLUTION = pswindows.PSResult(stdout=GUID, returncode=0)
# Saved BEFORE any monkeypatching: the executing lane must run the real
# Windows PowerShell transport even while other tests patch run_ps.
_REAL_RUN_PS = pswindows.run_ps

OFF_NOTE = "VM is powered off after restore; call hyperv_start_vm to bring it back up."
SAVED_NOTE = (
    "Standard checkpoint restored the saved memory state; the VM is saved, not off. "
    "Call hyperv_start_vm to resume it with memory intact."
)
PAUSED_NOTE = (
    "Checkpoint restored; the VM is paused at the restored state. Call Resume-VM to "
    "resume it (hyperv_start_vm is for stopped/saved VMs)."
)
RUNNING_NOTE = "Checkpoint restored; the VM is running the restored state. No start needed."


def _is_resolver_leg(script):
    return "Msvm_ComputerSystem" in script and "ConvertTo-Json" not in script


def _action_legs(scripts):
    return [s for s in scripts if not _is_resolver_leg(s)]


def _norm(script):
    return " ".join(script.split())


class FakePS:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolver_leg(script):
            return RESOLUTION
        if not self.responses:
            return pswindows.PSResult(stdout="", returncode=0)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class Recorder:
    """Content-served recorder: resolver legs get the GUID, everything else an
    empty success or a canned action response."""

    def __init__(self, action_stdout=""):
        self.scripts = []
        self.action_stdout = action_stdout

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolver_leg(script):
            return RESOLUTION
        return pswindows.PSResult(stdout=self.action_stdout, returncode=0)


def _capture_standard_script(monkeypatch, original="Production"):
    """Drive checkpoint_create(standard) through a Recorder and return the
    action script plus the canned success rows the runtime would parse."""
    rec = Recorder(action_stdout=json.dumps({"original_type": original, "restore_error": ""}))
    monkeypatch.setattr(pswindows, "run_ps", rec)
    out = lifecycle.checkpoint_create(Config(unrestricted=True), "vm1", "base", checkpoint_type="standard")
    return _action_legs(rec.scripts)[-1], out, rec


# ---------------------------------------------------------------------------
# script-placement precision (C2 underconstrains placement, C5 the emission)
# ---------------------------------------------------------------------------

def test_restore_binding_sits_inside_or_after_finally(monkeypatch):
    script, _, _ = _capture_standard_script(monkeypatch)
    n = _norm(script)
    assert n.index("-CheckpointType $orig") > n.index("finally"), (
        "the CheckpointType restore must execute inside/after the finally block"
    )


def test_original_type_emits_the_captured_var_not_a_reread(monkeypatch):
    script, _, _ = _capture_standard_script(monkeypatch)
    n = _norm(script)
    assert "original_type=$orig" in n, "the result JSON must carry the captured $orig"
    assert "original_type=[string]$vm.CheckpointType" not in n, (
        "emitting a post-mutation re-read would misreport the pre-call type"
    )


def test_vm_info_emits_the_checkpoint_type_expression(monkeypatch):
    rec = Recorder(action_stdout=json.dumps({"id": GUID, "name": "vm1", "checkpoint_type": "Production"}))
    monkeypatch.setattr(pswindows, "run_ps", rec)
    lifecycle.get_vm_info(Config(unrestricted=True), "vm1")
    n = _norm(_action_legs(rec.scripts)[-1])
    assert "checkpoint_type = [string]$vm.CheckpointType" in n, (
        "get_vm_info must emit the typed CheckpointType read, not any substring mention"
    )


# ---------------------------------------------------------------------------
# enum map, invalid matrix, and caller compatibility
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,literal", [
    ("standard", "Standard"),
    ("production", "Production"),
    ("production_only", "ProductionOnly"),
])
def test_enum_maps_to_fixed_literals(monkeypatch, value, literal):
    monkeypatch.setattr(pswindows, "run_ps", FakePS())
    lifecycle.checkpoint_create(Config(unrestricted=True), "vm1", "base", checkpoint_type=value)
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.checkpoint_create(Config(unrestricted=True), "vm1", "base", checkpoint_type=value)
    assert f"-CheckpointType {literal}" in _action_legs(fake.scripts)[-1]


@pytest.mark.parametrize("bad", ["Standard; rm", "STANDARD", " standard", None, ["standard"]])
def test_invalid_inputs_raise_valueerror_before_any_powershell(monkeypatch, bad):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(ValueError, match="checkpoint_type"):
        lifecycle.checkpoint_create(Config(unrestricted=True), "vm1", "base", checkpoint_type=bad)
    assert fake.scripts == []


def test_positional_vm_id_still_binds_fourth(monkeypatch):
    """Round-1 critic: appending checkpoint_type must not shift the existing
    positional binding of vm_id (4th). The by-id name-lookup leg answers the
    VM name; the action preamble embeds the GUID."""
    scripts = []

    def fake(script, **kwargs):
        scripts.append(script)
        if "$vm.Name" in script:
            return pswindows.PSResult(stdout="vm1", returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.checkpoint_create(Config(unrestricted=True), "", "base", GUID)
    assert out["status"] == "created"
    assert not out.get("checkpoint_type"), "no type was requested"
    assert any(GUID in s for s in scripts), "4th positional vm_id must reach the scripts"
    assert not any("Set-VM" in s for s in scripts), "no type was requested: no Set-VM"


# ---------------------------------------------------------------------------
# default-path shape
# ---------------------------------------------------------------------------

def test_default_path_single_checkpoint_vm_and_no_new_result_keys(monkeypatch):
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.checkpoint_create(Config(unrestricted=True), "vm1")
    script = _action_legs(fake.scripts)[-1]
    assert script.count("Checkpoint-VM") == 1, "default path stays a single Checkpoint-VM"
    assert "Set-VM" not in script
    assert set(out) == {"status", "vm_name", "checkpoint_name"}, (
        "the default result contract must stay exactly today's keys"
    )


# ---------------------------------------------------------------------------
# restore notes: exact texts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("final,expected", [
    ("Off", OFF_NOTE),
    ("Saved", SAVED_NOTE),
    ("Paused", PAUSED_NOTE),
    ("Running", RUNNING_NOTE),
])
def test_restore_note_exact_texts(monkeypatch, final, expected):
    def fake(script, **kwargs):
        if _is_resolver_leg(script):
            return RESOLUTION
        if "final_state" in script:
            return pswindows.PSResult(stdout=json.dumps({"final_state": final}), returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.checkpoint_restore(Config(unrestricted=True), "vm1", "snap", confirm=True)
    assert out["note"] == expected


def test_off_note_is_byte_identical_to_the_legacy_constant():
    """The Off branch must keep today's wording byte-for-byte."""
    from hyperv_mcp import lifecycle as _l
    source = open(_l.__file__, encoding="utf-8").read()
    assert OFF_NOTE in source


def test_typed_path_auto_names_the_checkpoint(monkeypatch):
    """Final-critic probe 5 survivor: the auto-name contract (MCP-<timestamp>,
    README 'auto-generates ... only on create') must hold on the TYPED path
    too. A mutant that skips auto-naming whenever checkpoint_type is set
    (e.g. `if not checkpoint_name and not checkpoint_type:`) would otherwise
    emit an empty -SnapshotName and a blank result name, undetected."""
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = lifecycle.checkpoint_create(Config(unrestricted=True), "vm1", checkpoint_type="standard")
    assert out["checkpoint_name"].startswith("MCP-"), (
        f"the typed path must auto-name like the default path (got {out['checkpoint_name']!r})"
    )
    script = _action_legs(fake.scripts)[-1]
    assert out["checkpoint_name"] in script, "the auto-generated name must reach -SnapshotName"
    assert f"SnapshotName {pswindows.ps_name(out['checkpoint_name'])}" in script


# ---------------------------------------------------------------------------
# Phase 4.2 guardrail: the note is a pure function of the observed state
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("final", ["Off", "Saved", "Paused", "Running", "Starting"])
def test_guardrail_note_never_claims_a_state_it_is_not(final):
    """Issue #26's defect class: the restore note was a CONSTANT claiming Off
    regardless of the observed state. The note must be derived from the
    observed state — non-Off states must never be told the VM is powered off,
    and any unmodeled future state gets a neutral note, not a claim. RED on
    the original constant note for every non-Off state; GREEN on the map."""
    note = lifecycle.restore_note(final)
    if final == "Off":
        assert note == OFF_NOTE
    else:
        assert "powered off" not in note, f"{final}: {note!r}"
        assert note != OFF_NOTE


# ---------------------------------------------------------------------------
# real-PowerShell error matrix for the standard variant (executing lane)
# ---------------------------------------------------------------------------

_STUBS = """
function Get-VM { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments=$true)]$rest)
    [pscustomobject]@{ Id = 'e953c649-dcab-438d-9a54-3af74a82b624'; Name = 'vm1'; CheckpointType = 'Production' } }
function Set-VM { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments=$true)]$rest)
    $t = $null
    for ($i = 0; $i -lt $rest.Count; $i++) { if ($rest[$i] -eq '-CheckpointType') { $t = $rest[$i + 1] } }
    Add-Content -Path $env:F02_SVM_LOG -Value "set:$t"
    if ($env:F02_SVM_FAIL_ON -and $t -eq $env:F02_SVM_FAIL_ON) { Write-Error 'setvm-failed' -ErrorAction Stop } }
function Checkpoint-VM { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments=$true)]$rest)
    if ($env:F02_CP_FAIL -eq '1') { Write-Error 'checkpoint-failed' -ErrorAction Stop } }
"""


def _run_standard_script_real_ps(monkeypatch, tmp_path, cp_fail="0", svm_fail_on=""):
    """Execute the FULL generated standard-variant script under shadowing
    cmdlet stubs via the real Windows PowerShell transport."""
    script, _, _ = _capture_standard_script(monkeypatch)
    if not os.path.isfile(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
        pytest.skip("Windows PowerShell not available")
    pswindows.init(Config(unrestricted=True))
    log = tmp_path / "svm.log"
    composed = (
        f"$env:F02_SVM_LOG = '{log.as_posix()}'\n"
        f"$env:F02_CP_FAIL = '{cp_fail}'\n"
        f"$env:F02_SVM_FAIL_ON = '{svm_fail_on}'\n"
        + _STUBS + script
    )
    result = _REAL_RUN_PS(composed, timeout_s=120)
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls


def test_error_matrix_checkpoint_fails_restore_ok(monkeypatch, tmp_path):
    result, calls = _run_standard_script_real_ps(monkeypatch, tmp_path, cp_fail="1")
    assert result.returncode != 0 and "checkpoint-failed" in result.stderr
    assert calls == ["set:Standard", "set:Production"], (
        "the finally must restore the captured pre-call type after a checkpoint failure"
    )


def test_error_matrix_restore_fails_checkpoint_ok(monkeypatch, tmp_path):
    result, calls = _run_standard_script_real_ps(monkeypatch, tmp_path, svm_fail_on="Production")
    assert result.returncode != 0
    assert "restore failed" in result.stderr and "pre-call type Production" in result.stderr
    assert "set:Standard" in calls and "set:Production" in calls


def test_error_matrix_dual_failure_keeps_checkpoint_primary(monkeypatch, tmp_path):
    result, calls = _run_standard_script_real_ps(
        monkeypatch, tmp_path, cp_fail="1", svm_fail_on="Production"
    )
    assert result.returncode != 0
    assert "checkpoint-failed" in result.stderr, "checkpoint error must stay primary"
    assert "restore also failed" in result.stderr and "pre-call type Production" in result.stderr
    assert calls == ["set:Standard", "set:Production"]


def test_success_path_transport_mock_primary_error(monkeypatch):
    """Transport-level companion: an action-leg failure surfaces the stub's
    own checkpoint error text through the envelope, never a restore error."""
    fake = FakePS([
        pswindows.PSResult(stdout="", returncode=1, stderr="checkpoint-failed"),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(RuntimeError, match="checkpoint-failed"):
        lifecycle.checkpoint_create(Config(unrestricted=True), "vm1", "base", checkpoint_type="standard")


# ---------------------------------------------------------------------------
# MCP forwarding + tool description + schema stays confirm-free
# ---------------------------------------------------------------------------

def test_mcp_forwarding_reaches_the_generated_script(monkeypatch, tmp_path):
    """C1 pins the lifecycle layer and C6 the schema; this pin closes the gap:
    a Standard request through the REAL registered tool must forward
    checkpoint_type into the generated action script and report both types."""
    doc = {"allowed_vm_patterns": ["*"], "unrestricted": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    os.environ["HYPERV_MCP_STATE_DB"] = str(tmp_path / "state.db")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    scripts = []

    def fake_run_ps(script, **kwargs):
        scripts.append(script)
        if _is_resolver_leg(script):
            return RESOLUTION
        return pswindows.PSResult(
            stdout=json.dumps({"original_type": "Production", "restore_error": ""}), returncode=0
        )

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)
    result = asyncio.run(mod.get_mcp().call_tool(
        "hyperv_checkpoint_create",
        {"vm_name": "vm1", "checkpoint_name": "base", "checkpoint_type": "standard"},
    ))
    from conftest import content_blocks

    texts = [c for c in content_blocks(result) if getattr(c, "type", "") == "text"]
    payload = json.loads(texts[0].text)
    n = _norm(_action_legs(scripts)[-1])
    assert "-CheckpointType Standard" in n and "finally" in n, (
        "the MCP call path must forward checkpoint_type into the generated script"
    )
    assert payload["checkpoint_type"] == "standard"
    assert payload["vm_checkpoint_type"] == "Production"
    importlib.reload(server_module)


def test_tool_description_discloses_host_checkpoint_store():
    mod = importlib.reload(server_module)
    mod.bootstrap({})
    tools = asyncio.run(mod.get_mcp().list_tools())
    desc = next(t.description or "" for t in tools if t.name == "hyperv_checkpoint_create")
    assert "guest memory" in desc and "host checkpoint store" in desc, (
        "the security disclosure must name the host checkpoint store, not just memory"
    )
    assert "confirm" not in (
        getattr(next(t for t in tools if t.name == "hyperv_checkpoint_create"),
                "input_schema", None) or
        next(t for t in tools if t.name == "hyperv_checkpoint_create").inputSchema
    ).get("properties", {})
    importlib.reload(server_module)


# ---------------------------------------------------------------------------
# idempotency fingerprint
# ---------------------------------------------------------------------------

def test_idempotency_fingerprint_distinguishes_checkpoint_type(monkeypatch, tmp_path):
    """Same idempotency_key with a different checkpoint_type must conflict,
    not replay: checkpoint_type is NOT in _FINGERPRINT_EXCLUDED."""
    doc = {"allowed_vm_patterns": ["*"], "unrestricted": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    os.environ["HYPERV_MCP_STATE_DB"] = str(tmp_path / "state.db")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    scripts = []

    def fake_run_ps(script, **kwargs):
        scripts.append(script)
        if _is_resolver_leg(script):
            return RESOLUTION
        return pswindows.PSResult(
            stdout=json.dumps({"original_type": "Production", "restore_error": ""}), returncode=0
        )

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)
    from conftest import content_blocks

    asyncio.run(mod.get_mcp().call_tool(
        "hyperv_checkpoint_create",
        {"vm_name": "vm1", "checkpoint_type": "standard", "idempotency_key": "f02-pin"},
    ))
    result = asyncio.run(mod.get_mcp().call_tool(
        "hyperv_checkpoint_create",
        {"vm_name": "vm1", "checkpoint_type": "production", "idempotency_key": "f02-pin"},
    ))
    texts = [c for c in content_blocks(result) if getattr(c, "type", "") == "text"]
    envelope = json.loads(texts[0].text)
    assert envelope.get("ok") is False and "already used" in envelope.get("error", ""), (
        "same key + different checkpoint_type must be a fingerprint conflict, not a replay"
    )
    importlib.reload(server_module)


# ---------------------------------------------------------------------------
# parse-lane non-vacuity companion (C10 stays GREEN-shape at base)
# ---------------------------------------------------------------------------

def test_standard_variant_script_exists_and_folds_the_three_steps(monkeypatch):
    """Companion to the frozen C10: post-fix, the standard variant really
    produces a folded script for the parse lane to chew on."""
    script, _, _ = _capture_standard_script(monkeypatch)
    assert "Set-VM" in script and "Checkpoint-VM" in script and "finally" in script
