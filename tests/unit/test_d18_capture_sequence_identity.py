"""Acceptance checks for issue #82 (Workstream D follow-up, D-18): capture_sequence
pins the VM identity across its per-frame processes.

Each capture_sequence frame is one self-contained folded process that
re-resolves the VM by NAME; at base no frame carries identity metadata and the
host diffs payloads blindly, so a mid-sequence rename/recreate under the same
name splices frames from two different physical VMs into one plausible-looking
result. This file freezes the fix's contract: the per-frame script emits
``VMID=``, the host routes it through the same ``guestexec.validate_vm_guid``
gate the screenshot path uses, a mid-sequence identity change aborts the
sequence with a structured error naming both GUIDs, every frame reports the
GUID it actually captured, and frames without a ``VMID=`` line (the folded
self-containment pin's metadata-less captures) stay unattributed and legal.

RED at base ed5a35f33d42ca92b7ba393bd10fa5654a83e4a9, GREEN after the fix.
AC-mapped rows: C10 (AC1) and C12 (AC3) of the trace; the same-identity
reporting pin is the companion.
"""

from __future__ import annotations

import base64
import json

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config

GUID_A = "e953c649-dcab-438d-9a54-3af74a82b624"
GUID_B = "0f7d1c22-2222-4b3c-8d1e-6a5b4c3d2e1f"
W, H = 320, 240


def _frame_response(guid: str | None, pixel: int) -> pswindows.PSResult:
    payload = b"\x01\x02\x03\x04" + bytes([pixel]) * (W * H * 2)
    body = json.dumps({
        "returnValue": 0,
        "imageDataB64": base64.b64encode(payload).decode(),
    })
    stdout = (f"VMID={guid}\n{body}") if guid else body
    return pswindows.PSResult(stdout=stdout, returncode=0)


class _SequenceStub:
    """Serves one queued response per capture script (one process per frame)."""

    def __init__(self, responses) -> None:
        self.scripts: list[str] = []
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return self.responses.pop(0)


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


# ---------------------------------------------------------------------------
# AC1 (C10) — a mid-sequence identity change aborts the sequence
# ---------------------------------------------------------------------------

def test_sequence_aborts_when_a_frame_resolves_a_different_vm(monkeypatch, unrestricted):
    stub = _SequenceStub([
        _frame_response(GUID_A, 0x00),
        _frame_response(GUID_B, 0x5A),
    ])
    monkeypatch.setattr(pswindows, "run_ps", stub)
    captured = "ok"
    try:
        console.capture_sequence(
            unrestricted, "vm1", count=2, interval_s=1, width=W, height=H)
    except console.ConsoleError as exc:
        captured = str(exc)
    except Exception as exc:  # a non-structured error is also a failure here
        captured = f"WRONG-TYPE: {exc!r}"
    assert GUID_A in captured and GUID_B in captured, (
        "D18-AC1-RED-AT-BASE: capture_sequence accepts frames resolved to two "
        f"different VM GUIDs and returns a spliced sequence (outcome: "
        f"{captured[:200]!r}); a sequence spanning two identities must fail "
        "loudly naming both GUIDs"
    )


# ---------------------------------------------------------------------------
# AC3 (C12) — an invalid VMID= is a structured identity error
# ---------------------------------------------------------------------------

def test_sequence_rejects_an_invalid_frame_guid(monkeypatch, unrestricted):
    stub = _SequenceStub([
        _frame_response(GUID_A, 0x00),
        _frame_response("not-a-guid", 0x00),
    ])
    monkeypatch.setattr(pswindows, "run_ps", stub)
    captured = "ok"
    try:
        console.capture_sequence(
            unrestricted, "vm1", count=2, interval_s=1, width=W, height=H)
    except console.ConsoleError as exc:
        captured = str(exc)
    except Exception as exc:
        captured = f"WRONG-TYPE: {exc!r}"
    assert captured != "ok" and not captured.startswith("WRONG-TYPE"), (
        "D18-AC3-RED-AT-BASE: a frame emitting VMID=not-a-guid is accepted and "
        f"decoded (outcome: {captured[:200]!r}); the frame GUID must pass the "
        "same validate_vm_guid gate the screenshot path uses"
    )
    assert "invalid" in captured.lower()


# ---------------------------------------------------------------------------
# companion pins — same identity reports per frame; absent metadata stays legal
# ---------------------------------------------------------------------------

def test_sequence_reports_each_frame_identity(monkeypatch, unrestricted):
    stub = _SequenceStub([
        _frame_response(GUID_A, 0x00),
        _frame_response(GUID_A, 0x00),
        _frame_response(GUID_A, 0x00),
    ])
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.capture_sequence(
        unrestricted, "vm1", count=3, interval_s=1, width=W, height=H)
    assert out["ok"] is True
    assert [f["vm_id"] for f in out["frames"]] == [GUID_A] * 3, (
        "every frame must report the GUID it actually captured"
    )
    # one folded process per frame — the identity channel adds no process
    assert len(stub.scripts) == 3
    for script in stub.scripts:
        assert "VMID=" in script, (
            "the per-frame capture script must emit the VMID= metadata line"
        )


def test_sequence_without_metadata_stays_unattributed(monkeypatch, unrestricted):
    """#82 AC2's tolerance rule: the folded self-containment pin serves
    metadata-less captures — a frame with no VMID= line is unattributed, not
    an error (strictness applies only when VMID= is present)."""
    stub = _SequenceStub([
        _frame_response(None, 0x00),
        _frame_response(None, 0x00),
    ])
    monkeypatch.setattr(pswindows, "run_ps", stub)
    out = console.capture_sequence(
        unrestricted, "vm1", count=2, interval_s=1, width=W, height=H)
    assert out["ok"] is True
    assert all(f["vm_id"] is None for f in out["frames"])
