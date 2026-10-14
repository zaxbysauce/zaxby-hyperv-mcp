"""Busy-taxonomy wiring tests for issue #15 (Change 6b of the approved plan).

The frozen acceptance checks pin pswindows.run_ps's pool behavior
(test_c02_ps_cap.py) and errors.classify directly (C4); these tests pin the
WIRING — that a PowerShellBusy raised through a real module path surfaces as
error_class "busy" at the layer that owns each key:

- guestexec's module result dicts carry {ok, error, error_class} only;
  retryable/retry_after_ms are attached by errors.enrich_failure at the
  server boundary (server.py), so that is where the retryable assertion
  lives.
- guestjobs.job_stop keeps its documented stop-result key set; a busy stop
  leg reports error_class "busy" with stopped=False and the entry stays
  retryable.

No real process spawns: run_ps is monkeypatched at the pswindows module
attribute each consumer calls.
"""

import pytest

from hyperv_mcp import errors, guestexec, guestjobs, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")


VM_GUID = "e953c649-1234-5678-9abc-def012345678"  # same canned GUID as test_guestexec


class SeqPS:
    """Sequenced fake like tests/unit/test_guestexec.py::FakePS: first leg
    resolves the VM (GUID stdout), the guest leg raises the given exception."""

    def __init__(self, exc):
        self.exc = exc
        self.calls = 0

    def __call__(self, script, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return pswindows.PSResult(stdout=VM_GUID, returncode=0)
        raise self.exc


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


def test_guestexec_busy_wires_to_busy_class(monkeypatch, unrestricted):
    """A PowerShellBusy through guest_run_ps's except-Exception arm reports
    error_class "busy" (not "transport"); enrich_failure then marks it
    retryable with the 2000 ms guidance — the layer that owns those keys."""
    fake = SeqPS(pswindows.PowerShellBusy("pool saturated"))
    monkeypatch.setattr(pswindows, "run_ps", fake)
    assert fake.calls == 0  # leg count sanity: resolve + guest
    out = guestexec.guest_run_ps(unrestricted, "vm1", "Get-Date", cred=CRED)
    assert fake.calls == 2  # the exception came from the guest leg, post-resolve
    assert out["ok"] is False
    assert out["error_class"] == "busy"
    enriched = errors.enrich_failure(out)
    assert enriched["retryable"] is True
    assert enriched["retry_after_ms"] == errors.BUSY_RETRY_MS


def test_guestexec_transport_still_transport(monkeypatch, unrestricted):
    """The wiring must not reclassify ordinary transport failures."""
    monkeypatch.setattr(
        pswindows, "run_ps", SeqPS(RuntimeError("transport down"))
    )
    out = guestexec.guest_run_ps(unrestricted, "vm1", "Get-Date", cred=CRED)
    assert out["error_class"] == "transport"
    assert errors.enrich_failure(out)["retryable"] is False


def test_guestjobs_stop_busy_keeps_entry_stoppable(monkeypatch):
    """A PowerShellBusy stop leg reports error_class "busy" with stopped
    False; the entry stays registered so a retry can stop it later."""
    monkeypatch.setattr(
        guestjobs,
        "_jobs",
        {
            "job-1": {
                "vm_name": "vm-a",
                "pid": 4242,
                "job_dir": "dummy",
                "vm_id": "11111111-2222-3333-4444-555555555555",
                "cred": CRED,
            }
        },
    )
    def raising_run_ps(script, *, timeout_s=None, stdin_b64=None):
        raise pswindows.PowerShellBusy("pool saturated")

    monkeypatch.setattr(pswindows, "run_ps", raising_run_ps)
    out = guestjobs.job_stop(Config(unrestricted=True), "job-1")
    assert out["ok"] is False
    assert out["error_class"] == "busy"
    assert out["stopped"] is False
    assert "job-1" in guestjobs._jobs  # entry remains stoppable
    enriched = errors.enrich_failure(out)
    assert enriched["retryable"] is True


def test_busy_envelope_end_to_end():
    """classify -> envelope: the catch-all envelope every server tool uses
    emits {error_class: busy, retryable: true, retry_after_ms: 2000}."""
    env = errors.envelope(pswindows.PowerShellBusy("pool saturated"))
    assert env["error_class"] == "busy"
    assert env["retryable"] is True
    assert env["retry_after_ms"] == errors.BUSY_RETRY_MS
