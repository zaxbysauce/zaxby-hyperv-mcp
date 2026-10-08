"""B02 guardrail pins (issue #11, phase 4 additions): the contract shapes
the frozen acceptance probes imply but do not pin — relay eviction nulls
the evicted credential, the unattributed local principal (None owner)
keeps working against agent-attributed entries, a WRONG secret 401s with
no guest leg, and a foreign probe of an in-flight job reads unknown."""

import json
import re
import urllib.request
import uuid

import pytest

from hyperv_mcp import guestjobs, pswindows, relay
from hyperv_mcp.config import Config, DestructivePolicy
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")

_NAME_RE = re.compile(r"ElementName -eq '([^']*)'")


def _is_resolution_leg(script: str) -> bool:
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _resolved_guid(script: str) -> str:
    m = _NAME_RE.search(script)
    return str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1) if m else ""))


class FakePS:
    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


def _relay_cfg() -> Config:
    return Config(allowed_vm_patterns=["test-*"], destructive=DestructivePolicy(relay=True))


@pytest.fixture(autouse=True)
def _clean_registries():
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()
    yield
    relay.clear_registry_for_tests()
    guestjobs.clear_registry_for_tests()


def test_relay_cap_eviction_nulls_evicted_credential(monkeypatch):
    """Cap-time eviction releases the evicted entry's stored credential
    before deleting it (issue #11; guestjobs eviction parity)."""
    monkeypatch.setattr(relay, "_MAX_RELAYS", 2, raising=False)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    cfg = _relay_cfg()
    ids = [
        relay.relay_start(cfg, "test-vm", port, cred=CRED, owner="agent-a")["relay_id"]
        for port in (9201, 9202)
    ]
    relay.relay_stop(cfg, ids[0])
    assert relay._relays[ids[0]]["context"]["cred"] is None
    # A third start at the cap evicts the OLDEST STOPPED entry.
    out3 = relay.relay_start(cfg, "test-vm", 9203, cred=CRED, owner="agent-a")
    assert ids[0] not in relay._relays
    assert ids[1] in relay._relays
    assert out3["relay_id"] in relay._relays
    assert relay._relays[ids[1]]["context"]["cred"] is CRED


def test_local_principal_stops_agent_attributed_relay(monkeypatch):
    """The unattributed local principal (module-level calls, owner=None)
    keeps working against an agent-attributed relay — the documented
    single-principal contract for stdio/anonymous/library callers."""
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    cfg = _relay_cfg()
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED, owner="agent-a")
    # No owner kwarg: exactly the frozen probes' module-level cleanup shape.
    stopped = relay.relay_stop(cfg, out["relay_id"])
    assert stopped["ok"] is True and stopped["stopped"] is True


def test_local_principal_stops_agent_attributed_job(monkeypatch):
    """Same local-principal contract for jobs: a module-level stop of an
    agent-attributed job succeeds (owner=None skips the ownership check)."""
    fake = FakePS([
        _ok({"pid": 4242, "job_dir": "C:/Temp/hyperv-mcp-job-x"}),
        _ok({"stopped": True}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    cfg = Config(unrestricted=True)
    start = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED, owner="agent-a")
    out = guestjobs.job_stop(cfg, start["job_id"])
    assert out["ok"] is True and out["stopped"] is True


def test_wrong_relay_secret_gets_401_and_no_guest_leg(monkeypatch):
    """A PRESENT-but-wrong secret 401s with the connection closed and no
    PowerShell leg (issue #11)."""
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    cfg = _relay_cfg()
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED, owner="agent-a")
    wrong = f"http://127.0.0.1:{out['host_port']}/not-the-secret/json/version"
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(wrong, timeout=10)
    assert excinfo.value.code == 401
    assert len(fake.scripts) == 1 and _is_resolution_leg(fake.scripts[0])


def test_foreign_in_flight_job_id_reads_unknown():
    """A foreign agent probing a job id during the start window gets the
    unknown-id response, never the in-flight signal (issue #11)."""
    cfg = Config(unrestricted=True)
    job_id = "0" * 32
    with guestjobs._jobs_lock:
        guestjobs._jobs[job_id] = {
            "job_id": job_id, "vm_name": "test-vm", "vm_id": "g", "pid": 1,
            "in_flight": True, "owner": "agent-a",
            "started_at": "2026-10-08T00:00:00.000+00:00",
            "cred": None, "stopped": False,
        }
    try:
        with pytest.raises(ValueError, match="unknown job_id"):
            guestjobs.job_status(cfg, job_id, owner="agent-b")
        # The owner's own follow-up still sees the honest in-flight signal.
        with pytest.raises(ValueError, match="still starting"):
            guestjobs.job_status(cfg, job_id, owner="agent-a")
    finally:
        with guestjobs._jobs_lock:
            guestjobs._jobs.clear()
