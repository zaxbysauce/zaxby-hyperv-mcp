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


def test_bind_failure_after_reservation_releases_placeholder(monkeypatch):
    """A bind OSError AFTER the reservation must release the in-flight
    placeholder: no stranded slot, registry empty (issue #11 review)."""
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    monkeypatch.setattr(relay, "_RelayServer", lambda addr, handler: (_ for _ in ()).throw(OSError("boom")))
    cfg = _relay_cfg()
    with pytest.raises(RuntimeError, match="could not bind"):
        relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    assert relay._relays == {}


def test_thread_start_failure_releases_placeholder_and_closes_socket(monkeypatch):
    """A post-bind failure (Thread.start under resource exhaustion raises
    RuntimeError) must release the in-flight placeholder AND close the
    bound socket — an unreleased strand would be invisible to status,
    unstoppable, cap-consuming, and would block that vm:port forever via
    the duplicate scan (issue #11 implementation review, Finding 1)."""
    import threading as threading_mod

    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))

    class BoomThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    closed = []

    class StubServer:
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, addr, handler):
            self.server_address = (addr[0], 0)

        def serve_forever(self, poll_interval=0.5):
            raise AssertionError("never runs: Thread.start is stubbed to fail")

        def server_close(self):
            closed.append(True)

    monkeypatch.setattr(relay, "_RelayServer", StubServer)
    monkeypatch.setattr(threading_mod, "Thread", BoomThread)
    cfg = _relay_cfg()
    with pytest.raises(RuntimeError, match="can't start new thread"):
        relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    assert relay._relays == {}
    assert closed == [True]


def test_relay_cap_eviction_releases_evicted_entry_state(monkeypatch):
    """Cap-time eviction removes the OLDEST stopped entry and its stored
    credential is released at that moment (held by reference so the
    evicted dict stays observable after the del; issue #11 review
    PRR-010). The credential is normally already None because relay_stop
    nulls it on stop — this pin documents that the invariant still holds
    at eviction time (relay.py nulls it defensively before delete)."""
    monkeypatch.setattr(relay, "_MAX_RELAYS", 2, raising=False)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    cfg = _relay_cfg()
    ids = [
        relay.relay_start(cfg, "test-vm", port, cred=CRED, owner="agent-a")["relay_id"]
        for port in (9201, 9202)
    ]
    relay.relay_stop(cfg, ids[0])
    evicted_entry = relay._relays[ids[0]]  # held reference survives the del
    assert evicted_entry["context"]["cred"] is None
    out3 = relay.relay_start(cfg, "test-vm", 9203, cred=CRED, owner="agent-a")
    assert ids[0] not in relay._relays
    assert ids[1] in relay._relays and out3["relay_id"] in relay._relays
    assert evicted_entry["context"]["cred"] is None


def test_positive_owner_by_id_status_and_stop(monkeypatch):
    """The RIGHTFUL owner can address its own relay by id — the positive
    arm of the ownership check (inverting the comparison would deny the
    owner; issue #11 review PRR-009)."""
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    cfg = _relay_cfg()
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED, owner="agent-a")
    status = relay.relay_status(cfg, out["relay_id"], owner="agent-a")
    assert status["ok"] is True and len(status["relays"]) == 1
    assert status["relays"][0]["relay_id"] == out["relay_id"]
    stopped = relay.relay_stop(cfg, out["relay_id"], owner="agent-a")
    assert stopped["ok"] is True and stopped["stopped"] is True


def test_owner_listing_positive_control(monkeypatch):
    """agent-a's listing shows its OWN relay while agent-b's shows none —
    the filter must not over-filter (issue #11 review PRR-009)."""
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    cfg = _relay_cfg()
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED, owner="agent-a")
    own = relay.relay_status(cfg, owner="agent-a")
    assert [r["relay_id"] for r in own["relays"]] == [out["relay_id"]]
    other = relay.relay_status(cfg, owner="agent-b")
    assert other["relays"] == []


def test_status_rows_never_carry_the_secret(monkeypatch):
    """The capability secret appears ONLY in relay_start's returned url —
    never in any relay_status row url (issue #11 review PRR-009)."""
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    cfg = _relay_cfg()
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED, owner="agent-a")
    secret = out["url"].split("/", 3)[3].rstrip("/")
    assert secret and len(secret) >= 22  # returned url carries it
    status = relay.relay_status(cfg, out["relay_id"], owner="agent-a")
    row_url = status["relays"][0]["url"]
    assert secret not in row_url
    assert row_url == f"http://127.0.0.1:{out['host_port']}/"


def test_relay_placeholder_is_invisible():
    """An in-flight placeholder (start still binding) is invisible: by-id
    status/stop answer the unknown-id error and the listing omits it
    (issue #11 review PRR-009)."""
    cfg = _relay_cfg()
    ghost = "relay-9222-" + "0" * 32
    with relay._relays_lock:
        relay._relays[ghost] = {
            "relay_id": ghost, "vm_name": "test-vm", "vm_id": "g",
            "guest_port": 9222, "owner": "agent-a", "in_flight": True,
            "started_at": "2026-10-08T00:00:00.000+00:00", "stopped": False,
        }
    try:
        with pytest.raises(ValueError, match="unknown relay_id"):
            relay.relay_status(cfg, ghost, owner="agent-a")
        with pytest.raises(ValueError, match="unknown relay_id"):
            relay.relay_stop(cfg, ghost, owner="agent-a")
        assert relay.relay_status(cfg, owner="agent-a")["relays"] == []
    finally:
        with relay._relays_lock:
            relay._relays.clear()


def test_foreign_and_unknown_envelopes_are_identical(monkeypatch):
    """A foreign id and a nonexistent id are indistinguishable in EVERY
    caller-visible surface: the response is a pure function of the
    caller's own input — the echo-shaped unknown-id text — with no
    registry state in it, so existence cannot be probed (issue #11
    review PRR-012; refutes the claim that the probes allow a distinct
    access-denied response for foreign ids)."""
    fake = FakePS([_ok({"pid": 4242, "job_dir": "C:/Temp/hyperv-mcp-job-x"})])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    cfg = Config(unrestricted=True)
    started = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED, owner="agent-a")
    foreign = started["job_id"]
    unknown = "f" * 32
    with pytest.raises(ValueError) as exc_foreign:
        guestjobs.job_status(cfg, foreign, owner="agent-b")
    with pytest.raises(ValueError) as exc_unknown:
        guestjobs.job_status(cfg, unknown, owner="agent-b")
    # Each response is exactly the echo of the caller's own input: same
    # message template, same exception type, zero registry information.
    assert str(exc_foreign.value) == f"unknown job_id '{foreign}'"
    assert str(exc_unknown.value) == f"unknown job_id '{unknown}'"
    assert type(exc_foreign.value) is type(exc_unknown.value)
    # Same property for relay ids (module-level, no guest legs involved).
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    relay_cfg = _relay_cfg()
    relay_out = relay.relay_start(relay_cfg, "test-vm", 9222, cred=CRED, owner="agent-a")
    with pytest.raises(ValueError) as r_foreign:
        relay.relay_stop(relay_cfg, relay_out["relay_id"], owner="agent-b")
    with pytest.raises(ValueError) as r_unknown:
        relay.relay_stop(relay_cfg, "relay-9222-" + "f" * 32, owner="agent-b")
    assert str(r_foreign.value) == f"unknown relay_id '{relay_out['relay_id']}'"
    assert str(r_unknown.value) == f"unknown relay_id 'relay-9222-{'f' * 32}'"
    assert type(r_foreign.value) is type(r_unknown.value)


def test_thread_constructor_failure_releases_placeholder(monkeypatch):
    """A Thread-CONSTRUCTOR failure (resource exhaustion) sits before the
    server bind but inside the release window: the placeholder must be
    released and nothing bound (issue #11 PR review round 2, NEW-B —
    the window now covers construction, not just start)."""
    import threading as threading_mod

    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))

    class BoomCtorThread:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("can't create new thread")

    constructed = []

    class StubServer:
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, addr, handler):
            self.server_address = (addr[0], 0)
            constructed.append(self)

        def serve_forever(self, poll_interval=0.5):
            raise AssertionError("never runs: Thread construction is stubbed to fail")

        def server_close(self):
            raise AssertionError("bind never completed: no socket to close")

    monkeypatch.setattr(relay, "_RelayServer", StubServer)
    monkeypatch.setattr(threading_mod, "Thread", BoomCtorThread)
    cfg = _relay_cfg()
    with pytest.raises(RuntimeError, match="can't create new thread"):
        relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    assert relay._relays == {}
    # The server WAS constructed (it precedes the Thread ctor) but its
    # socket is released when the propagating exception drops the frame
    # (CPython refcounting) — server_close is deliberately not attempted
    # on this path because the stub would flag any call.
    assert len(constructed) == 1


def test_non_oserror_server_construction_failure_releases_placeholder(monkeypatch):
    """A non-OSError from the server constructor (outside the OSError bind
    conversion) must also release the placeholder (issue #11 PR review
    round 2, NEW-B)."""
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))

    class BoomServer:
        def __init__(self, addr, handler):
            raise ValueError("bad address family")

    monkeypatch.setattr(relay, "_RelayServer", BoomServer)
    cfg = _relay_cfg()
    with pytest.raises(ValueError, match="bad address family"):
        relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    assert relay._relays == {}
