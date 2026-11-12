"""Issue #140 round-3 expansion checks: the UIA state-receipt contract's
remaining polarity gaps (fix-plan F2.2/F2.3), authored BEFORE the fix
(arm's-length author; round 1's C1-C12 and round 2's C13-C29 live, untouched,
in tests/unit/test_console_commit_guard_uia.py / _extra.py — imported here as
`frozen` / `extra`, never edited).

Rows:
- C30  dispatch-timeout bump polarity: a MUTATING verb whose helper leg
  times out AFTER the forward framed the request still bumps the input
  ledger (bump-at-DECISION, not bump-after-success) — the prior state read
  goes stale and a guarded click citing it refuses with zero mouse input.
- C31  brokered route bump: the same bump must fire on the BROKERED seam
  (uia.route -> _pipe_request(3-arg) -> _pipe_forward rebuilding its
  transport from the _CALL slot), driven through the real verb layer by
  making session discovery answer so the read SEEDES the registration the
  mutating verb then routes through.
- C32  wait_for per-slice mint churn bound: during a budget-expiry wait the
  number of record_state_read mints equals the number of helper legs the
  pipe stub observed (the stub counts legs; a fake clock in uia.time makes
  the slice count itself deterministic) and stays bounded by the budget.
- C33  failure-path no-mint spies (parametrized, one check id): helper
  ok-False frame, transport failure (PowerShellTransportError),
  ambiguous_session, adapter-gate refusal — each read returns without
  minting; a positive control (one successful read mints exactly once)
  makes the zero legs non-vacuous and fails first at base.

Transport tiers after the prior rounds' idioms: the LEG tier (LegStub at
uia._run_uia_leg, extra.LegStub) keeps _pipe_forward — the F2.2 bump seam —
REAL; C30 additionally stubs one tier BELOW the bump site (uia._frame_leg)
so the raise lands AFTER the forward framed the request; C32 uses the PIPE
tier (frozen.PipeStub on uia._pipe_request) where only the mint matters.
PRE-FIX: every NEW-SURFACE check fails on the missing surface.
"""

import base64
import json

import pytest
import test_console_commit_guard_uia as frozen
import test_console_commit_guard_uia_extra as extra

from hyperv_mcp import console, pswindows, uia
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

CRED = frozen.CRED
GUID = frozen.GUID

#: The single interactive session session discovery reports for C31 so the
#: read seeds registration (GUID, 2) and the mutating verb routes brokered.
_QUSER_SESSION = {"user": CRED.username, "session_id": 2}


class DispatchTimeoutLeg:
    """LEG-tier stub at uia._frame_leg — ONE TIER BELOW the F2.2 bump site
    (uia._pipe_forward stays REAL and has already framed the request when
    this raises). Reads delegate to the real _frame_leg (LegStub answers at
    _run_uia_leg); MUTATING verbs raise TimeoutError — the write was
    dispatched and delivery is unknowable."""

    def __init__(self):
        self.real = uia._frame_leg
        self.timed_out: list[dict] = []

    def __call__(self, cfg, ref, cred, script, payload_b64, *, timeout_ms=15000):
        request = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
        if request.get("verb") in uia.MUTATING_VERBS:
            self.timed_out.append(request)
            raise TimeoutError("the dispatched helper write timed out")
        return self.real(cfg, ref, cred, script, payload_b64, timeout_ms=timeout_ms)


class _FakeClock:
    """Deterministic wait_for pacing: uia.time is swapped for this object,
    so monotonic() advances a fixed step per read and sleep() is a no-op —
    the slice loop cannot spin unbounded and needs no real sleeps."""

    def __init__(self, step: float = 0.3):
        self._now = 1000.0
        self._step = step

    def monotonic(self) -> float:
        self._now += self._step
        return self._now

    def sleep(self, _s) -> None:
        pass


def _wire_leg(monkeypatch, leg=None, quser=None, gate=False):
    """Wire the LEG tier (extra round 2's _ui_leg_transport idiom): LegStub
    at uia._run_uia_leg keeps _pipe_forward — the bump seam — real."""
    fake = frozen.FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(uia, "_run_uia_leg", leg or extra.LegStub())
    monkeypatch.setattr(uia, "_run_quser", lambda cfg, ref, cred: quser)
    monkeypatch.setattr(uia, "_ps_guest_text", lambda cfg, ref, cred, guest_command, timeout_s=30: "")
    if gate:
        monkeypatch.setattr(uia, "_shared_mutation_gate", lambda *a, **k: None)
    return fake


def _mint_spy(monkeypatch) -> list:
    """Spy on console.record_state_read (raising=False: absent at base)."""
    mints: list = []

    def spy(*a, **k):
        mints.append(k)
        return f"polarity-mint-{len(mints)}"

    monkeypatch.setattr(console, "record_state_read", spy, raising=False)
    return mints


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


@pytest.fixture(autouse=True)
def _clean_ledger():
    console.reset_input_ledger()
    yield
    console.reset_input_ledger()


# C30 (F2.2 polarity): a dispatched-then-timed-out MUTATING verb still bumps


def test_dispatch_timeout_bump_stales_prior_receipt(monkeypatch, unrestricted):
    fake = _wire_leg(monkeypatch, gate=True)
    leg = DispatchTimeoutLeg()
    monkeypatch.setattr(uia, "_frame_leg", leg)
    console.note_name_guid_hint("vm1", GUID)
    read_out = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert read_out.get("ok") is True, "the fake helper transport must serve the read"
    before = console._last_input_seq_for(GUID)
    out = uia.invoke(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert out.get("ok") is False, "the timed-out write must fail its envelope"
    assert out.get("error_class") == "helper_unavailable", (
        "the dispatch-timeout leg must map to the transport-failure class"
    )
    assert len(leg.timed_out) == 1 and leg.timed_out[0].get("verb") == "invoke", (
        "sanity: exactly one MUTATING request was dispatched, then timed out"
    )
    after = console._last_input_seq_for(GUID)
    assert after > before, (
        "C30: a MUTATING verb whose helper leg timed out AFTER dispatch "
        "must still bump the input ledger — bump-at-decision, not "
        f"bump-after-success (ledger seq {before} -> {after}); without the "
        "bump the prior state read stays fresh and a guarded click against "
        "it does not refuse stale"
    )
    rid = read_out.get("state_receipt")
    assert isinstance(rid, str) and rid, "C30: the prior read must mint and return `state_receipt`"
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


# C31 (F2.2 brokered seam): route()-dispatched mutations bump too


def test_brokered_route_dispatch_bumps_ledger(monkeypatch, unrestricted):
    fake = _wire_leg(monkeypatch, quser=_QUSER_SESSION, gate=True)
    routed: list[dict] = []
    real_route = uia.route

    def spy_route(registration, request, **kw):
        routed.append(dict(request))
        return real_route(registration, request, **kw)

    monkeypatch.setattr(uia, "route", spy_route)
    console.note_name_guid_hint("vm1", GUID)
    rid = frozen._mint_receipt(unrestricted, "vm1")
    out = uia.invoke(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert out.get("ok") is True, "the fake helper transport must serve the brokered invoke"
    assert any(r.get("verb") == "invoke" for r in routed), (
        "C31 sanity: the mutating verb must dispatch through the BROKERED "
        "uia.route seam (the read seeded the registration; session "
        "discovery reported the session), not only the direct path"
    )
    with pytest.raises(ConsoleError, match="stale"):
        frozen._guarded_receipt_click(unrestricted, "vm1", rid)
    frozen._assert_no_mouse(fake)


# C32 (F2.3 churn bound): wait_for mints per slice, never more than legs


def test_wait_for_slice_mint_churn_bounded(monkeypatch, unrestricted):
    empty = {
        "ok": True,
        "result": {"elements": []},
        "session": {"session_id": 2, "interactive_user": "tester"},
    }
    pipe = frozen.PipeStub(empty)
    fake = frozen.FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    monkeypatch.setattr(uia, "_pipe_request", pipe)
    mints = _mint_spy(monkeypatch)
    monkeypatch.setattr(uia, "time", _FakeClock(step=0.3))
    out = uia.wait_for(unrestricted, "vm1", CRED, {"name": "NeverAppears"}, timeout_s=1)
    assert out.get("ok") is True and out.get("timed_out") is True, (
        "the wait must expire unanswered on empty slices"
    )
    assert len(pipe.requests) >= 1, "sanity: at least one helper leg ran"
    assert len(mints) == len(pipe.requests), (
        "C32: wait_for per-slice mint churn must be bounded by the slice "
        f"count: record_state_read calls ({len(mints)}) must equal the "
        f"helper legs the pipe stub observed ({len(pipe.requests)}) — the "
        "registry must not grow faster than one receipt per leg"
    )
    assert len(pipe.requests) <= 8, (
        "C32: the slice count itself stays bounded by the budget "
        f"(1 s budget at a 0.3 s clock tick gave {len(pipe.requests)} legs)"
    )


# C33 (F2.3 no-mint failure paths): parametrized, one check id.
# Param set: helper_ok_false / transport_failure / ambiguous_session /
# adapter_gate_refusal — the four failure families a read can take.


@pytest.mark.parametrize(
    "label",
    [
        "helper_ok_false",
        "transport_failure",
        "ambiguous_session",
        "adapter_gate_refusal",
    ],
)
def test_failure_paths_mint_nothing(monkeypatch, unrestricted, label):
    mints = _mint_spy(monkeypatch)
    _wire_leg(monkeypatch)  # positive control: the plain LEG tier serves ok
    ok_out = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})
    assert ok_out.get("ok") is True, "the control read must succeed first"
    assert len(mints) == 1, (
        "C33 positive control: one successful read must mint exactly once "
        f"via console.record_state_read (observed {len(mints)}) — without "
        "it the failure legs' zero-mint pins below would be vacuous"
    )
    mints.clear()
    expected_class = {
        "helper_ok_false": "helper_error",
        "transport_failure": "helper_unavailable",
        "ambiguous_session": "ambiguous_session",
        "adapter_gate_refusal": "adapter_unapproved",
    }[label]
    if label == "helper_ok_false":
        monkeypatch.setattr(uia, "_run_uia_leg", extra.LegStub(frozen._fail_frame()))
        out = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})
    elif label == "transport_failure":

        def broken_leg(*a, **k):
            raise pswindows.PowerShellTransportError("the helper transport leg exploded")

        monkeypatch.setattr(uia, "_frame_leg", broken_leg)
        out = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})
    elif label == "ambiguous_session":

        def two_sessions(cfg, ref, cred):
            raise uia.UiAError("ambiguous_session: 2 active sessions for " + CRED.username)

        monkeypatch.setattr(uia, "_run_quser", two_sessions)
        out = uia.find(unrestricted, "vm1", CRED, {"automation_id": "File"})
    else:
        out = uia.find(unrestricted, "vm1", CRED, {"name": "File"}, adapter="electron")
    assert out.get("ok") is False and out.get("error_class") == expected_class, (
        f"sanity: the {label} leg must actually take its failure path "
        f"(got error_class={out.get('error_class')!r})"
    )
    assert mints == [], (
        f"C33 ({label}): a failed read must NOT mint — record_state_read stayed uncalled on the failure path"
    )
    assert "state_receipt" not in out, f"C33 ({label}): a failed read must not return `state_receipt`"
