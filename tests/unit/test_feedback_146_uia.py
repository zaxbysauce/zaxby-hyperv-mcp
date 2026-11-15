"""Falsification pins for the uia.py findings on PR #146 (FB-003, FB-005,
FB-006, FB-008). Every node here kills a mutant that survived the shipped
suite at ``e82d79e4f58f2aaed76c948e9db9e6a7fb060ee0``.
"""
from __future__ import annotations

import asyncio
import inspect
import json

from hyperv_mcp import uia, vmident
from hyperv_mcp.config import Config

VM_GUID = "11111111-2222-3333-4444-555555555555"


def _cred():
    from hyperv_mcp import credentials

    return credentials.CredentialSet(username="tester",
                                     password="placeholder-pass")


def _ref():
    return vmident.VMRef(id=VM_GUID, name="vm1")


def _session_block(capabilities=None) -> dict:
    return {
        "session_id": 7,
        "interactive_user": "tester",
        "locked": False,
        "helper": {"running": True, "sha256": "0" * 64,
                   "capabilities": capabilities or ["uia"]},
    }


def _electron_request() -> dict:
    return {"id": "probe-1", "verb": "find", "args": {},
            "adapter": "electron", "selector": {"name": "OK"}}


class _RecordingFrontDoor:
    """The 4-arg verb front-door shape: records every forwarded frame and
    answers from a per-verb table. Correlates the response id."""

    def __init__(self, frames=None):
        self.requests: list[dict] = []
        self.frames = frames or {}

    def _answer(self, request):
        self.requests.append(json.loads(json.dumps(request)))
        frame = self.frames.get(request.get("verb"))
        if frame is None:
            frame = {"ok": True, "result": {},
                     "session": _session_block()}
        out = json.loads(json.dumps(frame))
        out["id"] = request.get("id")
        return out

    def __call__(self, *args):
        # _pipe_request is an arity-dispatched seam: the 4-arg verb front-door
        # shape and the 3-arg broker-forward shape both land here.
        request = args[3] if len(args) == 4 else args[1]
        return self._answer(request)

    def forward(self, transport, request, correlation_id):
        # the 3-arg broker-forward shape _front_door uses for its probe
        return self._answer(request)


class _Patch:
    """Swap the front door's collaborators for the duration of one probe."""

    def __init__(self, pipe):
        self.pipe = pipe
        self.orig = None

    def __enter__(self):
        self.orig = (uia._install_facts, uia._sid_for, uia._bootstrap_session,
                     uia.ensure_registration, uia._pipe_request, uia._Transport,
                     uia._pipe_forward)
        uia._install_facts = lambda cfg, ref, cred: {}
        uia._sid_for = lambda cfg, ref, cred: "S-1-5-21-1"
        uia._bootstrap_session = lambda cfg, ref, cred: (7, "")
        uia._pipe_request = self.pipe
        uia._Transport = lambda cfg, ref, cred: object()
        uia._pipe_forward = self.pipe.forward
        return self

    def __exit__(self, *exc):
        (uia._install_facts, uia._sid_for, uia._bootstrap_session,
         uia.ensure_registration, uia._pipe_request, uia._Transport,
         uia._pipe_forward) = self.orig
        return False


# --------------------------------------------------------------------------
# FB-005 / RC-09 — the bootstrap probe carries a real session id
# --------------------------------------------------------------------------

def test_bootstrap_probe_carries_the_resolved_session_id():
    """RC-09: the adapter-neutral bootstrap probe was a SHALLOW copy of the
    request forwarded BEFORE ``request["target"]["session_id"]`` was assigned,
    so it carried a null session id and the helper refused it
    ``session_unverified`` -- the bootstrap could never seed anything on a
    fresh process. Mutant: move the assignment back after the forward -- this
    node fails."""
    pipe = _RecordingFrontDoor()
    with _Patch(pipe):
        uia._front_door(Config(), _ref(), _cred(), _electron_request())

    probes = [r for r in pipe.requests if r.get("verb") == "session_state"]
    assert probes, (
        f"a fresh process must run the adapter-neutral bootstrap probe; "
        f"forwarded verbs: {[r.get('verb') for r in pipe.requests]}")
    target = probes[0].get("target") or {}
    assert target.get("session_id") == 7, (
        "the bootstrap probe must carry the RESOLVED session id, or the "
        f"helper refuses it session_unverified; got {target!r}")
    assert "adapter" not in probes[0], (
        "the bootstrap probe must be adapter-neutral (never gated)")
    # The frame advertises no electron capability, so the gate refuses -- that
    # is the correct outcome and is what the frozen AC4 pin asserts. What this
    # node owns is that the probe was FORWARDED with a usable session id at all.


# --------------------------------------------------------------------------
# FB-006 / RC-47 — the capability upgrade is reachable
# --------------------------------------------------------------------------

def test_bootstrap_upgrades_an_existing_row_lacking_the_adapter():
    """RC-47: ``_front_door`` called ``ensure_registration(frame=...)`` only
    when the lookup returned None, so a row seeded ``{'uia'}`` stayed
    unapprovable for electron for the life of the host process -- exactly what
    the capability upgrade exists to prevent. Mutant: restore the
    ``registration is None`` guard -- this node fails."""
    rows: dict = {}

    def _ensure(cfg, ref, cred, *, session_id=None, frame=None,
                target_guid=None):
        # _front_door seeds by session_id and upgrades by target_guid alone;
        # both must address the same row for this probe to mean anything.
        key = (target_guid or ref.id, session_id if session_id is not None else 7)
        if key in rows:
            row = rows[key]
            if frame is not None:
                incoming = set(((frame.get("session") or {})
                                .get("helper") or {}).get("capabilities") or [])
                if incoming and incoming <= uia._CAPABILITIES:
                    row["capabilities"] |= incoming
            return row
        if frame is not None:
            incoming = set(((frame.get("session") or {})
                            .get("helper") or {}).get("capabilities") or [])
            rows[key] = {
                "capabilities": (incoming & uia._CAPABILITIES) or {"uia"},
                "user_sid": "S-1-5-21-1", "transport": None}
            return rows[key]
        return None

    pipe = _RecordingFrontDoor({
        "session_state": {"ok": True, "result": {},
                          "session": _session_block(
                              ["uia", "adapter:electron"])},
        "find": {"ok": True, "result": {"elements": []},
                 "session": _session_block(["uia", "adapter:electron"])},
    })
    with _Patch(pipe) as patch:
        patch.orig[3]  # keep the linter honest about the tuple shape
        uia.ensure_registration = _ensure
        # seed a row that exists but LACKS the adapter capability
        rows[(VM_GUID, 7)] = {"capabilities": {"uia"},
                              "user_sid": "S-1-5-21-1", "transport": None}
        out = uia._front_door(Config(), _ref(), _cred(), _electron_request())

    assert out.get("ok") is True, (
        f"a helper advertising adapter:electron must be able to upgrade an "
        f"existing row so the adapter becomes usable; got {out!r}")
    caps = rows[(VM_GUID, 7)]["capabilities"]
    assert "adapter:electron" in caps, (
        f"the row must gain the capability from the validated frame; got {caps}")


# --------------------------------------------------------------------------
# FB-008 / RC-21 — every adapter read verb exposes an adapter parameter
# --------------------------------------------------------------------------

def test_adapter_read_verbs_all_expose_an_adapter():
    """RC-21: ``_ADAPTER_READ_VERBS`` named ``wait_for``, which has NO
    ``adapter`` parameter -- an unreachable dead member, while
    ``hyperv_ui_inspect`` and ``hyperv_ui_snapshot`` DO expose
    ``adapter="electron"`` publicly with zero behavioural coverage. Mutant:
    add a verb without an adapter parameter, or remove one that has it -- this
    node fails either way."""
    for verb in sorted(uia._ADAPTER_READ_VERBS):
        fn = getattr(uia, verb, None)
        assert fn is not None, f"no uia.{verb} function for a set member"
        params = inspect.signature(fn).parameters
        assert "adapter" in params, (
            f"_ADAPTER_READ_VERBS names {verb!r}, which exposes no adapter "
            "parameter -- nothing can put an adapter on its request, so the "
            "member is unreachable dead code")
    exposing = {name for name in ("find", "inspect", "snapshot", "wait_for")
                if "adapter" in inspect.signature(
                    getattr(uia, name)).parameters}
    assert exposing <= set(uia._ADAPTER_READ_VERBS), (
        f"these verbs expose an adapter parameter but are not in "
        f"_ADAPTER_READ_VERBS: "
        f"{sorted(exposing - set(uia._ADAPTER_READ_VERBS))}")


# --------------------------------------------------------------------------
# FB-001 / RC-02 — the tool is reachable through the real MCP surface
# --------------------------------------------------------------------------

def test_new_tool_reaches_the_guest_leg_through_call_tool():
    """RC-02 (execution half): the two registrations forwarded the lease kwargs
    into ``guestexec.start_interactive``, so every MCP call raised TypeError
    with ``ps_spawns=0``. Mutant: add the kwargs back -- this node fails.

    The server module is reloaded and restored around the call, and the
    environment is never written: a bootstrapped singleton left behind here
    would break ``test_server.py``'s credential-envelope pin."""
    import importlib

    from hyperv_mcp import server as server_module

    environ = {
        "HYPERV_MCP_UNRESTRICTED": "1",
        "HYPERV_MCP_ALLOWED_VM_PATTERNS": "*",
        "HYPERV_GUEST_USERNAME": "tester",
        "HYPERV_GUEST_PASSWORD": "placeholder-pass",
    }
    mod = importlib.reload(server_module)
    try:
        mod.bootstrap(environ)
        mcp = mod.get_mcp()
        result = asyncio.run(mcp.call_tool(
            "hyperv_guest_start_interactive",
            {"vm_name": "*", "command": "notepad", "confirm": True}))
    finally:
        importlib.reload(server_module)
    text = result.content[0].text if result.content else ""
    assert "unexpected keyword argument 'lease_id'" not in text, (
        "the tool must not forward the lease kwargs into start_interactive")
    # The credential refusal is the PROOF the body ran: the tool reached the
    # credential factory, which only happens after argument binding succeeds.
    assert "credential" in text, (
        f"the tool body must run far enough to reach the credential stage; "
        f"got {text[:200]!r}")


def test_new_tool_does_not_forward_lease_kwargs():
    """RC-02 (source half): the lease gate reads the RAW arguments itself, so
    no sibling guest tool forwards the lease kwargs into its module function.
    Mutant: add the kwargs back -- this node fails."""
    import inspect
    import pathlib

    from hyperv_mcp import guestexec, server

    params = inspect.signature(guestexec.start_interactive).parameters
    assert "lease_id" not in params and "fencing_token" not in params, (
        "guestexec.start_interactive must not declare the lease kwargs")
    src = pathlib.Path(server.__file__).read_text(encoding="utf-8")
    i = src.index('"hyperv_guest_start_interactive", vm_name, "exec"')
    j = src.index(")", src.index("cred_factory", i))
    body = src[i:j]
    assert "lease_id=lease_id" not in body, (
        "the new tool must not forward the lease kwargs into start_interactive")
    assert "fencing_token=fencing_token" not in body, (
        "the new tool must not forward the lease kwargs into start_interactive")
