"""RC-23: the guest-side merge switch, pinned behaviourally at the host seam.

The shipped suite pinned the guest half only by source substrings, so the
mutant ``$mergeRuns = $true`` (unconditional) left the helper merging with the
switch OFF and every suite stayed green. This node drives the REAL
``uia._verb_request`` and asserts the switch's value rides on the request the
guest receives, in both positions -- which is the only channel the guest has.
"""
from __future__ import annotations

import json

from hyperv_mcp import pswindows, uia
from hyperv_mcp.config import Config


class _VerbPipe:
    """The 4-arg verb front-door shape: records the request and answers a
    generic successful frame."""

    def __init__(self):
        self.requests: list[dict] = []

    def __call__(self, cfg, vm, cred, request):
        self.requests.append(json.loads(json.dumps(request)))
        session = {"session_id": 2, "interactive_user": "tester",
                   "locked": False,
                   "helper": {"running": True, "sha256": "0" * 64,
                              "capabilities": ["uia", "adapter:electron"]}}
        if request.get("verb") == "enable_accessibility":
            return {"ok": True, "id": request.get("id"),
                    "result": {"available": True}, "session": session}
        return {"ok": True, "id": request.get("id"),
                "result": {"elements": []}, "session": session}


def _drive(monkeypatch, switch: bool):
    pipe = _VerbPipe()
    # the VM-resolve leg and the console hint leg both go through run_ps
    monkeypatch.setattr(
        pswindows, "run_ps",
        lambda *a, **k: pswindows.PSResult(
            stdout="11111111-2222-3333-4444-555555555555", returncode=0))
    monkeypatch.setattr(uia, "_install_facts", lambda cfg, ref, cred: {})
    monkeypatch.setattr(uia, "_sid_for", lambda cfg, ref, cred: "S-1-5-21-1")
    monkeypatch.setattr(uia, "_bootstrap_session", lambda cfg, ref, cred: (2, ""))
    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(uia, "_Transport", lambda cfg, ref, cred: object())
    monkeypatch.setattr(uia, "GLYPH_MERGE_DEFAULT", switch)
    out = uia.find(Config(unrestricted=True), "vm1", _cred(), {"name": "Word"},
                   adapter="electron")
    return out, pipe


def _cred():
    from hyperv_mcp import credentials

    return credentials.CredentialSet(username="tester",
                                     password="placeholder-pass")


def test_merge_switch_rides_on_the_electron_request(monkeypatch):
    """RC-23: with the module switch OFF the electron request must carry
    ``merge_glyph_runs = False``, and with it ON it must carry True. Mutant:
    make the helper ignore the flag (force ``$mergeRuns = $true``) -- the host
    still sends False, so the guest would merge against the caller's wish."""
    out_off, off = _drive(monkeypatch, False)
    assert out_off.get("ok") is True, out_off
    finds = [r for r in off.requests if r.get("verb") == "find"]
    assert finds, f"no find frame was issued: {[r.get('verb') for r in off.requests]}"
    args = finds[0].get("args") or {}
    assert args.get("merge_glyph_runs") is False, (
        f"with GLYPH_MERGE_DEFAULT off the electron request must carry "
        f"merge_glyph_runs=False; got {args!r}")


def test_merge_switch_on_rides_on_the_electron_request(monkeypatch):
    """RC-23 (control): the ON position must still ride on the request."""
    out_on, on = _drive(monkeypatch, True)
    assert out_on.get("ok") is True, out_on
    finds = [r for r in on.requests if r.get("verb") == "find"]
    assert finds, f"no find frame was issued: {[r.get('verb') for r in on.requests]}"
    args = finds[0].get("args") or {}
    assert args.get("merge_glyph_runs") is True, (
        f"with GLYPH_MERGE_DEFAULT on the electron request must carry "
        f"merge_glyph_runs=True; got {args!r}")


def test_helper_honours_the_merge_switch_off():
    """RC-23 (guest half): the helper's electron arm must read the flag from
    the request's args and take the unmerged branch when it is False. Mutant:
    force ``$mergeRuns = $true`` -- this node fails."""
    import pathlib

    from hyperv_mcp import uia

    text = pathlib.Path(uia.__file__).parent / "guest" / "uia_helper.ps1"
    helper = text.read_text(encoding="utf-8")
    assert "$mergeRuns = $true" in helper, (
        "the electron arm must default the merge switch ON")
    assert "[bool]$req['args']['merge_glyph_runs']" in helper, (
        "the electron arm must read the switch from the request's args, or "
        "turning it off leaves the guest merging anyway")
    assert "if (-not $mergeRuns) {" in helper, (
        "the electron arm must take an explicit unmerged branch when the "
        "switch is off")
