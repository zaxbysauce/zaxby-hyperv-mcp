"""Issue #129 acceptance checks (trace 128-129-134-gui-drivability): the
electron UI Automation adapter gains guest-side behavior -- the renderer
accessibility tree is ENABLED before selectors resolve, per-glyph text is
merged into word runs, and an unavailable tree is reported instead of
silently matching nothing.

AC map (issue #129 body):
  AC1  test_electron_adapter_requests_accessibility  NEW-SURFACE
  AC2  test_glyph_nodes_are_merged                  NEW-SURFACE
  AC2-geo test_glyph_runs_do_not_cross_lines        NEW-SURFACE
  AC2-bnd test_line_tolerance_boundary_is_pinned    NEW-SURFACE (wave-3 S3:
       the tolerance VALUE is pinned by boundary fixtures -- exactly at
       tolerance merges, one pixel above does not)
  AC2-sw  test_glyph_merge_default_switch           NEW-SURFACE (wave-3 S3:
       uia.GLYPH_MERGE_DEFAULT is on by default; with it off the electron
       path returns the per-glyph nodes UNCHANGED)
  AC2b test_helper_merges_glyph_runs_before_matching NEW-SURFACE (the
       helper's REAL dispatch, driven end-to-end for real under Windows
       PowerShell 5.1 -- the tests/unit/test_f05_interactive_helper.py
       dispatch idiom; no helper function name or signature is frozen)
  AC3  test_unavailable_tree_is_reported            NEW-SURFACE
  AC3+ test_enable_leg_receipt_and_ledger_polarity  NEW-SURFACE (wave-3 S8:
       the enable leg mints/bumps nothing -- one receipt per successful
       find, zero on a refused enable, zero console-input ledger entries)
  AC4  test_unapproved_adapter_still_refused        PRESERVING
  (AC5 is the live-host leg: a named button in a live Electron app.)

Every check is RED at base ea5fac5 (this spec file is absent; with the file
present AC1/AC2/AC2b/AC3 fail on the missing electron behavior) and GREEN
after the fix. No real PowerShell and no live VM on AC1/AC2/AC3: the seams
are the frozen test_f05_uia_helper.py / test_uia_refs_actions.py idioms --
uia._run_uia_leg (the single transport choke) and uia._pipe_request (the
verb front-door seam), plus PSRecorder on pswindows.run_ps for the vmident
resolve leg. AC2b alone spawns real Windows PowerShell 5.1 (the packaged
helper's functions, no VM, no pipe -- the F05 helper-dispatch idiom).

Frozen surface contract this file pins (the issue names the adapter, the
merge and the error class; the frame shapes are underdetermined by the
issue text, so this file IS the spec the fix implements against):

  uia.VERBS stays the closed nine-verb set pinned by the frozen F05 AC3
  (tests/unit/test_f05_uia_helper.py::test_request_verbs_are_closed_set)
  -- the enable frame is NOT a new VERBS member. The enable frame is
  issued through uia._pipe_request directly (never build_request, which
  rightly refuses verbs outside VERBS), and the FORWARD allowlist
  (validate_forward's verb check) must admit it -- e.g. a read-only
  side-channel set unioned into the forwarding check -- without growing
  uia.VERBS.

  THE ENABLE REQUEST (AC1/AC3): whenever a verb call carries
  adapter="electron", the verb layer -- BEFORE issuing the verb's own
  request frame -- sends the helper a separate read-only request frame
  through the uia._pipe_request seam:

      {id, verb: "enable_accessibility", args: {...},
       agent_id, adapter: "electron"}

  (``adapter`` stays top-level on the frame, the existing build_request
  shape). The ordered verb frames observed at the seam for an electron
  find are EXACTLY ["enable_accessibility", "find"] -- an inspect (or any
  other selector-resolving verb) before the enable, or any extra frame,
  fails the sequence pin.

  The helper's answer reports whether Chromium's renderer accessibility
  tree became available:

      {"ok": true,  "result": {"available": true}}
      {"ok": true,  "result": {"available": false}}   # stayed off
      {"ok": true,  "result": {}}                     # available MISSING
      {"ok": false, "error_class": ..., "error": ...}

  The host treats ``available`` not-True (missing or false) as UNAVAILABLE
  and refuses the call with the envelope

      {"ok": false, "error_class": "accessibility_unavailable", "error": ...}

  WITHOUT issuing the verb's own frame -- an unavailable tree must never
  degrade into a successful empty match list, and ZERO find frames may be
  issued. When the helper itself reports accessibility_unavailable in an
  ok:false frame, that error_class surfaces verbatim too (module-built
  envelopes keep their error_class).

  THE GLYPH MERGE (AC2): on the electron-adapter path the returned element
  list is normalized host-side between the pipe seam and the verb's return
  (the same reach the password drop has; adapter "" is NOT touched):

    - a GLYPH node is an element dict with control_type "Text", a
      single-character name and a ``rect`` (the helper's "x,y,w,h" string
      -- uia_helper.ps1 emits '{0},{1},{2},{3}' X,Y,Width,Height);
    - each maximal run of ADJACENT glyph nodes whose rects share a line
      (y within LINE_TOLERANCE_PX (=2) of the run's first node's y -- the
      boundary is INCLUSIVE: a y difference of exactly 2 merges, 3 does
      not; test_line_tolerance_boundary_is_pinned pins the value) becomes
      ONE node with control_type "Text" and name = the run's names joined
      in order (one node per word run);
    - a glyph on a DIFFERENT line (y further than LINE_TOLERANCE_PX away)
      TERMINATES the run -- two lines never merge into one node;
    - multi-character names and non-Text control types are preserved
      verbatim and terminate a run;
    - the merged node PRESERVES the run's metadata: ``element_id`` (the
      run's FIRST node's id), ``state`` (the run's first node's state) and
      a ``rect`` spanning the run ("min_x,y,(max_x+max_w)-min_x,max_h" --
      x/width over the run's union, the line's y, the run's tallest
      height). A merge that silently drops element_id, rect or state
      fails.

  THE MERGE SWITCH: uia.GLYPH_MERGE_DEFAULT is the module-level switch
  the implementation must expose (read at CALL time, so tests and callers
  can turn the merge off). Its default is ON (True); with it False the
  electron path returns the helper's per-glyph nodes UNCHANGED
  (test_glyph_merge_default_switch).

  THE HELPER-SIDE MERGE (AC2b, wave-3 S4 rewrite -- BEHAVIOR and WIRING,
  no naming): the packaged helper (src/hyperv_mcp/guest/uia_helper.ps1)
  merges at the SOURCE, before matching, INSIDE ITS PRODUCTION DISPATCH.
  The frozen wiring: for a find request carrying adapter "electron", the
  element list the dispatch's own resolution step (Resolve-Target)
  produces is glyph-run-merged BEFORE the selector's name is matched, so
  the joined word -- and only the joined word -- satisfies a name
  selector, and the returned element carries the run's first identity
  (its RuntimeId) and a spanning rect, i.e. it is ACTIONABLE (an
  element_id a later invoke/act can resolve). No helper function name or
  signature is frozen; an unwired merge helper (a function nothing calls)
  leaves the glyphs unmerged and fails the dispatch check. The plain
  (adapter-less) dispatch path does NOT merge.

  THE GATE (AC4, preserving): uia._adapter_gate keeps refusing
  adapter="electron" with {"ok": False, "error_class": "adapter_unapproved"}
  unless the registration carries uia.ELECTRON_CAPABILITY, and keeps firing
  BEFORE any transport leg (uia.route and the _front_door callers return
  the refusal without a single _run_uia_leg).
"""

import base64
import importlib.resources
import json

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("testuser", "placeholder-pass")
VM_GUID = "e953c649-1234-5678-9abc-def012345678"
SID = "S-1-5-21-1000-2000-3000-1001"
FAKE_SHA = "aa" * 32

#: The helper session block ok frames carry (the F4 integrity contract:
#: an ok frame's session.helper.sha256 must match uia._packaged_helper_sha256,
#: stubbed to FAKE_SHA in these tests -- the test_uia_refs_actions idiom).
HELPER_SESSION = {
    "session_id": 2,
    "interactive_user": "tester",
    "locked": False,
    "helper": {"running": True, "sha256": FAKE_SHA},
}

#: One find result element that is NOT a glyph node (multi-character name).
PLAIN_ELEMENT = {"name": "OK", "control_type": "Button"}

#: Same-line tolerance for the glyph-run geometry, in pixels (the helper's
#: rects are integer "x,y,w,h" strings; two glyphs are on ONE line when
#: their y values differ by AT MOST this much -- the boundary fixtures in
#: test_line_tolerance_boundary_is_pinned pin this VALUE: a y difference
#: of exactly LINE_TOLERANCE_PX merges, LINE_TOLERANCE_PX + 1 does not).
LINE_TOLERANCE_PX = 2

#: The frozen AC1 frame sequence for an electron find: the enable frame,
#: then the find frame -- NOTHING else (an inspect before the enable, a
#: find first, or any extra frame fails).
EXACT_ELECTRON_FIND_SEQUENCE = ["enable_accessibility", "find"]


# ---------------------------------------------------------------------------
# shared harness (no real PowerShell on any path except AC2b)
# ---------------------------------------------------------------------------

class PSRecorder:
    """pswindows.run_ps stand-in: records scripts, always answers `stdout`
    (the vmident resolve leg reads the VM GUID out of it)."""

    def __init__(self, stdout: str = ""):
        self.scripts: list[str] = []
        self.stdout = stdout

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(stdout=self.stdout, returncode=0)


class CorrelatedLeg:
    """uia._run_uia_leg stand-in (the transport choke): records every
    (script, stdin_b64) and serves a helper frame built by
    `frame_factory(request)` with the request parsed from the framed
    stdin's SECOND line, so the served frame's id correlates with the
    request (the F4 parse contract)."""

    def __init__(self, frame_factory):
        self.scripts: list[str] = []
        self.stdin_b64: list[str | None] = []
        self.frame_factory = frame_factory

    def __call__(self, cfg, script, *, stdin_b64=None, timeout_s=None,
                 **kwargs):
        self.scripts.append(script)
        self.stdin_b64.append(stdin_b64)
        request: dict = {}
        if stdin_b64:
            lines = stdin_b64.strip().split("\n")
            if len(lines) >= 2:
                try:
                    request = json.loads(
                        base64.b64decode(lines[1]).decode("utf-8"))
                except (ValueError, TypeError):
                    request = {}
        return pswindows.PSResult(
            stdout=json.dumps(self.frame_factory(request)), returncode=0)

    def requests(self) -> list[dict]:
        """Every request frame that reached the transport, in order."""
        out: list[dict] = []
        for framed in self.stdin_b64:
            if not framed:
                continue
            lines = framed.strip().split("\n")
            if len(lines) >= 2:
                out.append(json.loads(
                    base64.b64decode(lines[1]).decode("utf-8")))
        return out


class FrontDoorPipe:
    """uia._pipe_request stand-in (the 4-arg verb front-door shape):
    records every request frame the verb layer builds and answers from a
    per-verb frame table; any verb without an entry gets the FAILURE MODE
    AC3 forbids -- a successful EMPTY match list -- so a wrong
    implementation fails the check instead of passing vacuously."""

    def __init__(self, frames: dict | None = None):
        self.requests: list[dict] = []
        self.frames = {
            verb: json.loads(json.dumps(frame))
            for verb, frame in (frames or {}).items()
        }

    def __call__(self, cfg, vm, cred, request):
        self.requests.append(request)
        frame = self.frames.get(request.get("verb"))
        if frame is None:
            frame = {"ok": True, "result": {"elements": []},
                     "session": dict(HELPER_SESSION)}
        return json.loads(json.dumps(frame))


class BrokerPipe:
    """uia._pipe_request stand-in (the 3-arg broker-forward shape) for the
    preserving gate pin: records calls, answers generically."""

    def __init__(self):
        self.calls: list[dict] = []

    def __call__(self, registration, request, correlation_id):
        self.calls.append({"request": request,
                           "correlation_id": correlation_id})
        return {"ok": True, "verb": request.get("verb"),
                "correlation_id": correlation_id}


class LegRecorder:
    """uia._run_uia_leg stand-in that must stay UNTOUCHED on a refusal:
    records every leg; serving is irrelevant because the pin is emptiness."""

    def __init__(self):
        self.scripts: list[str] = []
        self.stdin_b64: list[str | None] = []

    def __call__(self, cfg, script, *, stdin_b64=None, timeout_s=None,
                 **kwargs):
        self.scripts.append(script)
        self.stdin_b64.append(stdin_b64)
        return pswindows.PSResult(
            stdout=json.dumps({"ok": True, "id": "unused", "result": {},
                               "session": dict(HELPER_SESSION)}),
            returncode=0)


def _wire_front_door(monkeypatch, leg) -> None:
    """Make the REAL _pipe_request front door runnable without a guest:
    vmident's resolve leg reads the VM GUID, the quser discovery answers
    session 2, the text-discovery legs answer empty, the transport choke is
    `leg`, and the packaged-helper digest matches the frames we serve."""
    from hyperv_mcp import uia

    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))
    monkeypatch.setattr(uia, "_run_uia_leg", leg)
    monkeypatch.setattr(
        uia, "_ps_guest_text",
        lambda cfg, ref, cred, guest_command, timeout_s=30: "")
    monkeypatch.setattr(
        uia, "_run_quser",
        lambda cfg, ref, cred: {"user": CRED.username, "session_id": 2})
    monkeypatch.setattr(uia, "_packaged_helper_sha256", lambda: FAKE_SHA)


def _seed_registration(capabilities: set) -> dict:
    """Seed the (vm, session) registration row the front door will find."""
    from hyperv_mcp import uia

    return uia.register_helper(
        vm_guid=VM_GUID, user_sid=SID, session_id=2,
        capabilities=capabilities, nonce="",
    )


def _electron_find(cfg, selector=None):
    from hyperv_mcp import uia

    return uia.find(cfg, "vm1", CRED, selector or {"name": "OK"},
                    adapter="electron")


def _rect(x: int, y: int, w: int, h: int) -> str:
    """A rect in the helper's frozen convention: "x,y,w,h"."""
    return f"{x},{y},{w},{h}"


def _spanning_rect(rects: list[str]) -> str:
    """The rect a merged glyph run must carry: x/width over the run's
    union, the run's (first node's) line y, the run's tallest height."""
    parsed = [tuple(int(p) for p in r.split(",")) for r in rects]
    x = min(r[0] for r in parsed)
    y = parsed[0][1]
    right = max(r[0] + r[2] for r in parsed)
    h = max(r[3] for r in parsed)
    return _rect(x, y, right - x, h)


def _is_glyph(element: dict) -> bool:
    return (element.get("control_type") == "Text"
            and isinstance(element.get("name"), str)
            and len(element["name"]) == 1)


def _expected_merge(elements: list[dict]) -> list[dict]:
    """The frozen merge contract computed independently in the test: glyph
    runs on one line join (metadata from the run's first node, spanning
    rect); anything else -- multi-char names, non-Text types, or a glyph
    whose y is further than LINE_TOLERANCE_PX from the run's first node's
    y -- terminates the run and passes through verbatim."""
    out: list[dict] = []
    run: list[dict] = []

    def _flush():
        if not run:
            return
        first = dict(run[0])
        first["name"] = "".join(e["name"] for e in run)
        first["rect"] = _spanning_rect([e["rect"] for e in run])
        out.append(first)
        run.clear()

    def _line_y(element: dict) -> int:
        return int(str(element["rect"]).split(",")[1])

    for element in elements:
        if _is_glyph(element) and element.get("rect"):
            if run and abs(_line_y(element) - _line_y(run[0])) <= LINE_TOLERANCE_PX:
                run.append(element)
                continue
            _flush()
            run.append(element)
            continue
        _flush()
        out.append(dict(element))
    _flush()
    return out


def _exact_verb_sequence(verbs: list) -> bool:
    """The frozen AC1 pin: the electron find path issues EXACTLY
    [enable_accessibility, find] at the seam -- nothing before, between
    or after."""
    return list(verbs) == EXACT_ELECTRON_FIND_SEQUENCE


# ---------------------------------------------------------------------------
# AC1: the enable request precedes the selector resolution
# ---------------------------------------------------------------------------

def test_electron_adapter_requests_accessibility(monkeypatch):
    """AC1: WHEN a find request uses the electron adapter on an approved
    registration, the system sends the helper a request to ENABLE the
    renderer accessibility tree BEFORE resolving the selector -- and the
    ordered frames observed at the transport choke are EXACTLY
    [enable_accessibility, find] (strengthened: an inspect or any other
    selector-resolving verb before the enable, a find-first order, or any
    extra frame fails). Driven through the REAL front door (approved
    registration, real adapter gate).
    RED at base (no enable frame exists), GREEN after the fix."""
    from hyperv_mcp import uia

    _seed_registration({"uia", uia.ELECTRON_CAPABILITY})
    leg = CorrelatedLeg(lambda request: {
        "ok": True,
        "id": request.get("id"),
        "result": ({"available": True}
                   if request.get("verb") == "enable_accessibility"
                   else {"elements": [dict(PLAIN_ELEMENT)]}),
        "session": dict(HELPER_SESSION),
    })
    _wire_front_door(monkeypatch, leg)

    out = _electron_find(Config(unrestricted=True))

    assert out.get("ok") is True, out
    requests = leg.requests()
    verbs = [r.get("verb") for r in requests]
    assert "find" in verbs, f"the find itself must still run: {verbs!r}"
    assert "enable_accessibility" in verbs, (
        "the electron adapter must send the helper a request to enable the "
        "renderer accessibility tree (verb enable_accessibility) before "
        f"resolving the selector; frames observed: {verbs!r}")
    assert _exact_verb_sequence(verbs), (
        f"the electron find path must issue EXACTLY "
        f"{EXACT_ELECTRON_FIND_SEQUENCE!r} at the transport seam, in that "
        f"order -- nothing before, between or after; observed: {verbs!r}")
    # companion negative: prove the exact-sequence predicate REJECTS the
    # wrong orders (an inspect -- or any selector-resolving verb -- BEFORE
    # the enable, a find first, an extra frame), so the pin above cannot
    # pass vacuously.
    for bad in (["inspect", "enable_accessibility", "find"],
                ["enable_accessibility", "inspect", "find"],
                ["find", "enable_accessibility"],
                ["enable_accessibility", "find", "find"],
                ["enable_accessibility"],
                ["find"]):
        assert not _exact_verb_sequence(bad), (
            f"the exact-sequence predicate must reject {bad!r} -- an "
            f"inspect (or any selector-resolving verb) before "
            f"enable_accessibility, or any deviation, must FAIL the check")
    assert not _exact_verb_sequence(["inspect"] + verbs), (
        "the exact-sequence predicate must reject the observed frames with "
        "a leading inspect -- the strengthened check has teeth")
    enable = requests[verbs.index("enable_accessibility")]
    assert enable.get("adapter") == "electron", (
        "the enable request is itself an electron-adapter request")
    find_req = requests[verbs.index("find")]
    assert find_req.get("adapter") == "electron"
    assert find_req.get("selector"), "the find frame still carries the selector"


# ---------------------------------------------------------------------------
# AC2: adjacent single-glyph text nodes merge into word runs (electron only)
# ---------------------------------------------------------------------------

def test_glyph_nodes_are_merged(monkeypatch):
    """AC2: WHEN the electron adapter returns text nodes, adjacent
    single-glyph text nodes whose rects share a line (y within 2px) merge
    into ONE node per word run; a glyph on a DIFFERENT line TERMINATES the
    run (two lines never become one node); the merged node PRESERVES the
    run's first element_id, its state, and carries a rect spanning the run
    (a merge that silently drops element_id/rect/state fails). The plain
    (non-electron) path is NOT merged -- the merge is adapter-scoped. Both
    paths are fed the SAME per-glyph fixture through the pipe seam, so the
    two outcomes differ only by the adapter.
    RED at base (no merge exists), GREEN after the fix."""
    # one node per glyph, WITH line geometry ("x,y,w,h" rects); the
    # multi-char " (status)" and the Button terminate runs, so the word
    # runs are exactly "Ok" and "Done"
    per_glyph = [
        {"name": "O", "control_type": "Text", "element_id": "42:11",
         "state": {"enabled": True}, "rect": _rect(0, 10, 8, 16)},
        {"name": "k", "control_type": "Text", "element_id": "42:12",
         "state": {"enabled": True}, "rect": _rect(8, 10, 8, 16)},
        {"name": " (status)", "control_type": "Text", "element_id": "42:13",
         "state": {}, "rect": _rect(16, 10, 70, 16)},
        {"name": "Save", "control_type": "Button", "element_id": "42:14",
         "state": {}, "rect": _rect(0, 34, 60, 24)},
        {"name": "D", "control_type": "Text", "element_id": "42:15",
         "state": {"enabled": True}, "rect": _rect(0, 70, 9, 16)},
        {"name": "o", "control_type": "Text", "element_id": "42:16",
         "state": {"enabled": True}, "rect": _rect(9, 70, 9, 16)},
        {"name": "n", "control_type": "Text", "element_id": "42:17",
         "state": {"enabled": True}, "rect": _rect(18, 70, 9, 16)},
        {"name": "e", "control_type": "Text", "element_id": "42:18",
         "state": {"enabled": True}, "rect": _rect(27, 70, 8, 16)},
    ]
    pipe = FrontDoorPipe({
        "enable_accessibility": {"ok": True, "result": {"available": True},
                                 "session": dict(HELPER_SESSION)},
        "find": {"ok": True, "result": {"elements": per_glyph},
                 "session": dict(HELPER_SESSION)},
    })
    from hyperv_mcp import uia

    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))
    cfg = Config(unrestricted=True)

    # electron: one node per word run, with preserved metadata
    out_e = uia.find(cfg, "vm1", CRED, {"name": "x"}, adapter="electron")
    assert out_e.get("ok") is True, out_e
    elements = out_e.get("elements")
    assert isinstance(elements, list), out_e
    assert [e.get("name") for e in elements] == ["Ok", " (status)", "Save",
                                                 "Done"], (
        f"adjacent single-glyph Text nodes on one line must merge into one "
        f"node per word run (concatenated name), with non-glyph nodes "
        f"preserved verbatim: {[e.get('name') for e in elements]!r}")
    assert [e.get("control_type") for e in elements] == [
        "Text", "Text", "Button", "Text"], (
        "merged nodes keep the Text control type; non-Text nodes pass "
        "through unchanged")
    assert len(elements) == 4

    # metadata preservation: the merged "Ok" run keeps its FIRST node's
    # identity and state, and carries a rect spanning the run
    ok_node = elements[0]
    assert ok_node.get("element_id") == "42:11", (
        f"the merged node must keep the run's FIRST element_id (42:11), "
        f"got {ok_node.get('element_id')!r} -- a merge that drops "
        f"element_id leaves the run unaddressable")
    assert ok_node.get("state") == {"enabled": True}, (
        f"the merged node must keep the run's first state block, got "
        f"{ok_node.get('state')!r}")
    assert ok_node.get("rect") == _rect(0, 10, 16, 16), (
        f"the merged node must carry a rect spanning the run "
        f"(0,10,16,16 -- union of its glyphs' rects), got "
        f"{ok_node.get('rect')!r}")
    done_node = elements[3]
    assert done_node.get("element_id") == "42:15", (
        f"the second word run keeps its own first element_id (42:15), got "
        f"{done_node.get('element_id')!r}")
    assert done_node.get("rect") == _rect(0, 70, 35, 16), (
        f"the second merged node spans its own run (0,70,35,16), got "
        f"{done_node.get('rect')!r}")

    # the electron path issued the enable first, then the find
    verbs_e = [r.get("verb") for r in pipe.requests]
    assert verbs_e == ["enable_accessibility", "find"], verbs_e

    # plain adapter: the SAME fixture comes back untouched
    pipe.requests.clear()
    out_p = uia.find(cfg, "vm1", CRED, {"name": "x"})
    assert out_p.get("ok") is True, out_p
    plain = out_p.get("elements")
    assert [e.get("name") for e in plain] == [
        "O", "k", " (status)", "Save", "D", "o", "n", "e"], (
        f"the merge is adapter-scoped: the non-electron path must return "
        f"the helper's nodes verbatim, got "
        f"{[e.get('name') for e in plain]!r}")
    assert len(plain) == 8
    assert [r.get("verb") for r in pipe.requests] == ["find"], (
        "the plain path issues no enable request -- only the electron "
        "adapter pays for it")


def test_glyph_runs_do_not_cross_lines(monkeypatch):
    """AC2 geometry negative (companion to test_glyph_nodes_are_merged):
    glyph runs are LINE-BOUND -- list-adjacent glyphs whose rects sit on
    DIFFERENT lines (y further than 2px apart) must NOT merge into one
    node. A geometry-blind merge (runs split only by control type or name
    length) produces one four-character node here and fails.
    RED at base (no merge exists -- and a geometry-blind merge stays RED),
    GREEN after the fix."""
    two_lines = [
        {"name": "A", "control_type": "Text", "element_id": "42:21",
         "state": {"enabled": True}, "rect": _rect(0, 10, 8, 16)},
        {"name": "B", "control_type": "Text", "element_id": "42:22",
         "state": {"enabled": True}, "rect": _rect(8, 10, 8, 16)},
        # same list, next glyph FORTY px down: a different line
        {"name": "C", "control_type": "Text", "element_id": "42:23",
         "state": {}, "rect": _rect(0, 50, 8, 16)},
        {"name": "D", "control_type": "Text", "element_id": "42:24",
         "state": {}, "rect": _rect(8, 50, 8, 16)},
    ]
    pipe = FrontDoorPipe({
        "enable_accessibility": {"ok": True, "result": {"available": True},
                                 "session": dict(HELPER_SESSION)},
        "find": {"ok": True, "result": {"elements": two_lines},
                 "session": dict(HELPER_SESSION)},
    })
    from hyperv_mcp import uia

    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    out = uia.find(Config(unrestricted=True), "vm1", CRED, {"name": "x"},
                   adapter="electron")
    assert out.get("ok") is True, out
    elements = out.get("elements")
    assert isinstance(elements, list), out
    assert [e.get("name") for e in elements] == ["AB", "CD"], (
        f"a glyph on a DIFFERENT line must terminate the run -- two lines "
        f"are two nodes, never one: "
        f"{[e.get('name') for e in elements]!r}")
    assert len(elements) == 2
    # each line's node keeps ITS OWN first identity and spanning rect
    assert elements[0].get("element_id") == "42:21", elements[0]
    assert elements[0].get("rect") == _rect(0, 10, 16, 16), elements[0]
    assert elements[1].get("element_id") == "42:23", elements[1]
    assert elements[1].get("rect") == _rect(0, 50, 16, 16), elements[1]
    # the expectation is the frozen contract computed independently
    assert elements == _expected_merge(two_lines), (
        f"the merged two-line fixture must equal the frozen merge contract "
        f"computed independently in this file: {elements!r}")


# ---------------------------------------------------------------------------
# AC2 boundary (wave-3 S3): the tolerance VALUE itself is pinned
# ---------------------------------------------------------------------------

#: The boundary fixture table: (label, y-difference between the two
#: adjacent glyphs, expected names). A y difference of EXACTLY
#: LINE_TOLERANCE_PX is still ONE line (the boundary is inclusive);
#: LINE_TOLERANCE_PX + 1 is not; a large difference is not; and a glyph
#: that starts a new line's x-run entirely is not. An implementation
#: whose tolerance is anything other than 2px fails one of these rows
#: (a 39px tolerance, for instance, merges the +3 row and the +40 row).
_BOUNDARY_CASES = [
    ("exactly-at-tolerance", LINE_TOLERANCE_PX, ["AB"]),
    ("just-above-tolerance", LINE_TOLERANCE_PX + 1, ["A", "B"]),
    ("well-above-tolerance", 40, ["A", "B"]),
    ("different-line-entirely", 40, ["A", "B"]),
]


@pytest.mark.parametrize(
    "label,y_delta,expected_names",
    _BOUNDARY_CASES,
    ids=[case[0] for case in _BOUNDARY_CASES])
def test_line_tolerance_boundary_is_pinned(monkeypatch, label, y_delta,
                                           expected_names):
    """AC2 boundary (S3): the same-line tolerance is LINE_TOLERANCE_PX = 2
    and the boundary is INCLUSIVE -- a glyph exactly 2px below the run's
    first node MERGES, one 3px below does NOT, and neither does a glyph
    far below (40px) or one starting a different line entirely. Every row
    is also checked against the frozen merge contract computed
    independently in this file, so the tolerance VALUE (not just the
    concept) is pinned.
    RED at base (no merge exists -- and any tolerance other than 2px,
    including a 39px one, fails the just-above row), GREEN after the
    fix."""
    # the different-line-entirely row additionally resets the x run (the
    # second glyph starts at x=0 like a real wrapped line)
    second_x = 8 if label != "different-line-entirely" else 0
    fixture = [
        {"name": "A", "control_type": "Text", "element_id": "42:51",
         "state": {"enabled": True}, "rect": _rect(0, 10, 8, 16)},
        {"name": "B", "control_type": "Text", "element_id": "42:52",
         "state": {"enabled": True},
         "rect": _rect(second_x, 10 + y_delta, 8, 16)},
    ]
    pipe = FrontDoorPipe({
        "enable_accessibility": {"ok": True, "result": {"available": True},
                                 "session": dict(HELPER_SESSION)},
        "find": {"ok": True, "result": {"elements": fixture},
                 "session": dict(HELPER_SESSION)},
    })
    from hyperv_mcp import uia

    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    out = uia.find(Config(unrestricted=True), "vm1", CRED, {"name": "x"},
                   adapter="electron")
    assert out.get("ok") is True, out
    # the electron path issued the enable first, then the find (keeps every
    # boundary row RED at base, where no enable frame exists)
    assert [r.get("verb") for r in pipe.requests] == [
        "enable_accessibility", "find"], (
        f"the {label} row runs on the ELECTRON path: exactly "
        f"[enable_accessibility, find] must be issued; observed "
        f"{[r.get('verb') for r in pipe.requests]!r}")
    elements = out.get("elements")
    assert isinstance(elements, list), out
    assert [e.get("name") for e in elements] == expected_names, (
        f"the {label} row (y difference {y_delta}px) must yield "
        f"{expected_names!r} -- the tolerance is EXACTLY "
        f"LINE_TOLERANCE_PX={LINE_TOLERANCE_PX} px, inclusive at the "
        f"boundary; got {[e.get('name') for e in elements]!r}")
    assert elements == _expected_merge(fixture), (
        f"the {label} row must equal the frozen merge contract computed "
        f"independently in this file: {elements!r}")
    if len(elements) == 1:
        assert elements[0].get("element_id") == "42:51", elements[0]
        assert elements[0].get("rect") == _spanning_rect(
            [e["rect"] for e in fixture]), elements[0]


def test_glyph_merge_default_switch(monkeypatch):
    """AC2 switch (S3 option-off companion): the merge is governed by the
    module-level switch ``uia.GLYPH_MERGE_DEFAULT`` -- ON by default, and
    read at CALL time: with it turned off, the ELECTRON path returns the
    helper's original per-glyph nodes UNCHANGED (byte-for-byte the input
    list, no merging, no reordering, no dropped metadata).
    RED at base (uia.GLYPH_MERGE_DEFAULT does not exist), GREEN after the
    fix."""
    from hyperv_mcp import uia

    assert getattr(uia, "GLYPH_MERGE_DEFAULT", None) is True, (
        "uia.GLYPH_MERGE_DEFAULT must exist, be module-level, and default "
        "to True (the glyph merge ships ON); got "
        f"{getattr(uia, 'GLYPH_MERGE_DEFAULT', None)!r}")

    per_glyph = [
        {"name": "O", "control_type": "Text", "element_id": "42:11",
         "state": {"enabled": True}, "rect": _rect(0, 10, 8, 16)},
        {"name": "k", "control_type": "Text", "element_id": "42:12",
         "state": {"enabled": True}, "rect": _rect(8, 10, 8, 16)},
        {"name": "!", "control_type": "Text", "element_id": "42:13",
         "state": {}, "rect": _rect(16, 10, 4, 16)},
    ]
    pipe = FrontDoorPipe({
        "enable_accessibility": {"ok": True, "result": {"available": True},
                                 "session": dict(HELPER_SESSION)},
        "find": {"ok": True, "result": {"elements": per_glyph},
                 "session": dict(HELPER_SESSION)},
    })
    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    # default ON: the glyphs merge (sanity -- the switch governs this path)
    merged = uia.find(Config(unrestricted=True), "vm1", CRED, {"name": "x"},
                      adapter="electron")
    assert merged.get("ok") is True, merged
    assert [e.get("name") for e in merged.get("elements")] == ["Ok!"], (
        f"with GLYPH_MERGE_DEFAULT on (the default) the glyphs must merge: "
        f"{merged.get('elements')!r}")

    # option OFF: the SAME fixture comes back UNCHANGED on the electron path
    monkeypatch.setattr(uia, "GLYPH_MERGE_DEFAULT", False)
    try:
        out = uia.find(Config(unrestricted=True), "vm1", CRED,
                       {"name": "x"}, adapter="electron")
    finally:
        monkeypatch.setattr(uia, "GLYPH_MERGE_DEFAULT", True)
    assert out.get("ok") is True, out
    elements = out.get("elements")
    assert isinstance(elements, list), out
    assert elements == per_glyph, (
        f"with uia.GLYPH_MERGE_DEFAULT turned off, the electron path must "
        f"return the helper's per-glyph nodes UNCHANGED (the exact input "
        f"list); got {elements!r}")
    assert [r.get("verb") for r in pipe.requests] == [
        "enable_accessibility", "find"] * 2, (
        "both legs (merge on, then merge off) still issue the enable first "
        "-- the switch governs the merge only, not the accessibility "
        f"enable: {[r.get('verb') for r in pipe.requests]!r}")


# ---------------------------------------------------------------------------
# AC2b (wave-3 S4 rewrite): the HELPER's REAL dispatch, driven end-to-end
# for real under PS 5.1 -- behavior and wiring, no function naming
# ---------------------------------------------------------------------------

def _helper_functions_slice() -> str:
    """The packaged helper's function definitions, sliced verbatim from the
    artifact (the tests/unit/test_f05_interactive_helper.py:367-381 idiom):
    everything between the first `function Read-HelperFile` and the startup
    section that reads the provisioned files."""
    helper = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8-sig")
    )
    start = helper.index("function Read-HelperFile")
    end = helper.index("$HelperVersion = Read-HelperFile 'version.txt'")
    return helper[start:end]


def _ps_available() -> bool:
    import os

    return os.path.isfile(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")


def _run_helper_dispatch(cases_ps: str, tmp_path) -> list[dict]:
    """Run `cases_ps` against the helper's real functions in PS 5.1; parse
    the one-JSON-per-case stdout into dicts (the
    tests/unit/test_f05_interactive_helper.py:391-425 idiom; the script
    travels as a -File)."""
    import json as _json
    import subprocess

    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "Add-Type -AssemblyName UIAutomationClient",
        "Add-Type -AssemblyName UIAutomationTypes",
        _helper_functions_slice(),
        cases_ps,
    ])
    script_file = tmp_path / "electron-glyph-dispatch-cases.ps1"
    script_file.write_text(script, encoding="utf-8-sig")
    proc = subprocess.run(
        [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(script_file)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"helper dispatch harness failed — stdout: {proc.stdout!r} "
        f"stderr: {proc.stderr[-2000:]!r}"
    )
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            out.append(_json.loads(line))
    assert out, f"no case JSON in harness output: {proc.stdout!r}"
    return out


def test_helper_merges_glyph_runs_before_matching(tmp_path):
    """AC2b (wave-3 S4 rewrite -- behavior and wiring, NOT naming): the
    helper's REAL request path (Invoke-Request, the production dispatch --
    the tests/unit/test_f05_interactive_helper.py:391-425 idiom) is driven
    for real under Windows PowerShell 5.1 against a synthetic per-glyph
    element tree hung under the dispatch's own element-resolution seam
    (Resolve-Target, redefined per that idiom):

      - an ELECTRON find whose selector names the JOINED word resolves to
        exactly ONE merged element: name "Word", the run's FIRST
        identity (element_id 42:31 -- a RuntimeId a later invoke/act can
        resolve, i.e. actionable), and a rect SPANNING the run;
      - an ELECTRON find whose selector names a single UNMERGED glyph
        ("W") resolves to NOTHING -- the unmerged glyphs do not satisfy
        the selector;
      - a PLAIN (adapter-less) find over the same tree never hands back a
        merged "Word" element -- the helper-side merge is electron-scoped.

    No helper function name or parameter set is pinned; an UNWIRED merge
    helper (a function nothing in the dispatch calls -- the S4 survivor)
    leaves the glyphs unmerged and fails the joined-name leg here.
    RED at base (the electron dispatch path does not merge -- the
    joined-name leg resolves nothing); the Windows PowerShell 5.1 leg is
    skipped only when that binary is genuinely absent."""
    if not _ps_available():
        pytest.skip("Windows PowerShell 5.1 is genuinely absent")
    guid = VM_GUID.lower()
    cases = "\n".join([
        # -- the dispatch's gates (the F05 dispatch idiom's setup block)
        "$HelperVersion = '1'",
        "$ownNonce = 'nonce-ac2b'",
        f"$recordedUuid = '{guid}'",
        "$identity = @{ sid = '" + SID + "'; user = 'tester'; session_id = 2 }",
        "$capabilities = @('uia')",
        "$MaxMatches = 200; $MaxValueChars = 65536",
        "function Get-LockState { $false }",
        f"function Get-LiveUuid {{ '{guid}' }}",
        "function Test-OwnsInputDesktop { $true }",
        "function Get-ForegroundWindow { $null }",
        # -- the synthetic per-glyph tree: W o r d on one line (y=10,
        #    x=0/8/16/24), each a UIA-element-shaped PSObject (Current
        #    reads for the merge; GetRuntimeId for the identity;
        #    GetUpdatedCache returning $this for the result builder)
        "function New-GlyphElement([string]$glyph, [int]$x, [string]$rid) {",
        "  $rect = New-Object PSObject",
        "  $rect | Add-Member -MemberType NoteProperty -Name X"
        " -Value $x",
        "  $rect | Add-Member -MemberType NoteProperty -Name Y"
        " -Value 10",
        "  $rect | Add-Member -MemberType NoteProperty -Name Width"
        " -Value 8",
        "  $rect | Add-Member -MemberType NoteProperty -Name Height"
        " -Value 16",
        "  $ct = New-Object PSObject",
        "  $ct | Add-Member -MemberType NoteProperty -Name"
        " ProgrammaticName -Value 'ControlType.Text'",
        "  $cur = New-Object PSObject",
        "  $cur | Add-Member -MemberType NoteProperty -Name Name"
        " -Value $glyph",
        "  $cur | Add-Member -MemberType NoteProperty -Name ControlType"
        " -Value $ct",
        "  $cur | Add-Member -MemberType NoteProperty -Name"
        " BoundingRectangle -Value $rect",
        "  $el = New-Object PSObject",
        "  $el | Add-Member -MemberType NoteProperty -Name Current"
        " -Value $cur",
        "  $el | Add-Member -MemberType NoteProperty -Name Cached"
        " -Value $cur",
        "  $el | Add-Member -MemberType NoteProperty -Name rid"
        " -Value $rid",
        "  $el | Add-Member -MemberType ScriptMethod -Name GetRuntimeId"
        " -Value { @($this.rid -split ':') }",
        "  $el | Add-Member -MemberType ScriptMethod -Name GetUpdatedCache"
        " -Value { $this }",
        "  return $el",
        "}",
        "$gW = New-GlyphElement 'W' 0 '42:31'",
        "$gO = New-GlyphElement 'o' 8 '42:32'",
        "$gR = New-GlyphElement 'r' 16 '42:33'",
        "$gD = New-GlyphElement 'd' 24 '42:34'",
        # -- the dispatch's own element-resolution seam, fed the synthetic
        #    tree (the F05 idiom: later definitions win)
        "function Resolve-Target { param($selector, $cache)"
        " @($gW,$gO,$gR,$gD) }",
        f"$target = @{{ vm_guid = '{guid}'; user_sid = '{SID}';"
        " session_id = 2 }",
        # case 1: ELECTRON find naming the JOINED word -> the merged,
        #         actionable element
        "$r1 = Invoke-Request @{ id = 'req-1'; verb = 'find';"
        " nonce = 'nonce-ac2b'; min_version = '1'; adapter = 'electron';"
        " target = $target; selector = @{ name = 'Word' } }",
        "$e1 = @($r1.result.elements)[0]",
        "@{ case = 'joined'; ok = $r1.ok; count = @($r1.result.elements).Count;"
        " name = [string]$e1.name; control_type = [string]$e1.control_type;"
        " element_id = [string]$e1.element_id; rect = [string]$e1.rect }"
        " | ConvertTo-Json -Compress -Depth 6",
        # case 2: ELECTRON find naming a single UNMERGED glyph -> nothing
        "$r2 = Invoke-Request @{ id = 'req-2'; verb = 'find';"
        " nonce = 'nonce-ac2b'; min_version = '1'; adapter = 'electron';"
        " target = $target; selector = @{ name = 'W' } }",
        "@{ case = 'unmerged'; ok = $r2.ok; count = @($r2.result.elements).Count }"
        " | ConvertTo-Json -Compress -Depth 6",
        # case 3: PLAIN find (no adapter) naming the joined word -> never
        #         a merged "Word" element (the helper-side merge is
        #         electron-scoped; unmerged glyphs make the plain path
        #         answer empty or ambiguous, never a merged node)
        "$r3 = Invoke-Request @{ id = 'req-3'; verb = 'find';"
        " nonce = 'nonce-ac2b'; min_version = '1'; target = $target;"
        " selector = @{ name = 'Word' } }",
        "$names3 = ''",
        "if ($r3.ok) { $names3 = (@($r3.result.elements) |"
        " ForEach-Object { $_.name }) -join '|' }",
        "@{ case = 'plain'; ok = $r3.ok; error_class ="
        " [string]$r3.error_class; names = $names3 }"
        " | ConvertTo-Json -Compress -Depth 6",
    ])
    results = {row["case"]: row for row in _run_helper_dispatch(cases, tmp_path)}

    joined = results["joined"]
    assert joined["ok"] is True, (
        f"an electron find naming the JOINED word must succeed through the "
        f"helper's real dispatch: {joined!r}")
    assert joined["count"] == 1, (
        f"one word run must resolve to exactly ONE element: {joined!r}")
    assert joined["name"] == "Word", (
        f"the merged element's name is the JOINED word run (the merge ran "
        f"at the source, BEFORE matching -- only then does a 'Word' "
        f"selector resolve): {joined!r}")
    assert joined["control_type"] == "Text", joined
    assert joined["element_id"] == "42:31", (
        f"the merged element must carry the run's FIRST identity "
        f"(element_id 42:31, the RuntimeId a later invoke/act resolves -- "
        f"an ACTIONABLE element): {joined!r}")
    assert joined["rect"] == _rect(0, 10, 32, 16), (
        f"the merged element must carry a rect SPANNING the run "
        f"(0,10,32,16): {joined!r}")

    unmerged = results["unmerged"]
    assert unmerged["ok"] is True, unmerged
    assert unmerged["count"] == 0, (
        f"an electron find naming a single UNMERGED glyph ('W') must "
        f"resolve NOTHING -- the unmerged glyphs do not satisfy the "
        f"selector, only the joined name does: {unmerged!r}")

    plain = results["plain"]
    assert not (plain["ok"] is True and "Word" in (plain["names"] or "")), (
        f"a PLAIN (adapter-less) find over the same tree must never hand "
        f"back a merged 'Word' element -- the helper-side merge is "
        f"electron-scoped: {plain!r}")


# ---------------------------------------------------------------------------
# AC3: an unavailable tree is accessibility_unavailable, never an empty list
# ---------------------------------------------------------------------------

#: The three enable answers that each mean UNAVAILABLE: the tree stayed
#: off (available false), the answer NEVER SAID (available missing), and
#: the helper itself refused with accessibility_unavailable.
UNAVAILABLE_ENABLE_FRAMES = [
    {"ok": True, "result": {"available": False}},
    {"ok": True, "result": {}},
    {"ok": False, "error_class": "accessibility_unavailable",
     "error": "chromium accessibility stayed off (helper-reported)"},
]
UNAVAILABLE_IDS = ["stayed-off", "available-missing", "helper-reported"]


@pytest.mark.parametrize(
    "enable_frame", UNAVAILABLE_ENABLE_FRAMES, ids=UNAVAILABLE_IDS)
def test_unavailable_tree_is_reported(monkeypatch, enable_frame):
    """AC3: IF the renderer accessibility tree stays unavailable after the
    enable request -- because the answer reports available false, because
    the answer omits ``available`` entirely, or because the helper itself
    refused -- the system reports error_class accessibility_unavailable
    with ZERO find frames issued. The pipe serves the parametrized enable
    answer; the DEFAULT frame for any other verb is a successful EMPTY
    match list -- exactly the degradation AC3 forbids -- so proceeding to
    the find anyway fails this check.
    RED at base (no availability handling exists), GREEN after the fix."""
    from hyperv_mcp import uia

    pipe = FrontDoorPipe({
        "enable_accessibility": dict(enable_frame,
                                     session=dict(HELPER_SESSION)),
    })
    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    out = uia.find(Config(unrestricted=True), "vm1", CRED,
                   {"name": "OK"}, adapter="electron")

    assert out.get("ok") is False, (
        f"an unavailable renderer tree must not report success: {out!r}")
    assert out.get("error_class") == "accessibility_unavailable", (
        f"the refusal must be exactly error_class "
        f"accessibility_unavailable, got {out.get('error_class')!r}")
    assert out.get("error"), "the refusal carries a human-readable error"
    assert not out.get("elements"), (
        "an unavailable tree is an error, never an (empty) match list")
    verbs = [r.get("verb") for r in pipe.requests]
    assert "enable_accessibility" in verbs, (
        "AC3 is about the tree staying unavailable AFTER the enable "
        "request -- the enable must have been sent")
    assert "find" not in verbs, (
        "with the tree unavailable the selector must not be resolved into "
        "an empty match list -- ZERO find frames may be issued")
    assert verbs.count("find") == 0 and all(
        v != "inspect" for v in verbs), (
        f"no selector-resolving verb may run on an unavailable tree; "
        f"frames observed: {verbs!r}")


# ---------------------------------------------------------------------------
# AC3+ (wave-3 S8): the enable leg's receipt/ledger polarity
# ---------------------------------------------------------------------------

def test_enable_leg_receipt_and_ledger_polarity(monkeypatch):
    """AC3+ (S8): the electron enable leg is READ-ONLY housekeeping on the
    verb layer's own seams (console.record_state_read /
    console.record_console_input -- the tests/unit/
    test_console_commit_guard_uia_polarity.py _mint_spy idiom):

      - a SUCCESSFUL electron find mints EXACTLY ONE state receipt (the
        find's; the enable_accessibility request itself must not mint a
        second one) and records ZERO console-input ledger entries -- the
        ledger seq for the resolved VM is unmoved;
      - a REFUSED enable (tree unavailable) mints ZERO receipts, bumps
        ZERO ledger entries, and issues ZERO find frames.

    RED at base: no enable exists there, so the refused-enable leg still
    runs a plain find that SUCCEEDS on the default frame and mints one
    receipt -- the zero-mint pin fires. GREEN after the fix."""
    from hyperv_mcp import uia

    pipe = FrontDoorPipe({
        "enable_accessibility": {"ok": True, "result": {"available": True},
                                 "session": dict(HELPER_SESSION)},
        "find": {"ok": True, "result": {"elements": [dict(PLAIN_ELEMENT)]},
                 "session": dict(HELPER_SESSION)},
    })
    monkeypatch.setattr(uia, "_pipe_request", pipe)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder(VM_GUID))

    mints: list = []

    def _mint_spy(*a, **k):
        mints.append(k)
        return f"s8-mint-{len(mints)}"

    monkeypatch.setattr(console, "record_state_read", _mint_spy)

    inputs: list = []
    real_record_input = console.record_console_input

    def _input_spy(*a, **k):
        inputs.append((a, k))
        return real_record_input(*a, **k)

    monkeypatch.setattr(console, "record_console_input", _input_spy)

    console.note_name_guid_hint("vm1", VM_GUID)
    console.reset_input_ledger()
    try:
        before = console._last_input_seq_for(VM_GUID)
        out = uia.find(Config(unrestricted=True), "vm1", CRED,
                       {"name": "OK"}, adapter="electron")
        assert out.get("ok") is True, out
        assert [r.get("verb") for r in pipe.requests] == [
            "enable_accessibility", "find"], (
            "sanity: the successful leg issued exactly the enable, then the "
            f"find: {[r.get('verb') for r in pipe.requests]!r}")
        assert len(mints) == 1, (
            f"a successful electron find must mint EXACTLY ONE state "
            f"receipt (the find's -- the enable_accessibility request is "
            f"read-only housekeeping and must not mint); "
            f"record_state_read calls: {mints!r}")
        assert out.get("state_receipt") == "s8-mint-1", (
            f"the envelope's state_receipt must be the one mint the find "
            f"drove: {out!r}")
        assert inputs == [], (
            f"enable_accessibility must record ZERO console-input ledger "
            f"entries (it sends no input to any console); "
            f"record_console_input calls: {inputs!r}")
        assert console._last_input_seq_for(VM_GUID) == before, (
            "the electron enable+find flow must leave the VM's input-ledger "
            "sequence unmoved -- zero ledger bumps")

        # -- the refused enable: zero receipts, zero ledger bumps, zero
        #    find frames (FrontDoorPipe's default frame for an unlisted
        #    verb is a SUCCESSFUL empty match -- exactly the degradation
        #    that would mint and pass vacuously)
        mints.clear()
        inputs.clear()
        refused_pipe = FrontDoorPipe({
            "enable_accessibility": {"ok": True,
                                     "result": {"available": False},
                                     "session": dict(HELPER_SESSION)},
        })
        monkeypatch.setattr(uia, "_pipe_request", refused_pipe)
        refused = uia.find(Config(unrestricted=True), "vm1", CRED,
                           {"name": "OK"}, adapter="electron")
        assert refused.get("ok") is False, (
            f"an unavailable renderer tree must not report success: "
            f"{refused!r}")
        assert refused.get("error_class") == "accessibility_unavailable", (
            refused)
        assert "find" not in [r.get("verb") for r in refused_pipe.requests], (
            "with the tree unavailable ZERO find frames may be issued")
        assert mints == [], (
            f"a REFUSED enable must mint ZERO state receipts; "
            f"record_state_read calls: {mints!r}")
        assert inputs == [], (
            f"a refused enable must bump ZERO console-input ledger entries; "
            f"record_console_input calls: {inputs!r}")
        assert console._last_input_seq_for(VM_GUID) == before, (
            "the refused enable must leave the input-ledger sequence unmoved")
    finally:
        console.reset_input_ledger()


# ---------------------------------------------------------------------------
# AC4 (preserving): no capability -> adapter_unapproved, zero transport
# ---------------------------------------------------------------------------

def test_unapproved_adapter_still_refused(monkeypatch):
    """AC4 (preserving): a registration WITHOUT uia.ELECTRON_CAPABILITY
    still gets {"ok": False, "error_class": "adapter_unapproved"} for an
    electron request, and the refusal still fires BEFORE any transport
    leg. Both layers are pinned: the brokered route (the
    test_f05_interactive_helper.py:335-352 mirror -- the pipe seam records
    nothing) and the verb path through the REAL front door (the transport
    choke records nothing)."""
    from hyperv_mcp import uia

    cfg = Config(unrestricted=True)

    # -- verb level: the real front door, a found-but-unapproved
    #    registration, the transport choke stubbed -- it must stay EMPTY
    _seed_registration({"uia"})  # approved for UIA, NOT for electron
    legs = LegRecorder()
    _wire_front_door(monkeypatch, legs)
    out = uia.find(cfg, "vm1", CRED, {"name": "OK"}, adapter="electron")
    assert out.get("ok") is False, out
    assert out.get("error_class") == "adapter_unapproved", (
        f"the electron adapter without the registered capability must be "
        f"refused as adapter_unapproved, got {out.get('error_class')!r}")
    assert legs.scripts == [], (
        f"the gate must fire BEFORE any transport leg; {len(legs.scripts)} "
        "helper leg(s) ran")

    # -- broker level (the frozen AC21 mirror): the pipe seam records
    #    nothing for the refused electron request
    reg_plain = uia.register_helper(
        vm_guid=VM_GUID, user_sid=SID, session_id=2,
        capabilities={"uia"}, nonce="pin",
    )
    broker = BrokerPipe()
    monkeypatch.setattr(uia, "_pipe_request", broker)
    request = {
        "verb": "find",
        "target": {"vm_guid": VM_GUID, "user_sid": SID, "session_id": 2},
        "selector": {"name": "OK"},
        "agent_id": "agent-e",
        "adapter": "electron",
    }
    refused = uia.route(reg_plain, request)
    assert refused.get("ok") is False, refused
    assert refused.get("error_class") == "adapter_unapproved", refused
    assert broker.calls == [], (
        "the unapproved adapter request must not reach the helper pipe")
