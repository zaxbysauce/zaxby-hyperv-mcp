"""Evidence run journal (issue #131).

An opt-in append-only journal: while an evidence run is open, every MUTATING
tool call (the tools the lease gate recognises via ``server.TOOL_SCOPES`` —
the authoritative mutating map) appends one JSONL line to a journal file under
the run directory, recording the call, its raw result, and the frames captured
immediately before and after it. Stopping the run writes a SHA-256 manifest
covering every file in the directory, so a reviewer can prove a cited receipt
was not edited after the fact; where ffmpeg is available and video was
requested at start, the frames are additionally assembled into an MP4 with a
per-step action marker.

Manifest scope edge (review ASK-152-1, swarm-critic adjudicated 2026-11-18):
the manifest records the bytes present when ``stop_run`` executed. If the
stop result carried a ``"tree kill FAILED"`` video note (ffmpeg termination
could not be established — never observed in practice), a LATER digest
mismatch on ``evidence.mp4`` is the expected result of that edge, not
evidence of tampering; the file was already flagged untrusted via
``video: None`` plus the note. Reusing a ``run_dir`` for a second run is
not supported.

Design commitments (from the frozen spec + plan-critic rounds):

* The record stores typed text as its LENGTH, never the text (AC2) — the
  journal must not become a secret store. Sensitive argument keys (text,
  value, script, command, expression, ...) are length-replaced, and the
  collected secret values are scrubbed from the serialized RESULT as well, so
  a command that echoes its own typed secret cannot leak it back in.
* ``username``/``password`` and any resolved ``secret_ref`` VALUE are never
  serialized (the hook reads arguments before ``_resolve_secret`` expands
  them).
* Opt-in: with no run open for a (agent, vm) the module does nothing and every
  tool behaves byte-identically to before (AC5). ``begin`` returns None in
  that case; the guard hooks are all no-ops on a None token.
* Frame capture (screenshots) lives under ``run_dir/frames/`` through the
  console capture seam (already host-write gated at start); a capture failure
  records null frame fields and NEVER fails the journaled call.

The module holds no reference to ``server`` at import time (server imports
this module), avoiding an import cycle: ``install()`` injects the mutating
predicate, the config getter, and the screenshot function at bootstrap.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Argument keys whose string values are typed text / executable content: these
# are recorded by LENGTH, never verbatim (AC2), and their values are collected
# for result-scrubbing (PC10). Matched case-insensitively on the leaf key.
_SENSITIVE_KEYS = frozenset({
    "text", "value", "script", "command", "expression", "scancodes", "value_b64",
    # issue #152 review F-007: per-keystroke input slots are content too —
    # a caller can spell arbitrary text one press_key at a time.
    "key", "keys", "modifiers",
})
# Keys that carry credentials: never serialized at all (value -> length only).
_NEVER_KEYS = frozenset({"password", "username", "secret_ref", "secret", "cred"})
# prefix marking a scrub token that must match only its quoted repr form
# (sensitive-list elements; review F-007) — never the bare substring.
_QUOTED_MARK = "\x00quoted:"
# key-name slots whose values are echoed only through {x!r} validation
# errors: scrubbed repr-form-only (F-007 round-4), not exact-replaced.
_ECHO_ONLY_KEYS = frozenset({"key", "keys", "modifiers"})

_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_ARG_STR = 2000  # cap on non-sensitive string fields kept verbatim

# ---- injected seams (set by server.install) --------------------------------

def _no_config() -> Any:
    return None


def _not_mutating(name: str) -> bool:
    return False


_get_config: Callable[[], Any] = _no_config
_is_mutating: Callable[[str], bool] = _not_mutating
_screenshot: Callable[..., dict] | None = None


def install(*, get_config: Callable[[], Any],
            is_mutating: Callable[[str], bool],
            screenshot: Callable[..., dict]) -> None:
    """Wire the module to the server at bootstrap (breaks the import cycle).

    ``screenshot(cfg, *, vm_name, vm_id, save_path, width, height)`` returns a
    dict with ``frame_hash`` and the written ``saved_path`` (console.screenshot
    metadata), or ``{}`` on failure — never raises into the journaled call.
    """
    global _get_config, _is_mutating, _screenshot
    _get_config = get_config
    _is_mutating = is_mutating
    _screenshot = screenshot


# ---- run registry ----------------------------------------------------------

class _Run:
    def __init__(self, run_id: str, run_dir: Path, agent: str | None,
                 vms: list[str], video: bool) -> None:
        self.run_id = run_id
        self.run_dir = run_dir
        self.agent = agent
        # normalized (casefolded) VM identity strings this run covers; empty
        # means every VM the calling agent touches.
        self.vms = {v.strip().casefold() for v in vms if v and v.strip()}
        self.video = video
        self.frames_dir = run_dir / "frames"
        self.journal_path = run_dir / "journal.jsonl"
        self.state = "open"          # open -> closing -> closed
        self.inflight = 0
        self.seq = 0
        self.lock = threading.Lock()
        self.frames: list[tuple[int, str, str, Path]] = []  # (seq, role, tool, path)
        self.started_at = time.monotonic()

    def covers(self, agent: str | None, vm_ids: set[str]) -> bool:
        if self.agent != agent:
            return False
        if not self.vms:
            return True
        # Expand BOTH sides through the hint map so a run stored under a name
        # matches calls carrying that VM's GUID and vice versa (review F-004).
        try:
            from . import console as _console

            expanded = set(self.vms)
            for v in self.vms:
                hint = _console._NAME_GUID_HINTS.get(v)
                if hint:
                    expanded.add(hint)
            called = set(vm_ids)
            for v in vm_ids:
                hint = _console._NAME_GUID_HINTS.get(v)
                if hint:
                    called.add(hint)
            return bool(expanded & called)
        except Exception:  # noqa: BLE001 — fall back to literal intersection
            return bool(self.vms & vm_ids)


_RUNS: dict[str, _Run] = {}
_RUNS_LOCK = threading.Lock()
# review F-011: an agent that never stops its runs would grow the registry
# (and on-disk run dirs) without bound; refuse a new start past the open cap.
_MAX_OPEN_RUNS = 16


def reset_for_tests() -> None:
    """Drop all runs (test isolation). Not for production use."""
    with _RUNS_LOCK:
        _RUNS.clear()


def _vm_ids_from_arguments(arguments: dict) -> set[str]:
    """Every identity spelling a call may address its VM under: the literal
    casefolded name/id values plus the hint-resolved GUID for each name
    (issue #152 review F-004 — a run scoped by name must cover by-GUID calls
    for the same VM and vice versa)."""
    ids: set[str] = set()
    raw_names: list[str] = []
    for key in ("vm_name", "vm_id"):
        v = arguments.get(key)
        if isinstance(v, str) and v.strip():
            ids.add(v.strip().casefold())
            if key == "vm_name":
                raw_names.append(v.strip())
    # multi-VM plans carry per-plan vm identities
    plans = arguments.get("plans")
    if isinstance(plans, list):
        for plan in plans:
            if isinstance(plan, dict):
                for key in ("vm_name", "vm_id"):
                    v = plan.get(key)
                    if isinstance(v, str) and v.strip():
                        ids.add(v.strip().casefold())
                        if key == "vm_name":
                            raw_names.append(v.strip())
    # Expand each caller-supplied name with its hint-resolved GUID (the
    # console ledger's identity map); a GUID learned later still matches the
    # run's stored name spelling through _Run.covers' own expansion below.
    try:
        from . import console as _console

        for name in raw_names:
            hint = _console._NAME_GUID_HINTS.get(name.casefold())
            if hint:
                ids.add(hint)
    except Exception:  # noqa: BLE001 — identity hints are best-effort; the
        pass           # literal spellings still apply
    return ids


def has_open_run(agent: str | None, vm_ids: set[str]) -> bool:
    with _RUNS_LOCK:
        active = [r for r in _RUNS.values() if r.state == "open"]
    return any(r.covers(agent, vm_ids) for r in active)


def current_agent() -> str | None:
    # Late import to avoid a cycle at module load; auditlog has no dependency
    # on evidencejournal.
    from . import auditlog

    return auditlog.current_agent_id()


# ---- argument/result sanitization ------------------------------------------

def _sanitize_args(obj: Any, secrets: list[str]) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if kl in _ECHO_ONLY_KEYS and isinstance(v, str):
                # key name slots (review F-007): content is echoed only via
                # {x!r} in validation errors, so the token is collected for
                # repr-form-only scrubbing; exact replacement of a short key
                # name (e.g. "a") would rewrite every occurrence in
                # unrelated result metadata.
                if v:
                    secrets.append(_QUOTED_MARK + v)
                out[k] = len(v)
            elif kl in _ECHO_ONLY_KEYS and isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and item:
                        secrets.append(_QUOTED_MARK + item)
                out[k] = len(v)
            elif kl in _SENSITIVE_KEYS and isinstance(v, str):
                if v:
                    secrets.append(v)
                out[k] = len(v)
            elif kl in _SENSITIVE_KEYS and isinstance(v, list):
                # scancodes / keys lists: record count, not contents. The
                # elements are collected for QUOTED-FORM-ONLY scrubbing
                # (review F-007 round-2): a validation error echoes an
                # invalid element via repr ("unknown key 'x'"), so scrubbing
                # the quoted 'x' form closes that leak without the global
                # exact-replace corrupting unrelated result metadata (a
                # bare "a" in the scrub set would rewrite every 'a' in
                # hashes, ids and error text).
                for item in v:
                    if isinstance(item, str) and item:
                        secrets.append(_QUOTED_MARK + item)
                out[k] = len(v)
            elif kl in _NEVER_KEYS:
                # length-only AND collected for result scrubbing (review
                # F-007): an echoed credential value must not survive in the
                # serialized result.
                if isinstance(v, str) and v:
                    secrets.append(v)
                out[k] = len(v) if isinstance(v, str) else 0
            else:
                out[k] = _sanitize_args(v, secrets)
        return out
    if isinstance(obj, list):
        return [_sanitize_args(v, secrets) for v in obj]
    if isinstance(obj, str) and len(obj) > _MAX_ARG_STR:
        return obj[:_MAX_ARG_STR] + "..."
    return obj


def _scrub_text(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s.startswith(_QUOTED_MARK):
            # echo-only token (sensitive key/keys/modifiers values and
            # sensitive list elements, review F-007): scrub the repr form
            # the validation errors actually emit ({x!r}) — repr() covers
            # escaping (backslash/newline) and both quote styles — never
            # the bare substring (would corrupt unrelated metadata such as
            # hashes and identifiers).
            t = s[len(_QUOTED_MARK):]
            text = text.replace(repr(t), f"<{len(t)} chars>")
        elif s:
            text = text.replace(s, f"<{len(s)} chars>")
    return text


def _sanitize_result_keys(obj: Any, *, top: bool = True) -> Any:
    """Result-side echo-slot redaction (review F-007 round-5, scoped rounds
    7-8): ONLY the TOP-LEVEL echo-only key slots (key/keys/modifiers) of the
    normalized result collapse — the only place a tool legitimately echoes
    back an input slot (e.g. the heartbeat result's "key"). Two deliberate
    narrowings from review: (1) content-sensitive keys (text/value/script/
    ...) are NEVER key-guessed on the result side — result fields under
    those names carry legitimate COMPUTED data (hyperv_cdp_eval returns its
    evaluation result as "value"; round-6's collapse-to-0 falsified real
    journal data), and the ARGUMENT side already enforces the typed-text
    content contract; (2) the redaction is NOT recursive — a nested dict is
    computed data (a CDP evaluation can legitimately return {"key": "abc"}),
    so key-name redaction inside it would corrupt results (round-8)."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if top and kl in _ECHO_ONLY_KEYS:
                # str/list echoes collapse (input slots); any other type is
                # passed through unchanged — a fabricated 0 would falsify
                # computed result data (review F-007 round-6 finding).
                out[k] = (len(v) if isinstance(v, str) else
                          (len(v) if isinstance(v, list) else v))
            else:
                out[k] = _sanitize_result_keys(v, top=False)
        return out
    if isinstance(obj, list):
        return [_sanitize_result_keys(v, top=False) for v in obj]
    return obj


def _scrub_result(obj: Any, secrets: list[str]) -> Any:
    if isinstance(obj, dict):
        return {k: _scrub_result(v, secrets) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub_result(v, secrets) for v in obj]
    if isinstance(obj, str):
        return _scrub_text(obj, secrets)
    return obj


def _normalize_result(result: Any) -> dict | None:
    """Best-effort: turn a CallToolResult (or a raw dict) into the logical
    envelope dict the journal records (C1 asserts result.ok)."""
    if isinstance(result, dict):
        return result
    content = getattr(result, "content", result)
    if not isinstance(content, list):
        return None
    for part in content:
        if getattr(part, "type", "") == "text":
            try:
                parsed = json.loads(part.text)
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


# ---- capture seam ----------------------------------------------------------

def _capture_frame(run: _Run, token: JournalToken, role: str) -> None:
    if _screenshot is None:
        return
    with run.lock:
        seq = run.seq
        run.seq += 1
    fname = f"{seq:06d}-{token.call_id}-{role}.png"
    save_path = run.frames_dir / fname
    try:
        meta = _screenshot(
            _get_config(), vm_name=token.vm_name, vm_id=token.vm_id,
            save_path=str(save_path), width=token.width, height=token.height,
        ) or {}
        h = meta.get("frame_hash")
        sp = meta.get("saved_path") or (str(save_path) if save_path.is_file() else None)
        if h and _HEX64.fullmatch(str(h)):
            if role == "pre":
                token.pre_frame_hash = h
                token.pre_frame_path = sp
            else:
                token.post_frame_hash = h
                token.post_frame_path = sp
            if sp:
                with run.lock:
                    run.frames.append((seq, role, token.tool, Path(sp)))
    except Exception:  # noqa: BLE001 — a capture hiccup must never fail the call
        return


# ---- per-call journal token ------------------------------------------------

class JournalToken:
    """One mutating call's journal state; finalized exactly once."""

    def __init__(self, run: _Run, tool: str, arguments: dict,
                 agent: str | None) -> None:
        self.run = run
        self.tool = tool
        self.agent = agent
        self.call_id = uuid.uuid4().hex[:8]
        self.dispatched = False
        self.finished = False
        # Review R2-F2: the inflight slot is reserved at BIND time (atomically
        # with run selection), not at arm time — otherwise stop can drain and
        # manifest during the bind->arm window while this token still writes.
        self.counted = False
        # True once the detached runner (or the tasks route) owns the token's
        # resolution: the inline guard's finally must NOT resolve it, or a
        # detached call would journal twice (once the divert handle, once the
        # real result). exactly-once is guarded by `finished` regardless.
        self.handed_off = False
        self.result: dict | None = None
        self.secrets: list[str] = []
        self.arguments = _sanitize_args(arguments or {}, self.secrets)
        self.pre_frame_hash: str | None = None
        self.pre_frame_path: str | None = None
        self.post_frame_hash: str | None = None
        self.post_frame_path: str | None = None
        self.width = int((arguments or {}).get("width") or 1024)
        self.height = int((arguments or {}).get("height") or 768)
        vn = (arguments or {}).get("vm_name")
        vi = (arguments or {}).get("vm_id")
        self.vm_name = vn if isinstance(vn, str) else ""
        self.vm_id = vi if isinstance(vi, str) else ""
        self.t_start = time.monotonic()

    def arm_pre(self) -> None:
        """Called immediately before the body dispatches input: capture the
        pre-frame. The inflight slot was already reserved at bind() time
        (R2-F2); never increment here or the counter double-counts."""
        if self.dispatched or self.finished:
            return
        with self.run.lock:
            if self.run.state != "open":
                return
            self.dispatched = True
        _capture_frame(self.run, self, "pre")

    def finish(self, result: Any = None, *, outcome: str = "body") -> None:
        """Append the single journal line and close the token. ``outcome`` is
        informational (body / refusal / reattach / cancel / exception)."""
        if self.finished:
            return
        self.finished = True
        run = self.run
        if self.result is None:
            self.result = _normalize_result(result)
        if self.dispatched:
            _capture_frame(run, self, "post")
        # Decrement inflight ONLY after the journal append (below): the stop
        # drain waits for this counter, so decrementing early lets stop
        # manifest a run before its final journal line exists (review F2).
        ts_mono = time.monotonic() - run.started_at
        line = {
            "seq": self._seq_stamp(run),
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "ts_monotonic": ts_mono,
            "run_id": run.run_id,
            "tool": self.tool,
            "vm_name": self.vm_name,
            "category": "journal",
            "dispatched": self.dispatched,
            "outcome": outcome,
            "arguments": self.arguments,
            "result": _scrub_result(
                _sanitize_result_keys(self.result), self.secrets)
            if self.result is not None else None,
            "pre_frame_hash": self.pre_frame_hash,
            "pre_frame_path": self.pre_frame_path,
            "post_frame_hash": self.post_frame_hash,
            "post_frame_path": self.post_frame_path,
        }
        try:
            with run.lock:
                try:
                    with open(run.journal_path, "a", encoding="utf-8") as fh:
                        try:
                            payload = json.dumps(line, ensure_ascii=False,
                                                 default=str, allow_nan=False)
                        except ValueError:
                            payload = json.dumps(_json_safe(line),
                                                 ensure_ascii=False,
                                                 default=str, allow_nan=False)
                        fh.write(payload + "\n")
                finally:
                    # The counter is released ONLY after the append is done
                    # (or has definitively failed), under the same lock the
                    # stop drain reads — no manifest before the final line
                    # (review F2).
                    if self.counted:
                        run.inflight -= 1
                        self.counted = False
        except OSError:
            pass

    def _seq_stamp(self, run: _Run) -> int:
        with run.lock:
            return run.seq


# ---- lifecycle: begin / finish from the server hooks -----------------------

def begin(tool: str, arguments: dict, *, agent: str | None = None) -> JournalToken | None:
    """Create a journal token for a mutating call when a run covers it.

    Returns None (=> every hook below is a no-op) when no run is open for the
    (agent, vm) or the tool is not mutating. The token is bound BEFORE the body
    so every terminal outcome — body, refusal, replay, reattach, cancellation —
    resolves exactly one line.
    """
    if not _is_mutating(tool):
        return None
    vm_ids = _vm_ids_from_arguments(arguments or {})
    ag = agent if agent is not None else current_agent()
    with _RUNS_LOCK:
        run = next((r for r in _RUNS.values()
                    if r.state == "open" and r.covers(ag, vm_ids)), None)
        if run is None:
            return None
        token = JournalToken(run, tool, arguments or {}, ag)
        # Reserve the inflight slot AT BIND time, under the same global lock
        # stop uses to close admission (R2-F2). Stop can no longer observe
        # inflight==0 while a bound token has yet to append its line.
        with run.lock:
            if run.state != "open":
                return None
            run.inflight += 1
            token.counted = True
    return token


def has_any_open_run() -> bool:
    with _RUNS_LOCK:
        return any(r.state == "open" for r in _RUNS.values())


def finish(token: JournalToken | None, result: Any = None, *,
           outcome: str = "body") -> None:
    """Resolve a token exactly once (no-op for None or an already-resolved
    token). The runner OWNS a handed-off token and calls this with its real
    result; the guard uses finish_if_unowned so a detached call is never
    journalled twice (review F1)."""
    if token is None or token.finished:
        return
    token.finish(result, outcome=outcome)


def finish_if_unowned(token: JournalToken | None, result: Any = None, *,
                      outcome: str = "body") -> None:
    """Guard-side finalizer: a handed-off token belongs to the runner."""
    if token is None or token.finished or token.handed_off:
        return
    token.finish(result, outcome=outcome)


def arm(token: JournalToken | None) -> None:
    """Mark the call as dispatching input and capture the pre-frame. A
    handed-off token is legitimately armed by its runner (review F1)."""
    if token is None or token.finished:
        return
    token.arm_pre()


def hand_off(token: JournalToken | None) -> None:
    """Give the token to a detached runner (guard's finally must not resolve)."""
    if token is not None:
        token.handed_off = True


# ---- run start / stop ------------------------------------------------------

def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def start_run(run_dir: str, vms: list[str] | None, *, agent: str | None = None,
              video: bool = False) -> dict:
    cfg = _get_config()
    if not run_dir or not str(run_dir).strip():
        return {"ok": False, "error": "run_dir is required", "error_class": "invalid"}
    # host-write gate on the run root (policy.check_host_write is enforced by
    # the console capture seam too; validate up front so start fails closed).
    from . import policy

    try:
        canonical = policy.check_host_write(cfg, run_dir)
        root = Path(str(canonical.exists_prefix_resolved or run_dir))
    except Exception as exc:  # noqa: BLE001 — classify, don't crash
        return {"ok": False, "error": f"run_dir refused: {exc}",
                "error_class": "invalid"}
    ag = agent if agent is not None else current_agent()
    # Cap check + registry insert in ONE lock hold, BEFORE any filesystem
    # creation (review F-011 round-5): a refused start creates nothing on
    # disk. A mkdir failure after admission rolls the registry entry back.
    with _RUNS_LOCK:
        open_count = sum(
            1 for r in _RUNS.values()
            if r.state in ("open", "closing", "initializing")
            and (r.agent == ag))
        if open_count >= _MAX_OPEN_RUNS:
            return {
                "ok": False,
                "error": (
                    f"too many open evidence runs ({open_count} >= "
                    f"{_MAX_OPEN_RUNS} for a single agent); stop one with "
                    "hyperv_evidence_run_stop before starting another"),
                "error_class": "invalid",
            }
        run_id = uuid.uuid4().hex
        run = _Run(run_id, root, ag, list(vms or []), bool(video))
        # "initializing" while the directories are created: begin() binds
        # only runs whose state is "open", so a concurrent mutating call in
        # this window cannot bind a run whose journal path does not exist
        # yet (review F-003-adjacent round-6: no journal loss on mkdir).
        run.state = "initializing"
        _RUNS[run_id] = run
        # (no closed-run prune needed: stop_run removes the entry when the
        # run closes, so _RUNS retains only open/closing/initializing runs,
        # which the per-agent cap above bounds)
    try:
        root.mkdir(parents=True, exist_ok=True)
        (root / "frames").mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        with _RUNS_LOCK:
            _RUNS.pop(run_id, None)
        return {"ok": False, "error": f"cannot create run dir: {exc}",
                "error_class": "invalid"}
    with _RUNS_LOCK:
        if _RUNS.get(run_id) is run:
            run.state = "open"
    return {"ok": True, "run_id": run_id, "run_dir": str(root),
            "video": bool(video)}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_safe(obj: Any) -> Any:
    """Replace non-finite floats (NaN/Inf) with None so json.dumps with
    allow_nan=False never emits invalid bare tokens (review F-010)."""
    if isinstance(obj, float):
        return obj if (obj == obj and obj not in
                       (float("inf"), float("-inf"))) else None
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def _maybe_video(run: _Run) -> dict | None:
    if not run.video:
        return None
    frames = sorted({p for _s, _r, _t, p in run.frames if p.is_file()})
    if not frames:
        return None
    import shutil
    import subprocess

    if shutil.which("ffmpeg") is None:
        return {"video": None, "note": "ffmpeg not available"}
    out = run.run_dir / "evidence.mp4"
    # Per-step action markers (issue #131): the sidecar is written AND its
    # CONTENT is passed as ffmpeg output metadata BEFORE the output filename,
    # so the assembled video actually carries the markers (review R2-F4).
    # Fixed argv entries, no shell, no pathname-as-comment placeholder.
    markers = [{"seq": s, "role": r, "tool": t, "file": p.name}
               for s, r, t, p in sorted(run.frames)]
    marker_doc = json.dumps({"markers": markers}, ensure_ascii=False)
    marker_path = run.run_dir / "markers.json"
    marker_path.write_text(marker_doc, encoding="utf-8")
    # ffmpeg OPTION ORDER (final-critic C1): -metadata is an OUTPUT option and
    # MUST come AFTER every -i input and the filter, immediately before the
    # output filename. Placing it before the first -i makes real ffmpeg
    # refuse to open the inputs ("Option metadata cannot be applied to input
    # url") — the mocked C4 could not see that.
    argv = ["ffmpeg", "-y", "-framerate", "2"]
    for p in frames:
        argv += ["-i", str(p)]
    n = len(frames)
    if n == 1:
        argv += ["-map", "0:v"]
    else:
        # setpts paces the concatenated frames at 2 fps; without it the
        # concat output has microsecond timestamps and is ~40 ms long
        # regardless of frame count (final-critic R2-C4).
        chain = ("".join(f"[{i}:v]" for i in range(n))
                 + f"concat=n={n}:v=1:a=0,setpts=N/(2*TB)[outv]")
        argv += ["-r", "2", "-filter_complex", chain, "-map", "[outv]"]
    argv += ["-metadata", f"comment=action-markers:{marker_doc}", str(out)]
    # Fixed argv, no shell, sanitized child env (the spawn-site census
    # requires the literal `env=pswindows.child_env()` call at the site —
    # a local Name or an IfExp reads as uncompliant), bounded timeout.
    # Popen + explicit tree kill on timeout (review F-008): subprocess.run's
    # timeout kills only the direct ffmpeg child; filter chains can leave
    # grandchildren writing the output file, so taskkill /T takes the tree.
    try:
        from . import pswindows

        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                env=pswindows.child_env())
    except OSError:
        return {"video": None, "note": "ffmpeg invocation failed"}
    try:
        proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        # taskkill /T /F returning 0 reports the whole tree terminated; the
        # bounded re-wait confirms the direct child exited. Every note states
        # only what was ESTABLISHED (review F-008 round-6).
        tree_dead = False
        try:
            tk = subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=10, env=pswindows.child_env())
        except (OSError, subprocess.SubprocessError):
            tk = None
        if tk is not None and tk.returncode == 0:
            try:
                proc.wait(timeout=10)
                tree_dead = True
            except subprocess.TimeoutExpired:
                tree_dead = False
        child_dead = False
        if not tree_dead:
            try:
                proc.kill()
                proc.wait(timeout=5)
                child_dead = True
            except (OSError, subprocess.SubprocessError):
                child_dead = False
        if tree_dead:
            note = "ffmpeg timed out after 120s; tree killed"
        else:
            note = ("ffmpeg timed out after 120s; tree kill FAILED"
                    + ("; direct child killed" if child_dead else
                       "; direct child kill UNVERIFIED"))
        # The out path rides the failure result for diagnostics; stop_run
        # certifies the whole run dir and discloses the untrusted video via
        # this note (review round-10: narrowing the manifest contract to a
        # partial certification is an owner decision, recorded ASK).
        return {"video": None, "note": note, "out": str(out)}
    if proc.returncode != 0:
        return {"video": None, "note": f"ffmpeg exited {proc.returncode}"}
    if not out.is_file():
        return {"video": None, "note": "ffmpeg produced no output file"}
    return {"video": str(out)}


def stop_run(run_id: str, *, agent: str | None = None) -> dict:
    with _RUNS_LOCK:
        run = _RUNS.get(run_id)
    if run is None:
        return {"ok": False, "error": f"unknown run_id {run_id!r}",
                "error_class": "invalid"}
    ag = agent if agent is not None else current_agent()
    if run.agent != ag:
        return {"ok": False, "error": f"unknown run_id {run_id!r}",
                "error_class": "invalid"}
    # Close ADMISSION atomically first (review F2): no new call may bind a
    # token after stop begins, and begin() refuses non-open runs under the
    # same _RUNS_LOCK. Then drain the calls that already bound one; their
    # finish() decrements inflight only AFTER appending its journal line.
    with _RUNS_LOCK:
        run.state = "closing"
    deadline = time.monotonic() + 5.0
    outstanding = 1
    while True:
        with run.lock:
            outstanding = run.inflight
            if outstanding <= 0:
                break
        if time.monotonic() >= deadline:
            # Never certify a final manifest while writers are outstanding:
            # a late journal line would invalidate every digest (review R2-F2
            # second finding). Leave the run open so callers can retry stop;
            # disclose the exact outstanding count.
            with _RUNS_LOCK:
                run.state = "open"  # re-arm admission; stop was not completed
            return {"ok": False,
                    "error": (f"journal drain timed out with {outstanding} "
                              "call(s) still open; retry run_stop after they "
                              "finish"),
                    "error_class": "journal_drain_timeout",
                    "retryable": True, "retry_after_ms": 1000,
                    "outstanding": outstanding}
        time.sleep(0.01)
    video = _maybe_video(run)
    # manifest: SHA-256 of every file in the run dir (including the mp4).
    # Known residual (review round-10, ASK-recorded): if ffmpeg's tree kill
    # FAILED (taskkill unsuccessful — never demonstrated on this host) a
    # surviving writer could mutate evidence.mp4 after this digest; the stop
    # result carries the honest "tree kill FAILED" note in that edge so the
    # caller knows the video lane is untrusted. Narrowing the manifest
    # contract (partial certification) needs a product decision and was NOT
    # taken unilaterally.
    entries: dict[str, str] = {}
    for p in sorted(run.run_dir.rglob("*")):
        if p.is_file():
            try:
                entries[str(p.relative_to(run.run_dir))] = _digest(p)
            except OSError:
                continue
    manifest_path = run.run_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps({"run_id": run.run_id, "entries": entries},
                   ensure_ascii=False), encoding="utf-8")
    with run.lock:
        run.state = "closed"
    with _RUNS_LOCK:
        _RUNS.pop(run_id, None)
    result = {"ok": True, "run_id": run.run_id, "manifest": str(manifest_path),
              "manifest_path": str(manifest_path), "files": len(entries)}
    if video:
        result.update(video)
    return result
