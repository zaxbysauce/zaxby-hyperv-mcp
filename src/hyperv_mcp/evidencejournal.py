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
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# Argument keys whose string values are typed text / executable content: these
# are recorded by LENGTH, never verbatim (AC2), and their values are collected
# for result-scrubbing (PC10). Matched case-insensitively on the leaf key.
_SENSITIVE_KEYS = frozenset({
    "text", "value", "script", "command", "expression", "scancodes", "value_b64",
})
# Keys that carry credentials: never serialized at all (value -> length only).
_NEVER_KEYS = frozenset({"password", "username", "secret_ref", "secret", "cred"})

_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_ARG_STR = 2000  # cap on non-sensitive string fields kept verbatim

# ---- injected seams (set by server.install) --------------------------------

_get_config: Callable[[], Any] = lambda: None
_is_mutating: Callable[[str], bool] = lambda name: False
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
        self.frames: list[tuple[int, str, Path]] = []  # (seq, role, path)
        self.started_at = time.monotonic()

    def covers(self, agent: str | None, vm_ids: set[str]) -> bool:
        if self.agent != agent:
            return False
        if not self.vms:
            return True
        return bool(self.vms & vm_ids)


_RUNS: dict[str, _Run] = {}
_RUNS_LOCK = threading.Lock()


def reset_for_tests() -> None:
    """Drop all runs (test isolation). Not for production use."""
    with _RUNS_LOCK:
        _RUNS.clear()


def _vm_ids_from_arguments(arguments: dict) -> set[str]:
    ids: set[str] = set()
    for key in ("vm_name", "vm_id"):
        v = arguments.get(key)
        if isinstance(v, str) and v.strip():
            ids.add(v.strip().casefold())
    # multi-VM plans carry per-plan vm identities
    plans = arguments.get("plans")
    if isinstance(plans, list):
        for plan in plans:
            if isinstance(plan, dict):
                for key in ("vm_name", "vm_id"):
                    v = plan.get(key)
                    if isinstance(v, str) and v.strip():
                        ids.add(v.strip().casefold())
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
            if kl in _SENSITIVE_KEYS and isinstance(v, str):
                if v:
                    secrets.append(v)
                out[k] = len(v)
            elif kl in _SENSITIVE_KEYS and isinstance(v, list):
                # scancodes / keys lists: record count, not contents
                out[k] = len(v)
            elif kl in _NEVER_KEYS:
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
        if s:
            text = text.replace(s, f"<{len(s)} chars>")
    return text


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

def _capture_frame(run: _Run, token: "JournalToken", role: str) -> None:
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
            "result": _scrub_result(self.result, self.secrets)
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
                        fh.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")
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


def finish(token: "JournalToken | None", result: Any = None, *,
           outcome: str = "body") -> None:
    """Resolve a token exactly once (no-op for None or an already-resolved
    token). The runner OWNS a handed-off token and calls this with its real
    result; the guard uses finish_if_unowned so a detached call is never
    journalled twice (review F1)."""
    if token is None or token.finished:
        return
    token.finish(result, outcome=outcome)


def finish_if_unowned(token: "JournalToken | None", result: Any = None, *,
                      outcome: str = "body") -> None:
    """Guard-side finalizer: a handed-off token belongs to the runner."""
    if token is None or token.finished or token.handed_off:
        return
    token.finish(result, outcome=outcome)


def arm(token: "JournalToken | None") -> None:
    """Mark the call as dispatching input and capture the pre-frame. A
    handed-off token is legitimately armed by its runner (review F1)."""
    if token is None or token.finished:
        return
    token.arm_pre()


def hand_off(token: "JournalToken | None") -> None:
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
    try:
        root.mkdir(parents=True, exist_ok=True)
        (root / "frames").mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": f"cannot create run dir: {exc}",
                "error_class": "invalid"}
    run_id = uuid.uuid4().hex
    ag = agent if agent is not None else current_agent()
    run = _Run(run_id, root, ag, list(vms or []), bool(video))
    with _RUNS_LOCK:
        _RUNS[run_id] = run
    return {"ok": True, "run_id": run_id, "run_dir": str(root),
            "video": bool(video)}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    argv = ["ffmpeg", "-y", "-framerate", "2",
            "-metadata", f"comment=action-markers:{marker_doc}"]
    for p in frames:
        argv += ["-i", str(p)]
    n = len(frames)
    if n == 1:
        argv += ["-map", "0:v", str(out)]
    else:
        chain = "".join(f"[{i}:v]" for i in range(n)) + f"concat=n={n}:v=1:a=0[outv]"
        argv += ["-filter_complex", chain, "-map", "[outv]", str(out)]
    try:
        from . import pswindows

        # Fixed argv, no shell, sanitized child env (the spawn-site census
        # requires the literal `env=pswindows.child_env()` call at the site —
        # a local Name or an IfExp reads as uncompliant), bounded timeout.
        subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=120, check=False, env=pswindows.child_env())
    except (OSError, subprocess.SubprocessError):
        return {"video": None, "note": "ffmpeg invocation failed"}
    return {"video": str(out) if out.is_file() else None}


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
