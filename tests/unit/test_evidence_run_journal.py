"""Issue #131 acceptance checks: the evidence run journal.

RED at base, GREEN after the fix. Five checks, one per acceptance criterion:
  AC1 test_mutating_calls_are_journaled  — one JSONL line per mutating call
      (raw result, pre/post frame hashes, saved frame paths, timestamps).
  AC2 test_typed_text_is_not_journaled   — typed text recorded as its LENGTH,
      never the text (console 'text', ui 'value', guest 'script'/'command').
  AC3 test_stop_writes_matching_manifest — stop writes a manifest whose
      SHA-256 entries match every file in the run directory.
  AC4 test_optional_video_assembly       — where ffmpeg is available and video
      output is requested, stop assembles the frames into an MP4 (the ffmpeg
      spawn is intercepted at the subprocess module; nothing real runs).
  AC5 test_no_run_no_change              — with no run open, tools behave
      exactly as before (PRESERVING floor).

Surface reconciliation (the issue leaves these free; the observables here
are the contract): the journal is discovered by scanning run_dir for
JSON-lines files whose records carry a tool-name field; the manifest is the
non-journal file under run_dir whose parsed document carries >= 2 distinct
64-hex digests (or is referenced by run_stop's payload); video output is
requested with video=true on run_start.

What is faked: every PowerShell leg. Conftest pins the folded console
transport (COM_AVAILABLE False); pswindows.run_ps is stubbed after the
adaptive FakePS pattern in tests/unit/test_console.py (by-name resolution
-> stable per-name GUID; folded captures -> the frozen VMID/HEAD/SIZES/USED
protocol; input legs -> the RC/CHUNK protocol). The ffmpeg availability
probe (shutil.which) and the spawn itself (subprocess.run/check_output/
Popen) are intercepted, so no real process ever runs. The ledger is reset
around every test (src/hyperv_mcp/console.py reset_input_ledger).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import console, pswindows

HEX64 = re.compile(r"[0-9a-f]{64}")
_GUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _guid_for(name: str) -> str:
    """Stable per-name GUID: distinct names are distinct VMs."""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, name))


def _vm_name_in(script: str) -> str:
    """The VM name an action script's embedded resolver carries (by-name
    console scripts embed the resolver — the name literal, not a GUID)."""
    m = re.search(r"ElementName -eq '([^']*)'", script)
    return m.group(1) if m else ""


class JournalPS:
    """Adaptive run_ps stub: serves the legs the console tools run against a
    fake VM — by-name resolution, folded captures (so pre/post frames hash
    and save for real), display info, and input legs."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=_guid_for(_vm_name_in(script)),
                                      returncode=0)
        if "GetVirtualSystemThumbnailImage" in script:
            w = h = 0
            # CHECK_WRONG (implementation review): the folded capture script
            # emits `$sizes = @(,(W,H))` (a single-element array holding a
            # tuple). The old regex only matched the historic `@((W,H))`
            # spelling, so w=h=0 and the 4-byte payload made the real capture
            # fail with "thumbnail payload length mismatch" — no frames were
            # ever saved and the journal AC could not be satisfied. Tolerate
            # both spellings; the real script is the authority.
            m = re.search(r"\$sizes = @\(\s*,?\s*\(?\s*(\d+)\s*,\s*(\d+)", script)
            if m:
                w, h = int(m.group(1)), int(m.group(2))
            guid = ""
            m = _GUID_RE.search(script)
            if m:
                guid = m.group(0)
            else:
                name = _vm_name_in(script)
                guid = _guid_for(name) if name else _guid_for("vm1")
            payload = b"\x00\x00\x00\x00" + b"\x00\x00" * (w * h)
            body = json.dumps({
                "returnValue": 0,
                "imageDataB64": base64.b64encode(payload).decode(),
            })
            return pswindows.PSResult(
                stdout="VMID=" + guid
                       + "\nHEAD=1024x768\nSIZES=" + str(w) + "x" + str(h)
                       + "\nUSED=" + str(w) + "x" + str(h) + "\n" + body,
                returncode=0)
        if "EnabledState" in script:
            name = _vm_name_in(script)
            guid = _guid_for(name) if name else _guid_for("vm1")
            body = json.dumps({
                "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
                "keyboard_present": True, "keyboard_enabled": 2,
                "mouse_present": True, "mouse_enabled": 2,
            })
            return pswindows.PSResult(
                stdout="VMID=" + guid + "\n" + body, returncode=0)
        if "Msvm_VideoHead" in script:
            return pswindows.PSResult(
                stdout='{"horizontal": 1024, "vertical": 768}', returncode=0)
        if "RC=" in script or "CHUNK" in script or "TypeText" in script:
            return pswindows.PSResult(stdout="RC=1 CHUNK=1/1", returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)


@pytest.fixture(autouse=True)
def _clean_console_state(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)
    console.reset_input_ledger()
    yield
    console.reset_input_ledger()


def _boot(tmp_path: Path):
    cfg_file = tmp_path / "journal-cfg.json"
    cfg_file.write_text(json.dumps({
        "unrestricted": True,
        "audit_log_path": str(tmp_path / "audit.jsonl"),
    }), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_file)})
    return mod


def _call(mcp, tool: str, args: dict) -> dict:
    """Drive a registered tool through call_tool; parse the first text
    block's envelope (the shape every tool returns)."""
    result = asyncio.run(mcp.call_tool(tool, args))
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {tool}"
    return json.loads(texts[0].text)


def _best_effort_stop(mcp, run_id) -> None:
    """Close the run through the public lifecycle even when an assert below
    is about to fail, so no open run leaks into the next test."""
    if not run_id:
        return
    try:
        _call(mcp, "hyperv_evidence_run_stop", {"run_id": run_id})
    except Exception:
        pass


def _flatten(obj, prefix: str = ""):
    """Yield (key, value) for every nested dict/list slot."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k), v
            yield from _flatten(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _flatten(v)


def _tool_name_of(record: dict) -> str | None:
    for k, v in record.items():
        if k.lower() in ("tool", "tool_name") and isinstance(v, str):
            return v
    return None


def _journal_records(run_dir: Path) -> list[tuple[Path, dict]]:
    """Every parsed JSON-lines record under run_dir whose dicts carry a
    tool-name field — the journal, discovered from the filesystem rather
    than a pinned filename."""
    found: list[tuple[Path, dict]] = []
    if not run_dir.exists():
        return found
    for p in sorted(run_dir.rglob("*")):
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            continue
        try:
            parsed = [json.loads(ln) for ln in lines]
        except json.JSONDecodeError:
            continue
        if not all(isinstance(r, dict) for r in parsed):
            continue
        if any(_tool_name_of(r) is not None for r in parsed):
            found.extend((p, r) for r in parsed)
    return found


def _sub_dict(record: dict, needle: str) -> dict | None:
    """The first dict-valued (or JSON-string) field whose key contains the
    needle — arguments/results ride under such keys."""
    for k, v in record.items():
        if needle in k.lower() and isinstance(v, dict):
            return v
    for k, v in record.items():
        if needle in k.lower() and isinstance(v, str):
            try:
                parsed = json.loads(v)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


def _hash_for(record: dict, needle: str) -> str | None:
    """A 64-hex value under a key carrying the needle (pre/post frame
    hashes), at any nesting depth."""
    for k, v in _flatten(record):
        if needle in k.lower() and isinstance(v, str) and HEX64.fullmatch(v):
            return v
    return None


def _paths_under(record: dict, run_dir: Path) -> set[Path]:
    """Existing file paths inside run_dir referenced by the record, at any
    nesting depth (saved frame paths)."""
    root = run_dir.resolve()
    out: set[Path] = set()
    for _k, v in _flatten(record):
        if not isinstance(v, str) or "\n" in v or len(v) > 500:
            continue
        for cand in (Path(v), run_dir / v):
            try:
                resolved = cand.resolve()
            except OSError:
                continue
            if resolved != root and root in resolved.parents and resolved.is_file():
                out.add(resolved)
                break
    return out


def _digest_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _find_manifest(run_dir: Path, stop_payload: dict):
    """The manifest: a non-journal file under run_dir whose parsed document
    (or per-line rows) carry >= 2 distinct 64-hex digests — preferring a
    path the stop payload references. Extension-free by design."""
    journal_paths = {p for p, _r in _journal_records(run_dir)}
    candidates: list[Path] = []
    for _k, v in _flatten(stop_payload):
        if isinstance(v, str):
            for cand in (Path(v), run_dir / v):
                if cand.is_file():
                    candidates.append(cand)
                    break
    candidates += sorted(p for p in run_dir.rglob("*") if p.is_file())
    for p in candidates:
        if p in journal_paths:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        doc = None
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            rows = []
            ok = True
            for ln in text.splitlines():
                if not ln.strip():
                    continue
                try:
                    rows.append(json.loads(ln))
                except json.JSONDecodeError:
                    ok = False
                    break
            if ok and rows and all(isinstance(r, dict) for r in rows):
                doc = {"entries": rows}
        if not isinstance(doc, dict):
            continue
        digests = {v for _k, v in _flatten(doc)
                   if isinstance(v, str) and HEX64.fullmatch(v)}
        if len(digests) >= 2:
            return p, doc
    return None, None


# ---------------------------------------------------------------------------
# AC1 — one journal line per mutating call, with result and pre/post hashes
# ---------------------------------------------------------------------------

def test_mutating_calls_are_journaled(tmp_path, monkeypatch):
    """AC1: while a run is open, each mutating tool call (the console input
    tools carry a lease scope in TOOL_SCOPES — the authoritative mutating
    map) appends exactly one journal line with its raw result, pre and post
    frame hashes, saved frame paths and timestamps.

    RED at base: hyperv_evidence_run_start does not exist, so the call_tool
    raises before anything is journaled."""
    mod = _boot(tmp_path)
    try:
        stub = JournalPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()
        run_dir = tmp_path / "evidence-run"
        start = _call(mcp, "hyperv_evidence_run_start",
                      {"run_dir": str(run_dir), "vms": ["vm1"]})
        assert start.get("ok") is True, (
            "AC1: hyperv_evidence_run_start must succeed and open the run "
            f"(envelope: {json.dumps(start)[:300]})")
        run_id = start.get("run_id")
        assert run_id, "AC1: run_start must return a run_id"

        pressed = _call(mcp, "hyperv_console_press_key",
                        {"vm_name": "vm1", "key": "enter"})
        assert pressed.get("ok") is True, (
            "AC1: the journaled mutating call itself must succeed against "
            "the fake transport")

        stopped = _call(mcp, "hyperv_evidence_run_stop", {"run_id": run_id})
        assert stopped.get("ok") is True, (
            "AC1: hyperv_evidence_run_stop must close the run "
            f"(envelope: {json.dumps(stopped)[:300]})")

        records = _journal_records(run_dir)
        assert records, "AC1: the stopped run directory holds no journal"
        line = next((r for _p, r in records
                     if _tool_name_of(r) == "hyperv_console_press_key"), None)
        assert line is not None, (
            "AC1: no journal line records the mutating press_key call; "
            f"journal tools seen: {sorted({_tool_name_of(r) for _p, r in records})}")

        # the raw result of the call is recorded
        result_part = _sub_dict(line, "result")
        assert result_part is not None, "AC1: the journal line records no result"
        assert result_part.get("ok") is True, (
            f"AC1: the journaled raw result must be the call's (got {result_part})")

        # pre and post frame hashes, 64-hex, around the call
        pre = _hash_for(line, "pre")
        post = _hash_for(line, "post")
        assert pre is not None, "AC1: no pre-frame hash (64-hex) on the journal line"
        assert post is not None, "AC1: no post-frame hash (64-hex) on the journal line"

        # frames saved as files under run_dir, referenced by the line
        frame_paths = _paths_under(line, run_dir)
        assert len(frame_paths) >= 2, (
            "AC1: the journal line must reference the pre and post frames as "
            f"saved files under run_dir (found {len(frame_paths)})")

        # timestamps on the line
        stamps = [
            v for k, v in _flatten(line)
            if ("ts" in k.lower() or "time" in k.lower()
                or k.lower().endswith("_at"))
            and isinstance(v, (int, float, str)) and v != ""
        ]
        assert stamps, "AC1: the journal line carries no timestamps"
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC2 — typed text is journaled as its length, never the text
# ---------------------------------------------------------------------------

def test_typed_text_is_not_journaled(tmp_path, monkeypatch):
    """AC2: a journaled console type_text must record the typed LENGTH and
    never the text — the journal must not become a secret store.

    RED at base: hyperv_evidence_run_start does not exist."""
    secret = "S3cr3t-Typed-Text-131"
    mod = _boot(tmp_path)
    run_id = None
    try:
        stub = JournalPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()
        run_dir = tmp_path / "evidence-run-redaction"
        start = _call(mcp, "hyperv_evidence_run_start",
                      {"run_dir": str(run_dir), "vms": ["vm1"]})
        assert start.get("ok") is True, (
            "AC2: hyperv_evidence_run_start must succeed "
            f"(envelope: {json.dumps(start)[:300]})")
        run_id = start.get("run_id")

        typed = _call(mcp, "hyperv_console_type_text",
                      {"vm_name": "vm1", "text": secret})
        assert typed.get("ok") is True, (
            "AC2: the journaled type_text call itself must succeed")

        stopped = _call(mcp, "hyperv_evidence_run_stop", {"run_id": run_id})
        assert stopped.get("ok") is True, "AC2: run_stop must close the run"
        run_id = None

        # the typed text appears in NO file of the run directory (frames and
        # journal alike) — the strongest form of the never-the-text rule
        for p in sorted(run_dir.rglob("*")):
            if p.is_file():
                assert secret.encode("utf-8") not in p.read_bytes(), (
                    f"AC2: the typed text leaked into the run directory file {p.name}")

        records = _journal_records(run_dir)
        line = next((r for _p, r in records
                     if _tool_name_of(r) == "hyperv_console_type_text"), None)
        assert line is not None, "AC2: no journal line records the type_text call"
        args_part = _sub_dict(line, "arg")
        assert args_part is not None, (
            "AC2: the journal line records no arguments for the call")
        lengths = [
            v for _k, v in _flatten(args_part)
            if isinstance(v, int) and not isinstance(v, bool) and v == len(secret)
        ]
        assert lengths, (
            "AC2: the journaled arguments must carry the typed LENGTH "
            f"({len(secret)}) in place of the text (arguments: "
            f"{json.dumps(args_part)[:300]})")
    finally:
        if run_id:
            _best_effort_stop(mod.get_mcp(), run_id)
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC3 — stop writes a manifest matching every file in the run directory
# ---------------------------------------------------------------------------

def test_stop_writes_matching_manifest(tmp_path, monkeypatch):
    """AC3: stopping the run writes a manifest whose SHA-256 entries match
    every file in the run directory — a reviewer can prove a cited receipt
    was not edited after the run.

    RED at base: hyperv_evidence_run_start does not exist."""
    mod = _boot(tmp_path)
    run_id = None
    try:
        stub = JournalPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()
        run_dir = tmp_path / "evidence-run-manifest"
        start = _call(mcp, "hyperv_evidence_run_start",
                      {"run_dir": str(run_dir), "vms": ["vm1"]})
        assert start.get("ok") is True, (
            "AC3: hyperv_evidence_run_start must succeed "
            f"(envelope: {json.dumps(start)[:300]})")
        run_id = start.get("run_id")
        for key in ("enter", "space"):
            pressed = _call(mcp, "hyperv_console_press_key",
                            {"vm_name": "vm1", "key": key})
            assert pressed.get("ok") is True, (
                f"AC3: the journaled press_key({key}) must succeed")

        stopped = _call(mcp, "hyperv_evidence_run_stop", {"run_id": run_id})
        assert stopped.get("ok") is True, "AC3: run_stop must close the run"
        run_id = None

        manifest_path, doc = _find_manifest(run_dir, stopped)
        assert manifest_path is not None, (
            "AC3: stop wrote no manifest (a non-journal file under run_dir "
            "whose entries carry SHA-256 digests)")
        files = [p for p in sorted(run_dir.rglob("*"))
                 if p.is_file() and p != manifest_path]
        assert len(files) >= 3, (
            "AC3: the run directory must hold the journal and the saved "
            f"frames to hash (found {len(files)}: {[p.name for p in files]})")
        flat = list(_flatten(doc))
        for f in files:
            digest = _digest_of(f)
            digest_hit = any(v == digest for _k, v in flat)
            name_hit = any(
                (isinstance(v, str) and f.name in v) or f.name in k
                for k, v in flat)
            assert digest_hit, (
                f"AC3: manifest entry mismatch for {f.name} — its SHA-256 "
                "is not in the manifest")
            assert name_hit, (
                f"AC3: manifest entry mismatch for {f.name} — no entry "
                "associates the digest with the file's name")
    finally:
        if run_id:
            _best_effort_stop(mod.get_mcp(), run_id)
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC4 — optional MP4 assembly at stop, with the ffmpeg spawn intercepted
# ---------------------------------------------------------------------------

def test_optional_video_assembly(tmp_path, monkeypatch):
    """AC4: where ffmpeg is available and video output is requested, stop
    assembles the run's frames into an MP4. The availability probe and the
    spawn are intercepted (shutil.which / subprocess.run / check_output /
    Popen), so no real process runs; the assertion is on the recorded argv:
    ffmpeg, the run's frames, and an .mp4 output path.

    RED at base: hyperv_evidence_run_start does not exist."""
    mod = _boot(tmp_path)
    run_id = None
    try:
        stub = JournalPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        spawns: list[list] = []

        real_which = shutil.which

        def fake_which(cmd, path=None):
            if str(cmd).lower() == "ffmpeg":
                return r"C:\fake-bin\ffmpeg.exe"
            return real_which(cmd, path) if path is not None else real_which(cmd)

        monkeypatch.setattr(shutil, "which", fake_which)

        def fake_run(argv, *args, **kwargs):
            spawns.append(list(argv) if isinstance(argv, (list, tuple)) else [argv])
            return subprocess.CompletedProcess(argv, 0)

        class _FakePopen:
            def __init__(self, argv, *args, **kwargs):
                spawns.append(list(argv) if isinstance(argv, (list, tuple)) else [argv])
                self.returncode = 0

            def wait(self, timeout=None):
                return 0

            def communicate(self, *args, **kwargs):
                return (b"", b"")

        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setattr(subprocess, "check_output", fake_run)
        monkeypatch.setattr(subprocess, "Popen", _FakePopen)

        mcp = mod.get_mcp()
        run_dir = tmp_path / "evidence-run-video"
        start = _call(mcp, "hyperv_evidence_run_start",
                      {"run_dir": str(run_dir), "vms": ["vm1"], "video": True})
        assert start.get("ok") is True, (
            "AC4: run_start with video requested must succeed "
            f"(envelope: {json.dumps(start)[:300]})")
        run_id = start.get("run_id")

        pressed = _call(mcp, "hyperv_console_press_key",
                        {"vm_name": "vm1", "key": "enter"})
        assert pressed.get("ok") is True, "AC4: the journaled call must succeed"

        stopped = _call(mcp, "hyperv_evidence_run_stop", {"run_id": run_id})
        assert stopped.get("ok") is True, "AC4: run_stop must close the run"
        run_id = None

        frames = [p for p in run_dir.rglob("*") if p.is_file()
                  and p.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp"}]
        assert frames, "AC4: the run must save frames for the video to assemble"
        assert spawns, (
            "AC4: stop spawned nothing — with ffmpeg available and video "
            "requested it must assemble the frames into an MP4")
        argv = spawns[0]
        joined = " ".join(str(a) for a in argv)
        assert "ffmpeg" in joined.lower(), (
            f"AC4: the assembled argv must name ffmpeg (argv: {joined[:300]})")
        assert any(str(a).lower().endswith(".mp4") for a in argv), (
            f"AC4: the assembled argv must carry an .mp4 output path "
            f"(argv: {joined[:300]})")
        frame_hit = any(
            str(a) == str(f) or (isinstance(a, str) and f.name in str(a))
            for a in argv for f in frames)
        assert frame_hit, (
            f"AC4: the assembled argv must reference the run's frames "
            f"(argv: {joined[:300]}, frames: {[f.name for f in frames]})")
    finally:
        if run_id:
            _best_effort_stop(mod.get_mcp(), run_id)
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC5 — no run open: tool behavior identical (PRESERVING floor)
# ---------------------------------------------------------------------------

def test_no_run_no_change(tmp_path, monkeypatch):
    """AC5: with NO evidence run open, existing tools behave exactly as
    before: the console envelopes keep their current shape and the calls
    leave no files behind beyond the configured audit log.

    GREEN-preserving at base by design (the floor #131 must not move)."""
    mod = _boot(tmp_path)
    try:
        stub = JournalPS()
        monkeypatch.setattr(pswindows, "run_ps", stub)
        mcp = mod.get_mcp()

        def _tree() -> set[str]:
            return {str(p) for p in tmp_path.rglob("*") if p.is_file()}

        def _harness_owned(path: str) -> bool:
            """Files the harness itself owns under tmp_path: the configured
            audit log, and the conftest-redirected state store (issue #22
            points HYPERV_MCP_STATE_DB here, and every console call writes
            its vm_lock call row)."""
            name = Path(path).name
            return name == "audit.jsonl" or name.startswith("state.db")

        before = _tree()
        pressed = _call(mcp, "hyperv_console_press_key",
                        {"vm_name": "vm1", "key": "enter"})
        assert pressed.get("ok") is True and pressed.get("scancodes_sent", 0) >= 1, (
            "AC5: with no run open press_key must keep its current envelope "
            f"(got {json.dumps(pressed)[:300]})")
        info = _call(mcp, "hyperv_console_get_display_info", {"vm_name": "vm1"})
        assert info.get("ok") is True and info.get("head_horizontal") == 1024, (
            "AC5: with no run open get_display_info must keep its current "
            f"envelope (got {json.dumps(info)[:300]})")

        # no journal-shaped artifact anywhere under tmp_path
        journalish = [
            p for p in tmp_path.rglob("*")
            if p.is_file() and p.suffix.lower() in {".jsonl", ".manifest", ".mp4"}
            and p.name != "audit.jsonl"
        ]
        assert journalish == [], (
            "AC5: with no run open the calls must leave no journal, manifest "
            f"or video artifact (found {[str(p) for p in journalish]})")
        new_files = _tree() - before
        stray = sorted(p for p in new_files if not _harness_owned(p))
        assert stray == [], (
            "AC5: with no run open the calls must create no files beyond the "
            f"harness's own audit log and state store (new files: {stray})")
    finally:
        importlib.reload(server_module)
