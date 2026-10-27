"""Acceptance checks for issue #27 (Workstream F PR 3, F-03): the frame-stable wait.

An agent driving a Windows UI needs to know when the screen has SETTLED — the
animation finished, the dialog painted. ``wait_frame_change`` stops on the
first differing frame and polls in whole seconds; ``capture_sequence`` sleeps
a fixed interval. Neither answers "unchanged for N ms". This file freezes the
contract of ``console.wait_frame_stable`` and its
``hyperv_console_wait_frame_stable`` registration: a bounded, sub-second,
single-process settle wait on both transports that returns the settled frame
and its pixel-only hash, with an optional movement baseline so "my input did
nothing" (``unchanged``) is distinguishable from "already settled"
(``stable``).

RED at base ed5a35f33d42ca92b7ba393bd10fa5654a83e4a9 (neither symbol exists),
GREEN after the fix. Companion pins (max-poll derivation, WMI transport
semantics, no-vm-lock read admission) ride in the same file so the whole
contract freezes at one blob; the AC-mapped rows are C1-C5 of the trace.
"""

from __future__ import annotations

import asyncio
import base64
import importlib

import pytest
from test_console import FakePS  # same-directory import (--import-mode=prepend)

import hyperv_mcp.server as server_module
from hyperv_mcp import console, pswindows, vmlocks
from hyperv_mcp.config import Config

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
W, H = 320, 240


def _payload(pixel: int = 0x5A) -> bytes:
    return b"\x01\x02\x03\x04" + bytes([pixel]) * (W * H * 2)


def _stable_result(payload: bytes, polls: int = 6, stable_ms: int = 1501) -> pswindows.PSResult:
    body = f"STOP=stable POLLS={polls} HASH=deadbeef STABLE_MS={stable_ms}\nFRAME="
    return pswindows.PSResult(
        stdout=body + base64.b64encode(payload).decode(), returncode=0)


class _NoSpawnStub:
    """Records every run_ps attempt and refuses to serve anything: the bounds
    contract must raise ValueError BEFORE any PowerShell starts."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, script, **kwargs):
        self.calls += 1
        raise AssertionError("no PowerShell may start for a bounds violation")


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


@pytest.fixture()
def fresh_server():
    """Mirror of test_server.py's fixture: reload server, bootstrap, restore."""
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


# ---------------------------------------------------------------------------
# AC1 (C1) — a STOP=stable result returns the settled frame + its hash
# ---------------------------------------------------------------------------

def test_wait_frame_stable_returns_stable_frame(monkeypatch, unrestricted):
    payload = _payload()
    fake = FakePS([_stable_result(payload)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = {}
    try:
        out = console.wait_frame_stable(
            unrestricted, "vm1", stable_ms=1500, timeout_s=30,
            interval_ms=250, width=W, height=H,
        )
    except Exception as exc:
        out = {"_error": repr(exc)}
    assert "_error" not in out, (
        "F03-AC1-RED-AT-BASE: console.wait_frame_stable does not exist yet; "
        "a bounded settle wait that returns the settled frame and its hash "
        f"is required (call outcome: {out['_error']!r})"
    )
    assert out["stop_reason"] == "stable"
    assert out["stable"] is True
    assert out["image"].size == (W, H)
    assert out["frame_hash"] == console._frame_hash(payload), (
        "the returned frame_hash must be the pixel-only domain, byte-identical "
        "to _frame_hash, so it chains into baseline_hash like wait_frame_change"
    )


# ---------------------------------------------------------------------------
# AC2 (C2) — bounds raise ValueError before any PowerShell runs
# ---------------------------------------------------------------------------

def test_wait_frame_stable_bounds(monkeypatch, unrestricted):
    if not hasattr(console, "wait_frame_stable"):
        pytest.fail(
            "F03-AC2-RED-AT-BASE: console.wait_frame_stable does not exist "
            "yet; once it does, stable_ms<=0 / interval_ms<100 / timeout_s<1 "
            "/ stable_ms>=timeout_s*1000 must raise ValueError before any "
            "PowerShell starts"
        )
    stub = _NoSpawnStub()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    with pytest.raises(ValueError, match="stable_ms"):
        console.wait_frame_stable(unrestricted, "vm1", stable_ms=0)
    with pytest.raises(ValueError, match="interval_ms"):
        console.wait_frame_stable(unrestricted, "vm1", interval_ms=99)
    with pytest.raises(ValueError, match="timeout_s"):
        console.wait_frame_stable(unrestricted, "vm1", timeout_s=0)
    with pytest.raises(ValueError, match="stable_ms"):
        console.wait_frame_stable(unrestricted, "vm1", stable_ms=30_000, timeout_s=30)
    assert stub.calls == 0, (
        "F03-AC2-RED-AT-BASE: wait_frame_stable must not exist yet — and once "
        "it does, no bounds violation may start a PowerShell child"
    )


# ---------------------------------------------------------------------------
# companion pin — the poll cap and child deadline are derived, not literals
# ---------------------------------------------------------------------------

def test_wait_frame_stable_max_polls_derived(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(
        stdout="STOP=deadline POLLS=80 HASH=abc", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.wait_frame_stable(
        unrestricted, "vm1", timeout_s=20, interval_ms=250)
    # derived: ceil(20*1000 / 250) = 80 polls; child deadline 20 + 15
    assert fake.kwargs[-1]["timeout_s"] == 35
    assert "$polls -lt 80" in fake.scripts[-1], (
        "the poll cap must be derived from timeout_s*1000/interval_ms and "
        "embedded in the script like wait_frame_change's max_polls"
    )
    assert out["stop_reason"] == "deadline"


# ---------------------------------------------------------------------------
# AC3 (C3) — deadline: stable False, no image, bounded child
# ---------------------------------------------------------------------------

def test_wait_frame_stable_deadline_has_no_image(monkeypatch, unrestricted):
    fake = FakePS([pswindows.PSResult(
        stdout="STOP=deadline POLLS=80 HASH=abc", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = {}
    try:
        out = console.wait_frame_stable(
            unrestricted, "vm1", timeout_s=20, interval_ms=250)
    except Exception as exc:
        out = {"_error": repr(exc)}
    assert "_error" not in out, (
        "F03-AC3-RED-AT-BASE: wait_frame_stable does not exist yet; the "
        f"deadline contract (stable False, no image) is unfrozen "
        f"(call outcome: {out['_error']!r})"
    )
    assert out["stop_reason"] == "deadline"
    assert out["stable"] is False
    assert "image" not in out


# ---------------------------------------------------------------------------
# AC4 (C4) — supplied baseline never differs: unchanged, validated, embedded
# ---------------------------------------------------------------------------

def test_wait_frame_stable_baseline_never_changed(monkeypatch, unrestricted):
    baseline = "a" * 64
    fake = FakePS([pswindows.PSResult(
        stdout=f"STOP=unchanged POLLS=8 HASH={baseline}", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = {}
    try:
        out = console.wait_frame_stable(
            unrestricted, "vm1", baseline_hash=baseline,
            timeout_s=5, interval_ms=250,
        )
    except Exception as exc:
        out = {"_error": repr(exc)}
    assert "_error" not in out, (
        "F03-AC4-RED-AT-BASE: wait_frame_stable does not exist yet; the "
        f"unchanged-vs-baseline discrimination is unfrozen "
        f"(call outcome: {out['_error']!r})"
    )
    assert out["stop_reason"] == "unchanged"
    assert out["stable"] is False
    assert "image" not in out
    # the baseline is embedded in the script only after 64-hex validation
    assert baseline in fake.scripts[-1]
    with pytest.raises(ValueError, match="64-char hex"):
        console.wait_frame_stable(unrestricted, "vm1", baseline_hash="nothex")


# ---------------------------------------------------------------------------
# companion pin — WMI transport: zero spawns, stable stop, read admission
# ---------------------------------------------------------------------------

def test_wait_frame_stable_wmi_semantics(monkeypatch, unrestricted):
    from test_wmiconsole import (  # noqa: F401  same-directory import
        FakeWMIService,
        _install_wmi,
        _ps,
    )

    svc = FakeWMIService(head=(W, H))
    _install_wmi(monkeypatch, unrestricted, lambda cfg: svc)
    stub = _ps(monkeypatch)
    locked: list = []
    real_lock = vmlocks.vm_lock

    import contextlib

    @contextlib.contextmanager
    def recording_lock(key, *args, **kwargs):
        locked.append(key)
        with real_lock(key, *args, **kwargs):
            yield

    monkeypatch.setattr(vmlocks, "vm_lock", recording_lock)
    # constant frames + real 100 ms interval: poll 1 starts the quiet window,
    # poll 2's elapsed (>= interval_ms) satisfies stable_ms=1 -> stable.
    out = console.wait_frame_stable(
        unrestricted, "vm1", stable_ms=1, timeout_s=5, interval_ms=100,
        width=W, height=H,
    )
    assert stub.scripts == [], "the WMI transport must not spawn PowerShell"
    assert out["stop_reason"] == "stable" and out["stable"] is True
    assert out["timings"]["transport"] == "wmi"
    assert locked == [], "a read-only settle wait must never take the vm lock"


# ---------------------------------------------------------------------------
# AC5 (C5) — registration: params present, no confirm, read-only parity
# ---------------------------------------------------------------------------

def _schemas(mod):
    mcp = mod.get_mcp()
    tools = asyncio.run(mcp.list_tools())
    return {t.name: (getattr(t, "input_schema", None) or t.inputSchema) for t in tools}


def test_tool_registered_without_confirm(fresh_server):
    mod = fresh_server({})
    schemas = _schemas(mod)
    props = {}
    try:
        props = schemas["hyperv_console_wait_frame_stable"]["properties"]
    except KeyError as exc:
        pytest.fail(
            "F03-AC5-RED-AT-BASE: hyperv_console_wait_frame_stable is not "
            f"registered yet ({exc!r}); the settle wait must be a first-class "
            "read-only console tool"
        )
    for name in ("vm_name", "stable_ms", "timeout_s", "interval_ms",
                 "width", "height", "baseline_hash", "vm_id"):
        assert name in props, f"schema must expose {name}"
    assert "confirm" not in props, "a read-only tool never takes confirm"
    reference = schemas["hyperv_console_wait_frame_change"]["properties"]
    assert "confirm" not in reference and "confirm" not in props, (
        "the settle wait must sit beside wait_frame_change on the read-only, "
        "no-confirm surface"
    )
