"""PRR-105 round-2 coverage: the delivered-so-far leg-failure messages are
PINNED, not merely reached — closing the reviewer's surviving-mutant probe.

The PRR-105 fix made every mid-sequence console-input failure name the leg
index and the delivered-so-far count, but the reviewer's mutation probe
showed the message texts SURVIVED mutation: no test asserted their content,
so a mutant that garbled the leg index (``{i + 1}`` -> ``{i}``) or the
delivered count kept every existing check green. This file drives REAL
failing legs on both transports — run_ps captured and stubbed to return
returncode=1 on the failing leg, and the WMI fakes failing exactly one
TypeText/TypeScancodes call — then pins the SHIPPED message fragments
character-for-character:

* remote type_text past the 100-chunk compose cap (two composed legs, leg 2
  fails) -> "leg 2/2 failed; about 51200 characters delivered by earlier
  legs: " plus the underlying transport error;
* local type_scancodes past _SCANCODES_PER_SCRIPT (two script-slice legs,
  leg 2 fails) -> the slice grammar actually shipped: "leg 2/2 failed; 1600
  of 3200 codes delivered by the earlier legs: ";
* WMI type_text with the second 512-char chunk's ReturnValue nonzero (the
  PRR-015 chunk seam driven to failure; PRR-105 round-2 R1 wrap) -> "leg
  2/2 failed; 512 of 600 characters delivered by the earlier legs: TypeText
  failed with ReturnValue=7";
* WMI type_scancodes with the second 64-code window failing -> "leg 2/3
  failed; 64 of 130 codes delivered by the earlier legs: TypeScancodes
  failed with ReturnValue=9".

A wrong-index mutant in any of those wraps now FAILS this file. NOT frozen:
a supplementary pin file; the frozen D-18 pack is untouched.
"""

from __future__ import annotations

import base64
import re
from types import SimpleNamespace

import pytest
from test_wmiconsole import (  # noqa: F401  (same-directory import, --import-mode=prepend)
    FakeWMIService,
    _install_wmi,
    _ps,
)

from hyperv_mcp import console, credentials, pswindows
from hyperv_mcp.config import Config


@pytest.fixture(autouse=True)
def _transport_gate():
    """run_ps's argv composition needs a resolved _ps_path (the same gate the
    folded-protocol pack installs before executing scripts)."""
    pswindows.init(Config(unrestricted=True))


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


class _FailingLegRunner:
    """pswindows.run_ps replacement: every call answers returncode=0 EXCEPT
    call number ``fail_at`` (1-based), which answers returncode=1 carrying
    ``stderr`` — the REAL check_result failure the leg wrappers append.
    Records every (script, stdin_b64) pair so the delivered-so-far claims are
    cross-checked against what the earlier legs actually carried."""

    def __init__(self, fail_at: int, stderr: str) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.fail_at = fail_at
        self.stderr = stderr

    def __call__(self, script, timeout_s=None, stdin_b64=None):
        self.calls.append((script, stdin_b64))
        if len(self.calls) == self.fail_at:
            return pswindows.PSResult(
                stdout="", stderr=self.stderr, returncode=1, duration_ms=0.0
            )
        return pswindows.PSResult(stdout="", returncode=0, duration_ms=0.0)


def _stdin_decoded_len(stdin_b64: str | None) -> int:
    """Characters a composed leg actually delivered: one UTF-8 base64 stdin
    line per 512-char chunk, decoded and summed."""
    assert stdin_b64, "a type_text leg carried no stdin payload"
    return sum(
        len(base64.b64decode(line).decode("utf-8"))
        for line in stdin_b64.split("\n")
        if line.strip()
    )


def _seed_codes(script: str) -> list[int]:
    """The codes one emitted scancodes script carries: the folded
    ``$chunks = @(...)`` seed line (the D-02 AC19-pinned shape)."""
    m = re.search(r"^\$chunks = @\((\d+(?:,\d+)*)\)$", script, re.M)
    assert m, "no $chunks seed array found in the emitted scancodes script"
    return [int(x) for x in m.group(1).split(",")]


def test_remote_type_text_second_leg_failure_names_delivered_chars(monkeypatch):
    """PRR-105 (round 2, R2a): 101 chunks force the 100-chunk compose cap
    into TWO remote legs; leg 2's returncode=1 must surface the shipped
    wrap — the leg index AND leg 1's delivered character count — ahead of
    the underlying transport error."""
    cfg = Config.from_dict({"hyperv": {"host": "nuc01"}, "unrestricted": True})
    # Implicit-auth remote (no HYPERV_HOST_* pair): the hop carries no
    # -Credential, deterministically independent of this process's env.
    monkeypatch.setattr(credentials, "resolve_host", lambda environ=None: None)
    n_chunks = pswindows.REMOTE_PAYLOAD_LINES_CAP + 1  # 101 -> legs 100 + 1
    text = "a" * (512 * n_chunks)
    runner = _FailingLegRunner(fail_at=2, stderr="simulated remote leg failure")
    monkeypatch.setattr(pswindows, "run_ps", runner)

    with pytest.raises(console.ConsoleError) as excinfo:
        console.type_text(cfg, "vm1", text)
    message = str(excinfo.value)

    # Two composed legs ran; leg 1 delivered its full 100-chunk payload.
    assert len(runner.calls) == 2, (
        f"expected exactly 2 composed legs, saw {len(runner.calls)}"
    )
    assert "Invoke-Command -ComputerName 'nuc01'" in runner.calls[0][0], (
        "the failing sequence did not go through the real compose_remote hop"
    )
    delivered_leg1 = _stdin_decoded_len(runner.calls[0][1])
    assert delivered_leg1 == 512 * pswindows.REMOTE_PAYLOAD_LINES_CAP, (
        f"leg 1 delivered {delivered_leg1} characters, not "
        f"{512 * pswindows.REMOTE_PAYLOAD_LINES_CAP}"
    )

    # The shipped wrap, pinned character-for-character (the 'about' hedges
    # only the final partial-chunk-free arithmetic: 100 full chunks = 51200).
    assert (
        f"leg 2/2 failed; about {delivered_leg1} characters delivered by "
        "earlier legs: " in message
    ), f"delivered-so-far wrap missing or garbled: {message!r}"
    assert "console type_text: simulated remote leg failure" in message, (
        f"the underlying leg-2 error text was not preserved: {message!r}"
    )


def test_type_scancodes_second_leg_failure_names_delivered_codes(
    monkeypatch, unrestricted_cfg
):
    """PRR-105 (round 2, R2b): 3200 codes split into two script-slice legs
    (_SCANCODES_PER_SCRIPT=1600); leg 2's returncode=1 must surface the
    SHIPPED slice grammar — leg index plus '1600 of 3200 codes delivered by
    the earlier legs' — ahead of the underlying transport error."""
    codes = [123] * 3200
    runner = _FailingLegRunner(fail_at=2, stderr="simulated scancode leg failure")
    monkeypatch.setattr(pswindows, "run_ps", runner)

    with pytest.raises(console.ConsoleError) as excinfo:
        console.type_scancodes(unrestricted_cfg, "vm1abc", codes)
    message = str(excinfo.value)

    assert len(runner.calls) == 2, (
        f"expected exactly 2 script-slice legs, saw {len(runner.calls)}"
    )
    # Leg 1's seed is exactly the first slice — the delivered count the
    # wrap reports is what leg 1 actually carried, not a derived constant.
    assert _seed_codes(runner.calls[0][0]) == codes[:1600], (
        "leg 1's seed was not the first contiguous code slice"
    )

    # The shipped slice-leg grammar, pinned character-for-character.
    assert (
        "leg 2/2 failed; 1600 of 3200 codes delivered by the earlier legs: "
        in message
    ), f"delivered-so-far wrap missing or garbled: {message!r}"
    assert "console scancodes: simulated scancode leg failure" in message, (
        f"the underlying leg-2 error text was not preserved: {message!r}"
    )


class _TypeTextSecondChunkFails(FakeWMIService):
    """First TypeText call succeeds, the SECOND returns a nonzero
    ReturnValue — the PRR-015 chunk seam of test_wmiconsole_extra's
    multichunk test, driven to failure."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.typetext_calls = 0

    def exec_method(self, obj, name, in_params):
        if name == "TypeText":
            self.methods.append(
                (obj._props["Path_"].Path, name, dict(in_params.values))
            )
            self.typetext_calls += 1
            if self.typetext_calls == 2:
                return SimpleNamespace(ReturnValue=7)
        return super().exec_method(obj, name, in_params)


def test_wmi_type_text_second_chunk_failure_names_delivered_chars(
    monkeypatch, unrestricted_cfg
):
    """PRR-105 (round 2, R2c): >512-char WMI type_text with the SECOND
    chunk's ReturnValue nonzero must surface the per-chunk wrap (round-2 R1)
    — chunk index plus delivered characters — ahead of the preserved
    underlying WMI error."""
    svc = _TypeTextSecondChunkFails(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    with pytest.raises(console.ConsoleError) as excinfo:
        console.type_text(unrestricted_cfg, "vm1", "a" * 600)
    message = str(excinfo.value)

    assert svc.typetext_calls == 2, (
        f"expected exactly 2 TypeText calls (512+88 chunks), saw "
        f"{svc.typetext_calls}"
    )
    # The wrap, pinned character-for-character: chunk 1 (512 chars)
    # succeeded before chunk 2 failed, out of 600 total.
    assert (
        "leg 2/2 failed; 512 of 600 characters delivered by the earlier "
        "legs: " in message
    ), f"delivered-so-far wrap missing or garbled: {message!r}"
    assert "TypeText failed with ReturnValue=7" in message, (
        f"the underlying WMI error text was not preserved: {message!r}"
    )
    assert stub.scripts == [], "the WMI path must not fall back to PowerShell"


class _ScanCodesSecondWindowFails(FakeWMIService):
    """First 64-code TypeScancodes window succeeds, the SECOND returns a
    nonzero ReturnValue — the multi-window WMI failure path."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.scancodes_calls = 0

    def exec_method(self, obj, name, in_params):
        if name == "TypeScancodes":
            self.methods.append(
                (obj._props["Path_"].Path, name, dict(in_params.values))
            )
            self.scancodes_calls += 1
            if self.scancodes_calls == 2:
                return SimpleNamespace(ReturnValue=9)
        return super().exec_method(obj, name, in_params)


def test_wmi_type_scancodes_second_window_failure_names_delivered_codes(
    monkeypatch, unrestricted_cfg
):
    """PRR-105 (round 2, R2d): 130 codes ride three 64-code WMI windows
    (64+64+2); the second window's nonzero ReturnValue must surface the
    SHIPPED per-window wrap — window index plus delivered code count —
    ahead of the preserved underlying WMI error."""
    svc = _ScanCodesSecondWindowFails(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)
    codes = [123] * 130

    with pytest.raises(console.ConsoleError) as excinfo:
        console.type_scancodes(unrestricted_cfg, "vm1", codes)
    message = str(excinfo.value)

    assert svc.scancodes_calls == 2, (
        f"expected exactly 2 TypeScancodes calls, saw {svc.scancodes_calls}"
    )
    # Window 1 delivered exactly the first 64 codes before window 2 failed.
    assert svc.methods[0][2]["ScanCodes"] == codes[:64], (
        "window 1 did not carry the first 64-code slice"
    )

    # The shipped wrap, pinned character-for-character.
    assert (
        "leg 2/3 failed; 64 of 130 codes delivered by the earlier legs: "
        in message
    ), f"delivered-so-far wrap missing or garbled: {message!r}"
    assert "TypeScancodes failed with ReturnValue=9" in message, (
        f"the underlying WMI error text was not preserved: {message!r}"
    )
