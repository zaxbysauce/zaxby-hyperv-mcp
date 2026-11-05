"""Acceptance checks AC16/AC17 (issue #83): positional mouse inputs are
validated host-side before any spawn.

RED at base b1ed4f7, GREEN after the fix.

The positional mouse ops interpolate caller coordinates and frame dimensions
into the folded script with bare ``str()`` and no type check: a string
coordinate sails through as ``$x = foo`` (no error), a bool frame dim passes
the ``<= 0`` guard because ``True <= 0`` is False, and a string dim dies at
the guard with a TypeError instead of a ValueError. The button parameters
accept ``True`` at five sites because ``True in (1, 2)`` — the generated
script then reads ``ButtonIndex = True`` (02-reproduction.md Attempt 5).

Every check drives the module functions directly (bypassing the MCP layer's
own coercion) against a recording run_ps stub, so each leg proves the
rejection happens BEFORE any PowerShell spawn.
"""

from __future__ import annotations

from hyperv_mcp import console, pswindows


class _RecordingPS:
    """Counts spawns and serves a valid positional-mouse response, so a call
    that fails to reject at base completes cleanly (DID NOT RAISE / wrong
exception / spawn-before-reject are the three base failure modes)."""

    def __init__(self) -> None:
        self.count = 0

    def __call__(self, script, **kwargs):
        self.count += 1
        return pswindows.PSResult(stdout="HEADX=10\nHEADY=10\nRC=0", returncode=0)


def test_positional_mouse_rejects_non_integer_coordinates(monkeypatch, unrestricted_cfg):
    """AC16: non-integer coordinates/frame dims raise ValueError pre-spawn.

    Every leg must raise ValueError (not TypeError, not silence) and must not
    start a PowerShell process doing it. The ``y=None`` leg is the pre-existing
    PRR-014 guard (green at base); the others are the defect: base either
    interpolates the junk into the script (str coordinate, bool frame dim),
    or raises TypeError at the positivity guard (string dims), or spawns
    before raising at all."""
    cfg = unrestricted_cfg
    stub = _RecordingPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    legs = [
        ("mouse_move x='foo'",
         lambda: console.mouse_move(cfg, "vm1", x="foo", y=5)),
        ("click x='foo'",
         lambda: console.click(cfg, "vm1", x="foo", y=10)),
        ("mouse_move y=None",
         lambda: console.mouse_move(cfg, "vm1", x=5, y=None)),
        ("mouse_move frame_width=True",
         lambda: console.mouse_move(cfg, "vm1", 10, 10, frame_width=True, frame_height=240)),
        ("mouse_move frame_width='3'",
         lambda: console.mouse_move(cfg, "vm1", 10, 10, frame_width="3", frame_height=240)),
        ("click frame_height='0x10'",
         lambda: console.click(cfg, "vm1", 10, 10, frame_width=320, frame_height="0x10")),
    ]
    problems: list[str] = []
    for name, call in legs:
        before = stub.count
        raised: BaseException | None = None
        try:
            call()
        except BaseException as exc:  # noqa: BLE001 - classify, never swallow
            raised = exc
        if not isinstance(raised, ValueError):
            problems.append(
                f"{name}: expected ValueError before spawn, got {raised!r}")
        elif stub.count != before:
            problems.append(
                f"{name}: ValueError raised but only after {stub.count - before} "
                "PowerShell spawn(s) — the invalid input reached the transport")
    assert problems == [], "AC16 legs that failed to reject pre-spawn:\n  " + "\n  ".join(problems)


def test_mouse_button_rejects_bools(monkeypatch, unrestricted_cfg):
    """AC17: button=True/False are rejected like the scancode path rejects
    bools — a ValueError whose message names the reason (a bool mention),
    raised before any spawn.

    Base behavior: ``True in (1, 2)`` is True so button=True is accepted and
    the script emits ``ButtonIndex = True``; button=False does raise the
    generic ValueError but its message never names the bool. The sequence-step
    lane matters because step dicts bypass the MCP schema entirely."""
    cfg = unrestricted_cfg
    stub = _RecordingPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    legs = [
        ("mouse_button button=True",
         lambda: console.mouse_button(cfg, "vm1", button=True, is_down=True)),
        ("mouse_button button=False",
         lambda: console.mouse_button(cfg, "vm1", button=False, is_down=False)),
        ("click(no coords) button=True",
         lambda: console.click(cfg, "vm1", button=True)),
        ("click(no coords) button=False",
         lambda: console.click(cfg, "vm1", button=False)),
        ("run_sequence step mouse_button button=True",
         lambda: console.run_sequence(
             cfg, "vm1", steps=[{"action": "mouse_button", "button": True, "is_down": True}],
             timeout_s=30)),
    ]
    problems: list[str] = []
    for name, call in legs:
        before = stub.count
        raised: BaseException | None = None
        try:
            call()
        except BaseException as exc:  # noqa: BLE001 - classify, never swallow
            raised = exc
        if not isinstance(raised, ValueError):
            problems.append(
                f"{name}: expected ValueError before spawn, got {raised!r}")
            continue
        if "bool" not in str(raised).lower():
            problems.append(
                f"{name}: ValueError raised but the message ({raised}) does not "
                "name the bool rejection")
        if stub.count != before:
            problems.append(
                f"{name}: ValueError raised but only after {stub.count - before} "
                "PowerShell spawn(s) — the bool reached the transport")
    assert problems == [], "AC17 legs that failed to reject bools pre-spawn:\n  " + "\n  ".join(problems)
