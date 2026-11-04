"""Non-frozen pins for issue #83 (trace 75-76-78-81-83-84-collated): the
SEQUENCE-side input validation legs the frozen C16/C17 checks do not carry,
plus direct-path mirrors.

The frozen checks (test_d18_mouse_input_validation.py) drive the module
functions directly — string/bool coordinates and frame dims on the positional
path, bool buttons at the membership sites. run_sequence step dicts bypass
the MCP schema entirely (a plain dict list), so the same junk reaches the
composer through `_validate_sequence_steps` unless the guards run there too:
these pins prove the step-indexed ValueError fires BEFORE any spawn and
BEFORE the plan's int() coercions could launder a bool into 1/0.

Every leg drives a recording run_ps stub and asserts the spawn count never
moved, so a validation that only rejected after a PowerShell start fails
exactly like one that did not reject at all.
"""

from __future__ import annotations

from hyperv_mcp import console, pswindows


class _RecordingPS:
    """Counts spawns and serves a plausible sequence success, so a call that
    fails to reject completes cleanly instead of erroring for another
    reason (DID NOT RAISE / wrong exception / spawn-before-reject are the
    three failure modes these pins discriminate)."""

    def __init__(self) -> None:
        self.count = 0

    def __call__(self, script, **kwargs):
        self.count += 1
        return pswindows.PSResult(
            stdout="VMID=e953c649-dcab-438d-9a54-3af74a82b624\nSTEP=0 OK=1",
            returncode=0,
        )


def _classify(stub: _RecordingPS, call) -> list[str]:
    """Run one leg; return the problems (empty == the leg rejected right)."""
    before = stub.count
    raised: BaseException | None = None
    try:
        call()
    except BaseException as exc:  # noqa: BLE001 - classify, never swallow
        raised = exc
    if not isinstance(raised, ValueError):
        return [f"expected ValueError before spawn, got {raised!r}"]
    problems = []
    if "step 0:" not in str(raised):
        problems.append(f"the message is not step-indexed: {raised}")
    if stub.count != before:
        problems.append(
            f"ValueError raised but only after {stub.count - before} "
            "PowerShell spawn(s) — the invalid step reached the transport"
        )
    return problems


def test_sequence_rejects_non_integer_step_coordinates(monkeypatch, unrestricted_cfg):
    """Sequence mouse_move and click-positional steps with string/bool
    coordinates and frame dims raise a step-indexed ValueError before any
    spawn — the guards run ahead of the plan's int() coercions, so a bool
    can never arrive as 1/0 and a string can never ride the script."""
    cfg = unrestricted_cfg
    stub = _RecordingPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    legs = [
        ("mouse_move x='foo'",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "mouse_move", "x": "foo", "y": 5}], timeout_s=30)),
        ("mouse_move y=True",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "mouse_move", "x": 5, "y": True}], timeout_s=30)),
        ("mouse_move frame_width=True",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "mouse_move", "x": 5, "y": 5,
              "frame_width": True, "frame_height": 240}], timeout_s=30)),
        ("mouse_move frame_height='3'",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "mouse_move", "x": 5, "y": 5,
              "frame_width": 320, "frame_height": "3"}], timeout_s=30)),
        ("click x='foo'",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "click", "x": "foo", "y": 10}], timeout_s=30)),
        ("click frame_height='0x10'",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "click", "x": 10, "y": 10,
              "frame_width": 320, "frame_height": "0x10"}], timeout_s=30)),
        ("click frame_width=True",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "click", "x": 10, "y": 10,
              "frame_width": True, "frame_height": 240}], timeout_s=30)),
    ]
    problems: list[str] = []
    for name, call in legs:
        for problem in _classify(stub, call):
            problems.append(f"{name}: {problem}")
    assert problems == [], (
        "sequence legs that failed to reject pre-spawn:\n  "
        + "\n  ".join(problems)
    )


def test_sequence_rejects_bool_buttons_at_every_step_site(monkeypatch, unrestricted_cfg):
    """Sequence mouse_button, click-positional and click-at-current-position
    steps with button=True/False raise a step-indexed ValueError whose
    message names the bool, before any spawn."""
    cfg = unrestricted_cfg
    stub = _RecordingPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    legs = [
        ("mouse_button button=True",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "mouse_button", "button": True, "is_down": True}],
             timeout_s=30)),
        ("mouse_button button=False",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "mouse_button", "button": False, "is_down": False}],
             timeout_s=30)),
        ("click(positional) button=True",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "click", "x": 10, "y": 10, "button": True}],
             timeout_s=30)),
        ("click(current) button=False",
         lambda: console.run_sequence(cfg, "vm1", steps=[
             {"action": "click", "button": False}], timeout_s=30)),
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
            problems.append(f"{name}: expected ValueError before spawn, got {raised!r}")
            continue
        if "bool" not in str(raised).lower():
            problems.append(
                f"{name}: ValueError raised but the message ({raised}) does not "
                "name the bool rejection"
            )
        if "step 0:" not in str(raised):
            problems.append(f"{name}: the message is not step-indexed: {raised}")
        if stub.count != before:
            problems.append(
                f"{name}: ValueError raised but only after {stub.count - before} "
                "PowerShell spawn(s) — the bool reached the transport"
            )
    assert problems == [], (
        "sequence legs that failed to reject bools pre-spawn:\n  "
        + "\n  ".join(problems)
    )


def test_sequence_step_index_names_the_offending_step(monkeypatch, unrestricted_cfg):
    """The step-indexed message names THE offending step, not always step 0:
    a valid first step followed by an invalid second must report step 1."""
    cfg = unrestricted_cfg
    stub = _RecordingPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    try:
        console.run_sequence(cfg, "vm1", steps=[
            {"action": "mouse_move", "x": 5, "y": 5},
            {"action": "mouse_move", "x": "foo", "y": 5},
        ], timeout_s=30)
    except ValueError as exc:
        assert "step 1:" in str(exc), (
            f"the invalid SECOND step must be named by its index: {exc}"
        )
    else:
        raise AssertionError("the invalid second step was accepted")
    assert stub.count == 0, "validation must reject the plan before any spawn"


def test_direct_positional_path_mirrors_the_frozen_legs(monkeypatch, unrestricted_cfg):
    """Direct-path mirrors of the frozen C16/C17 legs (mouse_move/click with
    string/bool coords and dims, bool buttons on both click forms and
    mouse_button): ValueError before any spawn, message naming the bool where
    a bool was supplied."""
    cfg = unrestricted_cfg
    stub = _RecordingPS()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    legs = [
        ("mouse_move x='foo'", False,
         lambda: console.mouse_move(cfg, "vm1", x="foo", y=5)),
        ("click x='foo'", False,
         lambda: console.click(cfg, "vm1", x="foo", y=10)),
        ("mouse_move y=True", True,
         lambda: console.mouse_move(cfg, "vm1", x=5, y=True)),
        ("mouse_move frame_width=True", True,
         lambda: console.mouse_move(cfg, "vm1", 10, 10, frame_width=True, frame_height=240)),
        ("mouse_move frame_width='3'", False,
         lambda: console.mouse_move(cfg, "vm1", 10, 10, frame_width="3", frame_height=240)),
        ("click frame_height='0x10'", False,
         lambda: console.click(cfg, "vm1", 10, 10, frame_width=320, frame_height="0x10")),
        ("mouse_button button=True", True,
         lambda: console.mouse_button(cfg, "vm1", button=True, is_down=True)),
        ("mouse_button button=False", True,
         lambda: console.mouse_button(cfg, "vm1", button=False, is_down=False)),
        ("click(no coords) button=True", True,
         lambda: console.click(cfg, "vm1", button=True)),
        ("click(no coords) button=False", True,
         lambda: console.click(cfg, "vm1", button=False)),
    ]
    problems: list[str] = []
    for name, expects_bool_mention, call in legs:
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
        if expects_bool_mention and "bool" not in str(raised).lower():
            problems.append(
                f"{name}: ValueError raised but the message ({raised}) does not "
                "name the bool rejection"
            )
        if stub.count != before:
            problems.append(
                f"{name}: ValueError raised but only after {stub.count - before} "
                "PowerShell spawn(s) — the invalid input reached the transport"
            )
    assert problems == [], (
        "direct-path legs that failed to reject pre-spawn:\n  "
        + "\n  ".join(problems)
    )
