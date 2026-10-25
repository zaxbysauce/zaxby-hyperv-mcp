"""Frozen acceptance checks for issue #25 (trace 25-f1): the console
keyboard covers the Windows key, punctuation and the numpad, and a click at
(0,0) is a real coordinate.

Discriminating checks AC1-AC7 live here; each is RED at base (names
unknown / origin sentinel / schema default 0 / description under-advertises)
and GREEN after the fix. The preserving halves AC8-AC11 live in
tests/unit/test_console.py (AC8 is the rewritten no-coordinates test there)
and stay GREEN throughout. AC12 ships as the integration test
test_console_windows_key_opens_start in tests/integration/test_hyperv_real.py
(env-gated, NON-EXECUTABLE on a host without a disposable Hyper-V VM).
"""

import asyncio
import importlib

import pytest

# tests/unit has no __init__.py and pytest runs with --import-mode=prepend,
# so the sibling file is importable as the top-level module `test_console`
# (the same cross-file style test_a04_vm_identity.py uses for `conftest`).
from test_console import FakePS

import hyperv_mcp.server as server_module
from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import _scancodes_for_combo, _scancodes_for_key

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


def _listed_tools() -> dict:
    """name -> LIVE registered tool object, read off the MCP surface a client
    sees: reload + bootstrap({}) + get_mcp().list_tools(), the pattern
    tests/unit/test_a01_ps_environment.py and test_a04_vm_identity.py use.
    The schema assertions in AC6 and the description assertion in AC7 read
    THIS surface (the registered tool's JSON schema / description), not
    inspect.signature."""
    mod = importlib.reload(server_module)
    try:
        mod.bootstrap({})
        return {t.name: t for t in asyncio.run(mod.get_mcp().list_tools())}
    finally:
        importlib.reload(server_module)


def _capture(names) -> dict:
    """Per name: the _scancodes_for_key result, or the exception type name
    (the AC1 capture shape: at base an unknown name reports ValueError, not
    a crash — the assertion below is what fails)."""
    captured = {}
    for name in names:
        try:
            captured[name] = _scancodes_for_key(name)
        except Exception as exc:  # the error NAME is the captured signal
            captured[name] = type(exc).__name__
    return captured


# ---------------------------------------------------------------------------
# AC1-AC4: named-key vocabulary (DISCRIMINATING)
# ---------------------------------------------------------------------------

def test_windows_key_scancodes(monkeypatch, unrestricted):
    """AC1: win/leftwin/rightwin/apps encode as the PS/2 set-1 GUI and
    Application keys — E0 before make and before break, win aliasing
    leftwin and menu aliasing apps with the SAME prefixed bytes. RED at
    base (names unknown), GREEN after the fix. The alias-equivalence
    asserts exist because the encoders read _EXTENDED_KEYS membership of
    the called name: an alias registered without its extended-set entry
    would emit unprefixed bytes and fail the equality legs below. The
    final leg drives the press_key TOOL path with a bare win press (final
    critic FC1): the combo builder rejects modifier-only input, so the
    tool must encode a modifierless press through the plain key path —
    4 codes emitted, the win byte sequence in the TypeScancodes chunk."""
    expected = {
        "win": [0xE0, 0x5B, 0xE0, 0xDB],
        "leftwin": [0xE0, 0x5B, 0xE0, 0xDB],
        "rightwin": [0xE0, 0x5C, 0xE0, 0xDC],
        "apps": [0xE0, 0x5D, 0xE0, 0xDD],
        "menu": [0xE0, 0x5D, 0xE0, 0xDD],
    }
    captured = _capture(expected)
    assert captured == expected, (
        "F01-AC1-RED-AT-BASE: win-key scancodes " + repr(captured)
    )
    assert captured["win"] == captured["leftwin"], (
        "F01-AC1-RED-AT-BASE: win must alias leftwin bytes " + repr(captured)
    )
    assert captured["menu"] == captured["apps"], (
        "F01-AC1-RED-AT-BASE: menu must alias apps bytes " + repr(captured)
    )
    fake = FakePS([
        pswindows.PSResult(stdout="RC=0 CHUNK=1/1", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.press_key(unrestricted, "vm1", "win")
    assert out["scancodes_sent"] == 4, (
        "F01-AC1-RED-AT-BASE: bare win press " + repr(out)
    )
    assert "$chunks = @(224,91,224,219)" in fake.scripts[-1], (
        "F01-AC1-RED-AT-BASE: bare win press bytes "
        + repr(fake.scripts[-1][-400:])
    )


def test_win_is_a_combo_modifier():
    """AC2: win is accepted as a combo modifier — GUI make first, R
    make/break, GUI break last, E0 on both GUI bytes. RED at base (win is
    rejected from the modifier list), GREEN after the fix."""
    try:
        captured = _scancodes_for_combo(["win", "r"])
    except Exception as exc:  # the error NAME is the captured signal
        captured = type(exc).__name__
    assert captured == [0xE0, 0x5B, 0x13, 0x93, 0xE0, 0xDB], (
        "F01-AC2-RED-AT-BASE: win+r combo " + repr(captured)
    )


def test_punctuation_named_keys():
    """AC3: the eleven punctuation names exist as unprefixed [make, make|0x80]
    pairs. RED at base (names unknown), GREEN after the fix."""
    makes = {
        "minus": 0x0C, "equals": 0x0D, "leftbracket": 0x1A,
        "rightbracket": 0x1B, "semicolon": 0x27, "apostrophe": 0x28,
        "grave": 0x29, "backslash": 0x2B, "comma": 0x33,
        "period": 0x34, "slash": 0x35,
    }
    expected = {name: [make, make | 0x80] for name, make in makes.items()}
    captured = _capture(expected)
    assert captured == expected, (
        "F01-AC3-RED-AT-BASE: punctuation keys " + repr(captured)
    )


def test_numpad_keys():
    """AC4: numpad names exist — unprefixed pairs for num0..num9,
    numdecimal, nummultiply, numsubtract, numadd and numlock; E0-prefixed
    numdivide (E0 35) and numenter (E0 1C). home stays E0-prefixed, proving
    the keypad digits sharing its make bytes (Keypad 7 = 0x47 = Home's make)
    do not leak the prefix onto cursor keys. RED at base (names unknown),
    GREEN after the fix."""
    unprefixed_makes = {
        "num0": 0x52, "num1": 0x4F, "num2": 0x50, "num3": 0x51,
        "num4": 0x4B, "num5": 0x4C, "num6": 0x4D, "num7": 0x47,
        "num8": 0x48, "num9": 0x49, "numdecimal": 0x53, "nummultiply": 0x37,
        "numsubtract": 0x4A, "numadd": 0x4E, "numlock": 0x45,
    }
    expected = {name: [make, make | 0x80]
                for name, make in unprefixed_makes.items()}
    expected["numdivide"] = [0xE0, 0x35, 0xE0, 0xB5]
    expected["numenter"] = [0xE0, 0x1C, 0xE0, 0x9C]
    expected["home"] = [0xE0, 0x47, 0xE0, 0xC7]
    captured = _capture(expected)
    assert captured == expected, (
        "F01-AC4-RED-AT-BASE: numpad keys " + repr(captured)
    )


# ---------------------------------------------------------------------------
# AC5: click at the frame origin is a real coordinate (DISCRIMINATING)
# ---------------------------------------------------------------------------

def test_click_at_origin_moves_pointer(monkeypatch, unrestricted):
    """AC5: a click at frame (0,0) positions the pointer (scaled to head
    (0,0)) before ClickButton instead of silently clicking wherever the
    pointer already is. RED at base ((0,0) is the skip-positioning
    sentinel), GREEN after the fix. The stub serves ONE folded positional
    response (HEADX/HEADY/RC) because the fixed click takes the folded
    positional branch, whose single PowerShell leg must parse HEADX=0 and
    HEADY=0 out of the result; at base the same response serves the
    in-place leg, whose result carries no head coordinates."""
    fake = FakePS([
        pswindows.PSResult(stdout="HEADX=0" + "\n" + "HEADY=0" + "\n" +
                           "RC=0", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.click(unrestricted, "vm1", 0, 0,
                        frame_width=640, frame_height=480)
    captured = (
        "SetAbsolutePosition" in fake.scripts[-1],
        out.get("head_x"),
        out.get("head_y"),
    )
    assert captured == (True, 0, 0), (
        "F01-AC5-RED-AT-BASE: click at origin " + repr(captured)
    )


# ---------------------------------------------------------------------------
# AC6-AC7: the registered tool surface (DISCRIMINATING)
# ---------------------------------------------------------------------------

def test_click_schema_has_no_origin_sentinel(monkeypatch, unrestricted):
    """AC6: hyperv_console_click expresses 'click at the current position' by
    OMITTING x/y: on the live registered schema both default to null (never
    0), and giving exactly one of x/y raises ValueError('x and y must be
    given together'). RED at base (schema default is 0 and one-sided x=0 is
    accepted), GREEN after the fix."""
    tools = _listed_tools()
    schema = getattr(tools["hyperv_console_click"], "input_schema", None) \
        or tools["hyperv_console_click"].inputSchema
    props = schema["properties"]
    x_default = props["x"].get("default", "absent")
    y_default = props["y"].get("default", "absent")

    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    try:
        console.click(unrestricted, "vm1", x=0)  # exactly one of x/y
        one_sided = "no ValueError"
    except ValueError as exc:
        one_sided = str(exc)
    captured = (
        x_default is None,
        y_default is None,
        "x and y must be given together" in one_sided,
    )
    assert captured == (True, True, True), (
        "F01-AC6-RED-AT-BASE: click schema/one-sided x "
        + repr((x_default, y_default, one_sided))
    )


def test_press_key_description_lists_new_keys():
    """AC7: the hyperv_console_press_key tool description names the new key
    families — the words win, numpad and punctuation all appear (the
    description is the discovery surface agents choose keys from). RED at
    base (the description stops at the old key set), GREEN after the fix."""
    tools = _listed_tools()
    description = (tools["hyperv_console_press_key"].description or "").lower()
    missing = sorted(
        word for word in ("win", "numpad", "punctuation") if word not in description
    )
    assert missing == [], (
        "F01-AC7-RED-AT-BASE: press_key description missing " + repr(missing)
    )
