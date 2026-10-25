"""Review-pin tests for PR #99 (swarm-pr-review run pr99-20261024) and the
PR #100 follow-up (run pr100-20261025).

PR #99 pins close the coverage gaps the review validated and the critic
confirmed (feedback ledger F1/F2/F4 in .zcode/pr-review/pr99-20261024/):
the single-character alias oracle, the position-before-click ordering on
BOTH transports, the press_key modifier-present emission branch (incl. the
role-swap fix), bare modifier-named presses, the schema's null acceptance,
and a tool-layer numpad emission. PR #100 adds the unknown-key recovery
message shape pin (review item 2, derived from the production tables).
This file is NOT part of the issue-25 checkpoint manifest — it is additive
review coverage.
"""

import asyncio
import importlib

import pytest
from test_console import FakePS
from test_wmiconsole import FakeWMIService, _install_wmi, _ps

import hyperv_mcp.server as server_module
from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.console import _scancodes_for_key

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


def _listed_tools() -> dict:
    """name -> LIVE registered tool object (the a01/a04 reload+bootstrap
    pattern; conftest restores the module globals)."""
    mod = importlib.reload(server_module)
    try:
        mod.bootstrap({})
        return {t.name: t for t in asyncio.run(mod.get_mcp().list_tools())}
    finally:
        importlib.reload(server_module)


# ---------------------------------------------------------------------------
# F1: the single-character punctuation aliases must map to the same bytes as
# their long names (issue #25 AC3; advertised in the tool description).
# ---------------------------------------------------------------------------

def test_punctuation_single_char_aliases_match_long_names():
    long_names = {
        "-": "minus", "=": "equals", "[": "leftbracket",
        "]": "rightbracket", "\\": "backslash", ";": "semicolon",
        "'": "apostrophe", "`": "grave", ",": "comma", ".": "period",
        "/": "slash",
    }
    for alias, name in long_names.items():
        assert _scancodes_for_key(alias) == _scancodes_for_key(name), (
            f"P-ALIAS: alias {alias!r} must encode identically to {name!r}"
        )


# ---------------------------------------------------------------------------
# F4: press_key's modifier-present branch — the key is ALWAYS the tapped key,
# even when it shares a modifier name (role-swap fix).
# ---------------------------------------------------------------------------

def _press(monkeypatch, key, modifiers):
    fake = FakePS([
        pswindows.PSResult(stdout="RC=0 CHUNK=1/1", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.press_key(Config(unrestricted=True), "vm1", key,
                            list(modifiers))
    chunk = [line.strip() for line in fake.scripts[-1].splitlines()
             if line.strip().startswith("$chunks")][0]
    return out, chunk


def test_press_key_modifier_present_taps_key_holds_modifiers(monkeypatch):
    """win+ctrl holds ctrl (0x1D make, 0x9D break) around the win tap."""
    out, chunk = _press(monkeypatch, "win", ["ctrl"])
    assert out["scancodes_sent"] == 6
    assert chunk == "$chunks = @(29,224,91,224,219,157)"


def test_press_key_modifier_order_unchanged_for_plain_key(monkeypatch):
    """r+win still holds win and taps r (the pre-existing correct shape)."""
    _out, chunk = _press(monkeypatch, "r", ["win"])
    assert chunk == "$chunks = @(224,91,19,147,224,219)"


def test_press_key_bare_modifier_named_key(monkeypatch):
    """ctrl/alt/shift are valid bare presses through the plain-key path."""
    for key, make, brk in (("ctrl", 0x1D, 0x9D), ("alt", 0x38, 0xB8),
                           ("shift", 0x2A, 0xAA)):
        out, chunk = _press(monkeypatch, key, [])
        assert out["scancodes_sent"] == 2, key
        assert chunk == f"$chunks = @({make},{brk})", key


def test_press_key_tool_layer_numpad_emission(monkeypatch):
    """The advertised numpad reaches the wire through the tool path."""
    out, chunk = _press(monkeypatch, "numenter", [])
    assert out["scancodes_sent"] == 4
    assert chunk == "$chunks = @(224,28,224,156)"


# ---------------------------------------------------------------------------
# F2: position-before-click ordering, pinned on BOTH transports.
# ---------------------------------------------------------------------------

def test_wmi_origin_click_positions_before_clicking(monkeypatch, unrestricted_cfg):
    """The WMI method stream order is SetAbsolutePosition THEN ClickButton
    (a dict keyed by method name discards exactly this fact)."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)
    console.click(unrestricted_cfg, "vm1", 0, 0)
    names = [m[1] for m in svc.methods]
    assert "SetAbsolutePosition" in names and "ClickButton" in names
    assert names.index("SetAbsolutePosition") < names.index("ClickButton"), (
        "P-ORDER-WMI: origin click must position the pointer before clicking"
    )


def test_ps_origin_click_positions_before_clicking(monkeypatch, unrestricted):
    """The folded PS positional script positions (SetAbsolutePosition)
    before it clicks (ClickButton) — index order, not membership."""
    fake = FakePS([
        pswindows.PSResult(stdout="HEADX=0" + "\n" + "HEADY=0" + "\n" +
                           "RC=0", returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    console.click(unrestricted, "vm1", 0, 0, frame_width=640, frame_height=480)
    script = fake.scripts[-1]
    assert "SetAbsolutePosition" in script and "ClickButton" in script
    assert script.index("SetAbsolutePosition") < script.index("ClickButton"), (
        "P-ORDER-PS: origin click must position the pointer before clicking"
    )


# ---------------------------------------------------------------------------
# AC6 strengthening: the schema must ADMIT null (anyOf integer/null), not
# merely default to null.
# ---------------------------------------------------------------------------

def test_click_schema_type_admits_null():
    tools = _listed_tools()
    tool = tools["hyperv_console_click"]
    schema = getattr(tool, "inputSchema", None) or tool.input_schema
    props = schema["properties"]
    for axis in ("x", "y"):
        schema = props[axis]
        admits_null = (
            schema.get("type") == "null"
            or "null" in schema.get("type", [])
            or any(
                isinstance(t, dict) and t.get("type") == "null"
                for t in schema.get("anyOf", [])
            )
        )
        assert admits_null, f"P-SCHEMA: {axis} must admit null, got {schema}"
        assert schema.get("default", "absent") is None


# ---------------------------------------------------------------------------
# ITEM 2 (PR #99 review): the unknown-key recovery text must keep the frozen
# "unknown key ..." shape, list every supported name EXCEPT the punctuation
# aliases comma-separated in a sorted first clause, and present the
# punctuation aliases as a space-separated sorted trailing clause (no
# ", "-separator collision with the "," alias). The pin derives its
# expectations from the production tables (console._PUNCT_ALIASES and
# console._KEY_SCANCODES), so table extensions fail it only when they
# actually change the delivered message.
# ---------------------------------------------------------------------------

def test_unknown_key_message_readable_recovery_shape():
    alias_set = set(console._PUNCT_ALIASES)
    all_names = set(console._KEY_SCANCODES)
    with pytest.raises(ValueError) as exc:
        _scancodes_for_key("meta")
    message = str(exc.value)
    assert message.startswith("unknown key 'meta'; supported keys: "), (
        "P-ERRMSG: frozen prefix shape changed"
    )
    body = message[len("unknown key 'meta'; supported keys: "):]
    alias_marker = "; single-char aliases: "
    assert alias_marker in body, (
        "P-ERRMSG: single-char aliases must be a separated trailing clause, "
        f"got {message!r}"
    )
    long_part, alias_part = body.split(alias_marker, 1)
    long_tokens = [t.strip() for t in long_part.split(",")]
    alias_tokens = alias_part.split(" ")

    # every supported name appears exactly once across the two clauses, and
    # no single-character token (punctuation alias OR canonical 1-char name)
    # leaks into the comma-separated clause
    assert set(long_tokens) | set(alias_tokens) == all_names, (
        "P-ERRMSG: the message must still list every supported name "
        f"exactly once; missing={all_names - set(long_tokens) - set(alias_tokens)!r} "
        f"extra={set(long_tokens + alias_tokens) - all_names!r}"
    )
    assert len(long_tokens) + len(alias_tokens) == len(all_names), (
        "P-ERRMSG: duplicate name in the message"
    )
    assert not any(not t.isalnum() for t in long_tokens), (
        "P-ERRMSG: punctuation tokens must live in the alias clause "
        "(only alphanumeric names never collide with the ', ' separator), "
        f"got {long_part!r}"
    )

    # alias clause: exactly the punctuation aliases, space-separated, sorted
    assert alias_tokens == sorted(alias_set), (
        "P-ERRMSG: alias clause must be the sorted punctuation aliases "
        f"space-separated, got {alias_tokens!r}"
    )
    assert all(len(a) == 1 for a in alias_tokens), (
        f"P-ERRMSG: alias clause must hold single-char aliases, got {alias_tokens!r}"
    )
    # every listed alias still resolves to the same bytes as its long name
    long_names = {
        "-": "minus", "=": "equals", "[": "leftbracket",
        "]": "rightbracket", "\\": "backslash", ";": "semicolon",
        "'": "apostrophe", "`": "grave", ",": "comma", ".": "period",
        "/": "slash",
    }
    assert alias_set == set(long_names)
    for alias, name in long_names.items():
        assert _scancodes_for_key(alias) == _scancodes_for_key(name), alias
