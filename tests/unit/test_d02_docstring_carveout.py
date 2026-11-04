"""Issue #84 AC25: the D-02 pack docstring states the capture_sequence carve-out.

RED at base b1ed4f7, GREEN after the #84 amendment. The pack file
tests/unit/test_d02_console_spawns.py opens with the unconditional claim
"Every console call must start exactly ONE PowerShell process", but
``capture_sequence`` is the sanctioned exception — README's spawn_ms prose
and the console module docstring both carry it: it carries no payload
between frames, so each frame is its own folded process (``count``
processes by name, ``count + 1`` by id). The amended pack docstring must
name ``capture_sequence`` and state the per-frame exception in the MODULE
DOCSTRING itself, where the unconditional claim sits.
"""

import ast
from pathlib import Path

PACK = Path(__file__).resolve().parent / "test_d02_console_spawns.py"


def test_pack_docstring_states_capture_sequence_carveout():
    """AC25: the module docstring (ast.get_docstring, CUB-carveout-26) names
    capture_sequence and the per-frame exception."""
    # CUB-carveout-26: parse the docstring instead of scanning the first ten
    # physical lines, and require the branch that matches the actual wording
    # ("each frame is its own self-contained folded process" — the docstring
    # hyphenates "per-frame", so a "per frame" spaced probe never matched).
    docstring = ast.get_docstring(ast.parse(PACK.read_text(encoding="utf-8")))
    assert docstring is not None, (
        "AC25: the D-02 pack file carries no module docstring"
    )
    assert "capture_sequence" in docstring, (
        "AC25: the D-02 pack docstring does not mention the capture_sequence "
        f"exception (docstring:\n{docstring})"
    )
    assert "frame is its own" in docstring, (
        "AC25: the D-02 pack docstring does not state that each frame is its "
        "own process — the carve-out README and console.py carry "
        f"(docstring:\n{docstring})"
    )
