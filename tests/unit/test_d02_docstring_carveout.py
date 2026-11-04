"""Issue #84 AC25: the D-02 pack docstring states the capture_sequence carve-out.

RED at base b1ed4f7, GREEN after the #84 amendment. The pack file
tests/unit/test_d02_console_spawns.py opens with the unconditional claim
"Every console call must start exactly ONE PowerShell process", but
``capture_sequence`` is the sanctioned exception — README's spawn_ms prose
and the console module docstring both carry it: it carries no payload
between frames, so each frame is its own folded process (``count``
processes by name, ``count + 1`` by id). The amended pack docstring must
name ``capture_sequence`` and state the per-frame exception within its
first ten lines, where the unconditional claim sits today.
"""

from pathlib import Path

PACK = Path(__file__).resolve().parent / "test_d02_console_spawns.py"


def test_pack_docstring_states_capture_sequence_carveout():
    """AC25: the first ten lines name capture_sequence and the per-frame exception."""
    head = "\n".join(PACK.read_text(encoding="utf-8").splitlines()[:10])
    assert "capture_sequence" in head, (
        "AC25: the D-02 pack docstring's first ten lines do not mention the "
        f"capture_sequence exception (first ten lines:\n{head})"
    )
    assert "per frame" in head or "frame is its own" in head, (
        "AC25: the D-02 pack docstring's first ten lines do not state that each "
        "frame is its own process — the carve-out README and console.py carry "
        f"(first ten lines:\n{head})"
    )
