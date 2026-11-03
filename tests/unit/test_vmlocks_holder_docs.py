"""Issue #60 Part B acceptance check: vmlocks.py documents the queued-writer
semantics of its holder metadata.

When a reader times out while only a QUEUED writer blocks it (no writer is
admitted yet), the holder record it reports is the oldest pending writer's,
whose `since`/`held_ms` measure QUEUE time, not lock-hold time: the record
refreshes only when no writer is queued, and its held_ms is recomputed live
at read time (via _live_holder) -- and when contention drains entirely the
failure carries no `holder` key at all. None of these four facts is stated
in the module docstring at base; the _pending_writer field comment names
the record's purpose but not its queue-time meaning.

RED at base 92854d9: the module docstring lacks all four facts and the
field comment lacks the queue-time fact. GREEN after the docs fix: the
docstring carries a queued-writer paragraph covering all four concepts and
the field comment states the queue-time meaning.

Deterministic: text analysis of the module docstring (via import) and of
the source file's _pending_writer comment block. No locks are taken, no
threads started.
"""

from __future__ import annotations

from pathlib import Path

from hyperv_mcp import vmlocks

_VMLOCKS_PY = Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp" / "vmlocks.py"

#: Accepted phrasings for fact (2), the refresh rule: any one of these
#: variants (case-insensitive) satisfies the concept.
_REFRESH_VARIANTS = (
    "no writer is queued",
    "no other writer queues",
    "refreshes only when",
)


def _paragraphs(text: str) -> list[str]:
    return [p for p in text.split("\n\n") if p.strip()]


def test_module_docstring_documents_queued_writer():
    """The vmlocks module docstring carries a queued-writer paragraph with
    all four facts (issue #60 Part B)."""
    doc = vmlocks.__doc__ or ""
    low = doc.lower()

    # Fact 1: the words "queue time", in a paragraph that also names the
    # fields whose meaning it qualifies (since / held_ms).
    queue_paragraphs = [p for p in _paragraphs(doc) if "queue time" in p.lower()]
    assert queue_paragraphs, (
        "issue #60: the vmlocks module docstring never states that the "
        "queued writer's since/held_ms measure QUEUE time"
    )
    assert any(
        "held_ms" in p.lower() or "since" in p.lower() for p in queue_paragraphs
    ), (
        "issue #60: a 'queue time' paragraph exists but never ties the "
        "measurement to the since/held_ms fields it describes"
    )

    # Fact 2: the record refreshes only while the queue is empty (any of
    # the accepted variants).
    assert any(variant in low for variant in _REFRESH_VARIANTS), (
        "issue #60: the docstring does not state the refresh rule for the "
        "pending-writer record; accepted phrasings: "
        + " / ".join(_REFRESH_VARIANTS)
    )

    # Fact 3: held_ms is recomputed live at read time.
    assert "recomputed live" in low, (
        "issue #60: the docstring does not state that held_ms is "
        "recomputed live at read time"
    )

    # Fact 4: drained contention carries no holder key (backticks optional).
    unbackticked = doc.replace("`", "").lower()
    assert "no holder key" in unbackticked, (
        "issue #60: the docstring does not state that a drained-contention "
        "failure carries no `holder` key"
    )


def test_pending_writer_comment_covers_queue_time():
    """The _pending_writer field's comment block states the queue-time fact:
    the record it stores measures time spent QUEUED (its since/held_ms),
    not time holding the lock (issue #60 Part B)."""
    lines = _VMLOCKS_PY.read_text(encoding="utf-8").splitlines()
    anchor = next(
        (i for i, line in enumerate(lines) if line.strip().startswith("self._pending_writer")),
        None,
    )
    assert anchor is not None, (
        "the self._pending_writer field declaration moved or was renamed in "
        "vmlocks.py; update this pin alongside it"
    )
    comment: list[str] = []
    j = anchor - 1
    while j >= 0 and lines[j].strip().startswith("#"):
        comment.append(lines[j])
        j -= 1
    block = " ".join(comment).lower()
    assert "queue time" in block, (
        "issue #60: the _pending_writer field comment does not state that "
        "the queued writer's record measures queue time"
    )
    assert "held_ms" in block or "since" in block, (
        "issue #60: the _pending_writer field comment mentions queue time "
        "but not the since/held_ms fields it qualifies"
    )
