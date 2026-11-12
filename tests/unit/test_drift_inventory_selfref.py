"""Self-reference safety of the drift-inventory generator (issue #143).

The 63-66-119-collated trace's C8 pair pins docs/issue-trace-drift-inventory.md
itself, so every regeneration used to change the hash the gate compares
against — the quine behind the regenerate -> re-AMEND -> regenerate ritual and
the --no-verify pre-push bypass. These pins hold the fix's contract:

- the census classifies self-pinned pairs out of the gate verdict (AC1),
- a real sibling drift still fails `--check` and names the trace even when
  the docs copy matches the regeneration (AC2),
- the self pair's verdict stays visible in the generated document (AC3),
- the informational verdict reads the COMMITTED blob (`git ls-tree HEAD`),
  not the working tree, so two consecutive checks agree.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "gen_trace_drift_inventory.py"
_SPEC = importlib.util.spec_from_file_location("gen_trace_drift_inventory", _SCRIPT)
mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mod)


def _write_manifest(path: Path, rows: list[tuple[str, str, str, str]]) -> None:
    lines = [f"# issue-tracer checkpoint manifest v1 rows={len(rows)}"]
    for i, (kind, target, blob, check) in enumerate(rows, 1):
        lines.append(
            f"{i}\t{kind}\t{target}\t{blob}\t100644\t{check}\tbash check-{check}.sh\t-\t{'0' * 32}\t-"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repo fixture: one trace manifest pinning the inventory path (the
    self pair) plus one sibling manifest pinning an unrelated file."""
    traces = tmp_path / ".agents" / "issue-traces"
    self_slug = "63-66-119-collated"
    sibling = "sibling-wave"
    for slug in (self_slug, sibling):
        (traces / slug / "repro").mkdir(parents=True)
    _write_manifest(
        traces / self_slug / "repro" / "checkpoint.manifest",
        [("CHECKPOINT", mod.SELF_PATH, "f" * 40, "C8")],
    )
    _write_manifest(
        traces / sibling / "repro" / "checkpoint.manifest",
        [("CHECKPOINT", "README.md", "3" * 40, "C1")],
    )
    monkeypatch.setattr(mod, "REPO", tmp_path)
    monkeypatch.setattr(mod, "TRACES", traces)
    monkeypatch.setattr(mod, "DOCS", tmp_path / "docs" / "issue-trace-drift-inventory.md")
    # Deterministic informational verdict: the working-tree blob differs
    # from the frozen blob in the moved-pair scenario and matches in the
    # clean one (tests override per scenario below).
    monkeypatch.setattr(mod, "_live_blob", lambda _path: "a" * 40)
    return tmp_path


def _fake_verify(monkeypatch: pytest.MonkeyPatch, outputs: dict[str, str]) -> None:
    def _verify(slug: str):
        out = outputs.get(slug, "")
        code = 1 if "CHANGED " in out else 0
        return code, out

    monkeypatch.setattr(mod, "_verify", _verify)


OK_SELF = "OK " + mod.SELF_PATH + "\n"
CHANGED_SELF = f"CHANGED {mod.SELF_PATH} {'f' * 40} {'a' * 40} (C8)\n"
CHANGED_SIBLING = f"CHANGED README.md {'3' * 40} {'9' * 40} (C1)\n"


def _seed_docs(root: Path) -> Path:
    docs = root / "docs" / "issue-trace-drift-inventory.md"
    docs.parent.mkdir()
    docs.write_text(
        "# Issue-trace checkpoint inventory\n\nstale body\n",
        encoding="utf-8", newline="\n",
    )
    return docs


def _main(monkeypatch: pytest.MonkeyPatch, *flags: str) -> int:
    monkeypatch.setattr(sys, "argv", ["gen_trace_drift_inventory.py", *flags])
    return mod.main()


def test_self_pair_moves_and_check_is_stable(tmp_path, monkeypatch, capsys):
    """AC1: the self-pinned pair moved (working tree differs from the frozen
    blob), the operator regenerates, then runs --check twice — both exit 0
    with no manifest re-AMEND between."""
    root = _sandbox(tmp_path, monkeypatch)
    _fake_verify(monkeypatch, {
        "63-66-119-collated": CHANGED_SELF,
        "sibling-wave": "OK README.md\n",
    })
    _seed_docs(root)
    assert _main(monkeypatch, "--snapshot") == 0  # seed the markers
    assert _main(monkeypatch) == 0  # regenerate in place
    first = _main(monkeypatch, "--check")
    second = _main(monkeypatch, "--check")
    assert first == 0, capsys.readouterr().out
    assert second == 0, capsys.readouterr().out
    # and the flow never edited the manifest:
    manifest = root / ".agents/issue-traces/63-66-119-collated/repro/checkpoint.manifest"
    assert "AMEND" not in manifest.read_text(encoding="utf-8")


def test_sibling_drift_still_fails_the_gate(tmp_path, monkeypatch, capsys):
    """AC2: a genuinely drifted sibling fails --check and names the trace —
    even when the docs copy already matches the regeneration."""
    root = _sandbox(tmp_path, monkeypatch)
    _fake_verify(monkeypatch, {
        "63-66-119-collated": OK_SELF,
        "sibling-wave": CHANGED_SIBLING,
    })
    _seed_docs(root)
    assert _main(monkeypatch, "--snapshot") == 0  # seed the markers + record the drift
    assert _main(monkeypatch) == 0  # regenerate: the docs copy now MATCHES live
    body = (root / "docs" / "issue-trace-drift-inventory.md").read_text(encoding="utf-8")
    assert "sibling-wave" in body  # the drift is recorded in the census
    rc = _main(monkeypatch, "--check")
    assert rc == 1
    captured = capsys.readouterr().out + capsys.readouterr().err
    assert "sibling-wave" in captured  # ...and --check still names it


def test_self_pair_verdict_is_visible_in_generated_doc(tmp_path, monkeypatch, capsys):
    """AC3: the self pair stays in the document with its committed-vs-frozen
    verdict in a labelled section."""
    root = _sandbox(tmp_path, monkeypatch)
    _fake_verify(monkeypatch, {
        "63-66-119-collated": CHANGED_SELF,
        "sibling-wave": "OK README.md\n",
    })
    docs = _seed_docs(root)
    assert _main(monkeypatch, "--snapshot") == 0  # seed the markers
    assert _main(monkeypatch) == 0
    body = docs.read_text(encoding="utf-8")
    assert "Self-referential pairs" in body
    assert "63-66-119-collated" in body
    assert "live tree diverged from the frozen pin" in body


def test_self_pair_extraction_prefers_the_last_row(tmp_path):
    """The manifest's effective blob per check-id is the LAST row (the
    AMEND-path rule), not the first."""
    manifest = tmp_path / "checkpoint.manifest"
    _write_manifest(
        manifest,
        [("CHECKPOINT", mod.SELF_PATH, "a" * 40, "C8"),
         ("AMEND", mod.SELF_PATH, "b" * 40, "C8"),
         ("CHECKPOINT", "README.md", "c" * 40, "C1")],
    )
    pairs = mod._manifest_self_pairs(manifest)
    assert pairs == [{"check": "C8", "blob": "b" * 40}]
