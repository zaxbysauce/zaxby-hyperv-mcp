"""Verbatim-AMEND guard contract (issue #148 claim 4; AC8 of trace
148-151-153-followup-hygiene-triad, plan F4).

Two-tier contract: every AMEND row is compared against its predecessor
effective row for the same (path, check-id) pair — an argv mismatch above
the baseline watermark is corruption (exit 1 FAIL naming the row); an
expect-only or base-only change is a disclosed semantic amendment (exit 2
WARN naming the row); a verbatim row is a silent OK (exit 0).

Watermark semantics: AMEND rows with seq <= the manifest's watermark_seq in
docs/amend-guard-baseline.json are BASELINE-dispositioned (counted, never
FAIL); a manifest with no baseline entry is watermark 0 — born strict from
row 1.

Every arm drives the REAL tool (scripts/verify_amend_verbatim.py) as a
subprocess against a sandbox manifest + sandbox baseline json, each arm in
its own fresh tmp directory. The tool derives the slug from
manifest_path.parent.parent.name, so each sandbox lays the manifest out at
<tmp>/<arm>/<slug>/repro/checkpoint.manifest.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "scripts" / "verify_amend_verbatim.py"

_ARGV = "bash check-c1.sh"
_ARGV_RETYPED = "bash check-c1-retyped.sh"
_BASE = "0" * 40
_BASE_MOVED = "1" * 40
_PATH = "tests/unit/test_sandbox.py"


def _row(seq: int, kind: str, argv: str, expect: str = "-",
         base: str = _BASE, path: str = _PATH, check: str = "C1") -> str:
    reason = "-" if kind == "CHECKPOINT" else "CHECK_WRONG"
    return "\t".join([
        str(seq), kind, path, "f" * 40, "100644", check,
        argv, expect, base, reason,
    ])


def _sandbox(tmp_path: Path, arm: str, rows: list[str],
             entry: dict | None = None) -> tuple[Path, Path]:
    """Fresh per-arm sandbox: <tmp>/<arm>/<slug>/repro/checkpoint.manifest
    plus a baseline json whose single entry (when given) keys on the slug
    the tool will derive from the manifest's location."""
    slug = f"{arm}-sandbox-trace"
    manifest = tmp_path / arm / slug / "repro" / "checkpoint.manifest"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        f"# issue-tracer checkpoint manifest v1 rows={len(rows)}\n"
        + "\n".join(rows) + "\n",
        encoding="utf-8", newline="\n",
    )
    baseline = {slug: entry} if entry is not None else {}
    baseline_file = tmp_path / arm / "baseline.json"
    baseline_file.write_text(
        json.dumps(baseline), encoding="utf-8", newline="\n")
    return manifest, baseline_file


def _guard(manifest: Path, baseline: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_TOOL), str(manifest), "--baseline", str(baseline)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60,
    )


def test_verbatim_amend_above_watermark_is_ok(tmp_path):
    """A verbatim AMEND row evaluated strictly (seq > watermark) reads OK:
    exit 0 with the clean-run line."""
    manifest, baseline = _sandbox(
        tmp_path, "verbatim",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV)],
        entry={"watermark_seq": 1},
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: all AMEND rows verbatim or baseline-covered" in proc.stdout


def test_retyped_argv_amend_above_watermark_fails(tmp_path):
    """An argv-retyped AMEND row above the watermark is corruption: exit 1
    with a FAIL line naming the row (path + check id)."""
    manifest, baseline = _sandbox(
        tmp_path, "retyped",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV_RETYPED)],
        entry={"watermark_seq": 1},
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL" in proc.stdout
    assert _PATH in proc.stdout
    assert "C1" in proc.stdout
    assert "argv" in proc.stdout


def test_expect_only_amend_above_watermark_warns(tmp_path):
    """An expect-only change above the watermark is a disclosed semantic
    amendment: exit 2 with a WARN line naming the row."""
    manifest, baseline = _sandbox(
        tmp_path, "expectonly",
        [_row(1, "CHECKPOINT", _ARGV, expect="sig-old"),
         _row(2, "AMEND", _ARGV, expect="AssertionError: AC3: stable-predicate")],
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "WARN" in proc.stdout
    assert _PATH in proc.stdout
    assert "C1" in proc.stdout
    assert "expect" in proc.stdout


def test_base_only_amend_above_watermark_warns(tmp_path):
    """A base-only change above the watermark (versioning-policy amendment)
    is a disclosed semantic amendment: exit 2."""
    manifest, baseline = _sandbox(
        tmp_path, "baseonly",
        [_row(1, "CHECKPOINT", _ARGV, base=_BASE),
         _row(2, "AMEND", _ARGV, base=_BASE_MOVED)],
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "WARN" in proc.stdout
    assert "base" in proc.stdout


def test_baseline_watermark_covers_retyped_row(tmp_path):
    """BASELINE disposition: the same retyped-argv row that FAILs strictly
    passes once the manifest's watermark covers its seq (watermark_seq >=
    seq) — no FAIL line, exit 0."""
    manifest, baseline = _sandbox(
        tmp_path, "covered",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV_RETYPED)],
        entry={"watermark_seq": 5},
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FAIL" not in proc.stdout


def test_watermark_zero_manifest_is_born_strict(tmp_path):
    """A manifest with NO baseline entry is watermark 0 (born strict): the
    retyped row FAILs from row 1 — the both-directions proof with the
    baseline-covered arm above."""
    manifest, baseline = _sandbox(
        tmp_path, "bornstrict",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV_RETYPED)],
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL" in proc.stdout
    assert _PATH in proc.stdout


def test_authorized_repair_row_passes_as_baseline(tmp_path):
    """AUTHORIZED-REPAIR shape (plan F5): a baseline entry carrying the full
    audited metadata (watermark_seq set to the repaired rows' seq,
    dispositioned_commit, legacy_argv_exceptions) covers the repaired row's
    seq — exit 0, no FAIL."""
    manifest, baseline = _sandbox(
        tmp_path, "authorized",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV_RETYPED)],
        entry={"watermark_seq": 7,
               "dispositioned_commit": "c3a9f8d0241faeb4e3656e097e7855fb855f11aa",
               "legacy_argv_exceptions": 1},
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FAIL" not in proc.stdout


def test_manifest_without_amend_rows_is_ok(tmp_path):
    """A manifest with no AMEND rows at all is trivially clean: exit 0 with
    the OK line."""
    manifest, baseline = _sandbox(
        tmp_path, "noamend",
        [_row(1, "CHECKPOINT", _ARGV, path="tests/unit/test_one.py"),
         _row(2, "CHECKPOINT", _ARGV, path="tests/unit/test_two.py",
              check="C2")],
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: all AMEND rows verbatim or baseline-covered" in proc.stdout
