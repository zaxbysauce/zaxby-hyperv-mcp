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
        entry={"watermark_seq": 2},
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
        entry={"watermark_seq": 2,
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


def test_severity_fail_dominates_warn_regardless_of_order(tmp_path):
    """Severity dominance: exit codes are severity-ordered (FAIL=1 worse
    than WARN=2), not numeric — an argv-FAIL row and an expect-only WARN
    row in the SAME manifest aggregate to exit 1 whichever row order they
    appear in. Pins the aggregation fix at the end of verify_manifest:
    without the post-loop FAIL recheck, a WARN aggregated after a FAIL
    (worst = max(worst, 2)) would downgrade the exit from 1 to 2."""
    other_path = "tests/unit/test_mirror.py"
    fail_first = [
        _row(1, "CHECKPOINT", _ARGV),
        _row(2, "AMEND", _ARGV_RETYPED),
        _row(3, "CHECKPOINT", _ARGV, path=other_path, check="C2",
             expect="sig-old"),
        _row(4, "AMEND", _ARGV, path=other_path, check="C2",
             expect="AssertionError: AC3: stable-predicate"),
    ]
    manifest, baseline = _sandbox(
        tmp_path, "failfirst", fail_first, entry={"watermark_seq": 0})
    proc = _guard(manifest, baseline)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL" in proc.stdout
    assert "WARN" in proc.stdout

    warn_first = [
        _row(1, "CHECKPOINT", _ARGV, path=other_path, check="C2",
             expect="sig-old"),
        _row(2, "AMEND", _ARGV, path=other_path, check="C2",
             expect="AssertionError: AC3: stable-predicate"),
        _row(3, "CHECKPOINT", _ARGV),
        _row(4, "AMEND", _ARGV_RETYPED),
    ]
    manifest, baseline = _sandbox(
        tmp_path, "warnfirst", warn_first, entry={"watermark_seq": 0})
    proc = _guard(manifest, baseline)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL" in proc.stdout
    assert "WARN" in proc.stdout


def test_committed_baseline_unwrap_pin(tmp_path):
    """load_baseline's committed-form unwrap pin. The committed baseline
    (docs/amend-guard-baseline.json, reached via --repo-root) nests the
    per-slug entries under a top-level "traces" key with contract metadata
    alongside; load_baseline unwraps with doc.get("traces", doc) before
    verify_manifest looks the slug up.

    Decisive pair on the SAME retyped-argv manifest (which FAILs strictly):
      (i)  NESTED baseline, watermark_seq covering every row -> exit 0: the
           watermark was applied THROUGH the traces unwrap.
      (ii) FLAT baseline (the same watermark numbers hoisted to the top
           level, no "traces" wrapper and no slug key) -> exit 1: the slug
           lookup finds nothing, the manifest is born-strict (watermark 0).

    Removing load_baseline's .get("traces", doc) unwrap changes production
    behavior and this arm detects it: without the unwrap the nested doc
    ({"_contract": ..., "traces": {...}}) has no slug at the top level, so
    arm (i) would read watermark 0 and FAIL exit 1, while arm (ii) stays
    exit 1 either way — the pair discriminates the unwrap specifically (the
    wrapper, not the watermark numbers, is what applies the watermark)."""
    slug = "repounwrap-sandbox-trace"
    repo_root = tmp_path / "repo"
    manifest = repo_root / slug / "repro" / "checkpoint.manifest"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        "# issue-tracer checkpoint manifest v1 rows=2\n"
        + "\n".join([
            _row(1, "CHECKPOINT", _ARGV),
            _row(2, "AMEND", _ARGV_RETYPED),
        ]) + "\n",
        encoding="utf-8", newline="\n",
    )
    entry = {"watermark_seq": 2,
             "dispositioned_commit": "c3a9f8d0241faeb4e3656e097e7855fb855f11aa",
             "legacy_argv_exceptions": 1}
    baseline_file = repo_root / "docs" / "amend-guard-baseline.json"
    baseline_file.parent.mkdir(parents=True)

    def _guard_repo() -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(_TOOL), str(manifest),
             "--repo-root", str(repo_root)],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60,
        )

    # (i) nested committed form: the unwrap applies the covering watermark.
    baseline_file.write_text(json.dumps({
        "_contract": "amend-guard-baseline v1 (nested committed form)",
        "traces": {slug: entry},
    }), encoding="utf-8", newline="\n")
    nested = _guard_repo()
    assert nested.returncode == 0, nested.stdout + nested.stderr
    assert "FAIL" not in nested.stdout
    assert "OK: all AMEND rows verbatim or baseline-covered" in nested.stdout

    # (ii) flat form: same watermark numbers at the top level, no traces
    # wrapper and no slug key — born-strict, the retyped row FAILs.
    baseline_file.write_text(json.dumps({
        "watermark_seq": entry["watermark_seq"],
        "dispositioned_commit": entry["dispositioned_commit"],
        "legacy_argv_exceptions": entry["legacy_argv_exceptions"],
    }), encoding="utf-8", newline="\n")
    flat = _guard_repo()
    assert flat.returncode == 1, flat.stdout + flat.stderr
    assert "FAIL" in flat.stdout
    assert "argv" in flat.stdout


def test_watermark_above_manifest_max_seq_is_a_shape_error(tmp_path):
    """An unbounded watermark (watermark_seq above the manifest's max seq)
    would disposition every AMEND row BASELINE and turn the guard off for
    that manifest: a usage/shape error (exit 3), not a silent pass."""
    manifest, baseline = _sandbox(
        tmp_path, "unbounded",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV_RETYPED)],
        entry={"watermark_seq": 99},
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "exceeds manifest max seq" in proc.stderr


def test_non_int_watermark_is_a_shape_error(tmp_path):
    """A watermark_seq that is not a non-negative int (a JSON string here)
    is a usage/shape error (exit 3) — never a silent watermark 0."""
    manifest, baseline = _sandbox(
        tmp_path, "nonint",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV_RETYPED)],
        entry={"watermark_seq": "high"},
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "non-negative int" in proc.stderr


def test_malformed_manifest_row_is_a_shape_error(tmp_path):
    """A manifest row with fewer than 10 tab-separated fields is malformed
    (the row grammar is exactly 10; a '-' reason is the VALUE of the 10th
    field, not a 9-field row): a shape error (exit 3), not an uncaught
    traceback (exit 1)."""
    slug = "malformed-sandbox-trace"
    manifest = tmp_path / "malformed" / slug / "repro" / "checkpoint.manifest"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        "# issue-tracer checkpoint manifest v1 rows=1\n"
        + "\t".join([
            "1", "CHECKPOINT", _PATH, "f" * 40, "100644", "C1", _ARGV, "-",
        ]) + "\n",
        encoding="utf-8", newline="\n",
    )
    baseline_file = tmp_path / "malformed" / "baseline.json"
    baseline_file.write_text(json.dumps({}), encoding="utf-8", newline="\n")
    proc = _guard(manifest, baseline_file)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "malformed row" in proc.stderr


def test_nested_baseline_via_explicit_baseline_flag(tmp_path):
    """The committed nested form (per-slug entries under a top-level
    'traces' key) must work through --baseline exactly as through
    --repo-root: the explicit-file branch applies the same
    doc.get('traces', doc) unwrap, so the covering watermark applies."""
    manifest, baseline = _sandbox(
        tmp_path, "nestedflag",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV_RETYPED)],
    )
    slug = "nestedflag-sandbox-trace"
    baseline.write_text(json.dumps({
        "_contract": "amend-guard-baseline v1 (nested committed form)",
        "traces": {slug: {"watermark_seq": 2}},
    }), encoding="utf-8", newline="\n")
    proc = _guard(manifest, baseline)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: all AMEND rows verbatim or baseline-covered" in proc.stdout


def test_legacy_count_mismatch_is_a_shape_error(tmp_path):
    """The committed legacy_argv_exceptions count must equal the manifest's
    actual at-watermark argv-diff rows: a mismatch means the baseline file
    describes a different manifest (exit 3). Here the watermark covers the
    retyped row (1 actual argv-diff row) but the entry declares 0."""
    manifest, baseline = _sandbox(
        tmp_path, "countmismatch",
        [_row(1, "CHECKPOINT", _ARGV), _row(2, "AMEND", _ARGV_RETYPED)],
        entry={"watermark_seq": 2, "legacy_argv_exceptions": 0},
    )
    proc = _guard(manifest, baseline)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "legacy argv exceptions" in proc.stderr
