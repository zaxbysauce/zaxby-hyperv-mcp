#!/usr/bin/env python
"""Verify that AMEND rows in an issue-tracer checkpoint manifest preserve
their predecessor rows (issue #148, claim 4).

Contract (two-tier, plan F4):
  - An AMEND row whose argv differs from its predecessor's argv is argv
    corruption and FAILS (exit 1) — unless the row is covered by the
    per-manifest baseline watermark (docs/amend-guard-baseline.json). Rows
    whose seq <= watermark_seq are BASELINE-dispositioned; the reviewed F5
    repair rows are covered because the two repaired manifests' watermark
    seqs were set AFTER those repairs landed (activation commit B postdates
    repair commit R, and dispositioned_commit is always a proper ancestor
    of the commit carrying the baseline file, never the activation commit —
    that ancestor invariant is documented here and in the runbook but not
    yet enforced in code; it needs a full-history git checkout).
  - The watermark is bounded: a watermark_seq that is not a non-negative
    int, or that exceeds the manifest's max seq, is a usage/shape error
    (exit 3) — an unbounded watermark would disposition every AMEND row
    BASELINE and turn the guard off for that manifest. The committed
    legacy_argv_exceptions count must also match the manifest's actual
    at-watermark argv-diff rows (a mismatch means the baseline file
    describes a different manifest).

Exit codes: 0 clean (verbatim and baseline-covered rows only); 2 warnings
(semantic amendments above the watermark); 1 failure (post-watermark argv
mismatch); 3 usage/shape errors.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

FIELDS = 10  # seq, type, path, blob, mode, check_id, argv, expect, base, reason


def parse_manifest(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < FIELDS:
            # The row grammar is exactly 10 fields (repro-check.sh hardcodes
            # ten and its validator rejects any other count); a '-' reason is
            # the VALUE of the 10th field, not a 9-field row. Anything
            # shorter is malformed.
            raise ValueError(f"{path}: malformed row ({len(parts)} fields)")
        rows.append({
            "seq": int(parts[0]),
            "type": parts[1],
            "path": parts[2],
            "blob": parts[3],
            "mode": parts[4],
            "check_id": parts[5],
            "argv": parts[6],
            "expect": parts[7],
            "base": parts[8],
            "reason": parts[9],
        })
    return rows


def load_baseline(repo_root: Path) -> dict:
    f = repo_root / "docs" / "amend-guard-baseline.json"
    if not f.exists():
        return {}
    try:
        doc = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"verify_amend_verbatim: baseline unreadable: {exc}",
              file=sys.stderr)
        raise SystemExit(3) from exc
    # The committed baseline nests per-slug entries under a top-level
    # "traces" key (with contract metadata alongside); accept the flat
    # {slug: {...}} form too.
    return doc.get("traces", doc) if isinstance(doc, dict) else {}


def verify_manifest(manifest_path: Path, baseline: dict) -> tuple[int, list]:
    """Return (worst_exit, findings). worst_exit: 0 ok, 2 warn, 1 fail,
    3 usage/shape error (unbounded watermark, count mismatch)."""
    slug = manifest_path.parent.parent.name
    entry = baseline.get(slug, {})
    watermark = entry.get("watermark_seq", 0)
    if (not isinstance(watermark, int) or isinstance(watermark, bool)
            or watermark < 0):
        print(f"verify_amend_verbatim: {slug}: watermark_seq must be a "
              f"non-negative int (got {watermark!r})", file=sys.stderr)
        return 3, []
    findings: list[dict] = []
    worst = 0
    rows = parse_manifest(manifest_path)
    max_seq = max((row["seq"] for row in rows), default=0)
    if watermark > max_seq:
        print(f"verify_amend_verbatim: {slug}: watermark_seq {watermark} "
              f"exceeds manifest max seq {max_seq}", file=sys.stderr)
        return 3, findings
    predecessor: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = (row["path"], row["check_id"])
        prev = predecessor.get(key)
        predecessor[key] = row
        if row["type"] != "AMEND" or prev is None:
            continue
        if row["seq"] <= watermark:
            findings.append({"row": row["seq"], "path": key[0],
                             "check_id": key[1], "verdict": "BASELINE",
                             "field": "argv" if row["argv"] != prev["argv"]
                             else None})
            continue
        if row["argv"] != prev["argv"]:
            findings.append({"row": row["seq"], "path": key[0],
                             "check_id": key[1], "verdict": "FAIL",
                             "field": "argv",
                             "detail": "argv differs from predecessor"})
            worst = 1
        elif row["expect"] != prev["expect"]:
            findings.append({"row": row["seq"], "path": key[0],
                             "check_id": key[1], "verdict": "WARN",
                             "field": "expect",
                             "detail": "expect-only change (sanctioned "
                                       "CHECK_WRONG stable-predicate repair)"})
            worst = max(worst, 2)
        elif row["base"] != prev["base"]:
            findings.append({"row": row["seq"], "path": key[0],
                             "check_id": key[1],
                             "verdict": "WARN", "field": "base",
                             "detail": "base-only change (versioning-policy "
                                       "amendment)"})
            worst = max(worst, 2)
    # Failure dominates warnings regardless of row order: a WARN aggregated
    # after a FAIL must never downgrade the exit (review finding R1 — exit
    # codes are severity-ordered here, not numerically).
    if any(f["verdict"] == "FAIL" for f in findings):
        worst = 1
    # Baseline cross-check: the committed legacy_argv_exceptions count must
    # equal the manifest's actual at-watermark argv-diff rows — a mismatch
    # means the baseline file describes a different manifest than the one
    # being verified (exit 3, usage/shape error).
    declared = entry.get("legacy_argv_exceptions")
    if declared is not None:
        actual = sum(1 for f in findings
                     if f["verdict"] == "BASELINE" and f["field"] == "argv")
        if int(declared) != actual:
            print(f"verify_amend_verbatim: {slug}: baseline declares "
                  f"{declared} legacy argv exceptions, manifest shows "
                  f"{actual}", file=sys.stderr)
            return 3, findings
    return worst, findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", help="checkpoint.manifest path")
    ap.add_argument("--repo-root", default=".",
                    help="repo root holding docs/amend-guard-baseline.json")
    ap.add_argument("--baseline", default=None,
                    help="explicit baseline json path (overrides --repo-root)")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="machine-readable findings on stdout")
    args = ap.parse_args()
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"verify_amend_verbatim: no such manifest: {manifest_path}",
              file=sys.stderr)
        return 3
    baseline_file = Path(args.baseline) if args.baseline else None
    if baseline_file is not None:
        try:
            doc = json.loads(baseline_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"verify_amend_verbatim: baseline unreadable: {exc}",
                  file=sys.stderr)
            return 3
        # Same nested/flat acceptance as load_baseline: the committed
        # baseline nests per-slug entries under a top-level "traces" key.
        baseline = doc.get("traces", doc) if isinstance(doc, dict) else {}
    else:
        baseline = load_baseline(Path(args.repo_root))
    try:
        worst, findings = verify_manifest(manifest_path, baseline)
    except ValueError as exc:
        # Malformed manifest row: a shape error per the docstring contract
        # (exit 3), not an uncaught traceback (exit 1).
        print(f"verify_amend_verbatim: {exc}", file=sys.stderr)
        return 3
    if args.as_json:
        # ok is exactly the clean state (exit 0): a shape error (exit 3) is
        # never "ok", and the watermark is serialized as-is — a forced int()
        # here would raise outside the ValueError handler for a non-int
        # watermark that verify_manifest already refused with exit 3.
        print(json.dumps({"ok": worst == 0, "exit": worst,
                          "manifest": str(manifest_path),
                          "watermark_seq": baseline.get(
                              manifest_path.parent.parent.name, {})
                          .get("watermark_seq", 0),
                          "findings": findings}, indent=1))
    else:
        for f in findings:
            if f["verdict"] == "BASELINE":
                continue
            print(f"{f['verdict']} seq={f['row']} {f['path']} {f['check_id']}"
                  f" field={f['field']}: {f['detail']}")
        if worst == 0 and not [f for f in findings
                               if f["verdict"] != "BASELINE"]:
            print("OK: all AMEND rows verbatim or baseline-covered")
    return worst


if __name__ == "__main__":
    sys.exit(main())
