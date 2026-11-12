"""Drift inventory generator for the frozen-checkpoint regime (issue #119).

Walks every local trace under .agents/issue-traces/, runs the vendored
verify-checkpoint per trace, and renders docs/issue-trace-drift-inventory.md.

Modes:
  --snapshot  capture the CURRENT state as the durable artifact: dynamic
              section + a static Discovery snapshot section (verbatim
              verify-checkpoint output of every drifted trace). Run once,
              at the state you want recorded.
  --check     regenerate the dynamic section in memory and compare it
              against the docs copy; exit 1 + diff when stale. The gate
              command documented in docs/rebaseline-runbook.md. The gate
              also fails when any OTHER (non-self-referential) frozen pair
              is genuinely CHANGED at the live tree, even when the docs
              copy already matches the regeneration — a real drift is a
              failure, not an up-to-date record of one (issue #143 AC2).
  (no flag)   regenerate the docs file in place, preserving its static
              Discovery snapshot section.

The dynamic section is deterministic from the live tree; the Discovery
snapshot is static text recorded once, so the record of what the inventory
FOUND survives the repair itself.

Self-reference safety (issue #143): a trace whose manifest pins the
inventory document itself (63-66-119-collated's C8 pair) would otherwise
make every regeneration change the very hash the gate compares against —
the quine that forced the regenerate -> re-AMEND -> regenerate ritual and
the --no-verify pre-push bypass. Such pairs are EXCLUDED from the gate
verdict AND from the rendered counts (their OK/CHANGED lines move with the
document's own bytes) and reported in their own labelled section. The
section lists each pair with the document's live working-tree blob id
(`git hash-object`) and NO rendered match/diverge verdict — a document
cannot contain a prefix of its own hash, so any rendered comparison could
never converge (final-critic finding 4); the census text is therefore
regeneration-stable by construction and two consecutive `--check` runs
agree. The pair stays visible (issue #143 AC3); re-anchoring is the next
re-baseline wave's bookkeeping, never a gate failure.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TRACES = REPO / ".agents" / "issue-traces"
DOCS = REPO / "docs" / "issue-trace-drift-inventory.md"
REPRO = ".agents/skills/issue-tracer/scripts/repro-check.sh"

BEGIN = "<!-- regenerated-state-begin -->"
END = "<!-- regenerated-state-end -->"
DISCOVERY_HEADING = "## Discovery snapshot"
SELF_PATH = "docs/issue-trace-drift-inventory.md"


def _verify(slug: str) -> tuple[int, str]:
    proc = subprocess.run(
        [r"C:\Program Files\Git\bin\bash.exe", REPRO, "verify-checkpoint", "--slug", slug],
        cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode, proc.stdout + proc.stderr


def _live_blob(path: str) -> str | None:
    """The git blob id of the WORKING-TREE file (None when unreadable).

    The self-referential pair's informational verdict uses this identity:
    unlike the committed blob it does not move when the document is
    committed, and unlike a working-tree CONTENT hash it uses the repo's
    own blob filter (LF normalization), so the verdict is stable across
    both regenerations and commits once the tree converges (issue #143).
    """
    proc = subprocess.run(
        ["git", "hash-object", "--", path],
        cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    blob = proc.stdout.strip()
    return blob or None


def _manifest_self_pairs(manifest: Path) -> list[dict]:
    """Effective (check-id -> frozen blob) pairs whose pinned path is the
    inventory document itself, from one checkpoint manifest. The manifest
    is tab-separated; the last row per check-id wins (the AMEND-path rule
    verify-checkpoint itself applies)."""
    effective: dict[str, str] = {}
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 6 or parts[2] != SELF_PATH:
            continue
        effective[parts[5]] = parts[3]
    return [{"check": k, "blob": v} for k, v in sorted(effective.items())]


def _collect() -> list[dict]:
    rows = []
    manifests = sorted(TRACES.glob("*/repro/checkpoint.manifest"))
    if not manifests:
        print(
            "FAIL: no local checkpoint manifests under .agents/issue-traces/ "
            "(git-ignored state; the gate cannot run from a clean checkout) — "
            "run on the maintainer host that holds the local traces",
            file=sys.stderr,
        )
        raise SystemExit(2)
    for manifest in manifests:
        slug = manifest.parent.parent.name
        code, out = _verify(slug)
        lines = out.splitlines()
        changed_lines = [line for line in lines if line.startswith("CHANGED ")]
        # The self-referential pairs (rows pinning the inventory document)
        # are excluded from the gate verdict AND from the rendered counts
        # (issue #143): a CHANGED *or* OK line naming that path varies with
        # the document's own bytes, so even the OK count is quine-affected.
        self_changed = [line for line in changed_lines if SELF_PATH in line]
        gate_changed = [line for line in changed_lines if SELF_PATH not in line]
        gate_ok = sum(
            1 for line in lines
            if line.startswith("OK ") and SELF_PATH not in line
        )
        rows.append({
            "slug": slug, "code": code,
            "pairs": gate_ok + len(gate_changed),
            "ok": gate_ok, "changed": len(gate_changed),
            "self_pairs": _manifest_self_pairs(manifest),
            "self_changed": self_changed,
            "gate_changed": gate_changed,
            "changed_lines": changed_lines,
        })
    return rows


def _dynamic(rows: list[dict]) -> str:
    lines = [
        BEGIN, "",
        "Live verify-checkpoint state of every local trace (regenerate with",
        "`python scripts/gen_trace_drift_inventory.py`; gate with `--check`; runbook:",
        "docs/rebaseline-runbook.md). Self-referential pairs (traces whose",
        "manifest pins this document itself) are excluded from the gate and",
        "reported below (issue #143).",
        "",
        "| trace | pairs | OK | CHANGED | verify-checkpoint |",
        "|---|---:|---:|---:|---|",
    ]
    for row in rows:
        # A nonzero verify-checkpoint exit with no CHANGED line is a broken
        # leg (missing manifest, invalid check id -> exit 2), not a clean
        # trace: surface the exit instead of rendering "clean" (reviewer R8).
        gate_state = (
            "clean"
            if not row["gate_changed"] and row["code"] == 0
            else f"exit {row['code']}"
        )
        lines.append(f"| {row['slug']} | {row['pairs']} | {row['ok']} | {len(row['gate_changed'])} | {gate_state} |")
    lines += [
        "",
        "## Self-referential pairs (excluded from the gate, issue #143)",
        "",
        "Pairs whose frozen path is this document itself, listed with the",
        "live working-tree blob id of the document (`git hash-object`). No",
        "match/diverge verdict is rendered: a document cannot contain a",
        "prefix of its own hash, so a rendered comparison could never",
        "converge (final-critic finding 4). The frozen blob lives in the",
        "trace's manifest; re-anchoring is the next re-baseline wave's",
        "bookkeeping and is never a gate failure.",
        "",
    ]
    self_rows = [(row, pair) for row in rows for pair in row["self_pairs"]]
    if not self_rows:
        lines.append("None — no trace pins the inventory document itself.")
    for row, pair in self_rows:
        live = _live_blob(SELF_PATH) or "unavailable"
        lines.append(
            f"- `{row['slug']}` {pair['check']}: live doc blob {live[:12]} "
            "(informational; excluded from the gate)"
        )
    lines += ["", "## Drift detail (CHANGED pairs)", ""]
    drifted = [row for row in rows if row["gate_changed"]]
    if not drifted:
        lines.append("None — every gate-relevant frozen pair verifies OK at the current tree.")
    for row in drifted:
        lines += [f"### {row['slug']} (exit {row['code']})", ""]
        lines += [f"- `{line}`" for line in row["gate_changed"]]
        lines.append("")
    lines += [END, ""]
    return "\n".join(lines)


def _static_of(text: str) -> str:
    start = text.find(DISCOVERY_HEADING)
    return text[start:] if start != -1 else ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", action="store_true",
                        help="capture current state as the durable artifact (run once, pre-repair)")
    parser.add_argument("--force", action="store_true",
                        help="allow --snapshot to replace an existing Discovery snapshot")
    parser.add_argument("--check", action="store_true",
                        help="compare regeneration against the docs copy; exit 1 on drift")
    args = parser.parse_args()

    rows = _collect()
    dynamic = _dynamic(rows)

    if args.snapshot:
        if DOCS.exists() and _static_of(DOCS.read_text(encoding="utf-8")) and not args.force:
            print("FAIL: docs copy already carries a Discovery snapshot; --snapshot would "
                  "replace the recorded audit trail. Use --force only to intentionally "
                  "re-record it.", file=sys.stderr)
            return 1
        base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                              capture_output=True, text=True, encoding="utf-8").stdout.strip()
        parts = [
            "# Issue-trace checkpoint inventory",
            "",
            dynamic.rstrip("\n"), "",
        ]
        drifted = [row for row in rows if row["gate_changed"]]
        if drifted:
            parts.append(f"{DISCOVERY_HEADING} (recorded {datetime.date.today().isoformat()}, base {base})")
            parts.append("")
            parts.append("Verbatim verify-checkpoint output per drifted trace at the recorded state.")
            parts.append("")
            for row in drifted:
                parts += [f"### {row['slug']}", "", "```", ""]
                code, out = _verify(row["slug"])
                parts += [out.rstrip("\n"), "```", ""]
        DOCS.write_text("\n".join(parts), encoding="utf-8", newline="\n")
        print(f"wrote {DOCS.relative_to(REPO)}")
        return 0

    if args.check:
        if not DOCS.exists():
            print(f"FAIL: {DOCS.relative_to(REPO)} missing — run --snapshot to record the inventory", file=sys.stderr)
            return 1
        # Real drift anywhere in the census is a gate failure on its own
        # (issue #143 AC2): the docs copy matching the regeneration must not
        # launder a CHANGED sibling into an OK verdict.
        drifted = [row for row in rows if row["gate_changed"]]
        if drifted:
            for row in drifted:
                print(f"CHANGED {row['slug']}: " + "; ".join(row["gate_changed"]))
            print("FAIL: inventory drift — regenerate with python scripts/gen_trace_drift_inventory.py")
            return 1
        # A nonzero verify-checkpoint exit with no CHANGED lines is a broken
        # leg (missing manifest / invalid check id -> exit 2), not a clean
        # census: fail the gate instead of laundering it (reviewer R8). A
        # trace whose only divergence is the excluded self pair keeps its
        # nonzero exit (the excluded pair IS its exit cause) without
        # tripping this branch.
        broken = [
            row for row in rows
            if row["code"] != 0 and not row["gate_changed"] and not row["self_changed"]
        ]
        if broken:
            for row in broken:
                print(f"ERROR {row['slug']}: verify-checkpoint exited "
                      f"{row['code']} with no CHANGED lines — inspect that "
                      "trace's local checkpoint setup")
            print("FAIL: inventory drift — regenerate with python scripts/gen_trace_drift_inventory.py")
            return 1
        existing = DOCS.read_text(encoding="utf-8")
        s = existing.find(BEGIN)
        e = existing.find(END)
        if s == -1 or e == -1:
            print("FAIL: docs copy has no regenerated-state markers — run --snapshot", file=sys.stderr)
            return 1
        current = existing[s:e + len(END)]
        if current == dynamic.rstrip("\n"):
            print("inventory --check: OK (docs copy matches live state)")
            return 0
        diff = "\n".join(difflib.unified_diff(
            current.splitlines(), dynamic.splitlines(),
            fromfile="docs copy", tofile="live regeneration", lineterm=""))
        print(diff)
        print("FAIL: inventory drift — regenerate with python scripts/gen_trace_drift_inventory.py")
        return 1

    # regenerate in place
    if DOCS.exists():
        existing = DOCS.read_text(encoding="utf-8")
        s_idx = existing.find(BEGIN)
        e_idx = existing.find(END)
        static = _static_of(existing)
        if s_idx == -1 or e_idx == -1 or (not static and any(
                row["gate_changed"] for row in rows)):
            print("FAIL: docs copy is malformed (missing regenerated-state markers or "
                  "Discovery snapshot); refusing to write — fix it with --snapshot "
                  "--force or restore from git history", file=sys.stderr)
            return 1
        head = existing[:s_idx].rstrip("\n")
        body = head + "\n\n" + dynamic.rstrip("\n") + "\n"
        if static:
            body += "\n" + static
        DOCS.write_text(body, encoding="utf-8", newline="\n")
        print(f"regenerated {DOCS.relative_to(REPO)}")
    else:
        print(f"FAIL: {DOCS.relative_to(REPO)} missing — run --snapshot first")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
