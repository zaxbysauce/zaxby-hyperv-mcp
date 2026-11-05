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
              command documented in docs/rebaseline-runbook.md.
  (no flag)   regenerate the docs file in place, preserving its static
              Discovery snapshot section.

The dynamic section is deterministic from the live tree; the Discovery
snapshot is static text recorded once, so the record of what the inventory
FOUND survives the repair itself.
"""

from __future__ import annotations

import argparse
import difflib
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TRACES = REPO / ".agents" / "issue-traces"
DOCS = REPO / "docs" / "issue-trace-drift-inventory.md"
REPRO = ".agents/skills/issue-tracer/scripts/repro-check.sh"

BEGIN = "<!-- regenerated-state-begin -->"
END = "<!-- regenerated-state-end -->"
DISCOVERY_HEADING = "## Discovery snapshot"


def _verify(slug: str) -> tuple[int, str]:
    proc = subprocess.run(
        [r"C:\Program Files\Git\bin\bash.exe", REPRO, "verify-checkpoint", "--slug", slug],
        cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode, proc.stdout + proc.stderr


def _collect() -> list[dict]:
    rows = []
    for manifest in sorted(TRACES.glob("*/repro/checkpoint.manifest")):
        slug = manifest.parent.parent.name
        code, out = _verify(slug)
        lines = out.splitlines()
        ok = sum(1 for line in lines if line.startswith("OK "))
        changed_lines = [line for line in lines if line.startswith("CHANGED ")]
        rows.append({
            "slug": slug, "code": code, "pairs": ok + len(changed_lines),
            "ok": ok, "changed": len(changed_lines), "changed_lines": changed_lines,
        })
    return rows


def _dynamic(rows: list[dict]) -> str:
    lines = [
        BEGIN, "",
        "Live verify-checkpoint state of every local trace (regenerate with",
        "`python scripts/gen_trace_drift_inventory.py`; gate with `--check`; runbook:",
        "docs/rebaseline-runbook.md).",
        "",
        "| trace | pairs | OK | CHANGED | verify-checkpoint |",
        "|---|---:|---:|---:|---|",
    ]
    for row in rows:
        state = "clean" if row["changed"] == 0 and row["code"] == 0 else f"exit {row['code']}"
        lines.append(f"| {row['slug']} | {row['pairs']} | {row['ok']} | {row['changed']} | {state} |")
    lines += ["", "## Drift detail (CHANGED pairs)", ""]
    drifted = [row for row in rows if row["changed_lines"]]
    if not drifted:
        lines.append("None — every frozen pair verifies OK at the current tree.")
    for row in drifted:
        lines += [f"### {row['slug']} (exit {row['code']})", ""]
        lines += [f"- `{line}`" for line in row["changed_lines"]]
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
    parser.add_argument("--check", action="store_true",
                        help="compare regeneration against the docs copy; exit 1 on drift")
    args = parser.parse_args()

    dynamic = _dynamic(_collect())

    if args.snapshot:
        parts = [
            "# Issue-trace checkpoint inventory",
            "",
            dynamic.rstrip("\n"), "",
        ]
        drifted = [row for row in _collect() if row["changed_lines"]]
        if drifted:
            parts.append(f"{DISCOVERY_HEADING} (recorded 2026-11-05, base 8bc60cb7196ae128231c25a15881cded26b0afda)")
            parts.append("")
            parts.append("Verbatim verify-checkpoint output per drifted trace at the recorded state.")
            parts.append("")
            for row in drifted:
                parts += [f"### {row['slug']}", "", "```", ""]
                code, out = _verify(row["slug"])
                parts += [out.rstrip("\n"), "```", ""]
        DOCS.write_text("\n".join(parts), encoding="utf-8")
        print(f"wrote {DOCS.relative_to(REPO)}")
        return 0

    if args.check:
        if not DOCS.exists():
            print(f"FAIL: {DOCS.relative_to(REPO)} missing — run --snapshot to record the inventory", file=sys.stderr)
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
        static = _static_of(existing)
        head = existing[:existing.find(BEGIN)].rstrip("\n")
        body = head + "\n\n" + dynamic.rstrip("\n") + "\n"
        if static:
            body += "\n" + static
        DOCS.write_text(body, encoding="utf-8")
        print(f"regenerated {DOCS.relative_to(REPO)}")
    else:
        print(f"FAIL: {DOCS.relative_to(REPO)} missing — run --snapshot first")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
