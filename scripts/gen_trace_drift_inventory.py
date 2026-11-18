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
section lists each pair by trace and check id only and renders NO hash or
verdict at all — ANY document-derived value (a blob id, a comparison)
moves with the document's own bytes and would re-open the quine; the
census text is therefore
regeneration-stable by construction and two consecutive `--check` runs
agree. The pair stays visible (issue #143 AC3); re-anchoring is the next
re-baseline wave's bookkeeping, never a gate failure.

Amend guard + trace ledger (issue #148, plan F4/F7): when
docs/amend-guard-baseline.json exists (the guard's activation switch),
_collect() also runs scripts/verify_amend_verbatim.py per manifest —
guard exit 1 (post-watermark argv corruption) fails --check and
regeneration; exit 2 (semantic amendments) is disclosed on stderr only.
docs/issue-trace-ledger.md registers every slug ever rendered: a
regeneration appends new slugs (first-rendered commit, status active),
and an active ledger slug no longer rendered is reported as
`MISSING <slug>` on stderr and fails --check. Guard and ledger results
are exit-code/stderr-only and are never rendered into the document
(quine safety), so consecutive regenerations stay byte-stable.
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
LEDGER_BEGIN = "<!-- ledger-rows-begin -->"
LEDGER_END = "<!-- ledger-rows-end -->"

_LEDGER_SKELETON = (
    "# Issue-trace ledger\n"
    "\n"
    "Append-only register of every trace slug ever rendered into\n"
    "docs/issue-trace-drift-inventory.md (issue #148, plan F7). Machine rows\n"
    "live between the markers, one per slug:\n"
    "\n"
    "- <slug> | <active|retired> | <first-rendered commit> | <retirement date+reason or ->\n"
    "\n"
    "Regeneration (python scripts/gen_trace_drift_inventory.py) appends newly\n"
    "rendered slugs automatically; retiring a trace — flip its row to\n"
    "`retired` with a date and reason — is the only manual edit. The ledger\n"
    "carries no inventory-derived value (no blobs, counts, or verdicts), so\n"
    "it adds no self-referential hash surface to the inventory document.\n"
    "\n"
    f"{LEDGER_BEGIN}\n"
    f"{LEDGER_END}\n"
)


def _verify(slug: str) -> tuple[int, str]:
    proc = subprocess.run(
        [r"C:\Program Files\Git\bin\bash.exe", REPRO, "verify-checkpoint", "--slug", slug],
        cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode, proc.stdout + proc.stderr


def _tail(text: str, limit: int = 400) -> str:
    """Bounded single-line tail of a guard transcript for the stderr /
    exit-code disclosure lines."""
    flat = " ".join((text or "").split())
    return flat[-limit:] if len(flat) > limit else flat


def _guard(manifest: Path) -> tuple[str | None, str | None]:
    """Run the amend-verbatim guard on one manifest (issue #148, plan F4).
    Returns (fail_tail, warn_tail); at most one is set. Exit 3 (usage/shape
    error) would be a real bug in the wiring — it is surfaced as a failure,
    never silently skipped."""
    try:
        proc = subprocess.run(
            [sys.executable,
             str(REPO / "scripts" / "verify_amend_verbatim.py"),
             str(manifest), "--repo-root", str(REPO)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except OSError as exc:
        return f"guard did not run: {exc}", None
    if proc.returncode == 0:
        return None, None
    transcript = _tail((proc.stdout or "") + (proc.stderr or ""))
    if proc.returncode == 2:
        return None, transcript or "guard warned with no output"
    # 1 = post-watermark argv corruption; anything else (including the
    # usage-error 3) means the guard invocation itself is broken: both
    # fail the inventory run.
    return transcript or f"guard exited {proc.returncode}", None


def _ledger_file() -> Path:
    # Resolved from REPO at call time: tests repoint REPO at a sandbox.
    return REPO / "docs" / "issue-trace-ledger.md"


def _ledger_rows(text: str) -> list[list[str]]:
    """Parsed machine rows between the ledger markers: columns are
    [slug, status, first-rendered commit, retirement]. Non-machine lines
    inside the markers are ignored (and preserved untouched by appends)."""
    try:
        section = text.split(LEDGER_BEGIN, 1)[1].split(LEDGER_END, 1)[0]
    except IndexError:
        return []
    rows = []
    for line in section.splitlines():
        if not line.startswith("- "):
            continue
        cols = [c.strip() for c in line[2:].split("|")]
        if len(cols) >= 2:
            rows.append(cols)
    return rows


def _doc_slugs(text: str) -> set[str]:
    """Slugs rendered in the census table of a document (between the
    regenerated-state markers)."""
    try:
        section = text.split(BEGIN, 1)[1].split(END, 1)[0]
    except IndexError:
        return set()
    slugs = set()
    for line in section.splitlines():
        if not line.startswith("| ") or line.startswith("|---"):
            continue
        cols = [c.strip() for c in line.split("|")]
        if len(cols) >= 2 and cols[1] and cols[1] != "trace":
            slugs.add(cols[1])
    return slugs


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
    # The amend-verbatim guard activates only when the committed baseline
    # watermark exists (plan F4 ordering: the activation commit lands
    # docs/amend-guard-baseline.json and switches the generator on in the
    # same wave). Without it the legacy pre-guard AMEND rows would be
    # evaluated strict from row 1 and the gate could never go green.
    guard_active = (REPO / "docs" / "amend-guard-baseline.json").exists()
    for manifest in manifests:
        slug = manifest.parent.parent.name
        code, out = _verify(slug)
        lines = out.splitlines()
        changed_lines = [line for line in lines if line.startswith("CHANGED ")]
        # The self-referential pairs (rows pinning the inventory document)
        # are excluded from the gate verdict AND from the rendered counts
        # (issue #143): a CHANGED *or* OK line naming that path varies with
        # the document's own bytes, so even the OK count is quine-affected.
        # Classify by the parsed PATH FIELD (verify-checkpoint prints
        # 'CHANGED <path> <frozen> <actual> (<check>)'), not substring
        # membership — a future pinned path merely CONTAINING the doc path
        # must not be silently excluded (PR-144 review RISK-02).
        def _line_path(line: str) -> str:
            return line.split()[1] if len(line.split()) >= 2 else ""

        self_changed = [line for line in changed_lines if _line_path(line) == SELF_PATH]
        gate_changed = [line for line in changed_lines if _line_path(line) != SELF_PATH]
        gate_ok = sum(
            1 for line in lines
            if line.startswith("OK ") and SELF_PATH not in line
        )
        row = {
            "slug": slug, "code": code,
            "pairs": gate_ok + len(gate_changed),
            "ok": gate_ok, "changed": len(gate_changed),
            "self_pairs": _manifest_self_pairs(manifest),
            "self_changed": self_changed,
            "gate_changed": gate_changed,
            "changed_lines": changed_lines,
        }
        if guard_active:
            row["guard_fail"], row["guard_warn"] = _guard(manifest)
        rows.append(row)
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
        # The cell must be IDENTICAL whether the excluded self pair reads OK
        # or CHANGED (final-critic round-2 finding: the exit code includes
        # the self pair's own result, so a re-anchored doc flip-flopped
        # between two renderings forever). A trace whose only divergence is
        # the excluded pair renders clean; a broken leg (nonzero exit, no
        # gate CHANGED, no self divergence) still renders its exit (the R8
        # anti-laundering pin holds).
        gate_state = (
            "clean"
            if not row["gate_changed"] and (row["code"] == 0 or row["self_changed"])
            else f"exit {row['code']}"
        )
        lines.append(f"| {row['slug']} | {row['pairs']} | {row['ok']} | {len(row['gate_changed'])} | {gate_state} |")
    lines += [
        "",
        "## Self-referential pairs (excluded from the gate, issue #143)",
        "",
        "Pairs whose frozen path is this document itself. No hash or",
        "verdict is rendered at all: any document-derived value (a blob id,",
        "a comparison) moves with the document's own bytes and re-opens the",
        "quine (final-critic finding 4, twice over). The frozen blob lives",
        "in the trace's manifest; re-anchoring is the next re-baseline",
        "wave's bookkeeping and is never a gate failure.",
        "",
    ]
    self_rows = [(row, pair) for row in rows for pair in row["self_pairs"]]
    if not self_rows:
        lines.append("None — no trace pins the inventory document itself.")
    for row, pair in self_rows:
        lines.append(
            f"- `{row['slug']}` {pair['check']} (informational; excluded from the gate)"
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
        # Guard failures fail the gate (plan F4 wiring): post-watermark argv
        # corruption in any walked manifest is disclosed per trace and fails
        # --check even when the document itself is current. Warnings (the
        # sanctioned semantic-amendment tier) are stderr-disclosed only.
        for row in rows:
            if row.get("guard_warn"):
                print(f"GUARD WARN {row['slug']}: {row['guard_warn']}", file=sys.stderr)
        guard_failed = [row for row in rows if row.get("guard_fail")]
        if guard_failed:
            for row in guard_failed:
                print(f"GUARD FAIL {row['slug']}: {row['guard_fail']}")
            print("FAIL: amend-guard corruption — repair the manifest with the "
                  "per-pair AMEND procedure in docs/rebaseline-runbook.md")
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
        # Deletion laundering guard (plan F7): a ledger-active slug that is
        # no longer rendered in the census is a deleted trace — after the
        # deletion both the store and the document lack the slug, so the
        # census alone cannot see it; only the committed ledger can. Stderr
        # + exit code only, never rendered into the document (quine safety).
        existing = DOCS.read_text(encoding="utf-8")
        ledger = _ledger_file()
        ledger_text = ledger.read_text(encoding="utf-8") if ledger.exists() else ""
        active = {r[0] for r in _ledger_rows(ledger_text) if r[1] == "active"}
        missing = sorted(active - _doc_slugs(existing))
        for slug in missing:
            print(f"MISSING {slug}", file=sys.stderr)
        if missing:
            print("FAIL: ledger-active traces missing from the rendered inventory — "
                  "restore the trace store or retire the ledger row in "
                  "docs/issue-trace-ledger.md")
            return 1
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
    # Ledger maintenance + guard/MISSING disclosure (issue #148, plan F7):
    # stderr and exit-code only — the rendered document is never touched by
    # any of it, so consecutive regenerations stay byte-stable (the ledger
    # is committed state, not regenerated content: appends touch only the
    # ledger file, MISSING rows are never rendered into the document).
    status = 0
    for row in rows:
        if row.get("guard_warn"):
            print(f"GUARD WARN {row['slug']}: {row['guard_warn']}", file=sys.stderr)
        if row.get("guard_fail"):
            print(f"GUARD FAIL {row['slug']}: {row['guard_fail']}", file=sys.stderr)
            status = 1
    rendered = [row["slug"] for row in rows]
    ledger = _ledger_file()
    ledger_text = (ledger.read_text(encoding="utf-8")
                   if ledger.exists() else _LEDGER_SKELETON)
    if LEDGER_BEGIN not in ledger_text or LEDGER_END not in ledger_text:
        print(f"FAIL: {ledger.relative_to(REPO)} is malformed (no ledger-rows "
              "markers) — restore it from git history", file=sys.stderr)
        return 1
    known = {r[0] for r in _ledger_rows(ledger_text)}
    fresh = [slug for slug in rendered if slug not in known]
    if fresh:
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                             capture_output=True, text=True,
                             encoding="utf-8")
        commit = (rev.stdout.strip()
                  if rev.returncode == 0 and rev.stdout.strip() else "-")
        addition = "".join(f"- {slug} | active | {commit} | -\n"
                           for slug in fresh)
        idx = ledger_text.index(LEDGER_END)
        ledger.write_text(ledger_text[:idx] + addition + ledger_text[idx:],
                          encoding="utf-8", newline="\n")
    active = {r[0] for r in _ledger_rows(ledger_text) if r[1] == "active"}
    missing = sorted(active - set(rendered))
    for slug in missing:
        print(f"MISSING {slug}", file=sys.stderr)
    if missing:
        print("FAIL: ledger-active traces missing from the rendered inventory — "
              "restore the trace store or retire the ledger row in "
              "docs/issue-trace-ledger.md", file=sys.stderr)
        status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
